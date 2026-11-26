package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ---------- File permission checks ----------
//
// -install and the service start-up check who can read or change the files
// the agent depends on. Decoding a DACL and judging it is platform
// independent (and tested everywhere); service_windows.go reads the security
// descriptors with GetNamedSecurityInfoW.

// Access rights in file and folder DACLs (winnt.h).
const (
	rightReadData     = 0x00000001 // FILE_READ_DATA; FILE_LIST_DIRECTORY on folders
	rightWriteData    = 0x00000002 // FILE_WRITE_DATA; FILE_ADD_FILE on folders
	rightAppendData   = 0x00000004 // FILE_APPEND_DATA; FILE_ADD_SUBDIRECTORY on folders
	rightDeleteChild  = 0x00000040 // FILE_DELETE_CHILD
	rightDelete       = 0x00010000 // DELETE
	rightWriteDAC     = 0x00040000 // WRITE_DAC
	rightWriteOwner   = 0x00080000 // WRITE_OWNER
	rightGenericAll   = 0x10000000 // GENERIC_ALL
	rightGenericWrite = 0x40000000 // GENERIC_WRITE
	rightGenericRead  = 0x80000000 // GENERIC_READ

	// rightsModify let an account change, replace, delete or re-permission a
	// file, or add, remove or replace the entries of a folder.
	rightsModify = rightWriteData | rightAppendData | rightDeleteChild | rightDelete |
		rightWriteDAC | rightWriteOwner | rightGenericAll | rightGenericWrite
	// rightsParent let an account rename, remove or re-permission a folder and
	// so replace everything below it.
	rightsParent = rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner | rightGenericAll
	// rightsSecret let an account read or change a file that holds secrets.
	rightsSecret = rightsModify | rightReadData | rightGenericRead
)

// ACE types and flags (winnt.h).
const (
	aceAccessAllowed               = 0x00
	aceAccessAllowedObject         = 0x05
	aceAccessAllowedCallback       = 0x09
	aceAccessAllowedCallbackObject = 0x0B
	aceInheritOnly                 = 0x08 // INHERIT_ONLY_ACE
)

// Well-known SIDs.
const (
	sidLocalSystem      = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// aclGrant is an access-allowed DACL entry that applies to the object itself.
type aclGrant struct {
	sid  string
	mask uint32
}

// objectSecurity is the owner and the effective allow entries of a file or folder.
type objectSecurity struct {
	owner    string // SID string, "" when there is none
	nullDACL bool   // no DACL at all: everyone has full access
	grants   []aclGrant
}

// sidString formats a binary SID as S-1-<authority>-<subauthority>...
func sidString(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 {
		return "", errors.New("invalid SID")
	}
	n := int(b[1])
	if n > 15 || len(b) < 8+4*n {
		return "", errors.New("invalid SID")
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var s strings.Builder
	s.WriteString("S-1-")
	if auth >= 1<<32 {
		fmt.Fprintf(&s, "0x%012X", auth)
	} else {
		s.WriteString(strconv.FormatUint(auth, 10))
	}
	for i := 0; i < n; i++ {
		s.WriteByte('-')
		s.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[8+4*i:])), 10))
	}
	return s.String(), nil
}

// parseDACL decodes a binary ACL (an ACL header followed by its ACEs) and
// returns the access-allowed entries that apply to the object itself.
// Inherit-only entries only shape future children and are skipped. Deny
// entries are ignored, which can only make a check stricter.
func parseDACL(acl []byte) ([]aclGrant, error) {
	if len(acl) < 8 {
		return nil, errors.New("ACL is truncated")
	}
	size := int(binary.LittleEndian.Uint16(acl[2:]))
	count := int(binary.LittleEndian.Uint16(acl[4:]))
	if size < 8 || size > len(acl) {
		return nil, errors.New("ACL size is invalid")
	}
	acl = acl[:size]
	var grants []aclGrant
	off := 8
	for i := 0; i < count; i++ {
		if off+4 > len(acl) {
			return nil, errors.New("ACE is truncated")
		}
		aceType, aceFlags := acl[off], acl[off+1]
		aceSize := int(binary.LittleEndian.Uint16(acl[off+2:]))
		if aceSize < 4 || off+aceSize > len(acl) {
			return nil, errors.New("ACE size is invalid")
		}
		ace := acl[off : off+aceSize]
		off += aceSize

		sidStart := 8
		switch aceType {
		case aceAccessAllowed, aceAccessAllowedCallback:
		case aceAccessAllowedObject, aceAccessAllowedCallbackObject:
			if len(ace) < 12 {
				return nil, errors.New("ACE is truncated")
			}
			sidStart = 12
			flags := binary.LittleEndian.Uint32(ace[8:])
			if flags&1 != 0 { // ACE_OBJECT_TYPE_PRESENT
				sidStart += 16
			}
			if flags&2 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
				sidStart += 16
			}
		default:
			continue // deny entries
		}
		if aceFlags&aceInheritOnly != 0 {
			continue
		}
		if len(ace) < sidStart {
			return nil, errors.New("ACE is truncated")
		}
		sid, err := sidString(ace[sidStart:])
		if err != nil {
			return nil, err
		}
		grants = append(grants, aclGrant{sid: sid, mask: binary.LittleEndian.Uint32(ace[4:])})
	}
	return grants, nil
}

// sidTrust is the set of accounts that may control the agent's files: SYSTEM,
// Administrators, TrustedInstaller, the CREATOR OWNER / CREATOR GROUP / OWNER
// RIGHTS placeholders (the owner is judged on its own), the built-in
// Administrator account and the Domain and Enterprise Admins groups, plus the
// extra SIDs given to newSIDTrust (the service account, and the account that
// runs the installer or the agent).
type sidTrust map[string]bool

func newSIDTrust(extra ...string) sidTrust {
	t := sidTrust{
		sidLocalSystem: true, sidAdministrators: true, sidTrustedInstaller: true,
		"S-1-3-0": true, "S-1-3-1": true, "S-1-3-4": true,
	}
	for _, s := range extra {
		if s != "" {
			t[strings.ToUpper(s)] = true
		}
	}
	return t
}

func (t sidTrust) trusted(sid string) bool {
	sid = strings.ToUpper(sid)
	if t[sid] {
		return true
	}
	// S-1-5-21-<machine or domain>-<RID>: the built-in Administrator account
	// (500), Domain Admins (512) and Enterprise Admins (519).
	if parts := strings.Split(sid, "-"); len(parts) == 8 && parts[3] == "21" {
		switch parts[7] {
		case "500", "512", "519":
			return true
		}
	}
	return false
}

// describeRights names the rights in r for a message.
func describeRights(r uint32) string {
	var parts []string
	if r&rightGenericAll != 0 {
		parts = append(parts, "take full control")
	}
	if r&(rightReadData|rightGenericRead) != 0 {
		parts = append(parts, "read")
	}
	if r&(rightWriteData|rightAppendData|rightGenericWrite) != 0 {
		parts = append(parts, "write")
	}
	if r&(rightDelete|rightDeleteChild) != 0 {
		parts = append(parts, "delete")
	}
	if r&(rightWriteDAC|rightWriteOwner) != 0 {
		parts = append(parts, "change permissions or owner")
	}
	return strings.Join(parts, ", ")
}

// untrustedAccess describes every way in which accounts outside trust can use
// rights in mask on an object: a missing DACL, owning it (an owner can always
// change the permissions) or holding such a right.
func untrustedAccess(sec objectSecurity, mask uint32, trust sidTrust, name func(string) string) []string {
	if sec.nullDACL {
		return []string{"it has no access control list, so everyone has full access"}
	}
	var out []string
	if sec.owner == "" || !trust.trusted(sec.owner) {
		out = append(out, "it is owned by "+name(sec.owner))
	}
	var order []string
	rights := map[string]uint32{}
	for _, g := range sec.grants {
		r := g.mask & mask
		if r == 0 || trust.trusted(g.sid) {
			continue
		}
		if _, seen := rights[g.sid]; !seen {
			order = append(order, g.sid)
		}
		rights[g.sid] |= r
	}
	for _, sid := range order {
		out = append(out, name(sid)+" may "+describeRights(rights[sid]))
	}
	return out
}

// permissionCheck collects the permission problems of files and folders.
type permissionCheck struct {
	trust    sidTrust
	read     func(path string) (objectSecurity, error)
	name     func(sid string) string
	checked  map[string]bool
	problems []string
}

func newPermissionCheck(trust sidTrust, read func(string) (objectSecurity, error), name func(string) string) *permissionCheck {
	return &permissionCheck{trust: trust, read: read, name: name, checked: map[string]bool{}}
}

// object checks a file or folder once for untrusted rights in mask. A
// security descriptor that cannot be read counts as a problem.
func (c *permissionCheck) object(what, path string, mask uint32) {
	if path == "" {
		return
	}
	key := strings.ToLower(filepath.Clean(path))
	if c.checked[key] {
		return
	}
	c.checked[key] = true
	sec, err := c.read(path)
	if err != nil {
		c.problems = append(c.problems, fmt.Sprintf("%s %s: cannot read its permissions: %v", what, path, err))
		return
	}
	for _, p := range untrustedAccess(sec, mask, c.trust, c.name) {
		c.problems = append(c.problems, fmt.Sprintf("%s %s: %s", what, path, p))
	}
}

// parents checks every folder above p, up to the volume root, for rights that
// let an account rename, remove or re-permission it. Folders already checked
// (with the wider rightsModify) are skipped.
func (c *permissionCheck) parents(p string) {
	if p == "" {
		return
	}
	for d := filepath.Dir(filepath.Clean(p)); ; {
		up := filepath.Dir(d)
		mask := uint32(rightsParent)
		if up == d {
			mask &^= rightDelete // a volume root cannot be renamed or removed
		}
		c.object("parent folder", d, mask)
		if up == d {
			return
		}
		d = up
	}
}

// installTargets checks what a new service depends on: no untrusted account
// may change scim-agent.exe, the CA files, the program, config or log folder
// (including adding files to them), or rename or re-permission a folder above
// them. config.json itself is not checked because -install resets its
// permissions.
func (c *permissionCheck) installTargets(exePath, configPath, logDir string, caFiles []string) []string {
	exeDir := filepath.Dir(exePath)
	configDir := filepath.Dir(configPath)
	c.object("program file", exePath, rightsModify)
	c.object("program folder", exeDir, rightsModify)
	c.object("config folder", configDir, rightsModify)
	c.object("log folder", logDir, rightsModify)
	for _, f := range caFiles {
		c.object("CA file", f, rightsModify)
	}
	for _, p := range append([]string{exeDir, configDir, logDir}, caFiles...) {
		c.parents(p)
	}
	return c.problems
}

// configFile checks that no untrusted account can read or change config.json
// (the agent token and the local SCIM credentials) or owns it.
func (c *permissionCheck) configFile(configPath string) []string {
	c.object("config.json", configPath, rightsSecret)
	return c.problems
}
