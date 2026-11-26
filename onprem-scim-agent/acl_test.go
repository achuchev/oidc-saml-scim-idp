package main

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Access masks as Windows stores them for the usual icacls grants.
const (
	maskFull       = 0x001F01FF // F
	maskModify     = 0x001301BF // M
	maskReadExec   = 0x001200A9 // RX
	maskRead       = 0x00120089 // R
	maskAddSubdir  = 0x00000004 // AD
	maskWriteFiles = 0x00000116 // WD, AD, WEA, WA (BUILTIN\Users on %ProgramData%)
)

const (
	testUsers     = "S-1-5-32-545"
	testAuthUsers = "S-1-5-11"
	testEveryone  = "S-1-1-0"
)

func sidBytes(t *testing.T, sid string) []byte {
	t.Helper()
	parts := strings.Split(sid, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" {
		t.Fatalf("bad SID %q", sid)
	}
	num := func(s string) uint64 {
		var n uint64
		for _, c := range s {
			n = n*10 + uint64(c-'0')
		}
		return n
	}
	auth := num(parts[2])
	b := []byte{1, byte(len(parts) - 3), byte(auth >> 40), byte(auth >> 32), byte(auth >> 24), byte(auth >> 16), byte(auth >> 8), byte(auth)}
	for _, p := range parts[3:] {
		b = binary.LittleEndian.AppendUint32(b, uint32(num(p)))
	}
	return b
}

func testACE(t *testing.T, aceType, flags byte, mask uint32, sid string) []byte {
	b := []byte{aceType, flags, 0, 0}
	b = binary.LittleEndian.AppendUint32(b, mask)
	b = append(b, sidBytes(t, sid)...)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func testACL(aces ...[]byte) []byte {
	b := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		b = append(b, a...)
	}
	binary.LittleEndian.PutUint16(b[2:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[4:], uint16(len(aces)))
	return b
}

func TestSIDStringRoundTrip(t *testing.T) {
	for _, sid := range []string{sidLocalSystem, sidAdministrators, sidTrustedInstaller, testEveryone, serviceSID(DefaultServiceName), "S-1-5-21-1004336348-1177238915-682003330-512"} {
		got, err := sidString(sidBytes(t, sid))
		if err != nil || got != sid {
			t.Errorf("sidString(%s) = %q, %v", sid, got, err)
		}
	}
	if serviceSID("TrustedInstaller") != sidTrustedInstaller {
		t.Fatalf("TrustedInstaller SID mismatch")
	}
	for _, bad := range [][]byte{nil, {1, 1, 0, 0, 0, 0, 0, 5}, {2, 0, 0, 0, 0, 0, 0, 5}} {
		if _, err := sidString(bad); err == nil {
			t.Errorf("sidString(%v) accepted a malformed SID", bad)
		}
	}
}

func TestParseDACLSkipsInheritOnlyAndDenyEntries(t *testing.T) {
	objectACE := []byte{aceAccessAllowedObject, 0, 0, 0}
	objectACE = binary.LittleEndian.AppendUint32(objectACE, maskModify)
	objectACE = binary.LittleEndian.AppendUint32(objectACE, 1) // ACE_OBJECT_TYPE_PRESENT
	objectACE = append(objectACE, make([]byte, 16)...)
	objectACE = append(objectACE, sidBytes(t, testAuthUsers)...)
	binary.LittleEndian.PutUint16(objectACE[2:], uint16(len(objectACE)))

	acl := testACL(
		testACE(t, aceAccessAllowed, 0x03, maskFull, sidLocalSystem),         // (OI)(CI)
		testACE(t, aceAccessAllowed, 0x0B, maskFull, "S-1-3-0"),              // CREATOR OWNER (OI)(CI)(IO)
		testACE(t, 0x01, 0, maskModify, testEveryone),                        // deny
		testACE(t, aceAccessAllowed, 0x10, maskReadExec, testUsers),          // inherited
		testACE(t, aceAccessAllowedCallback, 0, maskRead, sidAdministrators), // conditional
		objectACE,
	)
	grants, err := parseDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	want := []aclGrant{{sidLocalSystem, maskFull}, {testUsers, maskReadExec}, {sidAdministrators, maskRead}, {testAuthUsers, maskModify}}
	if len(grants) != len(want) {
		t.Fatalf("grants = %v, want %v", grants, want)
	}
	for i := range want {
		if grants[i] != want[i] {
			t.Errorf("grant %d = %v, want %v", i, grants[i], want[i])
		}
	}
	for _, bad := range [][]byte{acl[:6], acl[:len(acl)-3], append(append([]byte{}, acl[:2]...), 0xff, 0xff)} {
		if _, err := parseDACL(bad); err == nil {
			t.Errorf("parseDACL accepted a truncated ACL (%d bytes)", len(bad))
		}
	}
}

func TestSIDTrust(t *testing.T) {
	svc := serviceSID(DefaultServiceName)
	trust := newSIDTrust(svc, "S-1-5-21-1-2-3-1105")
	for _, sid := range []string{sidLocalSystem, sidAdministrators, sidTrustedInstaller, svc, "S-1-5-21-1-2-3-1105",
		"S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-519", "S-1-3-0", "S-1-3-4"} {
		if !trust.trusted(sid) {
			t.Errorf("%s should be trusted", sid)
		}
	}
	for _, sid := range []string{testUsers, testAuthUsers, testEveryone, "S-1-5-4", "S-1-5-19", "S-1-5-21-1-2-3-513",
		"S-1-5-21-1-2-3-1106", "S-1-5-21-500", "S-1-5-32-551", serviceSID("OtherService"), ""} {
		if trust.trusted(sid) {
			t.Errorf("%s should not be trusted", sid)
		}
	}
}

// fakeFS answers readObjectSecurity for a fixed set of paths.
type fakeFS map[string]objectSecurity

func (f fakeFS) read(p string) (objectSecurity, error) {
	if sec, ok := f[p]; ok {
		return sec, nil
	}
	return objectSecurity{}, errors.New("not found")
}

func sec(owner string, grants ...aclGrant) objectSecurity {
	return objectSecurity{owner: owner, grants: grants}
}

func problemsFor(problems []string, path string) []string {
	var out []string
	for _, p := range problems {
		if strings.Contains(p, " "+path+": ") {
			out = append(out, p)
		}
	}
	return out
}

func TestInstallTargetsFlagsWritableProgramAndConfigFolders(t *testing.T) {
	svc := serviceSID(DefaultServiceName)
	fs := fakeFS{
		// A volume root like C:\ on Windows 10/11: Authenticated Users may add
		// folders, and a grant that includes DELETE does not matter on a root.
		"/": sec(sidTrustedInstaller, aclGrant{sidLocalSystem, maskFull}, aclGrant{testAuthUsers, maskAddSubdir}, aclGrant{testUsers, maskReadExec | rightDelete}),
		// A new folder below that root inherits Authenticated Users: Modify.
		"/agent":                 sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{sidAdministrators, maskFull}, aclGrant{testAuthUsers, maskModify}),
		"/agent/scim-agent.exe":  sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{testAuthUsers, maskModify}),
		"/ProgramData":           sec(sidLocalSystem, aclGrant{sidLocalSystem, maskFull}, aclGrant{testUsers, maskReadExec}, aclGrant{testUsers, maskWriteFiles}),
		"/ProgramData/Agent":     sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{testUsers, maskReadExec}, aclGrant{testUsers, maskWriteFiles}),
		"/ProgramData/Agent/log": sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{svc, maskModify}),
	}
	check := newPermissionCheck(newSIDTrust(svc), fs.read, func(s string) string { return s })
	problems := check.installTargets("/agent/scim-agent.exe", "/ProgramData/Agent/config.json", "/ProgramData/Agent/log", []string{"/ProgramData/Agent/missing-ca.pem"})

	if p := problemsFor(problems, "/agent/scim-agent.exe"); len(p) != 1 || !strings.HasSuffix(p[0], testAuthUsers+" may write, delete") {
		t.Errorf("program file: %v", p)
	}
	if p := problemsFor(problems, "/agent"); len(p) != 1 || !strings.HasPrefix(p[0], "program folder /agent: "+testAuthUsers+" may ") {
		t.Errorf("program folder: %v", p)
	}
	if p := problemsFor(problems, "/ProgramData/Agent"); len(p) != 1 || !strings.HasPrefix(p[0], "config folder ") || !strings.HasSuffix(p[0], testUsers+" may write") {
		t.Errorf("config folder (stock %%ProgramData%% permissions): %v", p)
	}
	if p := problemsFor(problems, "/ProgramData/Agent/missing-ca.pem"); len(p) != 1 || !strings.Contains(p[0], "cannot read its permissions") {
		t.Errorf("unreadable CA file: %v", p)
	}
	for _, ok := range []string{"/", "/ProgramData", "/ProgramData/Agent/log"} {
		if p := problemsFor(problems, ok); len(p) != 0 {
			t.Errorf("%s should pass: %v", ok, p)
		}
	}
	if len(problems) != 4 {
		t.Errorf("expected 4 problems, got %d:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

func TestInstallTargetsAcceptsHardenedLayout(t *testing.T) {
	svc := serviceSID(DefaultServiceName)
	installer := "S-1-5-21-1-2-3-1105"
	stock := []aclGrant{{sidLocalSystem, maskFull}, {sidAdministrators, maskFull}, {testUsers, maskReadExec}}
	fs := fakeFS{
		"/":                                     sec(sidTrustedInstaller, aclGrant{sidLocalSystem, maskFull}, aclGrant{testAuthUsers, maskAddSubdir}),
		"/Program Files":                        sec(sidTrustedInstaller, aclGrant{sidTrustedInstaller, maskFull}, aclGrant{sidLocalSystem, maskModify}, aclGrant{testUsers, maskReadExec}),
		"/Program Files/Agent":                  sec(sidAdministrators, stock...),
		"/Program Files/Agent/scim-agent.exe":   sec(installer, append(stock, aclGrant{installer, maskFull})...),
		"/ProgramData":                          sec(sidLocalSystem, aclGrant{sidLocalSystem, maskFull}, aclGrant{testUsers, maskWriteFiles}),
		"/ProgramData/Agent":                    sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{sidAdministrators, maskFull}),
		"/ProgramData/Agent/logs":               sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{svc, maskModify}),
		"/ProgramData/Agent/ca.pem":             sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{svc, maskRead}),
		"/ProgramData/Agent/S-1-5-21-x-500.pem": sec("S-1-5-21-9-9-9-500", aclGrant{"S-1-5-21-9-9-9-512", maskFull}),
	}
	check := newPermissionCheck(newSIDTrust(svc, installer), fs.read, func(s string) string { return s })
	problems := check.installTargets("/Program Files/Agent/scim-agent.exe", "/ProgramData/Agent/config.json", "/ProgramData/Agent/logs",
		[]string{"/ProgramData/Agent/ca.pem", "/ProgramData/Agent/S-1-5-21-x-500.pem"})
	if len(problems) != 0 {
		t.Fatalf("hardened layout rejected:\n%s", strings.Join(problems, "\n"))
	}
}

func TestConfigFileCheck(t *testing.T) {
	svc := serviceSID(DefaultServiceName)
	runner := "S-1-5-21-1-2-3-1105"
	trust := newSIDTrust(svc, runner)
	name := func(s string) string { return "<" + s + ">" }
	cases := []struct {
		sec  objectSecurity
		want []string
	}{
		{sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{sidAdministrators, maskFull}, aclGrant{svc, maskRead}), nil},
		{sec(runner, aclGrant{runner, maskFull}, aclGrant{sidLocalSystem, maskFull}), nil},
		// 1.0.x layout: config.json next to the program inherits Users: RX.
		{sec(sidAdministrators, aclGrant{sidLocalSystem, maskFull}, aclGrant{testUsers, maskReadExec}), []string{"<" + testUsers + "> may read"}},
		{sec(sidAdministrators, aclGrant{testEveryone, rightGenericRead}, aclGrant{testEveryone, rightWriteDAC}), []string{"<" + testEveryone + "> may read, change permissions or owner"}},
		{sec(testUsers, aclGrant{sidLocalSystem, maskFull}), []string{"it is owned by <" + testUsers + ">"}},
		{sec("", aclGrant{sidLocalSystem, maskFull}), []string{"it is owned by <>"}},
		{objectSecurity{owner: sidAdministrators, nullDACL: true}, []string{"it has no access control list, so everyone has full access"}},
		// READ_CONTROL, SYNCHRONIZE and FILE_READ_ATTRIBUTES alone expose nothing.
		{sec(sidAdministrators, aclGrant{testUsers, 0x00120080}), nil},
	}
	for i, c := range cases {
		check := newPermissionCheck(trust, fakeFS{"/cfg/config.json": c.sec}.read, name)
		got := check.configFile("/cfg/config.json")
		if len(got) != len(c.want) {
			t.Errorf("case %d: got %v, want %v", i, got, c.want)
			continue
		}
		for j := range got {
			if got[j] != "config.json /cfg/config.json: "+c.want[j] {
				t.Errorf("case %d: got %q, want %q", i, got[j], c.want[j])
			}
		}
	}
	check := newPermissionCheck(trust, fakeFS{}.read, name)
	if got := check.configFile("/cfg/config.json"); len(got) != 1 || !strings.Contains(got[0], "cannot read its permissions") {
		t.Errorf("unreadable config: %v", got)
	}
}
