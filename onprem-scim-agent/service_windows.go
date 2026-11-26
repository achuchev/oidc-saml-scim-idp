//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	serviceWin32OwnProcess = 0x00000010
	serviceAutoStart       = 0x00000002
	serviceErrorNormal     = 0x00000001
	serviceAllAccess       = 0x000F01FF
	scManagerAllAccess     = 0x000F003F

	serviceStopped      = 0x00000001
	serviceStartPending = 0x00000002
	serviceStopPending  = 0x00000003
	serviceRunning      = 0x00000004

	serviceAcceptStop     = 0x00000001
	serviceAcceptShutdown = 0x00000004

	serviceControlStop        = 0x00000001
	serviceControlInterrogate = 0x00000004
	serviceControlShutdown    = 0x00000005

	serviceConfigDescription            = 1
	serviceConfigServiceSidInfo         = 5
	serviceConfigRequiredPrivilegesInfo = 6
	serviceSidTypeUnrestricted          = 1
	noError                             = 0

	seFileObject             = 1 // SE_OBJECT_TYPE SE_FILE_OBJECT
	ownerSecurityInformation = 0x00000001
	daclSecurityInformation  = 0x00000004
)

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

type serviceTableEntry struct {
	serviceName *uint16
	serviceProc uintptr
}

type serviceDescription struct {
	description *uint16
}

// serviceSidInfo is SERVICE_SID_INFO.
type serviceSidInfo struct {
	serviceSidType uint32
}

// serviceRequiredPrivilegesInfo is SERVICE_REQUIRED_PRIVILEGES_INFOW.
type serviceRequiredPrivilegesInfo struct {
	requiredPrivileges *uint16
}

// winACL is the header of an ACL; its ACEs follow it in memory.
type winACL struct {
	aclRevision byte
	sbz1        byte
	aclSize     uint16
	aceCount    uint16
	sbz2        uint16
}

var (
	advapi32                       = syscall.NewLazyDLL("advapi32.dll")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procStartServiceCtrlDispatcher = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandler = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus           = advapi32.NewProc("SetServiceStatus")
	procOpenSCManager              = advapi32.NewProc("OpenSCManagerW")
	procCreateService              = advapi32.NewProc("CreateServiceW")
	procOpenService                = advapi32.NewProc("OpenServiceW")
	procDeleteService              = advapi32.NewProc("DeleteService")
	procStartService               = advapi32.NewProc("StartServiceW")
	procControlService             = advapi32.NewProc("ControlService")
	procChangeServiceConfig2       = advapi32.NewProc("ChangeServiceConfig2W")
	procCloseServiceHandle         = advapi32.NewProc("CloseServiceHandle")
	procGetCurrentProcessId        = kernel32.NewProc("GetCurrentProcessId")
	procProcessIdToSessionId       = kernel32.NewProc("ProcessIdToSessionId")
	procGetSystemDirectory         = kernel32.NewProc("GetSystemDirectoryW")
	procGetNamedSecurityInfo       = advapi32.NewProc("GetNamedSecurityInfoW")
	procLocalFree                  = kernel32.NewProc("LocalFree")
)

var (
	activeSvcName   string
	activeStatusHdl uintptr
	activeStartFn   func()
	activeStopFn    func()
	svcStopDone     chan struct{}
)

func isWindowsServiceProcess() bool {
	pid, _, _ := procGetCurrentProcessId.Call()
	var sessionID uint32
	r1, _, _ := procProcessIdToSessionId.Call(pid, uintptr(unsafe.Pointer(&sessionID)))
	if r1 != 0 && sessionID == 0 {
		return true
	}
	return false
}

// currentUserSID returns the SID of the account running this process, or "".
func currentUserSID() string {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return ""
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return ""
	}
	return sid
}

// runningAsLocalSystem reports whether the process token belongs to LocalSystem
// (services installed by agent versions before 1.1.0).
func runningAsLocalSystem() bool {
	return currentUserSID() == sidLocalSystem
}

// readObjectSecurity reads the owner and the DACL of a file or folder.
func readObjectSecurity(path string) (objectSecurity, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return objectSecurity{}, err
	}
	var owner *syscall.SID
	var dacl *winACL
	var sd uintptr
	r, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		uintptr(unsafe.Pointer(&dacl)),
		0,
		uintptr(unsafe.Pointer(&sd)),
	)
	if r != 0 {
		return objectSecurity{}, syscall.Errno(r)
	}
	defer procLocalFree.Call(sd)
	var sec objectSecurity
	if owner != nil {
		if s, err := owner.String(); err == nil {
			sec.owner = s
		}
	}
	if dacl == nil {
		sec.nullDACL = true
		return sec, nil
	}
	// parseDACL copies what it keeps, so nothing refers to sd once it is freed.
	sec.grants, err = parseDACL(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), int(dacl.aclSize)))
	return sec, err
}

// accountName formats a SID as "DOMAIN\name (SID)" for messages.
func accountName(sid string) string {
	if sid == "" {
		return "no account"
	}
	s, err := syscall.StringToSid(sid)
	if err != nil {
		return sid
	}
	account, domain, _, err := s.LookupAccount("")
	if err != nil || account == "" {
		return sid
	}
	if domain != "" {
		account = domain + `\` + account
	}
	return account + " (" + sid + ")"
}

// configPermissionProblems lists how accounts other than SYSTEM,
// Administrators, TrustedInstaller, NT SERVICE\<serviceName> and the account
// running the agent can read or change config.json, or own it.
func configPermissionProblems(serviceName, configPath string) []string {
	check := newPermissionCheck(newSIDTrust(serviceSID(serviceName), currentUserSID()), readObjectSecurity, accountName)
	return check.configFile(configPath)
}

func setSvcStatus(state uint32, controls uint32, waitHint uint32) {
	if activeStatusHdl == 0 {
		return
	}
	st := serviceStatus{
		serviceType:      serviceWin32OwnProcess,
		currentState:     state,
		controlsAccepted: controls,
		win32ExitCode:    noError,
		waitHint:         waitHint,
	}
	_, _, _ = procSetServiceStatus.Call(activeStatusHdl, uintptr(unsafe.Pointer(&st)))
}

func svcCtrlHandler(control, eventType, eventData, context uintptr) uintptr {
	switch uint32(control) {
	case serviceControlStop, serviceControlShutdown:
		setSvcStatus(serviceStopPending, 0, 10000)
		if activeStopFn != nil {
			activeStopFn()
		}
		setSvcStatus(serviceStopped, 0, 0)
		select {
		case <-svcStopDone:
		default:
			close(svcStopDone)
		}
		return noError
	case serviceControlInterrogate:
		return noError
	}
	return noError
}

func svcMain(argc uintptr, argv uintptr) uintptr {
	namePtr, _ := syscall.UTF16PtrFromString(activeSvcName)
	hdl, _, _ := procRegisterServiceCtrlHandler.Call(
		uintptr(unsafe.Pointer(namePtr)),
		syscall.NewCallback(svcCtrlHandler),
		0,
	)
	if hdl == 0 {
		return 1
	}
	activeStatusHdl = hdl
	setSvcStatus(serviceStartPending, 0, 5000)
	if activeStartFn != nil {
		activeStartFn()
	}
	setSvcStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0)
	<-svcStopDone
	return 0
}

func runAsWindowsService(serviceName string, onStart func(), onStop func()) error {
	activeSvcName = serviceName
	activeStartFn = onStart
	activeStopFn = onStop
	svcStopDone = make(chan struct{})

	namePtr, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return err
	}
	table := []serviceTableEntry{
		{serviceName: namePtr, serviceProc: syscall.NewCallback(svcMain)},
		{serviceName: nil, serviceProc: 0},
	}
	r1, _, e1 := procStartServiceCtrlDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	if r1 == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcherW failed: %v", e1)
	}
	return nil
}

func quoteWinArg(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// systemTool returns the full path of a tool in the Windows system folder, so
// a copy planted in the current folder or on PATH is never run.
func systemTool(name string) (string, error) {
	buf := make([]uint16, syscall.MAX_PATH+1)
	n, _, err := procGetSystemDirectory.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) >= len(buf) {
		return "", fmt.Errorf("GetSystemDirectoryW failed: %v", err)
	}
	return filepath.Join(syscall.UTF16ToString(buf[:n]), name), nil
}

// runTool runs a Windows system tool and includes its output in the error.
func runTool(exe string, args ...string) error {
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v: %s", filepath.Base(exe), strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func pathEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(filepath.Clean(a), `\`), strings.TrimRight(filepath.Clean(b), `\`))
}

// pathWithin reports whether p is root or lies below root (case-insensitive).
func pathWithin(p, root string) bool {
	p = strings.ToLower(strings.TrimRight(filepath.Clean(p), `\`))
	root = strings.ToLower(strings.TrimRight(filepath.Clean(root), `\`))
	return root != "" && root != "." && (p == root || strings.HasPrefix(p, root+`\`))
}

func userProfileRoots() []string {
	var roots []string
	if v := os.Getenv("SystemDrive"); v != "" {
		roots = append(roots, v+`\Users`)
	}
	for _, env := range []string{"PUBLIC", "USERPROFILE"} {
		if v := os.Getenv(env); v != "" {
			roots = append(roots, filepath.Dir(v))
		}
	}
	return roots
}

// unsafeLogDirReason explains why the service must not get write access (an
// inheritable Modify grant) on dir: drive and share roots, the Windows folder,
// the shared Program Files / ProgramData folders themselves and user profiles.
// It returns "" when dir is acceptable.
func unsafeLogDirReason(dir string) string {
	candidates := []string{filepath.Clean(dir)}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		candidates = append(candidates, filepath.Clean(resolved))
	}
	for _, d := range candidates {
		if !filepath.IsAbs(d) {
			return "it is not an absolute path"
		}
		if pathEqual(d, filepath.VolumeName(d)+`\`) {
			return "it is a drive or share root"
		}
		if win := os.Getenv("SystemRoot"); win != "" && pathWithin(d, win) {
			return "it is inside the Windows folder"
		}
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"} {
			if v := os.Getenv(env); v != "" && pathEqual(d, v) {
				return "it is the shared %" + env + "% folder itself"
			}
		}
		for _, profiles := range userProfileRoots() {
			if pathWithin(d, profiles) {
				return "it is inside the user profiles folder"
			}
		}
	}
	return ""
}

// installPermissionProblems lists how accounts other than SYSTEM,
// Administrators, TrustedInstaller, the service account and the installing
// administrator could change what the service runs or trusts: scim-agent.exe,
// the CA files, the program, config and log folders and the folders above
// them. Program and config folders inside user profiles are refused as well,
// because programs running as that user can change them.
func installPermissionProblems(svcSID, exePath, configPath, logDir string, caFiles []string) []string {
	check := newPermissionCheck(newSIDTrust(svcSID, currentUserSID()), readObjectSecurity, accountName)
	problems := check.installTargets(exePath, configPath, logDir, caFiles)
	for _, f := range []struct{ what, dir string }{
		{"program folder", filepath.Dir(exePath)},
		{"config folder", filepath.Dir(configPath)},
	} {
		for _, profiles := range userProfileRoots() {
			if pathWithin(f.dir, profiles) {
				problems = append(problems, fmt.Sprintf("%s %s: it is inside the user profiles folder", f.what, f.dir))
				break
			}
		}
	}
	return problems
}

// installWindowsService registers the agent as an auto-start service that runs
// as the virtual account NT SERVICE\<serviceName> instead of LocalSystem, with
// only SeChangeNotifyPrivilege. It refuses to do so while accounts other than
// SYSTEM, Administrators, TrustedInstaller, the service and the installing
// administrator can change scim-agent.exe, the CA files or their folders, the
// config or log folder, or the folders above them, unless allowInsecure is set
// (allow_insecure_file_permissions in config.json); then it only warns. It
// then restricts config.json (agent token and local SCIM credentials) to
// SYSTEM and Administrators (full control) plus the service account (read),
// grants the service Modify on the log folder and read access to readableFiles
// (the configured CA files). If any step fails, the new service is deleted
// again.
func installWindowsService(serviceName, displayName, description, exePath, configPath, logPath string, allowInsecure bool, readableFiles ...string) error {
	if !validServiceName(serviceName) {
		return fmt.Errorf("invalid service name %q", serviceName)
	}
	icacls, err := systemTool("icacls.exe")
	if err != nil {
		return err
	}
	svcSID := serviceSID(serviceName)

	logDir := ""
	if logPath != "" {
		logDir = filepath.Dir(logPath)
		if reason := unsafeLogDirReason(logDir); reason != "" {
			return fmt.Errorf("will not grant the service write access to the log folder %s because %s; set log_file to a dedicated folder such as C:\\ProgramData\\IdentityCloudScimAgent\\logs\\scim-agent.log", logDir, reason)
		}
	}

	// Fail before creating anything when not elevated, so that the log folder
	// is never created (and owned) by a non-elevated user.
	scm, _, err := procOpenSCManager.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManager failed (run Command Prompt / PowerShell as Administrator): %v", err)
	}
	defer procCloseServiceHandle.Call(scm)

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0700); err != nil {
			return fmt.Errorf("cannot create the log folder %s: %w", logDir, err)
		}
		if reason := unsafeLogDirReason(logDir); reason != "" { // re-check with links resolved
			return fmt.Errorf("will not grant the service write access to the log folder %s because %s", logDir, reason)
		}
	}

	var caFiles []string
	for _, f := range readableFiles {
		if f != "" && !pathEqual(f, configPath) {
			caFiles = append(caFiles, f)
		}
	}
	if problems := installPermissionProblems(svcSID, exePath, configPath, logDir, caFiles); len(problems) > 0 {
		list := "\n  - " + strings.Join(problems, "\n  - ")
		if !allowInsecure {
			return fmt.Errorf("refusing to install: accounts other than SYSTEM, Administrators, TrustedInstaller, NT SERVICE\\%s and you could change files the service runs or trusts:%s\n"+
				"Restrict these files and folders (see \"Where to put the files\" in README.md), or set \"allow_insecure_file_permissions\": true in config.json to install anyway", serviceName, list)
		}
		fmt.Fprintf(os.Stderr, "WARNING: installing although other accounts could change files the service runs or trusts, because allow_insecure_file_permissions is set:%s\n", list)
	}
	if logDir != "" && pathEqual(logDir, filepath.Dir(exePath)) {
		fmt.Fprintf(os.Stderr, "NOTE: the log folder is the program folder, so the service account may modify files there, scim-agent.exe included. A dedicated log folder such as C:\\ProgramData\\IdentityCloudScimAgent\\logs is preferable.\n")
	}

	binCmd := quoteWinArg(exePath) + " -config " + quoteWinArg(configPath)
	svcNamePtr, _ := syscall.UTF16PtrFromString(serviceName)
	dispPtr, _ := syscall.UTF16PtrFromString(displayName)
	binPtr, _ := syscall.UTF16PtrFromString(binCmd)
	acctPtr, _ := syscall.UTF16PtrFromString(`NT SERVICE\` + serviceName)

	svc, _, createErr := procCreateService.Call(
		scm,
		uintptr(unsafe.Pointer(svcNamePtr)),
		uintptr(unsafe.Pointer(dispPtr)),
		serviceAllAccess,
		serviceWin32OwnProcess,
		serviceAutoStart,
		serviceErrorNormal,
		uintptr(unsafe.Pointer(binPtr)),
		0,                                // lpLoadOrderGroup
		0,                                // lpdwTagId
		0,                                // lpDependencies
		uintptr(unsafe.Pointer(acctPtr)), // lpServiceStartName: the virtual service account
		0,                                // lpPassword: none for virtual accounts
	)
	if svc == 0 {
		return fmt.Errorf("CreateServiceW failed: %v", createErr)
	}
	defer procCloseServiceHandle.Call(svc)

	installed := false
	defer func() {
		if !installed {
			_, _, _ = procDeleteService.Call(svc)
		}
	}()

	descPtr, _ := syscall.UTF16PtrFromString(description)
	sd := serviceDescription{description: descPtr}
	_, _, _ = procChangeServiceConfig2.Call(svc, serviceConfigDescription, uintptr(unsafe.Pointer(&sd)))

	sidInfo := serviceSidInfo{serviceSidType: serviceSidTypeUnrestricted}
	if r1, _, e1 := procChangeServiceConfig2.Call(svc, serviceConfigServiceSidInfo, uintptr(unsafe.Pointer(&sidInfo))); r1 == 0 {
		return fmt.Errorf("setting the service SID type failed: %v", e1)
	}
	// Keep only SeChangeNotifyPrivilege (no SeImpersonatePrivilege and the
	// like) for a process that acts on remote input.
	privs, _ := syscall.UTF16FromString("SeChangeNotifyPrivilege")
	privs = append(privs, 0) // REG_MULTI_SZ: double NUL terminated
	reqPrivs := serviceRequiredPrivilegesInfo{requiredPrivileges: &privs[0]}
	r1, _, e1 := procChangeServiceConfig2.Call(svc, serviceConfigRequiredPrivilegesInfo, uintptr(unsafe.Pointer(&reqPrivs)))
	runtime.KeepAlive(privs)
	if r1 == 0 {
		return fmt.Errorf("restricting the service privileges failed: %v", e1)
	}

	if logDir != "" {
		if err := runTool(icacls, logDir, "/grant:r", "*"+svcSID+":(OI)(CI)M"); err != nil {
			return err
		}
	}

	// CA files hold public certificates; the service must be able to read them
	// even when they sit in a folder restricted to Administrators.
	for _, f := range caFiles {
		if err := runTool(icacls, f, "/grant:r", "*"+svcSID+":R"); err != nil {
			return err
		}
	}

	// Remove inherited and explicit entries from config.json, then allow only
	// SYSTEM and Administrators (full control) and the service (read), with
	// Administrators as owner.
	if err := runTool(icacls, configPath, "/reset"); err != nil {
		return err
	}
	if err := runTool(icacls, configPath, "/inheritance:r", "/grant:r",
		"*"+sidLocalSystem+":F", "*"+sidAdministrators+":F", "*"+svcSID+":R"); err != nil {
		return err
	}
	if err := runTool(icacls, configPath, "/setowner", "*"+sidAdministrators); err != nil {
		return err
	}

	installed = true
	return nil
}

func uninstallWindowsService(serviceName string) error {
	_ = stopWindowsService(serviceName)
	scm, _, err := procOpenSCManager.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManager failed (run as Administrator): %v", err)
	}
	defer procCloseServiceHandle.Call(scm)

	svcNamePtr, _ := syscall.UTF16PtrFromString(serviceName)
	svc, _, openErr := procOpenService.Call(scm, uintptr(unsafe.Pointer(svcNamePtr)), serviceAllAccess)
	if svc == 0 {
		return fmt.Errorf("OpenServiceW failed: %v", openErr)
	}
	defer procCloseServiceHandle.Call(svc)

	r1, _, delErr := procDeleteService.Call(svc)
	if r1 == 0 {
		return fmt.Errorf("DeleteService failed: %v", delErr)
	}
	return nil
}

func startWindowsService(serviceName string) error {
	scm, _, err := procOpenSCManager.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManager failed (run as Administrator): %v", err)
	}
	defer procCloseServiceHandle.Call(scm)

	svcNamePtr, _ := syscall.UTF16PtrFromString(serviceName)
	svc, _, openErr := procOpenService.Call(scm, uintptr(unsafe.Pointer(svcNamePtr)), serviceAllAccess)
	if svc == 0 {
		return fmt.Errorf("OpenServiceW failed: %v", openErr)
	}
	defer procCloseServiceHandle.Call(svc)

	r1, _, startErr := procStartService.Call(svc, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("StartServiceW failed: %v", startErr)
	}
	return nil
}

func stopWindowsService(serviceName string) error {
	scm, _, err := procOpenSCManager.Call(0, 0, scManagerAllAccess)
	if scm == 0 {
		return fmt.Errorf("OpenSCManager failed (run as Administrator): %v", err)
	}
	defer procCloseServiceHandle.Call(scm)

	svcNamePtr, _ := syscall.UTF16PtrFromString(serviceName)
	svc, _, openErr := procOpenService.Call(scm, uintptr(unsafe.Pointer(svcNamePtr)), serviceAllAccess)
	if svc == 0 {
		return fmt.Errorf("OpenServiceW failed: %v", openErr)
	}
	defer procCloseServiceHandle.Call(svc)

	var st serviceStatus
	r1, _, ctrlErr := procControlService.Call(svc, serviceControlStop, uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		return fmt.Errorf("ControlService(STOP) failed: %v", ctrlErr)
	}
	time.Sleep(500 * time.Millisecond)
	return nil
}
