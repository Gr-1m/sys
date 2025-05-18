package extra

import (
	wincall "golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	// Privilege attributes, wincall
	//SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	//SE_PRIVILEGE_ENABLED            = 0x00000002
	//SE_PRIVILEGE_REMOVED            = 0x00000004
	//SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
	//SE_PRIVILEGE_VALID_ATTRIBUTES   = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS

	// NT Defined Privileges
	SE_CREATE_TOKEN_NAME                      = "SeCreateTokenPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME                = "SeAssignPrimaryTokenPrivilege"
	SE_LOCK_MEMORY_NAME                       = "SeLockMemoryPrivilege"
	SE_INCREASE_QUOTA_NAME                    = "SeIncreaseQuotaPrivilege"
	SE_UNSOLICITED_INPUT_NAME                 = "SeUnsolicitedInputPrivilege"
	SE_MACHINE_ACCOUNT_NAME                   = "SeMachineAccountPrivilege"
	SE_TCB_NAME                               = "SeTcbPrivilege"
	SE_SECURITY_NAME                          = "SeSecurityPrivilege"
	SE_TAKE_OWNERSHIP_NAME                    = "SeTakeOwnershipPrivilege"
	SE_LOAD_DRIVER_NAME                       = "SeLoadDriverPrivilege"
	SE_SYSTEM_PROFILE_NAME                    = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME                        = "SeSystemtimePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME               = "SeProfileSingleProcessPrivilege"
	SE_INC_BASE_PRIORITY_NAME                 = "SeIncreaseBasePriorityPrivilege"
	SE_CREATE_PAGEFILE_NAME                   = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME                  = "SeCreatePermanentPrivilege"
	SE_BACKUP_NAME                            = "SeBackupPrivilege"
	SE_RESTORE_NAME                           = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME                          = "SeShutdownPrivilege"
	SE_DEBUG_NAME                             = "SeDebugPrivilege"
	SE_AUDIT_NAME                             = "SeAuditPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME                = "SeSystemEnvironmentPrivilege"
	SE_CHANGE_NOTIFY_NAME                     = "SeChangeNotifyPrivilege"
	SE_REMOTE_SHUTDOWN_NAME                   = "SeRemoteShutdownPrivilege"
	SE_UNDOCK_NAME                            = "SeUndockPrivilege"
	SE_SYNC_AGENT_NAME                        = "SeSyncAgentPrivilege"
	SE_ENABLE_DELEGATION_NAME                 = "SeEnableDelegationPrivilege"
	SE_MANAGE_VOLUME_NAME                     = "SeManageVolumePrivilege"
	SE_IMPERSONATE_NAME                       = "SeImpersonatePrivilege"
	SE_CREATE_GLOBAL_NAME                     = "SeCreateGlobalPrivilege"
	SE_TRUSTED_CREDMAN_ACCESS_NAME            = "SeTrustedCredManAccessPrivilege"
	SE_RELABEL_NAME                           = "SeRelabelPrivilege"
	SE_INC_WORKING_SET_NAME                   = "SeIncreaseWorkingSetPrivilege"
	SE_TIME_ZONE_NAME                         = "SeTimeZonePrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME              = "SeCreateSymbolicLinkPrivilege"
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege"
)

const (
	// Logon Support APIs
	LOGON32_PROVIDER_DEFAULT = uint32(iota)
	LOGON32_PROVIDER_WINNT35
	LOGON32_LOGON_INTERACTIVE
	LOGON32_LOGON_NETWORK
	LOGON32_LOGON_BATCH
	LOGON32_LOGON_SERVICE
	LOGON32_LOGON_UNLOCK = iota + 1

	// LogonFlags
	LOGON_WITH_PROFILE         uint32 = 0x00000001
	LOGON_NETCREDENTIALS_ONLY  uint32 = 0x00000002
	LOGON_ZERO_PASSWORD_BUFFER uint32 = 0x80000000
)

var (
	// Regedit API
	procRegCreateKeyEx = modadvapi32.NewProc("RegCreateKeyExW")
	procRegEnumValueEx = modadvapi32.NewProc("RegEnumValueW")
	procRegSetValueEx  = modadvapi32.NewProc("RegSetValueExW")

	// Service API
	procControlServiceEx           = modadvapi32.NewProc("ControlServiceExW")
	procDeleteService              = modadvapi32.NewProc("DeleteServiceW")

	//
	procLogonUser               = modadvapi32.NewProc("LogonUserW")
	procCreateProcessWithToken  = modadvapi32.NewProc("CreateProcessWithTokenW")
	procImpersonateLoggedOnUser = modadvapi32.NewProc("ImpersonateLoggedOnUser")
)

func LogonUser(lpszUsername, lpszDomain, lpszPassword string, dwLogonType, dwLogonProvider uint32, phToken *wincall.Token) (err error) {
	r1, _, e1 := syscall.SyscallN(procLogonUser.Addr(),
		uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpszUsername))),
		uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpszDomain))),
		uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpszPassword))),
		uintptr(dwLogonType),
		uintptr(dwLogonProvider),
		uintptr(unsafe.Pointer(phToken)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func DuplicateTokenEx(hExistingToken wincall.Token, dwDesireAccess uint32, lpTokenAttr *wincall.SecurityAttributes, impersonationLevel, tokenType uint32, phNewToken *wincall.Token) (err error) {
	return wincall.DuplicateTokenEx(hExistingToken,dwDesireAccess,lpTokenAttr,impersonationLevel,tokenType,phNewToken)
	//r1, _, e1 := syscall.SyscallN(procDuplicateTokenEx.Addr(),
	//	uintptr(hExistingToken),
	//	uintptr(dwDesireAccess),
	//	uintptr(unsafe.Pointer(lpTokenAttr)),
	//	uintptr(impersonationLevel),
	//	uintptr(tokenType),
	//	uintptr(unsafe.Pointer(phNewToken)),
	//)
	//if r1 == 0 {
	//	err = errnoErr(e1)
	//}
	//
	//return
}

func RegCreateKeyEx(hKey wincall.Handle, lpSubKey *uint16, Reserved DWORD, lpClass LPCWSTR, dwOptions, samDesired DWORD, lpSecurityAttr *wincall.SecurityAttributes, phkResult *wincall.Handle, lpdwDisposition *DWORD) (err error) {
	r1, _, e1 := syscall.SyscallN(procRegCreateKeyEx.Addr(),
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpSubKey)),
		uintptr(Reserved),
		uintptr(unsafe.Pointer(lpClass)),
		uintptr(dwOptions),
		uintptr(samDesired),
		uintptr(unsafe.Pointer(lpSecurityAttr)),
		uintptr(unsafe.Pointer(phkResult)),
		uintptr(unsafe.Pointer(lpdwDisposition)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

// RegOpenKeyEx = syscall.RegOpenKeyEx
// RegCloseKey = syscall.RegCloseKey
// TODO:
func RegEnumValue(hKey wincall.Handle, dwIndex uint32, lpValueName *uint16, lpcchValueName, lpReserved, dwType *uint32, lpData LPBYTE, lpcbData *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procRegEnumValueEx.Addr(),
		uintptr(hKey),
		uintptr(dwIndex),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(unsafe.Pointer(lpcchValueName)),
		uintptr(unsafe.Pointer(lpReserved)),
		uintptr(unsafe.Pointer(dwType)),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(unsafe.Pointer(lpcbData)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RegSetValueEx(hKey wincall.Handle, lpValueName LPCWSTR, Reserved, dwType DWORD, lpData LPBYTE, cbData DWORD) (err error) {
	r1, _, e1 := syscall.SyscallN(procRegSetValueEx.Addr(),
		uintptr(hKey),
		uintptr(unsafe.Pointer(lpValueName)),
		uintptr(Reserved),
		uintptr(dwType),
		uintptr(unsafe.Pointer(lpData)),
		uintptr(cbData),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenSCManager(lpMachineName, lpDatabaseName *uint16, dwDesiredAccess uint32) (handle wincall.Handle, err error) {
	return wincall.OpenSCManager(lpMachineName, lpDatabaseName, dwDesiredAccess)
	//r1, _, e1 := syscall.SyscallN(procOpenSCManager.Addr(), uintptr(unsafe.Pointer(lpMachineName)), uintptr(unsafe.Pointer(lpDatabaseName)), uintptr(dwDesiredAccess))
	//if r1 == 0 {
	//	err = errnoErr(e1)
	//} else {
	//	handle = wincall.Handle(r1)
	//}
	//
	//return
}

// Use wincall CreateService
//func CreateService(hSCManager wincall.Handle, lpServiceName, lpDisplayName *uint16, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl uint32,
//	lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword *uint16) (handle wincall.Handle, err error) {
//	// wincall.CreateService()
//	r1, _, e1 := syscall.SyscallN(procCreateService.Addr(),
//		uintptr(hSCManager),
//		uintptr(unsafe.Pointer(lpServiceName)),
//		uintptr(unsafe.Pointer(lpDisplayName)),
//		uintptr(dwDesiredAccess),
//		uintptr(dwServiceType),
//		uintptr(dwStartType),
//		uintptr(dwErrorControl),
//		uintptr(unsafe.Pointer(lpBinaryPathName)),
//		uintptr(unsafe.Pointer(lpLoadOrderGroup)),
//		uintptr(unsafe.Pointer(lpdwTagId)),
//		uintptr(unsafe.Pointer(lpDependencies)),
//		uintptr(unsafe.Pointer(lpServiceStartName)),
//		uintptr(unsafe.Pointer(lpPassword)),
//	)
//	if r1 == 0 {
//		err = errnoErr(e1)
//	} else {
//		handle = wincall.Handle(r1)
//	}
//
//	return
//}

// Use wincall OpenService
func OpenService(hSCManager wincall.Handle, lpServiceName *uint16, dwDesiredAccess uint32) (handle wincall.Handle, err error) {
	return wincall.OpenService(hSCManager,lpServiceName,dwDesiredAccess)
	//r1, _, e1 := syscall.SyscallN(procOpenService.Addr(), uintptr(hSCManager), uintptr(unsafe.Pointer(lpServiceName)), uintptr(dwDesiredAccess))
	//if r1 == 0 {
	//	err = errnoErr(e1)
	//} else {
	//	handle = wincall.Handle(r1)
	//}
	//
	//return
}

// Use wincall StartService
//func StartService(hService wincall.Handle, dwNumServiceArgs uint32, lpServiceArgVectors *int16) (err error) {}

// Use wincall ControlService
func ControlService(hService wincall.Handle, dwControl uint32, pControlParam *wincall.SERVICE_STATUS) (err error) {
	return wincall.ControlService(hService,dwControl,pControlParam)
	//r1, _, e1 := syscall.SyscallN(procControlService.Addr(), uintptr(hService), uintptr(dwControl), uintptr(unsafe.Pointer(pControlParam)))
	//if r1 == 0 {
	//	err = errnoErr(e1)
	//}
	//
	//return
}

func ControlServiceEx(hService wincall.Handle, dwControl, dwInfoLevel uint32, pControlParam *wincall.SERVICE_STATUS) (err error) {
	r1, _, e1 := syscall.SyscallN(procControlServiceEx.Addr(), uintptr(hService), uintptr(dwControl), uintptr(dwInfoLevel), uintptr(unsafe.Pointer(pControlParam)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func DeleteService(hService wincall.Handle) (err error) {
	//return wincall.DeleteService(hService)
	r1, _, e1 := syscall.SyscallN(procDeleteService.Addr(), uintptr(hService))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}
// Use wincall RegisterServiceCtrlHandler
//func RegisterServiceCtrlHandler(lpServiceName *uint16, lpHandlerProc uintptr) (r1 uintptr, err error) {}

// Use wincall SetServiceStatus
//func SetServiceStatus(hServiceStatus wincall.Handle, lpServiceStatus *ServiceStatus) (err error) {}

// Use wincall StartServiceCtrlDispatcher
//func StartServiceCtrlDispatcher(serviceTable []ServiceTableEntry) (err error) {}

// Use wincall CloseServiceHandle
//func CloseServiceHandle(hSCObject wincall.Handle) (err error) {}

// Use wincall LookupPrivilegeValue
//func LookupPrivilegeValue(lpSystemName, lpName *uint16, lpLuid *wincall.LUID) (err error) {}

// Use wincall AdjustTokenPrivileges
//func AdjustTokenPrivileges(TokenHandle wincall.Token, DisableAllPrivileges bool, NewState *TokenPrivilegeS, BufferLength uint32, PreviousState *TokenPrivilegeS, ReturnLength *uint32) (err error) {}

func CreateProcessWithToken(token wincall.Token, dwLogonFlags uint32, appName *uint16, commandLine *uint16, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *wincall.StartupInfo, outProcInfo *wincall.ProcessInformation) (err error) {
	r1, _, e1 := syscall.SyscallN(procCreateProcessWithToken.Addr(),
		uintptr(token),
		uintptr(dwLogonFlags),
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(outProcInfo)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func ImpersonateLoggedOnUser(token wincall.Token) (err error) {
	r1, _, e1 := syscall.Syscall(procImpersonateLoggedOnUser.Addr(), 1, uintptr(token), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}
