package extra

// Service Table
const (
	// Service Types
	//SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	//SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	//SERVICE_WIN32               = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
	SERVICE_USER_SERVICE        = 0x00000040
	//SERVICE_INTERACTIVE_PROCESS = 0x00000100

	// Service State -- for CurrentState
	//SERVICE_STOPPED          = 0x00000001
	//SERVICE_START_PENDING    = 0x00000002
	//SERVICE_STOP_PENDING     = 0x00000003
	//SERVICE_RUNNING          = 0x00000004
	//SERVICE_CONTINUE_PENDING = 0x00000005
	//SERVICE_PAUSE_PENDING    = 0x00000006
	//SERVICE_PAUSED           = 0x00000007

	// Service object specific access type
	//SERVICE_QUERY_CONFIG         = 0x0001
	//SERVICE_CHANGE_CONFIG        = 0x0002
	//SERVICE_QUERY_STATUS         = 0x0004
	//SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	//SERVICE_START                = 0x0010
	//SERVICE_STOP                 = 0x0020
	//SERVICE_PAUSE_CONTINUE       = 0x0040
	//SERVICE_INTERROGATE          = 0x0080
	//SERVICE_USER_DEFINED_CONTROL = 0x0100
	SERVICE_ALL_ACCESS           = 0xF01FF // ALL of (Service object specific access type) | ()

	// Service Control Manager object specific access types
	//SC_MANAGER_CONNECT            = 0x0001
	//SC_MANAGER_CREATE_SERVICE     = 0x0002
	//SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
	//SC_MANAGER_LOCK               = 0x0008
	//SC_MANAGER_QUERY_LOCK_STATUS  = 0x0010
	//SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
	//SC_MANAGER_ALL_ACCESS         = 0xF003F // ALL of (SCM object specific access type) | ()

	//SERVICE_ERROR_NORMAL = 0x00000001
	//SERVICE_AUTO_START   = 0x00000002
	//SERVICE_DEMAND_START = 0x00000003

	// Controls Accepted  (Bit Mask)
	//SERVICE_ACCEPT_STOP           = 0x00000001
	//SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002
	//SERVICE_ACCEPT_SHUTDOWN       = 0x00000004

	// Controls
	SERVICE_CONTROL_TIMECHANGE            = 0x00000010
)

// Service Start Table
//type ServiceTableEntry struct {
//	LpServiceName *uint16
//	LpServiceProc uintptr // func(dwNumServicesArgs uint32, lpServiceArgVectors uintptr)
//}
//
//type ServiceStatus struct {
//	DwServiceType             uint32
//	dwCurrentState            uint32
//	DwControlsAccepted        uint32
//	DwWin32ExitCode           uint32
//	DwServiceSpecificExitCode uint32
//	DwCheckPoint              uint32
//	DwWaitHint                uint32
//}
//
//func (s *ServiceStatus) SetCurrentState(dwStatus uint32) {
//	s.dwCurrentState = dwStatus
//	return
//}
