package extra

import (
	wincall "github.com/Gr-1m/sys/windows"
	"syscall"
	"unsafe"
)

type ProcessInformationClass any

var (
	ProcessBasicInformation ProcessInformationClass = wincall.ProcessBasicInformation
)
var(
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
)

func NtQueryInformationProcess(hProcess wincall.Handle, information wincall.PROCESS_BASIC_INFORMATION, pbi wincall.ProcessInformation, returnLength uint32) (err error){
	r1,_,e1:= syscall.SyscallN(procNtQueryInformationProcess.Addr(),
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&information)),
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&returnLength)),
		)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}