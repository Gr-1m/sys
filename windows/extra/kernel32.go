package extra

import (
	wincall "golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

//const (
//	// end_access
//	MEM_COMMIT   = 0x1000
//	MEM_RESERVE  = 0x2000
//	MEM_RESET    = 0x00080000
//	MEM_DECOMMIT = 0x00004000
//	MEM_RELEASE  = 0x00008000
//	MEM_FREE     = 0x00010000
//
//	// Process dwCreationFlag values
//	DEBUG_PROCESS           = 0x00000001
//	DEBUG_ONLY_THIS_PROCESS = 0x00000002
//	CREATE_SUSPENDED        = 0x00000004
//	DETACHED_PROCESS        = 0x00000008
//	CREATE_NEW_CONSOLE      = 0x00000010
//
//	// OpenProcess dwDesiredAccess values
//	PROCESS_TERMINATE                 = 0x0001
//	PROCESS_CREATE_THREAD             = 0x0002
//	PROCESS_SET_SESSIONID             = 0x0004
//	PROCESS_VM_OPERATION              = 0x0008
//	PROCESS_VM_READ                   = 0x0010
//	PROCESS_VM_WRITE                  = 0x0020
//	PROCESS_DUP_HANDLE                = 0x0040
//	PROCESS_CREATE_PROCESS            = 0x0080
//	PROCESS_SET_QUOTA                 = 0x0100
//	PROCESS_SET_INFORMATION           = 0x0200
//	PROCESS_QUERY_INFORMATION         = 0x0400
//	PROCESS_SUSPEND_RESUME            = 0x0800
//	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
//	PROCESS_SET_LIMITED_INFORMATION   = 0x2000
//	PROCESS_ALL_ACCESS                = wincall.STANDARD_RIGHTS_REQUIRED | wincall.SYNCHRONIZE | 0xFFFF
//)

var (

	// In Kernel API
	procGetModuleHandle      = modkernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc          = modkernel32.NewProc("GlobalAlloc")
	procGlobalFree           = modkernel32.NewProc("GlobalFree")
	procGlobalLock           = modkernel32.NewProc("GlobalLock")
	procGlobalUnlock         = modkernel32.NewProc("GlobalUnlock")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")

	procVirtualAlloc       = modkernel32.NewProc("VirtualAlloc")
	procVirtualAllocEx     = modkernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = modkernel32.NewProc("VirtualFreeEx")
	procVirtualProtect     = modkernel32.NewProc("VirtualProtect")
	procReadProcessMemory  = modkernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
	procRtlCopyMemory      = modkernel32.NewProc("RtlCopyMemory")

	procIsDebuggerPresent          = modkernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = modkernel32.NewProc("CheckRemoteDebuggerPresent")
	procOutputDebugStringW         = modkernel32.NewProc("OutputDebugStringW")
)

func GlobalAlloc(uFlags uint32, dwSize *uint32) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGlobalAlloc.Addr(), uintptr(uFlags), uintptr(unsafe.Pointer(dwSize)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}
func GlobalFree(hMem uintptr) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGlobalFree.Addr(), hMem)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func GlobalLock(hMem uintptr) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGlobalLock.Addr(), hMem)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func GlobalUnlock(hMem uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procGlobalUnlock.Addr(), hMem)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func GlobalMemoryStatusEx(lpBuffer *MemoryStatusEX) (err error) {
	r1, _, e1 := syscall.SyscallN(procGlobalMemoryStatusEx.Addr(), uintptr(unsafe.Pointer(lpBuffer)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func VirtualProtect(lpAddress, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualProtect.Addr(), lpAddress, dwSize, uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func VirtualAlloc(lpAddress, dwSize uintptr, flAllocationType, flProtect uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAlloc.Addr(), lpAddress, dwSize, uintptr(flAllocationType), uintptr(flProtect))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func VirtualAllocEx(hProcess wincall.Handle, lpAddress uintptr, dwSize *uint32, flAllocationType, flProtect uint32) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAllocEx.Addr(), uintptr(hProcess), lpAddress, uintptr(unsafe.Pointer(dwSize)), uintptr(flAllocationType), uintptr(flProtect))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func VirtualFreeEx(hProcess wincall.Handle, lpAddress uintptr, dwSize *uint32, dwFreeType uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualFreeEx.Addr(), uintptr(hProcess), lpAddress, uintptr(unsafe.Pointer(dwSize)), uintptr(dwFreeType))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func ReadProcessMemory(hProcess wincall.Handle, lpBaseAddr uintptr, lpBuffer *byte, nSize uint32, lpNumberOfBytesRead *uint16) (err error) {
	//wincall.ReadProcessMemory()
	r1, _, e1 := syscall.SyscallN(procReadProcessMemory.Addr(),
		uintptr(hProcess),
		lpBaseAddr,
		uintptr(unsafe.Pointer(lpBuffer)),
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func WriteProcessMemory(hProcess wincall.Handle, lpBaseAddr uintptr, lpBuffer *byte, nSize uint32, lpNumberOfBytesRead *uint16) (err error) {
	//wincall.WriteProcessMemory()
	r1, _, e1 := syscall.SyscallN(procWriteProcessMemory.Addr(),
		uintptr(hProcess),
		lpBaseAddr,
		uintptr(unsafe.Pointer(lpBuffer)),
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func RtlCopyMemory(dst, src uintptr, length uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procRtlCopyMemory.Addr(), dst, src, uintptr(length))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func CreateRemoteThread(hProcess wincall.Handle, lpThreadAttributes *wincall.SecurityAttributes, dwStackSize uint32, lpStartAddress wincall.Handle, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (tHandle wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWriteProcessMemory.Addr(),
		uintptr(hProcess),
		uintptr(unsafe.Pointer(lpThreadAttributes)),
		uintptr(dwStackSize),
		uintptr(lpStartAddress),
		uintptr(dwCreationFlags),
		lpParameter,
		uintptr(unsafe.Pointer(lpThreadId)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		tHandle = wincall.Handle(r1)
	}

	return
}

func IsDebuggerPresent() bool {
	r1, _, e1 := syscall.SyscallN(procIsDebuggerPresent.Addr())
	_ = errnoErr(e1)

	return r1 != 0
}

func CheckRemoteDebuggerPresent(hProcess wincall.Handle, pbDebuggerPresent *bool) (err error) {
	r1, _, e1 := syscall.SyscallN(procCheckRemoteDebuggerPresent.Addr(), uintptr(hProcess), uintptr(unsafe.Pointer(pbDebuggerPresent)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func OutputDebugString(lpOutputStr *uint16) (err error) {
	r1, _, e1 := syscall.SyscallN(procCheckRemoteDebuggerPresent.Addr(), uintptr(unsafe.Pointer(lpOutputStr)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return

}
