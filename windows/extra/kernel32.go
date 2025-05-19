package extra

import (
	wincall "github.com/Gr-1m/sys/windows"
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

	procVirtualAllocEx     = modkernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = modkernel32.NewProc("VirtualFreeEx")
	procRtlCopyMemory      = modkernel32.NewProc("RtlCopyMemory")
	procCreateRemoteThread = modkernel32.NewProc("CreateRemoteThread")

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

// Use wincall VirtualProtect
//func VirtualProtect(lpAddress, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {}

// Use wincall VirtualAlloc
func VirtualAlloc(lpAddress, dwSize uintptr, flAllocationType, flProtect uint32) (value uintptr,err error) {
	return wincall.VirtualAlloc(lpAddress,dwSize,flAllocationType,flProtect)
}

func VirtualAllocEx(hProcess wincall.Handle, lpAddress , dwSize uintptr, flAllocationType, flProtect uint32) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAllocEx.Addr(), uintptr(hProcess), lpAddress, dwSize, uintptr(flAllocationType), uintptr(flProtect))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func VirtualFreeEx(hProcess wincall.Handle,  lpAddress , dwSize uintptr, dwFreeType uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualFreeEx.Addr(), uintptr(hProcess), lpAddress, dwSize, uintptr(dwFreeType))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

// Use wincall ReadProcessMemory
//func ReadProcessMemory(hProcess wincall.Handle, lpBaseAddr uintptr, lpBuffer *byte, nSize uint32, lpNumberOfBytesRead *uint16) (err error) {}

// Use wincall WriteProcessMemory
//func WriteProcessMemory(hProcess wincall.Handle, lpBaseAddr uintptr, lpBuffer *byte, nSize uint32, lpNumberOfBytesRead *uint16) (err error) {}

func RtlCopyMemory(dst, src uintptr, length uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procRtlCopyMemory.Addr(), dst, src, uintptr(length))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

// TODO: lpStartAddress LPTHREAD_START_ROUTINE
func CreateRemoteThread(hProcess wincall.Handle, lpThreadAttributes *wincall.SecurityAttributes, dwStackSize , lpStartAddress uintptr, lpParameter uintptr,dwCreationFlags uint32, lpThreadId *uint32)(r1 uintptr,err error){
	r1,_,e1:= syscall.SyscallN(procCreateRemoteThread.Addr(),uintptr(hProcess), uintptr(unsafe.Pointer(lpThreadAttributes)), dwStackSize, lpStartAddress, lpParameter, uintptr(dwCreationFlags), uintptr(unsafe.Pointer(lpThreadId)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

// Use wincall WriteProcessMemory
//func WriteProcessMemory(hProcess wincall.Handle, lpThreadAttributes *wincall.SecurityAttributes, dwStackSize uint32, lpStartAddress wincall.Handle, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (tHandle wincall.Handle, err error) {}

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
