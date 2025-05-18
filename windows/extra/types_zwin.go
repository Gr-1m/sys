package extra

import (
	"syscall"
	"unsafe"
)

// U
const (
	// Windows Error
	ERROR_SUCCESS syscall.Errno = 0

	CF_TEXT        = 1
	CF_UNICODETEXT = 13
	CW_USEDEFAULT  = ^uintptr(uint32(0))

	HC_ACTION = 0

	WS_EX_APPWINDOW = 0x00040000
	WS_POPUP        = 0x80000000
)

type (
	LONG   = int32
	ULONG  = uint32
	WORD   = uint16
	DWORD  = uint32
	HKEY   = uintptr
	LPARAM = uintptr
	WPARAM = uintptr

	LPCWSTR = *uint16
	LPCTSTR = *uint16
	LPTSTR  = *uint16
	LPDWORD = *uint32
	LPBYTE  = *byte

	SIZE_T = *uint32
	LPVOID = unsafe.Pointer
	HANDLE = syscall.Handle
)

type Point struct {
	X, Y int32
}

type MSG struct {
	Pt      Point
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
}

type MemoryStatusEX struct {
	DwLength                uint32
	DwMemoryLoad            uint32
	UllTotalPhys            uint64
	UllAvailPhys            uint64
	UllTotalPageFile        uint64
	UllAvailPageFile        uint64
	UllTotalVirtual         uint64
	UllAvailVirtual         uint64
	UllAvailExtendedVirtual uint64

	//SzReserved              [216]byte
}

// WindowClassEX Windows
type WindowClassEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type BitMapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// Callback Initialize a WindowsClassEx for register
type Callback func(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr

func InitWindowClassEx(cb Callback, hInstance uintptr, lpClassName string) (ex *WindowClassEX) {
	ex = &WindowClassEX{
		CbSize:        uint32(unsafe.Sizeof(WindowClassEX{})),
		Style:         0,
		LpfnWndProc:   syscall.NewCallback(cb),
		CbClsExtra:    0,
		CbWndExtra:    0,
		HInstance:     hInstance,
		HIcon:         0,
		HCursor:       0,
		HbrBackground: 0,
		LpszMenuName:  nil,
		LpszClassName: syscall.StringToUTF16Ptr(lpClassName),
		HIconSm:       0,
	}

	return
}

// Privileges

type LUID struct {
	LowPart  uint32
	HighPart uint32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

type TokenPrivilegeS struct {
	PrivilegeCount uint32
	Privileges     [1]LUIDAndAttributes
}
