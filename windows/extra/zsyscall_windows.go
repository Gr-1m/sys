package extra

import (
	"github.com/Gr-1m/sys/windows/extra/sysdll"
	"fmt"
	wincall "golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = wincall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e wincall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	//libgdi32    = syscall.NewLazyDLL(sysdll.Add("gdi32.dll")) // GDI(Graphic Device APInterface)
	modwinhttp  = wincall.NewLazyDLL(sysdll.Add("winhttp.dll"))
	moduser32   = wincall.NewLazyDLL(sysdll.Add("user32.dll")) // User Menu
	modadvapi32 = wincall.NewLazyDLL(sysdll.Add("advapi32.dll"))
	modkernel32 = wincall.NewLazyDLL(sysdll.Add("kernel32.dll"))

	//procCreateCompatibleDC   = libgdi32.NewProc("CreateCompati ableDC")
	//procGetObject            = libgdi32.NewProc("GetObject")
	//procSelectObject         = libgdi32.NewProc("SelectObject")
	//procGetDIBits            = libgdi32.NewProc("GetDIBits")

	// Clipboard API
	procAddClipboardFormatListener    = moduser32.NewProc("AddClipboardFormatListener")
	procIsClipboardFormatAvailable    = moduser32.NewProc("IsClipboardFormatAvailable")
	procRemoveClipboardFormatListener = moduser32.NewProc("RemoveClipboardFormatListener")
	procOpenClipboard                 = moduser32.NewProc("OpenClipboard")
	procCloseClipboard                = moduser32.NewProc("CloseClipboard")
	procEmptyClipboard                = moduser32.NewProc("EmptyClipboard")
	procGetClipboardData              = moduser32.NewProc("GetClipboardData")
	procSetClipboardData              = moduser32.NewProc("SetClipboardData")
	procGetDC                         = moduser32.NewProc("GetDC")

	// Windows Hook And Message API
	procCreateWindowEx      = moduser32.NewProc("CreateWindowExW")
	procDefWindowProc       = moduser32.NewProc("DefWindowProcW")
	procSetWindowsHookEx    = moduser32.NewProc("SetWindowsHookExW")
	procCallNextHookEx      = moduser32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx = moduser32.NewProc("UnhookWindowsHookEx")
	procGetMessage          = moduser32.NewProc("GetMessageW")
	procTranslateMessage    = moduser32.NewProc("TranslateMessage")
	procDispatchMessage     = moduser32.NewProc("DispatchMessageW")
	procPostQuitMessage     = moduser32.NewProc("PostQuitMessage")
	procRegisterClassEx     = moduser32.NewProc("RegisterClassExW")
	procUnregisterClass     = moduser32.NewProc("UnregisterClassW")

	// WinHTTP API
	procWinHttpGetIEProxyConfigForCurrentUser = modwinhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHttpDetectAutoProxyConfigUrl       = modwinhttp.NewProc("WinHttpDetectAutoProxyConfigUrl")
	ProcWinHttpOpen                           = modwinhttp.NewProc("WinHttpOpen")
	ProcWinHttpConnect                        = modwinhttp.NewProc("WinHttpConnect")
	ProcWinHttpOpenRequest                    = modwinhttp.NewProc("WinHttpOpenRequest")
	ProcWinHttpSendRequest                    = modwinhttp.NewProc("WinHttpSendRequest")
	ProcWinHttpAddRequestHeader               = modwinhttp.NewProc("WinHttpAddRequestHeader")
	ProcWinHttpReceiveResponse                = modwinhttp.NewProc("WinHttpReceiveResponse")
	ProcWinHttpQueryDataAvailable             = modwinhttp.NewProc("WinHttpQueryDataAvailable")
	ProcWinHttpReadData                       = modwinhttp.NewProc("WinHttpReadData")
	ProcWinHttpCloseHandle                    = modwinhttp.NewProc("WinHttpCloseHandle")
)

func AddClipboardFormatListener(handle uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procAddClipboardFormatListener.Addr(), handle)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func IsClipboardFormatAvailable(format uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procIsClipboardFormatAvailable.Addr(), uintptr(format))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func OpenClipboard(hWndNewOwner uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procOpenClipboard.Addr(), hWndNewOwner)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CloseClipboard() (err error) {
	r1, _, e1 := syscall.SyscallN(procCloseClipboard.Addr())
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetClipboardData(format uint32) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGetClipboardData.Addr(), uintptr(format))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func SetClipboardData() (err error) {
	r1, _, e1 := syscall.SyscallN(procSetClipboardData.Addr(), uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(nil)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func RemoveClipboardFormatListener(handle uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procRemoveClipboardFormatListener.Addr(), handle)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func GetModuleHandle(lpModuleName *uint16) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGetModuleHandle.Addr(), uintptr(unsafe.Pointer(lpModuleName)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func CallNextHookEx(nCode int32, wParam, lParam uintptr) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procCallNextHookEx.Addr(), 0, uintptr(nCode), wParam, lParam)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func SetWindowsHookEx(idHook int, lpFn, hMod uintptr, dwThreadId uint32) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procSetWindowsHookEx.Addr(), uintptr(idHook), lpFn, hMod, uintptr(dwThreadId))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func UnhookWindowsHookEx(hhk uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procUnhookWindowsHookEx.Addr(), hhk)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func GetMessage(lpMsg *MSG, hWnd, wMsgFilterMin, wMsgFilterMax uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procGetMessage.Addr(), uintptr(unsafe.Pointer(lpMsg)), uintptr(hWnd), uintptr(wMsgFilterMin), uintptr(wMsgFilterMax))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func TranslateMessage(lpMsg *MSG) (err error) {
	r1, _, e1 := syscall.SyscallN(procTranslateMessage.Addr(), uintptr(unsafe.Pointer(lpMsg)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func DispatchMessage(lpMsg *MSG) (err error) {
	r1, _, e1 := syscall.SyscallN(procDispatchMessage.Addr(), uintptr(unsafe.Pointer(lpMsg)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func PostQuitMessage(nExitCode int) (err error) {
	r1, _, e1 := syscall.SyscallN(procPostQuitMessage.Addr(), uintptr(nExitCode))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func RegisterClass(ex *WindowClassEX) (err error) {
	r1, _, e1 := syscall.SyscallN(procRegisterClassEx.Addr(), uintptr(unsafe.Pointer(ex)))
	fmt.Println(r1, e1)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func UnregisterClass(lpClassName string, hInstance uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procUnregisterClass.Addr(), uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpClassName))), hInstance)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

// TODO: Debug
func CreateWindowEx(lpClassName, lpWindowName string, hInstance uintptr) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procCreateWindowEx.Addr(),
		^uintptr(uint32(0)),
		uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpClassName))),
		uintptr(unsafe.Pointer(wincall.StringToUTF16Ptr(lpWindowName))),
		WS_POPUP,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		0,
		0,
		hInstance,
		0,
	)
	fmt.Println(r1, e1, wincall.GetLastError())

	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func DefWindowProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) (r1 uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procDefWindowProc.Addr(), hwnd, uintptr(msg), wParam, lParam)
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func WinHttpGetIEProxyConfigForCurrentUser(pProxyConfig *WinHttpCurrUserIEProxyConfig) (err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpGetIEProxyConfigForCurrentUser.Addr(), uintptr(unsafe.Pointer(pProxyConfig)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func WinHttpDetectAutoProxyConfigUrl(dwAutoDetectFlags uint32, ppwstrAutoConfigUrl *uint16) (err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpDetectAutoProxyConfigUrl.Addr(), uintptr(dwAutoDetectFlags), uintptr(unsafe.Pointer(ppwstrAutoConfigUrl)))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

/*
func WinHttpOpen(pszAgentW *uint16, dwAccessType uint32, pszProxyW, pszProxyBypassW *uint16, dwFlags uint32) (hSession wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpOpen.Addr(),
		uintptr(unsafe.Pointer(pszAgentW)),
		uintptr(dwAccessType),
		uintptr(unsafe.Pointer(pszProxyW)),
		uintptr(unsafe.Pointer(pszProxyBypassW)),
		uintptr(dwFlags),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hSession = wincall.Handle(r1)
	}

	return
}

func WinHttpConnect(hSession wincall.Handle, pswzServerName *uint16, nServerPort uint16, dwReserved uint32) (hConnect wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpConnect.Addr(),
		uintptr(hSession),
		uintptr(unsafe.Pointer(pswzServerName)),
		uintptr(nServerPort),
		uintptr(dwReserved),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hConnect = wincall.Handle(r1)
	}

	return
}

func WinHttpOpenRequest(hConnect wincall.Handle, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes *uint16, dwFlags uint32) (hRequest wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpOpenRequest.Addr(),
		uintptr(hConnect),
		uintptr(unsafe.Pointer(pwszVerb)),
		uintptr(unsafe.Pointer(pwszObjectName)),
		uintptr(unsafe.Pointer(pwszReferrer)),
		uintptr(unsafe.Pointer(ppwszAcceptTypes)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hRequest = wincall.Handle(r1)
	}

	return
}

func WinHttpAddRequestHeader(hRequest wincall.Handle, pswzServerName *uint16, nServerPort uint16, dwHeadersLength, dwModifiers uint32) (hConnect wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpAddRequestHeader.Addr(),
		uintptr(hRequest),
		uintptr(unsafe.Pointer(pswzServerName)),
		uintptr(nServerPort),
		uintptr(dwModifiers),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hConnect = wincall.Handle(r1)
	}

	return
}

func WinHttpSendRequest(hRequest wincall.Handle, pswzServerName *uint16, nServerPort uint16, dwOptionalLength, dwTotalLength uint32) (hConnect wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpSendRequest.Addr(),
		uintptr(hRequest),
		uintptr(unsafe.Pointer(pswzServerName)),
		uintptr(nServerPort),
		uintptr(dwOptionalLength),
		uintptr(dwTotalLength),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hConnect = wincall.Handle(r1)
	}

	return
}

func WinHttpReceiveResponse(hRequest wincall.Handle, lpReserved uintptr) (hConnect wincall.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpReceiveResponse.Addr(),
		uintptr(hRequest),
		lpReserved,
	)
	if r1 == 0 {
		err = errnoErr(e1)
	} else {
		hConnect = wincall.Handle(r1)
	}

	return
}

func WinHttpQueryDataAvailable(hInternet wincall.Handle, lpdwNumberOfBytesAvailable uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpQueryDataAvailable.Addr(), uintptr(hInternet), uintptr(lpdwNumberOfBytesAvailable))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func WinHttpReadData(hInternet wincall.Handle, dwNumberOfBytesToRead uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpReadData.Addr(), uintptr(hInternet), uintptr(dwNumberOfBytesToRead))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

func WinHttpCloseHandle(hInternet wincall.Handle) (err error) {
	r1, _, e1 := syscall.SyscallN(procWinHttpCloseHandle.Addr(), uintptr(hInternet))
	if r1 == 0 {
		err = errnoErr(e1)
	}

	return
}

/*
	WinHttpGetIEProxyConfigForCurrentUser
	WinHttpOpen
	WinHttpConnect
	WinHttpOpenRequest
	WinHttpSendRequest
	WinHttpAddRequestHeader
	WinHttpReceiveResponse
	WinHttpQueryDataAvailable
	WinHttpReadData
	WinHttpCloseHandle
*/
