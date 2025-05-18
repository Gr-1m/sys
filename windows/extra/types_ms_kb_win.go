package extra

// 鼠标动作
const (
	WM_MOUSEMOVE     = iota + 0x0200
	WM_LBUTTONDOWN   // 左键按下
	WM_LBUTTONUP     // 左键释放
	WM_LBUTTONDBLCLK // 左键双击
	WM_RBUTTONDOWN   // 右键按下
	WM_RBUTTONUP     // 右键释放
	WM_RBUTTONDBLCLK // 右键双击
	WM_MBUTTONDOWN   // 中键按下
	WM_MBUTTONUP     // 中键释放
	WM_MBUTTONDBLCLK // 中键双击

	// 剪贴板动作
	WM_DESTROYCLIPBOARD = 0x0307
	WM_DRAWCLIPBOARD    = 0x0308
	WM_CLIPBOARDUPDATE  = 0x031D

	WH_KEYBOARD_LL = 13
	WH_MOUSE_LL    = 14
)

// KbdLLHook KeyBoard Hook Struct
type KbdLLHook struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

// MsLLHook Mouse Hook Struct
type MsLLHook struct {
	Pt          Point
	MouseData   uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}
