package extra

import (
	"errors"
	wincall "golang.org/x/sys/windows"
	"log"
	"path/filepath"
	"unicode/utf16"
	"unsafe"
)

type Slice struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

func ReportErrorCloseHandle(err error, header string, handle wincall.Handle, closeFunc func(wincall.Handle)) {
	if err != nil {
		log.Println(header, " Error: ", err)
		return
	}
	closeFunc(handle)
}

func StringFromU16Slice(charName []uint16) string {
	s1 := ""
	for i := 0; i < len(charName) && charName[i] != 0; i++ {
		s1 = s1 + string(rune(int(charName[i])))
	}

	return s1
}

func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	// Find NUL terminator.
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	// Turn *uint16 into []uint16.
	var s []uint16
	hdr := (*Slice)(unsafe.Pointer(&s))
	hdr.Data = unsafe.Pointer(p)
	hdr.Cap = n
	hdr.Len = n
	// Decode []uint16 into string.
	return string(utf16.Decode(s))
}

func CreateProcess(appName *uint16, commandLine *uint16, cF uint32, sI *wincall.StartupInfo, pI *wincall.ProcessInformation) error {
	var (
		pS wincall.SecurityAttributes
		tS wincall.SecurityAttributes
		iH = true
		//env uint16
		//cD  uint16
	)
	//argv := wincall.StringToUTF16Ptr("C:\\Windows\\System32\\cmd.exe")
	//argv := wincall.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe '123.txt'")

	return wincall.CreateProcess(
		appName, commandLine, &pS, &tS, iH, cF, nil, nil, sI, pI,
	)
}

func CreateCmdProcess(StdInPipeRead, StdOutPipeWrite wincall.Handle) (wincall.Handle, error) {
	var (
		pS wincall.SecurityAttributes
		tS wincall.SecurityAttributes
		iH = true
		cF uint32
		//env uint16
		//cD  uint16
		sI wincall.StartupInfo
		pI wincall.ProcessInformation
	)
	appName := wincall.StringToUTF16Ptr("C:\\Windows\\System32\\cmd.exe")
	commandLine := wincall.StringToUTF16Ptr("C:\\Windows\\System32\\cmd.exe")

	sI.Cb = uint32(unsafe.Sizeof(wincall.StartupInfo{}))
	sI.Flags = wincall.STARTF_USESTDHANDLES | wincall.STARTF_USESHOWWINDOW
	sI.StdInput = StdInPipeRead
	sI.StdOutput = StdOutPipeWrite
	sI.StdErr = StdOutPipeWrite

	return pI.Process, wincall.CreateProcess(appName, commandLine, &pS, &tS, iH, cF, nil, nil, &sI, &pI)
}

func FindProcName(name string, pe32 *wincall.ProcessEntry32) error {
	hSnapshot, err := wincall.CreateToolhelp32Snapshot(wincall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return errors.New("CreateToolhelp32Snapshot Failed: " + err.Error())
	}
	defer wincall.CloseHandle(hSnapshot)

	pe32.Size = uint32(unsafe.Sizeof(*pe32))
	// lookup every process in snap
	for err = wincall.Process32First(hSnapshot, pe32); err == nil; err = wincall.Process32Next(hSnapshot, pe32) {
		if wincall.UTF16ToString(pe32.ExeFile[:]) == filepath.Base(name) {
			return nil
		}
	}
	if pe32.ProcessID == 0 {
		return errors.New("Process32First Error: " + err.Error())
	}
	return errors.New("Process32Next Error: " + err.Error())
}

func OpenCurrentProcessToken() (wincall.Token, error) {
	var token wincall.Token
	err := wincall.OpenProcessToken(wincall.CurrentProcess(), wincall.TOKEN_ADJUST_PRIVILEGES|wincall.TOKEN_QUERY|wincall.TOKEN_DUPLICATE, &token)
	return token, err
	//p, e := wincall.GetCurrentProcess()
	//if e != nil {
	//	return 0, e
	//}
	//var t wincall.Token
	//e = wincall.OpenProcessToken(p, wincall.TOKEN_ADJUST_PRIVILEGES|wincall.TOKEN_QUERY, &t)
	//if e != nil {
	//	return 0, e
	//}
	//return t, nil
}

func EnableDebugPrivilege(hToken *wincall.Token) (err error) {
	if hToken == nil {
		currpToken, err := OpenCurrentProcessToken()
		if err != nil {
			return errors.New("OpenCurrentProcessToken Error: " + err.Error())
		}
		hToken = &currpToken
	}
	// defer wincall.CloseHandle(wincall.Handle(hToken))

	var tp = &wincall.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Attributes = wincall.SE_PRIVILEGE_ENABLED
	err = wincall.LookupPrivilegeValue(nil, wincall.StringToUTF16Ptr(SE_DEBUG_NAME), &tp.Privileges[0].Luid)
	if err != nil {
		return errors.New("LookupPrivilegeValue Error: " + err.Error())
	}

	err = wincall.AdjustTokenPrivileges(*hToken, false, tp, (uint32)(unsafe.Sizeof(*tp)), nil, nil)
	if err != nil {
		return errors.New("AdjustTokenPrivileges Error: " + err.Error())
	}

	return
}

func EnablePrivileges(token *wincall.Token, privs []string) (err error) {

	if token == nil {
		currpToken, err := OpenCurrentProcessToken()
		if err != nil {
			return errors.New("OpenCurrentProcessToken Error: " + err.Error())
		}
		token = &currpToken
	}

	var tp = &wincall.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Attributes = wincall.SE_PRIVILEGE_ENABLED

	for _, p := range privs {
		err = wincall.LookupPrivilegeValue(nil, wincall.StringToUTF16Ptr(p), &tp.Privileges[0].Luid)
		if err != nil {
			return errors.New("LookupPrivilegeValue Error: " + err.Error())
		}

		err = wincall.AdjustTokenPrivileges(*token, false, tp, (uint32)(unsafe.Sizeof(*tp)), nil, nil)
		if err != nil {
			return errors.New("AdjustTokenPrivileges Error: " + err.Error())
		}
	}
	return wincall.CloseHandle(wincall.Handle(*token))
}

func RemovePrivileges(token *wincall.Token, privs []string) (err error) {
	if token == nil {
		currpToken, err := OpenCurrentProcessToken()
		if err != nil {
			return errors.New("OpenCurrentProcessToken Error: " + err.Error())
		}
		token = &currpToken
	}
	// defer wincall.CloseHandle(wincall.Handle(hToken))

	var tp = &wincall.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Attributes = wincall.SE_PRIVILEGE_REMOVED

	for _, p := range privs {
		err = wincall.LookupPrivilegeValue(nil, wincall.StringToUTF16Ptr(p), &tp.Privileges[0].Luid)
		if err != nil {
			return errors.New("LookupPrivilegeValue Error: " + err.Error())
		}

		err = wincall.AdjustTokenPrivileges(*token, false, tp, (uint32)(unsafe.Sizeof(*tp)), nil, nil)
		if err != nil {
			return errors.New("AdjustTokenPrivileges Error: " + err.Error())
		}

	}
	return
}
