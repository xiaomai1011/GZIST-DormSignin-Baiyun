//go:build windows

package browserhost

import (
	"context"
	"golang.org/x/sys/windows"
	"sync"
	"unsafe"
)

var windowUser32 = windows.NewLazySystemDLL("user32.dll")
var (
	enumHostWindows = windowUser32.NewProc("EnumWindows")
	windowPID       = windowUser32.NewProc("GetWindowThreadProcessId")
	windowClass     = windowUser32.NewProc("GetClassNameW")
	windowOwner     = windowUser32.NewProc("GetWindow")
	windowRect      = windowUser32.NewProc("GetWindowRect")
	windowPlacement = windowUser32.NewProc("GetWindowPlacement")
	windowVisible   = windowUser32.NewProc("IsWindowVisible")
	windowIconic    = windowUser32.NewProc("IsIconic")
	windowShowAsync = windowUser32.NewProc("ShowWindowAsync")
)

type hostRect struct{ Left, Top, Right, Bottom int32 }
type hostPlacement struct {
	Length, Flags, Show    uint32
	MinX, MinY, MaxX, MaxY int32
	Normal                 hostRect
}
type nativeWindowBackend struct {
	pid     uint32
	created windows.Filetime
	session uint32
}

func (b *nativeWindowBackend) process() (windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, b.pid)
	if err != nil {
		return 0, ErrWindowIdentity
	}
	var created, exit, kernel, user windows.Filetime
	var session uint32
	err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user)
	status, waitErr := windows.WaitForSingleObject(h, 0)
	sessionErr := windows.ProcessIdToSessionId(b.pid, &session)
	if err != nil || waitErr != nil || status != uint32(windows.WAIT_TIMEOUT) || sessionErr != nil || created != b.created || session != b.session {
		windows.CloseHandle(h)
		return 0, ErrWindowIdentity
	}
	return h, nil
}
func (b *nativeWindowBackend) Identity() error {
	h, err := b.process()
	if err == nil {
		windows.CloseHandle(h)
	}
	return err
}
func (b *nativeWindowBackend) inspect(hwnd uintptr) (windowInfo, bool) {
	var pid uint32
	windowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid != b.pid {
		return windowInfo{}, false
	}
	var class [256]uint16
	n, _, _ := windowClass.Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	if n == 0 {
		return windowInfo{}, false
	}
	owner, _, _ := windowOwner.Call(hwnd, 4) // GW_OWNER
	var r hostRect
	ok, _, _ := windowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	if ok == 0 {
		return windowInfo{}, false
	}
	iconic, _, _ := windowIconic.Call(hwnd)
	// Normal placement stays stable through asynchronous restore: IsIconic may
	// clear before GetWindowRect stops reporting the icon-sized transition rect.
	{
		p := hostPlacement{Length: uint32(unsafe.Sizeof(hostPlacement{}))}
		ok, _, _ = windowPlacement.Call(hwnd, uintptr(unsafe.Pointer(&p)))
		if ok == 0 {
			return windowInfo{}, false
		}
		r = p.Normal
	}
	visible, _, _ := windowVisible.Call(hwnd)
	return windowInfo{handle: hwnd, pid: int(pid), class: windows.UTF16ToString(class[:]), owner: owner, width: int(r.Right - r.Left), height: int(r.Bottom - r.Top), visible: visible != 0, minimized: iconic != 0}, true
}

type windowEnumeration struct {
	backend *nativeWindowBackend
	result  []windowInfo
}

var hostEnumerationMu sync.Mutex
var activeHostEnumeration *windowEnumeration
var hostWindowCallback = windows.NewCallback(func(hwnd, lparam uintptr) uintptr {
	e := activeHostEnumeration
	if e == nil {
		return 0
	}
	if w, ok := e.backend.inspect(hwnd); ok {
		e.result = append(e.result, w)
	}
	return 1
})

func (b *nativeWindowBackend) Windows() ([]windowInfo, error) {
	hostEnumerationMu.Lock()
	defer hostEnumerationMu.Unlock()
	e := &windowEnumeration{backend: b}
	activeHostEnumeration = e
	defer func() { activeHostEnumeration = nil }()
	ok, _, _ := enumHostWindows.Call(hostWindowCallback, 0)
	if ok == 0 {
		return nil, ErrWindowVerify
	}
	return e.result, nil
}
func (b *nativeWindowBackend) Command(hwnd uintptr, command int) error {
	h, err := b.process()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	w, ok := b.inspect(hwnd)
	if !ok || !mainWindow(w) {
		return ErrWindowIdentity
	}
	okResult, _, _ := windowShowAsync.Call(hwnd, uintptr(command))
	if okResult == 0 {
		return ErrWindowVerify
	}
	return nil
}
func newHostWindow(pid int) (hostWindow, error) {
	if pid <= 0 {
		return nil, ErrWindowIdentity
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, ErrWindowIdentity
	}
	defer windows.CloseHandle(h)
	b := &nativeWindowBackend{pid: uint32(pid)}
	var exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &b.created, &exit, &kernel, &user) != nil || windows.ProcessIdToSessionId(b.pid, &b.session) != nil {
		return nil, ErrWindowIdentity
	}
	var ownSession uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &ownSession) != nil || ownSession != b.session {
		return nil, ErrWindowIdentity
	}
	c := &controlledWindow{backend: b}
	if err := c.SetVisible(context.Background(), false); err != nil {
		return nil, err
	}
	return c, nil
}
