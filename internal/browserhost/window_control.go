package browserhost

import (
	"context"

	"errors"
	"sync"
	"time"
)

// Window errors are fixed categories: never contain page URLs or profile paths.
var (
	ErrWindowIdentity    = errors.New("window_identity_changed")
	ErrWindowAmbiguous   = errors.New("window_ambiguous")
	ErrWindowMissing     = errors.New("window_not_found")
	ErrWindowVerify      = errors.New("window_verification_failed")
	ErrWindowUnsupported = errors.New("window_unsupported")
	ErrWindowUnavailable = errors.New("window_not_bound")
	errWindowGeometry    = errors.New("window_geometry_transition")
)

const windowTimeout = 2 * time.Second

type hostWindow interface {
	SetVisible(context.Context, bool) error
}
type windowLaunchKey struct{}
type windowLaunchResult struct{ window hostWindow }
type windowInfo struct {
	handle             uintptr
	pid                int
	class              string
	owner              uintptr
	width, height      int
	visible, minimized bool
}
type windowBackend interface {
	Identity() error
	Windows() ([]windowInfo, error)
	Command(uintptr, int) error
}
type controlledWindow struct {
	mu      sync.Mutex
	backend windowBackend
	handle  uintptr
}

func mainWindow(w windowInfo) bool {
	return w.class == "Chrome_WidgetWin_1" && w.owner == 0 && w.width >= 200 && w.height >= 150 && w.width <= 16384 && w.height <= 16384
}
func (c *controlledWindow) candidate() (windowInfo, error) {
	if err := c.backend.Identity(); err != nil {
		return windowInfo{}, err
	}
	ws, err := c.backend.Windows()
	if err != nil {
		return windowInfo{}, err
	}
	var found windowInfo
	count := 0
	geometryTransition := false
	for _, w := range ws {
		if c.handle != 0 && w.handle == c.handle && w.class == "Chrome_WidgetWin_1" && w.owner == 0 && !mainWindow(w) {
			geometryTransition = true
		}
		// Edge creates an initially hidden same-class/same-size helper surface.
		// Bind only a unique visible main window; afterwards only that exact HWND
		// remains eligible while hidden. Never promote an unbound hidden helper.
		if mainWindow(w) && (w.visible || (c.handle != 0 && w.handle == c.handle)) {
			found = w
			count++
		}
	}
	if count > 1 {
		return windowInfo{}, ErrWindowAmbiguous
	}
	if count == 0 {
		if geometryTransition {
			return windowInfo{}, errWindowGeometry
		}
		if c.handle != 0 {
			return windowInfo{}, ErrWindowIdentity
		}
		return windowInfo{}, ErrWindowMissing
	}
	if c.handle != 0 && c.handle != found.handle {
		return windowInfo{}, ErrWindowIdentity
	}
	return found, nil
}
func windowPause(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ErrWindowVerify
	case <-time.After(20 * time.Millisecond):
		return nil
	}
}
func (c *controlledWindow) SetVisible(parent context.Context, visible bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, windowTimeout)
	defer cancel()
	var w windowInfo
	for {
		var err error
		w, err = c.candidate()
		if err == nil {
			break
		}
		if err != ErrWindowMissing || c.handle != 0 {
			return err
		}
		if windowPause(ctx) != nil {
			return ErrWindowMissing
		}
	}
	c.handle = w.handle
	command := func(n int) error {
		if ctx.Err() != nil {
			return ErrWindowVerify
		}
		now, err := c.candidate()
		if err != nil {
			return err
		}
		if now.handle != w.handle {
			return ErrWindowIdentity
		}
		return c.backend.Command(w.handle, n)
	}
	if visible {
		if err := command(9); err != nil {
			return err
		} // SW_RESTORE, exactly one HWND
	} else {
		// Wait for asynchronous minimization before hiding, avoiding residual black surfaces.
		if w.visible && !w.minimized {
			if err := command(6); err != nil {
				return err
			} // SW_MINIMIZE
			for {
				var err error
				w, err = c.candidate()
				if err == errWindowGeometry {
					if windowPause(ctx) != nil {
						return ErrWindowVerify
					}
					continue
				}
				if err != nil {
					return err
				}
				if w.minimized {
					break
				}
				if windowPause(ctx) != nil {
					return ErrWindowVerify
				}
			}
		}
		if err := command(0); err != nil {
			return err
		} // SW_HIDE
	}
	for {
		now, err := c.candidate()
		if err == errWindowGeometry {
			if windowPause(ctx) != nil {
				return ErrWindowVerify
			}
			continue
		}
		if err != nil {
			return err
		}
		if now.visible == visible && (!visible || !now.minimized) {
			return nil
		}
		if windowPause(ctx) != nil {
			return ErrWindowVerify
		}
	}
}

// setHostWindow deliberately requires an already-bound session controller, not a PID.
func setHostWindow(ctx context.Context, window hostWindow, visible bool) error {
	if window == nil {
		return ErrWindowUnavailable
	}
	return window.SetVisible(ctx, visible)
}
func windowErrorCategory(err error) string {
	for _, e := range []error{ErrWindowIdentity, ErrWindowAmbiguous, ErrWindowMissing, ErrWindowVerify, ErrWindowUnsupported, ErrWindowUnavailable} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "window_operation_failed"
}
