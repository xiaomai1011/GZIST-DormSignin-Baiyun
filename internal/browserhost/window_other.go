//go:build !windows

package browserhost

func newHostWindow(pid int) (hostWindow, error) { return nil, ErrWindowUnsupported }
