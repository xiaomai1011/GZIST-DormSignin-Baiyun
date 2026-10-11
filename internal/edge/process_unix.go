//go:build linux || darwin

package edge

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func startOwnedProcess(cmd *exec.Cmd) (func() error, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}, nil
}

func waitOwnedProcess(cmd *exec.Cmd) error { return cmd.Wait() }

func lockProfile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("浏览器目录正在被其他实例使用: %w", err)
	}
	return func() { _ = f.Close() }, nil
}
