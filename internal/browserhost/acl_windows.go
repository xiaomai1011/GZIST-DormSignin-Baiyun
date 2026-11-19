//go:build windows

package browserhost

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeStateFile creates the state file with its restrictive descriptor in
// place from the very first byte: the secret must never exist in a file that
// briefly inherits permissive permissions from its parent directory.
func writeStateFile(path string, data []byte) error {
	// CREATE_NEW applies the security attributes only when it creates the file,
	// so a stale copy is removed first (it is ours to replace).
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除旧状态文件失败: %w", err)
	}
	sid, err := currentUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FA;;;%s)", sid.String()))
	if err != nil {
		return fmt.Errorf("构造状态文件安全描述符失败: %w", err)
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.DELETE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("创建状态文件失败: %w", err)
	}
	f := os.NewFile(uintptr(h), path)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return verifyStateFileACL(path)
}

// verifyStateFileACL checks what is actually on disk: one protected ACE, for
// the current user, and nothing else.
func verifyStateFileACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取状态文件 DACL 失败: %w", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("状态文件 DACL 未受保护，仍可能继承父目录的权限")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("状态文件没有 DACL")
	}
	if dacl.AceCount != 1 {
		return fmt.Errorf("状态文件 DACL 有 %d 条规则，期望仅当前用户一条", dacl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("读取状态文件 ACE 失败: %w", err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		return fmt.Errorf("状态文件 DACL 首条规则类型为 %d，期望允许型", ace.Header.AceType)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	want, err := currentUser()
	if err != nil {
		return err
	}
	if !sid.Equals(want) {
		return errors.New("状态文件 DACL 授予了其它用户")
	}
	return nil
}

func currentUser() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("读取当前用户失败: %w", err)
	}
	return u.User.Sid, nil
}
