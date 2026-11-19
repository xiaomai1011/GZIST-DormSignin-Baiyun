//go:build windows

package browserhost

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The state file carries the control token, so its DACL is not a nicety: the
// test reads the DACL back and requires a single protected ACE for this user.
func TestStateFileACLIsRestrictedToCurrentUser(t *testing.T) {
	d, _, _ := newFakeDaemon(t, true)
	if err := verifyStateFileACL(d.statePath); err != nil {
		t.Fatalf("状态文件权限未收紧: %v", err)
	}
}

// TestStateFileGetsRestrictiveACLEvenInPermissiveDir: the parent directory is
// deliberately made readable by Everyone first; the state file must still end
// up with a single protected ACE for the current user only.
func TestStateFileGetsRestrictiveACLEvenInPermissiveDir(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)(RX)").CombinedOutput(); err != nil {
		t.Fatalf("放宽父目录权限失败: %v: %s", err, out)
	}
	path := filepath.Join(dir, "state.json")
	want := []byte(`{"token":"secret-token-value"}`)
	if err := writeStateFile(path, want); err != nil {
		t.Fatalf("写入状态文件失败: %v", err)
	}
	if err := verifyStateFileACL(path); err != nil {
		t.Fatalf("状态文件权限不符合保证: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("内容不一致: %q", got)
	}
}
