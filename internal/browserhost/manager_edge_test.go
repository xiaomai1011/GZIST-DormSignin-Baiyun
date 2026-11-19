package browserhost

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// These tests use the real Edge with throwaway profiles and only about:blank.
// They never visit the school. Like the other Edge tests they run only with
// DORMSIGN_EDGE_TEST=1.

func edgeManagerConfig(t *testing.T, name string) store.Settings {
	t.Helper()
	return store.Settings{
		EdgePath: edgeExe(t),
		UserData: filepath.Join(t.TempDir(), name),
		ViewW:    430,
		ViewH:    900,
	}
}

// Switching accounts must close the old host and start a new one for the new
// profile; the old browser must not be handed to the new account.
func TestManagerSwitchesAccountsWithRealEdge(t *testing.T) {
	cfgA := edgeManagerConfig(t, "a")
	cfgB := edgeManagerConfig(t, "b")
	m := NewManager(false)
	t.Cleanup(func() {
		if err := m.CloseAll(); err != nil {
			t.Errorf("清理常驻宿主: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	clientA, err := m.Ensure(ctx, cfgA)
	if err != nil {
		t.Fatalf("启动账号 A 的宿主: %v", err)
	}
	before, err := clientA.Status()
	if err != nil {
		t.Fatalf("查询账号 A 状态: %v", err)
	}

	if err := m.Switch(cfgB); err != nil {
		t.Fatalf("空闲时切换账号: %v", err)
	}
	clientB, err := m.Ensure(ctx, cfgB)
	if err != nil {
		t.Fatalf("启动账号 B 的宿主: %v", err)
	}
	after, err := clientB.Status()
	if err != nil {
		t.Fatalf("查询账号 B 状态: %v", err)
	}
	if after.PID == before.PID {
		t.Fatalf("切换账号后仍连着旧浏览器：pid=%d", after.PID)
	}
	if after.Launches != 1 {
		t.Fatalf("新账号的宿主应只启动一次，实得 %d", after.Launches)
	}
	if before.Launches != 1 {
		t.Fatalf("旧账号的宿主应只启动一次，实得 %d", before.Launches)
	}
}

// A lease that is in use must block the switch; releasing it makes the same
// switch succeed. No second browser may exist while the first is leased.
func TestManagerRefusesSwitchWhileRealEdgeIsLeased(t *testing.T) {
	cfgA := edgeManagerConfig(t, "a")
	cfgB := edgeManagerConfig(t, "b")
	m := NewManager(false)
	t.Cleanup(func() {
		if err := m.CloseAll(); err != nil {
			t.Errorf("清理常驻宿主: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	client, err := m.Ensure(ctx, cfgA)
	if err != nil {
		t.Fatalf("启动账号 A 的宿主: %v", err)
	}
	before, err := client.Status()
	if err != nil {
		t.Fatalf("查询状态: %v", err)
	}
	_, release, err := client.Attach(ctx, 2*time.Minute)
	if err != nil {
		t.Fatalf("附加: %v", err)
	}

	if err := m.Switch(cfgB); !errors.Is(err, ErrSwitchBusy) {
		t.Fatalf("租约未释放时应拒绝切换，实得 %v", err)
	}
	if m.Hosts() != 1 {
		t.Fatalf("拒绝切换时旧宿主应保留，实得 %d", m.Hosts())
	}
	release()

	if err := m.Switch(cfgB); err != nil {
		t.Fatalf("释放后切换: %v", err)
	}
	clientB, err := m.Ensure(ctx, cfgB)
	if err != nil {
		t.Fatalf("启动账号 B 的宿主: %v", err)
	}
	after, err := clientB.Status()
	if err != nil {
		t.Fatalf("查询账号 B 状态: %v", err)
	}
	if after.PID == before.PID {
		t.Fatalf("切换后仍是旧浏览器：pid=%d", after.PID)
	}
}
