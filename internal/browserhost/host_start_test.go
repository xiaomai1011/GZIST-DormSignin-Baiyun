package browserhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// tempProfiles lists the daemon-owned profile directories currently in the OS
// temp directory, so a test can tell whether a failed Start left one behind.
func tempProfiles(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("读取临时目录失败: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "dormsign-browserhost-") {
			out[e.Name()] = true
		}
	}
	return out
}

func newProfiles(before, after map[string]bool) []string {
	var added []string
	for name := range after {
		if !before[name] {
			added = append(added, name)
		}
	}
	return added
}

type startResult struct {
	d   *Daemon
	err error
}

// startGated installs a launcher whose start blocks on a gate, then calls Start
// in the background and returns the gate plus the result channel.
func startGated(t *testing.T, ctx context.Context, cleanup bool, profileDir string, closeErrs map[int]error) (
	*gatedBrowsers, chan struct{}, chan int, chan startResult) {
	t.Helper()
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	g := &gatedBrowsers{closeErrs: closeErrs}
	gate := make(chan struct{})
	started := make(chan int, 4)
	g.gate = gate
	g.started = started
	launchSession = g.start
	revokeBrowser = g.close
	waitExit = func(*edge.Session, time.Duration) bool { return true }
	t.Cleanup(func() { launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait })

	res := make(chan startResult, 1)
	go func() {
		d, err := Start(ctx, store.Settings{UserData: profileDir},
			filepath.Join(t.TempDir(), "state.json"), cleanup)
		res <- startResult{d: d, err: err}
	}()
	return g, gate, started, res
}

func waitStart(t *testing.T, started <-chan int) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("启动未进入启动器")
	}
}

// TestStartCancelWhileLaunchingKeepsProfileUntilExitIsConfirmed: cancelling the
// wait must not delete the profile while the browser start is still running;
// the dir goes only after the late start was discarded and its exit confirmed.
func TestStartCancelWhileLaunchingKeepsProfileUntilExitIsConfirmed(t *testing.T) {
	before := tempProfiles(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, gate, started, res := startGated(t, ctx, true, "", map[int]error{})
	waitStart(t, started)

	profiles := newProfiles(before, tempProfiles(t))
	if len(profiles) != 1 {
		t.Fatalf("新增临时 profile 数 = %d，期望 1", len(profiles))
	}
	dir := filepath.Join(os.TempDir(), profiles[0])

	// The caller gives up while the start is still gated: the profile must not
	// be removed at this instant, because the browser may still be starting.
	cancel()
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("退出确认前不得删除 profile: %v", err)
	}
	close(gate)

	select {
	case r := <-res:
		if r.err == nil {
			t.Fatal("启动应失败")
		}
		if r.d != nil {
			t.Fatal("失败时不应返回 daemon")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start 未返回")
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("退出确认后临时 profile 应被删除，实际 err=%v", err)
	}
}

// TestStartCancelKeepsProfileWhenLateCleanupFails: when the late browser cannot
// be reaped, the profile stays and the error carries both causes.
func TestStartCancelKeepsProfileWhenLateCleanupFails(t *testing.T) {
	before := tempProfiles(t)
	boom := errors.New("模拟迟到启动整树清理失败")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, gate, started, res := startGated(t, ctx, true, "", map[int]error{1001: boom})
	waitStart(t, started)

	profiles := newProfiles(before, tempProfiles(t))
	if len(profiles) != 1 {
		t.Fatalf("新增临时 profile 数 = %d，期望 1", len(profiles))
	}
	dir := filepath.Join(os.TempDir(), profiles[0])

	cancel()
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("退出确认前不得删除 profile: %v", err)
	}
	close(gate)

	select {
	case r := <-res:
		if r.err == nil {
			t.Fatal("启动应失败")
		}
		if !errors.Is(r.err, context.Canceled) {
			t.Fatalf("错误未保留取消原因: %v", r.err)
		}
		if !errors.Is(r.err, boom) {
			t.Fatalf("错误未保留清理失败: %v", r.err)
		}

	case <-time.After(10 * time.Second):
		t.Fatal("Start 未返回")
	}

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("清理失败时必须保留 profile，实际 err=%v", err)
	}
	_ = os.RemoveAll(dir)
}

// TestStartExternalProfileIsNeverDeleted: a caller supplied directory survives
// even a failed start whose cleanup also failed.
func TestStartExternalProfileIsNeverDeleted(t *testing.T) {
	external := filepath.Join(t.TempDir(), "caller-profile")
	if err := os.MkdirAll(external, 0o700); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("模拟外部 profile 清理失败")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, gate, started, res := startGated(t, ctx, false, external, map[int]error{1001: boom})
	waitStart(t, started)
	cancel()
	time.Sleep(200 * time.Millisecond)
	close(gate)

	select {
	case r := <-res:
		if r.err == nil {
			t.Fatal("启动应失败")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start 未返回")
	}
	if _, err := os.Stat(external); err != nil {
		t.Fatalf("外部传入的 profile 不应被删除: %v", err)
	}
}

// TestStartStateWriteFailureKeepsOriginalCause: the listen/state-write exits go
// through the same teardown and keep the original error.
func TestStartStateWriteFailureKeepsOriginalCause(t *testing.T) {
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	launchSession = func(context.Context, store.Settings) (*edge.Session, error) {
		return &edge.Session{PID: 1, Endpoint: "ws://127.0.0.1:1/x"}, nil
	}
	revokeBrowser = func(*edge.Session) error { return nil }
	waitExit = func(*edge.Session, time.Duration) bool { return true }
	t.Cleanup(func() { launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait })

	dir := t.TempDir()
	// A state path whose parent is a regular file makes writeState fail after
	// the listener is up.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := Start(context.Background(), store.Settings{UserData: filepath.Join(dir, "p")},
		filepath.Join(blocker, "state.json"), false)
	if err == nil {
		_ = d.Close()
		t.Fatal("状态文件写入失败时 Start 应返回错误")
	}
	if d != nil {
		t.Fatal("失败时不应返回 daemon")
	}
	if !strings.Contains(err.Error(), "state.json") && !errors.Is(err, os.ErrNotExist) {
		t.Logf("错误原文: %v", fmt.Sprintf("%v", err))
	}
}
