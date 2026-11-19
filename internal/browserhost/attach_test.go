package browserhost

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// newAttachHarness starts a daemon over fake browsers and keeps the state path
// so a second process can dial the very same host.
func newAttachHarness(t *testing.T) (string, *Client, *fakeBrowsers) {
	t.Helper()
	oldLaunch, oldRevoke, oldWait, oldExited := launchSession, revokeBrowser, waitExit, sessionExited
	f := &fakeBrowsers{}
	launchSession = f.start
	revokeBrowser = f.close
	waitExit = func(*edge.Session, time.Duration) bool { return true }
	oldAttach := attachSession
	attachSession = func(ctx context.Context, endpoint string, pid int, userData string, targetID string) (*edge.Session, error) {
		return &edge.Session{Ctx: ctx, PID: pid, Endpoint: endpoint, UserData: userData, TargetID: targetID, Attached: true}, nil
	}
	t.Cleanup(func() {
		launchSession, revokeBrowser, waitExit, sessionExited = oldLaunch, oldRevoke, oldWait, oldExited
		attachSession = oldAttach
	})
	statePath := filepath.Join(t.TempDir(), "state.json")
	d, err := Start(context.Background(), store.Settings{UserData: filepath.Join(t.TempDir(), "profile")}, statePath, true)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	c, err := Dial(statePath, "")
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	return statePath, c, f
}

// TestHelperLease runs as a separate OS process: it leases the resident browser
// from the same state file and reports which PID the host is serving. It is
// skipped during a normal test run.
func TestHelperLease(t *testing.T) {
	path := os.Getenv("BROWSERHOST_HELPER_STATE")
	if path == "" {
		t.Skip("helper process only")
	}
	c, err := Dial(path, os.Getenv("BROWSERHOST_HELPER_PROFILE"))
	if err != nil {
		fmt.Printf("HELPER_ERR=%v\n", err)
		os.Exit(3)
	}
	res, err := c.Reserve(context.Background(), time.Minute)
	if err != nil {
		fmt.Printf("HELPER_ERR=%v\n", err)
		os.Exit(3)
	}
	endpoint, err := c.Confirm(context.Background(), res)
	if err != nil {
		fmt.Printf("HELPER_ERR=%v\n", err)
		os.Exit(3)
	}
	c.release(res.ID)
	st, err := c.Status()
	if err != nil {
		fmt.Printf("HELPER_ERR=%v\n", err)
		os.Exit(3)
	}
	fmt.Printf("HELPER_PID=%d HELPER_ENDPOINT=%s HELPER_LAUNCHES=%d\n", st.PID, endpoint, st.Launches)
}

// TestASecondProcessLeasesTheSameBrowser proves the reuse is cross-process, not
// an in-memory shortcut: a child process dials the state file, takes a lease on
// the already running browser and sees the same PID and launch count.
func TestASecondProcessLeasesTheSameBrowser(t *testing.T) {
	if os.Getenv("BROWSERHOST_SKIP_SUBPROCESS") != "" {
		t.Skip("BROWSERHOST_SKIP_SUBPROCESS 已设置")
	}
	statePath, c, f := newAttachHarness(t)
	before, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperLease$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "BROWSERHOST_HELPER_STATE="+statePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("子进程失败: %v\n%s", err, out)
	}
	text := string(out)
	want := fmt.Sprintf("HELPER_PID=%d", before.PID)
	if !strings.Contains(text, want) {
		t.Fatalf("子进程没有看到同一浏览器（期望 %s）:\n%s", want, text)
	}
	if !strings.Contains(text, fmt.Sprintf("HELPER_LAUNCHES=%d", before.Launches)) {
		t.Fatalf("子进程租约期间不应有新启动:\n%s", text)
	}
	after, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if f.n != 1 || after.Launches != before.Launches || after.PID != before.PID {
		t.Fatalf("复用改变了宿主状态: launches=%d/%d pid=%d/%d fake=%d", before.Launches, after.Launches, before.PID, after.PID, f.n)
	}
	if after.Leased {
		t.Fatal("子进程释放后租约仍被占")
	}
}

// TestALongIdleKeepsTheSameBrowser keeps the fake host's single simulated
// session across a real idle wait. It proves the daemon's lease/keep-alive
// logic does not relaunch; it does not prove a real Edge stayed alive (that is
// TestCrossProcessCDPAttachSharesPageState with DORMSIGN_EDGE_TEST=1). It only
// runs when BROWSERHOST_LONG_IDLE is set, and reports the duration it actually
// waited instead of claiming a fixed number.
func TestALongIdleKeepsTheSameBrowser(t *testing.T) {
	spec := os.Getenv("BROWSERHOST_LONG_IDLE")
	if spec == "" {
		t.Skip("未设置 BROWSERHOST_LONG_IDLE")
	}
	idle, err := time.ParseDuration(spec)
	if err != nil || idle < time.Second {
		t.Fatalf("BROWSERHOST_LONG_IDLE 不是合法时长: %q", spec)
	}
	_, c, f := newAttachHarness(t)
	first, release, err := c.Attach(context.Background(), 10*time.Minute)
	if err != nil {
		t.Fatalf("首次接管失败: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭会话失败: %v", err)
	}
	release()
	start := time.Now()
	time.Sleep(idle)
	second, release2, err := c.Attach(context.Background(), 10*time.Minute)
	if err != nil {
		t.Fatalf("空闲后接管失败: %v", err)
	}
	release2()
	waited := time.Since(start).Round(time.Millisecond)
	if second.PID != first.PID || second.Endpoint != first.Endpoint {
		t.Fatalf("空闲后换了浏览器: pid %d→%d", first.PID, second.PID)
	}
	if f.n != 1 {
		t.Fatalf("空闲 %s 后浏览器被重启（启动 %d 次）", waited, f.n)
	}
	t.Logf("空闲 %s 后仍复用同一浏览器 PID=%d", waited, second.PID)
}

// TestAnIdleLeaseDoesNotRelaunch keeps the browser idle for a short interval
// between two runs of the same process: the second lease must reuse it.
func TestAnIdleLeaseDoesNotRelaunch(t *testing.T) {
	_, c, f := newAttachHarness(t)
	first, release, err := c.Attach(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("第一次接管失败: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("关闭客户端会话失败: %v", err)
	}
	release()
	time.Sleep(300 * time.Millisecond)
	second, release2, err := c.Attach(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("空闲后接管失败: %v", err)
	}
	release2()
	if second.PID != first.PID || second.Endpoint != first.Endpoint {
		t.Fatalf("空闲后换了浏览器: pid %d→%d endpoint %s→%s", first.PID, second.PID, first.Endpoint, second.Endpoint)
	}
	if f.n != 1 {
		t.Fatalf("空闲复用仍启动了 %d 次浏览器", f.n)
	}
}
