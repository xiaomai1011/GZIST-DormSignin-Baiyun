package browserhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// gatedBrowsers is a launcher whose starts can be held open on a channel, so
// the tests interleave cancellation, TTL expiry and Close deterministically
// instead of sleeping and hoping.
type gatedBrowsers struct {
	mu            sync.Mutex
	n             int
	closed        []int
	concurrent    int
	maxConcurrent int
	closeErrs     map[int]error
	stacks        []string
	gate          chan struct{} // non-nil: every start waits for it to close
	started       chan int      // receives the id of a start that has begun
	closeGate     chan struct{} // non-nil: every close waits for it to close
	closeStarted  chan int      // receives the PID whose close has begun
}

func (g *gatedBrowsers) start(_ context.Context, cfg store.Settings) (*edge.Session, error) {
	g.mu.Lock()
	g.n++
	id := g.n
	g.concurrent++
	if g.concurrent > g.maxConcurrent {
		g.maxConcurrent = g.concurrent
	}
	gate, started := g.gate, g.started
	g.mu.Unlock()

	if started != nil {
		select {
		case started <- id:
		default:
		}
	}
	if gate != nil {
		<-gate
	}

	g.mu.Lock()
	g.concurrent--
	g.mu.Unlock()
	return &edge.Session{
		PID:      1000 + id,
		TargetID: fmt.Sprintf("owned-%d", id),
		Endpoint: fmt.Sprintf("ws://127.0.0.1:1/devtools/browser/%d", id),
		UserData: cfg.UserData,
	}, nil
}

func (g *gatedBrowsers) close(s *edge.Session) error {
	g.mu.Lock()
	if s == nil {
		g.mu.Unlock()
		return nil
	}
	pid := s.PID
	g.closed = append(g.closed, pid)
	err := g.closeErrs[pid]
	gate, started := g.closeGate, g.closeStarted
	g.mu.Unlock()

	if started != nil {
		select {
		case started <- pid:
		default:
		}
	}
	if gate != nil {
		<-gate
	}
	return err
}

func (g *gatedBrowsers) launched() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

func (g *gatedBrowsers) closedPIDs() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]int(nil), g.closed...)
}

// harness wires a daemon to gatedBrowsers.
type gatedHarness struct {
	d *Daemon
	c *Client
	g *gatedBrowsers
}

func newGatedHarness(t *testing.T, exitOK bool, cleanup bool) *gatedHarness {
	t.Helper()
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	oldExited := sessionExited
	g := &gatedBrowsers{closeErrs: map[int]error{}}
	launchSession = g.start
	revokeBrowser = g.close
	waitExit = func(*edge.Session, time.Duration) bool { return exitOK }
	t.Cleanup(func() {
		launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait
		sessionExited = oldExited
	})

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	d, err := Start(context.Background(), store.Settings{UserData: filepath.Join(dir, "profile")},
		statePath, cleanup)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	c, err := Dial(statePath, "")
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	return &gatedHarness{d: d, c: c, g: g}
}

// dropResident forgets the fake browser Start launched, so the next lease has
// to start a new one.
func (h *gatedHarness) dropResident() {
	h.d.mu.Lock()
	h.d.session = nil
	h.d.mu.Unlock()
}

// gateNext makes every subsequent start block until release is called.
func (h *gatedHarness) gateNext() {
	h.g.mu.Lock()
	h.g.gate = make(chan struct{})
	h.g.started = make(chan int, 4)
	h.g.mu.Unlock()
}

func (h *gatedHarness) waitStarted(t *testing.T, want int) {
	t.Helper()
	select {
	case id := <-h.g.started:
		if id != want {
			t.Fatalf("启动编号 = %d，期望 %d", id, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("启动 %d 未开始", want)
	}
}

func (h *gatedHarness) release() {
	h.g.mu.Lock()
	defer h.g.mu.Unlock()
	if h.g.gate != nil {
		close(h.g.gate)
		h.g.gate = nil
	}
}

func (h *gatedHarness) leaseAsync(ctx context.Context, ttl time.Duration) <-chan *http.Response {
	respCh := make(chan *http.Response, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			h.c.state.LeaseURL+"/lease", strings.NewReader(fmt.Sprintf(`{"ttlMs":%d}`, ttl/time.Millisecond)))
		if err != nil {
			respCh <- nil
			return
		}
		req.Header.Set("X-Control-Token", h.c.state.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			respCh <- nil
			return
		}
		if resp.StatusCode != http.StatusOK {
			respCh <- resp
			return
		}
		var offer leaseOffer
		if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
			_ = resp.Body.Close()
			respCh <- nil
			return
		}
		_ = resp.Body.Close()
		body := fmt.Sprintf(`{"id":%d,"token":%q}`, offer.ID, offer.Token)
		creq, err := http.NewRequestWithContext(ctx, http.MethodPost,
			h.c.state.LeaseURL+"/lease/confirm", strings.NewReader(body))
		if err != nil {
			respCh <- nil
			return
		}
		creq.Header.Set("X-Control-Token", h.c.state.Token)
		creq.Header.Set("Content-Type", "application/json")
		cresp, err := http.DefaultClient.Do(creq)
		if err != nil {
			respCh <- nil
			return
		}
		respCh <- cresp
	}()
	return respCh
}

func waitLaunches(t *testing.T, d *Daemon, want int) {
	t.Helper()
	waitUntil(t, 10*time.Second, func() bool { return d.Status().Launches == want })
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

// TestACancelledWaitStillAdoptsOneBrowser: cancelling the request must not
// abandon the start; the result is adopted, and no second start runs in
// parallel with the first.
func TestACancelledWaitStillAdoptsOneBrowser(t *testing.T) {
	h := newGatedHarness(t, true, false)
	h.gateNext()
	h.dropResident()

	ctx, cancel := context.WithCancel(context.Background())
	respCh := h.leaseAsync(ctx, time.Minute)
	h.waitStarted(t, 2)
	cancel()
	if resp := <-respCh; resp != nil {
		t.Fatalf("取消后仍拿到租约: %d", resp.StatusCode)
	}
	h.release()
	waitLaunches(t, h.d, 2)

	resp := h.c.rawLease(t, 5*time.Second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("后续租约状态 = %d，期望 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if h.g.maxConcurrent != 1 {
		t.Fatalf("同时启动了 %d 个浏览器", h.g.maxConcurrent)
	}
	if got := h.g.launched(); got != 2 {
		t.Fatalf("启动次数 = %d，期望 2（第二个必须复用）", got)
	}
}

// TestASecondClientWaitsForTheInFlightStart: the first request times out at its
// own lease deadline; the next client must wait for that same start instead of
// launching a second browser or being handed a lease early.
func TestASecondClientWaitsForTheInFlightStart(t *testing.T) {
	h := newGatedHarness(t, true, false)
	h.gateNext()
	h.dropResident()

	ctx, cancel := context.WithCancel(context.Background())
	first := h.leaseAsync(ctx, time.Minute)
	h.waitStarted(t, 2)
	second := h.leaseAsync(context.Background(), 30*time.Second)
	cancel()
	if resp := <-first; resp != nil && resp.StatusCode == http.StatusOK {
		t.Fatalf("取消的请求仍返回 200")
	}
	h.release()

	resp := <-second
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("第二次租约失败: %v", resp)
	}
	_ = resp.Body.Close()
	if got := h.g.launched(); got != 2 {
		t.Fatalf("启动次数 = %d，期望 2（第二个客户端必须复用同一次启动）", got)
	}
	if got := h.g.maxConcurrent; got != 1 {
		t.Fatalf("同时启动了 %d 个浏览器", got)
	}
}

// TestRevokeDuringLaunchDiscardsLateBrowser: revoking while a start is running
// must wait for it, discard the result and clean the process up.
func TestRevokeDuringLaunchDiscardsLateBrowser(t *testing.T) {
	h := newGatedHarness(t, true, false)
	h.gateNext()
	h.dropResident()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	respCh := h.leaseAsync(ctx, time.Minute)
	h.waitStarted(t, 2)

	done := make(chan error, 1)
	go func() { done <- h.d.revokeAll(10 * time.Second) }()
	select {
	case err := <-done:
		t.Fatalf("撤销在启动完成前返回: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	h.release()
	if err := <-done; err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if got := h.g.closedPIDs(); len(got) != 1 || got[0] != 1002 {
		t.Fatalf("被撤销的浏览器 = %v，期望 [1002]", got)
	}
	if got := h.d.Status().Launches; got != 1 {
		t.Fatalf("迟到的浏览器被登记为当前会话（启动计数 %d）", got)
	}
	_ = <-respCh
}

// TestCloseWaitsForInFlightLaunch: Close reports success only after the start
// that was running has been cleaned up and the throwaway profile removed.
func TestCloseWaitsForInFlightLaunch(t *testing.T) {
	h := newGatedHarness(t, true, true)
	h.gateNext()
	h.dropResident()
	profile := h.d.ownedProfile
	if profile == "" {
		t.Fatal("未创建临时 profile")
	}

	respCh := h.leaseAsync(context.Background(), time.Minute)
	h.waitStarted(t, 2)

	done := make(chan error, 1)
	go func() { done <- h.d.Close() }()
	waitUntil(t, 5*time.Second, func() bool { return h.d.Status().Closing })
	select {
	case err := <-done:
		t.Fatalf("Close 在启动完成前返回: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	h.release()
	if err := <-done; err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("profile 应已删除: %v", err)
	}
	if got := h.g.closedPIDs(); len(got) != 1 || got[0] != 1002 {
		t.Fatalf("被关闭的浏览器 = %v，期望 [1002]", got)
	}
	_ = <-respCh
}

// TestCloseKeepsProfileWhenLateSessionCannotBeCleaned: a late session that
// cannot be confirmed dead must fail the close and preserve the profile.
func TestCloseKeepsProfileWhenLateSessionCannotBeCleaned(t *testing.T) {
	h := newGatedHarness(t, true, true)
	h.gateNext()
	h.dropResident()
	h.g.mu.Lock()
	h.g.closeErrs[1002] = errors.New("模拟无法关闭")
	h.g.mu.Unlock()
	profile := h.d.ownedProfile

	respCh := h.leaseAsync(context.Background(), time.Minute)
	h.waitStarted(t, 2)

	done := make(chan error, 1)
	go func() { done <- h.d.Close() }()
	h.release()
	if err := <-done; err == nil {
		t.Fatal("迟到会话清理失败时 Close 不应报成功")
	}
	if _, statErr := os.Stat(profile); statErr != nil {
		t.Fatalf("profile 应保留: %v", statErr)
	}
	_ = <-respCh
}

// TestACleanupFailureOutlivesTheLaunchRecord: a late browser whose cleanup
// failed must keep failing Close even after the launch record is gone; the
// profile stays because a live process may still hold it.
func TestACleanupFailureOutlivesTheLaunchRecord(t *testing.T) {
	h := newGatedHarness(t, true, true)
	h.gateNext()
	h.dropResident()
	h.g.mu.Lock()
	h.g.closeErrs[1002] = errors.New("模拟整树清理失败")
	h.g.mu.Unlock()
	profile := h.d.ownedProfile

	_ = h.leaseAsync(context.Background(), time.Minute)
	h.waitStarted(t, 2)
	// A revocation may already have returned to its caller by the time the
	// start finishes; what it decided to discard must stay decided.
	h.d.launchMu.Lock()
	if h.d.inflight == nil {
		h.d.launchMu.Unlock()
		t.Fatal("缺少在途启动")
	}
	h.d.inflight.discarded = true
	h.d.launchMu.Unlock()
	h.release()

	waitUntil(t, 10*time.Second, func() bool {
		h.d.mu.Lock()
		cleanupFailed := h.d.cleanupErr != nil
		h.d.mu.Unlock()
		h.d.launchMu.Lock()
		finished := h.d.inflight == nil
		h.d.launchMu.Unlock()
		return cleanupFailed && finished
	})

	if err := h.d.Close(); err == nil {
		t.Fatal("清理失败被丢失：Close 报告成功")
	}
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("profile 应保留: %v", err)
	}
}

// TestTTLRevocationAndCloseShareOneTeardown: while the TTL revocation is still
// closing the browser, Close must wait for that same teardown instead of
// seeing a nil session and treating it as done.
func TestTTLRevocationAndCloseShareOneTeardown(t *testing.T) {
	h := newGatedHarness(t, true, true)
	h.dropResident()

	resp := h.c.rawLease(t, time.Second)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("租约状态 = %d，期望 200", resp.StatusCode)
	}
	_ = resp.Body.Close()
	pid := h.d.Status().PID

	h.g.mu.Lock()
	h.g.closeGate = make(chan struct{})
	h.g.closeStarted = make(chan int, 2)
	h.g.mu.Unlock()

	select {
	case got := <-h.g.closeStarted:
		if got != pid {
			t.Fatalf("关闭的 PID = %d，期望 %d", got, pid)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("TTL 撤销没有开始关闭浏览器")
	}

	done := make(chan error, 1)
	go func() { done <- h.d.Close() }()
	select {
	case err := <-done:
		t.Fatalf("Close 在清理完成前返回: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(h.g.closeGate)
	if err := <-done; err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if _, err := os.Stat(h.d.ownedProfile); !os.IsNotExist(err) {
		t.Fatalf("确认退出后临时 profile 应删除: %v", err)
	}
	if got := len(h.g.closedPIDs()); got != 1 {
		t.Fatalf("关闭次数 = %d，期望 1（两条路径必须共享同一次清理）", got)
	}
}

// TestAFailedReapStopsTheNextStart: the resident browser died, but its process
// tree could not be reaped. Starting a new one would collide with the profile
// lock, so the daemon must refuse instead.
func TestAFailedReapStopsTheNextStart(t *testing.T) {
	h := newGatedHarness(t, true, false)

	h.d.mu.Lock()
	old := h.d.session
	h.d.mu.Unlock()
	if old == nil {
		t.Fatal("缺少常驻浏览器")
	}
	sessionExited = func(s *edge.Session) bool { return s == old }
	h.g.mu.Lock()
	h.g.closeErrs[old.PID] = errors.New("模拟子进程回收失败")
	h.g.mu.Unlock()

	resp := h.c.rawLease(t, 5*time.Second)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("旧进程未确认清理时不应发放租约")
	}
	_ = resp.Body.Close()
	if got := h.g.launched(); got != 1 {
		t.Fatalf("启动次数 = %d，期望 1（清理失败后不得继续启动）", got)
	}
	if st := h.d.Status(); st.Broken == "" {
		t.Fatal("清理失败后应进入拒绝派发状态")
	}
}
