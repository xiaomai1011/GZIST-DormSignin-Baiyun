package browserhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type fakeBrowsers struct {
	mu      sync.Mutex
	n       int
	closed  []int
	failAll bool
	launch  time.Duration
}

func (f *fakeBrowsers) start(_ context.Context, cfg store.Settings) (*edge.Session, error) {
	if f.launch > 0 {
		time.Sleep(f.launch)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return &edge.Session{PID: 1000 + f.n, TargetID: fmt.Sprintf("owned-%d", f.n), Endpoint: fmt.Sprintf("ws://127.0.0.1:1/devtools/browser/%d", f.n), UserData: cfg.UserData}, nil
}

func (f *fakeBrowsers) close(s *edge.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s != nil {
		f.closed = append(f.closed, s.PID)
	}
	if f.failAll {
		return errors.New("模拟关闭失败")
	}
	return nil
}

// newFakeDaemon starts a daemon backed by fake browsers. exitOK controls
// whether a closed fake browser is reported as confirmed gone.
func newFakeDaemon(t *testing.T, exitOK bool) (*Daemon, *Client, *fakeBrowsers) {
	t.Helper()
	return newFakeDaemonWith(t, exitOK, nil)
}

func newFakeDaemonWith(t *testing.T, exitOK bool, configure func(*fakeBrowsers)) (*Daemon, *Client, *fakeBrowsers) {
	t.Helper()
	oldLaunch, oldRevoke, oldWait, oldExited := launchSession, revokeBrowser, waitExit, sessionExited
	f := &fakeBrowsers{}
	if configure != nil {
		configure(f)
	}
	launchSession = f.start
	revokeBrowser = f.close
	waitExit = func(*edge.Session, time.Duration) bool { return exitOK }
	t.Cleanup(func() {
		launchSession, revokeBrowser, waitExit, sessionExited = oldLaunch, oldRevoke, oldWait, oldExited
	})

	statePath := filepath.Join(t.TempDir(), "state.json")
	d, err := Start(context.Background(), store.Settings{UserData: filepath.Join(t.TempDir(), "profile")}, statePath, false)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	c, err := Dial(statePath, "")
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	return d, c, f
}

func (c *Client) rawInvite(t *testing.T, ttl time.Duration) *http.Response {
	t.Helper()
	return c.postJSON(t, "/lease", fmt.Sprintf(`{"ttlMs":%d}`, ttl/time.Millisecond))
}

// rawLease walks the whole handshake: reserve, then confirm. Tests that assert
// on status codes keep working, tests that care about the split use rawInvite.
func (c *Client) rawLease(t *testing.T, ttl time.Duration) *http.Response {
	t.Helper()
	invite := c.rawInvite(t, ttl)
	if invite.StatusCode != http.StatusOK {
		return invite
	}
	var offer leaseOffer
	if err := json.NewDecoder(invite.Body).Decode(&offer); err != nil {
		t.Fatalf("解析预约失败: %v", err)
	}
	_ = invite.Body.Close()
	return c.postJSON(t, "/lease/confirm", fmt.Sprintf(`{"id":%d,"token":%q}`, offer.ID, offer.Token))
}

func (c *Client) postJSON(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, c.state.LeaseURL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Control-Token", c.state.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (c *Client) rawRelease(t *testing.T, id uint64) int {
	t.Helper()
	resp := c.postJSON(t, "/release", fmt.Sprintf(`{"id":%d}`, id))
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func leaseID(t *testing.T, resp *http.Response) uint64 {
	t.Helper()
	defer resp.Body.Close()
	var out leaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("解析租约失败: %v", err)
	}
	return out.ID
}

func TestDialReportsAMissingDaemon(t *testing.T) {
	if _, err := Dial(filepath.Join(t.TempDir(), "nope.json"), ""); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("缺少状态文件时应返回 ErrNoDaemon，实际 %v", err)
	}
}

func TestDialRejectsBrokenState(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"坏 JSON": "{not json",
		"缺令牌":    `{"endpoint":"ws://x","leaseUrl":"http://x"}`,
		"缺连接地址":  `{"endpoint":"ws://x","token":"t"}`,
		"空文件":    "",
	}
	for name, body := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Dial(p, ""); !errors.Is(err, ErrNoDaemon) {
			t.Fatalf("%s: 应返回 ErrNoDaemon，实际 %v", name, err)
		}
	}
}

func TestControlRequiresToken(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)

	post := func(path string, hdr map[string]string, body string) int {
		req, _ := http.NewRequest(http.MethodPost, c.state.LeaseURL+path, bytes.NewReader([]byte(body)))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := post("/lease", nil, `{"ttlMs":5000}`); got != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", got)
	}
	if got := post("/lease", map[string]string{"X-Control-Token": "wrong"}, `{"ttlMs":5000}`); got != http.StatusUnauthorized {
		t.Fatalf("错误令牌应 401，实际 %d", got)
	}
	if got := post("/shutdown", map[string]string{"X-Control-Token": c.state.Token, "Origin": "http://evil.example"}, ""); got != http.StatusForbidden {
		t.Fatalf("带 Origin 的请求应 403，实际 %d", got)
	}
	resp, err := http.Get(c.state.LeaseURL + "/shutdown")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /shutdown 应被拒绝，实际 %d", resp.StatusCode)
	}
	if got := post("/lease", map[string]string{"X-Control-Token": c.state.Token}, `{"ttlMs":5000}`); got != http.StatusOK {
		t.Fatalf("合法令牌应 200，实际 %d", got)
	}
	http.DefaultClient.CloseIdleConnections()
}

func TestLeaseTTLIsValidated(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)
	for name, body := range map[string]string{
		"零":    `{"ttlMs":0}`,
		"负数":   `{"ttlMs":-5000}`,
		"超出上限": `{"ttlMs":3600000}`,
		"整数溢出": `{"ttlMs":9223372036854775807}`,
		"未知字段": `{"ttlMs":5000,"x":1}`,
	} {
		resp := c.postJSON(t, "/lease", body)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: 应 400，实际 %d", name, resp.StatusCode)
		}
	}
}

func TestStaleReleaseCannotFreeTheNextLease(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)

	first := leaseID(t, c.rawLease(t, 5*time.Second))
	if got := c.rawRelease(t, first); got != http.StatusNoContent {
		t.Fatalf("第一次释放应 204，实际 %d", got)
	}
	second := leaseID(t, c.rawLease(t, 5*time.Second))
	if second == first {
		t.Fatalf("租约标识不得复用: %d", second)
	}
	if got := c.rawRelease(t, first); got != http.StatusConflict {
		t.Fatalf("迟到的释放应被拒绝，实际 %d", got)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Leased {
		t.Fatal("迟到的释放把新租约放开了")
	}
}

func TestOldTimerCannotExpireTheNextLease(t *testing.T) {
	_, c, f := newFakeDaemon(t, true)

	first := leaseID(t, c.rawLease(t, time.Second))
	if got := c.rawRelease(t, first); got != http.StatusNoContent {
		t.Fatalf("释放失败: %d", got)
	}
	second := leaseID(t, c.rawLease(t, 10*time.Second))
	time.Sleep(1500 * time.Millisecond) // the first lease's timer would have fired
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Leased {
		t.Fatal("旧租约的定时器把新租约踢掉了")
	}
	if st.Launches != 1 {
		t.Fatalf("旧定时器不应导致浏览器重启，launches=%d", st.Launches)
	}
	f.mu.Lock()
	closed := len(f.closed)
	f.mu.Unlock()
	if closed != 0 {
		t.Fatalf("旧定时器不应撤销浏览器，实际关闭 %d 次", closed)
	}
	if got := c.rawRelease(t, second); got != http.StatusNoContent {
		t.Fatalf("释放第二个租约失败: %d", got)
	}
}

func TestExpiryRevokesTheBrowserBeforeTheNextLease(t *testing.T) {
	_, c, f := newFakeDaemon(t, true)

	first := leaseID(t, c.rawLease(t, time.Second))
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := c.Status()
		if err != nil {
			t.Fatal(err)
		}
		if !st.Leased && !st.Revoking {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TTL 到期后租约没有收回")
		}
		time.Sleep(50 * time.Millisecond)
	}
	f.mu.Lock()
	closed := append([]int(nil), f.closed...)
	f.mu.Unlock()
	if len(closed) != 1 {
		t.Fatalf("到期应先撤销旧浏览器，实际关闭 %v", closed)
	}

	second := leaseID(t, c.rawLease(t, 5*time.Second))
	if second == first {
		t.Fatal("租约标识不得复用")
	}
	st, _ := c.Status()
	if st.Launches != 2 {
		t.Fatalf("撤销后应启动新浏览器，launches=%d", st.Launches)
	}
	if st.PID == closed[0] {
		t.Fatalf("新浏览器复用了旧 PID %d", st.PID)
	}
}

func TestExpiryThatCannotConfirmExitFailsClosed(t *testing.T) {
	_, c, _ := newFakeDaemon(t, false) // browser never reports exit

	leaseID(t, c.rawLease(t, time.Second))
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := c.Status()
		if err != nil {
			t.Fatal(err)
		}
		if st.Broken != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("撤销失败后 daemon 没有进入拒绝派发状态")
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp := c.rawLease(t, 5*time.Second)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("无法确认退出时应拒绝派发，实际 %d", resp.StatusCode)
	}
}

// A slow browser start that eats the whole TTL must not yield a usable lease.
func TestSlowStartDoesNotHandOutAnExpiredLease(t *testing.T) {
	d, c, f := newFakeDaemon(t, true)
	// Force the next lease to start the browser from scratch, slowly.
	d.mu.Lock()
	d.session = nil
	d.mu.Unlock()
	f.mu.Lock()
	f.launch = 1500 * time.Millisecond
	f.mu.Unlock()

	resp := c.rawLease(t, time.Second)
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("启动耗时超过 TTL 时不得返回可用租约")
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Leased {
		t.Fatal("过期租约仍被标记为已租用")
	}
	// The browser that was still starting never reached a client: it may stay
	// as the daemon's resident browser, but nobody may hold a lease on it.
	f.mu.Lock()
	launched := f.n
	f.mu.Unlock()
	if launched == 0 {
		t.Fatal("应当尝试启动浏览器")
	}
}

func TestCloseFailureKeepsTheProfile(t *testing.T) {
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	defer func() { launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait }()
	f := &fakeBrowsers{failAll: true}
	launchSession = f.start
	revokeBrowser = f.close
	waitExit = func(*edge.Session, time.Duration) bool { return true }

	statePath := filepath.Join(t.TempDir(), "state.json")
	d, err := Start(context.Background(), store.Settings{}, statePath, true)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	profile := d.State().UserData
	if profile == "" {
		t.Fatal("daemon 应创建自己的临时 profile")
	}
	first := d.Close()
	if first == nil {
		t.Fatal("浏览器关闭失败时 Close 必须返回错误")
	}
	if _, err := os.Stat(profile); err != nil {
		t.Fatalf("关闭失败后不应删除临时 profile: %v", err)
	}
	second := d.Close()
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("重复 Close 应保留第一次的错误: first=%v second=%v", first, second)
	}
	_ = os.RemoveAll(profile)
}

func TestCloseRemovesOnlyTheProfileItCreated(t *testing.T) {
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	defer func() { launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait }()
	launchSession = (&fakeBrowsers{}).start
	revokeBrowser = func(*edge.Session) error { return nil }
	waitExit = func(*edge.Session, time.Duration) bool { return true }

	// A directory the caller made, carrying our prefix: ownership comes from
	// creation, not from the name, so this must survive.
	foreign, err := os.MkdirTemp("", "dormsign-browserhost-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(foreign) })

	statePath := filepath.Join(t.TempDir(), "state.json")
	d, err := Start(context.Background(), store.Settings{UserData: foreign}, statePath, true)
	if err != nil {
		t.Fatal(err)
	}
	own := d.State().UserData
	if own == foreign {
		t.Fatal("cleanupProfile 时 daemon 必须自建目录，而不是接管调用方目录")
	}
	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if _, err := os.Stat(own); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("daemon 自建的 profile 应被删除: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("调用方预建的目录不得删除: %v", err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("状态文件应被删除: %v", err)
	}
}

func TestExternalProfileWithoutCleanupIsKept(t *testing.T) {
	oldLaunch, oldRevoke, oldWait := launchSession, revokeBrowser, waitExit
	defer func() { launchSession, revokeBrowser, waitExit = oldLaunch, oldRevoke, oldWait }()
	launchSession = (&fakeBrowsers{}).start
	revokeBrowser = func(*edge.Session) error { return nil }
	waitExit = func(*edge.Session, time.Duration) bool { return true }

	external, err := os.MkdirTemp("", "dormsign-browserhost-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(external) })
	statePath := filepath.Join(t.TempDir(), "state.json")

	d, err := Start(context.Background(), store.Settings{UserData: external}, statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.State().UserData; got != external {
		t.Fatalf("cleanupProfile=false 时应使用调用方目录，实际 %q", got)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if _, err := os.Stat(external); err != nil {
		t.Fatalf("调用方目录不得删除: %v", err)
	}
}

func TestWaitingLeaseIsRejectedWhenClosing(t *testing.T) {
	d, c, f := newFakeDaemon(t, true)

	leaseID(t, c.rawLease(t, 30*time.Second))
	done := make(chan error, 1)
	go func() {
		done <- c.Run(context.Background(), func(context.Context) error { return nil }, RunOptions{Wait: 10 * time.Second})
	}()
	time.Sleep(200 * time.Millisecond) // let it block on the lease

	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("关闭时仍在排队的任务必须被拒绝")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("关闭后排队任务没有被唤醒")
	}
	f.mu.Lock()
	launches := f.n
	f.mu.Unlock()
	if launches != 1 {
		t.Fatalf("关闭过程中不应启动新的浏览器，实际 %d 次", launches)
	}
}
