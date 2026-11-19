package browserhost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// These tests drive a real Edge against a loopback page. They never touch the
// school, never read a real profile and never leave a browser behind. Like the
// other Edge tests in this repository they only run when DORMSIGN_EDGE_TEST=1.

func edgeExe(t *testing.T) string {
	t.Helper()
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("未设置 DORMSIGN_EDGE_TEST=1，跳过真实 Edge 集成测试")
	}
	candidates := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("本机没有 Edge，跳过长驻浏览器集成测试")
	return ""
}

func newHarness(t *testing.T) (*Daemon, *Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/write", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: r.URL.Query().Get("k"), Value: r.URL.Query().Get("v"), Path: "/"})
		_, _ = w.Write([]byte("<html><body>write</body></html>"))
	})
	mux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>read</body></html>"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	statePath := filepath.Join(t.TempDir(), "state.json")
	cfg := store.Settings{
		EdgePath: edgeExe(t),
		ViewW:    430,
		ViewH:    900,
	}
	d, err := Start(context.Background(), cfg, statePath, true)
	if err != nil {
		t.Fatalf("启动长驻浏览器失败: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("清理长驻浏览器失败: %v", err)
		}
	})
	c, err := Dial(statePath, "")
	if err != nil {
		t.Fatalf("读取状态文件失败: %v", err)
	}
	return d, c, srv
}

func goTo(url string) Task {
	return func(ctx context.Context) error {
		return chromedp.Run(ctx, chromedp.Navigate(url))
	}
}

func TestBrowserIsReusedAcrossRuns(t *testing.T) {
	_, c, srv := newHarness(t)

	if err := c.Run(context.Background(), goTo(srv.URL+"/write?k=lease&v=one"), RunOptions{}); err != nil {
		t.Fatalf("第一次任务失败: %v", err)
	}
	var cookie string
	read := func(ctx context.Context) error {
		return chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/read"), chromedp.Evaluate(`document.cookie`, &cookie))
	}
	if err := c.Run(context.Background(), read, RunOptions{}); err != nil {
		t.Fatalf("第二次任务失败: %v", err)
	}
	if !strings.Contains(cookie, "lease=one") {
		t.Fatalf("第二次任务没有看到第一次写入的 Cookie: %q", cookie)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatalf("状态查询失败: %v", err)
	}
	if st.Launches != 1 {
		t.Fatalf("两次任务应复用同一个浏览器，实际启动 %d 次", st.Launches)
	}
	if st.Tasks != 2 {
		t.Fatalf("任务计数应为 2，实际 %d", st.Tasks)
	}
}

func TestConcurrentRunsDoNotOverlap(t *testing.T) {
	_, c, srv := newHarness(t)

	var inside, peak int32
	slow := func(ctx context.Context) error {
		n := atomic.AddInt32(&inside, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
		atomic.AddInt32(&inside, -1)
		return chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/read"))
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.Run(context.Background(), slow, RunOptions{Wait: 30 * time.Second})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个并发任务失败: %v", i+1, err)
		}
	}
	if got := atomic.LoadInt32(&peak); got != 1 {
		t.Fatalf("并发任务发生了重叠，峰值 %d", got)
	}
	st, _ := c.Status()
	if st.Launches != 1 {
		t.Fatalf("并发任务不应再启动浏览器，实际 %d 次", st.Launches)
	}
}

func TestRelaunchAfterTheWindowIsClosed(t *testing.T) {
	_, c, srv := newHarness(t)
	if err := c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{}); err != nil {
		t.Fatalf("首次任务失败: %v", err)
	}
	before, _ := c.Status()

	kill := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(before.PID))
	if out, err := kill.CombinedOutput(); err != nil {
		t.Fatalf("结束浏览器失败: %v %s", err, out)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, _ := c.Status()
		if !st.Alive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("浏览器被杀掉后 daemon 仍认为它活着")
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{}); err != nil {
		t.Fatalf("窗口关闭后的任务失败: %v", err)
	}
	after, _ := c.Status()
	if after.Launches != before.Launches+1 {
		t.Fatalf("窗口关闭后应重新启动一次，launches %d → %d", before.Launches, after.Launches)
	}
	if after.PID == before.PID {
		t.Fatal("重新启动后 PID 应变化")
	}
}

func TestExpiryRevokesTheOldBrowserBeforeTheNextTask(t *testing.T) {
	_, c, srv := newHarness(t)
	before, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	oldErr := make(chan error, 1)
	go func() {
		oldErr <- c.Run(context.Background(), func(ctx context.Context) error {
			if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/read")); err != nil {
				return err
			}
			close(started)
			time.Sleep(3 * time.Second)
			// After the TTL fires the browser is gone: this must fail.
			return chromedp.Run(ctx, chromedp.Evaluate(`document.title`, nil))
		}, RunOptions{LeaseTTL: time.Second, Wait: 8 * time.Second})
	}()
	<-started
	time.Sleep(2500 * time.Millisecond)

	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Revoking || st.Leased {
		t.Fatalf("过期租约应已撤销并收回: %+v", st)
	}

	if err := c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{Wait: 10 * time.Second}); err != nil {
		t.Fatalf("撤销后新任务失败: %v", err)
	}
	after, _ := c.Status()
	if after.PID == before.PID {
		t.Fatalf("新任务应使用新浏览器，PID 仍是 %d", after.PID)
	}
	select {
	case err := <-oldErr:
		if err == nil {
			t.Fatal("旧任务在浏览器被撤销后仍successfully操作了页面")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("旧任务没有退出")
	}
}

func TestCancelledTaskReleasesTheLease(t *testing.T) {
	_, c, srv := newHarness(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	stuck := func(ctx context.Context) error {
		return chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/read"), chromedp.Sleep(5*time.Second))
	}
	if err := c.Run(ctx, stuck, RunOptions{Wait: 10 * time.Second}); err == nil {
		t.Fatal("被取消的任务应返回错误")
	}

	done := make(chan error, 1)
	go func() {
		done <- c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{Wait: 15 * time.Second})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("取消后租约没有释放: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("取消后第二个任务一直拿不到租约")
	}
}

func TestShutdownRemovesStateAndProfile(t *testing.T) {
	d, c, _ := newHarness(t)
	st, _ := c.Status()
	profile := d.State().UserData
	statePath := d.statePath

	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("状态文件应被删除: %v", err)
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatalf("临时 profile 应被删除: %v", err)
	}
	if pidAlive(t, st.PID) {
		t.Fatalf("关闭后浏览器进程 %d 仍在", st.PID)
	}
}

// The daemon's CDP session must outlive the HTTP request that triggered the
// launch; otherwise every later management call (and graceful close) is dead.
func TestHostControlSessionSurvivesLeaseRequests(t *testing.T) {
	_, c, srv := newHarness(t)
	if err := c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{}); err != nil {
		t.Fatalf("首次任务失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // the lease request has long finished
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Alive {
		t.Fatal("租约请求结束后浏览器进程不应退出")
	}
	if !st.Control {
		t.Fatal("宿主 CDP 会话被短命请求的上下文取消了")
	}
	if st.Launches != 1 {
		t.Fatalf("不应重启浏览器，launches=%d", st.Launches)
	}
	if err := c.Run(context.Background(), goTo(srv.URL+"/read"), RunOptions{}); err != nil {
		t.Fatalf("第二次任务失败: %v", err)
	}
}

// childReport is what the helper process writes: proof it drove the real page
// over CDP and what it saw there, not just a PID echoed by the host.
type childReport struct {
	PID    int    `json:"pid"`
	Cookie string `json:"cookie"`
	Marker string `json:"marker"`
	Title  string `json:"title"`
}

// TestHelperCDPRead is the child half of TestCrossProcessCDPAttachSharesPageState.
// It attaches to the host from another process, reads page state over CDP and
// writes a report file. Skipped unless the parent supplies the environment.
func TestHelperCDPRead(t *testing.T) {
	state := os.Getenv("BROWSERHOST_CHILD_STATE")
	if state == "" {
		t.Skip("仅作为跨进程测试的子进程运行")
	}
	profile := os.Getenv("BROWSERHOST_CHILD_PROFILE")
	url := os.Getenv("BROWSERHOST_CHILD_URL")
	report := os.Getenv("BROWSERHOST_CHILD_REPORT")

	c, err := Dial(state, profile)
	if err != nil {
		t.Fatalf("子进程读取状态失败: %v", err)
	}
	sess, release, err := c.Attach(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("子进程附加失败: %v", err)
	}
	defer release()

	var cookie, marker, title string
	if err := chromedp.Run(sess.Ctx,
		chromedp.Navigate(url),
		chromedp.Evaluate(`document.cookie`, &cookie),
		chromedp.Evaluate(`localStorage.getItem('probe')`, &marker),
		chromedp.Title(&title),
	); err != nil {
		t.Fatalf("子进程读取页面失败: %v", err)
	}
	out, _ := json.Marshal(childReport{PID: sess.PID, Cookie: cookie, Marker: marker, Title: title})
	if err := os.WriteFile(report, out, 0o600); err != nil {
		t.Fatalf("子进程写报告失败: %v", err)
	}
}

// TestCrossProcessCDPAttachSharesPageState is the evidence the fake harness
// cannot give: a second OS process attaches to the real resident Edge over CDP,
// sees page state written by the parent, detaches, and the same browser is
// reused after an idle wait — checked by cookie/localStorage content and the
// browser process still being alive, not only by the PID the host reports.
func TestCrossProcessCDPAttachSharesPageState(t *testing.T) {
	d, c, srv := newHarness(t)

	write := func(ctx context.Context) error {
		return chromedp.Run(ctx,
			chromedp.Navigate(srv.URL+"/write?k=cross&v=process"),
			chromedp.Evaluate(`localStorage.setItem('probe','parent-wrote-this')`, nil),
		)
	}
	if err := c.Run(context.Background(), write, RunOptions{}); err != nil {
		t.Fatalf("父进程写入页面状态失败: %v", err)
	}
	before, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("定位测试可执行文件失败: %v", err)
	}
	runChild := func(tag string) childReport {
		t.Helper()
		reportPath := filepath.Join(t.TempDir(), "child-"+tag+".json")
		child := exec.Command(exe, "-test.run=^TestHelperCDPRead$", "-test.timeout=90s")
		child.Env = append(os.Environ(),
			"DORMSIGN_EDGE_TEST=1",
			"BROWSERHOST_CHILD_STATE="+d.statePath,
			"BROWSERHOST_CHILD_PROFILE="+d.State().UserData,
			"BROWSERHOST_CHILD_URL="+srv.URL+"/read",
			"BROWSERHOST_CHILD_REPORT="+reportPath,
		)
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("子进程 %s 失败: %v\n%s", tag, err, out)
		}
		raw, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("读取子进程 %s 报告失败: %v", tag, err)
		}
		var got childReport
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("解析子进程 %s 报告失败: %v", tag, err)
		}
		if got.PID != before.PID {
			t.Fatalf("子进程 %s 附加到了另一个浏览器: %d vs %d", tag, got.PID, before.PID)
		}
		if !strings.Contains(got.Cookie, "cross=process") || got.Marker != "parent-wrote-this" {
			t.Fatalf("子进程 %s 没看到父进程写的页面状态: cookie=%q marker=%q", tag, got.Cookie, got.Marker)
		}
		return got
	}
	// Two separate OS processes attach one after another: the first proves the
	// page state crosses a process boundary, the second proves the browser
	// survived the first process detaching rather than only one reader working.
	first := runChild("first")
	second := runChild("second")
	if second.PID != first.PID {
		t.Fatalf("两次子进程附加到了不同浏览器: %d vs %d", second.PID, first.PID)
	}

	// The child leased, attached and detached. After a real idle wait the same
	// browser must still serve this account with the page state intact.
	idle := 20 * time.Second
	if v := os.Getenv("BROWSERHOST_CROSS_IDLE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			idle = d
		}
	}
	start := time.Now()
	time.Sleep(idle)
	waited := time.Since(start).Round(time.Millisecond)

	var cookieAfter, markerAfter string
	read := func(ctx context.Context) error {
		return chromedp.Run(ctx,
			chromedp.Navigate(srv.URL+"/read"),
			chromedp.Evaluate(`document.cookie`, &cookieAfter),
			chromedp.Evaluate(`localStorage.getItem('probe')`, &markerAfter),
		)
	}
	if err := c.Run(context.Background(), read, RunOptions{}); err != nil {
		t.Fatalf("空闲 %s 后再次任务失败: %v", waited, err)
	}
	after, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if after.PID != before.PID {
		t.Fatalf("空闲后换了浏览器: %d → %d", before.PID, after.PID)
	}
	if after.Launches != 1 {
		t.Fatalf("跨进程与空闲后不应重启浏览器，launches=%d", after.Launches)
	}
	if !strings.Contains(cookieAfter, "cross=process") || markerAfter != "parent-wrote-this" {
		t.Fatalf("空闲后页面状态丢失: cookie=%q marker=%q", cookieAfter, markerAfter)
	}
	if !pidAlive(t, after.PID) {
		t.Fatalf("浏览器进程 %d 不在了", after.PID)
	}
	t.Logf("跨进程附加后空闲 %s，同一浏览器 PID=%d 仍在，页面状态保留", waited, after.PID)
}

func pidAlive(t *testing.T, pid int) bool {
	t.Helper()
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}
