package signin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// A host that cannot start ends the run: no business submission, and above all
// no quiet switch to a private browser.
func TestAResidentHostThatCannotStartSubmitsNothing(t *testing.T) {
	oldNow, oldSign, oldLaunch := runNow, clickSignFn, launchEdge
	runNow = func() time.Time {
		// This tests host failure, not the late-line timer. Tomorrow keeps the
		// real context deadline in the future even when tests run after 23:00.
		n := time.Now().AddDate(0, 0, 1)
		return time.Date(n.Year(), n.Month(), n.Day(), 21, 30, 0, 0, n.Location())
	}
	submits := 0
	clickSignFn = func(*Runner, context.Context, store.Settings) error {
		submits++
		return nil
	}
	launches := 0
	launchEdge = func(context.Context, store.Settings) (*edge.Session, error) {
		launches++
		return &edge.Session{}, nil
	}
	t.Cleanup(func() { runNow, clickSignFn, launchEdge = oldNow, oldSign, oldLaunch })

	cfg := store.Settings{
		ResidentBrowser: true,
		EdgePath:        filepath.Join(t.TempDir(), "missing-browser.exe"),
		UserData:        filepath.Join(t.TempDir(), "account"),
		URL:             "https://xsfw.gzist.edu.cn/",
		LateLine:        "23:00",
		AttWindow:       "21:00-23:00",
	}
	m := browserhost.NewManager(false)
	t.Cleanup(func() { _ = m.CloseAll() })

	res := (&Runner{Cfg: cfg, Hosts: m}).Run(context.Background(), true)
	if res.Exit != 9 {
		t.Fatalf("宿主无法启动应以退出码 9 结束，实际 %+v", res)
	}
	if submits != 0 || launches != 0 {
		t.Fatalf("不应有业务提交或独立浏览器，实际提交 %d、独立启动 %d", submits, launches)
	}
}

// Two application-level tasks must drive the same resident browser. This is the
// path the tray application uses: Runner.openBrowser through the Manager.
func TestTheApplicationReusesOneResidentBrowserAcrossTwoTasks(t *testing.T) {
	if os.Getenv("BROWSERHOST_EDGE_TEST") != "1" {
		t.Skip("设置 BROWSERHOST_EDGE_TEST=1 才启动真实 Edge")
	}
	cfg := store.Settings{
		ResidentBrowser: true,
		EdgePath:        realEdge(t),
		UserData:        filepath.Join(t.TempDir(), "account"),
		URL:             "http://127.0.0.1:9/",
	}
	m := browserhost.NewManager(false)
	t.Cleanup(func() { _ = m.CloseAll() })
	r := &Runner{Cfg: cfg, Log: func(string) {}, Hosts: m}

	// Each task gets its own budget: an idle gap must not consume the next
	// task's context, which would look like a busy host.
	task := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 120*time.Second)
	}

	ctx1, cancel1 := task()
	first, release1, err := r.openBrowser(ctx1)
	if err != nil {
		cancel1()
		t.Fatalf("第一次任务启动常驻浏览器失败: %v", err)
	}
	cancel1()
	pid := first.PID
	release1()

	ctx2, cancel2 := task()
	second, release2, err := r.openBrowser(ctx2)
	if err != nil {
		cancel2()
		t.Fatalf("第二次任务应复用宿主: %v", err)
	}
	cancel2()
	if second.PID != pid {
		t.Fatalf("两次任务应复用同一浏览器：first=%d second=%d", pid, second.PID)
	}
	release2()

	// Optional real idle: the browser must survive a long gap between tasks.
	if raw := os.Getenv("BROWSERHOST_APP_IDLE"); raw != "" {
		idle, err := time.ParseDuration(raw)
		if err != nil {
			t.Fatalf("BROWSERHOST_APP_IDLE 无效: %v", err)
		}
		time.Sleep(idle)
		ctx3, cancel3 := task()
		third, release3, err := r.openBrowser(ctx3)
		cancel3()
		if err != nil {
			t.Fatalf("空闲 %s 后应仍能复用宿主: %v", idle, err)
		}
		if third.PID != pid {
			t.Fatalf("空闲后应仍是同一浏览器：first=%d third=%d", pid, third.PID)
		}
		release3()
	}

	// After both tasks the host must still be alive for the next one.
	if n := m.Hosts(); n != 1 {
		t.Fatalf("任务结束后宿主应保留一个，实得 %d", n)
	}
	if err := m.CloseAll(); err != nil {
		t.Fatalf("退出时应能关闭宿主: %v", err)
	}
}

func realEdge(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("BROWSERHOST_EDGE"); p != "" {
		return p
	}
	for _, p := range []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("找不到 Edge")
	return ""
}
