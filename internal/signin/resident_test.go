package signin

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// TestResidentModeNeverFallsBackToAPrivateBrowser locks the safety rule: when
// resident mode is on and the host cannot be reached, the run fails and no
// private Edge is started. A sign-in from an unaccounted browser is worse than
// no sign-in at all.
func TestResidentModeNeverFallsBackToAPrivateBrowser(t *testing.T) {
	launches := 0
	old := launchEdge
	launchEdge = func(ctx context.Context, cfg store.Settings) (*edge.Session, error) {
		launches++
		return &edge.Session{}, nil
	}
	t.Cleanup(func() { launchEdge = old })

	r := &Runner{Cfg: store.Settings{ResidentBrowser: true, UserData: t.TempDir()}}
	sess, release, err := r.openBrowser(context.Background())
	if err == nil {
		t.Fatal("宿主不存在时不应成功")
	}
	if sess != nil || release != nil {
		t.Fatal("失败时不应返回会话")
	}
	if launches != 0 {
		t.Fatalf("常驻模式在宿主不可用时启动了 %d 次独立浏览器", launches)
	}
	if !strings.Contains(err.Error(), "不会改用独立浏览器") {
		t.Fatalf("错误应明确说明不切换路径: %v", err)
	}
}

// TestResidentModeFailsClosedOnABrokenStateFile: an unreadable or forged state
// file is also a hard stop, not a reason to start a private browser.
func TestResidentModeFailsClosedOnABrokenStateFile(t *testing.T) {
	launches := 0
	old := launchEdge
	launchEdge = func(ctx context.Context, cfg store.Settings) (*edge.Session, error) {
		launches++
		return &edge.Session{}, nil
	}
	t.Cleanup(func() { launchEdge = old })

	r := &Runner{Cfg: store.Settings{ResidentBrowser: true, UserData: t.TempDir()}}
	path, err := residentStatePath(r.Cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.openBrowser(context.Background()); err == nil {
		t.Fatal("状态文件损坏时不应成功")
	}
	if launches != 0 {
		t.Fatalf("状态文件损坏时启动了 %d 次独立浏览器", launches)
	}
}

// TestPrivateModeUsesItsOwnBrowser proves the old path is untouched: without the
// resident flag the launcher is called and the host is never consulted.
func TestPrivateModeUsesItsOwnBrowser(t *testing.T) {
	launches := 0
	old := launchEdge
	launchEdge = func(ctx context.Context, cfg store.Settings) (*edge.Session, error) {
		launches++
		return &edge.Session{PID: 42}, nil
	}
	t.Cleanup(func() { launchEdge = old })

	r := &Runner{Cfg: store.Settings{UserData: t.TempDir()}}
	sess, release, err := r.openBrowser(context.Background())
	if err != nil || sess == nil || sess.PID != 42 {
		t.Fatalf("独立模式应正常启动: %v", err)
	}
	if release != nil {
		t.Fatal("独立模式没有租约可释放")
	}
	if launches != 1 {
		t.Fatalf("独立浏览器启动 %d 次", launches)
	}
}

// TestResidentStatePathLivesInsideTheAccountProfile pins where the host's state
// file is expected: inside the account's own profile, so two accounts can never
// resolve to the same discovery file.
func TestResidentStatePathLivesInsideTheAccountProfile(t *testing.T) {
	cfg := store.Settings{UserData: "profiles", EdgePath: `C:\Edge\msedge.exe`}
	got, err := residentStatePath(cfg)
	if err != nil {
		t.Fatalf("解析状态路径失败: %v", err)
	}
	profile, err := edge.ProfilePath(cfg)
	if err != nil {
		t.Fatalf("解析 profile 失败: %v", err)
	}
	if filepath.Clean(filepath.Dir(got)) != filepath.Clean(profile) {
		t.Fatalf("状态文件应在账号 profile 内: %s vs %s", got, profile)
	}
	if filepath.Base(got) != ".browserhost-state.json" {
		t.Fatalf("状态文件名不对: %s", got)
	}
}

// A refused host must stop the whole Run before the business step: no private
// browser, no lease, no attendance submission.
func TestARefusedResidentHostSubmitsNothing(t *testing.T) {
	oldNow, oldSign, oldLaunch := runNow, clickSignFn, launchEdge
	runNow = func() time.Time {
		// This tests host refusal, not the late-line timer. Tomorrow keeps the
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
		UserData:        filepath.Join(t.TempDir(), "account-b"),
		URL:             "https://xsfw.gzist.edu.cn/",
		LateLine:        "23:00",
		AttWindow:       "21:00-23:00",
	}
	path, err := residentStatePath(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "account-a")
	state := `{"pid":1,"userData":` + strconv.Quote(other) + `,"leaseUrl":"http://127.0.0.1:9","token":"x"}`
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Runner{Cfg: cfg}
	res := r.Run(context.Background(), true)
	if res.Exit != 9 {
		t.Fatalf("被拒绝的宿主应以退出码 9 结束，实际 %+v", res)
	}
	if !strings.Contains(res.Reason, "不会改用独立浏览器") {
		t.Fatalf("原因应说明不切换路径: %q", res.Reason)
	}
	if submits != 0 {
		t.Fatalf("被拒绝的宿主不应触发业务提交，实际 %d 次", submits)
	}
	if launches != 0 {
		t.Fatalf("被拒绝的宿主不应启动独立浏览器，实际 %d 次", launches)
	}
}

// Two accounts must never share a discovery file: otherwise a run for account B
// could find (and attach to) the browser account A is signed in on.
func TestResidentStatePathsArePerAccount(t *testing.T) {
	a := store.Settings{UserData: filepath.Join("profiles", "a"), EdgePath: `C:\Edge\msedge.exe`}
	b := store.Settings{UserData: filepath.Join("profiles", "b"), EdgePath: `C:\Edge\msedge.exe`}
	pa, err := residentStatePath(a)
	if err != nil {
		t.Fatalf("解析 A 失败: %v", err)
	}
	pb, err := residentStatePath(b)
	if err != nil {
		t.Fatalf("解析 B 失败: %v", err)
	}
	if filepath.Clean(pa) == filepath.Clean(pb) {
		t.Fatalf("两个账号解析到了同一个状态文件: %s", pa)
	}
}

// A discovery file left by another account must stop the run before any lease
// is taken — no attach, no sign-in, and no private browser either.
func TestAnotherAccountsHostIsRefusedBeforeAnyLease(t *testing.T) {
	launches := 0
	old := launchEdge
	launchEdge = func(ctx context.Context, cfg store.Settings) (*edge.Session, error) {
		launches++
		return &edge.Session{}, nil
	}
	t.Cleanup(func() { launchEdge = old })

	cfg := store.Settings{ResidentBrowser: true, UserData: filepath.Join(t.TempDir(), "account-b")}
	path, err := residentStatePath(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	otherProfile := filepath.Join(t.TempDir(), "account-a")
	state := `{"pid":4242,"userData":` + strconv.Quote(otherProfile) + `,"leaseUrl":"http://127.0.0.1:9","token":"x"}`
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &Runner{Cfg: cfg}
	sess, release, err := r.openBrowser(context.Background())
	if err == nil {
		t.Fatal("他人账号的宿主被发现文件不能当作可用宿主")
	}
	if sess != nil || release != nil {
		t.Fatal("失败时不应返回会话")
	}
	if launches != 0 {
		t.Fatalf("被拒绝时应零独立浏览器启动，实际 %d", launches)
	}
	if !strings.Contains(err.Error(), "不会改用独立浏览器") {
		t.Fatalf("错误应说明不切换路径: %v", err)
	}
}

// A manager that is already closed is the state left behind by a failed
// cleanup or by switching the mode off: the run must stop at the entry point,
// with no private browser and no attendance submission.
func TestAClosedResidentManagerStopsTheRunBeforeBusiness(t *testing.T) {
	oldNow, oldSign, oldLaunch := runNow, clickSignFn, launchEdge
	runNow = func() time.Time {
		// This tests a closed manager, not the late-line timer. Tomorrow keeps
		// the real context deadline in the future, including after 23:00.
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

	m := browserhost.NewManager(false)
	if err := m.CloseAll(); err != nil {
		t.Fatalf("关闭测试管理器: %v", err)
	}
	cfg := store.Settings{
		ResidentBrowser: true,
		UserData:        filepath.Join(t.TempDir(), "account"),
		URL:             "https://xsfw.gzist.edu.cn/",
		LateLine:        "23:00",
		AttWindow:       "21:00-23:00",
	}
	r := &Runner{Cfg: cfg, Hosts: m}
	res := r.Run(context.Background(), true)
	if res.Exit != 9 {
		t.Fatalf("已关闭的常驻管理器应以退出码 9 结束，实际 %+v", res)
	}
	if !strings.Contains(res.Reason, "不会改用独立浏览器") {
		t.Fatalf("原因应说明不切换路径: %q", res.Reason)
	}
	if submits != 0 || launches != 0 {
		t.Fatalf("不应提交业务或启动独立浏览器：提交 %d、启动 %d", submits, launches)
	}
}
