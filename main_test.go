package main

import (
	"context"
	"errors"
	"testing"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// appTestHost stands in for a resident Edge process: the application code under
// test only needs liveness, lease state and a close result.
type appTestHost struct {
	alive    bool
	leased   bool
	closeErr error
	closed   int
}

func (h *appTestHost) Alive() bool { return h.alive }

func (h *appTestHost) Status() browserhost.Status {
	return browserhost.Status{Leased: h.leased}
}

func (h *appTestHost) Close() error {
	h.closed++
	h.alive = false
	return h.closeErr
}

func newTestApp(t *testing.T) (*app, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st := store.New(dir)
	lg := applog.New(dir)
	t.Cleanup(func() { _ = lg.Close() })
	return &app{store: st, log: lg}, st
}

// installFakeHosts replaces the manager factory for one test and records the
// hosts it produced, so the test can flip the lease and close result.
func installFakeHosts(t *testing.T) *[]*appTestHost {
	t.Helper()
	original := newHostManager
	created := &[]*appTestHost{}
	newHostManager = func() *browserhost.Manager {
		return browserhost.NewManagerWithHooks(
			func(store.Settings, string) (browserhost.Host, error) {
				h := &appTestHost{alive: true}
				*created = append(*created, h)
				return h, nil
			},
			func(string, string) (*browserhost.Client, error) {
				return &browserhost.Client{}, nil
			},
		)
	}
	t.Cleanup(func() { newHostManager = original })
	return created
}

func saveBase(t *testing.T, st *store.Store) store.Settings {
	t.Helper()
	cfg := st.Load()
	cfg.UserData = t.TempDir()
	if err := st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Turning the mode off closes the hosts; turning it on again must work without
// restarting the process.
func TestResidentModeCanBeTurnedOffAndOnAgain(t *testing.T) {
	a, st := newTestApp(t)
	cfg := saveBase(t, st)
	cfg.ResidentBrowser = true
	if err := st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	installFakeHosts(t)

	if err := a.applyResidentSetting(true); err != nil {
		t.Fatal(err)
	}
	first := a.hosts
	if err := a.applyResidentSetting(false); err != nil {
		t.Fatalf("关闭常驻模式失败: %v", err)
	}
	if err := a.applyResidentSetting(true); err != nil {
		t.Fatalf("重新开启常驻模式失败: %v", err)
	}
	if a.hosts == first {
		t.Fatal("重新开启应换一个未关闭的管理器")
	}
	if err := a.residentStop(); err != nil {
		t.Fatalf("正常关闭再开启不应阻断任务: %v", err)
	}
}

// Clearing the account installs a fresh manager, so saving a new account does
// not hit ErrManagerClosed.
func TestClearingTheAccountThenSavingANewOneKeepsTheResidentManagerUsable(t *testing.T) {
	a, st := newTestApp(t)
	cfg := saveBase(t, st)
	cfg.ResidentBrowser = true
	if err := st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	created := installFakeHosts(t)
	if err := a.applyResidentSetting(true); err != nil {
		t.Fatal(err)
	}
	oldCfg, err := accountSettings(st.Load(), "20230001", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := a.hosts.Ensure(context.Background(), oldCfg)
	if err != nil || client == nil {
		t.Fatalf("准备宿主失败: %v", err)
	}
	old := a.hosts
	a.reconcileResidentAfterCredentialChange(st.Load(), "", "")
	if a.hosts == old {
		t.Fatal("清空账号后应重建管理器")
	}
	if len(*created) != 1 || (*created)[0].closed != 1 {
		t.Fatalf("清空账号应关闭旧宿主一次，实际 %d", (*created)[0].closed)
	}
	a.reconcileResidentAfterCredentialChange(st.Load(), "20230002", "pw")
	if err := a.residentStop(); err != nil {
		t.Fatalf("清空后重新保存不应要求重启: %v", err)
	}
}

// A switch refused because a task holds the lease is retried when the task ends.
func TestBusyAccountSwitchIsAppliedAfterTheTaskEnds(t *testing.T) {
	a, st := newTestApp(t)
	cfg := saveBase(t, st)
	cfg.ResidentBrowser = true
	if err := st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	created := installFakeHosts(t)
	if err := a.applyResidentSetting(true); err != nil {
		t.Fatal(err)
	}
	oldCfg, err := accountSettings(st.Load(), "20230001", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.hosts.Ensure(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	(*created)[0].leased = true

	a.reconcileResidentAfterCredentialChange(st.Load(), "20230002", "pw")
	if a.pendingSwitch == nil {
		t.Fatal("任务占用时应挂起账号切换")
	}
	if err := a.residentStop(); err != nil {
		t.Fatalf("忙时切换不应阻断任务: %v", err)
	}

	(*created)[0].leased = false
	a.applyPendingSwitch()
	if a.pendingSwitch != nil {
		t.Fatal("任务结束后应完成挂起的切换")
	}
	if err := a.residentStop(); err != nil {
		t.Fatalf("正常切换不应阻断任务: %v", err)
	}
}

// A close that cannot be confirmed still stops later runs after the account is
// cleared.
func TestACleanupFailureDuringAccountClearStopsLaterRuns(t *testing.T) {
	a, st := newTestApp(t)
	cfg := saveBase(t, st)
	cfg.ResidentBrowser = true
	if err := st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	created := installFakeHosts(t)
	if err := a.applyResidentSetting(true); err != nil {
		t.Fatal(err)
	}
	oldCfg, err := accountSettings(st.Load(), "20230001", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.hosts.Ensure(context.Background(), oldCfg); err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("浏览器拒绝退出")
	(*created)[0].closeErr = closeErr

	a.reconcileResidentAfterCredentialChange(st.Load(), "", "")
	blocked := a.residentStop()
	if blocked == nil {
		t.Fatal("清理失败后必须停止后续任务")
	}
	if !errors.Is(blocked, closeErr) {
		t.Fatalf("阻断原因应保留原始错误: %v", blocked)
	}
}
