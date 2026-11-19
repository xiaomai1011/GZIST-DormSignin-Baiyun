package browserhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// A retire that failed leaves the entry with broken set and host nil. CloseAll
// must still report it: the caller uses that result to decide whether the
// profile directory may be deleted.
func TestCloseAllReportsAPriorCleanupFailure(t *testing.T) {
	m, rec, _ := newTestManager(t)
	closeErr := errors.New("浏览器拒绝退出")
	m.start = func(store.Settings, string) (Host, error) {
		h := &fakeHost{alive: true, closeErr: closeErr}
		rec.add(h)
		return h, nil
	}
	m.dial = func(string, string) (*Client, error) { return nil, errors.New("无法连接常驻宿主") }

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	if err := os.MkdirAll(cfg.UserData, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(context.Background(), cfg); err == nil {
		t.Fatal("拨号失败时应返回错误")
	}

	err := m.CloseAll()
	if err == nil {
		t.Fatal("上一次清理失败时 CloseAll 不能报成功")
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("CloseAll 丢失了原始清理错误: %v", err)
	}
	if !strings.Contains(err.Error(), "上次清理失败仍未确认") {
		t.Fatalf("CloseAll 未说明这是先前未确认的清理: %v", err)
	}
	if _, statErr := os.Stat(cfg.UserData); statErr != nil {
		t.Fatalf("清理未确认时目录必须保留: %v", statErr)
	}
}

// CloseAll stops waiting after its budget. A start that publishes later must be
// closed by the manager itself, never handed to a caller.
func TestALateStartIsClosedAfterTheCloseTimesOut(t *testing.T) {
	m, rec, _ := newTestManager(t)
	m.startWait = 20 * time.Millisecond
	entered := make(chan struct{})
	release := make(chan struct{})
	late := &fakeHost{alive: true}
	m.start = func(store.Settings, string) (Host, error) {
		close(entered)
		<-release
		rec.add(late)
		return late, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	done := make(chan error, 1)
	go func() {
		_, err := m.Ensure(context.Background(), cfg)
		done <- err
	}()
	<-entered

	start := time.Now()
	if err := m.CloseAll(); err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("启动未结束时应报超时，得到 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("CloseAll 未按预算返回: %s", elapsed)
	}

	close(release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrManagerClosed) {
			t.Fatalf("迟到启动的调用方应得到管理器已关闭，得到 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Ensure 未在迟到启动后返回")
	}

	deadline := time.Now().Add(2 * time.Second)
	for late.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("迟到启动的宿主没有被关闭")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := m.CloseAll(); err == nil {
		t.Fatal("重复关闭必须保留超时失败")
	}
}

// When the late host cannot be closed, the failure becomes part of the sticky
// close result: the process must not exit claiming a clean sweep.
func TestALateStartThatCannotBeClosedIsRemembered(t *testing.T) {
	m, _, _ := newTestManager(t)
	m.startWait = 20 * time.Millisecond
	entered := make(chan struct{})
	release := make(chan struct{})
	lateErr := errors.New("迟到的浏览器拒绝退出")
	m.start = func(store.Settings, string) (Host, error) {
		close(entered)
		<-release
		return &fakeHost{alive: true, closeErr: lateErr}, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	<-entered
	if err := m.CloseAll(); err == nil {
		t.Fatal("启动未结束时应报超时")
	}
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for {
		err := m.CloseAll()
		if errors.Is(err, lateErr) && strings.Contains(err.Error(), "迟到的常驻宿主关闭失败") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("迟到的清理失败未被记住: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A start that finishes while the sweep is still waiting is closed by the
// manager; if that close fails, its error must survive the sweep's own result.
func TestALateStartThatFailsWhileTheSweepWaitsIsStillReported(t *testing.T) {
	m, _, _ := newTestManager(t)
	m.startWait = 2 * time.Second
	entered := make(chan struct{})
	release := make(chan struct{})
	lateErr := errors.New("拒绝退出")
	m.start = func(store.Settings, string) (Host, error) {
		close(entered)
		<-release
		return &fakeHost{alive: true, closeErr: lateErr}, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	<-entered

	done := make(chan error, 1)
	go func() { done <- m.CloseAll() }()
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		closing := m.closing
		m.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("CloseAll 未开始")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)

	err := <-done
	if !errors.Is(err, lateErr) {
		t.Fatalf("迟到的清理失败被本次结清覆盖: %v", err)
	}
	if !strings.Contains(err.Error(), "迟到的常驻宿主关闭失败") {
		t.Fatalf("错误未说明是迟到宿主: %v", err)
	}
}

// CloseAll's wait must cover the late host's Close, not just its launch: the
// caller deletes a profile on success, so a close that is still running (or
// about to fail) may not be reported as a completed sweep.
func TestCloseAllWaitsForTheLateHostClose(t *testing.T) {
	m, rec, _ := newTestManager(t)
	m.startWait = 5 * time.Second
	startRelease := make(chan struct{})
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	m.start = func(store.Settings, string) (Host, error) {
		<-startRelease
		h := &fakeHost{alive: true, closeEntered: closeEntered, allowClose: allowClose}
		rec.add(h)
		return h, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	if err := os.MkdirAll(cfg.UserData, 0o700); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	waitFor(t, func() bool { return m.Hosts() == 1 }, "启动未登记")

	done := make(chan error, 1)
	go func() { done <- m.CloseAll() }()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closing || m.closed
	}, "CloseAll 未开始")

	close(startRelease)
	<-closeEntered
	defer func() {
		select {
		case <-allowClose:
		default:
			close(allowClose)
		}
	}()

	select {
	case err := <-done:
		t.Fatalf("迟到宿主仍在关闭中，CloseAll 提前返回: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, statErr := os.Stat(cfg.UserData); statErr != nil {
		t.Fatalf("关闭未完成时目录必须保留: %v", statErr)
	}

	close(allowClose)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("关闭成功后 CloseAll 应报成功，得到 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll 未在关闭完成后返回")
	}
	if got := rec.at(0).count(); got != 1 {
		t.Fatalf("迟到宿主应被关闭一次，实际 %d", got)
	}
}

// If that close fails, the sweep must return the failure — the same call that
// would authorise deleting the profile.
func TestCloseAllReportsTheLateHostCloseFailure(t *testing.T) {
	m, _, _ := newTestManager(t)
	m.startWait = 5 * time.Second
	startRelease := make(chan struct{})
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	closeErr := errors.New("迟到的浏览器拒绝退出")
	m.start = func(store.Settings, string) (Host, error) {
		<-startRelease
		return &fakeHost{alive: true, closeErr: closeErr, closeEntered: closeEntered, allowClose: allowClose}, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	waitFor(t, func() bool { return m.Hosts() == 1 }, "启动未登记")
	done := make(chan error, 1)
	go func() { done <- m.CloseAll() }()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closing || m.closed
	}, "CloseAll 未开始")
	close(startRelease)
	<-closeEntered
	close(allowClose)

	select {
	case err := <-done:
		if !errors.Is(err, closeErr) {
			t.Fatalf("CloseAll 丢失了迟到宿主的关闭失败: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll 未返回")
	}
}

// When the close exceeds the budget CloseAll reports "unconfirmed"; a later
// success must never turn that answer into a success.
func TestAnUnconfirmedCloseStaysUnconfirmed(t *testing.T) {
	m, _, _ := newTestManager(t)
	m.startWait = 30 * time.Millisecond
	startRelease := make(chan struct{})
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	m.start = func(store.Settings, string) (Host, error) {
		<-startRelease
		return &fakeHost{alive: true, closeEntered: closeEntered, allowClose: allowClose}, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	waitFor(t, func() bool { return m.Hosts() == 1 }, "启动未登记")
	done := make(chan error, 1)
	go func() { done <- m.CloseAll() }()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closing || m.closed
	}, "CloseAll 未开始")
	close(startRelease)
	<-closeEntered

	first := <-done
	if first == nil || !strings.Contains(first.Error(), "超时") {
		t.Fatalf("超过预算应报未确认，得到 %v", first)
	}

	close(allowClose)
	time.Sleep(100 * time.Millisecond)
	if err := m.CloseAll(); err == nil {
		t.Fatal("收尾后来成功，但先前已报未确认，之后不能改口为成功")
	}
}

// Concurrent closes share one result; none of them may see a clean sweep while
// the late host is still closing.
func TestConcurrentCloseAllShareTheLateCloseResult(t *testing.T) {
	m, _, _ := newTestManager(t)
	m.startWait = 5 * time.Second
	startRelease := make(chan struct{})
	closeEntered := make(chan struct{})
	allowClose := make(chan struct{})
	closeErr := errors.New("拒绝退出")
	m.start = func(store.Settings, string) (Host, error) {
		<-startRelease
		return &fakeHost{alive: true, closeErr: closeErr, closeEntered: closeEntered, allowClose: allowClose}, nil
	}

	cfg := store.Settings{UserData: profileDir(t, "账号")}
	go func() { _, _ = m.Ensure(context.Background(), cfg) }()
	waitFor(t, func() bool { return m.Hosts() == 1 }, "启动未登记")

	results := make(chan error, 2)
	go func() { results <- m.CloseAll() }()
	waitFor(t, func() bool {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.closing || m.closed
	}, "第一次 CloseAll 未开始")
	go func() { results <- m.CloseAll() }()
	close(startRelease)
	<-closeEntered
	close(allowClose)

	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, closeErr) {
				t.Fatalf("第 %d 个并发关闭结果不一致: %v", i+1, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("并发 CloseAll 未返回")
		}
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(time.Millisecond)
	}
}

// A refused switch must leave every other host exactly as it was, whatever
// order the map iterates in.
func TestSwitchLeavesEveryHostUntouchedWhenOneIsBusy(t *testing.T) {
	for i := 0; i < 20; i++ {
		m, rec, _ := newTestManager(t)
		busy := store.Settings{UserData: profileDir(t, fmt.Sprintf("busy-%d", i))}
		idle := store.Settings{UserData: profileDir(t, fmt.Sprintf("idle-%d", i))}
		if _, err := m.Ensure(context.Background(), busy); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Ensure(context.Background(), idle); err != nil {
			t.Fatal(err)
		}
		rec.at(0).set(func(f *fakeHost) { f.leased = true })

		target := store.Settings{UserData: profileDir(t, fmt.Sprintf("target-%d", i))}
		if err := m.Switch(target); !errors.Is(err, ErrSwitchBusy) {
			t.Fatalf("第 %d 轮应拒绝切换，得到 %v", i, err)
		}
		if got := rec.at(1).count(); got != 0 {
			t.Fatalf("第 %d 轮：忙时切换关闭了其它账号的宿主", i)
		}
		if _, err := m.Ensure(context.Background(), idle); err != nil {
			t.Fatalf("第 %d 轮：被拒的切换把空闲宿主留在了启动中: %v", i, err)
		}
		if got := rec.len(); got != 2 {
			t.Fatalf("第 %d 轮：被拒的切换启动了替代宿主（共 %d 个）", i, got)
		}
	}
}
