package browserhost

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

type fakeHost struct {
	mu       sync.Mutex
	alive    bool
	leased   bool
	closed   int
	closeErr error

	// closeEntered is closed once Close is entered; allowClose, when non-nil,
	// holds Close inside the call until the test releases it. Both let a test
	// pin the exact interleaving instead of hoping the scheduler obliges.
	closeEntered chan struct{}
	allowClose   chan struct{}
	enterOnce    sync.Once
}

func (f *fakeHost) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive
}

func (f *fakeHost) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Status{Leased: f.leased}
}

func (f *fakeHost) Close() error {
	if f.closeEntered != nil {
		f.enterOnce.Do(func() { close(f.closeEntered) })
	}
	if f.allowClose != nil {
		<-f.allowClose
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	f.alive = false
	return f.closeErr
}

func (f *fakeHost) set(fn func(*fakeHost)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeHost) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// recorder counts started hosts; starts run on their own goroutine, so every
// access goes through the lock (otherwise -race flags the tests themselves).
type recorder struct {
	mu    sync.Mutex
	hosts []*fakeHost
}

func (r *recorder) add(h *fakeHost) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, h)
}

func (r *recorder) at(i int) *fakeHost {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hosts[i]
}

func (r *recorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hosts)
}

func newTestManager(t *testing.T) (*Manager, *recorder, *int) {
	t.Helper()
	rec := &recorder{}
	dials := 0
	var dialMu sync.Mutex
	m := &Manager{entries: map[string]*managedHost{}}
	m.start = func(store.Settings, string) (Host, error) {
		h := &fakeHost{alive: true}
		rec.add(h)
		return h, nil
	}
	m.dial = func(string, string) (*Client, error) {
		dialMu.Lock()
		defer dialMu.Unlock()
		dials++
		return &Client{}, nil
	}
	t.Cleanup(func() { _ = m.CloseAll() })
	return m, rec, &dials
}

func profileDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

func TestEnsureStartsOneHostAndReusesIt(t *testing.T) {
	m, rec, dials := newTestManager(t)
	cfg := store.Settings{UserData: profileDir(t, "a")}

	if _, err := m.Ensure(context.Background(), cfg); err != nil {
		t.Fatalf("首次 Ensure: %v", err)
	}
	if _, err := m.Ensure(context.Background(), cfg); err != nil {
		t.Fatalf("第二次 Ensure: %v", err)
	}
	if rec.len() != 1 || *dials != 2 {
		t.Fatalf("应只启动一个宿主、两次拨号，实得启动 %d 次、拨号 %d 次", rec.len(), *dials)
	}
}

func TestEnsureReplacesADeadHost(t *testing.T) {
	m, rec, _ := newTestManager(t)
	cfg := store.Settings{UserData: profileDir(t, "a")}
	if _, err := m.Ensure(context.Background(), cfg); err != nil {
		t.Fatalf("首次 Ensure: %v", err)
	}
	rec.at(0).set(func(f *fakeHost) { f.alive = false })

	if _, err := m.Ensure(context.Background(), cfg); err != nil {
		t.Fatalf("替换死宿主: %v", err)
	}
	if rec.len() != 2 {
		t.Fatalf("应启动第二个宿主，实得 %d", rec.len())
	}
	if got := rec.at(0).count(); got != 1 {
		t.Fatalf("死宿主应被关闭一次，实得 %d", got)
	}
}

func TestEnsureDropsAHostWhoseClientCannotBeBuilt(t *testing.T) {
	m, rec, _ := newTestManager(t)
	m.dial = func(string, string) (*Client, error) { return nil, errors.New("状态文件损坏") }
	cfg := store.Settings{UserData: profileDir(t, "a")}

	if _, err := m.Ensure(context.Background(), cfg); err == nil {
		t.Fatal("拨号失败应向上返回")
	}
	if m.Hosts() != 0 || rec.at(0).count() != 1 {
		t.Fatalf("失败宿主应被摘除并关闭，实得宿主 %d、关闭 %d", m.Hosts(), rec.at(0).count())
	}
}

// A host that cannot close must stay on record: a replacement would leave a
// second browser running next to the one nobody could account for.
func TestADeadHostThatCannotBeClosedIsKeptAndNotReplaced(t *testing.T) {
	m, rec, _ := newTestManager(t)
	cfg := store.Settings{UserData: profileDir(t, "a")}
	if _, err := m.Ensure(context.Background(), cfg); err != nil {
		t.Fatalf("首次 Ensure: %v", err)
	}
	rec.at(0).set(func(f *fakeHost) {
		f.alive = false
		f.closeErr = errors.New("拒绝退出")
	})

	_, err := m.Ensure(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "无法关闭") {
		t.Fatalf("关闭失败应向上返回并说明保留记录，实得 %v", err)
	}
	if rec.len() != 1 || m.Hosts() != 1 {
		t.Fatalf("不得启动替代宿主：启动 %d 次、记录 %d 个", rec.len(), m.Hosts())
	}

	_, err = m.Ensure(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "清理失败") {
		t.Fatalf("再次调用应报告记录中的清理失败，实得 %v", err)
	}
	if rec.len() != 1 {
		t.Fatalf("仍然不得启动替代宿主，实得 %d", rec.len())
	}
}

func TestAFailedDialKeepsTheRecordWhenTheCloseAlsoFails(t *testing.T) {
	m, rec, _ := newTestManager(t)
	m.dial = func(string, string) (*Client, error) { return nil, errors.New("状态文件损坏") }
	m.start = func(store.Settings, string) (Host, error) {
		h := &fakeHost{alive: true, closeErr: errors.New("拒绝退出")}
		rec.add(h)
		return h, nil
	}

	_, err := m.Ensure(context.Background(), store.Settings{UserData: profileDir(t, "a")})
	if err == nil {
		t.Fatal("拨号与关闭都失败时必须报错")
	}
	if !strings.Contains(err.Error(), "状态文件损坏") || !strings.Contains(err.Error(), "拒绝退出") {
		t.Fatalf("两个原因都应保留，实得 %v", err)
	}
	if m.Hosts() != 1 || rec.len() != 1 {
		t.Fatalf("记录应保留且不得重启：记录 %d、启动 %d", m.Hosts(), rec.len())
	}
}

// A cancelled task must stop waiting for the start instead of hanging the exit
// path; the browser that does come up stays accounted for and is closed later.
func TestEnsureStopsWaitingWhenTheCallerCancels(t *testing.T) {
	m, rec, _ := newTestManager(t)
	gate := make(chan struct{})
	m.start = func(store.Settings, string) (Host, error) {
		<-gate
		h := &fakeHost{alive: true}
		rec.add(h)
		return h, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := m.Ensure(ctx, store.Settings{UserData: profileDir(t, "a")})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("应返回取消，实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消后仍在等待启动")
	}

	close(gate)
	deadline := time.Now().Add(2 * time.Second)
	for m.Hosts() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Hosts() != 1 {
		t.Fatalf("启动完成后宿主应仍被登记，实得 %d", m.Hosts())
	}
	if err := m.CloseAll(); err != nil {
		t.Fatalf("收尾: %v", err)
	}
	if rec.len() != 1 || rec.at(0).count() != 1 {
		t.Fatalf("宿主应被关闭一次，实得 %d", rec.at(0).count())
	}
}

func TestCloseAllRefusesNewWorkAndRepeatsTheSameResult(t *testing.T) {
	m, rec, _ := newTestManager(t)
	if _, err := m.Ensure(context.Background(), store.Settings{UserData: profileDir(t, "a")}); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	rec.at(0).set(func(f *fakeHost) { f.closeErr = errors.New("关闭失败") })

	first := m.CloseAll()
	if first == nil {
		t.Fatal("关闭失败应被上报")
	}
	second := m.CloseAll()
	if second == nil || second.Error() != first.Error() {
		t.Fatalf("第二次应返回同一错误，实得 %v", second)
	}
	if _, err := m.Ensure(context.Background(), store.Settings{UserData: profileDir(t, "b")}); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("关闭后 Ensure 应被拒绝，实得 %v", err)
	}
	if err := m.Switch(store.Settings{UserData: profileDir(t, "b")}); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("关闭后 Switch 应被拒绝，实得 %v", err)
	}
}

func TestCloseAllWaitsForAnInFlightStartAndClosesIt(t *testing.T) {
	m, rec, _ := newTestManager(t)
	gate := make(chan struct{})
	m.start = func(store.Settings, string) (Host, error) {
		<-gate
		h := &fakeHost{alive: true}
		rec.add(h)
		return h, nil
	}

	ensured := make(chan error, 1)
	go func() {
		_, err := m.Ensure(context.Background(), store.Settings{UserData: profileDir(t, "a")})
		ensured <- err
	}()
	time.Sleep(20 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- m.CloseAll() }()
	time.Sleep(20 * time.Millisecond)
	close(gate)

	if err := <-closed; err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if err := <-ensured; !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("启动在关闭期间完成时不应交付客户端，实得 %v", err)
	}
	if rec.len() != 1 || rec.at(0).count() != 1 {
		t.Fatalf("宿主应被关闭一次，实得启动 %d、关闭 %d", rec.len(), rec.at(0).count())
	}
}

func TestSwitchClosesTheOtherAccountOnlyWhenIdle(t *testing.T) {
	m, rec, _ := newTestManager(t)
	a := store.Settings{UserData: profileDir(t, "a")}
	b := store.Settings{UserData: profileDir(t, "b")}
	if _, err := m.Ensure(context.Background(), a); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	rec.at(0).set(func(f *fakeHost) { f.leased = true })

	if err := m.Switch(b); !errors.Is(err, ErrSwitchBusy) {
		t.Fatalf("有任务时应拒绝切换，实得 %v", err)
	}
	if rec.at(0).count() != 0 {
		t.Fatal("拒绝切换时不能关闭宿主")
	}

	rec.at(0).set(func(f *fakeHost) { f.leased = false })
	if err := m.Switch(b); err != nil {
		t.Fatalf("空闲切换: %v", err)
	}
	if rec.at(0).count() != 1 || m.Hosts() != 0 {
		t.Fatalf("切换后旧宿主应关闭，实得关闭 %d、剩余 %d", rec.at(0).count(), m.Hosts())
	}
}

func TestSwitchKeepsTheRecordWhenTheOldHostCannotClose(t *testing.T) {
	m, rec, _ := newTestManager(t)
	a := store.Settings{UserData: profileDir(t, "a")}
	b := store.Settings{UserData: profileDir(t, "b")}
	if _, err := m.Ensure(context.Background(), a); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	rec.at(0).set(func(f *fakeHost) { f.closeErr = errors.New("拒绝退出") })

	if err := m.Switch(b); err == nil {
		t.Fatal("关闭失败应被上报")
	}
	if m.Hosts() != 1 {
		t.Fatalf("失败记录应保留，实得 %d", m.Hosts())
	}
	if err := m.Switch(b); err == nil || !strings.Contains(err.Error(), "清理失败") {
		t.Fatalf("再次切换应报告清理失败，实得 %v", err)
	}
}
