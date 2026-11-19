package browserhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
)

// The discovery file must never carry the CDP endpoint: whoever can read the
// profile directory can read this file, and reading it must not be enough to
// drive the browser. The endpoint is only handed out by a confirmation.
func TestTheStateFileCarriesNoEndpoint(t *testing.T) {
	d, c, _ := newFakeDaemon(t, true)
	st, err := c.Status()
	if err != nil {
		t.Fatalf("状态查询失败: %v", err)
	}
	if st.PID == 0 {
		t.Fatal("宿主应已经启动浏览器")
	}
	raw, err := os.ReadFile(d.statePath)
	if err != nil {
		t.Fatalf("读取状态文件失败: %v", err)
	}
	if strings.Contains(string(raw), "endpoint") || strings.Contains(string(raw), "devtools") {
		t.Fatalf("状态文件泄露了调试地址: %s", raw)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("状态文件不是合法 JSON: %v", err)
	}
	if _, ok := parsed["endpoint"]; ok {
		t.Fatal("状态文件仍含 endpoint 字段")
	}
}

// A state file that names another account's profile must be refused before any
// lease is taken, and a host whose live profile differs from the state file
// must be refused at attach time.
func TestAnotherAccountsProfileIsRefused(t *testing.T) {
	d, _, _ := newFakeDaemon(t, true)
	own := d.State().UserData
	other := filepath.Join(filepath.Dir(own), "another-account")

	if _, err := Dial(d.statePath, other); !errors.Is(err, ErrWrongProfile) {
		t.Fatalf("读取他人账号状态文件应被拒绝，实际: %v", err)
	}

	// Even when the file itself claims the other profile, the live host is
	// authoritative: the attach must stop before reserving anything.
	st := d.State()
	st.UserData = other
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("序列化状态失败: %v", err)
	}
	if err := writeStateFile(d.statePath, raw); err != nil {
		t.Fatalf("改写状态文件失败: %v", err)
	}
	c, err := Dial(d.statePath, other)
	if err != nil {
		t.Fatalf("状态文件改写后应能读出: %v", err)
	}
	if _, _, err := c.Attach(context.Background(), time.Minute); !errors.Is(err, ErrWrongProfile) {
		t.Fatalf("附加到他人账号的宿主应被拒绝，实际: %v", err)
	}
	status, _ := c.Status()
	if status.Leased || status.Tasks != 0 {
		t.Fatalf("被拒绝的附加不应占用租约: %+v", status)
	}
}

// The lease deadline is authoritative even when its timer has not run yet.
func TestAnExpiredLeaseIsRejectedBeforeItsTimerFires(t *testing.T) {
	d, _, _ := newFakeDaemon(t, true)
	id, _, tok, err := d.acquire(context.Background(), 120*time.Millisecond)
	if err != nil {
		t.Fatalf("预约失败: %v", err)
	}
	if _, err := d.announce(id); err != nil {
		t.Fatalf("发布预约失败: %v", err)
	}
	// Simulate a timer that has not been scheduled yet: the deadline alone must
	// decide. This is the exact case a timer cannot cover.
	d.leaseMu.Lock()
	if d.leaseTimer != nil {
		d.leaseTimer.Stop()
		d.leaseTimer = nil
	}
	if d.confirmTimer != nil {
		d.confirmTimer.Stop()
		d.confirmTimer = nil
	}
	d.leaseMu.Unlock()
	time.Sleep(180 * time.Millisecond)

	endpoint, _, err := d.confirm(id, tok)
	if !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("到期后确认应被拒绝，实际: %v（endpoint=%q）", err, endpoint)
	}
	if endpoint != "" {
		t.Fatalf("到期后不应返回调试地址: %q", endpoint)
	}
	if st := d.Status(); st.Leased {
		t.Fatalf("到期租约应已回收: %+v", st)
	}
}

// A confirmation announced against one browser must not be honoured after that
// browser was revoked and replaced.
func TestAnOldConfirmationCannotReachTheReplacementBrowser(t *testing.T) {
	d, _, f := newFakeDaemon(t, true)
	id, _, tok, err := d.acquire(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("预约失败: %v", err)
	}
	if _, err := d.announce(id); err != nil {
		t.Fatalf("发布预约失败: %v", err)
	}

	if err := d.revokeAll(5 * time.Second); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	endpoint, _, err := d.confirm(id, tok)
	if err == nil {
		t.Fatalf("旧确认不应拿到调试地址: %q", endpoint)
	}
	if endpoint != "" {
		t.Fatalf("旧确认返回了地址: %q", endpoint)
	}
	// The stale lease still holds the slot; the client's abort path is what
	// frees it in production (the test releases it directly).
	if !d.releaseLease(id) {
		t.Fatal("旧租约未能释放")
	}

	// The next lease on the replacement browser still works.
	id2, _, tok2, err := d.acquire(context.Background(), time.Minute)
	if err != nil {
		t.Fatalf("再次预约失败: %v", err)
	}
	if err := d.ensureAlive(context.Background()); err != nil {
		t.Fatalf("撤销后应能重新启动浏览器: %v", err)
	}
	if _, err := d.announce(id2); err != nil {
		t.Fatalf("再次发布失败: %v", err)
	}
	ep2, first, err := d.confirm(id2, tok2)
	if err != nil || !first || ep2 == "" {
		t.Fatalf("新浏览器上的确认失败: %v first=%v ep=%q", err, first, ep2)
	}
	if f.n != 2 {
		t.Fatalf("撤销后应重新启动一次浏览器，实际 %d 次", f.n)
	}
}

// When the confirmation reply is lost after the host activated the lease, the
// client cannot know whether it may drive the browser. It must abort by id —
// and must report the abort result, not assume the lease was never used.
func TestALostConfirmationReplyStillAbortsTheLease(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "account")
	var mu sync.Mutex
	activated, aborts := false, 0

	mux := http.NewServeMux()
	mux.HandleFunc("/lease", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":7,"token":"tok","confirmWindowMs":1000}`))
	})
	mux.HandleFunc("/lease/confirm", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		activated = true
		mu.Unlock()
		// Drop the connection after the host has acted: the client sees EOF and
		// does not know whether the endpoint was handed out.
		if hj, ok := w.(http.Hijacker); ok {
			c, _, err := hj.Hijack()
			if err == nil {
				_ = c.Close()
			}
			return
		}
	})
	mux.HandleFunc("/lease/abort", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		aborts++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"userData":` + strconv.Quote(profile) + `}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	state := `{"pid":1,"userData":` + strconv.Quote(profile) + `,"leaseUrl":` + strconv.Quote(srv.URL) + `,"token":"ctl"}`
	if err := os.WriteFile(statePath, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Dial(statePath, profile)
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if _, _, err := c.Attach(context.Background(), time.Minute); err == nil {
		t.Fatal("确认回复丢失时应返回错误")
	}
	mu.Lock()
	defer mu.Unlock()
	if !activated {
		t.Fatal("测试前提不成立：宿主应已激活租约")
	}
	if aborts != 1 {
		t.Fatalf("确认回复丢失后应按编号撤销一次，实际 %d 次", aborts)
	}
}

// A failed attach must revoke the lease (the browser may be in use) and report
// the revocation failure next to the original error instead of dropping it.
func TestAFailedAttachReportsTheRevocationFailure(t *testing.T) {
	_, c, f := newFakeDaemonWith(t, false, func(f *fakeBrowsers) { f.failAll = true })
	oldAttach := attachSession
	attachSession = func(context.Context, string, int, string, string) (*edge.Session, error) {
		return nil, errors.New("模拟附加失败")
	}
	t.Cleanup(func() { attachSession = oldAttach })

	_, _, err := c.Attach(context.Background(), time.Minute)
	if err == nil {
		t.Fatal("附加失败时应返回错误")
	}
	msg := err.Error()
	if !strings.Contains(msg, "模拟附加失败") || !strings.Contains(msg, "撤销租约") || !strings.Contains(msg, "模拟关闭失败") {
		t.Fatalf("错误应同时保留附加失败与撤销失败，实际: %v", err)
	}
	if len(f.closed) == 0 {
		t.Fatal("附加失败的租约应触发撤销，而不是直接释放")
	}
}
