package browserhost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func decodeOffer(t *testing.T, resp *http.Response) leaseOffer {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("预约状态 = %d", resp.StatusCode)
	}
	var o leaseOffer
	if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
		t.Fatalf("解析预约: %v", err)
	}
	if o.ID == 0 || o.Token == "" {
		t.Fatalf("预约缺编号或凭据: %+v", o)
	}
	return o
}

func (c *Client) confirmRaw(t *testing.T, o leaseOffer) *http.Response {
	t.Helper()
	return c.postJSON(t, "/lease/confirm", fmt.Sprintf(`{"id":%d,"token":%q}`, o.ID, o.Token))
}

func endpointOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("确认状态 = %d", resp.StatusCode)
	}
	var out leaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("解析确认: %v", err)
	}
	return out.Endpoint
}

// TestTheFirstReplyCarriesNoEndpoint: the reservation must be useless to a
// client that never confirms, so it cannot contain a CDP endpoint.
func TestTheFirstReplyCarriesNoEndpoint(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)
	resp := c.rawInvite(t, time.Minute)
	defer resp.Body.Close()
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if _, ok := raw["endpoint"]; ok {
		t.Fatalf("预约响应泄露了 endpoint: %v", raw)
	}
	if raw["id"] == nil || raw["token"] == nil {
		t.Fatalf("预约缺少编号或凭据: %v", raw)
	}
}

// TestConfirmIsIdempotentAndCountsOnce: repeating a confirmation returns the
// same endpoint without re-activating the lease or resetting anything.
func TestConfirmIsIdempotentAndCountsOnce(t *testing.T) {
	_, c, _ := newFakeDaemon(t, true)
	offer := decodeOffer(t, c.rawInvite(t, time.Minute))
	first := endpointOf(t, c.confirmRaw(t, offer))
	second := endpointOf(t, c.confirmRaw(t, offer))
	if first == "" || first != second {
		t.Fatalf("重复确认返回了不同的 endpoint: %q vs %q", first, second)
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Tasks != 1 {
		t.Fatalf("重复确认被计为 %d 次任务", st.Tasks)
	}
}

// TestAnUnconfirmedReservationExpiresWithoutTouchingTheBrowser: the slot comes
// back on its own and the resident browser is neither revoked nor relaunched.
func TestAnUnconfirmedReservationExpiresWithoutTouchingTheBrowser(t *testing.T) {
	d, c, f := newFakeDaemon(t, true)
	d.leaseMu.Lock()
	d.confirmWindow = 60 * time.Millisecond
	d.leaseMu.Unlock()

	offer := decodeOffer(t, c.rawInvite(t, time.Minute))
	time.Sleep(200 * time.Millisecond)
	if resp := c.confirmRaw(t, offer); resp.StatusCode != http.StatusConflict {
		t.Fatalf("过期确认状态 = %d，期望 409", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	next := decodeOffer(t, c.rawInvite(t, time.Minute))
	if ep := endpointOf(t, c.confirmRaw(t, next)); ep == "" {
		t.Fatal("回收后新的预约无法确认")
	}
	if f.n != 1 {
		t.Fatalf("未确认的预约引发了 %d 次启动，期望复用同一个浏览器", f.n)
	}
}

// TestAStaleConfirmCannotDisturbTheNewLease: an expired reservation's credential
// must not activate, release or otherwise touch the current lease.
func TestAStaleConfirmCannotDisturbTheNewLease(t *testing.T) {
	d, c, _ := newFakeDaemon(t, true)
	d.leaseMu.Lock()
	d.confirmWindow = 50 * time.Millisecond
	d.leaseMu.Unlock()

	old := decodeOffer(t, c.rawInvite(t, time.Minute))
	time.Sleep(150 * time.Millisecond)
	fresh := decodeOffer(t, c.rawInvite(t, time.Minute))
	if resp := c.confirmRaw(t, old); resp.StatusCode != http.StatusConflict {
		t.Fatalf("旧凭据确认状态 = %d，期望 409", resp.StatusCode)
	} else {
		_ = resp.Body.Close()
	}
	if ep := endpointOf(t, c.confirmRaw(t, fresh)); ep == "" {
		t.Fatal("旧凭据影响到了新租约")
	}
}

// TestAbortRevokesABrowserThatMayHaveBeenUsed: once an endpoint could have been
// delivered, giving the slot back without revoking would let a second task drive
// a browser the first one may still hold.
func TestAbortRevokesABrowserThatMayHaveBeenUsed(t *testing.T) {
	_, c, f := newFakeDaemon(t, true)
	offer := decodeOffer(t, c.rawInvite(t, time.Minute))
	if ep := endpointOf(t, c.confirmRaw(t, offer)); ep == "" {
		t.Fatal("确认失败")
	}
	resp := c.postJSON(t, "/lease/abort", fmt.Sprintf(`{"id":%d,"token":%q}`, offer.ID, offer.Token))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("撤销状态 = %d", resp.StatusCode)
	}
	f.mu.Lock()
	closed := len(f.closed)
	f.mu.Unlock()
	if closed != 1 {
		t.Fatalf("撤销没有关掉浏览器（closed=%d）", closed)
	}
	// A new lease must start a fresh browser rather than reuse a revoked one.
	next := decodeOffer(t, c.rawInvite(t, time.Minute))
	if ep := endpointOf(t, c.confirmRaw(t, next)); ep == "" {
		t.Fatal("撤销后无法重新租用")
	}
	if f.n != 2 {
		t.Fatalf("撤销后的租用启动了 %d 次浏览器，期望 2", f.n)
	}
}

// TestConfirmAfterCloseReportsTheHostIsGone: the handshake must not hand out an
// endpoint once the daemon started shutting down.
func TestConfirmAfterCloseReportsTheHostIsGone(t *testing.T) {
	d, c, _ := newFakeDaemon(t, true)
	offer := decodeOffer(t, c.rawInvite(t, time.Minute))
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(confirmRequest{ID: offer.ID, Token: offer.Token})
	resp, err := c.do(t.Context(), http.MethodPost, "/lease/confirm", body)
	if err != nil {
		return // a closed host refusing the connection is the same answer
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusConflict {
		t.Fatalf("关闭后确认状态 = %d", resp.StatusCode)
	}
	_ = bytes.MinRead // keep bytes import honest if assertions change
}
