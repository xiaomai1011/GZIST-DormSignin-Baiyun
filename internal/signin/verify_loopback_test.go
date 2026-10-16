package signin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Loopback integration: a disposable Edge profile against a local test server
// that mimics the school flow — the page POSTs the auth endpoint and navigates
// away the moment the response arrives. Opt-in via DORMSIGN_EDGE_TEST=1.
// Never touches the school network, real credentials or any user profile.
func loopbackServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The POST fires only when the test calls window.__post() — a clean
		// barrier, so the observation is fully armed first (no timing race).
		_, _ = w.Write([]byte(`<html><body><script>
window.__post = function(){
  fetch('/v1/tickets',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(r){return r.json()})
    .then(function(j){location.replace('/after?ticket='+encodeURIComponent(j.ticket))})
    .catch(function(e){document.title='fetch-error'});
};
</script></body></html>`))
	})
	mux.HandleFunc("/v1/tickets", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tgt":"TGT-loop-123456","ticket":"ST-loop-123456"}`))
	})
	mux.HandleFunc("/after", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("navigated"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLoopbackInterceptionSurvivesNavigation(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv := loopbackServer(t)
	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	s, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := s.Ctx

	var lines []string
	var releases int
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	o := &authObservation{
		out:           make(chan VerificationResult, 1),
		trace:         tr,
		matchEndpoint: func(raw string) bool { return raw == srv.URL+"/v1/tickets" },
		matchDocument: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/login") },
		fetchPattern:  srv.URL + "/v1/tickets",
	}
	// Production release wrapped with a submission counter: exactly one pause
	// may ever be released, and it must end release=ok.
	o.release = func(c context.Context, ev *fetch.EventRequestPaused, b []byte, e error) bool {
		releases++
		return o.releasePausedCDP(c, ev, b, e)
	}
	chromedp.ListenTarget(ctx, func(ev any) {
		if e, ok := ev.(*network.EventResponseReceived); ok {
			t.Logf("[probe] respReceived req=%v url=%q cache=%v sw=%v status=%d",
				e.RequestID, e.Response.URL, e.Response.FromDiskCache, e.Response.FromServiceWorker, e.Response.Status)
		}
		if e, ok := ev.(*fetch.EventRequestPaused); ok {
			t.Logf("[probe] paused fetchReq=%v netID=%v url=%q status=%d",
				e.RequestID, e.NetworkID, e.Request.URL, e.ResponseStatusCode)
		}
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			t.Logf("[probe] reqWillBeSent req=%v url=%q doc=%q", e.RequestID, e.Request.URL, e.DocumentURL)
		}
		o.listen(ctx, ev)
	})

	// Network observation stays on (production parity; the capture path owns
	// the body and the network path is kept as its fallback).
	if err := network.Enable().Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := o.enableFetch(ctx); err != nil {
		t.Fatalf("fetch enable failed: %v", err)
	}
	defer o.disableFetch(ctx)
	if err := chromedp.Navigate(srv.URL + "/login").Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	o.arm()

	// Barrier: trigger the POST only after the arm is fully in place, so there
	// is no arm/navigation timing race at all.
	if err := chromedp.Evaluate("window.__post()", nil).Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-o.out:
		if !r.OK {
			t.Fatalf("interception must capture the body despite the immediate navigation: %+v", r)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no result within 30s")
	}

	// Page-side proof: the passthrough body must have reached the page and been
	// parsed (a wrong fulfill body encoding fails the page's r.json() and it
	// never navigates). A Go-side OK alone cannot catch that.
	path := ""
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := chromedp.Evaluate("location.pathname", &path).Do(exec(ctx)); err == nil && path == "/after" {
			break
		}
		if time.Now().After(deadline) {
			var title string
			_ = chromedp.Evaluate("document.title", &title).Do(exec(ctx))
			t.Fatalf("page never reached /after (path=%q title=%q) — passthrough broken", path, title)
		}
		time.Sleep(150 * time.Millisecond)
	}

	tr.finish()
	if releases != 1 {
		t.Fatalf("exactly one pause release expected, got %d", releases)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "release=ok") {
		t.Fatalf("trace must record release=ok: %v", lines)
	}
	if strings.Contains(lines[0], "code=unlisted") {
		t.Fatalf("tickets body must classify without a code: %s", lines[0])
	}
}

// Evidence probe for direction A's root cause: WITHOUT interception, does the
// legacy post-LoadingFinished read survive the immediate navigation? The
// result is recorded, not asserted — local timing differs from the school's.
func TestLoopbackLegacyReadAfterNavigation(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv := loopbackServer(t)
	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	s, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := s.Ctx

	o := &authObservation{out: make(chan VerificationResult, 1),
		matchEndpoint: func(raw string) bool { return raw == srv.URL+"/v1/tickets" },
		matchDocument: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/login") }}
	chromedp.ListenTarget(ctx, func(ev any) { o.listen(ctx, ev) })
	if err := network.Enable().Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	// Arm before navigating; the POST itself fires on demand via the barrier,
	// so the timing is fully deterministic.
	o.arm()
	if err := chromedp.Navigate(srv.URL + "/login").Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Evaluate("window.__post()", nil).Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-o.out:
		// Both outcomes carry information: OK means the legacy read won the
		// race locally; a body_* failure is the branch-A shape. Success is only
		// ever classified from real ticket evidence in the body, so an OK here
		// is genuine — it just means local timing differs from the school's.
		if r.OK {
			t.Logf("legacy read won the race locally (body still readable): OK")
		} else {
			t.Logf("legacy read after navigation: reason=%s (this is the branch-A shape)", r.ReasonCode)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no result within 30s")
	}
}
