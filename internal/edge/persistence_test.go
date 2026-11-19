package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Opt-in local measurements, loopback only, no school host: does the browser
// keep a cookie across a restart of the same profile, and does the way a run
// ends change that?
//
// Everything is verified through the browser itself and through a loopback
// server reading the Cookie header — never by grepping the cookie database.
//
//	set DORMSIGN_EDGE_TEST=1 to run these

const (
	persistentCookie = "dormsign_persist_probe"
	sessionCookie    = "dormsign_session_probe"
)

// cookieServer serves a page that sets both cookies and reports what the browser
// actually sends back on the next request.
func cookieServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><title>loopback</title><body>loopback</body>`))
	})
	mux.HandleFunc("/seen", func(w http.ResponseWriter, r *http.Request) {
		names := []string{}
		for _, c := range r.Cookies() {
			names = append(names, c.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(names)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// seenByServer reports which of our probe cookies the browser sent to the
// loopback server, which is the same thing a school page would see.
func seenByServer(ctx context.Context, base string) (map[string]bool, error) {
	var body string
	// Read through Evaluate rather than a query: a navigation can replace the
	// document between the two calls, which makes a stored node id stale.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(strings.TrimSuffix(base, "/")+"/seen"),
		chromedp.Evaluate(`document.body ? document.body.textContent : ''`, &body),
	); err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &names); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out, nil
}

// seedCookies sets one persistent cookie (explicit expiry) and one session
// cookie (no expiry) through the page itself, then proves the loopback server
// already receives both.
func seedCookies(t *testing.T, ctx context.Context, base string) {
	t.Helper()
	js := `(function(){
	  var later = new Date(Date.now() + 3600*1000).toUTCString();
	  document.cookie = "` + persistentCookie + `=1; path=/; expires=" + later;
	  document.cookie = "` + sessionCookie + `=1; path=/";
	  return document.cookie;
	})()`
	var got string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(base),
		chromedp.Evaluate(js, &got),
	); err != nil {
		t.Fatalf("write cookies: %v", err)
	}
	names, err := seenByServer(ctx, base)
	if err != nil {
		t.Fatalf("read cookies after writing: %v", err)
	}
	if !names[persistentCookie] || !names[sessionCookie] {
		t.Fatalf("the browser did not send back the cookies it just set: %v (document.cookie=%q)", names, got)
	}
}

func launchProbe(t *testing.T, dir string) (*Session, context.Context, context.CancelFunc) {
	t.Helper()
	cfg := store.Defaults()
	cfg.UserData = dir
	sess, err := Launch(cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	ctx, cancel := context.WithTimeout(sess.Ctx, 30*time.Second)
	// A failed assertion must never leave a browser and the profile lock behind:
	// teardown is registered as soon as the launch succeeds, and an unclean
	// teardown fails the test even when the first assertion already did.
	// Close is idempotent, so the explicit closes below still prove the restarts.
	t.Cleanup(func() {
		cancel()
		if err := sess.Close(); err != nil {
			t.Errorf("probe cleanup failed: %v", err)
		}
	})
	return sess, ctx, cancel
}

func TestCookiesAcrossARestartOfTheSameProfile(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local cookie-persistence measurement")
	}

	t.Run("graceful close keeps the persistent cookie", func(t *testing.T) {
		dir := t.TempDir()
		srv := cookieServer(t)

		sess, ctx, cancel := launchProbe(t, dir)
		seedCookies(t, ctx, srv.URL)
		cancel()
		if err := sess.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		_, ctxAfter, _ := launchProbe(t, dir)
		names, err := seenByServer(ctxAfter, srv.URL)
		if err != nil {
			t.Fatalf("read cookies after restart: %v", err)
		}
		t.Logf("after restart: persistent=%v session=%v (%v)", names[persistentCookie], names[sessionCookie], names)
		if !names[persistentCookie] {
			t.Fatal("the persistent cookie did not survive a graceful close and restart")
		}
	})

	// Reported, not asserted: a killed browser may or may not have flushed, and a
	// test that demands one outcome would be flaky rather than informative.
	t.Run("forced kill observation", func(t *testing.T) {
		dir := t.TempDir()
		srv := cookieServer(t)

		sess, ctx, cancel := launchProbe(t, dir)
		seedCookies(t, ctx, srv.URL)
		cancel()
		if sess.kill != nil {
			_ = sess.kill()
		}
		// The cookie outcome may vary here; a teardown that cannot be proven
		// complete may not.
		if err := sess.Close(); err != nil {
			t.Fatalf("cleanup after the forced kill: %v", err)
		}

		_, ctxAfter, _ := launchProbe(t, dir)
		names, err := seenByServer(ctxAfter, srv.URL)
		if err != nil {
			t.Fatalf("read cookies after restart: %v", err)
		}
		t.Logf("after a forced kill: persistent=%v session=%v", names[persistentCookie], names[sessionCookie])
	})
}
