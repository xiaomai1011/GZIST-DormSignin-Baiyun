package signin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// The form reader is JavaScript, so only a real page can prove it tells the
// account field from a stray input. Loopback pages, disposable profile, opt-in.
func TestProbeFormScriptReadsOnlyTheTrustedAccountField(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	const box = `style="width:120px;height:24px;display:block"`
	pages := map[string]string{
		"both": `<input id="userName" ` + box + `><input id="password" type="password" ` + box + `>`,
		"captcha-only": `<input id="password" type="password" ` + box + `>` +
			`<input id="captcha" type="text" ` + box + `><input id="search" type="search" ` + box + `>`,
		"disabled": `<input id="userName" disabled ` + box + `><input id="password" type="password" ` + box + `>`,
		"hidden":   `<div style="display:none"><input id="userName"><input id="password" type="password"></div>`,
	}
	want := map[string]struct{ account, visible bool }{
		"both":         {true, true},
		"captcha-only": {false, false},
		"disabled":     {false, false},
		"hidden":       {false, false},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Path[1:]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<html><body>%s</body></html>`, body)
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sess.Close()

	for name, exp := range want {
		var p ProbePage
		if err := chromedp.Run(sess.Ctx,
			chromedp.Navigate(srv.URL+"/"+name),
			chromedp.Evaluate(probeFormScript, &p),
		); err != nil {
			t.Fatalf("%s: evaluate: %v", name, err)
		}
		if p.Form.Account != exp.account || p.Form.Visible != exp.visible {
			t.Fatalf("%s: form = %+v, want account=%v visible=%v", name, p.Form, exp.account, exp.visible)
		}
	}
}

// Production-adapter loopback.
//
// Scripted ops cannot see the wiring bug this test exists for: edge.LaunchContext
// returns a session whose Ctx carries the CDP target, and handing any other
// context to the page ops makes every read fail. Only a real launch shows that.
// Opt-in via DORMSIGN_EDGE_TEST=1; a disposable profile and a local server, never
// the school network.
func TestProductionProbeAdapterUsesTheLaunchedBrowser(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><p>loopback marker</p></body></html>`))
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sess.Close()

	res := RunSessionProbe(context.Background(), sess.Ctx, srv.URL+"/entry")
	// The loopback host is not a school host, so the verdict must be "unsupported";
	// reaching that verdict at all proves navigation and reads ran inside the
	// launched browser. With a plain caller context the reads fail and this
	// becomes read_errors instead.
	if res.Stop != ProbeStopUnsupportedHost {
		t.Fatalf("stop = %s (%+v), want unsupported_host: the probe must read the launched browser, not a bare context", res.Stop, res)
	}
	if res.Reads < 1 {
		t.Fatalf("reads = %d, want at least one real read", res.Reads)
	}
	if res.Page != "other" {
		t.Fatalf("page = %q, want other: the URL must come from the page itself", res.Page)
	}
	if res.Elapsed <= 0 {
		t.Fatalf("elapsed = %v, want positive", res.Elapsed)
	}
}
