package signin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// rememberMeDOMOnlyJS is the DOM half alone: production wraps the same snippet
// in the page-trust and visible-form gates (see rememberMeJS), but the visibility
// rule it relies on is the shared production definition either way.
const rememberMeDOMOnlyJS = `(function(){` + casVisibleFnJS + rememberMeDOMJS + `})()`

// The school hides the checkbox with a CSS media query, so only a real page can
// show that widening the viewport brings it back and that the production DOM
// script then ticks it with a single click. Loopback server, disposable profile,
// opt-in: never the school network.
func TestWideningRevealsAndTicksTheResponsiveCheckbox(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	const page = `<!doctype html><html><head><meta name="viewport" content="width=device-width">
<style>
  input#userName, input#password { width:120px;height:24px;display:block }
</style>
<script>
  // The school's bundle renders the checkbox only for the desktop layout, so at
  // narrow width the node is absent from the DOM - not merely hidden.
  window.__changes = 0;
  document.addEventListener('change', function (e) {
    if (e.target && e.target.id === 'rememberMe') window.__changes++;
  });
  function render() {
    var host = document.getElementById('rm');
    var wide = window.matchMedia('(min-width: 981px)').matches;
    if (wide && !document.getElementById('rememberMe')) {
      host.innerHTML = '<label><input id="rememberMe" type="checkbox" name="rememberMe" value="on">记住密码</label>';
    } else if (!wide && document.getElementById('rememberMe')) {
      host.innerHTML = '';
    }
  }
  document.addEventListener('DOMContentLoaded', render);
  window.matchMedia('(min-width: 981px)').addEventListener('change', render);
</script>
</head><body>
  <input id="userName" style="width:120px;height:24px;display:block">
  <input id="password" type="password" style="width:120px;height:24px;display:block">
  <div id="rm"></div>
</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sess.Close()
	ctx := sess.Ctx

	if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL)); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	// 1. Narrow layout: the checkbox is not there for a person, so the script
	// must report "no such option" instead of ticking something invisible.
	var code int
	if err := chromedp.Evaluate(rememberMeDOMOnlyJS, &code).Do(exec(ctx)); err != nil {
		t.Fatalf("narrow: evaluate: %v", err)
	}
	if code != 0 {
		t.Fatalf("narrow: outcome = %d, want 0 (hidden checkbox must not be ticked)", code)
	}

	// 2. Production widening path: the page reports a desktop-width CSS viewport.
	vp, err := readBrowserViewport(ctx)
	if err != nil {
		t.Fatalf("read viewport: %v", err)
	}
	// The metric has to be the one the school's bundle reads.
	var clientWidth int
	if err := chromedp.Evaluate(`document.documentElement.clientWidth`, &clientWidth).Do(exec(ctx)); err != nil {
		t.Fatalf("read clientWidth: %v", err)
	}
	if vp.Width != clientWidth {
		t.Fatalf("viewport width = %d, want documentElement.clientWidth %d", vp.Width, clientWidth)
	}
	if vp.desktopWidth() {
		t.Fatalf("precondition: viewport %dx%d is already desktop width", vp.Width, vp.Height)
	}
	w, err := widenBrowserForRememberMe(ctx)
	if err != nil {
		t.Fatalf("widen: %v", err)
	}
	if !w.Applied {
		t.Fatal("widen: Applied = false, want true")
	}
	wide, err := readBrowserViewport(ctx)
	if err != nil {
		t.Fatalf("read wide viewport: %v", err)
	}
	if !wide.desktopWidth() {
		t.Fatalf("after widen: viewport width = %d, want > %d", wide.Width, desktopViewportMinWidth-1)
	}

	// 3. Same production script, now that the desktop layout has rendered it:
	// one click, a real change event, and the box left checked.
	if err := chromedp.Evaluate(rememberMeDOMOnlyJS, &code).Do(exec(ctx)); err != nil {
		t.Fatalf("wide: evaluate: %v", err)
	}
	if code != 1 {
		t.Fatalf("wide: outcome = %d, want 1 (ticked by this call)", code)
	}
	var state []any
	const js = `[window.__changes, document.getElementById('rememberMe').checked]`
	if err := chromedp.Evaluate(js, &state).Do(exec(ctx)); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(state) != 2 {
		t.Fatalf("state = %v, want [changes checked]", state)
	}
	if changes, _ := state[0].(float64); changes != 1 {
		t.Fatalf("change events = %v, want exactly 1", state[0])
	}
	if checked, _ := state[1].(bool); !checked {
		t.Fatal("checkbox is not checked after the production script ran")
	}

	// 4. Restore the exact original metrics and prove the page is back to the
	// narrow layout before anything layout-dependent runs.
	if err := restoreBrowserViewport(ctx, w); err != nil {
		t.Fatalf("restore: %v", err)
	}
	back, err := readBrowserViewport(ctx)
	if err != nil {
		t.Fatalf("read restored viewport: %v", err)
	}
	if back.Width != vp.Width || back.Height != vp.Height {
		t.Fatalf("restored %dx%d, want %dx%d", back.Width, back.Height, vp.Width, vp.Height)
	}
	// The page reacts to the resize through its own matchMedia listener, which
	// runs on its own task, so give it a bounded moment instead of assuming the
	// re-render happened before the read returned.
	if !waitCheckboxGone(ctx, 2*time.Second) {
		t.Fatal("after restore: the desktop-only checkbox is still rendered at the narrow width")
	}
}

// The DOM half is shared with production, but the source gate must still refuse
// a page that is not the school's login page: the widening code is reachable
// only behind that gate.
func TestRememberMeScriptRefusesAnUntrustedOrigin(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	page := `<html><body>
  <input id="userName" style="width:120px;height:24px;display:block">
  <input id="password" type="password" style="width:120px;height:24px;display:block">
  <label><input id="rememberMe" type="checkbox">记住密码</label>
</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sess.Close()

	var code int
	if err := chromedp.Run(sess.Ctx,
		chromedp.Navigate(srv.URL),
		chromedp.Evaluate(rememberMeJS, &code),
	); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if code != 0 {
		t.Fatalf("outcome = %d, want 0 (a loopback page must not be operated on)", code)
	}
	var checked bool
	if err := chromedp.Evaluate(`document.getElementById('rememberMe').checked`, &checked).Do(exec(sess.Ctx)); err != nil {
		t.Fatalf("read checked: %v", err)
	}
	if checked {
		t.Fatal("the checkbox was ticked on an untrusted origin")
	}
}

// waitCheckboxGone polls for the desktop-only node to disappear. The page
// re-renders from its own matchMedia listener, so the re-render lands on a later
// task than the restore call that triggered it.
func waitCheckboxGone(ctx context.Context, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	const presentJS = `!!document.getElementById('rememberMe')`
	for {
		var there bool
		if err := chromedp.Evaluate(presentJS, &there).Do(exec(ctx)); err != nil {
			return false
		}
		if !there {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			return false
		}
	}
}

// waitCheckboxPresent polls for the narrow-only node to appear after the page's
// own matchMedia listener re-renders.
func waitCheckboxPresent(ctx context.Context, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	const presentJS = `!!document.getElementById('rememberMe')`
	for {
		var there bool
		if err := chromedp.Evaluate(presentJS, &there).Do(exec(ctx)); err != nil {
			return false
		}
		if there {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		if err := sleepCtx(ctx, 100*time.Millisecond); err != nil {
			return false
		}
	}
}

// The widen only sets size and scale. Touch emulation belongs to dispatchTouchAt
// on the business page, so whatever state the page had must survive both the
// widen and the restore — the widen has no business silently disabling it.
func TestWideningLeavesTouchEmulationAlone(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	page := `<html><body><input id="userName" style="width:120px;height:24px">
<input id="password" type="password" style="width:120px;height:24px"></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer sess.Close()
	ctx := sess.Ctx

	touchPoints := func() int {
		var n int
		if err := chromedp.Evaluate(`navigator.maxTouchPoints || 0`, &n).Do(exec(ctx)); err != nil {
			t.Fatalf("read maxTouchPoints: %v", err)
		}
		return n
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(srv.URL),
		chromedp.ActionFunc(func(c context.Context) error {
			return emulation.SetTouchEmulationEnabled(true).Do(exec(c))
		}),
	); err != nil {
		t.Fatalf("enable touch: %v", err)
	}
	before := touchPoints()
	if before == 0 {
		t.Fatalf("precondition: touch emulation is not visible to the page (maxTouchPoints = 0)")
	}

	w, err := widenBrowserForRememberMe(ctx)
	if err != nil {
		t.Fatalf("widen: %v", err)
	}
	if got := touchPoints(); got != before {
		t.Fatalf("after widen: maxTouchPoints = %d, want %d (the widen must not touch touch emulation)", got, before)
	}
	if err := restoreBrowserViewport(ctx, w); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := touchPoints(); got != before {
		t.Fatalf("after restore: maxTouchPoints = %d, want %d", got, before)
	}
}

// The widen can succeed and the in-page script still fail. Two shapes are worth a
// real page: the desktop layout has no box at all (the control vanishes on the
// widen), and the box is there but disabled (the click cannot take). What this
// test pins down is the script itself: it types nothing, clicks nothing else and
// submits nothing. The flow around it keeps going (see
// TestAnUnavailableRememberBoxDoesNotBlockTheLogin), because an unavailable box is
// recorded, not treated as a credential failure.
func TestAFailedTickAfterTheWidenLeavesThePageUntouched(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	cases := []struct {
		name string
		page string
		want int
	}{
		{
			// Opposite of the school's page: the box exists only while narrow, so a
			// successful widen removes it.
			name: "box disappears on the wide layout",
			want: 0, // rememberMeDOMJS: no usable box on this page
			page: `<!doctype html><html><head><meta name="viewport" content="width=device-width">
<script>
  window.__submits = 0;
  function render() {
    var host = document.getElementById('rm');
    var narrow = window.matchMedia('(max-width: 980px)').matches;
    if (narrow && !document.getElementById('rememberMe')) {
      host.innerHTML = '<label><input id="rememberMe" type="checkbox" name="rememberMe" value="on">记住密码</label>';
    } else if (!narrow && document.getElementById('rememberMe')) {
      host.innerHTML = '';
    }
  }
  document.addEventListener('DOMContentLoaded', render);
  window.matchMedia('(max-width: 980px)').addEventListener('change', render);
  document.addEventListener('submit', function (e) { e.preventDefault(); window.__submits++; });
</script>
</head><body>
  <form id="login">
    <input id="userName" name="username" style="width:120px;height:24px;display:block">
    <input id="password" name="password" type="password" style="width:120px;height:24px;display:block">
    <div id="rm"></div>
    <button id="login_submit" type="submit">登录</button>
  </form>
</body></html>`,
		},
		{
			// A visible box a person cannot tick either: disabled.
			name: "box present but disabled",
			want: 3, // rememberMeDOMJS: present, but the click did not take
			page: `<!doctype html><html><head><meta name="viewport" content="width=device-width">
<script>
  window.__submits = 0;
  document.addEventListener('submit', function (e) { e.preventDefault(); window.__submits++; });
</script>
</head><body>
  <form id="login">
    <input id="userName" name="username" style="width:120px;height:24px;display:block">
    <input id="password" name="password" type="password" style="width:120px;height:24px;display:block">
    <label id="rm"><input id="rememberMe" type="checkbox" name="rememberMe" value="on" disabled>记住密码</label>
    <button id="login_submit" type="submit">登录</button>
  </form>
</body></html>`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = fmt.Fprint(w, tc.page)
			}))
			defer srv.Close()

			cfg := store.Defaults()
			cfg.UserData = t.TempDir()
			sess, err := edge.LaunchContext(context.Background(), cfg)
			if err != nil {
				t.Fatalf("launch: %v", err)
			}
			defer sess.Close()
			ctx := sess.Ctx
			if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL)); err != nil {
				t.Fatalf("navigate: %v", err)
			}

			w, err := widenBrowserForRememberMe(ctx)
			if err != nil {
				t.Fatalf("widen: %v", err)
			}
			if !w.Applied {
				t.Fatal("widen: Applied = false, want true on this narrow page")
			}
			// A person looking at the widened page can see no usable control, and the
			// production DOM half says so instead of pretending to have ticked it.
			var code int
			if err := chromedp.Evaluate(rememberMeDOMOnlyJS, &code).Do(exec(ctx)); err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if code != tc.want {
				t.Fatalf("outcome = %d, want %d", code, tc.want)
			}
			var state []any
			const js = `[(document.getElementById('userName')||{}).value||'',
 (document.getElementById('password')||{}).value||'', window.__submits||0]`
			if err := chromedp.Evaluate(js, &state).Do(exec(ctx)); err != nil {
				t.Fatalf("read state: %v", err)
			}
			if user, _ := state[0].(string); user != "" {
				t.Fatalf("username field = %q, want empty", user)
			}
			if pass, _ := state[1].(string); pass != "" {
				t.Fatal("password field is not empty, want empty")
			}
			if submits, _ := state[2].(float64); submits != 0 {
				t.Fatalf("submits = %v, want 0", state[2])
			}
			if err := restoreBrowserViewport(ctx, w); err != nil {
				t.Fatalf("restore: %v", err)
			}
		})
	}
}
