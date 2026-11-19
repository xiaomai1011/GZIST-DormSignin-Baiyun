package signin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Opt-in local integration test for the 「记住密码」 DOM script: it runs the real
// script (rememberMeDOMJS, and the guarded rememberMeJS for the origin case)
// against pages served from 127.0.0.1 and checks the browser's own state, not a
// preset answer. No school URL, no login, no credentials, disposable profile.
//
//	set DORMSIGN_EDGE_TEST=1 to run it

// rememberPage builds a fake login page carrying the school's form ids and one
// variant of the rememberMe checkbox. Every variant records its own events, so
// "the page saw a change" is measured in the page, not assumed.
func rememberPage(body string) string {
	return `<!doctype html><meta charset="utf-8"><title>login</title>
<form id="f" method="post" action="/submit">
<div><input id="userName" name="userName" value="20260001"></div>
<div><input id="password" name="password" type="password" value="x"></div>` + body + `
</form>
<script>
window.__ev=[];
var cb=document.querySelector('#f input[name=rememberMe]');
if(cb){cb.addEventListener('click',function(){window.__ev.push('click')});
       cb.addEventListener('change',function(){window.__ev.push('change')});}
window.__state=function(){
  var c=document.querySelector('#f input[name=rememberMe]');
  return {ev:window.__ev.slice(),checked:!!(c&&c.checked),
          form:String(new FormData(document.getElementById('f')).get('rememberMe'))};
};
</script>`
}

const (
	plainBox    = `<label><input type="checkbox" id="rememberMe" name="rememberMe" value="on">记住密码</label>`
	styledBox   = `<label class="nice"><input type="checkbox" id="rememberMe" name="rememberMe" value="on" style="opacity:0;width:0;height:0;position:absolute"><span class="tick">记住密码</span></label>`
	checkedBox  = `<label><input type="checkbox" id="rememberMe" name="rememberMe" value="on" checked>记住密码</label>`
	disabledBox = `<label><input type="checkbox" id="rememberMe" name="rememberMe" value="on" disabled>记住密码</label>`
	hiddenBox   = `<div style="display:none"><input type="checkbox" id="rememberMe" name="rememberMe" value="on"></div>`
	noIDBox     = `<label style="display:block;width:160px;height:24px"><input type="checkbox" name="rememberMe" value="on">七天之内记住密码</label>`
)

func TestRememberMeDOMAgainstLocalPages(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local rememberMe DOM test")
	}
	pages := map[string]string{
		"/plain":    rememberPage(plainBox),
		"/styled":   rememberPage(styledBox),
		"/checked":  rememberPage(checkedBox),
		"/disabled": rememberPage(disabledBox),
		"/hidden":   rememberPage(hiddenBox),
		"/noid":     rememberPage(noIDBox),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.Launch(cfg)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer func() {
		if err := sess.Close(); err != nil {
			t.Errorf("browser cleanup: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(sess.Ctx, 90*time.Second)
	defer cancel()

	// domScript is the production DOM body wrapped the way rememberMeJS wraps it,
	// minus the two gates (page trust, visible form) that the origin case below
	// exercises through the full string. A bare DOM body cannot be evaluated on its
	// own: its top-level return would be an illegal statement in a script.
	domScript := "(function(){" + casVisibleFnJS + rememberMeDOMJS + "})()"

	// readState runs one page's script and then reads the page's own record of
	// what happened (events, checked state, submitted form value).
	readState := func(t *testing.T, path, script string) (int, map[string]any) {
		t.Helper()
		if err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+path)); err != nil {
			t.Fatalf("%s: navigate: %v", path, err)
		}
		var code int
		if err := chromedp.Run(ctx, chromedp.Evaluate(script, &code)); err != nil {
			t.Fatalf("%s: evaluate: %v", path, err)
		}
		var state map[string]any
		if err := chromedp.Run(ctx, chromedp.Evaluate(`window.__state()`, &state)); err != nil {
			t.Fatalf("%s: state: %v", path, err)
		}
		return code, state
	}
	events := func(state map[string]any) string {
		raw, _ := state["ev"].([]any)
		parts := make([]string, 0, len(raw))
		for _, e := range raw {
			parts = append(parts, fmt.Sprint(e))
		}
		return strings.Join(parts, ",")
	}

	t.Run("plain checkbox is ticked and the page sees one change", func(t *testing.T) {
		code, state := readState(t, "/plain", domScript)
		if code != 1 {
			t.Fatalf("code = %d, want 1 (ticked)", code)
		}
		if got := events(state); got != "click,change" {
			t.Fatalf("events = %q, want exactly one click and one change (no double toggle)", got)
		}
		if state["checked"] != true {
			t.Fatalf("checked = %v, want true", state["checked"])
		}
		if state["form"] != "on" {
			t.Fatalf("submitted value = %q, want on: the form must carry the tick", state["form"])
		}
	})

	t.Run("styled box with a transparent native input is still tickable", func(t *testing.T) {
		code, state := readState(t, "/styled", domScript)
		if code != 1 {
			t.Fatalf("code = %d, want 1: a visible wrapper around a transparent input is a real option", code)
		}
		if state["checked"] != true {
			t.Fatalf("checked = %v, want true", state["checked"])
		}
		if state["form"] != "on" {
			t.Fatalf("submitted value = %q, want on", state["form"])
		}
	})

	t.Run("already ticked box is reported and left alone", func(t *testing.T) {
		code, state := readState(t, "/checked", domScript)
		if code != 2 {
			t.Fatalf("code = %d, want 2 (already ticked)", code)
		}
		if got := events(state); got != "" {
			t.Fatalf("events = %q, want none: an already ticked box must not be clicked", got)
		}
		if state["checked"] != true || state["form"] != "on" {
			t.Fatalf("state after read = %#v, want still ticked", state)
		}
	})

	t.Run("disabled box reports a failed write instead of pretending", func(t *testing.T) {
		code, state := readState(t, "/disabled", domScript)
		if code != 3 {
			t.Fatalf("code = %d, want 3 (present but the tick did not take)", code)
		}
		if state["checked"] != false {
			t.Fatalf("checked = %v, want false", state["checked"])
		}
		// A disabled control is not submitted at all, so the form carries no value.
		if state["form"] != "null" {
			t.Fatalf("submitted value = %q, want none (disabled controls are not submitted)", state["form"])
		}
	})

	t.Run("invisible option is reported absent, not ticked", func(t *testing.T) {
		code, state := readState(t, "/hidden", domScript)
		if code != 0 {
			t.Fatalf("code = %d, want 0 (no visible option)", code)
		}
		if got := events(state); got != "" {
			t.Fatalf("events = %q, want none", got)
		}
		if state["checked"] != false {
			t.Fatalf("checked = %v, want false", state["checked"])
		}
	})

	t.Run("box found through its label text when the id is missing", func(t *testing.T) {
		code, state := readState(t, "/noid", domScript)
		if code != 1 {
			t.Fatalf("code = %d, want 1: the label text 「七天之内记住密码」 identifies the option", code)
		}
		if state["checked"] != true || state["form"] != "on" {
			t.Fatalf("state = %#v, want ticked and carried in the form", state)
		}
	})

	// The full script keeps its page-trust gate: a loopback http page is not the
	// school's login origin, so nothing may be clicked even though the DOM would
	// allow it. This is the "wrong origin" case, run against the production string.
	t.Run("wrong origin is refused by the guarded script", func(t *testing.T) {
		code, state := readState(t, "/plain", rememberMeJS)
		if code != 0 {
			t.Fatalf("code = %d, want 0: an untrusted origin must not be acted on", code)
		}
		if got := events(state); got != "" {
			t.Fatalf("events = %q, want none on an untrusted origin", got)
		}
		if state["checked"] != false {
			t.Fatalf("checked = %v, want false: nothing may be written off-origin", state["checked"])
		}
		// checkRememberMe maps that refusal onto "no option here", which is what
		// the run reports; it must never report a tick.
		if out := checkRememberMe(ctx); out != rememberAbsent {
			t.Fatalf("checkRememberMe on an untrusted page = %v, want absent", out)
		}
	})
}
