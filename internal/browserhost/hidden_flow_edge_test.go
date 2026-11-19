//go:build windows

package browserhost

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
)

// Real Edge, temporary profiles and loopback only. Native visibility is checked
// separately from document.visibilityState, which focus emulation overrides.
func TestHiddenDynamicFormAndRedirectEdge(t *testing.T) {
	if os.Getenv("BROWSERHOST_HIDDEN_FLOW_TEST") != "1" {
		t.Skip("requires BROWSERHOST_HIDDEN_FLOW_TEST=1")
	}
	for _, tc := range []struct {
		name         string
		shown, focus bool
	}{
		{"hidden-unfocused", false, false}, {"shown-control", true, false}, {"hidden-focus", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts, attempts atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<!doctype html><html><body><div id="mount"></div><script>
window.events=[];
for(const type of ['mousedown','mouseup','click','submit','input'])document.addEventListener(type,e=>{
 window.events.push({type,target:e.target.id,trusted:e.isTrusted});
 sessionStorage.setItem('fixtureEvents',JSON.stringify(window.events));
},true);
setTimeout(()=>{document.getElementById('mount').innerHTML='<form method="POST" action="/session"><input id="fixtureUser" name="user"><input id="fixturePass" name="pass" type="password"><button id="submit">Submit fixture</button></form>'},150);
</script></body></html>`)
			})
			mux.HandleFunc("/session", func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if r.Method != http.MethodPost {
					http.Error(w, "method", 405)
					return
				}
				if err := r.ParseForm(); err != nil || r.Form.Get("user") != "fixture-user" || r.Form.Get("pass") != "fixture-only" {
					http.Error(w, "fixture", 400)
					return
				}
				posts.Add(1)
				http.Redirect(w, r, "/business", http.StatusSeeOther)
			})
			mux.HandleFunc("/business", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body><div id="ready">fixture business ready</div></body></html>`)
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			d, c, _ := newHarness(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var restored bool
			sess, finish, err := c.AttachForTask(ctx, time.Minute, func(cleanCtx context.Context, _ *edge.Session) error {
				if !tc.focus {
					return nil
				}
				err := chromedp.Run(cleanCtx, emulation.SetFocusEmulationEnabled(false))
				restored = err == nil
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := finish(); err != nil {
					t.Errorf("task cleanup: %v", err)
				}
			}()
			assertNative := func(wantVisible bool) {
				t.Helper()
				d.mu.Lock()
				control, ok := d.window.(*controlledWindow)
				d.mu.Unlock()
				if !ok {
					t.Fatal("missing native window controller")
				}
				control.mu.Lock()
				w, err := control.candidate()
				control.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("native visible=%v minimized=%v", w.visible, w.minimized)
				if w.visible != wantVisible {
					t.Fatalf("native visible=%v want=%v", w.visible, wantVisible)
				}
			}
			assertNative(false)
			if tc.shown {
				if err := c.SetWindowVisible(ctx, true); err != nil {
					t.Fatal(err)
				}
			}
			if tc.focus {
				if err := chromedp.Run(sess.Ctx, emulation.SetFocusEmulationEnabled(true)); err != nil {
					t.Fatal(err)
				}
			}
			assertNative(tc.shown)
			if err := chromedp.Run(sess.Ctx, chromedp.Navigate(srv.URL+"/login"), chromedp.WaitVisible("#submit", chromedp.ByQuery), chromedp.SendKeys("#fixtureUser", "fixture-user", chromedp.ByQuery), chromedp.SendKeys("#fixturePass", "fixture-only", chromedp.ByQuery)); err != nil {
				t.Fatal(err)
			}
			var diag struct {
				Width      int    `json:"width"`
				Height     int    `json:"height"`
				Visibility string `json:"visibility"`
				User       string `json:"user"`
				Pass       string `json:"pass"`
			}
			if err := chromedp.Run(sess.Ctx, chromedp.Evaluate(`({width:innerWidth,height:innerHeight,visibility:document.visibilityState,user:document.querySelector('#fixtureUser').value,pass:document.querySelector('#fixturePass').value})`, &diag)); err != nil {
				t.Fatal(err)
			}
			t.Logf("before click viewport=%dx%d document=%s user_filled=%v pass_filled=%v", diag.Width, diag.Height, diag.Visibility, diag.User == "fixture-user", diag.Pass == "fixture-only")
			if err := chromedp.Run(sess.Ctx, chromedp.Click("#submit", chromedp.ByQuery)); err != nil {
				t.Fatal(err)
			}
			if !tc.shown && !tc.focus {
				// Reproduce the original failure without waiting for a nonexistent redirect.
				select {
				case <-time.After(300 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				var count int
				if err := chromedp.Run(sess.Ctx, chromedp.Evaluate(`window.events.length`, &count)); err != nil {
					t.Fatal(err)
				}
				if count != 0 || attempts.Load() != 0 || diag.User != "" || diag.Pass != "" {
					t.Fatalf("baseline changed: events=%d requests=%d diag=%+v", count, attempts.Load(), diag)
				}
				assertNative(false)
				return
			}
			if err := chromedp.Run(sess.Ctx, chromedp.WaitVisible("#ready", chromedp.ByQuery)); err != nil {
				t.Fatalf("posts=%d: %v", posts.Load(), err)
			}
			var events []struct {
				Type    string `json:"type"`
				Trusted bool   `json:"trusted"`
			}
			if err := chromedp.Run(sess.Ctx, chromedp.Evaluate(`JSON.parse(sessionStorage.getItem('fixtureEvents')||'[]')`, &events)); err != nil {
				t.Fatal(err)
			}
			counts := map[string]int{}
			for _, e := range events {
				if !e.Trusted {
					t.Fatalf("untrusted event %s", e.Type)
				}
				counts[e.Type]++
			}
			for _, kind := range []string{"mousedown", "mouseup", "click", "submit"} {
				if counts[kind] != 1 {
					t.Fatalf("event %s count=%d", kind, counts[kind])
				}
			}
			if counts["input"] == 0 || posts.Load() != 1 || attempts.Load() != 1 {
				t.Fatalf("events=%v posts=%d requests=%d", counts, posts.Load(), attempts.Load())
			}
			t.Logf("confirmed trusted events=%v POST=%d business=true", counts, posts.Load())
			assertNative(tc.shown)
			if tc.focus {
				if err := finish(); err != nil {
					t.Fatal(err)
				}
				if !restored {
					t.Fatal("task did not restore focus before releasing")
				}
				d.mu.Lock()
				ownerCtx := d.session.Ctx
				d.mu.Unlock()
				verifyCtx, stop := context.WithTimeout(ownerCtx, 3*time.Second)
				defer stop()
				var visibility string
				if err := chromedp.Run(verifyCtx, chromedp.Evaluate(`document.visibilityState`, &visibility)); err != nil {
					t.Fatal(err)
				}
				if visibility != "hidden" {
					t.Fatalf("focus emulation not restored: %s", visibility)
				}
				assertNative(false)
			}
			if tc.shown {
				if err := c.SetWindowVisible(ctx, false); err != nil {
					t.Fatal(err)
				}
				assertNative(false)
			}
		})
	}
}
