package signin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Loopback reproduction of the ordering question of this round: a submission
// whose response carries a business code the flow cannot classify, followed by an
// error modal the page renders from the response continuation. The page mimics the
// public CAS client's own shape (the modal the school's antd build renders, in the
// same region the readers select). Opt-in via DORMSIGN_EDGE_TEST=1; nothing here
// touches the school, real credentials or a user profile.
//
// The page modes:
//
//	"generic"     the client's own unlisted-code sentence, one tick after the
//	              response (the test sets that gap: it reproduces the ordering, it
//	              does not claim the school's own latency);
//	"counter"     the wrong-password counter sentence, same gap;
//	"credential"  a credential sentence rendered in the response continuation with
//	              no added delay, i.e. the tightest race the page can produce;
//	"silent"      a leftover credential modal rendered at LOAD, and nothing after
//	              the response.
func promptLoopbackServer(t *testing.T, mode string, responseDelay time.Duration) (*httptest.Server, *int32) {
	t.Helper()
	var posts int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		stale := ""
		if mode == "silent" {
			// A leftover modal from a previous attempt, already visible BEFORE this
			// submission: it must never be usable as evidence about it.
			stale = `window.__show('登录失败','用户名或密码错误。');`
		}
		_, _ = w.Write([]byte(`<html><body>
<form><input id="userName"><input id="password"><button type="button" id="submit">登录</button></form>
<script>
window.__kind='` + mode + `';
window.__show=function(title,content){
  var m=document.createElement('div');
  m.className='ant-modal-confirm ant-modal-confirm-error';
  var b=document.createElement('div');b.className='ant-modal-confirm-body';
  var t=document.createElement('span');t.className='ant-modal-confirm-title';t.innerText=title;
  var c=document.createElement('div');c.className='ant-modal-confirm-content';c.innerText=content;
  b.appendChild(t);b.appendChild(c);m.appendChild(b);document.body.appendChild(m);
};
window.__notify=function(){
  if(window.__kind==='counter'){window.__show('登录失败','密码已连续错误【3】次，连续错误【5】次账号将被锁定。');return;}
  if(window.__kind==='credential'){window.__show('登录失败','用户名或密码错误。');return;}
  if(window.__kind==='silent'){return;}
  window.__show('登录失败','请检查账号或密码是否正确');
};
window.__post=function(){
  fetch('/v1/tickets',{method:'POST'}).then(function(r){return r.json()}).then(function(body){
    // The public client reads body.data.code: the code lives one level below the
    // response envelope, exactly where the Go extractor reads it too.
    var d=body.data, code=d&&d.code;
    if(!code){location.replace('/after?ticket='+(body.ticket||''));return;}
    if(window.__kind==='credential'||window.__kind==='silent'){window.__notify();return;}
    setTimeout(function(){window.__notify();},350);
  });
};
` + stale + `
</script></body></html>`))
	})
	mux.HandleFunc("/v1/tickets", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&posts, 1)
		if responseDelay > 0 {
			time.Sleep(responseDelay)
		}
		w.Header().Set("Content-Type", "application/json")
		// A business code the flow cannot classify, in the exact shape the public
		// client reads it from (body.data.code) — an unlisted string value, like
		// the one the real runs recorded.
		_, _ = w.Write([]byte(`{"data":{"code":"02e70410","uid":"loop"}}`))
	})
	mux.HandleFunc("/after", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("navigated"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &posts
}

// testRegionPromptJS reads the very same fixed error regions the production reader
// reads, without the school-host guard: a loopback page is not the school
// document, so only the region selection, the visibility filter and the
// sampled/parts split are exercised here. The guard itself is covered by
// TestPagePromptReaderIsPassiveAndScoped and
// TestLoopbackPromptFromAnUntrustedDocumentIsRefused.
const testRegionPromptJS = `JSON.stringify({"sampled":true,"parts":(` + casErrorRegionsJS + `)})`

type regionReaderCounter struct{ calls int32 }

func (c *regionReaderCounter) read(ctx context.Context) promptRead {
	atomic.AddInt32(&c.calls, 1)
	if ctx.Err() != nil {
		return promptRead{}
	}
	var raw string
	if err := chromedp.Evaluate(testRegionPromptJS, &raw).Do(exec(ctx)); err != nil {
		return promptRead{}
	}
	return parsePromptRead(raw)
}

// loopbackObservation wires the production observation onto the loopback page.
func loopbackObservation(t *testing.T, ctx context.Context, srv *httptest.Server, tr *verifyTrace, reader func(context.Context) promptRead) *authObservation {
	t.Helper()
	o := &authObservation{
		out:           make(chan VerificationResult, 1),
		trace:         tr,
		pagePrompt:    reader,
		matchEndpoint: func(raw string) bool { return raw == srv.URL+"/v1/tickets" },
		matchDocument: func(raw string) bool { return strings.HasPrefix(raw, srv.URL+"/login") },
		fetchPattern:  srv.URL + "/v1/tickets",
	}
	o.release = o.releasePausedCDP
	chromedp.ListenTarget(ctx, func(ev any) { o.listen(ctx, ev) })
	if err := network.Enable().Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := o.enableFetch(ctx); err != nil {
		t.Fatalf("fetch enable failed: %v", err)
	}
	t.Cleanup(func() { o.disableFetch(ctx) })
	if err := chromedp.Navigate(srv.URL + "/login").Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	return o
}

// loopbackBrowser launches a disposable Edge session for one loopback case.
func loopbackBrowser(t *testing.T) context.Context {
	t.Helper()
	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	s, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.Ctx
}

// The prompt appears after the verdict, and the bounded look still adopts it.
// The page's gap is set by the test: this reproduces the ordering the round is
// about and shows the look closes it. It is NOT a measurement of the school's own
// latency.
func TestLoopbackLatePagePromptIsObserved(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	for _, tc := range []struct {
		name      string
		mode      string
		wantIssue AuthIssue
		wantCode  VerifyReason
		want      string
	}{
		{"generic failure", "generic", AuthUnknown, ReasonPageGenericRejection, "prompt=generic"},
		{"wrong-password counter", "counter", AuthCredentialsRejected, ReasonPagePasswordCounter, "prompt=password_counter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, posts := promptLoopbackServer(t, tc.mode, 0)
			ctx := loopbackBrowser(t)
			var lines []string
			tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
			reader := &regionReaderCounter{}
			o := loopbackObservation(t, ctx, srv, tr, reader.read)
			snap := snapshotPagePrompt(o.readPagePrompt(ctx))
			if !snap.sampled || len(snap.before) != 0 {
				t.Fatalf("setup: the snapshot must be clean and readable: %+v", snap)
			}
			o.arm()
			t0 := time.Now()
			if err := chromedp.Evaluate("window.__post()", nil).Do(exec(ctx)); err != nil {
				t.Fatal(err)
			}
			var result VerificationResult
			var resultAt time.Duration
			select {
			case result = <-o.out:
				resultAt = time.Since(t0)
			case <-time.After(30 * time.Second):
				t.Fatal("no result within 30s")
			}
			if result.Issue != AuthUnknown || result.ReasonCode != ReasonUnknownBusinessCode {
				t.Fatalf("setup: expected the unclassified code, got %+v", result)
			}
			// Poll the page and note when a prompt USABLE for this attempt exists:
			// the gap is the one this test set, so the verdict is expected first.
			var promptAt time.Duration
			var seen []string
			deadline := time.Now().Add(5 * time.Second)
			for {
				read := reader.read(ctx)
				if read.sampled {
					if _, _, usable := classifyPagePrompt(read.parts, snap); usable {
						promptAt, seen = time.Since(t0), read.parts
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("the page never rendered an error modal usable for this attempt")
				}
				time.Sleep(25 * time.Millisecond)
			}
			t.Logf("verdict delivered %v; prompt usable %v: %q", resultAt, promptAt, seen)
			if promptAt <= resultAt {
				t.Fatalf("expected the prompt (%v) after the verdict (%v)", promptAt, resultAt)
			}
			refined, interrupted := o.observePagePrompt(ctx, result, snap)
			if interrupted {
				t.Fatal("unexpected interruption")
			}
			if refined.Issue != tc.wantIssue || refined.ReasonCode != tc.wantCode {
				t.Fatalf("refined result = %+v, want %s/%s", refined, tc.wantIssue, tc.wantCode)
			}
			if strings.Contains(refined.Reason, "密码错误") && tc.wantIssue != AuthCredentialsRejected {
				t.Fatalf("a non-credential outcome was worded as a password verdict: %q", refined.Reason)
			}
			tr.finish()
			if len(lines) != 1 || !strings.Contains(lines[0], tc.want) {
				t.Fatalf("summary = %v, want %s", lines, tc.want)
			}
			if n := atomic.LoadInt32(posts); n != 1 {
				t.Fatalf("exactly one submission expected, the server saw %d", n)
			}
		})
	}
}

// The tightest race the page can produce (the modal rendered in the response
// continuation, no added delay) must still end in the credential verdict, through
// the production wait — whichever of the two mechanisms reads it first.
func TestLoopbackImmediatePromptThroughTheProductionWait(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv, posts := promptLoopbackServer(t, "credential", 0)
	ctx := loopbackBrowser(t)
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	reader := &regionReaderCounter{}
	o := loopbackObservation(t, ctx, srv, tr, reader.read)
	snap := snapshotPagePrompt(o.readPagePrompt(ctx))
	if !snap.sampled || len(snap.before) != 0 {
		t.Fatalf("setup: the snapshot must be clean and readable: %+v", snap)
	}
	o.arm()
	t0 := time.Now()
	if err := chromedp.Evaluate("window.__post()", nil).Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	got := o.awaitAuthResult(ctx, tr, snap)
	t.Logf("awaitAuthResult returned after %v: %+v (page reads=%d)", time.Since(t0), got, atomic.LoadInt32(&reader.calls))
	if got.Issue != AuthCredentialsRejected {
		t.Fatalf("the page's credential sentence was not adopted: %+v", got)
	}
	tr.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=credential") {
		t.Fatalf("summary = %v", lines)
	}
	if n := atomic.LoadInt32(posts); n != 1 {
		t.Fatalf("exactly one submission expected, the server saw %d", n)
	}
}

// The leftover-modal scenario of the complete wait: a credential modal is already
// visible before the submission, and the response takes longer than several polls.
// The wait must not report a wrong password from it; the response verdict stands.
func TestLoopbackStaleModalDoesNotDecideASlowResponse(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv, posts := promptLoopbackServer(t, "silent", 600*time.Millisecond)
	ctx := loopbackBrowser(t)
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	reader := &regionReaderCounter{}
	o := loopbackObservation(t, ctx, srv, tr, reader.read)
	// The leftover modal is on the page BEFORE the submission, so it belongs to
	// the snapshot.
	snap := snapshotPagePrompt(o.readPagePrompt(ctx))
	if !snap.sampled || len(snap.before) != 1 {
		t.Fatalf("setup: expected exactly one leftover sentence in the snapshot: %+v", snap)
	}
	o.arm()
	if err := chromedp.Evaluate("window.__post()", nil).Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	got := o.awaitAuthResult(ctx, tr, snap)
	if got.Issue == AuthCredentialsRejected {
		t.Fatalf("the leftover modal was reported as this attempt's password error: %+v", got)
	}
	if got.Issue != AuthUnknown || got.ReasonCode != ReasonUnknownBusinessCode {
		t.Fatalf("the response verdict must stand: %+v", got)
	}
	if n := atomic.LoadInt32(&reader.calls); n < 2 {
		t.Fatalf("the wait must have polled the page before the slow response, reads=%d", n)
	}
	tr.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=no_new_sentence") {
		t.Fatalf("summary = %v", lines)
	}
	if n := atomic.LoadInt32(posts); n != 1 {
		t.Fatalf("exactly one submission expected, the server saw %d", n)
	}
}

// The production reader must refuse a document that is not the trusted school
// login page, and must say so: an unreadable document is not an empty one.
func TestLoopbackPromptFromAnUntrustedDocumentIsRefused(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for the local loopback Edge test")
	}
	srv, _ := promptLoopbackServer(t, "generic", 0)
	ctx := loopbackBrowser(t)
	if err := chromedp.Navigate(srv.URL + "/login").Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Evaluate("window.__show('登录失败','用户名或密码错误。')", nil).Do(exec(ctx)); err != nil {
		t.Fatal(err)
	}
	// The region reader sees it; the production reader refuses the document and
	// reports the read as unusable, not as an empty page.
	reader := &regionReaderCounter{}
	if read := reader.read(ctx); !read.sampled || len(read.parts) != 1 || read.parts[0] != "用户名或密码错误。" {
		t.Fatalf("setup: the modal was not visible to the region reader: %+v", read)
	}
	if read := casPagePrompt(ctx); read.sampled || len(read.parts) != 0 {
		t.Fatalf("the production reader trusted a non-CAS document: %+v", read)
	}
}
