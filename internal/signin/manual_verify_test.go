package signin

// Tests for visible-browser mode: the wait itself (verdicts, priority, safe page
// categories) and the flow that uses it (zero writes while a human works,
// exactly one resume afterwards, and the unchanged hidden-mode behaviour).
// Everything runs offline against the fake page; no browser, no school.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

func TestManualVerifyPageAllowList(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://ids.gzist.edu.cn/loginAgain", true},
		{"https://ids.gzist.edu.cn:443/loginAgain", true},
		{"https://ids.gzist.edu.cn/lyuapServer/login?service=x", true},
		{"https://xsfw.gzist.edu.cn/xsfw/sys/swmzncqapp/*default/index.do#/xscq/grcq", true},
		{"https://xsfw.gzist.edu.cn:443/xsfw/sys/x", true},
		// Same hostname is not enough: the rule is the same schoolURL the rest
		// of the flow trusts pages by — https, exact host, no userinfo, 443.
		{"http://xsfw.gzist.edu.cn/xsfw/sys/x", false},
		{"http://ids.gzist.edu.cn/loginAgain", false},
		{"https://ids.gzist.edu.cn:8443/loginAgain", false},
		{"https://xsfw.gzist.edu.cn:8443/xsfw/sys/x", false},
		{"https://user@ids.gzist.edu.cn/loginAgain", false},
		{"https://user:pass@xsfw.gzist.edu.cn/xsfw/sys/x", false},
		{"https://evil.example/loginAgain", false},
		{"https://ids.gzist.edu.cn.evil.invalid/loginAgain", false},
		{"https://evilids.gzist.edu.cn/loginAgain", false},
		{"ftp://ids.gzist.edu.cn/loginAgain", false},
		{"", false},
		{"not a url", false},
	}
	for _, c := range cases {
		if got := manualVerifyPageIsAllowed(c.url); got != c.want {
			t.Fatalf("manualVerifyPageIsAllowed(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestWaitForManualVerificationReachesTheBusinessPage(t *testing.T) {
	clock := newFakeClock()
	reads := 0
	ops := loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		probe: func(context.Context) (pageState, error) {
			reads++
			if reads < 3 {
				return pageState{URL: testTwoVerifyURL}, nil
			}
			return pageState{URL: testBusinessURL}, nil
		},
	}
	verdict, diag := waitForManualVerification(context.Background(), runOrigins{}, time.Second, ops)
	if verdict != manualVerifyReached {
		t.Fatalf("verdict = %s, want reached", verdict)
	}
	if diag.Reads != 3 || diag.Page != "business" {
		t.Fatalf("diag = %+v, want 3 reads ending on the business page", diag)
	}
	line := manualVerifyDiagLine(verdict, diag)
	if !strings.Contains(line, "verdict=reached") || strings.Contains(line, "/loginAgain") || strings.Contains(line, "?") {
		t.Fatalf("diag line = %q, want a fixed enumeration without any URL", line)
	}
}

func TestWaitForManualVerificationKeepsCancelBudgetAndLateLineApart(t *testing.T) {
	// A page that stays on the two-factor page forever: only ctx can end it.
	stuck := func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
			return nil
		}
	}
	ops := loginPageOps{
		now:   time.Now,
		sleep: stuck,
		probe: func(context.Context) (pageState, error) { return pageState{URL: testTwoVerifyURL}, nil },
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if v, _ := waitForManualVerification(cancelCtx, runOrigins{caller: cancelCtx}, time.Millisecond, ops); v != manualVerifyCanceled {
		t.Fatalf("verdict = %s, want canceled", v)
	}

	budgetCtx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if v, _ := waitForManualVerification(budgetCtx, runOrigins{caller: budgetCtx}, time.Millisecond, ops); v != manualVerifyBudget {
		t.Fatalf("verdict = %s, want budget: a spent run budget must not read as a cancel", v)
	}

	lateCtx, lateStop := context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), errLateLine)
	defer lateStop()
	if v, _ := waitForManualVerification(lateCtx, runOrigins{caller: lateCtx}, time.Millisecond, ops); v != manualVerifyStopped {
		t.Fatalf("verdict = %s, want late_line: past the late line nothing is resumed", v)
	}
}

func TestWaitForManualVerificationReportsAGoneBrowserWithoutGuessingWhy(t *testing.T) {
	ops := loginPageOps{
		now:   time.Now,
		sleep: func(context.Context, time.Duration) error { return nil },
		probe: func(context.Context) (pageState, error) { return pageState{}, errors.New("context canceled") },
	}
	verdict, diag := waitForManualVerification(context.Background(), runOrigins{}, time.Millisecond, ops)
	if verdict != manualVerifyDisconnected {
		t.Fatalf("verdict = %s, want disconnected", verdict)
	}
	if diag.ReadErrors != manualVerifyMaxReadErrors {
		t.Fatalf("read errors = %d, want %d consecutive reads before giving up", diag.ReadErrors, manualVerifyMaxReadErrors)
	}
	if verdict.String() == "crashed" {
		t.Fatal("the wait must not claim a crash it cannot see")
	}
}

func TestWaitForManualVerificationStopsOnAnUnsupportedPage(t *testing.T) {
	ops := loginPageOps{
		now:   time.Now,
		sleep: func(context.Context, time.Duration) error { return nil },
		probe: func(context.Context) (pageState, error) { return pageState{URL: "https://evil.example/steal"}, nil },
	}
	verdict, diag := waitForManualVerification(context.Background(), runOrigins{}, time.Millisecond, ops)
	if verdict != manualVerifyUnsupported {
		t.Fatalf("verdict = %s, want unsupported", verdict)
	}
	if diag.Page != "other" {
		t.Fatalf("page category = %q, want other (still desensitized)", diag.Page)
	}
}

// ---- flow level: the counts below are measured on the fake page ----

func TestFlowHiddenModeStillStopsAtTheTwoFactorPage(t *testing.T) {
	p := newFakeLoginPage()
	p.twoVerifyFromStart = true // hidden mode: nobody can finish it, so stop
	p.probeFailAfter = 50       // bound: a wrong wait here fails fast instead of hanging

	res, ok := p.submitFlow(t, 8, nil)
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok in hidden mode", res)
	}
	if res.Exit != 3 || res.AuthIssue != AuthActionRequired {
		t.Fatalf("result = %+v, want Exit 3 with AuthActionRequired", res)
	}
	if p.clicks != 0 || p.fills != 0 || p.solves != 0 {
		t.Fatalf("hidden mode wrote to the page: clicks=%d fills=%d solves=%d", p.clicks, p.fills, p.solves)
	}
	if !strings.Contains(res.Reason, "二次验证") {
		t.Fatalf("Reason = %q, want the two-factor reason", res.Reason)
	}
	if hasLog(p.logs, "人工验证等待") {
		t.Fatalf("hidden mode waited for a human: %v", p.logs)
	}
}

func TestFlowVisibleModeWaitsReadOnlyThenResumesExactlyOnce(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	p.businessAfterProbes = 3 // a human finished the two-factor step on the third read

	res, ok := p.submitFlow(t, 8, nil)
	if !ok || !res.OK {
		t.Fatalf("result = %+v ok=%v, want a resumed run", res, ok)
	}
	if p.clicks != 0 || p.fills != 0 || p.solves != 0 || p.refreshes != 0 {
		t.Fatalf("the wait wrote to the page: clicks=%d fills=%d solves=%d refreshes=%d",
			p.clicks, p.fills, p.solves, p.refreshes)
	}
	waits, resumes := 0, 0
	for _, l := range p.logs {
		if strings.Contains(l, "人工验证等待") {
			waits++
		}
		if strings.Contains(l, "仅此一次") {
			resumes++
		}
	}
	if waits != 1 {
		t.Fatalf("waits = %d, want exactly one wait (a late page change must not re-enter it): %v", waits, p.logs)
	}
	if resumes != 1 {
		t.Fatalf("resumes = %d, want exactly one resume", resumes)
	}
	if !hasLog(p.logs, "verdict=reached") {
		t.Fatalf("no reached verdict in the log: %v", p.logs)
	}
	if !hasLog(p.logs, "不填写、不点击、不发送短信") {
		t.Fatalf("the wait was not announced as read-only: %v", p.logs)
	}
}

func TestFlowVisibleModeCancelDuringTheWaitWins(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	res, ok := p.submitFlow(t, 8, func(_ context.Context, c context.CancelFunc) {
		p.onProbe = func(f *fakeLoginPage) {
			if f.probes >= 2 {
				c() // the run is stopped while the human is still working
			}
		}
	})
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok after a cancel", res)
	}
	if res.Exit != 5 {
		t.Fatalf("Exit = %d, want 5 (canceled)", res.Exit)
	}
	if p.clicks != 0 || p.fills != 0 {
		t.Fatalf("a canceled wait submitted something: clicks=%d fills=%d", p.clicks, p.fills)
	}
}

func TestFlowVisibleModeReportsAGoneBrowserInsteadOfWaitingForever(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	p.probeFailAfter = 2 // the window was closed mid-wait

	res, ok := p.submitFlow(t, 8, nil)
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
	if res.Exit != 9 {
		t.Fatalf("Exit = %d, want 9 (no browser)", res.Exit)
	}
	if !strings.Contains(res.Reason, "浏览器已关闭或连接中断") {
		t.Fatalf("Reason = %q, want it to say the browser is gone or the connection dropped", res.Reason)
	}
	if strings.Contains(res.Reason, "崩溃") {
		t.Fatalf("Reason = %q, must not claim a crash it cannot see", res.Reason)
	}
	if p.clicks != 0 || p.fills != 0 {
		t.Fatalf("a gone browser still wrote to the page: clicks=%d fills=%d", p.clicks, p.fills)
	}
}

// The same wait is reached from the read-only gates: a session that slides onto
// the two-factor page between filling the credentials and clicking must wait in
// visible mode instead of stopping, and still must not submit anything.
func TestFlowVisibleModeWaitsWhenAGateSeesTheTwoFactorPage(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.onProbe = func(f *fakeLoginPage) {
		if f.probes >= 3 {
			f.twoVerifyFromStart = true // the page moves while the run is filling in
		}
	}
	p.businessAfterProbes = 6 // the human finishes on a later read

	res, ok := p.submitFlow(t, 8, nil)
	if !ok || !res.OK {
		t.Fatalf("result = %+v ok=%v, want the gate stop to become a resumed wait", res, ok)
	}
	if p.clicks != 0 {
		t.Fatalf("clicks = %d, want 0: the credentials were already filled, nothing may be submitted", p.clicks)
	}
	if p.solves != 0 {
		t.Fatalf("solves = %d, want 0: no captcha is solved on the two-factor page", p.solves)
	}
	if !hasLog(p.logs, "verdict=reached") {
		t.Fatalf("the gate path did not wait: %v", p.logs)
	}
}

// ---- production context graph: who ended the run? ----

// The production wait ctx is derived from the browser context (runContext), so a
// window that closes cancels the wait outright. A fake read failure cannot prove
// that case, so these tests use the real graph: cancel the browser, keep the
// caller alive, and the result must still be "closed or disconnected".
func TestProductionGraphClosedBrowserIsDisconnectedNotCanceled(t *testing.T) {
	caller, stopCaller := context.WithCancel(context.Background())
	defer stopCaller()
	browser, stopBrowser := context.WithCancel(context.Background())
	ctx, cancel := runContext(caller, browser, 8*time.Minute)
	defer cancel()
	stopBrowser()

	verdict, diag := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, stuckOnTwoVerify())
	if verdict != manualVerifyDisconnected {
		t.Fatalf("verdict = %s, want disconnected: a browser that goes away is not a person pressing stop", verdict)
	}
	if diag.ReadErrors != 0 {
		t.Fatalf("read errors = %d, want 0: the ctx was already gone, no read should have been attempted", diag.ReadErrors)
	}
}

func TestProductionGraphCallerCancelIsCanceledNotDisconnected(t *testing.T) {
	caller, stopCaller := context.WithCancel(context.Background())
	browser, stopBrowser := context.WithCancel(context.Background())
	defer stopBrowser()
	ctx, cancel := runContext(caller, browser, 8*time.Minute)
	defer cancel()
	stopCaller()

	if v, _ := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, stuckOnTwoVerify()); v != manualVerifyCanceled {
		t.Fatalf("verdict = %s, want canceled: an explicit stop must not be reported as a dead browser", v)
	}
}

func TestProductionGraphCallerCancelOutranksABrowserThatAlsoWentAway(t *testing.T) {
	caller, stopCaller := context.WithCancel(context.Background())
	browser, stopBrowser := context.WithCancel(context.Background())
	defer stopBrowser()
	ctx, cancel := runContext(caller, browser, 8*time.Minute)
	defer cancel()
	stopCaller()
	stopBrowser() // both ended; the person's stop is the one that explains the run

	if v, _ := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, stuckOnTwoVerify()); v != manualVerifyCanceled {
		t.Fatalf("verdict = %s, want canceled: the browser must not overwrite an explicit stop", v)
	}
}

func TestProductionGraphLateLineOutranksABrowserThatAlsoWentAway(t *testing.T) {
	caller, lateStop := context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), errLateLine)
	defer lateStop()
	browser, stopBrowser := context.WithCancel(context.Background())
	ctx, cancel := runContext(caller, browser, 8*time.Minute)
	defer cancel()
	stopBrowser()

	if v, _ := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, stuckOnTwoVerify()); v != manualVerifyStopped {
		t.Fatalf("verdict = %s, want late_line: past the late line nothing is resumed", v)
	}
}

func stuckOnTwoVerify() loginPageOps {
	clock := newFakeClock()
	return loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		probe: func(context.Context) (pageState, error) { return pageState{URL: testTwoVerifyURL}, nil },
	}
}

func TestFlowVisibleModeStopsWhenThePageLeavesTheOfficialHosts(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	p.probeFailAfter = 40 // bound: a wrongly allowed page fails fast instead of hanging
	p.onProbe = func(f *fakeLoginPage) {
		if f.probes == 3 {
			// Same hostname, but plain http: the wait must not keep waiting here.
			f.pageURL = "http://ids.gzist.edu.cn/loginAgain"
		}
	}

	res, ok := p.submitFlow(t, 8, nil)
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
	if res.Exit != 3 {
		t.Fatalf("Exit = %d, want 3", res.Exit)
	}
	if !strings.Contains(res.Reason, "不受支持") {
		t.Fatalf("Reason = %q, want it to say the page is not supported", res.Reason)
	}
	if p.clicks != 0 || p.fills != 0 || p.solves != 0 {
		t.Fatalf("wrote to an unsupported page: clicks=%d fills=%d solves=%d", p.clicks, p.fills, p.solves)
	}
	if hasLog(p.logs, "继续业务页就绪检查与签到") {
		t.Fatalf("the flow resumed from an unsupported page: %v", p.logs)
	}
}

func TestFlowVisibleModeClosedBrowserIsDisconnectedOnTheRealGraph(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	browser, stopBrowser := context.WithCancel(context.Background())
	defer stopBrowser()
	p.onProbe = func(f *fakeLoginPage) {
		if f.probes == 3 {
			stopBrowser() // the person closes the window mid-wait
		}
	}

	res, ok := p.submitFlowWithOrigins(t, 8, browser, nil)
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
	if res.Exit != 9 {
		t.Fatalf("Exit = %d, want 9 (browser gone), got reason %q", res.Exit, res.Reason)
	}
	if !strings.Contains(res.Reason, "浏览器已关闭或连接中断") {
		t.Fatalf("Reason = %q, want the closed-or-disconnected wording", res.Reason)
	}
	if strings.Contains(res.Reason, "崩溃") {
		t.Fatalf("Reason = %q, must not claim a crash", res.Reason)
	}
	if p.clicks != 0 || p.fills != 0 {
		t.Fatalf("a closed browser still wrote to the page: clicks=%d fills=%d", p.clicks, p.fills)
	}
}

func TestFlowVisibleModeCallerStopDuringTheWaitStaysACancel(t *testing.T) {
	p := newFakeLoginPage()
	p.visible = true
	p.twoVerifyFromStart = true
	browser, stopBrowser := context.WithCancel(context.Background())
	defer stopBrowser()
	var stopCaller context.CancelFunc
	p.onProbe = func(f *fakeLoginPage) {
		if f.probes == 3 {
			stopCaller() // the person presses stop; the browser is still open
		}
	}

	res, ok := p.submitFlowWithOrigins(t, 8, browser, func(_ context.Context, c context.CancelFunc) { stopCaller = c })
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
	if res.Exit != 5 {
		t.Fatalf("Exit = %d, want 5 (canceled), got reason %q", res.Exit, res.Reason)
	}
	if strings.Contains(res.Reason, "浏览器已关闭") {
		t.Fatalf("Reason = %q, an explicit stop must not be reported as a closed browser", res.Reason)
	}
	if p.clicks != 0 || p.fills != 0 {
		t.Fatalf("a canceled wait wrote to the page: clicks=%d fills=%d", p.clicks, p.fills)
	}
}

// The late line is a fact about the run, and the merged context keeps whichever
// cancel happened first. If the browser closes before the late line passes, the
// merged cause stays "canceled" — reading it would report a plain stop instead of
// the late line. The order below is the one that exposes it.
func TestLateLineWinsEvenWhenTheBrowserEndedFirst(t *testing.T) {
	caller, stopCaller := context.WithCancelCause(context.Background())
	defer stopCaller(nil)
	browser, stopBrowser := context.WithCancel(context.Background())
	ctx, cancel := runContext(caller, browser, 8*time.Minute)
	defer cancel()

	stopBrowser()           // the window goes away first: the merged cause is "canceled"
	stopCaller(errLateLine) // only afterwards does the late line pass

	if errors.Is(context.Cause(ctx), errLateLine) {
		t.Fatal("precondition: the merged ctx must have kept the browser's cause, otherwise this case proves nothing")
	}
	verdict, _ := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, stuckOnTwoVerify())
	if verdict != manualVerifyStopped {
		t.Fatalf("verdict = %s, want late_line: the caller's own reason must be read directly", verdict)
	}

	// And the run's outcome must be the late line, not a plain cancel.
	r := &Runner{Cfg: store.Settings{VisibleBrowser: true}, Log: func(string) {}}
	r.origins = runOrigins{caller: caller, browser: browser} // what Run sets per attempt
	ok := false
	res, handled := r.manualVerification(ctx, stuckOnTwoVerify(), &ok)
	if !handled || ok || res.OK {
		t.Fatalf("result = %+v ok=%v handled=%v, want a stopped run", res, ok, handled)
	}
	if res.Exit != 8 || res.Reason != errLateLine.Error() || !res.Neutral {
		t.Fatalf("result = %+v, want the late-line result (exit 8, neutral)", res)
	}
}

// A caller cancel travels to the merged context through an asynchronous
// AfterFunc, so there is a window where the caller is stopped and the merged
// context still looks alive. Inside that window the wait must not read the page
// as progress — a business page must not resume a run that was already stopped.
func TestCallerStopIsNotMissedBeforeItReachesTheWaitContext(t *testing.T) {
	caller, stopCaller := context.WithCancel(context.Background())
	browser, stopBrowser := context.WithCancel(context.Background())
	defer stopBrowser()
	// Exactly the pre-propagation state: derived from the browser only.
	ctx, cancel := context.WithCancel(browser)
	defer cancel()
	stopCaller()
	if ctx.Err() != nil {
		t.Fatal("precondition: the wait ctx must still look alive, otherwise this case proves nothing")
	}

	verdict, diag := waitForManualVerification(ctx, runOrigins{caller: caller, browser: browser}, time.Millisecond, atBusinessPage())
	if verdict != manualVerifyCanceled {
		t.Fatalf("verdict = %s, want canceled: the caller had already stopped", verdict)
	}
	if diag.Reads != 0 {
		t.Fatalf("reads = %d, want 0: the page must not be read after the caller stopped", diag.Reads)
	}

	r := &Runner{Cfg: store.Settings{VisibleBrowser: true}, Log: func(string) {}, Notify: func(string, string) {}}
	r.origins = runOrigins{caller: caller, browser: browser} // what Run sets per attempt
	ok := false
	res, handled := r.manualVerification(ctx, atBusinessPage(), &ok)
	if !handled || ok || res.OK {
		t.Fatalf("result = %+v ok=%v, want no resume", res, ok)
	}
	if res.Exit != 5 {
		t.Fatalf("Exit = %d, want 5 (canceled), gut reason %q", res.Exit, res.Reason)
	}
}

func atBusinessPage() loginPageOps {
	clock := newFakeClock()
	return loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		probe: func(context.Context) (pageState, error) { return pageState{URL: testBusinessURL}, nil },
	}
}
