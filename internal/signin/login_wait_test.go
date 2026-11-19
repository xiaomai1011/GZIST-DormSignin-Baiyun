package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Offline reproduction of the 2026-10-21 auto-login interruption.
//
// Nothing here touches a browser, the network or a real login: the page is a
// scripted table of (virtual elapsed time → what a read would return) and the
// clock only advances when the code under test asks to sleep, so a 30s window
// runs in microseconds and the boundary cases land on exact milliseconds.

const (
	testBusinessURL = "https://xsfw.gzist.edu.cn/xsfw/sys/swmzncqapp/*default/index.do#/xscq/grcq"
	testCasFormURL  = "https://ids.gzist.edu.cn/lyuapServer/login?service=https%3A%2F%2Fxsfw.gzist.edu.cn%2Fxsfw%2Fsys%2Fswmzncqapp%2F*default%2Findex.do"
	testCasOtherURL = "https://ids.gzist.edu.cn/lyuapServer/casLogin"
	testUnknownURL  = "https://example.invalid/notice?token=deadbeef"
)

// navigationError mimics a read taken while the document is being replaced.
var navigationError = errors.New("Execution context was destroyed")

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// sleep advances virtual time instead of blocking, and still honours the context
// so cancellation, the run budget and the late line keep working.
func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return context.Cause(ctx)
	}
	c.t = c.t.Add(d)
	return nil
}

// pageAt is what a page read returns once virtual time reaches `at`.
type pageAt struct {
	at       time.Duration
	url      string
	form     bool
	formErr  error
	issue    AuthIssue
	probeErr error
}

type script []pageAt

// at returns the state in force at elapsed d (the last entry that already began).
func (s script) at(d time.Duration) pageAt {
	cur := pageAt{url: testCasFormURL, form: true}
	for _, p := range s {
		if d >= p.at {
			cur = p
		}
	}
	return cur
}

// scriptedOps drives the code under test from a script. It deliberately has no
// click, navigate or write hook: one observation window cannot submit anything.
func scriptedOps(clock *fakeClock, start time.Time, s script) loginPageOps {
	cur := func() pageAt { return s.at(clock.now().Sub(start)) }
	return loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		probe: func(context.Context) (pageState, error) {
			p := cur()
			if p.probeErr != nil {
				return pageState{}, p.probeErr
			}
			return pageState{URL: p.url}, nil
		},
		form: func(context.Context) (bool, error) {
			p := cur()
			return p.form, p.formErr
		},
		issue: func(context.Context) AuthIssue { return cur().issue },
	}
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 21, 21, 31, 25, 0, time.UTC)}
}

// countedOps scripts a page by read count instead of by time: the first
// `unreadable` probes land during the navigation (read fails, form gone) and only
// a later read can see where the page ended up.
func countedOps(clock *fakeClock, unreadable int, finalURL string) loginPageOps {
	probes := 0
	return loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		probe: func(context.Context) (pageState, error) {
			probes++
			if probes <= unreadable {
				return pageState{}, navigationError
			}
			return pageState{URL: finalURL}, nil
		},
		form: func(context.Context) (bool, error) {
			if probes <= unreadable {
				return false, navigationError
			}
			return false, nil // the redirect replaced the document
		},
		issue: func(context.Context) AuthIssue { return AuthNone },
	}
}

// 1. The redirect took longer than the old 10s window.
//
// Measured baseline: 2026-10-10..10-20 every successful auto-login was detected
// 16-17s after its 「识别: …」 line, and 2026-10-20 recorded responseStart=15727ms.
// A 10s window therefore expires before a normal answer arrives.
func TestLoginSubmitAcceptsRedirectSlowerThanTenSeconds(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true},
		{at: 16 * time.Second, url: testBusinessURL},
	})
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitAccepted {
		t.Fatalf("verdict = %v (%s), want accepted for a 16s redirect", verdict, loginDiagLine("test", verdict, diag))
	}
	if diag.Elapsed < 16*time.Second {
		t.Fatalf("elapsed = %v, want >= 16s", diag.Elapsed)
	}
	if loginRedirectBudget <= 10*time.Second {
		t.Fatalf("loginRedirectBudget = %v, want more than the 10s window that produced the 2026-10-21 false failures", loginRedirectBudget)
	}
}

// 2. The boundary race: the redirect commits while the window is closing, every
// in-window poll lands during the navigation (unreadable, form gone), and only a
// read taken after the window can see where the page ended up. Without that last
// authoritative read the run reports 「不再可信」 for a successful login.
func TestLoginSubmitAcceptsRedirectOnBudgetBoundary(t *testing.T) {
	clock := newFakeClock()
	unreadable := int(loginRedirectBudget / loginRedirectPoll)
	ops := countedOps(clock, unreadable, testBusinessURL)
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitAccepted {
		t.Fatalf("verdict = %v (%s), want accepted when the redirect lands on the boundary",
			verdict, loginDiagLine("test", verdict, diag))
	}
	if diag.ReadErrors == 0 {
		t.Fatalf("expected the in-window reads to have failed")
	}
}

// 3. The login form is gone because the redirect landed, while reads taken during
// the navigation failed. This is the exact shape of the 2026-10-21 hypothesis:
// 21:31:37 「登录页面或表单不再可信」 may have been a business page.
func TestLoginSubmitFormGoneOnBusinessPageIsAccepted(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true},
		// The document is being replaced: the form is gone and every read fails.
		{at: 1 * time.Second, url: testCasFormURL, form: false, probeErr: navigationError, formErr: navigationError},
		// ...until the business page is readable, which is success.
		{at: 2 * time.Second, url: testBusinessURL},
	})
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitAccepted {
		t.Fatalf("verdict = %v (%s), want accepted: a missing form on the business page is not an untrusted page",
			verdict, loginDiagLine("test", verdict, diag))
	}
}

// 3b. Same shape, decided by the pre-write gate rather than by a window: the form
// is gone and the page is the business page.
func TestClassifyLoginPageFormGoneOnBusinessPageIsAccepted(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{{at: 0, url: testBusinessURL, form: false}})
	var diag loginSubmitDiag
	if verdict := classifyLoginPage(context.Background(), &ops, &diag); verdict != loginSubmitAccepted {
		t.Fatalf("verdict = %v, want accepted for %s", verdict, safePageCategory(testBusinessURL))
	}
}

// 4. The form is gone and the page is not trusted: the run must still stop.
func TestLoginSubmitFormGoneOnUntrustedPageStops(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true},
		{at: 2 * time.Second, url: testUnknownURL, form: false},
	})
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict == loginSubmitAccepted {
		t.Fatalf("verdict = accepted for an untrusted page")
	}
	if verdict != loginSubmitUntrusted {
		t.Fatalf("verdict = %v, want untrusted: %s", verdict, loginDiagLine("test", verdict, diag))
	}
	res := loginSubmitFailure(verdict, diag)
	if res.OK || res.Exit != 3 {
		t.Fatalf("result = %+v, want a non-OK exit-3 stop", res)
	}
}

// 5. Captcha error, credential rejection and a network failure are three
// different facts and must not share one sentence.
func TestLoginSubmitSeparatesCaptchaCredentialsAndNetwork(t *testing.T) {
	run := func(t *testing.T, s script) (loginSubmitVerdict, Result) {
		t.Helper()
		clock := newFakeClock()
		start := clock.now()
		ops := scriptedOps(clock, start, s)
		verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return verdict, loginSubmitFailure(verdict, diag)
	}

	captchaVerdict, captchaRes := run(t, script{
		{at: 0, url: testCasFormURL, form: true},
		{at: 1 * time.Second, url: testCasFormURL, form: true, issue: AuthCaptcha},
	})
	if captchaVerdict != loginSubmitCaptchaRejected {
		t.Fatalf("captcha verdict = %v, want captcha_rejected", captchaVerdict)
	}
	if captchaRes.AuthIssue != AuthCaptcha {
		t.Fatalf("captcha result issue = %v, want %v", captchaRes.AuthIssue, AuthCaptcha)
	}

	credVerdict, credRes := run(t, script{
		{at: 0, url: testCasFormURL, form: true},
		{at: 1 * time.Second, url: testCasFormURL, form: true, issue: AuthCredentialsRejected},
	})
	if credVerdict != loginSubmitRejected {
		t.Fatalf("credential verdict = %v, want credentials_rejected", credVerdict)
	}
	if credRes.AuthIssue != AuthCredentialsRejected {
		t.Fatalf("credential result issue = %v, want %v", credRes.AuthIssue, AuthCredentialsRejected)
	}

	netVerdict, netRes := run(t, script{
		{at: 0, url: testCasFormURL, form: true, probeErr: navigationError},
	})
	if netVerdict != loginSubmitUnread {
		t.Fatalf("network verdict = %v, want unread", netVerdict)
	}
	if netRes.AuthIssue != AuthNone {
		t.Fatalf("network result must not carry an auth issue, got %v", netRes.AuthIssue)
	}

	if captchaRes.Reason == credRes.Reason || captchaRes.Reason == netRes.Reason || credRes.Reason == netRes.Reason {
		t.Fatalf("three different causes share a reason: %q / %q / %q", captchaRes.Reason, credRes.Reason, netRes.Reason)
	}
	for _, r := range []Result{captchaRes, credRes, netRes} {
		if strings.Contains(r.Reason, "验证码可能不对") {
			t.Fatalf("reason %q still blames the captcha without evidence", r.Reason)
		}
	}
}

// 6. A read failure during navigation is not a captcha error and not a confirmed
// untrusted page.
func TestLoginSubmitReadFailureIsNeitherCaptchaNorUntrusted(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true},
		{at: 500 * time.Millisecond, url: testCasFormURL, form: false, probeErr: navigationError, formErr: navigationError},
	})
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitUnread {
		t.Fatalf("verdict = %v, want unread: %s", verdict, loginDiagLine("test", verdict, diag))
	}
	if diag.ReadErrors == 0 {
		t.Fatalf("read errors were not counted")
	}
	if diag.LastRead != "operation-failed" {
		t.Fatalf("LastRead = %q, want the de-identified category", diag.LastRead)
	}
	if diag.Issue != AuthNone {
		t.Fatalf("a read failure must not be recorded as an auth issue, got %v", diag.Issue)
	}
	res := loginSubmitFailure(verdict, diag)
	if strings.Contains(res.Reason, "验证码") {
		t.Fatalf("read failure reported as a captcha problem: %q", res.Reason)
	}
}

// 6b. Read failures inside the window must not abort the observation: the answer
// can still arrive afterwards.
func TestLoginSubmitPollsPastReadFailures(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true, probeErr: navigationError, formErr: navigationError},
		{at: 5 * time.Second, url: testBusinessURL},
	})
	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitAccepted {
		t.Fatalf("verdict = %v, want accepted after transient read failures", verdict)
	}
	if diag.ReadErrors == 0 {
		t.Fatalf("expected the transient failures to be counted")
	}
}

// 7. Cancellation and the caller's deadline still win over the window.
func TestLoginSubmitHonoursCancellationAndDeadline(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		clock := newFakeClock()
		start := clock.now()
		ops := scriptedOps(clock, start, script{{at: 0, url: testCasFormURL, form: true}})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		verdict, _, err := observeLoginSubmit(ctx, loginRedirectBudget, loginRedirectPoll, ops)
		if verdict != loginSubmitCanceled || err == nil {
			t.Fatalf("verdict = %v err = %v, want canceled with an error", verdict, err)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		clock := newFakeClock()
		start := clock.now()
		ops := scriptedOps(clock, start, script{{at: 0, url: testCasFormURL, form: true}})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		// Real sleep is needed for the real deadline to fire.
		ops.sleep = sleepCtx
		verdict, _, err := observeLoginSubmit(ctx, loginRedirectBudget, time.Millisecond, ops)
		if verdict != loginSubmitCanceled || err == nil {
			t.Fatalf("verdict = %v err = %v, want canceled when the caller's budget ends", verdict, err)
		}
	})
}

// 8. Regression: the ordinary flows keep their meaning.
func TestLoginSubmitNormalFlowsDoNotRegress(t *testing.T) {
	t.Run("fast redirect", func(t *testing.T) {
		clock := newFakeClock()
		start := clock.now()
		ops := scriptedOps(clock, start, script{
			{at: 0, url: testCasFormURL, form: true},
			{at: 1500 * time.Millisecond, url: testBusinessURL},
		})
		verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
		if err != nil || verdict != loginSubmitAccepted {
			t.Fatalf("verdict = %v err = %v, want accepted", verdict, err)
		}
		if diag.Elapsed > 3*time.Second {
			t.Fatalf("elapsed = %v, a fast redirect must not wait out the budget", diag.Elapsed)
		}
	})
	t.Run("no answer keeps the form", func(t *testing.T) {
		clock := newFakeClock()
		start := clock.now()
		ops := scriptedOps(clock, start, script{{at: 0, url: testCasFormURL, form: true}})
		verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A login page that is still there and says nothing is "no verdict yet",
		// never an untrusted page and never a captcha rejection. Gate-wise that only
		// means the page may still be written to; the flow itself stops once its own
		// submission window closes without an answer instead of buying a second
		// submit (see TestFlowStopsAfterOneSubmitWhenWindowEndsWithoutAVerdict).
		if verdict != loginSubmitPending {
			t.Fatalf("verdict = %v (%s), want pending", verdict, loginDiagLine("test", verdict, diag))
		}
		if gateActionFor(verdict) != gateProceed {
			t.Fatalf("a pending page must not block the next attempt")
		}
	})
	t.Run("credential rejection is terminal", func(t *testing.T) {
		if gateActionFor(loginSubmitRejected) != gateStop {
			t.Fatalf("a credential rejection must stay terminal")
		}
		if gateActionFor(loginSubmitUntrusted) != gateStop || gateActionFor(loginSubmitUnread) != gateStop {
			t.Fatalf("an untrusted or unreadable page must stop")
		}
	})
}

// 7b. A read that does return a verdict must not overrule a cancel that fired
// while that read was in flight. The poll returns as soon as it decides, so this
// check cannot be left to the budget-exhausted path.
func TestLoginSubmitCancelBeatsAVerdictReadInFlight(t *testing.T) {
	cases := []struct {
		name string
		at   pageAt
	}{
		{"business page", pageAt{at: 500 * time.Millisecond, url: testBusinessURL}},
		{"captcha rejection", pageAt{at: 500 * time.Millisecond, url: testCasFormURL, form: true, issue: AuthCaptcha}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clock := newFakeClock()
			start := clock.now()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := scriptedOps(clock, start, script{
				{at: 0, url: testCasFormURL, form: true},
				c.at,
			})
			read := ops.probe
			ops.probe = func(ctx context.Context) (pageState, error) {
				state, err := read(ctx)
				cancel() // the cancel lands while this read is returning its verdict
				return state, err
			}
			verdict, diag, err := observeLoginSubmit(ctx, loginRedirectBudget, loginRedirectPoll, ops)
			if verdict != loginSubmitCanceled {
				t.Fatalf("verdict = %v (%s), want canceled: the cancel outranks the verdict just read",
					verdict, loginDiagLine("test", verdict, diag))
			}
			if err == nil {
				t.Fatalf("want the cancel cause, got nil")
			}
			if diag.Elapsed >= loginRedirectBudget {
				t.Fatalf("elapsed = %v, a cancel must not wait out the window", diag.Elapsed)
			}
		})
	}
}

// 3b. The snapshot taken before a submission must be the RAW error region. The
// filtered value of a previous read is the wrong thing to store: it has already
// dropped the text it was meant to remember, so the next read sees that same old
// text as brand new evidence.
func TestLoginBaselineSnapshotTakesTheRawIssue(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	noLog := func(string) {}
	ops := scriptedOps(clock, start, script{
		{at: 0, url: testCasFormURL, form: true, issue: AuthCaptcha},
	})
	ctx := context.Background()

	// Round 1: the text was already on the page before any submit, so it is not
	// evidence — but it must be remembered as the baseline.
	first, firstDiag := pageRead(ctx, &ops, "pre_submit", noLog)
	if first != loginSubmitCaptchaRejected {
		t.Fatalf("first read = %v (%s), want the pre-existing text reported as captcha_rejected",
			first, loginDiagLine("pre_submit", first, firstDiag))
	}
	ops = ops.withSnapshot(ops.rawIssue(ctx))
	if ops.baseline != AuthCaptcha {
		t.Fatalf("baseline = %q, want the raw text %q", ops.baseline, AuthCaptcha)
	}

	// Round 2 with the very same text still on the page: nothing new happened.
	second, secondDiag := pageRead(ctx, &ops, "pre_submit", noLog)
	if second != loginSubmitPending {
		t.Fatalf("second read = %v (%s), want pending: the same old text is not new evidence",
			second, loginDiagLine("pre_submit", second, secondDiag))
	}
	if secondDiag.Issue != AuthNone {
		t.Fatalf("second diag issue = %q, want none", secondDiag.Issue)
	}
	if ops.baseline != AuthCaptcha {
		t.Fatalf("baseline was overwritten to %q by a read that saw nothing new", ops.baseline)
	}

	// The old behaviour stored the filtered value instead; that loses the text and
	// then re-reads it as this submission's rejection. Kept as a delta assertion so
	// the fix cannot silently revert to it.
	buggy := ops.withSnapshot(issueSnapshot{Issue: secondDiag.Issue, Read: true})
	if buggy.baseline != AuthNone {
		t.Fatalf("expected the filtered value to be empty, got %q", buggy.baseline)
	}
	if verdict, _ := pageRead(ctx, &buggy, "pre_submit", noLog); verdict != loginSubmitCaptchaRejected {
		t.Fatalf("verdict = %v, want the stale-filtered baseline to mis-read the old text as new", verdict)
	}

	// A page without an error reader has no text to snapshot.
	blind := loginPageOps{}
	if snap := blind.rawIssue(ctx); snap.Issue != AuthNone || !snap.Read {
		t.Fatalf("rawIssue without a reader = %+v, want none and an unread snapshot", snap)
	}
}

// Diagnostics must stay de-identified: categories only, never a URL, query,
// credential or captcha text.
func TestLoginDiagLineLeaksNothing(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{{at: 0, url: testCasFormURL, form: true, probeErr: navigationError}})
	verdict, diag, _ := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	diag.Page = safePageCategory(testCasFormURL)
	line := loginDiagLine("submit_wait", verdict, diag)
	for _, bad := range []string{"http", "service=", "lyuapServer", "ids.gzist.edu.cn", "xsfw.gzist.edu.cn", "token=", "?"} {
		if strings.Contains(line, bad) {
			t.Fatalf("diagnostic line leaks %q: %s", bad, line)
		}
	}
}

func TestSafePageCategoryKeepsOnlyCategories(t *testing.T) {
	cases := map[string]string{
		testBusinessURL:      "business",
		testCasFormURL:       "cas-login",
		testCasOtherURL:      "cas-other",
		testUnknownURL:       "other",
		"":                   "none",
		"about:blank":        "none",
		"javascript:void(0)": "none",
	}
	allowed := map[string]bool{"business": true, "cas-login": true, "cas-other": true, "other": true, "none": true}
	for in, want := range cases {
		got := safePageCategory(in)
		if got != want {
			t.Fatalf("safePageCategory(%.40q) = %q, want %q", in, got, want)
		}
		if !allowed[got] {
			t.Fatalf("safePageCategory returned an out-of-set value %q", got)
		}
	}
}

// 3c. A snapshot that could not be read is not an empty region. The text found
// afterwards may answer this click or be a leftover, and the flow cannot tell
// which, so it must say exactly that instead of blaming the captcha.
func TestLoginSubmitUnreadBaselineIsNotAnEmptyRegion(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ctx := context.Background()
	noLog := func(string) {}
	ops := scriptedOps(clock, start, script{{at: 0, url: testCasFormURL, form: true, issue: AuthCaptcha}})

	unread := ops.withSnapshot(issueSnapshot{Issue: AuthNone, Read: false})
	if unread.baselineState != baselineUnread {
		t.Fatalf("baseline state = %v, want unread", unread.baselineState)
	}
	verdict, diag := pageRead(ctx, &unread, "pre_submit", noLog)
	if verdict != loginSubmitUnattributable {
		t.Fatalf("verdict = %v (%s), want unattributable: an unread snapshot cannot attribute the text",
			verdict, loginDiagLine("pre_submit", verdict, diag))
	}
	if diag.Baseline != "unread" {
		t.Fatalf("diag baseline = %q, want unread", diag.Baseline)
	}
	res := loginSubmitFailure(verdict, diag)
	if res.Exit != 3 || res.AuthIssue != AuthNone {
		t.Fatalf("result = %+v, want a stop that does not blame the captcha", res)
	}
	if gateActionFor(verdict) != gateStop {
		t.Fatalf("gate for %v, want stop: a text of unknown origin must not buy another submit", verdict)
	}

	// The very same text under a readable snapshot is filtered out: it was
	// already on the page when the click was made.
	readable := ops.withSnapshot(issueSnapshot{Issue: AuthCaptcha, Read: true})
	if v, d := pageRead(ctx, &readable, "pre_submit", noLog); v != loginSubmitPending {
		t.Fatalf("verdict = %v (%s), want pending: a snapshot that was read names the old text",
			v, loginDiagLine("pre_submit", v, d))
	}
}
