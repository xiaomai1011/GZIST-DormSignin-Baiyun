package signin

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The route exactly as the school serves it. Every case below is offline: no
// browser, no network, no real login.
const testTwoVerifyURL = "https://ids.gzist.edu.cn/loginAgain"

// The two-factor route is a business fact, so it is matched exactly. A variant
// may only be accepted when it provably is the same request.
func TestTwoVerifyURLOnlyAcceptsItsOwnExactRoute(t *testing.T) {
	accept := []string{
		testTwoVerifyURL,
		"https://ids.gzist.edu.cn:443/loginAgain", // the explicit default port is the same port
		"https://IDS.GZIST.EDU.CN/loginAgain",     // a host name is not case sensitive
	}
	for _, raw := range accept {
		if !twoVerifyURL(raw) {
			t.Errorf("the school's own route was treated as foreign: %q", raw)
		}
	}

	reject := []struct{ name, raw string }{
		{"plain http", "http://ids.gzist.edu.cn/loginAgain"},
		{"no scheme", "//ids.gzist.edu.cn/loginAgain"},
		{"another port", "https://ids.gzist.edu.cn:8443/loginAgain"},
		{"userinfo", "https://user:pass@ids.gzist.edu.cn/loginAgain"},
		{"suffix host", "https://ids.gzist.edu.cn.evil.invalid/loginAgain"},
		{"prefix host", "https://evilids.gzist.edu.cn/loginAgain"},
		{"another host", "https://example.invalid/loginAgain"},
		{"lowercase path", "https://ids.gzist.edu.cn/loginagain"},
		{"trailing slash", "https://ids.gzist.edu.cn/loginAgain/"},
		{"child path", "https://ids.gzist.edu.cn/loginAgain/x"},
		{"prefixed path", "https://ids.gzist.edu.cn/xloginAgain"},
		{"query", "https://ids.gzist.edu.cn/loginAgain?service=https%3A%2F%2Fevil.invalid"},
		{"empty query", "https://ids.gzist.edu.cn/loginAgain?"},
		{"fragment", "https://ids.gzist.edu.cn/loginAgain#/x"},
		{"empty", ""},
	}
	for _, c := range reject {
		if twoVerifyURL(c.raw) {
			t.Errorf("%s was accepted as the two-factor route: %q", c.name, c.raw)
		}
	}
}

// The de-identified page category may name the route, but it must not become the
// trust check and must not leak anything about the URL.
func TestTwoFactorRouteCategoryStaysADeidentifiedLabel(t *testing.T) {
	if got := safePageCategory(testTwoVerifyURL); got != "cas-twoverify" {
		t.Fatalf("category = %q, want cas-twoverify", got)
	}
	for _, raw := range []string{
		testTwoVerifyURL + "?service=https%3A%2F%2Fevil.invalid%2Fsecret",
		"https://ids.gzist.edu.cn:8443/loginAgain",
		"https://user:pass@ids.gzist.edu.cn/loginAgain",
		"http://ids.gzist.edu.cn/loginAgain",
	} {
		got := safePageCategory(raw)
		if got == "cas-twoverify" {
			t.Errorf("a page outside the exact route was labelled as the two-factor page: %q", raw)
		}
		if strings.ContainsAny(got, "/?:#@") {
			t.Errorf("category leaks URL text: %q (from %q)", got, raw)
		}
	}
	// The existing categories keep their meaning.
	for raw, want := range map[string]string{
		testBusinessURL: "business",
		testCasFormURL:  "cas-login",
		testCasOtherURL: "cas-other",
		testUnknownURL:  "other",
		"":              "none",
	} {
		if got := safePageCategory(raw); got != want {
			t.Errorf("category(%q) = %q, want %q", raw, got, want)
		}
	}
}

// Reaching the two-factor page answers the submission: the school received the
// credentials and now wants a human. Whatever text sits on that page is not this
// submission's verdict, so it must not be read as one.
func TestClassifyLoginPageSaysActionRequiredBeforeReadingAnyText(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{{at: 0, url: testTwoVerifyURL, form: false, issue: AuthCaptcha}})

	var diag loginSubmitDiag
	verdict := classifyLoginPage(context.Background(), &ops, &diag)

	if verdict != loginSubmitActionRequired {
		t.Fatalf("verdict = %v (%s), want action_required", verdict, loginDiagLine("test", verdict, diag))
	}
	if diag.Page != "cas-twoverify" {
		t.Fatalf("diag.Page = %q, want cas-twoverify", diag.Page)
	}
	if diag.Issue != AuthNone {
		t.Fatalf("diag.Issue = %q, want none: text on this page is not evidence about the captcha", diag.Issue)
	}
	if diag.Baseline != "" {
		t.Fatalf("diag.Baseline = %q, want empty: no verdict was taken from the error region", diag.Baseline)
	}
	if got := gateActionFor(verdict); got != gateStop {
		t.Fatalf("gate = %v, want stop: no page write belongs to this state", got)
	}
	line := loginDiagLine("pre_click", verdict, diag)
	if strings.Contains(line, "loginAgain") || strings.Contains(line, "http") {
		t.Fatalf("diagnostic line leaks the URL: %q", line)
	}
}

// Seeing the two-factor page ends the observation immediately; waiting out the
// rest of the window would only delay the same answer.
func TestObserveLoginSubmitStopsAsSoonAsTheTwoFactorPageIsSeen(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ops := scriptedOps(clock, start, script{{at: 0, url: testTwoVerifyURL, form: false}})

	verdict, diag, err := observeLoginSubmit(context.Background(), loginRedirectBudget, loginRedirectPoll, ops)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != loginSubmitActionRequired {
		t.Fatalf("verdict = %v (%s), want action_required", verdict, loginDiagLine("test", verdict, diag))
	}
	if diag.Elapsed > loginRedirectBudget/2 {
		t.Fatalf("elapsed = %v, want the answer as soon as the page is visible, not the whole %v window",
			diag.Elapsed, loginRedirectBudget)
	}
}

// Cancellation still outranks the two-factor page.
func TestCancelOutranksTheTwoFactorPage(t *testing.T) {
	clock := newFakeClock()
	start := clock.now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ops := scriptedOps(clock, start, script{{at: 0, url: testTwoVerifyURL, form: false}})
	probe := ops.probe
	ops.probe = func(c context.Context) (pageState, error) {
		st, err := probe(c)
		cancel() // the read itself is where the cancel lands
		return st, err
	}

	verdict, diag, err := observeLoginSubmit(ctx, loginRedirectBudget, loginRedirectPoll, ops)
	if err == nil {
		t.Fatalf("err = nil (%s), want the cancellation to be reported", loginDiagLine("test", verdict, diag))
	}
	if verdict != loginSubmitCanceled {
		t.Fatalf("verdict = %v, want canceled", verdict)
	}
}

// A route that merely looks similar stays an untrusted page: the two-factor stop
// must not be widened into "anything under ids.gzist.edu.cn".
func TestOtherCasRoutesAreNotTreatedAsTheTwoFactorPage(t *testing.T) {
	for _, raw := range []string{
		testCasOtherURL,
		testTwoVerifyURL + "?service=x",
		"https://ids.gzist.edu.cn:8443/loginAgain",
		"http://ids.gzist.edu.cn/loginAgain",
	} {
		clock := newFakeClock()
		ops := scriptedOps(clock, clock.now(), script{{at: 0, url: raw, form: false}})
		var diag loginSubmitDiag
		if v := classifyLoginPage(context.Background(), &ops, &diag); v == loginSubmitActionRequired {
			t.Errorf("%q was treated as the two-factor route (%s)", raw, loginDiagLine("test", v, diag))
		}
	}
}

// The result tells the operator what happened and blames nothing that was not
// proven.
func TestTwoFactorResultAsksForAHumanAndBlamesNothing(t *testing.T) {
	res := loginSubmitFailure(loginSubmitActionRequired, loginSubmitDiag{Page: "cas-twoverify"})
	if res.OK {
		t.Fatalf("result = %+v, want not-ok: a pending two-factor step is not a login", res)
	}
	if res.Exit != 3 {
		t.Fatalf("Exit = %d, want 3 (needs a human)", res.Exit)
	}
	if res.AuthIssue != AuthActionRequired {
		t.Fatalf("AuthIssue = %v, want action-required", res.AuthIssue)
	}
	for _, want := range []string{"二次验证", "人工完成", "本轮停止自动提交"} {
		if !strings.Contains(res.Reason, want) {
			t.Fatalf("Reason = %q, want it to contain %q", res.Reason, want)
		}
	}
	if strings.Contains(res.Reason, "验证码") {
		t.Fatalf("Reason = %q, must not mention the captcha: nothing proved it wrong", res.Reason)
	}
}

// A whole run: the school answers with its two-factor page. One submit, no
// second image, no second submit, and the result says a human is needed.
func TestFlowTwoFactorPageAfterSubmitNeverSubmitsAgain(t *testing.T) {
	p := newFakeLoginPage()
	p.twoVerifyAfter = 2 * time.Second

	res, ok := p.submitFlow(t, 8, nil)

	if p.clicks != 1 {
		t.Fatalf("submits = %d, want exactly 1 (refreshes=%d solves=%d): the two-factor page is not a captcha verdict",
			p.clicks, p.refreshes, p.solves)
	}
	if p.refreshes != 0 {
		t.Fatalf("captcha refreshes = %d, want 0: a required two-factor step does not ask for a new image", p.refreshes)
	}
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok: nobody finished the two-factor step", res)
	}
	if res.Exit != 3 || res.AuthIssue != AuthActionRequired {
		t.Fatalf("result = %+v, want exit 3 / action-required", res)
	}
	if !strings.Contains(res.Reason, "二次验证") || strings.Contains(res.Reason, "验证码") {
		t.Fatalf("Reason = %q, want the two-factor step named and the captcha not blamed", res.Reason)
	}
	if !hasLog(p.logs, "verdict=action_required") || !hasLog(p.logs, "page=cas-twoverify") {
		t.Fatalf("logs = %v, want a diagnostic line with verdict=action_required page=cas-twoverify", p.logs)
	}
}

// A whole run that starts on the two-factor page: nothing is filled, nothing is
// submitted.
func TestFlowTwoFactorPageBeforeSubmitNeverFillsOrClicks(t *testing.T) {
	p := newFakeLoginPage()
	p.twoVerifyFromStart = true

	res, ok := p.submitFlow(t, 8, nil)

	if p.clicks != 0 || p.fills != 0 || p.solves != 0 {
		t.Fatalf("clicks=%d fills=%d solves=%d, want 0/0/0: this page is not a login form",
			p.clicks, p.fills, p.solves)
	}
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
	if res.Exit != 3 || res.AuthIssue != AuthActionRequired {
		t.Fatalf("result = %+v, want exit 3 / action-required", res)
	}
	if !hasLog(p.logs, "verdict=action_required") {
		t.Fatalf("logs = %v, want a diagnostic line with verdict=action_required", p.logs)
	}
}

// A cancel that lands inside the pre-submit read must end the run as a cancel,
// even when the page that read returned is the school's two-factor page: the
// early return is a gate like any other, so it cannot outrank the cancel.
func TestFlowCancelInsideThePreSubmitProbeBeatsTheTwoFactorReturn(t *testing.T) {
	p := newFakeLoginPage()
	p.twoVerifyFromStart = true

	res, ok := p.submitFlow(t, 8, func(_ context.Context, cancel context.CancelFunc) {
		p.onProbe = func(*fakeLoginPage) {
			p.onProbe = nil
			cancel()
		}
	})

	if res.Exit != 5 {
		t.Fatalf("Exit = %d (%+v), want 5: a cancel inside the read must end the run as a cancel", res.Exit, res)
	}
	if res.AuthIssue == AuthActionRequired {
		t.Fatalf("AuthIssue = %v, want the cancel, not the two-factor verdict", res.AuthIssue)
	}
	if p.fills != 0 || p.clicks != 0 {
		t.Fatalf("fills=%d clicks=%d, want 0/0: nothing may be written after a cancel", p.fills, p.clicks)
	}
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok", res)
	}
}
