package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Flow-level tests for autoLoginWith: the page is a fake that counts the submits
// it receives, so "the flow did not submit again" is a measured click count, not
// a claim about a reader. No browser, no network, no real login, and the clock
// only advances when the code under test sleeps, so a 30s observation window
// costs microseconds and boundaries land on exact milliseconds.

// fakeLoginPage is the page autoLoginWith talks to. Every click it receives is
// counted and stamped, which is what lets a test say "exactly one submission".
type fakeLoginPage struct {
	clock *fakeClock
	start time.Time

	// page shape
	initialIssue       AuthIssue     // error region already on the page before any submit
	rejectAfter        time.Duration // >0: this text appears rejectAfter after a click
	rejectIssue        AuthIssue     // what that text says (AuthCaptcha when empty)
	landAfter          time.Duration // >0: business page reached landAfter after a click
	clearOnRefresh     bool          // fetching a new image re-renders the form: old text gone
	terminalOnPreClick AuthIssue     // != AuthNone: the terminal read before the click says so
	snapshotUnread     bool          // the pre-submit snapshot read fails (not the same as an empty region)
	onTerminal         func(p *fakeLoginPage)
	landOnCancel       bool          // a probe landing after a click reports the business page
	business           bool          // set by a test's onProbe hook
	twoVerifyFromStart bool          // the session was already moved to the two-factor page
	twoVerifyAfter     time.Duration // >0: that page is reached twoVerifyAfter after a click

	// visible-mode shape
	businessAfterProbes int    // >0: a human finished the wait and the business page is read on probe N
	probeFailAfter      int    // >0: reads fail from probe N+1 on (page unreadable)
	visible             bool   // the run was started in visible-browser mode
	pageURL             string // != "": the page stays on this URL (a redirect we must not wait on)

	// measurements
	clicks    int
	refreshes int
	fills     int
	solves    int
	probes    int
	clickAt   time.Time
	logs      []string
	// remember box (the school's own 「记住密码」 option)
	rememberPassword     bool            // the setting asks the run to tick it
	rememberResult       rememberOutcome // what the fake box reports
	rememberCalls        int
	rememberBeforeSubmit bool // was the box handled before the first submit?
	rememberBeforeFill   bool // was the box handled before any field was filled?
	onRemember           func(p *fakeLoginPage)

	// login-page viewport (the widen that makes 「记住密码」 render)
	widenCalls      int
	restoreCalls    int
	widenErr        error
	restoreErr      error
	widenBeforeFill bool // was the viewport changed before any field was filled?
	originalWidth   int  // what the fake page reports as its starting width
	onWiden         func(p *fakeLoginPage)

	onProbe func(p *fakeLoginPage)
}

func newFakeLoginPage() *fakeLoginPage {
	clock := newFakeClock()
	return &fakeLoginPage{clock: clock, start: clock.now()}
}

func (p *fakeLoginPage) url() string {
	if p.pageURL != "" {
		return p.pageURL
	}
	if p.businessAfterProbes > 0 && p.probes >= p.businessAfterProbes {
		return testBusinessURL
	}
	if p.twoVerifyFromStart {
		return testTwoVerifyURL
	}
	if p.twoVerifyAfter > 0 && !p.clickAt.IsZero() && p.clock.now().Sub(p.clickAt) >= p.twoVerifyAfter {
		return testTwoVerifyURL
	}
	if p.business || (p.landAfter > 0 && !p.clickAt.IsZero() && p.clock.now().Sub(p.clickAt) >= p.landAfter) {
		return testBusinessURL
	}
	return testCasFormURL
}

// issueNow is the page's own error region right now. A rejection only exists once
// the click it answers has had time to come back; before that the region holds
// whatever was already there (initialIssue), which is exactly the text the flow
// has to learn to ignore.
func (p *fakeLoginPage) issueNow() AuthIssue {
	if p.rejectAfter > 0 && !p.clickAt.IsZero() && p.clock.now().Sub(p.clickAt) >= p.rejectAfter {
		if p.rejectIssue != AuthNone {
			return p.rejectIssue
		}
		return AuthCaptcha
	}
	return p.initialIssue
}

func (p *fakeLoginPage) probe(context.Context) (pageState, error) {
	p.probes++
	if p.onProbe != nil {
		p.onProbe(p)
	}
	if p.probeFailAfter > 0 && p.probes > p.probeFailAfter {
		return pageState{}, errors.New("context canceled")
	}
	return pageState{URL: p.url()}, nil
}

func (p *fakeLoginPage) formVisible(context.Context) (bool, error) {
	u := p.url()
	return u != testBusinessURL && u != testTwoVerifyURL, nil
}

func (p *fakeLoginPage) click(context.Context) {
	p.clicks++
	p.clickAt = p.clock.now()
}

func (p *fakeLoginPage) refresh(context.Context) {
	p.refreshes++
	if p.clearOnRefresh {
		// A refreshed image comes with a re-rendered form: the previous answer's
		// text is gone, so the next submission starts from a clean region.
		p.clickAt = time.Time{}
	}
}

// driver is the injected page surface, satisfying the same loginDriver contract
// the browser driver satisfies.
func (p *fakeLoginPage) driver() loginDriver {
	return loginDriver{
		ops: loginPageOps{
			now:   p.clock.now,
			sleep: p.clock.sleep,
			probe: p.probe,
			form:  p.formVisible,
			issue: func(context.Context) AuthIssue { return p.issueNow() },
			// snapshot reports whether the read worked, exactly like the browser reader: a
			// failed read yields no text AND says so, instead of passing for an empty region.
			snapshot: func(context.Context) (AuthIssue, bool) {
				if p.snapshotUnread {
					return AuthNone, false
				}
				return p.issueNow(), true
			},
		},
		fill: func(context.Context, string, string) bool {
			p.fills++
			return true
		},
		extract: func(context.Context) string { return "data:image/png;base64,ZmFrZQ==" },
		solve: func(string) captcha.Result {
			p.solves++
			return captcha.Result{OK: true, Expr: "1+3", Ans: "1234", MinScore: 0.90, MinMargin: 0.60}
		},
		refresh: p.refresh,
		click:   p.click,
		remember: func(context.Context) rememberOutcome {
			p.rememberCalls++
			p.rememberBeforeSubmit = p.clicks == 0
			p.rememberBeforeFill = p.fills == 0
			if p.onRemember != nil {
				p.onRemember(p)
			}
			return p.rememberResult
		},
		terminal: func(context.Context) AuthIssue {
			if p.onTerminal != nil {
				p.onTerminal(p)
			}
			return p.terminalOnPreClick
		},
		widen: func(context.Context) (widened, error) {
			p.widenCalls++
			p.widenBeforeFill = p.fills == 0
			if p.onWiden != nil {
				p.onWiden(p)
			}
			if p.widenErr != nil {
				return widened{}, p.widenErr
			}
			width := p.originalWidth
			if width <= 0 {
				width = 430
			}
			return widened{Original: viewport{Width: width, Height: 900, DPR: 1}, Applied: true}, nil
		},
		restore: func(context.Context, widened) error {
			p.restoreCalls++
			return p.restoreErr
		},
	}
}

func (p *fakeLoginPage) runner(capMax int) *Runner {
	d := p.driver()
	return &Runner{
		Cfg:    store.Settings{CapMaxTry: capMax, ConfThr: 0.55, VisibleBrowser: p.visible, RememberPassword: p.rememberPassword},
		Log:    func(s string) { p.logs = append(p.logs, s) },
		Creds:  func() (string, string, error) { return "20260001", "not-a-real-password", nil },
		driver: &d,
	}
}

// submitFlow runs one whole auto-login. prep may hook the page before the flow
// starts (for example to cancel the context from inside a read).
func (p *fakeLoginPage) submitFlow(t *testing.T, capMax int, prep func(ctx context.Context, cancel context.CancelFunc)) (Result, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if prep != nil {
		prep(ctx, cancel)
	}
	ok := false
	return p.runner(capMax).autoLogin(ctx, &ok), ok
}

// submitFlowWithOrigins runs one auto-login on the production context graph: the
// wait's ctx comes from runContext(caller, browser), exactly like Runner.Run, and
// the caller stays separate so a test can end either participant.
func (p *fakeLoginPage) submitFlowWithOrigins(t *testing.T, capMax int, browser context.Context, prep func(ctx context.Context, stopCaller context.CancelFunc)) (Result, bool) {
	t.Helper()
	caller, stopCaller := context.WithCancel(context.Background())
	defer stopCaller()
	ctx, cancel := runContext(caller, browser, 3*time.Minute)
	defer cancel()
	r := p.runner(capMax)
	r.origins = runOrigins{caller: caller, browser: browser}
	if prep != nil {
		prep(ctx, stopCaller)
	}
	ok := false
	return r.autoLogin(ctx, &ok), ok
}

func hasLog(logs []string, want string) bool {
	for _, l := range logs {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}

// 1. A whole submission window passes and the page never says anything about the
// submission. Exactly one submit may have happened, and the result must be
// "unknown", never "验证码错误".
func TestFlowStopsAfterOneSubmitWhenWindowEndsWithoutAVerdict(t *testing.T) {
	p := newFakeLoginPage()
	res, ok := p.submitFlow(t, 8, nil)

	if p.clicks != 1 {
		t.Fatalf("submits = %d, want exactly 1 (refreshes=%d solves=%d fills=%d): an unanswered window must not buy another submission",
			p.clicks, p.refreshes, p.solves, p.fills)
	}
	if p.refreshes != 0 {
		t.Fatalf("captcha refreshes = %d, want 0: no conclusion is not a reason to fetch a new image", p.refreshes)
	}
	if ok || res.OK {
		t.Fatalf("result = %+v, want not-ok: nothing confirmed the login", res)
	}
	if res.AuthIssue == AuthCaptcha {
		t.Fatalf("Result.AuthIssue = %v, want no auth issue: the captcha was never blamed", res.AuthIssue)
	}
	if res.Exit != 3 {
		t.Fatalf("Exit = %d, want 3 (needs a human)", res.Exit)
	}
	if !strings.Contains(res.Reason, "未取得可信结论") || !strings.Contains(res.Reason, "结果未知") {
		t.Fatalf("Reason = %q, want it to say the outcome is unknown", res.Reason)
	}
	if strings.Contains(res.Reason, "验证码错误") {
		t.Fatalf("Reason = %q, must not report a captcha error that was never observed", res.Reason)
	}
	if !hasLog(p.logs, "停止自动提交") {
		t.Fatalf("no stop line in the log: %v", p.logs)
	}
	if hasLog(p.logs, "换一张再试") {
		t.Fatalf("the flow announced a captcha retry for an unanswered window: %v", p.logs)
	}
}

// 2. Cancellation wins over whatever the read it interrupted had to say.
func TestFlowCancellationWinsOverTheVerdictOfAnInFlightRead(t *testing.T) {
	t.Run("success read then cancel", func(t *testing.T) {
		p := newFakeLoginPage()
		var cancel context.CancelFunc
		res, ok := p.submitFlow(t, 8, func(ctx context.Context, c context.CancelFunc) {
			cancel = c
			p.onProbe = func(f *fakeLoginPage) {
				if f.clicks == 0 {
					return
				}
				f.business = true // the read that is about to return sees the redirect land
				cancel()
			}
		})

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1", p.clicks)
		}
		if res.Exit != 5 {
			t.Fatalf("Exit = %d, want 5 (stopped): a success read must not overwrite the cancel (%+v)", res.Exit, res)
		}
		if res.OK || ok {
			t.Fatalf("result = %+v ok = %v, want not-ok: the run was stopped before the verdict", res, ok)
		}
		if res.AuthIssue != AuthNone {
			t.Fatalf("AuthIssue = %v, want none", res.AuthIssue)
		}
		if strings.Contains(res.Reason, "登录成功") {
			t.Fatalf("Reason = %q, must not claim success after a cancel", res.Reason)
		}
	})

	t.Run("captcha rejection read then cancel", func(t *testing.T) {
		p := newFakeLoginPage()
		var cancel context.CancelFunc
		res, _ := p.submitFlow(t, 8, func(ctx context.Context, c context.CancelFunc) {
			cancel = c
			p.onProbe = func(f *fakeLoginPage) {
				if f.clicks == 0 {
					return
				}
				f.initialIssue = AuthCaptcha // this read is about to report 验证码错误
				cancel()
			}
		})

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1", p.clicks)
		}
		if p.refreshes != 0 {
			t.Fatalf("refreshes = %d, want 0: a cancellation must not be turned into a retry", p.refreshes)
		}
		if res.Exit != 5 {
			t.Fatalf("Exit = %d, want 5 (stopped), got %+v", res.Exit, res)
		}
		if res.AuthIssue == AuthCaptcha {
			t.Fatalf("AuthIssue = captcha, want none: the cancel outranks the rejection read")
		}
		if !strings.Contains(res.Reason, "已停止") {
			t.Fatalf("Reason = %q, want the stop reason", res.Reason)
		}
	})
}

// 3. A 验证码错误 that was already on the page before the first submit stays old
// evidence for every round: it must not trigger a retry and must not be read as
// the answer to this submission.
func TestFlowNeverReadsAStaleCaptchaTextAsThisSubmissionsAnswer(t *testing.T) {
	p := newFakeLoginPage()
	p.initialIssue = AuthCaptcha // left over from an earlier attempt/session
	res, _ := p.submitFlow(t, 8, nil)

	if p.clicks != 1 {
		t.Fatalf("submits = %d, want exactly 1: the stale text is not evidence about this submission", p.clicks)
	}
	if p.refreshes != 0 {
		t.Fatalf("refreshes = %d, want 0", p.refreshes)
	}
	if res.AuthIssue == AuthCaptcha {
		t.Fatalf("AuthIssue = captcha, want none: the old text was counted as this submission's rejection")
	}
	if strings.Contains(res.Reason, "验证码错误") {
		t.Fatalf("Reason = %q, must not report the stale text as this submission's answer", res.Reason)
	}
	if !strings.Contains(res.Reason, "结果未知") {
		t.Fatalf("Reason = %q, want the unknown-outcome wording", res.Reason)
	}
	// The window's own diagnostic line must record that nothing new appeared.
	if !hasLog(p.logs, "stage=submit_wait verdict=pending") {
		t.Fatalf("no pending observation line: %v", p.logs)
	}
	if !hasLog(p.logs, "issue=none") {
		t.Fatalf("the observation line did not record that no new issue appeared: %v", p.logs)
	}
	if hasLog(p.logs, "换一张再试") {
		t.Fatalf("the stale text produced a retry announcement: %v", p.logs)
	}
}

// 3b. The snapshot must stay the raw text between rounds. After a submission that
// really was rejected, the same old text is still on the page when the next
// submission is prepared: it is not evidence about that submission, so the flow
// stops instead of treating round 2 as another caption rejection. Storing the
// filtered read instead would erase the text and buy capMax submits.
func TestFlowKeepsTheRawSnapshotAcrossRounds(t *testing.T) {
	p := newFakeLoginPage()
	p.rejectAfter = time.Second // round 1 does get a real rejection
	// no clearOnRefresh: the refreshed image keeps the old text on the page
	res, _ := p.submitFlow(t, 4, nil)

	if p.clicks != 2 {
		t.Fatalf("submits = %d, want 2 (one rejected submit, then a stop): the old text must not be read as round 2's rejection (refreshes=%d)",
			p.clicks, p.refreshes)
	}
	if p.refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1: exactly one new image is fetched for the one real rejection", p.refreshes)
	}
	if res.AuthIssue == AuthCaptcha {
		t.Fatalf("AuthIssue = captcha, want none: the stale text was counted as a new rejection")
	}
	if !strings.Contains(res.Reason, "结果未知") {
		t.Fatalf("Reason = %q, want the unknown-outcome wording", res.Reason)
	}
}

// 4. A rejection that really is about this submission does allow another image —
// bounded by capMax and by ctx.
func TestFlowRetriesOnlyOnANewCaptchaRejectionWithinCap(t *testing.T) {
	t.Run("bounded by capMax", func(t *testing.T) {
		p := newFakeLoginPage()
		p.rejectAfter = time.Second // each submit gets its own 验证码错误
		p.clearOnRefresh = true     // a new image clears the previous answer's text
		res, ok := p.submitFlow(t, 3, nil)

		if p.clicks != 3 {
			t.Fatalf("submits = %d, want 3 (= capMax): a new rejection may retry, but the cap holds (refreshes=%d)", p.clicks, p.refreshes)
		}
		if p.refreshes != 2 {
			t.Fatalf("refreshes = %d, want 2: only the two still-allowed retries may fetch a new image", p.refreshes)
		}
		if ok || res.OK {
			t.Fatalf("result = %+v, want not-ok after the cap is exhausted", res)
		}
		if res.AuthIssue != AuthCaptcha {
			t.Fatalf("AuthIssue = %v, want captcha: the page did reject the captcha every time", res.AuthIssue)
		}
		if res.Exit != 3 {
			t.Fatalf("Exit = %d, want 3", res.Exit)
		}
	})

	t.Run("cancellation bounds the retries", func(t *testing.T) {
		p := newFakeLoginPage()
		p.rejectAfter = time.Second
		p.clearOnRefresh = true
		var cancel context.CancelFunc
		res, _ := p.submitFlow(t, 8, func(ctx context.Context, c context.CancelFunc) {
			cancel = c
			p.onProbe = func(f *fakeLoginPage) {
				if f.clicks == 2 {
					cancel() // stops while the second submission is being observed
				}
			}
		})

		if p.clicks != 2 {
			t.Fatalf("submits = %d, want 2: the cancel must stop the third submit", p.clicks)
		}
		if res.Exit != 5 {
			t.Fatalf("Exit = %d, want 5 (stopped), got %+v", res.Exit, res)
		}
		if res.AuthIssue == AuthCaptcha {
			t.Fatalf("AuthIssue = captcha, want none: the cancel outranks the pending rejection")
		}
	})
}

// 5. Regression: the ordinary paths keep their meaning under the new rules.
func TestFlowNormalPathsStillHold(t *testing.T) {
	t.Run("redirect inside the window", func(t *testing.T) {
		p := newFakeLoginPage()
		p.landAfter = 2 * time.Second
		res, ok := p.submitFlow(t, 8, nil)

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1", p.clicks)
		}
		// Success travels the way it always has: *loginOK is set and the returned
		// Result carries no failure exit, which is what Run turns into 「登录成功」.
		if !ok {
			t.Fatalf("loginOK = false, want true after the redirect landed: %+v", res)
		}
		if res.Exit != 0 {
			t.Fatalf("Exit = %d, want 0: %+v", res.Exit, res)
		}
		if p.refreshes != 0 {
			t.Fatalf("refreshes = %d, want 0", p.refreshes)
		}
	})

	t.Run("redirect that lands as the window closes", func(t *testing.T) {
		p := newFakeLoginPage()
		p.landAfter = loginRedirectBudget
		res, ok := p.submitFlow(t, 8, nil)

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1", p.clicks)
		}
		if !ok {
			t.Fatalf("loginOK = false, want true: a redirect that commits as the window closes is still a login (%+v)", res)
		}
		if res.Exit != 0 {
			t.Fatalf("Exit = %d, want 0: %+v", res.Exit, res)
		}
	})

	t.Run("no second submit after an unanswered window", func(t *testing.T) {
		p := newFakeLoginPage()
		res, ok := p.submitFlow(t, 8, nil)

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1 even with capMax=8", p.clicks)
		}
		if ok || res.OK {
			t.Fatalf("result = %+v, want not-ok", res)
		}
		if p.solves != 1 {
			t.Fatalf("captcha solves = %d, want 1: no extra image was read", p.solves)
		}
	})

	t.Run("credential rejection is terminal", func(t *testing.T) {
		p := newFakeLoginPage()
		p.rejectAfter = 500 * time.Millisecond
		p.rejectIssue = AuthCredentialsRejected
		res, _ := p.submitFlow(t, 8, nil)

		if p.clicks != 1 {
			t.Fatalf("submits = %d, want 1", p.clicks)
		}
		if p.refreshes != 0 {
			t.Fatalf("refreshes = %d, want 0: a credential rejection never buys another captcha", p.refreshes)
		}
		if res.AuthIssue != AuthCredentialsRejected {
			t.Fatalf("AuthIssue = %v, want credentials_rejected", res.AuthIssue)
		}
	})

	t.Run("locked account never reaches a submit", func(t *testing.T) {
		p := newFakeLoginPage()
		p.terminalOnPreClick = AuthLocked
		res, _ := p.submitFlow(t, 8, nil)

		if p.clicks != 0 {
			t.Fatalf("submits = %d, want 0: a locked account is terminal before any click", p.clicks)
		}
		if res.AuthIssue != AuthLocked {
			t.Fatalf("AuthIssue = %v, want locked", res.AuthIssue)
		}
	})
}

// 2c. A cancel that arrives while a read is in flight wins before any write. The
// read itself reports the business page - a success - yet a run that is already
// stopping must type no credentials, recognise nothing and submit nothing.
func TestFlowCancelDuringAFormReadStopsBeforeAnyWrite(t *testing.T) {
	p := newFakeLoginPage()
	res, ok := p.submitFlow(t, 8, func(ctx context.Context, c context.CancelFunc) {
		p.onProbe = func(f *fakeLoginPage) {
			f.business = true // the read that is about to return sees a business page
			c()
		}
	})

	if p.clicks != 0 {
		t.Fatalf("submits = %d, want 0: a stopped run must not click login", p.clicks)
	}
	if p.fills != 0 {
		t.Fatalf("page writes = %d, want 0: a stopped run must not type anything", p.fills)
	}
	if p.solves != 0 || p.refreshes != 0 {
		t.Fatalf("solves = %d refreshes = %d, want 0: there is nothing to recognise", p.solves, p.refreshes)
	}
	if res.Exit != 5 {
		t.Fatalf("Exit = %d, want 5 (stopped): the cancel must win over a success read (%+v)", res.Exit, res)
	}
	if res.OK || ok {
		t.Fatalf("result = %+v ok = %v, want not-ok: the run was stopped before the verdict", res, ok)
	}
	if strings.Contains(res.Reason, "登录成功") {
		t.Fatalf("Reason = %q, must not claim success after a cancel", res.Reason)
	}
}

// 3d. The snapshot taken before a submission can fail. A failed snapshot is not
// 「没有旧提示」: when a text is on the page afterwards the flow cannot tell it
// from a leftover, so it must never submit a second time on the strength of it.
func TestFlowFailedSnapshotNeverBuysASecondSubmit(t *testing.T) {
	p := newFakeLoginPage()
	p.initialIssue = AuthCaptcha // a 常驻 old prompt: present on every read, caused by nothing
	p.snapshotUnread = true
	res, ok := p.submitFlow(t, 8, nil)

	if p.clicks != 1 {
		t.Fatalf("submits = %d, want 1: an unreadable snapshot must not turn the old text into a retry (refreshes=%d)", p.clicks, p.refreshes)
	}
	if p.refreshes != 0 {
		t.Fatalf("refreshes = %d, want 0: nothing new was learned about the captcha", p.refreshes)
	}
	if res.Exit != 3 {
		t.Fatalf("Exit = %d, want 3 (stopped without a trustworthy result): %+v", res.Exit, res)
	}
	if res.AuthIssue != AuthNone {
		t.Fatalf("AuthIssue = %v, want none: the leftover text is not this submission's answer", res.AuthIssue)
	}
	if res.OK || ok {
		t.Fatalf("result = %+v ok = %v, want not-ok", res, ok)
	}
	if !hasLog(p.logs, "verdict=unattributable") {
		t.Fatalf("the run must say it could not attribute the text: %v", p.logs)
	}
}

// 2d. A terminal read that a cancel interrupted must not hand back its verdict.
// The read says 锁定 (or 凭据被拒), yet the run is already stopping: it stops as
// canceled, with no click at all.
func TestFlowCancelDuringATerminalReadStopsBeforeTheVerdict(t *testing.T) {
	p := newFakeLoginPage()
	p.terminalOnPreClick = AuthLocked
	var cancel context.CancelFunc
	res, ok := p.submitFlow(t, 8, func(ctx context.Context, c context.CancelFunc) {
		cancel = c
		p.onTerminal = func(f *fakeLoginPage) {
			if f.clicks == 0 {
				cancel() // the cancel arrives while the terminal read is in flight
			}
		}
	})

	if p.clicks != 0 {
		t.Fatalf("submits = %d, want 0: a stopping run must not click login", p.clicks)
	}
	if res.Exit != 5 {
		t.Fatalf("Exit = %d, want 5 (stopped): the cancel outranks the locked verdict (%+v)", res.Exit, res)
	}
	if res.AuthIssue != AuthNone {
		t.Fatalf("AuthIssue = %v, want none: a verdict read during a cancel is not a result", res.AuthIssue)
	}
	if res.OK || ok {
		t.Fatalf("result = %+v ok = %v, want not-ok", res, ok)
	}
	if !strings.Contains(res.Reason, "已停止") {
		t.Fatalf("Reason = %q, want the stop reason", res.Reason)
	}
}
