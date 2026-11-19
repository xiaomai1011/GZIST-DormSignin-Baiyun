package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Everything below is offline: the page ops are scripted, so no browser, no
// network and no school page is involved.
const probeBudget = 60 * time.Millisecond

type scriptedProbe struct {
	pages     []ProbePage
	readErr   error
	onRead    func(n int, sp *scriptedProbe)
	navigates int
	navigated string
	reads     int
	sleeps    int
	clock     time.Time
}

func (s *scriptedProbe) ops() ProbeOps {
	return ProbeOps{
		Navigate: func(ctx context.Context, target string) error {
			s.navigates++
			s.navigated = target
			return ctx.Err()
		},
		Read: func(ctx context.Context) (ProbePage, error) {
			s.reads++
			if s.onRead != nil {
				s.onRead(s.reads, s)
			}
			if s.readErr != nil {
				return ProbePage{}, s.readErr
			}
			if len(s.pages) == 0 {
				return ProbePage{}, nil
			}
			i := s.reads - 1
			if i >= len(s.pages) {
				i = len(s.pages) - 1
			}
			return s.pages[i], nil
		},
		Now: func() time.Time { return s.clock },
		Sleep: func(ctx context.Context, d time.Duration) error {
			s.sleeps++
			s.clock = s.clock.Add(d)
			return ctx.Err()
		},
	}
}

func runScripted(t *testing.T, sp *scriptedProbe, entry string) ProbeResult {
	t.Helper()
	return runScriptedBudget(t, sp, entry, probeBudget)
}

// runScriptedBudget runs the probe with a virtual clock: every sleep advances it
// by that sleep, so the login-form grace window is deterministic without waiting.
func runScriptedBudget(t *testing.T, sp *scriptedProbe, entry string, budget time.Duration) ProbeResult {
	t.Helper()
	if sp.clock.IsZero() {
		sp.clock = time.Date(2026, 10, 24, 21, 30, 0, 0, time.UTC)
	}
	return ProbeSession(context.Background(), nil, sp.ops(), entry, budget)
}

func TestSessionProbeEntryOnlyAcceptsTheSchoolService(t *testing.T) {
	entry, err := SessionProbeEntry(testBusinessURL)
	if err != nil {
		t.Fatalf("the configured business URL must be accepted: %v", err)
	}
	if !strings.HasPrefix(entry, "https://ids.gzist.edu.cn/lyuapServer/login?service=") {
		t.Fatalf("entry = %q, want the fixed CAS login route", entry)
	}
	if !strings.Contains(entry, "xsfw.gzist.edu.cn") {
		t.Fatalf("entry lost the service: %q", entry)
	}
	for _, bad := range []string{
		"http://xsfw.gzist.edu.cn/",
		"https://xsfw.gzist.edu.cn:8443/",
		"https://student@xsfw.gzist.edu.cn/",
		"https://xsfw.gzist.edu.cn.evil.invalid/",
		"https://example.invalid/",
		"",
	} {
		entry, err := SessionProbeEntry(bad)
		if err == nil {
			t.Fatalf("service %q must be rejected, got entry %q", bad, entry)
		}
		// The rejection names the fixed allowed template and a category label, but
		// must never echo the rejected value itself.
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatalf("the rejection must not echo the rejected service: %q", err.Error())
		}
		if strings.Contains(err.Error(), "?") || strings.Contains(err.Error(), "8443") || strings.Contains(err.Error(), "evil.invalid") {
			t.Fatalf("the rejection leaks details of the rejected service: %q", err.Error())
		}
		if !strings.Contains(err.Error(), "当前配置的地址不可用") {
			t.Fatalf("the rejection should point at the configuration: %q", err.Error())
		}
	}
}

func TestProbeRecoversOnAReadyBusinessPage(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{
		{URL: "about:blank"},
		{URL: testBusinessURL, Text: "查寝时间段 21:30-23:00 点击签到"},
	}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeRecovered || res.Stop != ProbeStopVerdict {
		t.Fatalf("result = %+v, want recovered/verdict", res)
	}
	if res.Reads != 2 || res.Page != "business" {
		t.Fatalf("reads = %d page = %q, want 2 and business", res.Reads, res.Page)
	}
	if sp.navigates != 1 {
		t.Fatalf("navigates = %d, want exactly 1", sp.navigates)
	}
}

func TestProbeReachingTheBusinessHostIsNotEnough(t *testing.T) {
	// The host is right but the page never shows what signing in needs.
	sp := &scriptedProbe{pages: []ProbePage{{URL: testBusinessURL, Text: "个人查寝 加载中"}}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeUnknown {
		t.Fatalf("class = %s, want unknown: a correct host alone is not recovery", res.Class)
	}
	if res.Stop != ProbeStopBudget {
		t.Fatalf("stop = %s, want budget", res.Stop)
	}
	if res.Page != "business" {
		t.Fatalf("page = %q, want business", res.Page)
	}
	if sp.navigates != 1 {
		t.Fatalf("navigates = %d, want exactly 1 (no retry)", sp.navigates)
	}
}

func TestProbeStopsOnThePasswordPage(t *testing.T) {
	// A rendered, visible login form is the evidence. It still has to stay on
	// screen for the whole grace window before it counts as "needs_login".
	form := ProbePage{URL: testCasFormURL, Text: "统一身份认证 用户名 密码 登录", Form: ProbeForm{Password: true, Account: true, Visible: true}}
	sp := &scriptedProbe{pages: []ProbePage{form}}
	res := runScriptedBudget(t, sp, "entry", 30*time.Second)
	if res.Class != ProbeNeedsLogin || res.Stop != ProbeStopVerdict {
		t.Fatalf("result = %+v, want needs_login/verdict", res)
	}
	if res.Reads < 6 || sp.sleeps < 5 {
		t.Fatalf("reads = %d sleeps = %d, want the grace window (%v) to elapse first", res.Reads, sp.sleeps, probeLoginGrace)
	}
	if sp.navigates != 1 {
		t.Fatalf("navigates = %d, want exactly 1 (no retry)", sp.navigates)
	}
}

func TestProbeHelpTextWithAccountAndPasswordWordsIsNotAForm(t *testing.T) {
	// Words in the page text are not a form: a warming-up page and a help block
	// both mention 账号/密码. Without a rendered pair of inputs this stays undecided.
	sp := &scriptedProbe{pages: []ProbePage{{URL: testCasFormURL, Text: "统一身份认证 用户名 密码 登录 忘记密码？"}}}
	res := runScriptedBudget(t, sp, "entry", time.Second)
	if res.Class != ProbeUnknown || res.Stop != ProbeStopBudget {
		t.Fatalf("result = %+v, want unknown/budget: text alone must not claim a login form", res)
	}
	if res.Reads < 3 {
		t.Fatalf("reads = %d, want it to keep observing instead of deciding early", res.Reads)
	}
}

func TestProbeHiddenFormIsNotAVisibleLoginForm(t *testing.T) {
	// A form that exists in the DOM but is not rendered (hidden container, zero
	// box, disabled field) is exactly what a page awaiting a redirect looks like;
	// it is not evidence that a person has to type a password.
	sp := &scriptedProbe{pages: []ProbePage{{
		URL:  testCasFormURL,
		Text: "统一身份认证 账号 密码 登录",
		Form: ProbeForm{Password: true, Account: true, Visible: false},
	}}}
	res := runScriptedBudget(t, sp, "entry", time.Second)
	if res.Class != ProbeUnknown || res.Stop != ProbeStopBudget {
		t.Fatalf("result = %+v, want unknown/budget: a hidden form is not a visible one", res)
	}
}

func TestProbePasswordBoxWithoutTheAccountFieldIsNotALoginForm(t *testing.T) {
	// A password box next to a captcha box, a search box or nothing at all is not
	// the login form: the account field has to be the trusted one.
	sp := &scriptedProbe{pages: []ProbePage{{
		URL:  testCasFormURL,
		Text: "统一身份认证 密码 验证码 登录",
		Form: ProbeForm{Password: true, Account: false, Visible: true},
	}}}
	res := runScriptedBudget(t, sp, "entry", time.Second)
	if res.Class != ProbeUnknown || res.Stop != ProbeStopBudget {
		t.Fatalf("result = %+v, want unknown/budget: a stray input is not the account field", res)
	}
}

func TestProbeFormScriptUsesTheTrustedSelectorsAndRefusesDisabledFields(t *testing.T) {
	for _, want := range []string{"#userName", "#password", "el.disabled", "el.readOnly", "getBoundingClientRect", "visibility"} {
		if !strings.Contains(probeFormScript, want) {
			t.Fatalf("probe form script lost %q: %s", want, probeFormScript)
		}
	}
	// No generic "any input" fallback may stand in for the account field.
	if strings.Contains(probeFormScript, "querySelectorAll('input')") {
		t.Fatalf("the form script must not treat any input as the account field: %s", probeFormScript)
	}
}

func TestProbeReadErrorRestartsTheGraceWindow(t *testing.T) {
	// Time when the page could not be read cannot witness a form that stayed on
	// screen; the window restarts from the next real snapshot.
	form := ProbePage{URL: testCasFormURL, Text: "统一身份认证 账号 密码 登录", Form: ProbeForm{Password: true, Account: true, Visible: true}}
	sp := &scriptedProbe{pages: []ProbePage{form}}
	sp.onRead = func(n int, s *scriptedProbe) {
		switch n {
		case 2:
			s.readErr = errors.New("page detached")
		case 3:
			s.readErr = nil
		}
	}
	res := runScriptedBudget(t, sp, "entry", 30*time.Second)
	if res.Class != ProbeNeedsLogin {
		t.Fatalf("class = %s, want needs_login", res.Class)
	}
	// res.Reads counts successful snapshots only. Without the reset the window
	// would finish on the 6th successful read (5s after the first sighting); with
	// it the second sighting starts a fresh window, so one more read is needed.
	if res.Reads < 7 {
		t.Fatalf("reads = %d, want >= 7 successful snapshots: an unreadable stretch must restart the %v window", res.Reads, probeLoginGrace)
	}
}

func TestProbeFormThatRecoversWithinTheGraceIsRecovered(t *testing.T) {
	// A form can appear and the page can still finish restoring the session. The
	// form must not decide the outcome on sight.
	sp := &scriptedProbe{pages: []ProbePage{
		{URL: testCasFormURL, Text: "统一身份认证", Form: ProbeForm{Password: true, Account: true, Visible: true}},
		{URL: testBusinessURL, Text: "查寝时间段 21:30-23:00 点击签到"},
	}}
	res := runScriptedBudget(t, sp, "entry", 30*time.Second)
	if res.Class != ProbeRecovered {
		t.Fatalf("class = %s, want recovered: a form that disappears before the grace window is not a failed recovery", res.Class)
	}
	if res.Reads != 2 {
		t.Fatalf("reads = %d, want 2", res.Reads)
	}
}

func TestProbeStopsOnTheSecondFactorPage(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{{URL: testTwoVerifyURL, Text: "手机验证 获取验证码"}}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeNeedsSecondFactor || res.Stop != ProbeStopVerdict {
		t.Fatalf("result = %+v, want needs_second_factor/verdict", res)
	}
	if res.Page != "cas-twoverify" {
		t.Fatalf("page = %q, want cas-twoverify", res.Page)
	}
	if res.Reads != 1 {
		t.Fatalf("reads = %d, want 1", res.Reads)
	}
}

func TestProbeStopsOnAForeignHostWithoutRetrying(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{{URL: testUnknownURL, Text: "notice"}}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeUnknown || res.Stop != ProbeStopUnsupportedHost {
		t.Fatalf("result = %+v, want unknown/unsupported_host", res)
	}
	if res.Reads != 1 || sp.sleeps != 0 {
		t.Fatalf("reads = %d sleeps = %d, want 1 and 0", res.Reads, sp.sleeps)
	}
}

func TestProbeReportsUnreadablePageAsClosedNotCrashed(t *testing.T) {
	sp := &scriptedProbe{readErr: errors.New("boom")}
	res := runScripted(t, sp, "entry")
	if res.Stop != ProbeStopReadErrors {
		t.Fatalf("stop = %s, want read_errors", res.Stop)
	}
	if res.ReadErrors != sessionProbeMaxReadErrors || res.Reads != 0 {
		t.Fatalf("read_err = %d reads = %d, want %d and 0", res.ReadErrors, res.Reads, sessionProbeMaxReadErrors)
	}
	if !strings.Contains(SessionProbeSummary(res), "已关闭或连接中断") {
		t.Fatalf("summary = %q, want closed-or-interrupted wording (never a crash claim)", SessionProbeSummary(res))
	}
}

func TestProbeCanceledBeforeItReadsAnything(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sp := &scriptedProbe{pages: []ProbePage{{URL: testBusinessURL, Text: "查寝时间段 点击签到"}}}
	res := ProbeSession(ctx, nil, sp.ops(), "entry", probeBudget)
	if res.Stop != ProbeStopCanceled {
		t.Fatalf("stop = %s, want canceled", res.Stop)
	}
	if res.Class != ProbeUnknown {
		t.Fatalf("class = %s, want unknown (a cancel is not a verdict)", res.Class)
	}
	if res.Reads != 0 || sp.sleeps != 0 {
		t.Fatalf("reads = %d sleeps = %d, want 0 and 0", res.Reads, sp.sleeps)
	}
}

func TestProbeCancelDuringAReadBeatsTheSnapshot(t *testing.T) {
	// The page would say "recovered", but the cancel landed while it was read.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sp := &scriptedProbe{
		pages: []ProbePage{{URL: testBusinessURL, Text: "查寝时间段 点击签到"}},
		onRead: func(n int, _ *scriptedProbe) {
			if n == 1 {
				cancel()
			}
		},
	}
	res := ProbeSession(ctx, nil, sp.ops(), "entry", probeBudget)
	if res.Stop != ProbeStopCanceled {
		t.Fatalf("stop = %s, want canceled", res.Stop)
	}
	if res.Class == ProbeRecovered {
		t.Fatalf("a canceled probe must not report recovery: %+v", res)
	}
	// The read was attempted but its snapshot is not counted as observed.
	if sp.reads != 1 || res.Reads != 0 || sp.sleeps != 0 {
		t.Fatalf("attempted = %d observed = %d sleeps = %d, want 1, 0 and 0", sp.reads, res.Reads, sp.sleeps)
	}
}

func TestProbeDiagLineCarriesNoURLCredentialsOrTicket(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{{URL: testTwoVerifyURL, Text: "手机验证"}}}
	res := runScripted(t, sp, "entry")
	line := SessionProbeDiagLine(res)
	for _, banned := range []string{"http", "/", "?", "ticket", "ST-", "TGT", "CASTGC", "cookie", "service="} {
		if strings.Contains(line, banned) {
			t.Fatalf("diag line leaks %q: %q", banned, line)
		}
	}
	for _, want := range []string{"class=needs_second_factor", "stop=verdict", "reads=1", "read_err=0", "page=cas-twoverify"} {
		if !strings.Contains(line, want) {
			t.Fatalf("diag line %q is missing %q", line, want)
		}
	}
	// A page whose URL carries a token must not put it in the log either.
	tokenProbe := &scriptedProbe{pages: []ProbePage{{URL: testUnknownURL, Text: "notice"}}}
	leaky := SessionProbeDiagLine(runScripted(t, tokenProbe, "entry"))
	for _, banned := range []string{"deadbeef", "example.invalid", "token"} {
		if strings.Contains(leaky, banned) {
			t.Fatalf("diag line leaked %q from the page URL: %q", banned, leaky)
		}
	}
}

func TestProbeSummariesStayHonestPerClass(t *testing.T) {
	cases := []struct {
		res  ProbeResult
		want []string
	}{
		{ProbeResult{Class: ProbeRecovered}, []string{"会话仍有效", "免密", "未提交"}},
		{ProbeResult{Class: ProbeNeedsLogin}, []string{"未能免密恢复", "不能据此断言服务端会话已失效", "不重试"}},
		{ProbeResult{Class: ProbeNeedsSecondFactor}, []string{"二次验证", "人工"}},
		{ProbeResult{Class: ProbeUnknown, Stop: ProbeStopBudget}, []string{"未能确认", "不重试"}},
		{ProbeResult{Class: ProbeUnknown, Stop: ProbeStopUnsupportedHost}, []string{"非学校页面", "不可信"}},
	}
	for _, c := range cases {
		got := SessionProbeSummary(c.res)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Fatalf("summary for %s missing %q: %q", c.res.Class, w, got)
			}
		}
	}
}

func TestProbeNeverReportsRecoveryFromTheSecondFactorPage(t *testing.T) {
	// The two-factor page lives on the CAS host; it must not be read as success
	// nor as a plain password prompt.
	sp := &scriptedProbe{pages: []ProbePage{{URL: testTwoVerifyURL + "?x=1", Text: "查寝时间段 点击签到"}}}
	res := runScripted(t, sp, "entry")
	if res.Class == ProbeRecovered {
		t.Fatalf("a two-factor page with unrelated text must not look recovered: %+v", res)
	}
	// A query string makes it not the exact route, so it is an unrecognised school
	// page rather than a confirmed two-factor page.
	if res.Stop != ProbeStopUnsupportedPage {
		t.Fatalf("stop = %s, want unsupported_page", res.Stop)
	}
}

func TestProbeWaitsThroughTheLoginRouteUntilTheFormRenders(t *testing.T) {
	// The probe navigates to the login route on purpose, so a snapshot of that
	// route is never a verdict: not when it is empty, not when it only mentions
	// 账号/密码, and not on the first sight of a real form either.
	form := ProbePage{URL: testCasFormURL, Text: "统一身份认证 账号 密码 登录", Form: ProbeForm{Password: true, Account: true, Visible: true}}
	sp := &scriptedProbe{pages: []ProbePage{
		{URL: testCasFormURL, Text: ""},
		{URL: testCasFormURL, Text: "统一身份认证 账号 密码 帮助"},
		form,
	}}
	res := runScriptedBudget(t, sp, "entry", 30*time.Second)
	if res.Class != ProbeNeedsLogin || res.Stop != ProbeStopVerdict {
		t.Fatalf("result = %+v, want needs_login/verdict", res)
	}
	if res.Reads < 8 {
		t.Fatalf("reads = %d, want the form to be observed through the whole grace window (%v)", res.Reads, probeLoginGrace)
	}
	if sp.navigates != 1 {
		t.Fatalf("navigates = %d, want exactly 1", sp.navigates)
	}
}

func TestProbeRecoversAfterAStopOnTheLoginRoute(t *testing.T) {
	// A session that is still being restored may sit on the login route first and
	// then land on the business page. That must come out as recovery, not death.
	sp := &scriptedProbe{pages: []ProbePage{
		{URL: testCasFormURL, Text: "正在恢复会话"},
		{URL: testBusinessURL, Text: "查寝时间段 21:30-23:00 点击签到"},
	}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeRecovered {
		t.Fatalf("class = %s, want recovered: a transient login route is not a dead session", res.Class)
	}
	if res.Reads != 2 {
		t.Fatalf("reads = %d, want 2", res.Reads)
	}
}

func TestProbeLoginRouteWithoutAFormNeverClaimsTheSessionDied(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{{URL: testCasFormURL, Text: "请稍候"}}}
	res := runScripted(t, sp, "entry")
	if res.Class != ProbeUnknown || res.Stop != ProbeStopBudget {
		t.Fatalf("result = %+v, want unknown/budget", res)
	}
	summary := SessionProbeSummary(res)
	if !strings.Contains(summary, "未能确认") {
		t.Fatalf("summary must stay undecided: %q", summary)
	}
	if strings.Contains(summary, "会话已失效") {
		t.Fatalf("summary must not claim the session is dead: %q", summary)
	}
}

func TestProbeNavigateFailureStopsBeforeAnyRead(t *testing.T) {
	sp := &scriptedProbe{pages: []ProbePage{{URL: testBusinessURL, Text: "查寝时间段 点击签到"}}}
	ops := sp.ops()
	ops.Navigate = func(context.Context, string) error { return errors.New("net down") }
	res := ProbeSession(context.Background(), nil, ops, "entry", probeBudget)
	if res.Stop != ProbeStopNavigateFailed {
		t.Fatalf("stop = %s, want navigate_failed", res.Stop)
	}
	if res.Reads != 0 || res.Class != ProbeUnknown {
		t.Fatalf("reads = %d class = %s, want 0 and unknown (never read a page from before the navigation)", res.Reads, res.Class)
	}
	if !strings.Contains(SessionProbeSummary(res), "打开学校登录入口失败") {
		t.Fatalf("summary = %q", SessionProbeSummary(res))
	}
}

func TestProbeReportsItsElapsedTime(t *testing.T) {
	// A non-named result would silently report 0 here: the deferred write would
	// only touch a local copy.
	// The read itself takes real time, so a zero elapsed can only mean the field
	// never reached the caller (a non-named result keeps zero here).
	ops := ProbeOps{
		Navigate: func(context.Context, string) error { return nil },
		Read: func(context.Context) (ProbePage, error) {
			time.Sleep(40 * time.Millisecond)
			return ProbePage{URL: testBusinessURL, Text: "查寝时间段 点击签到"}, nil
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	res := ProbeSession(context.Background(), nil, ops, "entry", 2*time.Second)
	if res.Class != ProbeRecovered {
		t.Fatalf("class = %s, want recovered", res.Class)
	}
	if res.Elapsed < 35*time.Millisecond {
		t.Fatalf("elapsed = %v, want at least the 40ms the read actually took", res.Elapsed)
	}
	if !strings.Contains(SessionProbeDiagLine(res), "elapsed=") {
		t.Fatalf("diag line lost the elapsed field: %q", SessionProbeDiagLine(res))
	}

	slow := ProbeOps{
		Navigate: func(context.Context, string) error { return nil },
		Read: func(context.Context) (ProbePage, error) {
			return ProbePage{URL: "about:blank"}, nil
		},
		Sleep: func(context.Context, time.Duration) error {
			time.Sleep(60 * time.Millisecond)
			return nil
		},
	}
	// about:blank never decides, so the run ends on the budget; the elapsed time
	// must include the real waiting, not just the last read.
	budgeted := ProbeSession(context.Background(), nil, slow, "entry", 150*time.Millisecond)
	if budgeted.Stop != ProbeStopBudget {
		t.Fatalf("stop = %s, want budget", budgeted.Stop)
	}
	if budgeted.Elapsed < 100*time.Millisecond {
		t.Fatalf("elapsed = %v, want at least 100ms of real waiting", budgeted.Elapsed)
	}
}

func TestProbeStopClassificationKeepsTheSourcesApart(t *testing.T) {
	pages := func() *scriptedProbe {
		return &scriptedProbe{pages: []ProbePage{{URL: "about:blank"}}}
	}

	t.Run("caller canceled", func(t *testing.T) {
		caller, cancel := context.WithCancel(context.Background())
		cancel()
		res := ProbeSession(caller, nil, pages().ops(), "entry", probeBudget)
		if res.Stop != ProbeStopCanceled {
			t.Fatalf("stop = %s, want canceled", res.Stop)
		}
	})

	t.Run("late line outranks anything else", func(t *testing.T) {
		caller, cancel := context.WithCancelCause(context.Background())
		cancel(errLateLine)
		browser, browserCancel := context.WithCancel(context.Background())
		defer browserCancel()
		res := ProbeSession(caller, browser, pages().ops(), "entry", probeBudget)
		if res.Stop != ProbeStopLateLine {
			t.Fatalf("stop = %s, want late_line", res.Stop)
		}
		if !strings.Contains(SessionProbeSummary(res), "晚归线") {
			t.Fatalf("summary = %q, want the late-line wording", SessionProbeSummary(res))
		}
	})

	t.Run("browser gone is not a cancel", func(t *testing.T) {
		browser, browserCancel := context.WithCancel(context.Background())
		browserCancel()
		res := ProbeSession(context.Background(), browser, pages().ops(), "entry", probeBudget)
		if res.Stop != ProbeStopDisconnected {
			t.Fatalf("stop = %s, want disconnected", res.Stop)
		}
		if res.Stop == ProbeStopCanceled {
			t.Fatalf("a closed browser must never be reported as a user cancel")
		}
	})

	t.Run("budget", func(t *testing.T) {
		res := ProbeSession(context.Background(), nil, pages().ops(), "entry", probeBudget)
		if res.Stop != ProbeStopBudget {
			t.Fatalf("stop = %s, want budget", res.Stop)
		}
	})
}
