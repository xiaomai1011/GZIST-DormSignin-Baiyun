package signin

import (
	"context"
	"fmt"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
)

// The CAS submit is a POST to the authentication server; the answer only becomes
// observable when the redirect to the business host commits. Measured evidence
// for the budget below:
//   - 2026-10-10..10-20, every successful auto-login was detected 16-17s after
//     its own 「识别: …」 line (dormsign.log: 10/10 21:30:38→21:30:54,
//     10/18 21:30:30→21:30:47, 10/20 21:30:40→21:30:56, …), i.e. longer than the
//     10s window the loop used to declare 「提交后未跳转」.
//   - the 2026-10-20 autopsy (20261020-213257-step6-timeout.json) recorded
//     responseStart=15727ms for a navigation on the same site.
//
// So 10s was shorter than the observed round trip and a timeout cannot be read
// as evidence about the captcha. This constant bounds how long ONE submission is
// observed; it does not change the submission count (CapMaxTry), the per-run
// budget (8min) or the late-line deadline, which all still apply unchanged.
const (
	loginRedirectBudget  = 30 * time.Second
	loginRedirectPoll    = 500 * time.Millisecond
	loginFinalReadBudget = 3 * time.Second
)

// loginSubmitVerdict is what one submission observation actually established.
// The values are kept apart on purpose: "no answer yet", "the page said the
// captcha was wrong", "the page said the credentials were rejected", "the page
// is gone", "the read failed" and "this is not a page we trust" are different
// facts and must not be collapsed into one "验证码可能不对" sentence.
type loginSubmitVerdict int

const (
	loginSubmitAccepted        loginSubmitVerdict = iota // trusted business page reached
	loginSubmitPending                                   // still the trusted login form, no verdict yet
	loginSubmitCaptchaRejected                           // the login page's own element said 验证码错误
	loginSubmitRejected                                  // the login page's own element said 密码错误/锁定
	loginSubmitCasFormGone                               // trusted login page, credentials form gone
	loginSubmitUntrusted                                 // neither the trusted login page nor the business page
	loginSubmitUnread                                    // the page could not be read (navigation/CDP/read error)
	loginSubmitCanceled                                  // canceled / late line / overall budget
	loginSubmitUnattributable                            // an error text is there, but the pre-submit snapshot could not be read
	loginSubmitActionRequired                            // the school's own two-factor page: a human must finish it
)

func (v loginSubmitVerdict) String() string {
	switch v {
	case loginSubmitAccepted:
		return "accepted"
	case loginSubmitPending:
		return "pending"
	case loginSubmitCaptchaRejected:
		return "captcha_rejected"
	case loginSubmitRejected:
		return "credentials_rejected"
	case loginSubmitCasFormGone:
		return "cas_form_gone"
	case loginSubmitUntrusted:
		return "untrusted"
	case loginSubmitUnread:
		return "unread"
	case loginSubmitCanceled:
		return "canceled"
	case loginSubmitUnattributable:
		return "unattributable"
	case loginSubmitActionRequired:
		return "action_required"
	}
	return "unknown"
}

// loginSubmitDiag is the de-identified evidence of one observation: fixed enums,
// bounded numbers and a page category. It never carries a URL, query, credential,
// cookie, captcha answer, business code or page text.
type loginSubmitDiag struct {
	Elapsed    time.Duration
	Probes     int
	ReadErrors int
	LastRead   string // safeDiagnosticError of the last failed read
	Page       string // safePageCategory
	Form       string // visible / missing / unknown
	Issue      AuthIssue
	// Baseline says whether the pre-submit snapshot of the error region was
	// actually read: "read", "unread" (the read failed) or "none" (no snapshot
	// was taken yet). A failed snapshot must never be reported as 「no old text」.
	Baseline string
}

// loginPageOps are the read-only page readers, injected so the decision logic
// can be exercised without a browser (see waitBusinessPage and recoveryOps for
// the same pattern).
type loginPageOps struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	probe func(context.Context) (pageState, error)
	form  func(context.Context) (bool, error)
	issue func(context.Context) AuthIssue
	// snapshot reads the same error region but also reports whether that read
	// succeeded. It is what a submission is compared against, and "the read
	// failed" is a different fact from "the region was empty": only the second
	// one means a later text belongs to this click. Nil falls back to issue with
	// the read reported as successful.
	snapshot func(context.Context) (AuthIssue, bool)
	// baseline is the error element that was already on the page before the
	// current submission. CAS re-renders the error region on the same DOM, so a
	// text seen before the click must not be re-read as the answer to it.
	baseline      AuthIssue
	baselineState baselineState
}

// baselineState is whether the pre-submit snapshot of the error region is known.
// Three states on purpose: "no snapshot taken yet" must stay different from
// "the snapshot was attempted and failed", otherwise a failed read would quietly
// become "there was no old text" and the next stale rejection would be read as
// the answer to a click that never produced it.
type baselineState int

const (
	baselineNone   baselineState = iota // no submission yet: read the region as it is
	baselineRead                        // snapshot taken and readable
	baselineUnread                      // snapshot attempted, the read failed
)

func (s baselineState) String() string {
	switch s {
	case baselineRead:
		return "read"
	case baselineUnread:
		return "unread"
	}
	return "none"
}

// issueSnapshot is the error region plus whether reading it worked.
type issueSnapshot struct {
	Issue AuthIssue
	Read  bool
}

func (o loginPageOps) withSnapshot(s issueSnapshot) loginPageOps {
	o.baseline = s.Issue
	if s.Read {
		o.baselineState = baselineRead
	} else {
		o.baselineState = baselineUnread
	}
	return o
}

// freshIssue reads the login page's own error region and reports whether the
// text it found can be attributed to the current submission. A text that was
// already there is dropped; a text read after a snapshot that failed cannot be
// attributed at all, so it is reported as such instead of being taken as new
// evidence.
func (o *loginPageOps) freshIssue(ctx context.Context) (AuthIssue, bool) {
	if o.issue == nil {
		return AuthNone, true
	}
	issue := o.issue(ctx)
	if issue == AuthNone {
		return AuthNone, true
	}
	switch o.baselineState {
	case baselineUnread:
		return issue, false
	case baselineRead:
		if issue == o.baseline {
			return AuthNone, true
		}
	}
	return issue, true
}

func browserLoginPageOps() loginPageOps {
	return loginPageOps{
		now:      time.Now,
		sleep:    sleepCtx,
		probe:    probePage,
		form:     formReady,
		issue:    loginDOMIssue,
		snapshot: loginDOMIssueRead,
	}
}

// rawIssue is the login page's own error region exactly as it is now, before the
// baseline filter, together with whether that read succeeded. Taking this
// snapshot before a submission is what lets the next observation tell 「the same
// old text is still on the page」 from 「a new text appeared because of this
// click」. Filtering first and storing the filtered value would blind the flow to
// the text it had already filtered out, which is exactly how a stale 验证码错误
// could be re-read as the answer to the next click; storing a failed read as an
// empty region would do the same damage from the other side.
func (o *loginPageOps) rawIssue(ctx context.Context) issueSnapshot {
	if o.snapshot != nil {
		issue, ok := o.snapshot(ctx)
		return issueSnapshot{Issue: issue, Read: ok}
	}
	if o.issue == nil {
		return issueSnapshot{Read: true}
	}
	return issueSnapshot{Issue: o.issue(ctx), Read: true}
}

// rememberOutcome is what the school's own 「记住密码」 checkbox (form field
// rememberMe) did during this submission. It is a report, not a promise: the
// program only ever ticks the checkbox a human could tick.
type rememberOutcome int

const (
	rememberNotRequested rememberOutcome = iota // the setting is off
	rememberAlreadyOn                           // the box was already ticked
	rememberChecked                             // this run ticked it
	rememberAbsent                              // this login page has no such checkbox
	rememberWriteFailed                         // present and unticked, but the tick did not take
)

func (o rememberOutcome) String() string {
	switch o {
	case rememberAlreadyOn:
		return "already_on"
	case rememberChecked:
		return "checked"
	case rememberAbsent:
		return "absent"
	case rememberWriteFailed:
		return "write_failed"
	default:
		return "not_requested"
	}
}

// rememberLine is the single log line one submission writes about the checkbox.
// It never claims the server will honour it.
func rememberLine(o rememberOutcome) string {
	switch o {
	case rememberChecked:
		return "  已勾选「记住密码」（学校页面上的官方选项，是否生效由服务端决定）"
	case rememberAlreadyOn:
		return "  「记住密码」已处于勾选状态，未重复点击"
	case rememberAbsent:
		// "absent" is what the script measured: no operable option it could find.
		// It is not evidence that the school omitted the field (the page renders it
		// only when the server sets locale.isRememberPass to "1"), and it is not
		// evidence about the value the page submits either — the script changed
		// nothing, so whatever the page's own state was is what gets sent.
		return "  本页未找到可操作的「记住密码」选项（可能是服务端未下发该字段，也可能控件未被识别）；程序未改动它，提交值取决于页面自身状态"
	case rememberWriteFailed:
		return "  勾选「记住密码」未生效（不改用其他方式）；程序未改动页面状态"
	default:
		return "  「记住密码」未启用（设置项关闭）"
	}
}

// loginDriver is every page interaction one auto-login performs: the read-only
// readers above plus the two fills, the captcha refresh and the login click. It
// exists so the submit loop can run against a scripted page offline — the click
// counter in those tests is then a real measurement of how many times the flow
// submitted, not a claim about it.
type loginDriver struct {
	ops           loginPageOps
	fillChecked   func(context.Context, string, string) error
	submitChecked func(context.Context) error
	fill          func(context.Context, string, string) bool
	extract       func(context.Context) string
	solve         func(string) captcha.Result
	refresh       func(context.Context)
	click         func(context.Context)
	terminal      func(context.Context) AuthIssue
	// remember ticks the official checkbox when the caller asked for it. A nil
	// hook means this driver cannot tick it, which is reported as absent; the
	// submission itself never depends on the outcome.
	remember func(context.Context) rememberOutcome
	// widen switches the page to a desktop-width viewport so the school's
	// responsive layout renders the checkbox; restore puts the captured metrics
	// back. A nil hook means this driver has no viewport to change.
	widen   func(context.Context) (widened, error)
	restore func(context.Context, widened) error
}

// browserLoginDriver is the production surface: the real CAS page.
func browserLoginDriver(solve func(string) captcha.Result) loginDriver {
	return loginDriver{
		ops:           browserLoginPageOps(),
		fill:          setReactValue,
		extract:       extractLoginCaptcha,
		solve:         solve,
		refresh:       refreshLoginCaptcha,
		fillChecked:   setReactValueChecked,
		submitChecked: clickLoginButton,
		terminal:      terminalDOMAuth,
		remember:      checkRememberMe,
		widen:         widenBrowserForRememberMe,
		restore:       restoreBrowserViewport,
	}
}

// withDefaults fills in the clock and the sleep a scripted page may omit; the
// production driver always supplies both.
func (d loginDriver) withDefaults() loginDriver {
	if d.ops.now == nil {
		d.ops.now = time.Now
	}
	if d.ops.sleep == nil {
		d.ops.sleep = sleepCtx
	}
	return d
}

// stopIfCanceled is the single cancellation gate used after every page read and
// before every page write. A cancel, the 8-minute run budget or the late line are
// all carried by ctx, so this adds no mechanism: it only refuses to let a success
// or a rejection overwrite a stop that already happened.
func stopIfCanceled(ctx context.Context) (Result, bool) {
	if ctx.Err() != nil {
		return canceledResult(ctx), true
	}
	return Result{}, false
}

// observeLoginSubmit watches ONE submission until the budget closes. It never
// submits, refreshes or navigates: it only reads. Cancellation, the overall run
// budget and the late line are all still carried by ctx.
func observeLoginSubmit(ctx context.Context, budget, poll time.Duration, ops loginPageOps) (loginSubmitVerdict, loginSubmitDiag, error) {
	var diag loginSubmitDiag
	if ops.now == nil {
		ops.now = time.Now
	}
	sleep := ops.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	start := ops.now()
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for ops.now().Sub(start) < budget {
		if err := sleep(waitCtx, poll); err != nil {
			if ctx.Err() != nil {
				return loginSubmitCanceled, diag, context.Cause(ctx)
			}
			break // the budget closed; classify below
		}
		verdict, decided := observeLoginPoll(waitCtx, &ops, &diag)
		// A read that returned "business page" or "验证码错误" must not overrule a
		// cancel, the run budget or the late line that fired while it was in
		// flight: the poll returns as soon as it decides, so this check cannot be
		// left to the budget-exhausted path below.
		if ctx.Err() != nil {
			diag.Elapsed = ops.now().Sub(start)
			return loginSubmitCanceled, diag, context.Cause(ctx)
		}
		if decided {
			diag.Elapsed = ops.now().Sub(start)
			return verdict, diag, nil
		}
	}
	// Running out of budget is not evidence about the captcha: one authoritative
	// read decides, so a redirect that commits at the boundary still counts.
	finalCtx, stop := context.WithTimeout(ctx, loginFinalReadBudget)
	verdict := classifyLoginPage(finalCtx, &ops, &diag)
	stop()
	diag.Elapsed = ops.now().Sub(start)
	if ctx.Err() != nil {
		return loginSubmitCanceled, diag, context.Cause(ctx)
	}
	return verdict, diag, nil
}

// observeLoginPoll is one in-flight read. Only two facts decide early: the
// trusted business page (success) and the login page's own explicit rejection.
// A read error is transient during navigation, so it is counted and polled past
// instead of ending the observation.
func observeLoginPoll(ctx context.Context, ops *loginPageOps, diag *loginSubmitDiag) (loginSubmitVerdict, bool) {
	state, err := ops.probe(ctx)
	if err != nil {
		diag.ReadErrors++
		diag.LastRead = safeDiagnosticError(err)
		return loginSubmitPending, false
	}
	diag.Probes++
	diag.Page = safePageCategory(state.URL)
	if schoolURL(state.URL, "xsfw.gzist.edu.cn") {
		return loginSubmitAccepted, true
	}
	if twoVerifyURL(state.URL) {
		// The school's own two-factor route. The submission reached the server and
		// the account now waits for a human; this is not evidence about the
		// captcha, and waiting out the rest of the window would only delay the
		// same answer.
		diag.Form = "unknown"
		return loginSubmitActionRequired, true
	}
	if issue, attributable := ops.freshIssue(ctx); issue != AuthNone {
		diag.Issue = issue
		diag.Baseline = ops.baselineState.String()
		if !attributable {
			// The text is there, but the snapshot taken before this click could
			// not be read, so there is no way to say whether it is the answer to
			// this submission or a text that was already sitting on the page.
			return loginSubmitUnattributable, true
		}
		return verdictForIssue(issue), true
	}
	return loginSubmitPending, false
}

// classifyLoginPage is the authoritative single read used at the end of a
// window and before every page write. The URL is read first: a form that is gone
// is only "untrusted" if the page is not the trusted business page, so a
// redirect that landed during the window is reported as success instead of as a
// missing/invisible form. A read failure stays its own outcome.
func classifyLoginPage(ctx context.Context, ops *loginPageOps, diag *loginSubmitDiag) loginSubmitVerdict {
	state, err := ops.probe(ctx)
	if err != nil {
		diag.ReadErrors++
		diag.LastRead = safeDiagnosticError(err)
		diag.Form = "unknown"
		return loginSubmitUnread
	}
	diag.Probes++
	diag.Page = safePageCategory(state.URL)
	if schoolURL(state.URL, "xsfw.gzist.edu.cn") {
		return loginSubmitAccepted
	}
	if twoVerifyURL(state.URL) {
		// Checked before reading any error text: whatever sits on this page is the
		// school's own pending two-factor step, not this submission's verdict.
		diag.Form = "unknown"
		return loginSubmitActionRequired
	}
	if issue, attributable := ops.freshIssue(ctx); issue != AuthNone {
		diag.Issue = issue
		diag.Baseline = ops.baselineState.String()
		if !attributable {
			return loginSubmitUnattributable
		}
		return verdictForIssue(issue)
	}
	if !casLoginURL(state.URL) {
		diag.Form = "unknown"
		return loginSubmitUntrusted
	}
	visible, err := ops.form(ctx)
	switch {
	case err != nil:
		diag.ReadErrors++
		diag.LastRead = safeDiagnosticError(err)
		diag.Form = "unknown"
		return loginSubmitUnread
	case visible:
		diag.Form = "visible"
		return loginSubmitPending
	default:
		diag.Form = "missing"
		return loginSubmitCasFormGone
	}
}

func verdictForIssue(issue AuthIssue) loginSubmitVerdict {
	switch issue {
	case AuthCaptcha:
		return loginSubmitCaptchaRejected
	case AuthCredentialsRejected, AuthLocked:
		return loginSubmitRejected
	}
	return loginSubmitPending
}

// gateAction is what a page read taken before a page write allows.
type gateAction int

const (
	gateProceed gateAction = iota // still the trusted login form
	gateLanded                    // the redirect already landed: success
	gateStop                      // stop, with the verdict's own reason
)

// gateActionFor decides whether a page may still be written to.
//
// A trusted login page whose own error region already said 验证码错误 is exactly
// the state a new submission starts from, so it proceeds and that text is
// remembered as the page's baseline instead of being read as the answer to the
// next click. A credential rejection or a locked account stays terminal, as it
// always was.
func gateActionFor(verdict loginSubmitVerdict) gateAction {
	switch verdict {
	case loginSubmitPending, loginSubmitCaptchaRejected:
		return gateProceed
	case loginSubmitAccepted:
		return gateLanded
	case loginSubmitActionRequired:
		// A human must finish the school's two-factor step: no page write belongs
		// to this run, whether the page was reached before or after a submit.
		return gateStop
	}
	return gateStop
}

// pageRead is the single authoritative read taken before a page write and at the
// top of every attempt. Only non-pending verdicts are logged, one line each.
func pageRead(ctx context.Context, ops *loginPageOps, stage string, log func(string)) (loginSubmitVerdict, loginSubmitDiag) {
	var diag loginSubmitDiag
	verdict := classifyLoginPage(ctx, ops, &diag)
	if verdict != loginSubmitPending {
		log(loginDiagLine(stage, verdict, diag))
	}
	return verdict, diag
}

// loginSubmitFailure turns a verdict into the result the run stops with. Only the
// credential/captcha families carry an AuthIssue; a read failure, an untrusted
// page and "no answer at all" say so instead of blaming the captcha.
func loginSubmitFailure(verdict loginSubmitVerdict, diag loginSubmitDiag) Result {
	switch verdict {
	case loginSubmitRejected:
		return authResult(diag.Issue)
	case loginSubmitCaptchaRejected:
		return authResult(AuthCaptcha)
	case loginSubmitPending:
		return loginSubmitUnknown(diag)
	case loginSubmitUnread:
		return Result{Reason: "提交后无法读取页面状态，未确认登录结果；本轮不重复提交，请人工确认后再试", Exit: 3}
	case loginSubmitCasFormGone:
		return Result{Reason: "登录页仍在，但账号或密码输入框已消失，未取得可信结果，停止自动登录", Exit: 3}
	case loginSubmitUntrusted:
		return Result{Reason: "登录后页面既不是可信登录页也不是学工系统，停止自动登录", Exit: 3}
	case loginSubmitCanceled:
		return Result{Reason: "自动登录已停止: 已取消或已到晚归线", Exit: 5}
	case loginSubmitActionRequired:
		res := authResult(AuthActionRequired)
		res.Reason = "学校要求二次验证（手机／密保），请人工完成；本轮停止自动提交"
		return res
	case loginSubmitUnattributable:
		return Result{Reason: "登录页上有错误提示，但提交前的旧提示未能读到，无法判断它是否属于本次提交；本轮不重复提交，请人工确认登录结果", Exit: 3}
	}
	return Result{Reason: "自动登录未取得可信结果，停止自动登录", Exit: 3}
}

// loginSubmitUnknown is the result for "the window closed and the login page said
// nothing about this submission". It is deliberately not a captcha verdict: the
// outcome is unknown, so the run stops and says so instead of re-submitting.
func loginSubmitUnknown(diag loginSubmitDiag) Result {
	return Result{
		Reason: fmt.Sprintf("提交后 %.0fs 内未取得可信结论（仍是登录页、页面未给出任何结论），结果未知 —— 停止自动提交，不再换验证码重试，请人工确认登录结果", diag.Elapsed.Seconds()),
		Exit:   3,
	}
}

// loginDiagLine renders the fixed-enum evidence line for one stage. Callers must
// not add free text: no URL, path, query, credential, cookie, captcha answer,
// business code or page content may appear here.
func loginDiagLine(stage string, verdict loginSubmitVerdict, diag loginSubmitDiag) string {
	read := diag.LastRead
	if read == "" {
		read = "ok"
	}
	page := diag.Page
	if page == "" {
		page = "none"
	}
	form := diag.Form
	if form == "" {
		form = "unknown"
	}
	issue := "none"
	if diag.Issue != AuthNone {
		issue = string(diag.Issue)
	}
	baseline := diag.Baseline
	if baseline == "" {
		baseline = "none"
	}
	return fmt.Sprintf("  登录诊断: stage=%s verdict=%s elapsed=%.1fs probe=%d read=%s page=%s form=%s issue=%s baseline=%s",
		stage, verdict, diag.Elapsed.Seconds(), diag.Probes, read, page, form, issue, baseline)
}
