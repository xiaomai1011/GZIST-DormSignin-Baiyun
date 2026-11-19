package signin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Session recovery probe.
//
// This answers exactly one question: does the existing account profile still
// recover the school session without a password? It is a diagnostic, not a
// sign-in: it navigates once to the fixed CAS entry, reads the page, and stops.
// It never fills credentials, clicks login, sends an SMS code, touches the
// two-factor form, or refreshes/extents cookies by hand. It also never retries:
// one navigation, one budget, one verdict.
//
// A page read is not truly passive: the page's own scripts may renew a ticket
// or update cookies while it renders. The honest name is therefore "navigation
// without form input", not "read only" — the code only refrains from acting.
const (
	// sessionProbeBudget bounds the whole probe: navigation plus reads.
	sessionProbeBudget = 45 * time.Second
	sessionProbePoll   = 1 * time.Second
	// A single read hiccup is not a closed browser; three in a row is evidence
	// that the page could not be read continuously (window closed or a lost
	// connection) — not proof of a crash.
	sessionProbeMaxReadErrors = 3
	// probeLoginGrace is how long a visible login form has to stay on screen
	// before "a person must log in" counts as observed. Shorter than this, the
	// page may still be finishing a redirect or renewing the session.
	probeLoginGrace = 5 * time.Second
)

// ProbeClass is the four-way answer the probe is allowed to give.
type ProbeClass int

const (
	// ProbeRecovered: the business page is up and shows what signing in needs.
	ProbeRecovered ProbeClass = iota
	// ProbeNeedsLogin: the trusted CAS password form is actually rendered.
	ProbeNeedsLogin
	// ProbeNeedsSecondFactor: the school's own /loginAgain page is showing.
	ProbeNeedsSecondFactor
	// ProbeUnknown: anything else, including an untrusted source or a failure.
	ProbeUnknown
)

func (c ProbeClass) String() string {
	switch c {
	case ProbeRecovered:
		return "recovered"
	case ProbeNeedsLogin:
		return "needs_login"
	case ProbeNeedsSecondFactor:
		return "needs_second_factor"
	default:
		return "unknown"
	}
}

// ProbeStop says why the probe stopped observing. The class says what it saw;
// this says whether a person, the budget, an unreadable page or a foreign host
// ended it.
type ProbeStop int

const (
	ProbeStopVerdict ProbeStop = iota
	ProbeStopCanceled
	// ProbeStopLateLine: the caller's own late-line channel stopped the run.
	ProbeStopLateLine
	ProbeStopBudget
	ProbeStopReadErrors
	// ProbeStopNavigateFailed: the single navigation itself failed.
	ProbeStopNavigateFailed
	// ProbeStopDisconnected: the browser's own lifetime ended mid-run.
	ProbeStopDisconnected
	// ProbeStopUnsupportedHost: a page outside the school hosts entirely.
	ProbeStopUnsupportedHost
	// ProbeStopUnsupportedPage: a school page that is none of the three routes
	// this probe may interpret (login, second factor, business).
	ProbeStopUnsupportedPage
)

func (s ProbeStop) String() string {
	switch s {
	case ProbeStopCanceled:
		return "canceled"
	case ProbeStopLateLine:
		return "late_line"
	case ProbeStopBudget:
		return "budget"
	case ProbeStopReadErrors:
		return "read_errors"
	case ProbeStopNavigateFailed:
		return "navigate_failed"
	case ProbeStopDisconnected:
		return "disconnected"
	case ProbeStopUnsupportedHost:
		return "unsupported_host"
	case ProbeStopUnsupportedPage:
		return "unsupported_page"
	default:
		return "verdict"
	}
}

// ProbePage is one snapshot of the controlled page. Text is only matched
// against readiness keywords and never logged.
type ProbePage struct {
	URL  string    `json:"url"`
	Text string    `json:"text"`
	Form ProbeForm `json:"form"`
}

// ProbeForm is what the page actually rendered: a password input and an account
// input that a person can see. Words in the page text are not a form — help text
// and a warming-up page mention both words happily.
type ProbeForm struct {
	Password bool `json:"password"`
	Account  bool `json:"account"`
	Visible  bool `json:"visible"`
}

// ProbeResult carries the verdict plus enough counters to audit a run. Page is
// the redacted category, never a URL.
type ProbeResult struct {
	Class      ProbeClass
	Stop       ProbeStop
	Elapsed    time.Duration
	Reads      int
	ReadErrors int
	Page       string
}

// ProbeOps are the three effects the probe needs. Tests script all of them, so
// no browser, no network and no school page is involved. Now is optional and
// exists so tests can drive the login-form grace window deterministically.
type ProbeOps struct {
	Navigate func(context.Context, string) error
	Read     func(context.Context) (ProbePage, error)
	Sleep    func(context.Context, time.Duration) error
	Now      func() time.Time
}

// SessionProbeEntry builds the single fixed entry the probe may visit: the
// school's own CAS login route with our service. Only a school business URL is
// accepted as the service, and the error stays redacted.
func SessionProbeEntry(serviceURL string) (string, error) {
	if !schoolURL(serviceURL, "xsfw.gzist.edu.cn") {
		return "", fmt.Errorf("探测入口只允许学校业务地址（https://xsfw.gzist.edu.cn），当前配置的地址不可用: %s", safePageCategory(serviceURL))
	}
	return "https://ids.gzist.edu.cn/lyuapServer/login?service=" + url.QueryEscape(serviceURL), nil
}

// trustedLoginFormShown reports a login form a person can actually see on the
// trusted CAS route: an enabled password input plus an account input, both
// rendered with a non-empty box. Keyword matching alone was not enough — a page
// that merely says "账号 / 密码" can still be loading or recovering.
func trustedLoginFormShown(p ProbePage) bool {
	return casLoginURL(p.URL) && p.Form.Password && p.Form.Account && p.Form.Visible
}

// classifyProbePage maps one snapshot to a verdict. decided=false means "not
// yet": the page is still blank or still working, so the probe keeps observing
// inside the same budget instead of calling the session dead.
func classifyProbePage(p ProbePage) (class ProbeClass, decided bool) {
	switch {
	case p.URL == "" || p.URL == "about:blank":
		return ProbeUnknown, false
	case twoVerifyURL(p.URL):
		return ProbeNeedsSecondFactor, true
	case casLoginURL(p.URL):
		// The probe navigates to this very route, and a page that has not decided
		// yet looks exactly like this. Never a verdict here: the caller keeps
		// observing, and only a form that stays on screen for the whole grace
		// window (see trustedLoginFormShown) becomes "needs_login".
		return ProbeUnknown, false
	case schoolURL(p.URL, "xsfw.gzist.edu.cn"):
		// Reaching the business host is not success by itself: the page has to
		// show what the sign-in step needs.
		if (strings.Contains(p.Text, "查寝时间段") && strings.Contains(p.Text, "点击签到")) || hitKeyword(p.Text) != "" {
			return ProbeRecovered, true
		}
		return ProbeUnknown, false
	default:
		// A source that is neither the CAS host nor the business host is not
		// something this probe is allowed to interpret.
		return ProbeUnknown, true
	}
}

// probeStopFor says why the run ended, in the order that keeps the strongest
// evidence first: the caller's own stop (a person, or the late line), then this
// round's budget, then the browser's own lifetime.
func probeStopFor(runCtx, caller, browser context.Context) (ProbeStop, bool) {
	if caller != nil && caller.Err() != nil {
		cause := context.Cause(caller)
		if errors.Is(cause, errLateLine) {
			return ProbeStopLateLine, true
		}
		if errors.Is(cause, context.DeadlineExceeded) {
			return ProbeStopBudget, true
		}
		return ProbeStopCanceled, true
	}
	if runCtx.Err() == nil {
		return ProbeStopVerdict, false
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return ProbeStopBudget, true
	}
	if browser != nil && browser.Err() != nil {
		return ProbeStopDisconnected, true
	}
	return ProbeStopCanceled, true
}

// ProbeSession runs one probe against a live page.
//
// caller carries a person's own stop (including the late-line channel); browser
// carries the launched browser's lifetime. They are kept separate on purpose: a
// merged context cannot tell "the user stopped" from "the browser went away",
// and the probe must never report a closed browser as a cancel. Either may be
// nil in a scripted test.
func ProbeSession(caller, browser context.Context, ops ProbeOps, entry string, budget time.Duration) (res ProbeResult) {
	start := time.Now()
	res = ProbeResult{Class: ProbeUnknown, Stop: ProbeStopVerdict, Page: "none"}
	// A named result is required here: a deferred write to a local copy would
	// never reach the caller.
	defer func() { res.Elapsed = time.Since(start) }()

	if browser == nil {
		browser = context.Background()
	}
	runCtx, cancel := runContext(caller, browser, budget)
	defer cancel()

	now := time.Now
	if ops.Now != nil {
		now = ops.Now
	}
	// A visible login form is not a verdict on sight: the page may still be
	// restoring the session, and it may still recover. Only a form that stays on
	// screen for the whole grace window becomes "needs_login".
	var loginSeenAt time.Time

	if ops.Navigate != nil {
		if err := ops.Navigate(runCtx, entry); err != nil {
			if stop, stopped := probeStopFor(runCtx, caller, browser); stopped {
				res.Stop = stop
			} else {
				// A page from before this navigation must not be read as this
				// round's result.
				res.Stop = ProbeStopNavigateFailed
			}
			return
		}
	}

	readErrors := 0
	for {
		if stop, stopped := probeStopFor(runCtx, caller, browser); stopped {
			res.Stop = stop
			return
		}
		page, err := ops.Read(runCtx)
		// A cancellation that landed while reading wins over whatever was read.
		if stop, stopped := probeStopFor(runCtx, caller, browser); stopped {
			res.Stop = stop
			return
		}
		if err != nil {
			// A read that never happened cannot witness a form that stayed on
			// screen: the grace window restarts from the next real snapshot.
			loginSeenAt = time.Time{}
			readErrors++
			res.ReadErrors = readErrors
			if readErrors >= sessionProbeMaxReadErrors {
				res.Stop = ProbeStopReadErrors
				return
			}
		} else {
			readErrors = 0
			res.Reads++
			res.Page = safePageCategory(page.URL)
			class, decided := classifyProbePage(page)
			res.Class = class
			if decided {
				if class == ProbeUnknown {
					if res.Page == "cas-other" {
						// A school CAS page that is none of the routes we interpret.
						res.Stop = ProbeStopUnsupportedPage
					} else {
						res.Stop = ProbeStopUnsupportedHost
					}
				}
				return
			}
			if trustedLoginFormShown(page) {
				if loginSeenAt.IsZero() {
					loginSeenAt = now()
				} else if now().Sub(loginSeenAt) >= probeLoginGrace {
					// The form survived the grace window and the page never
					// recovered: that is the evidence a person must log in.
					res.Class = ProbeNeedsLogin
					return
				}
			} else {
				loginSeenAt = time.Time{}
			}
		}
		if ops.Sleep != nil {
			if err := ops.Sleep(runCtx, sessionProbePoll); err != nil {
				if stop, stopped := probeStopFor(runCtx, caller, browser); stopped {
					res.Stop = stop
				} else {
					res.Stop = ProbeStopCanceled
				}
				return
			}
		}
	}
}

// SessionProbeDiagLine is the single audit line: fixed enumerations plus
// counters. It never contains a URL, a ticket, a cookie or page text.
func SessionProbeDiagLine(r ProbeResult) string {
	return fmt.Sprintf("会话探测: class=%s stop=%s elapsed=%.1fs reads=%d read_err=%d page=%s",
		r.Class, r.Stop, r.Elapsed.Seconds(), r.Reads, r.ReadErrors, r.Page)
}

// SessionProbeSummary is the human sentence for the same result. It says what
// was observed, never more: a login page means no password-less recovery was
// seen, not that the server-side session is provably gone.
func SessionProbeSummary(r ProbeResult) string {
	switch r.Class {
	case ProbeRecovered:
		return "会话仍有效：免密恢复到学工系统业务页（未提交任何表单，未点击登录）"
	case ProbeNeedsLogin:
		return "未能免密恢复：统一认证登录页已呈现（本次未观察到自动恢复；不能据此断言服务端会话已失效）。未提交任何表单，也不重试"
	case ProbeNeedsSecondFactor:
		return "会话被要求二次验证：停在学校的手机／密保验证页（须人工完成，程序不代做）"
	}
	switch r.Stop {
	case ProbeStopCanceled:
		return "未能确认会话状态：本轮被取消（不重试）"
	case ProbeStopLateLine:
		return "未能确认会话状态：已到晚归线，本轮停止（不重试）"
	case ProbeStopBudget:
		return "未能确认会话状态：" + fmt.Sprintf("%.0f 秒内页面没有给出可判定的结果（不重试）", r.Elapsed.Seconds())
	case ProbeStopReadErrors:
		return "未能确认会话状态：浏览器已关闭或连接中断（页面无法持续读取，不重试）"
	case ProbeStopNavigateFailed:
		return "未能确认会话状态：打开学校登录入口失败（网络或其他错误），不重试"
	case ProbeStopDisconnected:
		return "未能确认会话状态：浏览器已关闭或连接中断（本轮不重试）"
	case ProbeStopUnsupportedHost:
		return "未能确认会话状态：停在非学校页面（来源不可信，不继续）"
	case ProbeStopUnsupportedPage:
		return "未能确认会话状态：停在学校的其他页面（既不是登录页，也不是二次验证页或业务页），不继续"
	}
	return "未能确认会话状态（不重试）"
}

// probeFormScript reports what is actually rendered. The account field is the
// same selector the sign-in code fills (#userName), so a captcha box, a search
// box or any other stray input cannot stand in for it; a disabled or read-only
// field is not something a person can type into.
const probeFormScript = `(() => {
  const usable = (el) => {
    if (!el || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden' && s.opacity !== '0';
  };
  const pw = document.querySelector('#password') || document.querySelector('input[type=password]');
  const acct = document.querySelector('#userName');
  const okPw = usable(pw);
  const okAcct = usable(acct);
  return {
    url: location.href,
    text: (document.body ? document.body.innerText : '').replace(/\s+/g, ' '),
    form: {password: okPw, account: okAcct, visible: okPw && okAcct}
  };
})()`

// browserProbeOps wires the probe to the controlled page. Nothing here writes.
func browserProbeOps() ProbeOps {
	return ProbeOps{
		Navigate: func(ctx context.Context, target string) error {
			return chromedp.Navigate(target).Do(exec(ctx))
		},
		Read: func(ctx context.Context) (ProbePage, error) {
			var p ProbePage
			err := chromedp.Evaluate(probeFormScript, &p).Do(exec(ctx))
			return p, err
		},
		Sleep: func(ctx context.Context, d time.Duration) error { return sleepCtx(ctx, d) },
	}
}

// RunSessionProbe is the only exported entry: it uses the live page ops and the
// production budget. browser must be the launched session's own context
// (edge.Session.Ctx) — the page operations need the CDP target carried by it, so
// handing in a plain caller context would merely time out.
func RunSessionProbe(caller, browser context.Context, entry string) ProbeResult {
	return ProbeSession(caller, browser, browserProbeOps(), entry, sessionProbeBudget)
}
