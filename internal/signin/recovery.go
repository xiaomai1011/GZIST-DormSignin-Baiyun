package signin

import (
	"context"
	"errors"
	"github.com/chromedp/chromedp"
	"net/url"
	"time"
)

func (r *Runner) recoverStep6(ctx context.Context, deadline time.Time, last pageState, elapsed time.Duration, waitErr error) (pageState, time.Duration, error) {
	return recoverBusinessPage(ctx, deadline, r.Cfg.URL, r.Cfg.AutoLogin, last, elapsed, waitErr, recoveryOps{
		now: time.Now, probe: probePage,
		evidence: func(c context.Context) {
			r.reportDeadPage(c)
			if c.Err() != nil {
				return
			}
			shotCtx, stopShot := context.WithTimeout(c, 3*time.Second)
			defer stopShot()
			r.saveShot(shotCtx, "step6-timeout")
		},
		navigate: func(c context.Context, target string) error {
			r.log("  步骤6: 保留会话恢复一次，稳定入口: " + safePageURL(target))
			return chromedp.Navigate(target).Do(exec(c))
		},
		form: formReady,
		login: func(c context.Context) Result {
			rr := *r
			rr.Cfg.CapMaxTry = 1
			ok := false
			res := rr.autoLogin(c, &ok)
			if ok {
				return Result{OK: true}
			}
			return res
		},
		wait: func(c context.Context, b time.Duration, p func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
			return waitBusinessPage(c, b, 500*time.Millisecond, p, repairPageRoute)
		},
	})
}

// No browser creation or business-click callback is available to recovery.
type recoveryOps struct {
	now      func() time.Time
	probe    func(context.Context) (pageState, error)
	evidence func(context.Context)
	navigate func(context.Context, string) error
	form     func(context.Context) (bool, error)
	login    func(context.Context) Result
	wait     func(context.Context, time.Duration, func(context.Context) (pageState, error)) (pageState, time.Duration, error)
}

func schoolURL(raw, host string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() == host && u.User == nil && (u.Port() == "" || u.Port() == "443")
}
func casLoginURL(raw string) bool {
	if !schoolURL(raw, "ids.gzist.edu.cn") {
		return false
	}
	u, _ := url.Parse(raw)
	return u.Path == "/lyuapServer/login" || u.Path == "/authserver/login"
}
func stableRecoveryURL(raw string) bool {
	if !schoolURL(raw, "xsfw.gzist.edu.cn") {
		return false
	}
	u, _ := url.Parse(raw)
	return (u.Path == "/xsfw/sys/swmzncqapp/*default/index.do" || u.Path == "/index.do") && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "/xscq/grcq"
}

// Recheck in the same JS evaluation as credential mutation, not a stale probe.
// casPageTrustJS is the single definition of "this document is the trusted CAS
// login page": protocol, exact host, default port and the two known login
// paths. Everything that may act on, or read from, the login page includes it,
// so the rule cannot drift between call sites.
const casPageTrustJS = `(location.protocol==='https:'&&location.hostname==='ids.gzist.edu.cn'&&(location.port===''||location.port==='443')&&(location.pathname==='/lyuapServer/login'||location.pathname==='/authserver/login'))`

// casPageGuardJS is the integer-returning form of casPageTrustJS: 0 means "not
// the trusted login page".
const casPageGuardJS = `if(!` + casPageTrustJS + `) return 0;
`

// Called only once for the first step-6 result. Navigation, login and the second
// wait share 120s, still bounded by the caller's overall/late-line deadline.
func recoverBusinessPage(ctx context.Context, deadline time.Time, target string, autoLogin bool, last pageState, elapsed time.Duration, waitErr error, ops recoveryOps) (pageState, time.Duration, error) {
	if ctx.Err() != nil {
		return last, elapsed, context.Cause(ctx)
	}
	if !ops.now().Before(deadline) {
		return last, elapsed, errLateLine
	}
	if waitErr == nil {
		return last, elapsed, nil
	}
	if schoolURL(last.URL, "xsfw.gzist.edu.cn") && hitKeyword(last.Text) != "" {
		return last, elapsed, nil
	}
	// Capture the original page before any recovery navigation.
	evidenceCtx, stopEvidence := context.WithTimeout(ctx, 11*time.Second)
	ops.evidence(evidenceCtx)
	stopEvidence()
	if ctx.Err() != nil {
		return last, elapsed, context.Cause(ctx)
	}
	if !ops.now().Before(deadline) {
		return last, elapsed, errLateLine
	}
	if !errors.Is(waitErr, context.DeadlineExceeded) || elapsed < pageWaitBudget || !stableRecoveryURL(target) || !(schoolURL(last.URL, "xsfw.gzist.edu.cn") || casLoginURL(last.URL)) {
		return last, elapsed, waitErr
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, 3*time.Second)
	fresh, probeErr := ops.probe(probeCtx)
	stopProbe()
	if ctx.Err() != nil {
		return last, elapsed, context.Cause(ctx)
	}
	if !ops.now().Before(deadline) {
		return last, elapsed, errLateLine
	}
	if probeErr != nil || !(schoolURL(fresh.URL, "xsfw.gzist.edu.cn") || casLoginURL(fresh.URL)) {
		return last, elapsed, waitErr
	}
	if ready, _ := pageWaitPolicy(fresh, 0, true); ready {
		return fresh, elapsed, nil
	}
	retryCtx, stopRetry := context.WithTimeout(ctx, pageWaitBudget)
	defer stopRetry()
	started := time.Now()
	if err := ops.navigate(retryCtx, target); err != nil {
		if ctx.Err() != nil {
			return fresh, elapsed + time.Since(started), context.Cause(ctx)
		}
		return fresh, elapsed + time.Since(started), errors.New("恢复导航失败，停止本轮")
	}
	loginCalled := false
	var terminal error
	retryProbe := func(c context.Context) (pageState, error) {
		if c.Err() != nil {
			return pageState{}, context.Cause(c)
		}
		if !ops.now().Before(deadline) {
			terminal = errLateLine
			stopRetry()
			return pageState{}, terminal
		}
		s, err := ops.probe(c)
		if err != nil {
			return s, err
		}
		if c.Err() != nil {
			return s, context.Cause(c)
		}
		if schoolURL(s.URL, "xsfw.gzist.edu.cn") {
			return s, nil
		}
		if !casLoginURL(s.URL) {
			terminal = errors.New("恢复跳转到非允许页面，停止本轮")
		} else if !loginCalled {
			visible, formErr := ops.form(c)
			if formErr != nil || !visible {
				return pageState{URL: s.URL}, formErr
			}
			if c.Err() != nil {
				return s, context.Cause(c)
			}
			if !ops.now().Before(deadline) {
				terminal = errLateLine
			} else if !autoLogin {
				terminal = errors.New("恢复需要人工登录，停止本轮")
			} else {
				loginCalled = true
				if result := ops.login(c); !result.OK {
					terminal = errors.New("恢复重新登录失败，停止本轮；请人工检查账号或验证码")
					if result.AuthIssue != AuthNone {
						terminal = &authIssueError{issue: result.AuthIssue}
					}
				}
			}
		}
		if terminal != nil {
			stopRetry()
			return s, terminal
		}
		return pageState{URL: s.URL}, nil
	}
	final, _, err := ops.wait(retryCtx, pageWaitBudget, retryProbe)
	total := elapsed + time.Since(started)
	if ctx.Err() != nil {
		return final, total, context.Cause(ctx)
	}
	if !ops.now().Before(deadline) {
		return final, total, errLateLine
	}
	if terminal != nil {
		return final, total, terminal
	}
	return final, total, err
}
