package signin

import (
	"context"
	"fmt"
	"time"
)

type loginReadyVerdict string

const (
	loginReadyForm       loginReadyVerdict = "form_ready"
	loginReadyMissing    loginReadyVerdict = "form_missing"
	loginReadyReadFailed loginReadyVerdict = "read_failed"
	loginReadyUntrusted  loginReadyVerdict = "untrusted"
	loginReadyTwoVerify  loginReadyVerdict = "twoverify"
	loginReadyBusiness   loginReadyVerdict = "business"
	loginReadyCanceled   loginReadyVerdict = "canceled"
)

type loginReadyDiag struct{ Probes, Forms, ReadErrors int }

// waitLoginReady only observes: no reload, credential submission or window show.
// The injected clock controls polling; each individual read also has a real CDP
// deadline. A reader returning a late true never overrides either deadline.
func waitLoginReady(ctx context.Context, ops loginPageOps, budget, stableFor time.Duration) (loginReadyVerdict, loginReadyDiag) {
	var diag loginReadyDiag
	now := ops.now
	if now == nil {
		now = time.Now
	}
	sleep := ops.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	end := now().Add(budget)
	var since time.Time
	for now().Before(end) {
		if ctx.Err() != nil {
			return loginReadyCanceled, diag
		}
		if err := sleep(ctx, 300*time.Millisecond); err != nil {
			return loginReadyCanceled, diag
		}
		if ctx.Err() != nil {
			return loginReadyCanceled, diag
		}
		if !now().Before(end) {
			break
		}
		if ops.probe == nil || ops.form == nil {
			diag.ReadErrors++
			return loginReadyReadFailed, diag
		}
		readCtx, cancel := context.WithTimeout(ctx, min(loginFinalReadBudget, end.Sub(now())))
		st, err := ops.probe(readCtx)
		readErr := readCtx.Err()
		cancel()
		diag.Probes++
		if ctx.Err() != nil {
			return loginReadyCanceled, diag
		}
		if err != nil || readErr != nil || !now().Before(end) {
			diag.ReadErrors++
			return loginReadyReadFailed, diag
		}
		switch {
		case twoVerifyURL(st.URL):
			return loginReadyTwoVerify, diag
		case schoolURL(st.URL, "xsfw.gzist.edu.cn"):
			return loginReadyBusiness, diag
		case !casLoginURL(st.URL):
			return loginReadyUntrusted, diag
		}
		readCtx, cancel = context.WithTimeout(ctx, min(loginFinalReadBudget, end.Sub(now())))
		visible, err := ops.form(readCtx)
		readErr = readCtx.Err()
		cancel()
		diag.Forms++
		if ctx.Err() != nil {
			return loginReadyCanceled, diag
		}
		if err != nil || readErr != nil || !now().Before(end) {
			diag.ReadErrors++
			return loginReadyReadFailed, diag
		}
		if !visible {
			since = time.Time{}
			continue
		}
		if stableFor <= 0 {
			return loginReadyForm, diag
		}
		if since.IsZero() {
			since = now()
		}
		if now().Sub(since) >= stableFor {
			return loginReadyForm, diag
		}
	}
	if ctx.Err() != nil {
		return loginReadyCanceled, diag
	}
	return loginReadyMissing, diag
}

func loginReadyLine(stage string, verdict loginReadyVerdict, d loginReadyDiag) string {
	return fmt.Sprintf("  登录就绪: stage=%s verdict=%s probes=%d forms=%d read_errors=%d", stage, verdict, d.Probes, d.Forms, d.ReadErrors)
}

func (r *Runner) finishLoginReady(ctx context.Context, ops loginPageOps, loginOK *bool, verdict loginReadyVerdict) Result {
	if ctx.Err() != nil {
		return canceledResult(ctx)
	}
	switch verdict {
	case loginReadyBusiness:
		*loginOK = true
		return Result{OK: true, Reason: "已到达业务页"}
	case loginReadyTwoVerify:
		r.log(loginDiagLine("ready", loginSubmitActionRequired, loginSubmitDiag{Page: "twoverify", Form: "unknown"}))
		if res, handled := r.manualVerification(ctx, ops, loginOK); handled {
			return res
		}
		return loginSubmitFailure(loginSubmitActionRequired, loginSubmitDiag{})
	case loginReadyReadFailed:
		return Result{Exit: 9, AuthIssue: AuthNetwork, Reason: "登录页面读取失败或读取超时，本轮停止，未提交账号密码"}
	case loginReadyUntrusted:
		return Result{Exit: 3, AuthIssue: AuthUnknown, Reason: "登录等待到达非可信页面，本轮停止，未提交账号密码"}
	case loginReadyCanceled:
		return canceledResult(ctx)
	default:
		return Result{Exit: 3, AuthIssue: AuthUnknown, Reason: "等待结束仍未确认稳定登录表单，本轮停止，未提交账号密码"}
	}
}
