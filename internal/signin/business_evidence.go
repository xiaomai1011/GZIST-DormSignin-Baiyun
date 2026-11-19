package signin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"time"

	"github.com/chromedp/chromedp"
)

// ResultOutcome describes evidence, not who caused a server-side state change.
// Empty is retained for intermediate authentication and non-success results.
type ResultOutcome string

const (
	OutcomeObservedSigned     ResultOutcome = "observed-already-signed"
	OutcomeSubmittedConfirmed ResultOutcome = "submitted-confirmed"
)

func (r *Runner) observedSignedResult() Result {
	r.log("  签到结果分类: observed-already-signed（读取到已签到；本轮未提交签到）")
	return Result{OK: true, Reason: "今日已签到，无需再签", Outcome: OutcomeObservedSigned}
}

func (r *Runner) submittedConfirmedResult() Result {
	r.log("  签到结果分类: submitted-confirmed（本次已执行提交尝试，随后观察到成功；未关联服务端请求）")
	return Result{OK: true, Reason: "签到成功", Outcome: OutcomeSubmittedConfirmed}
}

// Only fixed categories leave this function. In particular a CAS callback's
// ticket, unknown paths and fragments are never logged or used as navigation.
func businessEntryCategory(raw string) string {
	if !schoolURL(raw, "xsfw.gzist.edu.cn") {
		return "not-business"
	}
	u, _ := url.Parse(raw)
	if u.Path != "/xsfw/sys/swmzncqapp/*default/index.do" && u.Path != "/index.do" {
		return "other-path"
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "entry-with-query"
	}
	if u.Fragment != "/xscq/grcq" {
		return "entry-other-route"
	}
	if u.Path == "/index.do" {
		return "stable-short-entry"
	}
	return "stable-full-entry"
}

// Fingerprint only the currently leased target; no target enumeration, tab
// selection, network request or page mutation is performed for diagnostics.
func businessTargetTag(ctx context.Context) string {
	c := chromedp.FromContext(ctx)
	if c == nil || c.Target == nil || c.Target.TargetID == "" {
		return "unavailable"
	}
	sum := sha256.Sum256([]byte(c.Target.TargetID))
	return fmt.Sprintf("%x", sum[:6])
}

func (r *Runner) logBusinessPhase(ctx context.Context, phase string) {
	// Callers provide only literals; constrain even future callers to the schema.
	switch phase {
	case "auth-reached", "initial-wait", "recovery-wait":
	default:
		phase = "unknown"
	}
	r.log(fmt.Sprintf("  业务阶段: phase=%s target=%s（当前绑定目标摘要；未切换标签页）", phase, businessTargetTag(ctx)))
}

func (r *Runner) waitBusinessPhase(ctx context.Context, phase string, budget time.Duration, probe func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
	r.logBusinessPhase(ctx, phase)
	last, elapsed, err := waitBusinessPageWith(ctx, waitOptions{
		budget: budget, poll: 500 * time.Millisecond,
		progressEvery: step6ProgressEvery, progress: r.step6Progress,
	}, probe, repairPageRoute)
	r.log(fmt.Sprintf("  业务等待结束: target=%s 页面=%s 入口=%s 耗时=%.1fs 读取结果=%s", businessTargetTag(ctx), safePageCategory(last.URL), businessEntryCategory(last.URL), elapsed.Seconds(), safeDiagnosticError(err)))
	return last, elapsed, err
}
