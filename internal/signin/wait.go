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

const pageWaitBudget = 120 * time.Second

// runOrigins names the two participants whose cancellation can end a run, so the
// wait can tell "the person stopped this run" from "the browser went away". ctx
// is derived from the browser context (see runContext), which means a closed
// window cancels it just like a caller cancel does; only the participants
// themselves can say which happened.
type runOrigins struct {
	caller  context.Context // the run request; canceling it is an explicit stop
	browser context.Context // the session's browser context; ending it is a closed window or a lost connection
}

// Keep browser values (including the CDP executor), but also honor the caller.
func runContext(caller, browser context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	linked, cancel := context.WithCancelCause(browser)
	stop := context.AfterFunc(caller, func() { cancel(context.Cause(caller)) })
	// AfterFunc is asynchronous, so cover callers already canceled on entry.
	if caller.Err() != nil {
		cancel(context.Cause(caller))
	}
	ctx, timeoutCancel := context.WithTimeout(linked, budget)
	return ctx, func() { stop(); timeoutCancel(); cancel(context.Canceled) }
}

func canceledResult(ctx context.Context) Result {
	// A caller cancel reaches the merged context through an asynchronous
	// AfterFunc, so this can be asked about a context that looks alive while the
	// run is already stopped: never dereference a nil cause.
	cause := context.Cause(ctx)
	if errors.Is(cause, errLateLine) {
		return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}
	}
	if cause == nil {
		cause = context.Canceled
	}
	return Result{Reason: "签到已停止: " + cause.Error(), Exit: 5}
}

type pageState struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

// A slow shell is not evidence of a broken page. Only repair a known missing
// route, never reload based on elapsed time or the absence of a sign-in card.
func pageWaitPolicy(s pageState, elapsed time.Duration, repaired bool) (ready, repair bool) {
	if schoolURL(s.URL, "xsfw.gzist.edu.cn") && ((strings.Contains(s.Text, "查寝时间段") && strings.Contains(s.Text, "点击签到")) || hitKeyword(s.Text) != "") {
		return true, false
	}
	u, err := url.Parse(s.URL)
	return false, !repaired && elapsed >= 3*time.Second && err == nil &&
		schoolURL(s.URL, "xsfw.gzist.edu.cn") &&
		!strings.HasPrefix(u.Fragment, "/xscq/grcq")
}

func probePage(ctx context.Context) (pageState, error) {
	var s pageState
	err := chromedp.Evaluate(`({url:location.href,text:(document.body?document.body.innerText:'').replace(/\s+/g,' ')})`, &s).Do(exec(ctx))
	return s, err
}

const repairPageRouteJS = `if(location.protocol==='https:' && location.hostname==='xsfw.gzist.edu.cn' && (location.port===''||location.port==='443') && !new URL(location.href).username && !new URL(location.href).password && !location.hash.startsWith('#/xscq/grcq')){location.hash='/xscq/grcq'}`

func repairPageRoute(ctx context.Context) error {
	// Re-check in the page: a redirect may have happened since the snapshot.
	return chromedp.Evaluate(repairPageRouteJS, nil).Do(exec(ctx))
}

// waitProgress is told what the page looks like while the wait is still running.
// It exists because a silent budget cannot be told apart from a stuck run: on
// 2026-10-25 a live run was killed at ~100 s into this wait and the only thing
// the log had to show was the line before it started.
type waitProgress func(elapsed time.Duration, s pageState, repaired bool, readErr error)

// waitOptions is the injectable form of the wait. Budgets are never extended:
// progress reporting only makes the existing wait legible.
type waitOptions struct {
	budget        time.Duration
	poll          time.Duration
	progressEvery time.Duration
	progress      waitProgress
}

// The budget covers probes and repair too, not just sleeps between them.
// Injection points let tests exercise deadlines without a browser or network.
func waitBusinessPage(ctx context.Context, budget, poll time.Duration,
	probe func(context.Context) (pageState, error), repair func(context.Context) error,
) (last pageState, elapsed time.Duration, err error) {
	return waitBusinessPageWith(ctx, waitOptions{budget: budget, poll: poll}, probe, repair)
}

func waitBusinessPageWith(ctx context.Context, opts waitOptions,
	probe func(context.Context) (pageState, error), repair func(context.Context) error,
) (last pageState, elapsed time.Duration, err error) {
	budget, poll := opts.budget, opts.poll
	start := time.Now()
	nextReport := opts.progressEvery
	defer func() { elapsed = time.Since(start) }()
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	repaired := false
	detail := "尚未出现查寝内容"
	for {
		if waitCtx.Err() != nil {
			return last, 0, fmt.Errorf("%w；%s", context.Cause(waitCtx), detail)
		}
		s, probeErr := probe(waitCtx)
		if waitCtx.Err() != nil {
			return last, 0, fmt.Errorf("%w；%s", context.Cause(waitCtx), detail)
		}
		if probeErr != nil {
			detail = "最近一次页面读取错误: " + safeDiagnosticError(probeErr)
		} else {
			last = s
			ready, fix := pageWaitPolicy(s, time.Since(start), repaired)
			if ready {
				return last, 0, nil
			}
			if fix {
				repaired = true // An unsuccessful attempt must not trigger a retry loop.
				if repairErr := repair(waitCtx); repairErr != nil {
					detail = "路由修复失败: " + safeDiagnosticError(repairErr)
				} else {
					detail = "已尝试一次路由修复，仍未出现查寝内容"
				}
			}
		}
		if opts.progress != nil && opts.progressEvery > 0 && time.Since(start) >= nextReport {
			nextReport = time.Since(start) + opts.progressEvery
			opts.progress(time.Since(start), last, repaired, probeErr)
		}
		if err := sleepCtx(waitCtx, poll); err != nil {
			return last, 0, fmt.Errorf("%w；%s", context.Cause(waitCtx), detail)
		}
	}
}

func pageWaitFailure(elapsed time.Duration, err error) Result {
	return Result{Reason: fmt.Sprintf("页面等待结束（实际耗时 %.1fs）: %v", elapsed.Seconds(), err), Exit: 5}
}
