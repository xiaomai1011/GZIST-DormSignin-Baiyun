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
	if errors.Is(context.Cause(ctx), errLateLine) {
		return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}
	}
	return Result{Reason: "签到已停止: " + context.Cause(ctx).Error(), Exit: 5}
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
		u.Hostname() == "xsfw.gzist.edu.cn" && (u.Scheme == "https" || u.Scheme == "http") &&
		!strings.HasPrefix(u.Fragment, "/xscq/grcq")
}

func probePage(ctx context.Context) (pageState, error) {
	var s pageState
	err := chromedp.Evaluate(`({url:location.href,text:(document.body?document.body.innerText:'').replace(/\s+/g,' ')})`, &s).Do(exec(ctx))
	return s, err
}

func repairPageRoute(ctx context.Context) error {
	// Re-check in the page: a redirect may have happened since the snapshot.
	return chromedp.Evaluate(`if(location.hostname==='xsfw.gzist.edu.cn' && !location.hash.startsWith('#/xscq/grcq')){location.hash='/xscq/grcq'}`, nil).Do(exec(ctx))
}

// The budget covers probes and repair too, not just sleeps between them.
// Injection points let tests exercise deadlines without a browser or network.
func waitBusinessPage(ctx context.Context, budget, poll time.Duration,
	probe func(context.Context) (pageState, error), repair func(context.Context) error,
) (last pageState, elapsed time.Duration, err error) {
	start := time.Now()
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
		if err := sleepCtx(waitCtx, poll); err != nil {
			return last, 0, fmt.Errorf("%w；%s", context.Cause(waitCtx), detail)
		}
	}
}

func pageWaitFailure(elapsed time.Duration, err error) Result {
	return Result{Reason: fmt.Sprintf("页面等待结束（实际耗时 %.1fs）: %v", elapsed.Seconds(), err), Exit: 5}
}
