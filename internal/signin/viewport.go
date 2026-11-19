package signin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// The school's login bundle decides its layout from the CSS layout viewport:
//
//	K = c <= 980          // c = document.documentElement.clientWidth
//	!K && isRememberPass  → render the 「记住密码」 checkbox
//
// The app's default window is 430x900, so the checkbox is not absent from the
// login page — it is hidden because K is true. This file is the only place that
// changes the viewport: it widens the page for the duration of the login so the
// desktop layout renders, and the caller restores the exact previous metrics
// before anything that depends on the business page layout runs.
const (
	// desktopViewportMinWidth is the first width the bundle counts as desktop
	// (K is `width <= 980`).
	desktopViewportMinWidth = 981
	widenViewportWidth      = 1280
	widenViewportHeight     = 900
	widenSettleTimeout      = 2 * time.Second
	widenSettlePoll         = 100 * time.Millisecond
	widenSettleSleep        = 300 * time.Millisecond

	// Every CDP exchange gets its own bound, and each phase gets a deadline of its
	// own as well: a read or an apply that hangs must not silently spend the run's
	// whole budget, and a phase deadline only means something if the calls inside
	// it cannot outlive it.
	viewportReadTimeout    = 1 * time.Second
	viewportApplyTimeout   = 2 * time.Second
	viewportRestoreTimeout = 3 * time.Second
	formStableBudget       = 3 * time.Second
)

// viewport is the CSS layout viewport the school measures, plus the device scale
// factor. These three metrics are exactly what this file manages: the emulation
// call sets the size and the scale factor and nothing else. Touch emulation is
// deliberately left alone — dispatchTouchAt owns it on the business page — and
// user agent, geolocation, colour scheme, … are never touched here. Restoring
// these three therefore restores everything this code changed.
type viewport struct {
	Width  int     // document.documentElement.clientWidth
	Height int     // document.documentElement.clientHeight
	DPR    float64 // window.devicePixelRatio
}

func (v viewport) desktopWidth() bool { return v.Width >= desktopViewportMinWidth }

// viewportOps isolates the two CDP calls so the widening rules can be tested
// without a browser. Production always uses browserViewportOps.
type viewportOps struct {
	read  func(context.Context) (viewport, error)
	apply func(context.Context, viewport) error
}

func browserViewportOps() viewportOps {
	return viewportOps{read: readBrowserViewport, apply: applyBrowserViewport}
}

func readBrowserViewport(ctx context.Context) (viewport, error) {
	var got []float64
	const js = `(function(){var d=document.documentElement;
 return [d.clientWidth, d.clientHeight, window.devicePixelRatio || 1];})()`
	if err := chromedp.Evaluate(js, &got).Do(exec(ctx)); err != nil {
		return viewport{}, err
	}
	if len(got) != 3 {
		return viewport{}, fmt.Errorf("读取页面视口失败: 返回 %d 个值", len(got))
	}
	return viewport{Width: int(got[0]), Height: int(got[1]), DPR: got[2]}, nil
}

func applyBrowserViewport(ctx context.Context, v viewport) error {
	if v.Width <= 0 || v.Height <= 0 {
		return fmt.Errorf("非法视口 %dx%d", v.Width, v.Height)
	}
	dpr := v.DPR
	if dpr <= 0 {
		dpr = 1
	}
	// Size and scale only. Touch emulation belongs to dispatchTouchAt for the
	// business page: switching it off here would change state that the widen never
	// restores, so this call leaves it untouched.
	return emulation.SetDeviceMetricsOverride(int64(v.Width), int64(v.Height), dpr, false).
		Do(exec(ctx))
}

// readViewport bounds one read. A blocking CDP call cannot outlive the bound, and
// an answer that only arrives after the bound is not treated as an answer.
func readViewport(ctx context.Context, ops viewportOps) (viewport, error) {
	c, cancel := context.WithTimeout(ctx, viewportReadTimeout)
	defer cancel()
	v, err := ops.read(c)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return viewport{}, fmt.Errorf("读取页面视口超时（%s）: %w", viewportReadTimeout, err)
		}
		return viewport{}, err
	}
	// An answer that only arrived after the bound is not evidence: the call may
	// have hung and returned a stale read, so treat it as no answer at all.
	if cerr := c.Err(); cerr != nil {
		if errors.Is(cerr, context.DeadlineExceeded) {
			return viewport{}, fmt.Errorf("读取页面视口超时（%s）: %w", viewportReadTimeout, cerr)
		}
		return viewport{}, cerr
	}
	return v, nil
}

// applyViewport bounds one apply.
func applyViewport(ctx context.Context, ops viewportOps, v viewport) error {
	c, cancel := context.WithTimeout(ctx, viewportApplyTimeout)
	defer cancel()
	if err := ops.apply(c, v); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("设置页面视口超时（%s）: %w", viewportApplyTimeout, err)
		}
		return err
	}
	// No error, but the bound elapsed while the call was running: whether the page
	// changed is unknown, so the caller is told instead of being reassured.
	if cerr := c.Err(); cerr != nil {
		if errors.Is(cerr, context.DeadlineExceeded) {
			return fmt.Errorf("设置页面视口超时（%s）: %w", viewportApplyTimeout, cerr)
		}
		return cerr
	}
	return nil
}

// widened records what a widen attempt may have done, so the caller can put the
// page back as it was — never to a hard-coded size.
type widened struct {
	Original viewport
	Applied  bool
}

// widenForRememberMe switches the page to a desktop-width viewport when the
// narrow layout is hiding the checkbox, and reports the metrics to restore.
//
// A page that is already wide enough is left untouched (Applied=false). The wait
// is on the CSS viewport the page actually reports, not on the window size, and
// it ends only after the wide width has been read twice with the settle pause in
// between — the responsive layout has to be stable before any field or checkbox
// is located again.
//
// Applied is set before the emulation is attempted, because that command can
// change the page and still fail or lose its reply. A failed apply therefore
// still leaves something to restore.
func widenForRememberMe(ctx context.Context, ops viewportOps, sleep func(context.Context, time.Duration) error) (widened, error) {
	cur, err := readViewport(ctx, ops)
	if err != nil {
		return widened{}, err
	}
	if cur.desktopWidth() {
		return widened{Original: cur}, nil
	}
	if err := ctx.Err(); err != nil {
		return widened{}, err
	}
	applied := widened{Original: cur, Applied: true}
	target := viewport{Width: widenViewportWidth, Height: widenViewportHeight, DPR: cur.DPR}
	if err := applyViewport(ctx, ops, target); err != nil {
		return applied, fmt.Errorf("切换到桌面宽度失败: %w", err)
	}
	// One deadline for the whole settle phase, shared by every read and sleep in
	// it: a second "wide enough" read that lands after the phase is over does not
	// count as settled.
	stage, cancelStage := context.WithTimeout(ctx, widenSettleTimeout)
	defer cancelStage()
	lastWidth := cur.Width
	stuck := func(width int) error {
		return fmt.Errorf("切宽后 %s 内页面视口仍为 %dpx（需要大于 %d）",
			widenSettleTimeout, width, desktopViewportMinWidth-1)
	}
	for {
		got, readErr := readViewport(stage, ops)
		// The run being cancelled wins over whatever the read answered.
		if err := ctx.Err(); err != nil {
			return applied, err
		}
		// So does the phase being over: a late answer cannot supply the width.
		if readErr == nil {
			lastWidth = got.Width
		}
		if err := stage.Err(); err != nil {
			width := lastWidth
			if readErr == nil {
				width = got.Width
			}
			return applied, stuck(width)
		}
		if readErr == nil && got.desktopWidth() {
			if sleep != nil {
				if err := sleep(stage, widenSettleSleep); err != nil {
					if ctxErr := ctx.Err(); ctxErr != nil {
						return applied, ctxErr
					}
					return applied, stuck(got.Width)
				}
			}
			settled, settleErr := readViewport(stage, ops)
			if err := ctx.Err(); err != nil {
				return applied, err
			}
			if stage.Err() != nil {
				return applied, stuck(got.Width)
			}
			if settleErr != nil {
				return applied, settleErr
			}
			if !settled.desktopWidth() {
				return applied, stuck(settled.Width)
			}
			return applied, nil
		}
		if sleep != nil {
			if err := sleep(stage, widenSettlePoll); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return applied, ctxErr
				}
				return applied, stuck(lastWidth)
			}
		}
	}
}

// restore puts the captured metrics back and proves it by reading them again.
// It is a no-op when nothing was changed, and it never invents a size.
//
// The caller's context may already be cancelled — that is often why a restore is
// needed at all — but the browser still has to be put back, so the cleanup runs
// on a context detached from that cancellation (values such as the CDP target
// are kept) and bounded by viewportRestoreTimeout. The device scale factor is
// part of what has to come back; touch emulation was never ours to change.
func (w widened) restore(ctx context.Context, ops viewportOps) error {
	if !w.Applied {
		return nil
	}
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), viewportRestoreTimeout)
	defer cancel()
	if err := applyViewport(c, ops, w.Original); err != nil {
		return fmt.Errorf("恢复原视口失败: %w", err)
	}
	got, err := readViewport(c, ops)
	if err != nil {
		return fmt.Errorf("恢复原视口后无法回读: %w", err)
	}
	if got.Width != w.Original.Width || got.Height != w.Original.Height || math.Abs(got.DPR-w.Original.DPR) > 0.001 {
		return fmt.Errorf("恢复原视口后仍为 %dx%d@%g（期望 %dx%d@%g）",
			got.Width, got.Height, got.DPR, w.Original.Width, w.Original.Height, w.Original.DPR)
	}
	return nil
}

// widenBrowserForRememberMe is the production hook used by the login driver.
func widenBrowserForRememberMe(ctx context.Context) (widened, error) {
	return widenForRememberMe(ctx, browserViewportOps(), sleepCtx)
}

// restoreBrowserViewport is the production counterpart of the hook above.
func restoreBrowserViewport(ctx context.Context, w widened) error {
	return w.restore(ctx, browserViewportOps())
}

// formReadyWithin bounds one form read and reports false as soon as the read's own
// bound elapsed — an answer that arrives after it is not evidence — or as soon as
// the run is cancelled.
func formReadyWithin(ctx context.Context, ops loginPageOps) bool {
	if ctx.Err() != nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, viewportReadTimeout)
	defer cancel()
	ok, err := ops.form(c)
	if ctx.Err() != nil || c.Err() != nil {
		return false
	}
	// A read that failed (timed out, dropped) cannot vouch for the form, whatever
	// value it came back with.
	if err != nil {
		return false
	}
	return ok
}

// waitFormStableAfterWiden waits for the login form to be present twice, with the
// settle pause in between, before the caller fills anything. The whole phase runs
// on one deadline that bounds its reads and its sleeps alike, each read is bounded
// on its own, and the cancellation is re-checked after every read, so a late
// answer cannot supply the second "ready" of a cancelled run.
func waitFormStableAfterWiden(ctx context.Context, ops loginPageOps) bool {
	if ops.form == nil {
		return false
	}
	now := ops.now
	if now == nil {
		now = time.Now
	}
	sleep := ops.sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	stage, cancelStage := context.WithTimeout(ctx, formStableBudget)
	defer cancelStage()
	deadline := now().Add(formStableBudget)
	for now().Before(deadline) && stage.Err() == nil {
		if err := sleep(stage, 150*time.Millisecond); err != nil {
			return false
		}
		if !formReadyWithin(stage, ops) {
			continue
		}
		if err := sleep(stage, widenSettleSleep); err != nil {
			return false
		}
		return formReadyWithin(stage, ops)
	}
	return false
}
