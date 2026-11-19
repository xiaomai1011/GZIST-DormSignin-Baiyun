package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Tests for the login-page viewport widening. The two CDP calls are replaced by
// a scripted surface, so nothing here needs a browser or a network; the ordering
// against the login flow is covered in login_viewport_test.go.

type fakeViewport struct {
	width, height int
	dpr           float64

	readErr  error
	applyErr error
	// stuck models a page that accepts the emulation but keeps reporting the old
	// CSS width — the case the widen must not call "done".
	stuck bool
	// applyErrAfterChange models the emulation that changes the page and then
	// fails (or loses its reply): the state has already moved.
	applyErrAfterChange bool
	// ignoreDPR models a page that accepts a size change but keeps its own device
	// scale factor, which the restore has to notice.
	ignoreDPR bool
	// readFn, when set, replaces the default read entirely.
	readFn func(context.Context) (viewport, error)

	applied []viewport
}

func (f *fakeViewport) ops() viewportOps {
	return viewportOps{
		read: func(ctx context.Context) (viewport, error) {
			if f.readFn != nil {
				return f.readFn(ctx)
			}
			if f.readErr != nil {
				return viewport{}, f.readErr
			}
			return viewport{Width: f.width, Height: f.height, DPR: f.dpr}, nil
		},
		apply: func(_ context.Context, v viewport) error {
			if f.applyErr != nil {
				return f.applyErr
			}
			f.applied = append(f.applied, v)
			if !f.stuck {
				f.width, f.height = v.Width, v.Height
				if !f.ignoreDPR {
					f.dpr = v.DPR
				}
			}
			// Fires once, on the widen itself: the restore that follows is a
			// normal apply.
			if f.applyErrAfterChange && v.Width == widenViewportWidth {
				f.applyErrAfterChange = false
				return errors.New("emulation reply lost")
			}
			return nil
		},
	}
}

// 1. A page that is already wide enough is left alone: nothing is applied, so
// there is nothing to restore either.
func TestWidenLeavesAnAlreadyWidePageAlone(t *testing.T) {
	f := &fakeViewport{width: 1280, height: 900, dpr: 1}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err != nil {
		t.Fatalf("widen failed: %v", err)
	}
	if got.Applied {
		t.Fatal("a wide page must not be reported as changed")
	}
	if len(f.applied) != 0 {
		t.Fatalf("applied %d viewports to a wide page, want none", len(f.applied))
	}
	if got.Original.Width != 1280 || got.Original.Height != 900 {
		t.Fatalf("captured %+v, want the page's own 1280x900", got.Original)
	}
}

// 2. The narrow default window is switched to desktop width and the metrics that
// have to come back are the ones the page actually reported.
func TestWidenSwitchesANarrowPageAndKeepsTheOriginalMetrics(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1.25}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err != nil {
		t.Fatalf("widen failed: %v", err)
	}
	if !got.Applied {
		t.Fatal("a narrow page must be reported as changed")
	}
	want := viewport{Width: 430, Height: 900, DPR: 1.25}
	if got.Original != want {
		t.Fatalf("captured %+v, want %+v", got.Original, want)
	}
	if len(f.applied) != 1 || f.applied[0].Width != widenViewportWidth {
		t.Fatalf("applied %+v, want one %dpx viewport", f.applied, widenViewportWidth)
	}
	if f.applied[0].DPR != 1.25 {
		t.Fatalf("device scale factor %v, want the page's own 1.25", f.applied[0].DPR)
	}
	if f.width != widenViewportWidth {
		t.Fatalf("page width is %d after widen, want %d", f.width, widenViewportWidth)
	}
}

// 3. Accepting the emulation is not the same as the page being wide: the widen
// only succeeds once the CSS viewport it reads back passes the school's 980px
// boundary.
func TestWidenFailsWhenTheWidthNeverPasses980(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1, stuck: true}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err == nil {
		t.Fatal("a page stuck at 430px must not be reported as widened")
	}
	if !strings.Contains(err.Error(), "930") && !strings.Contains(err.Error(), "430") {
		t.Fatalf("error does not name the width it is stuck at: %v", err)
	}
	if !got.Applied {
		t.Fatal("the page was changed, so a restore must still be possible")
	}
	if got.Original.Width != 430 {
		t.Fatalf("captured %+v, want the original 430px", got.Original)
	}
}

// 4. The emulation call is not atomic: it may change the page and still return an
// error (a failing touch step, a lost reply). The widen reports the failure but
// must leave a restore possible, and that restore has to work.
func TestWidenRegistersARestoreWhenApplyFailsAfterChangingThePage(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1, applyErrAfterChange: true}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err == nil || !strings.Contains(err.Error(), "切换到桌面宽度失败") {
		t.Fatalf("err = %v, want the apply failure", err)
	}
	if !got.Applied {
		t.Fatal("the page changed before the error, so a restore must be registered")
	}
	if got.Original.Width != 430 || got.Original.Height != 900 {
		t.Fatalf("captured %+v, want the original 430x900", got.Original)
	}
	if f.width != widenViewportWidth {
		t.Fatalf("precondition: page width = %d, want the applied %d", f.width, widenViewportWidth)
	}
	if err := got.restore(context.Background(), f.ops()); err != nil {
		t.Fatalf("restore after a partial apply failed: %v", err)
	}
	if f.width != 430 || f.height != 900 {
		t.Fatalf("page is %dx%d after restore, want 430x900", f.width, f.height)
	}
}

// 5. A failed emulation that did nothing is still reported as a failure; the
// registered restore is harmless because it puts back the metrics that are
// already there.
func TestWidenReportsAnApplyFailure(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1, applyErr: errors.New("emulation refused")}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err == nil || !strings.Contains(err.Error(), "切换到桌面宽度失败") {
		t.Fatalf("err = %v, want the apply failure", err)
	}
	if !got.Applied {
		t.Fatal("an apply error cannot prove the page was untouched, so a restore is kept")
	}
}

// 6. Restore puts back exactly what was captured — never a hard-coded 430x900.
func TestRestoreUsesTheCapturedMetrics(t *testing.T) {
	f := &fakeViewport{width: widenViewportWidth, height: widenViewportHeight, dpr: 2}
	w := widened{Original: viewport{Width: 512, Height: 777, DPR: 2}, Applied: true}
	if err := w.restore(context.Background(), f.ops()); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if len(f.applied) != 1 {
		t.Fatalf("applied %d viewports, want 1", len(f.applied))
	}
	if got := f.applied[0]; got.Width != 512 || got.Height != 777 || got.DPR != 2 {
		t.Fatalf("restored %+v, want the captured 512x777@2", got)
	}
}

// 7. A restore that cannot be confirmed by a read is an error, not a silent pass.
func TestRestoreFailsWhenTheMetricsDoNotComeBack(t *testing.T) {
	f := &fakeViewport{width: widenViewportWidth, height: widenViewportHeight, dpr: 1, stuck: true}
	w := widened{Original: viewport{Width: 430, Height: 900, DPR: 1}, Applied: true}
	err := w.restore(context.Background(), f.ops())
	if err == nil || !strings.Contains(err.Error(), "仍为") {
		t.Fatalf("err = %v, want a mismatch report", err)
	}
}

// 8. The device scale factor is part of the state that has to come back.
func TestRestoreChecksTheDeviceScaleFactor(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1.5, ignoreDPR: true}
	w := widened{Original: viewport{Width: 430, Height: 900, DPR: 2}, Applied: true}
	err := w.restore(context.Background(), f.ops())
	if err == nil || !strings.Contains(err.Error(), "仍为") {
		t.Fatalf("err = %v, want a DPR mismatch report", err)
	}
}

// 9. Nothing was changed, so restore does nothing at all.
func TestRestoreIsANoOpWhenNothingWasApplied(t *testing.T) {
	f := &fakeViewport{width: 1280, height: 900, dpr: 1}
	if err := (widened{Original: viewport{Width: 1280, Height: 900, DPR: 1}}).restore(context.Background(), f.ops()); err != nil {
		t.Fatalf("restore of an unchanged page failed: %v", err)
	}
	if len(f.applied) != 0 {
		t.Fatalf("applied %d viewports, want none", len(f.applied))
	}
}

// 10. Cancellation during the settle wait is reported as the stop it is.
func TestWidenHonoursCancellation(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1, stuck: true}
	ctx, cancel := context.WithCancel(context.Background())
	_, err := widenForRememberMe(ctx, f.ops(), func(context.Context, time.Duration) error {
		cancel()
		return context.Canceled
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
}

// 11. A read that blocks is bounded: the settle budget cannot be stretched to the
// whole run because one CDP call never answers.
func TestWidenGivesUpOnABlockingRead(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1}
	f.readFn = func(ctx context.Context) (viewport, error) {
		<-ctx.Done()
		return viewport{}, ctx.Err()
	}
	start := time.Now()
	_, err := widenForRememberMe(context.Background(), f.ops(), nil)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "读取页面视口超时") {
		t.Fatalf("err = %v, want a read timeout", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("blocking read took %s, want it bounded by %s", elapsed, viewportReadTimeout)
	}
}

// 12. A value that only arrives after its read timed out is not adopted as the
// settled width.
func TestWidenDoesNotAdoptAReadThatOutlivedItsDeadline(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1}
	calls := 0
	f.readFn = func(ctx context.Context) (viewport, error) {
		calls++
		if calls == 1 {
			return viewport{Width: 430, Height: 900, DPR: 1}, nil
		}
		// Ignore the deadline and answer late with a desktop width.
		time.Sleep(viewportReadTimeout + 200*time.Millisecond)
		return viewport{Width: widenViewportWidth, Height: widenViewportHeight, DPR: 1}, nil
	}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err == nil {
		t.Fatalf("a late read must not be accepted as the settled width (got %+v)", got)
	}
	if !strings.Contains(err.Error(), "读取页面视口超时") && !strings.Contains(err.Error(), "仍为") {
		t.Fatalf("err = %v, want the late read rejected as no answer", err)
	}
	if !got.Applied {
		t.Fatal("the emulation was applied, so a restore must be registered")
	}
}

// 13. A read that returns after a cancellation must not be adopted: the stop wins.
func TestWidenRechecksCancellationAfterARead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeViewport{width: 430, height: 900, dpr: 1}
	calls := 0
	f.readFn = func(context.Context) (viewport, error) {
		calls++
		if calls == 1 {
			return viewport{Width: 430, Height: 900, DPR: 1}, nil
		}
		cancel()
		return viewport{Width: widenViewportWidth, Height: widenViewportHeight, DPR: 1}, nil
	}
	if _, err := widenForRememberMe(ctx, f.ops(), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation even though the read answered", err)
	}
}

// 14. Restore has to work after the caller was cancelled: the cleanup cannot ride
// on the dead context.
func TestRestoreUsesAFreshContextAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ops := viewportOps{
		read: func(c context.Context) (viewport, error) {
			if err := c.Err(); err != nil {
				return viewport{}, err
			}
			return viewport{Width: 430, Height: 900, DPR: 1}, nil
		},
		apply: func(c context.Context, _ viewport) error { return c.Err() },
	}
	w := widened{Original: viewport{Width: 430, Height: 900, DPR: 1}, Applied: true}
	if err := w.restore(ctx, ops); err != nil {
		t.Fatalf("restore with a cancelled caller failed: %v", err)
	}
}

// 15. The form has to be ready twice after the layout change; a cancellation
// during the wait reports false instead of a form that is not there.
func TestWaitFormStableAfterWiden(t *testing.T) {
	clock := newFakeClock()
	ready := true
	ops := loginPageOps{
		now:   clock.now,
		sleep: clock.sleep,
		form:  func(context.Context) (bool, error) { return ready, nil },
	}
	if !waitFormStableAfterWiden(context.Background(), ops) {
		t.Fatal("a stable form must be accepted")
	}
	ready = false
	if waitFormStableAfterWiden(context.Background(), ops) {
		t.Fatal("an absent form must not be accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitFormStableAfterWiden(ctx, ops) {
		t.Fatal("a cancelled wait must not accept the form")
	}
}

// 16. A form read that hangs is bounded and reported as not-ready, and a read that
// answers only after the run was cancelled does not count either.
func TestFormReadyWithinBoundsTheReadAndHonoursCancellation(t *testing.T) {
	blocking := loginPageOps{form: func(ctx context.Context) (bool, error) {
		<-ctx.Done()
		return true, ctx.Err()
	}}
	start := time.Now()
	if formReadyWithin(context.Background(), blocking) {
		t.Fatal("a read that timed out must not be treated as a ready form")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("blocking form read took %s, want it bounded by %s", elapsed, viewportReadTimeout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	late := loginPageOps{form: func(context.Context) (bool, error) {
		cancel()
		return true, nil
	}}
	if formReadyWithin(ctx, late) {
		t.Fatal("a read that lands after the cancellation must not count as ready")
	}
}

// 17. A form read that returns "ready" only after its own bound elapsed is not
// evidence, even when the run itself is still alive.
func TestFormReadyWithinRejectsAnAnswerThatOutlivedItsOwnBound(t *testing.T) {
	late := loginPageOps{form: func(context.Context) (bool, error) {
		time.Sleep(viewportReadTimeout + 150*time.Millisecond)
		return true, nil
	}}
	if formReadyWithin(context.Background(), late) {
		t.Fatal("an answer that arrived after the read's own bound must not count as ready")
	}
}

// 18. The settle phase has one deadline: a second "wide enough" read that lands
// after it is over cannot make the widen a success.
func TestWidenRejectsASecondReadThatCrossesThePhaseDeadline(t *testing.T) {
	f := &fakeViewport{width: 430, height: 900, dpr: 1}
	calls := 0
	f.readFn = func(context.Context) (viewport, error) {
		calls++
		switch calls {
		case 1:
			return viewport{Width: 430, Height: 900, DPR: 1}, nil
		case 2:
			return viewport{Width: widenViewportWidth, Height: widenViewportHeight, DPR: 1}, nil
		default:
			// The confirmation read ignores its deadline and answers late.
			time.Sleep(widenSettleTimeout + 200*time.Millisecond)
			return viewport{Width: widenViewportWidth, Height: widenViewportHeight, DPR: 1}, nil
		}
	}
	got, err := widenForRememberMe(context.Background(), f.ops(), nil)
	if err == nil {
		t.Fatalf("a confirmation read that crossed the phase deadline must not be accepted (got %+v)", got)
	}
	if !strings.Contains(err.Error(), "仍为") {
		t.Fatalf("err = %v, want the settle-phase failure named", err)
	}
	if !got.Applied {
		t.Fatal("the emulation was applied, so a restore must be registered")
	}
}
