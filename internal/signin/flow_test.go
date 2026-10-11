package signin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoginFormMustRemainVisible(t *testing.T) {
	start := time.Date(2026, 10, 10, 21, 30, 0, 0, time.UTC)
	var form formVisibility
	if form.stable(start.Add(29*time.Second), true) {
		t.Fatal("late form prematurely accepted")
	}
	if form.stable(start.Add(32*time.Second), true) {
		t.Fatal("less than four seconds")
	}
	if !form.stable(start.Add(33*time.Second), true) {
		t.Fatal("four seconds not accepted")
	}
	form.stable(start.Add(34*time.Second), false)
	if form.stable(start.Add(40*time.Second), true) {
		t.Fatal("disappearance failed to reset stability timer")
	}
}

func TestLateLineCancelsSubmissionObservation(t *testing.T) {
	ctx, cancel := beforeLateLine(context.Background(), time.Now().Add(20*time.Millisecond))
	defer cancel()
	_, _, err := waitSignResult(ctx, time.Second, time.Millisecond, func(context.Context) string { return "等待结果" }, func(context.Context, int) { t.Fatal("unexpected captcha") })
	if !errors.Is(err, errLateLine) {
		t.Fatalf("lost late-line cause: %v", err)
	}
	result := canceledResult(ctx)
	if result.Exit != 8 || !result.Neutral {
		t.Fatalf("late line result: %#v", result)
	}
}

func TestSignObservationHandlesDelayedCaptcha(t *testing.T) {
	reads, handled := 0, 0
	hit, _, err := waitSignResult(context.Background(), time.Second, time.Millisecond, func(context.Context) string {
		reads++
		if reads < 3 {
			return "处理中"
		}
		if handled == 0 {
			return "请输入验证码"
		}
		return "签到成功"
	}, func(context.Context, int) { handled++ })
	if err != nil || hit != "签到成功" || handled != 1 {
		t.Fatalf("hit=%q handled=%d err=%v", hit, handled, err)
	}
}

func TestSignObservationCapsFailedCaptchaAttempts(t *testing.T) {
	attempts := 0
	_, _, err := waitSignResult(context.Background(), 30*time.Millisecond, time.Millisecond,
		func(context.Context) string { return "验证码" }, func(_ context.Context, n int) {
			attempts++
			if n != attempts {
				t.Fatal(n, attempts)
			}
		})
	if !errors.Is(err, context.DeadlineExceeded) || attempts != 3 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestSignObservationCanceledDoesNotSubmit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := waitSignResult(ctx, time.Second, time.Millisecond, func(context.Context) string { t.Fatal("read after cancellation"); return "" }, func(context.Context, int) { t.Fatal("submitted after cancellation") })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
