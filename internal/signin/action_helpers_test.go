package signin

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/input"
)

func TestActionCheckedErrorsAndCancellation(t *testing.T) {
	boom := errors.New("evaluation failed")
	for _, tc := range []struct {
		name   string
		code   int
		err    error
		cancel bool
	}{
		{"success", 1, nil, false}, {"absent", 0, nil, false}, {"evaluation", 1, boom, false}, {"cancel", 1, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err := checkedAction(ctx, "test", "", func(_ context.Context, _ string, out any) error {
				*(out.(*int)) = tc.code
				if tc.cancel {
					cancel()
				}
				return tc.err
			})
			if (err == nil) != (tc.code == 1 && tc.err == nil && !tc.cancel) {
				t.Fatalf("error=%v", err)
			}
			if tc.err != nil && !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if tc.cancel && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkedAction(ctx, "test", "", func(context.Context, string, any) error { t.Fatal("evaluated canceled action"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestActionMouseErrorsStopSequence(t *testing.T) {
	boom := errors.New("CDP failed")
	for fail := 0; fail < 3; fail++ {
		count := 0
		err := mouseClickWith(context.Background(), 10, 20, nil, func(context.Context, input.MouseType, float64, float64) error {
			n := count
			count++
			if n == fail {
				return boom
			}
			return nil
		}, func(context.Context, time.Duration) error { return nil })
		if !errors.Is(err, boom) || count != fail+1 {
			t.Fatalf("fail=%d count=%d err=%v", fail, count, err)
		}
	}
	for _, x := range []float64{-1, math.NaN(), math.Inf(1)} {
		if err := mouseClickWith(context.Background(), x, 1, nil, func(context.Context, input.MouseType, float64, float64) error {
			t.Fatal("invalid point dispatched")
			return nil
		}, nil); err == nil {
			t.Fatal("invalid point accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	err := mouseClickWith(ctx, 1, 2, nil, func(context.Context, input.MouseType, float64, float64) error { count++; return nil }, func(context.Context, time.Duration) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestActionSignRechecksAndNeverFallsBack(t *testing.T) {
	for _, mode := range []string{"absent", "error", "changed", "cancel", "ok"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, events := 0, 0
			err := clickSignWith(ctx, func(_ context.Context, expr string, out any) error {
				reads++
				if expr != signTargetJS {
					t.Fatal("unexpected evaluator")
				}
				if mode == "error" {
					return errors.New("read error")
				}
				p := []float64{10, 20}
				if mode == "absent" {
					p = nil
				}
				if mode == "changed" && reads > 1 {
					p = []float64{20, 30}
				}
				*(out.(*[]float64)) = p
				if mode == "cancel" {
					cancel()
				}
				return nil
			}, func(context.Context, input.MouseType, float64, float64) error { events++; return nil }, func(context.Context, time.Duration) error { return nil })
			if mode == "ok" {
				if err != nil || events != 3 || reads != 4 {
					t.Fatalf("reads=%d events=%d err=%v", reads, events, err)
				}
			} else if err == nil || events != 0 {
				t.Fatalf("events=%d err=%v", events, err)
			}
		})
	}
}

func TestActionScriptsRequireTrustedHitTargets(t *testing.T) {
	for _, part := range []string{"u.protocol!=='https:'", "u.hostname!=='xsfw.gzist.edu.cn'", "u.username||u.password", "u.port!=='443'", "查寝时间段", "candidates.length!==1", "actionable(e)"} {
		if !strings.Contains(signTargetJS, part) {
			t.Errorf("missing %s", part)
		}
	}
	for _, part := range []string{"isConnected", ":disabled", "[inert]", "getBoundingClientRect", "elementFromPoint", "e.contains(hit)", "innerWidth"} {
		if !strings.Contains(actionTargetJS, part) {
			t.Errorf("missing %s", part)
		}
	}
	if strings.Contains(clickLoginButtonJS, "ant-btn-primary") {
		t.Fatal("generic login fallback")
	}
	if strings.Contains(signTargetJS, ".click()") {
		t.Fatal("sign must preserve trusted CDP gesture")
	}
}

func TestActionLoginCheckedFailureStopsWithoutRetry(t *testing.T) {
	for _, stage := range []string{"credentials", "captcha", "submit"} {
		t.Run(stage, func(t *testing.T) {
			p := newFakeLoginPage()
			r := p.runner(8)
			writes, submits := 0, 0
			r.driver.fillChecked = func(_ context.Context, sel, val string) error {
				writes++
				if stage == "credentials" || (stage == "captcha" && sel == "#captcha") {
					return errors.New("secret-value-evaluation-error")
				}
				return nil
			}
			r.driver.submitChecked = func(context.Context) error { submits++; return errors.New("secret-value-evaluation-error") }
			ok := false
			res := r.autoLogin(context.Background(), &ok)
			if ok || res.OK || res.Exit == 0 || p.clicks != 0 || p.refreshes != 0 {
				t.Fatalf("result=%+v clicks=%d refreshes=%d", res, p.clicks, p.refreshes)
			}
			if stage == "submit" && submits != 1 {
				t.Fatalf("submits=%d", submits)
			}
			if stage != "submit" && submits != 0 {
				t.Fatalf("submits=%d", submits)
			}
			if stage == "credentials" && writes != 1 {
				t.Fatalf("writes=%d", writes)
			}
			if strings.Contains(res.Reason+strings.Join(p.logs, ""), "secret-value") {
				t.Fatal("error content leaked")
			}
		})
	}
}
