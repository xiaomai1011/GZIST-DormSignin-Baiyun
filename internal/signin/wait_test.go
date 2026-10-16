package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

func TestPageWaitPolicySlowPage(t *testing.T) {
	for _, text := range []string{"", "学工系统 页面外壳", "点击签到"} {
		for _, second := range []int{0, 3, 10, 25, 40, 45, 75, 119} {
			ready, repair := pageWaitPolicy(pageState{"https://xsfw.gzist.edu.cn/index.do#/xscq/grcq", text}, time.Duration(second)*time.Second, false)
			if ready || repair {
				t.Fatalf("slow page at %ds: ready=%v repair=%v", second, ready, repair)
			}
		}
	}
	if pageWaitBudget != 120*time.Second {
		t.Fatal("full budget must be 120 seconds")
	}
}

func TestPageWaitPolicyRouteRepair(t *testing.T) {
	cases := []struct {
		name, url      string
		elapsed        time.Duration
		repaired, want bool
	}{
		{"missing", "https://xsfw.gzist.edu.cn/index.do", 3 * time.Second, false, true},
		{"too early", "https://xsfw.gzist.edu.cn/index.do", 2 * time.Second, false, false},
		{"only once", "https://xsfw.gzist.edu.cn/index.do", 119 * time.Second, true, false},
		{"CAS", "https://ids.gzist.edu.cn/?service=https://xsfw.gzist.edu.cn", 100 * time.Second, false, false},
		{"spoof host", "https://xsfw.gzist.edu.cn.example.org/", 100 * time.Second, false, false},
		{"invalid", "://", 100 * time.Second, false, false},
		{"unknown", "", 100 * time.Second, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ready, repair := pageWaitPolicy(pageState{URL: tc.url}, tc.elapsed, tc.repaired)
			if ready || repair != tc.want {
				t.Fatalf("ready=%v repair=%v want=%v", ready, repair, tc.want)
			}
		})
	}
	for _, text := range []string{"查寝时间段 点击签到", "无需重复签到"} {
		ready, repair := pageWaitPolicy(pageState{"https://xsfw.gzist.edu.cn/", text}, 119*time.Second, false)
		if !ready || repair {
			t.Fatalf("ready page: %v %v", ready, repair)
		}
	}
}

func TestWaitBusinessPageFullBudget(t *testing.T) {
	const budget = 60 * time.Millisecond
	repairs := 0
	calls := 0
	_, elapsed, err := waitBusinessPage(context.Background(), budget, time.Millisecond,
		func(context.Context) (pageState, error) {
			calls++
			return pageState{URL: "https://xsfw.gzist.edu.cn/#/xscq/grcq", Text: "外壳"}, nil
		},
		func(context.Context) error { repairs++; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || elapsed < budget || repairs != 0 || calls == 0 {
		t.Fatalf("elapsed=%v error=%v repairs=%d calls=%d", elapsed, err, repairs, calls)
	}
}

func TestWaitBusinessPageSlowSuccess(t *testing.T) {
	start := time.Now()
	_, elapsed, err := waitBusinessPage(context.Background(), time.Second, time.Millisecond,
		func(context.Context) (pageState, error) {
			text := "外壳"
			if time.Since(start) >= 60*time.Millisecond {
				text = "查寝时间段 点击签到"
			}
			return pageState{URL: "https://xsfw.gzist.edu.cn/#/xscq/grcq", Text: text}, nil
		}, func(context.Context) error { t.Fatal("must not repair a slow correct route"); return nil })
	if err != nil || elapsed < 60*time.Millisecond {
		t.Fatalf("elapsed=%v error=%v", elapsed, err)
	}
}

func TestWaitBusinessPageCancellationAndBlockedProbe(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, err := waitBusinessPage(ctx, time.Second, time.Millisecond,
			func(context.Context) (pageState, error) { t.Fatal("probe after cancellation"); return pageState{}, nil }, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("cancel during probe", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		_, elapsed, err := waitBusinessPage(ctx, time.Second, time.Millisecond,
			func(ctx context.Context) (pageState, error) { cancel(); <-ctx.Done(); return pageState{}, ctx.Err() }, nil)
		if !errors.Is(err, context.Canceled) || elapsed >= time.Second {
			t.Fatalf("%v %v", elapsed, err)
		}
	})
	t.Run("blocked probe is bounded", func(t *testing.T) {
		_, elapsed, err := waitBusinessPage(context.Background(), 30*time.Millisecond, time.Millisecond,
			func(ctx context.Context) (pageState, error) { <-ctx.Done(); return pageState{}, ctx.Err() }, nil)
		if !errors.Is(err, context.DeadlineExceeded) || elapsed >= time.Second {
			t.Fatalf("%v %v", elapsed, err)
		}
	})
}

func TestWaitBusinessPageErrorReason(t *testing.T) {
	_, elapsed, err := waitBusinessPage(context.Background(), 20*time.Millisecond, time.Millisecond,
		func(context.Context) (pageState, error) { return pageState{}, errors.New("CDP probe failed") }, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "operation-failed") {
		t.Fatal(err)
	}
	result := pageWaitFailure(elapsed, err)
	if strings.Contains(result.Reason, "120s") || !strings.Contains(result.Reason, "实际耗时") || !strings.Contains(result.Reason, "operation-failed") {
		t.Fatal(result)
	}
}

type testExecutor struct{}

func (*testExecutor) Execute(context.Context, string, any, any) error { return nil }

func TestRunContextPreservesBrowserAndCancellation(t *testing.T) {
	browser, closeBrowser := chromedp.NewContext(context.Background())
	defer closeBrowser()
	executor := &testExecutor{}
	browser = cdp.WithExecutor(browser, executor)
	caller, cancelCaller := context.WithCancelCause(context.Background())
	ctx, cleanup := runContext(caller, browser, time.Minute)
	defer cleanup()
	if chromedp.FromContext(ctx) != chromedp.FromContext(browser) || cdp.ExecutorFromContext(ctx) != executor {
		t.Fatal("lost browser context/executor")
	}
	cause := errors.New("caller stopped")
	cancelCaller(cause)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("caller cancellation dropped")
	}
	if !errors.Is(context.Cause(ctx), cause) {
		t.Fatal(context.Cause(ctx))
	}
	if browser.Err() != nil {
		t.Fatal("canceled the original browser context")
	}
}

func TestRunContextCancellationSources(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		caller, cancel := context.WithCancel(context.Background())
		cancel()
		ctx, cleanup := runContext(caller, context.Background(), time.Minute)
		defer cleanup()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal(ctx.Err())
		}
	})
	t.Run("caller deadline", func(t *testing.T) {
		caller, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		ctx, cleanup := runContext(caller, context.Background(), time.Minute)
		defer cleanup()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("deadline dropped")
		}
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatal(context.Cause(ctx))
		}
	})
	t.Run("browser canceled", func(t *testing.T) {
		browser, cancel := context.WithCancel(context.Background())
		ctx, cleanup := runContext(context.Background(), browser, time.Minute)
		defer cleanup()
		cancel()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal(ctx.Err())
		}
	})
	t.Run("run budget", func(t *testing.T) {
		ctx, cleanup := runContext(context.Background(), context.Background(), time.Millisecond)
		defer cleanup()
		<-ctx.Done()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal(ctx.Err())
		}
	})
	t.Run("cleanup", func(t *testing.T) {
		ctx, cleanup := runContext(context.Background(), context.Background(), time.Minute)
		cleanup()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal(ctx.Err())
		}
	})
}

func TestWaitBusinessPageRepairAtMostOnce(t *testing.T) {
	repairs := 0
	_, elapsed, err := waitBusinessPage(context.Background(), 3100*time.Millisecond, time.Millisecond,
		func(context.Context) (pageState, error) {
			return pageState{URL: "https://xsfw.gzist.edu.cn/index.do", Text: "外壳"}, nil
		}, func(context.Context) error {
			repairs++
			return errors.New("route repair failed")
		})
	if repairs != 1 || elapsed < 3100*time.Millisecond || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "operation-failed") {
		t.Fatalf("repairs=%d elapsed=%v err=%v", repairs, elapsed, err)
	}
}

func TestRunAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := (&Runner{}).Run(ctx, true)
	if result.OK || !strings.Contains(result.Reason, "context canceled") {
		t.Fatal(result)
	}
}
