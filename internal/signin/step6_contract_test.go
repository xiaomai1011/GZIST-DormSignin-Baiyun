package signin

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// A reached manual verification must hand the run back, not end it. That is the
// coupling the 2026-10-25 log left unexplained: the run reached step 6 instead
// of returning a failure, and nothing in the log showed what happened next.
// These tests pin the contract that makes step 6 reachable at all.

func manualOpsReached() loginPageOps {
	return loginPageOps{
		now:   time.Now,
		sleep: func(ctx context.Context, d time.Duration) error { return ctx.Err() },
		probe: func(context.Context) (pageState, error) {
			// A business page with the sign-in card is what "reached" means.
			return pageState{
				URL:  "https://xsfw.gzist.edu.cn/#/xscq/grcq",
				Text: "查寝时间段 点击签到",
			}, nil
		},
		form:  func(context.Context) (bool, error) { return false, nil },
		issue: func(context.Context) AuthIssue { return AuthNone },
	}
}

func TestManualVerificationReachedKeepsTheRunAlive(t *testing.T) {
	var logs []string
	cfg := store.Defaults()
	cfg.VisibleBrowser = true
	r := &Runner{Cfg: cfg, Log: func(s string) { logs = append(logs, s) }}
	loginOK := false

	res, handled := r.manualVerification(context.Background(), manualOpsReached(), &loginOK)

	if !handled {
		t.Fatal("a visible run must handle the two-factor page itself, not fall through to a failure result")
	}
	if !res.OK {
		t.Fatalf("reached must not produce a failing result (that would end the run before step 6): %+v", res)
	}
	if !loginOK {
		t.Fatal("loginOK must be set: it is what tells Run the login already happened")
	}
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "继续业务页就绪检查与签到（仅此一次）") {
		t.Fatalf("log does not say the run continues into step 6: %q", logs)
	}
}

func TestManualVerificationHiddenModeDoesNotWait(t *testing.T) {
	cfg := store.Defaults()
	cfg.VisibleBrowser = false
	r := &Runner{Cfg: cfg}
	loginOK := false
	probes := 0
	ops := manualOpsReached()
	ops.probe = func(context.Context) (pageState, error) { probes++; return pageState{}, nil }

	if _, handled := r.manualVerification(context.Background(), ops, &loginOK); handled {
		t.Fatal("hidden mode has no window to hand to a person: it must keep the previous stop behaviour")
	}
	if probes != 0 {
		t.Fatalf("hidden mode read the page %d times, want 0", probes)
	}
	if loginOK {
		t.Fatal("hidden mode must not claim the login happened")
	}
}

// The wait behind step 6 must be able to finish when the page eventually becomes
// ready, without any budget change: this is the "slow page" case that a silent
// wait made indistinguishable from a stuck run.
func TestStep6WaitFinishesOnALateReadyPage(t *testing.T) {
	polls := 0
	opts := waitOptions{budget: 2 * time.Second, poll: time.Millisecond}
	last, elapsed, err := waitBusinessPageWith(context.Background(), opts,
		func(context.Context) (pageState, error) {
			polls++
			if polls < 5 {
				return pageState{URL: "https://xsfw.gzist.edu.cn/#/xscq/grcq", Text: "加载中"}, nil
			}
			return pageState{URL: "https://xsfw.gzist.edu.cn/#/xscq/grcq", Text: "查寝时间段 点击签到"}, nil
		},
		func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("a page that becomes ready inside the budget must succeed: %v", err)
	}
	if !strings.Contains(last.Text, "查寝时间段") {
		t.Fatalf("last snapshot = %+v, want the ready page", last)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed = %v, want inside the unchanged budget", elapsed)
	}
}
