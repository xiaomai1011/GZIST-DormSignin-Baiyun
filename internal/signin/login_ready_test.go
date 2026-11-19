package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func readyTestOps() loginPageOps {
	c := newFakeClock()
	return loginPageOps{now: c.now, sleep: c.sleep,
		probe: func(context.Context) (pageState, error) { return pageState{URL: testCasFormURL}, nil },
		form:  func(context.Context) (bool, error) { return true, nil }}
}

func TestLoginReadyStates(t *testing.T) {
	for _, tc := range []struct {
		name, url string
		visible   bool
		want      loginReadyVerdict
	}{
		{"form", testCasFormURL, true, loginReadyForm},
		{"missing", testCasFormURL, false, loginReadyMissing},
		{"business", testBusinessURL, true, loginReadyBusiness},
		{"twoverify", testTwoVerifyURL, true, loginReadyTwoVerify},
		{"untrusted", "https://example.invalid/?secret=private", true, loginReadyUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := readyTestOps()
			forms := 0
			ops.probe = func(context.Context) (pageState, error) { return pageState{URL: tc.url, Text: "private"}, nil }
			ops.form = func(context.Context) (bool, error) { forms++; return tc.visible, nil }
			got, d := waitLoginReady(context.Background(), ops, time.Second, 0)
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			if tc.url != testCasFormURL && forms != 0 {
				t.Fatal("form read on non-login page")
			}
			if strings.Contains(loginReadyLine("pre_form", got, d), "private") {
				t.Fatal("private log")
			}
		})
	}
}

func TestLoginReadyReadFailuresAndCancelPriority(t *testing.T) {
	for _, stage := range []string{"probe", "form"} {
		for _, mode := range []string{"error", "timeout", "cancel", "late_true"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ops := readyTestOps()
				originalNow := ops.now
				shift := time.Duration(0)
				ops.now = func() time.Time { return originalNow().Add(shift) }
				read := func(child context.Context) error {
					if child == ctx {
						t.Fatal("read did not receive child context")
					}
					if _, ok := child.Deadline(); !ok {
						t.Fatal("no read deadline")
					}
					switch mode {
					case "cancel":
						cancel()
						return nil
					case "late_true":
						shift = time.Minute
						return nil
					case "timeout":
						return context.DeadlineExceeded
					default:
						return errors.New("private URL/body")
					}
				}
				if stage == "probe" {
					ops.probe = func(c context.Context) (pageState, error) { return pageState{URL: testBusinessURL}, read(c) }
				} else {
					ops.form = func(c context.Context) (bool, error) { return true, read(c) }
				}
				got, d := waitLoginReady(ctx, ops, 30*time.Second, 0)
				want := loginReadyReadFailed
				if mode == "cancel" {
					want = loginReadyCanceled
				}
				if got != want {
					t.Fatalf("got %s want %s", got, want)
				}
				if mode != "cancel" && d.ReadErrors != 1 {
					t.Fatalf("diag %+v", d)
				}
			})
		}
	}
}

func TestLoginReadyStableGrace(t *testing.T) {
	ops := readyTestOps()
	start := ops.now()
	got, _ := waitLoginReady(context.Background(), ops, 30*time.Second, 4*time.Second)
	if got != loginReadyForm || ops.now().Sub(start) < 4*time.Second {
		t.Fatalf("got %s elapsed %v", got, ops.now().Sub(start))
	}
}

func TestLoginReadyFailureResults(t *testing.T) {
	r := &Runner{}
	for _, v := range []loginReadyVerdict{loginReadyReadFailed, loginReadyMissing, loginReadyUntrusted} {
		ok := false
		got := r.finishLoginReady(context.Background(), readyTestOps(), &ok, v)
		if got.OK || ok || (got.Exit != 3 && got.Exit != 9) {
			t.Fatalf("%s: %+v", v, got)
		}
		want := AuthUnknown
		if v == loginReadyReadFailed {
			want = AuthNetwork
		}
		if got.AuthIssue != want {
			t.Fatalf("%s: %+v", v, got)
		}
	}
}

func TestLoginReadyFlowStopsBeforeWrites(t *testing.T) {
	for _, mode := range []string{"missing", "form_error", "probe_error", "cancel_form", "business"} {
		t.Run(mode, func(t *testing.T) {
			p := newFakeLoginPage()
			r := p.runner(3)
			d := p.driver()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing":
				d.ops.form = func(context.Context) (bool, error) { return false, nil }
			case "form_error":
				d.ops.form = func(context.Context) (bool, error) { return true, errors.New("read failed") }
			case "probe_error":
				d.ops.probe = func(context.Context) (pageState, error) { return pageState{}, context.DeadlineExceeded }
			case "cancel_form":
				d.ops.form = func(context.Context) (bool, error) { cancel(); return true, nil }
			case "business":
				p.business = true
			}
			ok := false
			res := r.autoLoginWith(ctx, &ok, d)
			if p.fills != 0 || p.clicks != 0 || p.solves != 0 {
				t.Fatalf("writes fills=%d clicks=%d solves=%d", p.fills, p.clicks, p.solves)
			}
			if mode == "business" {
				if !ok || !res.OK {
					t.Fatalf("business %+v", res)
				}
			} else if res.OK || res.Exit == 0 {
				t.Fatalf("%s: %+v", mode, res)
			}
		})
	}
}
