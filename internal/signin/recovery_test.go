package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoginActionsAreCASBoundAndSingleClick(t *testing.T) {
	for _, js := range []string{refreshLoginCaptchaJS, clickLoginButtonJS} {
		if !strings.Contains(js, casPageGuardJS) || !strings.Contains(js, casVisibleFormJS) || strings.Count(js, ".click()") != 1 || strings.Contains(js, "dispatchEvent") {
			t.Fatal("login action lost atomic CAS/form guard or single-click bound")
		}
	}
}

func TestRecoverySharesRetryDeadline(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var navDeadline time.Time
	original := f.ops.navigate
	f.ops.navigate = func(c context.Context, target string) error {
		navDeadline, _ = c.Deadline()
		return original(c, target)
	}
	f.ops.wait = func(c context.Context, b time.Duration, p func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
		d, ok := c.Deadline()
		if !ok || !d.Equal(navDeadline) {
			t.Fatal("retry budget reset after navigation")
		}
		parentDeadline, _ := ctx.Deadline()
		if d.After(parentDeadline) {
			t.Fatal("recovery exceeded parent deadline")
		}
		return pageState{URL: recoveryTestURL, Text: "签到成功"}, 0, nil
	}
	if _, _, err := f.run(ctx); err != nil {
		t.Fatal(err)
	}
}

const recoveryTestURL = "https://xsfw.gzist.edu.cn/xsfw/sys/swmzncqapp/*default/index.do#/xscq/grcq"

type recoveryFixture struct {
	now, deadline                time.Time
	last, fresh                  pageState
	ops                          recoveryOps
	nav, waits, evidence, logins int
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	f := &recoveryFixture{now: time.Now(), last: pageState{URL: recoveryTestURL, Text: "个人查寝"}}
	f.deadline = f.now.Add(time.Hour)
	f.fresh = f.last
	f.ops = recoveryOps{
		now:   func() time.Time { return f.now },
		probe: func(context.Context) (pageState, error) { return f.fresh, nil },
		evidence: func(c context.Context) {
			f.evidence++
			if d, ok := c.Deadline(); !ok || time.Until(d) > 11*time.Second {
				t.Fatal("unbounded evidence")
			}
		},
		navigate: func(c context.Context, target string) error {
			f.nav++
			if f.evidence != 1 || target != recoveryTestURL {
				t.Fatal("wrong order/target")
			}
			if d, ok := c.Deadline(); !ok || time.Until(d) > pageWaitBudget {
				t.Fatal("unbounded recovery")
			}
			return nil
		},
		form:  func(context.Context) (bool, error) { return true, nil },
		login: func(context.Context) Result { f.logins++; return Result{OK: true} },
		wait: func(c context.Context, b time.Duration, p func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
			f.waits++
			return pageState{URL: recoveryTestURL, Text: "签到成功"}, time.Second, nil
		},
	}
	return f
}
func (f *recoveryFixture) run(ctx context.Context) (pageState, time.Duration, error) {
	return recoverBusinessPage(ctx, f.deadline, recoveryTestURL, true, f.last, pageWaitBudget, context.DeadlineExceeded, f.ops)
}
func TestRecoveryStableAndCASURLs(t *testing.T) {
	for _, u := range []string{recoveryTestURL, "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq"} {
		if !stableRecoveryURL(u) {
			t.Fatal("reject stable")
		}
	}
	for _, u := range []string{"http://xsfw.gzist.edu.cn/index.do#/xscq/grcq", "https://xsfw.gzist.edu.cn/index.do?ticket=fake#/xscq/grcq", "https://xsfw.gzist.edu.cn/index.do?%74icket=fake#/xscq/grcq", "https://xsfw.gzist.edu.cn/index.do?#/xscq/grcq", "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq?ticket=fake", "https://xsfw.gzist.edu.cn/index.do#/wrong", "https://xsfw.gzist.edu.cn/submit#/xscq/grcq", "https://user@xsfw.gzist.edu.cn/index.do#/xscq/grcq", "https://xsfw.gzist.edu.cn:444/index.do#/xscq/grcq", "https://xsfw.gzist.edu.cn.evil.invalid/index.do#/xscq/grcq", "https://xsfw.gzist.edu.cn@evil.invalid/index.do#/xscq/grcq"} {
		if stableRecoveryURL(u) {
			t.Fatal("accept unsafe stable", u)
		}
	}
	for _, u := range []string{"https://ids.gzist.edu.cn/lyuapServer/login?service=example", "https://ids.gzist.edu.cn/authserver/login"} {
		if !casLoginURL(u) {
			t.Fatal("reject CAS")
		}
	}
	for _, u := range []string{"http://ids.gzist.edu.cn/lyuapServer/login", "https://ids.gzist.edu.cn.evil.invalid/lyuapServer/login", "https://user@ids.gzist.edu.cn/lyuapServer/login", "https://ids.gzist.edu.cn:444/authserver/login", "https://ids.gzist.edu.cn/unrelated"} {
		if casLoginURL(u) {
			t.Fatal("accept unsafe CAS")
		}
	}
}
func TestRecoveryEligibility(t *testing.T) {
	for _, name := range []string{"full timeout", "short timeout", "non timeout", "ready", "signed", "wrong host", "parent canceled", "late", "unsafe target"} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			elapsed := pageWaitBudget
			firstErr := error(context.DeadlineExceeded)
			target := recoveryTestURL
			switch name {
			case "short timeout":
				elapsed -= time.Second
			case "non timeout":
				firstErr = errors.New("fake failure")
			case "ready":
				firstErr = nil
			case "signed":
				f.last.Text = "签到成功"
			case "wrong host":
				f.last.URL = "https://evil.invalid/"
			case "parent canceled":
				cancel()
			case "late":
				f.now = f.deadline
			case "unsafe target":
				target = "https://xsfw.gzist.edu.cn/index.do?ticket=fake#/xscq/grcq"
			}
			_, _, err := recoverBusinessPage(ctx, f.deadline, target, true, f.last, elapsed, firstErr, f.ops)
			want := 0
			if name == "full timeout" {
				want = 1
				if err != nil {
					t.Fatal(err)
				}
			}
			if f.nav != want || f.waits != want {
				t.Fatalf("nav=%d waits=%d want=%d", f.nav, f.waits, want)
			}
			if (name == "parent canceled" || name == "late") && f.evidence != 0 {
				t.Fatal("work after stop")
			}
		})
	}
}
func TestRecoverySingleAttempt(t *testing.T) {
	for _, name := range []string{"second timeout", "navigate failure"} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t)
			if name == "navigate failure" {
				f.ops.navigate = func(context.Context, string) error { f.nav++; return errors.New("fake error") }
			}
			f.ops.wait = func(context.Context, time.Duration, func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
				f.waits++
				return f.last, pageWaitBudget, context.DeadlineExceeded
			}
			_, _, err := f.run(context.Background())
			if err == nil || f.nav != 1 || f.waits > 1 {
				t.Fatalf("err=%v nav=%d waits=%d", err, f.nav, f.waits)
			}
		})
	}
}
func TestRecoveryStopBeforeNavigation(t *testing.T) {
	for _, phase := range []string{"evidence cancel", "probe cancel", "evidence late", "probe late", "probe error", "probe unknown host"} {
		t.Run(phase, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			evidence := f.ops.evidence
			f.ops.evidence = func(c context.Context) {
				evidence(c)
				if phase == "evidence cancel" {
					cancel()
				}
				if phase == "evidence late" {
					f.now = f.deadline
				}
			}
			f.ops.probe = func(context.Context) (pageState, error) {
				if phase == "probe cancel" {
					cancel()
				}
				if phase == "probe late" {
					f.now = f.deadline
				}
				if phase == "probe error" {
					return pageState{}, errors.New("fake probe")
				}
				if phase == "probe unknown host" {
					return pageState{URL: "https://evil.invalid/"}, nil
				}
				return f.last, nil
			}
			_, _, err := f.run(ctx)
			if err == nil || f.nav != 0 {
				t.Fatal("unsafe navigation", err, f.nav)
			}
		})
	}
}
func TestRecoveryFreshSuccess(t *testing.T) {
	for _, text := range successKws {
		t.Run(text, func(t *testing.T) {
			f := newRecoveryFixture(t)
			f.fresh.Text = text
			last, _, err := f.run(context.Background())
			if err != nil || last.Text != text || f.nav != 0 {
				t.Fatal("lost success")
			}
		})
	}
}
func TestRecoveryCASLoginBoundaries(t *testing.T) {
	for _, name := range []string{"success", "failure", "hidden", "manual", "unknown", "login cancellation", "login late"} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cas := pageState{URL: "https://ids.gzist.edu.cn/lyuapServer/login", Text: "签到成功"}
			reads := 0
			f.ops.probe = func(context.Context) (pageState, error) {
				if f.nav == 0 {
					return f.last, nil
				}
				if name == "unknown" {
					return pageState{URL: "https://evil.invalid/", Text: "签到成功"}, nil
				}
				if f.logins > 0 {
					reads++
					if reads > 1 {
						return pageState{URL: recoveryTestURL, Text: "签到成功"}, nil
					}
				}
				return cas, nil
			}
			f.ops.form = func(context.Context) (bool, error) { return name != "hidden", nil }
			f.ops.login = func(context.Context) Result {
				f.logins++
				if name == "login cancellation" {
					cancel()
				}
				if name == "login late" {
					f.now = f.deadline
				}
				return Result{OK: name != "failure"}
			}
			f.ops.wait = func(c context.Context, b time.Duration, p func(context.Context) (pageState, error)) (pageState, time.Duration, error) {
				f.waits++
				for i := 0; i < 5; i++ {
					s, err := p(c)
					if err != nil {
						return s, 0, err
					}
					if ready, _ := pageWaitPolicy(s, 0, true); ready {
						return s, 0, nil
					}
				}
				return pageState{}, 0, context.DeadlineExceeded
			}
			_, _, err := recoverBusinessPage(ctx, f.deadline, recoveryTestURL, name != "manual", f.last, pageWaitBudget, context.DeadlineExceeded, f.ops)
			wantLogin := 1
			if name == "hidden" || name == "manual" || name == "unknown" {
				wantLogin = 0
			}
			if f.logins != wantLogin || f.nav != 1 {
				t.Fatalf("logins=%d nav=%d", f.logins, f.nav)
			}
			if (err == nil) != (name == "success") {
				t.Fatal("unexpected result", err)
			}
		})
	}
}
func TestRecoveryWaitAndRejection(t *testing.T) {
	for _, text := range successKws {
		ready, repair := pageWaitPolicy(pageState{URL: recoveryTestURL, Text: text}, pageWaitBudget, false)
		if !ready || repair {
			t.Fatal("success not ready")
		}
	}
	if ready, _ := pageWaitPolicy(pageState{URL: "https://evil.invalid/?service=xsfw.gzist.edu.cn", Text: "查寝时间段 点击签到 签到成功"}, pageWaitBudget, false); ready {
		t.Fatal("spoofed success")
	}
	for _, text := range []string{"密码错误", "用户名或密码不正确", "用户名或密码有误", "账号或密码错误", "账户已锁定", "账号被锁定"} {
		if !loginRejected(text) {
			t.Fatal("rejection ignored")
		}
	}
	if loginRejected("验证码错误") {
		t.Fatal("captcha classified as password")
	}
}
