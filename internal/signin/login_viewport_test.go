package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The login flow may only change the viewport when the caller asked for the
// checkbox and the page is the trusted login page; it must do so before any
// field is filled, and it must put the original metrics back before it returns —
// including when the login ends in a stop. These tests drive the scripted login
// page, so no browser and no network are involved.

// 1. The widen happens before the fields are filled, the box is ticked on the
// desktop layout, and the page is restored before the login is reported as
// finished.
func TestWidenHappensBeforeFillingAndIsRestored(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.widenCalls != 1 {
		t.Fatalf("widen calls = %d, want exactly 1", p.widenCalls)
	}
	if !p.widenBeforeFill {
		t.Fatal("the viewport was changed after a field was filled, want before")
	}
	if p.restoreCalls != 1 {
		t.Fatalf("restore calls = %d, want exactly 1 before the run continues", p.restoreCalls)
	}
	if !hasLog(p.logs, "已切到桌面宽度") {
		t.Fatalf("log does not report the widened login page: %q", p.logs)
	}
	if !hasLog(p.logs, "已恢复原视口 430x900") {
		t.Fatalf("log does not report the restore: %q", p.logs)
	}
	if p.clicks != 1 {
		t.Fatalf("clicks = %d, want 1: the viewport change must not add a submission", p.clicks)
	}
}

// 2. With the setting off, the page layout is not touched at all.
func TestNoWidenWhenRememberPasswordIsOff(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.widenCalls != 0 || p.restoreCalls != 0 {
		t.Fatalf("widen/restore = %d/%d, want 0/0 with the setting off", p.widenCalls, p.restoreCalls)
	}
}

// 3. Off the trusted login page the layout is left alone: the widen is a login
// page affordance, not a general one.
func TestNoWidenOutsideTheTrustedLoginPage(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.pageURL = testCasOtherURL
	p.landAfter = time.Second

	p.submitFlow(t, 1, nil)
	if p.widenCalls != 0 {
		t.Fatalf("widen calls = %d, want 0 on a non-login page", p.widenCalls)
	}
	if p.clicks != 0 || p.fills != 0 || p.solves != 0 {
		t.Fatalf("untrusted page received writes: clicks=%d fills=%d solves=%d", p.clicks, p.fills, p.solves)
	}
	if !hasLog(p.logs, "stage=pre_form verdict=untrusted") {
		t.Fatalf("log does not report the untrusted pre-form stop: %q", p.logs)
	}
}

// 4. A success that cannot hand back the original viewport must not be reported
// as a success: the business page would then be laid out at unknown metrics.
func TestRestoreFailureDoesNotLetASuccessStand(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second
	p.restoreErr = errors.New("视口未恢复")

	res, loginOK := p.submitFlow(t, 1, nil)
	if res.OK {
		t.Fatalf("run reported success with an unrestored viewport: %+v", res)
	}
	// The success flag is the other half of the contract: Run() decides whether to
	// go on with the sign-in from it, so an unresolvable viewport has to withdraw it
	// too, not only the Result.
	if loginOK {
		t.Fatalf("loginOK was left true with an unrestored viewport (res=%+v)", res)
	}
	if res.Exit != 9 {
		t.Fatalf("exit = %d, want 9 for a page that cannot be trusted (res=%+v logs=%q)", res.Exit, res, p.logs)
	}
	if !strings.Contains(res.Reason, "恢复原视口失败") {
		t.Fatalf("reason = %q, want the restore failure named", res.Reason)
	}
	if !hasLog(p.logs, "恢复原视口失败") {
		t.Fatalf("log does not report the restore failure: %q", p.logs)
	}
}

// 5. When the run is stopped anyway, the restore failure is logged but cannot
// overwrite the reason the run really stopped for.
func TestRestoreFailureKeepsAnEarlierStop(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second
	p.restoreErr = errors.New("视口未恢复")

	res, _ := p.submitFlow(t, 1, func(_ context.Context, cancel context.CancelFunc) {
		p.onWiden = func(*fakeLoginPage) { cancel() }
	})
	if res.OK {
		t.Fatalf("a cancelled run must not report success: %+v", res)
	}
	if strings.Contains(res.Reason, "恢复原视口失败") {
		t.Fatalf("reason = %q, the restore failure must not replace the stop", res.Reason)
	}
	if !hasLog(p.logs, "恢复原视口失败") {
		t.Fatalf("log does not report the restore failure: %q", p.logs)
	}
}

// 6. An unavailable box is recorded and the login goes on: 「记住密码」 is a
// convenience, and by contract only an untrusted page, a cancelled run or a
// timeout may stop the sign-in — never an option the school did not offer.
func TestAnUnavailableRememberBoxDoesNotBlockTheLogin(t *testing.T) {
	for _, shape := range []struct {
		name    string
		outcome rememberOutcome
	}{
		{"absent", rememberAbsent},
		{"not ticked", rememberWriteFailed},
	} {
		t.Run(shape.name, func(t *testing.T) {
			p := newFakeLoginPage()
			p.rememberPassword = true
			p.rememberResult = shape.outcome
			p.landAfter = time.Second

			res, loginOK := p.submitFlow(t, 1, nil)
			if !loginOK || res.Exit != 0 {
				t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, loginOK, p.logs)
			}
			if p.rememberCalls != 1 {
				t.Fatalf("remember calls = %d, want exactly 1 attempt: the box is not retried", p.rememberCalls)
			}
			assertNoExtraAttempt(t, p, 1)
			if !hasLog(p.logs, "本次未确认启用「记住密码」") {
				t.Fatalf("log does not record that the option was not confirmed: %q", p.logs)
			}
			// The credential path is untouched: the normal submit still happened.
			if !hasLog(p.logs, "[1/1] 识别") {
				t.Fatalf("the run did not reach the normal captcha step: %q", p.logs)
			}
		})
	}
}

// 7. The box is handled before the credential fields are touched, so a tick that
// triggers a responsive re-render cannot land between filling and submitting; the
// fields are located again through the same selectors afterwards.
func TestTheRememberBoxIsHandledBeforeTheFieldsAreFilled(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	if _, ok := p.submitFlow(t, 1, nil); !ok {
		t.Fatalf("login did not finish: logs=%q", p.logs)
	}
	if !p.rememberBeforeFill {
		t.Fatalf("the box was handled after a fill: 「记住密码」 must come first")
	}
	if p.rememberCalls != 1 || p.clicks != 1 {
		t.Fatalf("remember/clicks = %d/%d, want 1/1", p.rememberCalls, p.clicks)
	}
}
