package signin

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Tests for the school's own 「记住密码」 box: the run may tick it, must never
// retry it, must never let it change the submission count, and must never
// present it as a guarantee. Everything here is scripted — no browser, no
// network, no account.

// 1. With the setting on and a box on the page, the box is handled once, before
// the first (and only) submit, and the log says it was ticked.
func TestRememberBoxIsTickedBeforeTheFirstSubmit(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.rememberCalls != 1 {
		t.Fatalf("remember calls = %d, want exactly 1", p.rememberCalls)
	}
	if !p.rememberBeforeSubmit {
		t.Fatalf("the box was handled after a submit, want before")
	}
	if p.clicks != 1 {
		t.Fatalf("clicks = %d, want 1: ticking the box must not add a submission", p.clicks)
	}
	if !hasLog(p.logs, "已勾选「记住密码」") {
		t.Fatalf("log does not say the box was ticked: %q", p.logs)
	}
	if hasLog(p.logs, "保证") || hasLog(p.logs, "免除") {
		t.Fatalf("log must not promise the server honours it: %q", p.logs)
	}
}

// 2. With the setting off, the page's box is never touched — the existing
// behaviour stays byte-for-byte the same.
func TestRememberBoxIsNotTouchedWhenTheSettingIsOff(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.rememberCalls != 0 {
		t.Fatalf("remember calls = %d, want 0 when the setting is off", p.rememberCalls)
	}
	if !hasLog(p.logs, "「记住密码」未启用") {
		t.Fatalf("log does not report the setting being off: %q", p.logs)
	}
}

// 3. An already-ticked box is left alone: no second click, no extra submission.
func TestAlreadyTickedBoxIsNotClickedAgain(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberAlreadyOn
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.rememberCalls != 1 {
		t.Fatalf("remember calls = %d, want 1", p.rememberCalls)
	}
	if p.clicks != 1 {
		t.Fatalf("clicks = %d, want 1", p.clicks)
	}
	if !hasLog(p.logs, "已处于勾选状态") {
		t.Fatalf("log does not report the box already being ticked: %q", p.logs)
	}
}

// 4. A page without the box is a fact to record, not a reason to give up the
// sign-in: the login proceeds exactly as it did before this feature existed, and
// the run states plainly that the option was not confirmed.
func TestMissingRememberBoxIsRecordedAndTheLoginGoesOn(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberAbsent
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 1, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	assertNoExtraAttempt(t, p, 1)
	if p.rememberCalls != 1 {
		t.Fatalf("remember calls = %d, want 1: an absent box is not retried", p.rememberCalls)
	}
	if !hasLog(p.logs, "本次未确认启用「记住密码」") {
		t.Fatalf("log does not record that the option was not enabled: %q", p.logs)
	}
	// The line must not claim more than the script measured: it cannot see the
	// server's locale flag, so it may not say the school omitted the field.
	if hasLog(p.logs, "学校未提供") || hasLog(p.logs, "按未勾选提交") {
		t.Fatalf("log claims more than the measurement supports: %q", p.logs)
	}
}

// 5. A tick that does not take is reported once and never retried, and it does not
// add a submission: the login continues on its normal path, with the failure
// recorded as "not confirmed" rather than as a credential problem.
func TestRememberWriteFailureIsReportedOnceAndNotRetried(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberWriteFailed
	p.landAfter = time.Second

	res, ok := p.submitFlow(t, 3, nil)
	if !ok || res.Exit != 0 {
		t.Fatalf("login did not finish: %+v ok=%v logs=%q", res, ok, p.logs)
	}
	if p.rememberCalls != 1 {
		t.Fatalf("remember calls = %d, want 1: a failed tick must not be retried", p.rememberCalls)
	}
	assertNoExtraAttempt(t, p, 1)
	if !hasLog(p.logs, "勾选「记住密码」未生效") {
		t.Fatalf("log does not report the failed tick: %q", p.logs)
	}
	if !hasLog(p.logs, "本次未确认启用「记住密码」") {
		t.Fatalf("log does not record that the option was not confirmed: %q", p.logs)
	}
}

// 6. A cancel that lands while the box is being handled stops the run before any
// submit happens.
func TestCancelDuringTheRememberClickStopsBeforeSubmitting(t *testing.T) {
	p := newFakeLoginPage()
	p.rememberPassword = true
	p.rememberResult = rememberChecked
	p.landAfter = time.Second

	var cancel context.CancelFunc
	p.onRemember = func(*fakeLoginPage) { cancel() }

	res, ok := p.submitFlow(t, 1, func(ctx context.Context, c context.CancelFunc) { cancel = c })
	_ = ok
	if p.clicks != 0 {
		t.Fatalf("clicks = %d, want 0: nothing may be submitted after a cancel", p.clicks)
	}
	if ok {
		t.Fatalf("loginOK = true after a cancel: %+v logs=%q", res, p.logs)
	}
	if !strings.Contains(res.Reason, "取消") && !strings.Contains(res.Reason, "cancel") {
		t.Fatalf("reason does not report the cancel: %q", res.Reason)
	}
}

// 7. Each outcome has its own line, and none of them claims the server will
// honour the box.
func TestRememberLinesAreDistinctAndNeverPromiseTheEffect(t *testing.T) {
	seen := map[string]rememberOutcome{}
	for _, o := range []rememberOutcome{
		rememberNotRequested, rememberAlreadyOn, rememberChecked, rememberAbsent, rememberWriteFailed,
	} {
		line := rememberLine(o)
		if prev, dup := seen[line]; dup {
			t.Fatalf("%v and %v share the same log line: %q", prev, o, line)
		}
		seen[line] = o
		for _, banned := range []string{"保证", "一定", "免除", "免二次", "永久"} {
			if strings.Contains(line, banned) {
				t.Fatalf("log line for %v claims %q: %q", o, banned, line)
			}
		}
	}
	if got := rememberNotRequested.String(); got != "not_requested" {
		t.Fatalf("not-requested reports %q", got)
	}
	if got := rememberChecked.String(); got != "checked" {
		t.Fatalf("checked reports %q", got)
	}
}

// assertNoExtraAttempt compares the run against an identical one with the
// 「记住密码」 setting off. An unavailable box may change what is logged; it may
// never change how many fields are written or how many times the form is
// submitted.
func assertNoExtraAttempt(t *testing.T, p *fakeLoginPage, capMax int) {
	t.Helper()
	control := newFakeLoginPage()
	control.landAfter = time.Second
	if _, ok := control.submitFlow(t, capMax, nil); !ok {
		t.Fatalf("control run did not finish")
	}
	if p.fills != control.fills || p.clicks != control.clicks || p.refreshes != control.refreshes {
		t.Fatalf("fills/clicks/refreshes = %d/%d/%d, want the setting-off run's %d/%d/%d: the box must not cost an attempt",
			p.fills, p.clicks, p.refreshes, control.fills, control.clicks, control.refreshes)
	}
}
