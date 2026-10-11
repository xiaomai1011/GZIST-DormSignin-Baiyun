package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

func fakeScheduleTime() time.Time {
	return time.Date(2026, 10, 11, 21, 30, 0, 0, time.FixedZone("test", 8*3600))
}
func testLedger(t *testing.T) *scheduleLedger {
	t.Helper()
	l, err := openScheduleLedger(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func claimTestSlot(t *testing.T, l *scheduleLedger, now time.Time, cfg store.Settings, account string) *scheduleTicket {
	t.Helper()
	ticket, err := l.claim(now, cfg, account, true, false)
	if err != nil || ticket == nil {
		t.Fatalf("claim = %v, %v", ticket, err)
	}
	return ticket
}
func TestScheduleClaimsAndConfirmedSuccess(t *testing.T) {
	l, now, cfg, account := testLedger(t), fakeScheduleTime(), store.Defaults(), accountKey("fake-student-A")
	claimTestSlot(t, l, now, cfg, account)
	// No success was recorded: same-slot failure is consumed, later retry allowed.
	for _, tick := range []time.Time{now, now.Add(20 * time.Second), now.Add(40 * time.Second)} {
		if ticket, err := l.claim(tick, cfg, account, true, false); ticket != nil || err != nil {
			t.Fatalf("repeated slot: %v %v", ticket, err)
		}
	}
	claimTestSlot(t, l, now.Add(10*time.Minute), cfg, account)
	if err := l.confirm(account, now.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	for _, tick := range []time.Time{now.Add(10*time.Minute + 20*time.Second), now.Add(20 * time.Minute), now.Add(30 * time.Minute)} {
		if ticket, err := l.claim(tick, cfg, account, true, false); ticket != nil || err != nil {
			t.Fatalf("repeated success: %v %v", ticket, err)
		}
	}
	if l.succeeded(account, now.AddDate(0, 0, 1)) || l.succeeded(accountKey("fake-student-B"), now) {
		t.Fatal("success leaked across day/account")
	}
	claimTestSlot(t, l, now.AddDate(0, 0, 1), cfg, account)
	claimTestSlot(t, l, now, cfg, accountKey("fake-student-B"))
}
func TestScheduleRestartAndPrivacy(t *testing.T) {
	l, now, cfg := testLedger(t), fakeScheduleTime(), store.Defaults()
	account := accountKey("fake-student-A")
	claimTestSlot(t, l, now, cfg, account)
	restored, err := openScheduleLedger(l.path)
	if err != nil {
		t.Fatal(err)
	}
	if ticket, _ := restored.claim(now, cfg, account, true, false); ticket != nil {
		t.Fatal("restart repeated claimed slot")
	}
	if err := restored.confirm(account, now.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	restored, err = openScheduleLedger(l.path)
	if err != nil || !restored.succeeded(account, now) {
		t.Fatalf("success not restored: %v", err)
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fake-student-A", "password", "cookie", "studentID"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("state contains %q", secret)
		}
	}
	if !strings.Contains(string(b), account) {
		t.Fatal("missing account digest")
	}
}
func TestScheduleJitterRechecks(t *testing.T) {
	cases := []string{"normal-minute-crossing", "holiday", "account", "credentials", "running", "manual-success", "date", "late-line", "removed-slot", "resume", "clock-backward"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			l, now, cfg, account := testLedger(t), fakeScheduleTime(), store.Defaults(), accountKey("fake-A")
			ticket := claimTestSlot(t, l, now, cfg, account)
			check := now.Add(89 * time.Second)
			creds, running := true, false
			switch name {
			case "holiday":
				cfg.Holiday = true
			case "account":
				account = accountKey("fake-B")
			case "credentials":
				creds = false
			case "running":
				running = true
			case "manual-success":
				if err := l.confirm(account, ticket.Date); err != nil {
					t.Fatal(err)
				}
			case "date":
				check = now.AddDate(0, 0, 1)
			case "late-line":
				cfg.LateLine = "21:31"
			case "removed-slot":
				cfg.Times = []string{"22:00"}
			case "resume":
				check = now.Add(3 * time.Minute)
			case "clock-backward":
				check = now.Add(-time.Second)
			}
			if got := l.eligible(ticket, check, cfg, account, creds, running); got != (name == "normal-minute-crossing") {
				t.Fatalf("eligible = %v", got)
			}
			// A canceled jitter must never release the claimed slot.
			if next, _ := l.claim(now, store.Defaults(), ticket.Account, true, false); next != nil {
				t.Fatal("canceled slot reclaimed")
			}
		})
	}
}
func TestScheduleManualSuccessBeforeSlot(t *testing.T) {
	l, now, cfg, account := testLedger(t), fakeScheduleTime(), store.Defaults(), accountKey("fake-A")
	if err := l.confirm(account, now.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	if ticket, _ := l.claim(now, cfg, account, true, false); ticket != nil {
		t.Fatal("manual success did not suppress schedule")
	}
}
func TestScheduleWriteFailureKeepsSuccess(t *testing.T) {
	l, now, account := testLedger(t), fakeScheduleTime(), accountKey("fake-A")
	// A directory at the destination makes rename fail on every platform.
	if err := os.Mkdir(l.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := l.confirm(account, now.Format("2006-01-02")); err == nil {
		t.Fatal("expected write error")
	}
	if !l.succeeded(account, now) {
		t.Fatal("write failure revoked in-memory success")
	}
	l2 := testLedger(t)
	if err := os.Mkdir(l2.path, 0700); err != nil {
		t.Fatal(err)
	}
	if ticket, err := l2.claim(now, store.Defaults(), account, true, false); ticket != nil || err == nil {
		t.Fatal("claim must fail closed on persistence failure")
	}
}
func TestScheduleConcurrentClaims(t *testing.T) {
	l, now, cfg, account := testLedger(t), fakeScheduleTime(), store.Defaults(), accountKey("fake-A")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, err := l.claim(now, cfg, account, true, false)
			if err != nil {
				t.Error(err)
			}
			if ticket != nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("claims = %d", wins.Load())
	}
}
func TestAccountSettingsIsolateProfiles(t *testing.T) {
	for _, base := range []string{"edge-userdata", filepath.Join(t.TempDir(), "profiles")} {
		cfg := store.Defaults()
		cfg.UserData = base
		a, err := accountSettings(cfg, "fake-A", "fake-password", nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := accountSettings(cfg, "fake-B", "fake-password", nil)
		if err != nil {
			t.Fatal(err)
		}
		again, err := accountSettings(cfg, "fake-A", "changed-password", nil)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(base, "accounts-v1", accountKey("fake-A"))
		if a.UserData != want || a.UserData == b.UserData || again.UserData != a.UserData {
			t.Fatalf("account profile isolation/stability: %q %q %q", a.UserData, b.UserData, again.UserData)
		}
		if cfg.UserData != base || a.URL != cfg.URL || a.EdgePath != cfg.EdgePath {
			t.Fatal("original config or unrelated settings changed")
		}
		if filepath.IsAbs(a.UserData) != filepath.IsAbs(base) {
			t.Fatal("relative/absolute semantics changed")
		}
		if strings.Contains(a.UserData, "fake-A") || strings.Contains(a.UserData, "password") {
			t.Fatal("plaintext account in profile path")
		}
	}
}
func TestAccountSettingsRejectInvalidInputs(t *testing.T) {
	for _, name := range []string{"empty-profile", "blank-profile", "empty-id", "empty-password", "credential-error"} {
		t.Run(name, func(t *testing.T) {
			cfg, id, pass := store.Defaults(), "fake-A", "fake-password"
			var credErr error
			switch name {
			case "empty-profile":
				cfg.UserData = ""
			case "blank-profile":
				cfg.UserData = "   "
			case "empty-id":
				id = ""
			case "empty-password":
				pass = ""
			case "credential-error":
				credErr = os.ErrPermission
			}
			got, err := accountSettings(cfg, id, pass, credErr)
			if err == nil || got.UserData != cfg.UserData {
				t.Fatal("invalid input accepted or path silently changed")
			}
		})
	}
}
func TestScheduleWallClockBounds(t *testing.T) {
	// Synthetic wall-clock values only; never change the host clock.
	l, now, cfg, account := testLedger(t), fakeScheduleTime(), store.Defaults(), accountKey("fake-A")
	ticket := claimTestSlot(t, l, now, cfg, account)
	for _, delta := range []time.Duration{-time.Nanosecond, 2*time.Minute + time.Nanosecond} {
		if l.eligible(ticket, now.Round(0).Add(delta), cfg, account, true, false) {
			t.Fatalf("accepted wall-clock delta %v", delta)
		}
	}
	if !l.eligible(ticket, now.Round(0).Add(89*time.Second), cfg, account, true, false) {
		t.Fatal("valid wall-clock jitter rejected")
	}
}

func TestModelConfirmedSuccessSurvivesFailedAttempt(t *testing.T) {
	now, account := fakeScheduleTime(), accountKey("fake-A")
	m := &model{cfg: store.Defaults()}
	m.syncSuccess(account, now, true)
	m.setResult(false, false, "fake failure")
	title, _, _, _ := m.statusLine()
	if title != "今日已签到" || !strings.Contains(m.notice, "fake failure") {
		t.Fatalf("success/attempt conflated: %q %q", title, m.notice)
	}
	m.syncSuccess(account, now.AddDate(0, 0, 1), false)
	if m.resultOK || m.notice != "" {
		t.Fatal("stale success/notice after midnight")
	}
	m.syncSuccess(account, now, true)
	m.setResult(true, false, "success")
	m.syncSuccess(accountKey("fake-B"), now, false)
	if m.resultOK || m.notice != "" {
		t.Fatal("stale success/notice after account change")
	}
}
