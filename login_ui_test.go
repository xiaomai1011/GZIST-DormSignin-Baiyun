package main

import (
	"image"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

func TestVerificationUIRejectsStaleResults(t *testing.T) {
	m := &model{id: "fake-A", pass: "fake-pass"}
	request := m.beginLoginVerification()
	m.id = "fake-B"
	m.credentialsEdited()
	m.id = "fake-A"
	m.credentialsEdited()
	m.finishLoginVerification(request, signin.VerificationResult{OK: true})
	if m.verifying || m.verifyOK || !strings.Contains(m.verifyMessage, "已丢弃") {
		t.Fatal("A-B-A accepted stale result")
	}
	current := m.beginLoginVerification()
	m.finishLoginVerification(request, signin.VerificationResult{Issue: signin.AuthCredentialsRejected})
	if !m.verifying || m.authIssue != signin.AuthNone {
		t.Fatal("old request changed new state")
	}
	m.verifyCanceled = true
	m.finishLoginVerification(current, signin.VerificationResult{OK: true})
	if m.verifyOK || m.verifyMessage != "验证已取消。" {
		t.Fatal("canceled request accepted success")
	}
}
func TestVerifyMessageFollowsReasonAndUnknownRaisesNoPasswordBanner(t *testing.T) {
	m := &model{id: "fake-A", pass: "fake-pass"}

	// An unlisted business code is an AuthUnknown outcome with its own reason.
	// The card must show that reason verbatim — never a password verdict, and
	// never a collapsed generic sentence standing in for it.
	fakeUnknown := "认证服务返回了暂未识别的结果，暂时无法判断账号密码是否正确，请勿连续重试。"
	request := m.beginLoginVerification()
	m.finishLoginVerification(request, signin.VerificationResult{
		Issue:      signin.AuthUnknown,
		Reason:     fakeUnknown,
		ReasonCode: signin.ReasonUnknownBusinessCode,
	})
	if m.verifyMessage != fakeUnknown {
		t.Fatalf("the reason-specific text was not shown verbatim: %q", m.verifyMessage)
	}
	for _, bad := range []string{"密码错误", "账号或密码错误"} {
		if strings.Contains(m.verifyMessage, bad) {
			t.Fatalf("unknown outcome shown as a password verdict: %q", m.verifyMessage)
		}
	}
	if title, _ := m.authBannerText(); title != "" {
		t.Fatalf("unknown outcome raised the credential banner: %q", title)
	}
	if m.authIssue != signin.AuthNone {
		t.Fatalf("unknown outcome recorded a credential issue: %s", m.authIssue)
	}

	// A genuine rejection still gets the red banner and its own wording.
	rejected := m.beginLoginVerification()
	m.finishLoginVerification(rejected, signin.VerificationResult{
		Issue:  signin.AuthCredentialsRejected,
		Reason: "账号或密码错误，请检查后重新验证",
	})
	title, _ := m.authBannerText()
	if !strings.Contains(title, "账号或密码错误") {
		t.Fatalf("credential rejection lost its banner: %q", title)
	}
	if m.authIssue != signin.AuthCredentialsRejected {
		t.Fatalf("credential rejection not recorded: %s", m.authIssue)
	}
	m.credentialsEdited()
	if m.authIssue != signin.AuthNone {
		t.Fatal("editing input did not clear the verification-sourced banner")
	}
}

func TestCredentialBannerClassificationAndOwnership(t *testing.T) {
	m := &model{id: "fake-A", pass: "fake-pass"}
	token := credentialIdentity(m.id, m.pass)
	for _, issue := range []signin.AuthIssue{signin.AuthNetwork, signin.AuthCaptcha, signin.AuthUnknown,
		signin.AuthCanceled, signin.AuthActionRequired, signin.AuthBusinessOther} {
		m.setAuthIssue(issue, "verify", token)
		if title, _ := m.authBannerText(); title != "" {
			t.Fatalf("false credential warning for %s", issue)
		}
	}
	m.setAuthIssue(signin.AuthCredentialsRejected, "verify", token)
	title, _ := m.authBannerText()
	if !strings.Contains(title, "账号或密码错误") {
		t.Fatal("missing red-banner text")
	}
	m.credentialsEdited()
	if m.authIssue != signin.AuthNone {
		t.Fatal("stale input banner")
	}
	m.applySignInAuthentication(signin.Result{AuthIssue: signin.AuthCredentialsRejected}, token, credentialIdentity("fake-A", "new-pass"))
	if m.authIssue != signin.AuthNone {
		t.Fatal("old password result accepted")
	}
	m.applySignInAuthentication(signin.Result{AuthIssue: signin.AuthCredentialsRejected}, token, token)
	m.credentialsEdited()
	if m.authIssue != signin.AuthCredentialsRejected {
		t.Fatal("editing unsaved fields hid stored-account problem")
	}
	m.savedCredentialsChanged("fake-A", "new-pass")
	if m.authIssue != signin.AuthNone {
		t.Fatal("old saved-credential banner retained")
	}
	m.setAuthIssue(signin.AuthLocked, "automatic", token)
	title, _ = m.authBannerText()
	if !strings.Contains(title, "锁定") {
		t.Fatal("lock misclassified")
	}
	m.applySignInAuthentication(signin.Result{OK: true}, token, token)
	if m.authIssue != signin.AuthNone {
		t.Fatal("success did not clear matching banner")
	}
}
func TestVerificationDoesNotChangeSavedOrSignInState(t *testing.T) {
	m := &model{id: "fake-new", pass: "fake-new-pass", storedID: "fake-saved", storedPass: "fake-old-pass", resultOK: true, notice: "签到成功"}
	req := m.beginLoginVerification()
	m.finishLoginVerification(req, signin.VerificationResult{OK: true})
	if !m.verifyOK || m.storedID != "fake-saved" || m.storedPass != "fake-old-pass" || !m.resultOK || m.notice != "签到成功" {
		t.Fatal("verification changed persisted/sign-in state")
	}
}
func TestOperationReservationAndExclusion(t *testing.T) {
	a := &app{}
	a.scheduledPending = true
	if a.acquireOperation(false) {
		t.Fatal("verification/manual action stole claimed slot")
	}
	if !a.acquireOperation(true) || a.scheduledPending {
		t.Fatal("reserved schedule could not start")
	}
	if a.acquireOperation(false) {
		t.Fatal("concurrent operation")
	}
	a.running.Store(false)
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a.acquireOperation(false) {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("operation winners=%d", winners)
	}
}
func TestClaimIsNotConsumedByVerification(t *testing.T) {
	ledger, err := openScheduleLedger(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &app{ledger: ledger}
	cfg := store.Defaults()
	cfg.Holiday = false
	cfg.Times = []string{"21:30"}
	now := time.Date(2026, 10, 13, 21, 30, 10, 0, time.Local)
	if !a.acquireOperation(false) {
		t.Fatal("cannot start verification")
	}
	ticket, err := a.claimScheduled(now, cfg, accountKey("fake-account"), true)
	if err != nil || ticket != nil {
		t.Fatal("busy claim should not consume slot")
	}
	a.running.Store(false)
	ticket, err = a.claimScheduled(now, cfg, accountKey("fake-account"), true)
	if err != nil || ticket == nil || !a.scheduledPending {
		t.Fatal("slot not recoverable after busy check")
	}
	if a.acquireOperation(false) {
		t.Fatal("verification consumed pending jitter ticket")
	}
	if !a.acquireOperation(true) {
		t.Fatal("pending ticket lost")
	}
}

func TestIndependentAuthWarningsAndCleanupLatch(t *testing.T) {
	m := &model{id: "fake-B", pass: "fake-pass-B"}
	saved := credentialIdentity("fake-A", "fake-pass-A")
	m.setAuthIssue(signin.AuthCredentialsRejected, "automatic", saved)
	req := m.beginLoginVerification()
	m.finishLoginVerification(req, signin.VerificationResult{Issue: signin.AuthCredentialsRejected})
	if m.authSource != "verify" || m.automaticIssue != signin.AuthCredentialsRejected {
		t.Fatal("saved warning lost behind verification")
	}
	m.credentialsEdited()
	if m.authSource != "automatic" || m.authIdentity != saved {
		t.Fatal("saved warning not restored after editing")
	}
	req = m.beginLoginVerification()
	m.verifyCanceled = true
	m.credentialsEdited()
	m.finishLoginVerification(req, signin.VerificationResult{CleanupFailed: true, Issue: signin.AuthUnknown})
	if !m.cleanupWarning || m.verifying || m.verifyOK {
		t.Fatal("cleanup failure hidden by cancel/stale input")
	}
	a := &app{}
	a.operationBlocked.Store(true)
	if a.acquireOperation(false) || a.acquireOperation(true) {
		t.Fatal("operation allowed after cleanup failure")
	}
}
func TestSaveSingleFlightAndInputOwnership(t *testing.T) {
	m := &model{id: "fake-new", pass: "fake-new-pass", saving: true, notice: "saving"}
	a := &app{m: m}
	a.save("fake-other", "fake-other-pass") // nil Store proves busy path never writes.
	if m.notice != "saving" {
		t.Fatal("second save disturbed first")
	}
	m.finishCredentialSave("fake-old", "fake-old-pass")
	if m.saving || m.id != "fake-new" || m.pass != "fake-new-pass" || m.storedID != "fake-old" || m.storedPass != "fake-old-pass" || !strings.Contains(m.notice, "尚未保存") {
		t.Fatal("save completion clobbered edited input/baseline")
	}
}

// Optional deterministic screenshots of the actual Go view. No App.Run,
// store, browser, GUI input events, real credentials, or scheduling are used.
// renderCard renders the whole window offscreen, in either appearance. The
// headless tester is used instead of ui.Render so the dark theme can be forced.
func renderCard(m *model, dark bool) *image.RGBA {
	tt := ui.NewTester(m.view, 440, 1100)
	tt.SetScale(2)
	if dark {
		tt.SetDark(true)
	}
	tt.Frame()
	return tt.Image()
}

func demoModel(kind string) *model {
	m := &model{cfg: store.Settings{Holiday: true, Times: []string{"21:30", "21:40", "21:50", "22:00"}, LateLine: "23:00", AttWindow: "21:30~23:00"}, id: "DEMO-000001", studentID: "DEMO-000001", storedID: "DEMO-000001", pass: "demo-only", storedPass: "demo-only", hasCreds: true, version: "演示 · 虚构账号"}
	never := func() { panic("offline screenshot must not invoke any action") }
	m.act = actions{Save: func(string, string) { never() }, Verify: func(string, string) { never() }, CancelVerify: never, Sign: never, SetHoliday: func(bool) { never() }, SetAutoSign: func(bool) { never() }, SetAutostart: func(bool) { never() }, OpenLogs: never}
	m.logs = []string{"离屏演示：所有账号与状态均为虚构。", "没有访问学校，没有执行登录或签到。"}
	token := credentialIdentity(m.id, m.pass)
	switch kind {
	case "verification-error":
		m.setAuthIssue(signin.AuthCredentialsRejected, "verify", token)
		m.verifyMessage = "账号或密码错误，请检查后重新验证"
	case "automatic-error":
		m.cfg.Holiday = false
		m.applySignInAuthentication(signin.Result{AuthIssue: signin.AuthCredentialsRejected}, token, token)
		m.notice = "演示：自动签到因账号认证被拒绝而停止。"
	case "verification-success":
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{OK: true, Reason: "账号密码验证通过（CAS 已签发新认证票据）"})
	case "unclassified":
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthUnknown,
			Reason:     signin.UserText(signin.ReasonUnknownBusinessCode),
			ReasonCode: signin.ReasonUnknownBusinessCode,
		})
	case "network-timeout":
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthUnknown,
			Reason:     signin.UserText(signin.ReasonVerificationTimeout),
			ReasonCode: signin.ReasonVerificationTimeout,
		})
	case "network-failure":
		// A network family result: the flow reports it as AuthNetwork, and the
		// request-failure path attaches the issue-level network sentence, so the
		// demo shows exactly what that outcome looks like in the application.
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthNetwork,
			Reason:     signin.IssueText(signin.AuthNetwork),
			ReasonCode: signin.ReasonNetworkFailed,
		})
	case "page-generic":
		// The bounded page-prompt look saw the login page say "the attempt did
		// not pass" and nothing more: still an information box, never a verdict.
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthUnknown,
			Reason:     signin.UserText(signin.ReasonPageGenericRejection),
			ReasonCode: signin.ReasonPageGenericRejection,
		})
	case "page-credential":
		// The look saw the page's own wrong-password counter sentence: a verdict
		// the page confirmed, so the red banner carries it.
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthCredentialsRejected,
			Reason:     signin.IssueText(signin.AuthCredentialsRejected),
			ReasonCode: signin.ReasonPagePasswordCounter,
		})
	case "page-lock":
		// The other counter sentence announces a lock: the advice is to stop
		// retrying, so it is a lock and not a wrong password.
		req := m.beginLoginVerification()
		m.finishLoginVerification(req, signin.VerificationResult{
			Issue:      signin.AuthLocked,
			Reason:     signin.IssueText(signin.AuthLocked),
			ReasonCode: signin.ReasonPagePasswordLocked,
		})
	default:
		t := testing.T{}
		t.Fatalf("unknown demo kind %q", kind)
	}
	return m
}

// TestRenderLoginDemo writes the offscreen demo shots. Nothing here starts the
// application, reads real credentials or touches the network.
func TestRenderLoginDemo(t *testing.T) {
	dir := os.Getenv("DORMSIGN_UI_DEMO_DIR")
	if dir == "" {
		t.Skip("explicit offline demo output directory not requested")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("demo directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, shot := range []struct {
		name, kind string
		dark       bool
	}{
		{"verification-error", "verification-error", false},
		{"automatic-error", "automatic-error", false},
		{"verification-success", "verification-success", false},
		{"unclassified-light", "unclassified", false},
		{"unclassified-dark", "unclassified", true},
		{"network-timeout-light", "network-timeout", false},
		{"network-failure-light", "network-failure", false},
		{"page-generic-light", "page-generic", false},
		{"page-credential-light", "page-credential", false},
		{"page-lock-light", "page-lock", false},
	} {
		t.Run(shot.name, func(t *testing.T) {
			img := renderCard(demoModel(shot.kind), shot.dark)
			f, err := os.Create(filepath.Join(dir, shot.name+".png"))
			if err != nil {
				t.Fatal(err)
			}
			err = png.Encode(f, img)
			closeErr := f.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		})
	}
}

// The presentation must be decided by the structured outcome, never by the
// wording: a message that happens to contain "账号或密码错误" cannot repaint an
// unclassified result, and a success cannot be turned grey by its text.
func TestVerifyPresentationIsDecidedByStructure(t *testing.T) {
	const hostile = "账号或密码错误，请检查后重新验证"
	for _, tc := range []struct {
		name      string
		ok        bool
		issue     signin.AuthIssue
		reason    signin.VerifyReason
		text      string
		wantTone  verifyTone
		wantTitle string
	}{
		{"unclassified code", false, signin.AuthUnknown, signin.ReasonUnknownBusinessCode, signin.UserText(signin.ReasonUnknownBusinessCode), verifyToneInfo, verifyTitleUnclassified},
		{"unclassified code with a password sentence", false, signin.AuthUnknown, signin.ReasonUnknownBusinessCode, hostile, verifyToneInfo, verifyTitleUnclassified},
		{"body read failure", false, signin.AuthUnknown, signin.ReasonBodyReadFailed, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"body read timeout", false, signin.AuthUnknown, signin.ReasonBodyReadTimeout, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"body resource gone", false, signin.AuthUnknown, signin.ReasonBodyResourceGone, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"empty body", false, signin.AuthUnknown, signin.ReasonBodyEmpty, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"oversize body", false, signin.AuthUnknown, signin.ReasonResponseBodyTooLarge, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"schema unknown", false, signin.AuthUnknown, signin.ReasonResponseSchemaUnknown, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"evidence missing", false, signin.AuthUnknown, signin.ReasonResponseEvidenceMissing, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"http status unexpected", false, signin.AuthUnknown, signin.ReasonHTTPStatusUnexpected, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"response not received", false, signin.AuthUnknown, signin.ReasonResponseNotReceived, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"network listen failed", false, signin.AuthUnknown, signin.ReasonListenFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"navigation failed", false, signin.AuthUnknown, signin.ReasonNavigateFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"verification timeout", false, signin.AuthUnknown, signin.ReasonVerificationTimeout, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"launch failed", false, signin.AuthUnknown, signin.ReasonLaunchFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"cas form timeout", false, signin.AuthUnknown, signin.ReasonCASFormTimeout, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"login click failed", false, signin.AuthUnknown, signin.ReasonLoginClickFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"ticket request not seen", false, signin.AuthUnknown, signin.ReasonTicketRequestNotSeen, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"unknown without a reason", false, signin.AuthUnknown, signin.ReasonNone, "x", verifyToneInfo, verifyTitleUnconfirmed},
		{"credential rejection", false, signin.AuthCredentialsRejected, signin.ReasonNone, hostile, verifyTonePlain, ""},
		{"locked", false, signin.AuthLocked, signin.ReasonNone, "x", verifyTonePlain, ""},
		{"captcha", false, signin.AuthCaptcha, signin.ReasonCAPTCHASolveFailed, "x", verifyTonePlain, ""},
		{"action required", false, signin.AuthActionRequired, signin.ReasonNone, "x", verifyTonePlain, ""},
		{"business other", false, signin.AuthBusinessOther, signin.ReasonNone, "x", verifyTonePlain, ""},
		{"canceled", false, signin.AuthCanceled, signin.ReasonCanceled, "x", verifyTonePlain, ""},
		{"network request failed", false, signin.AuthNetwork, signin.ReasonNetworkFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"network listen failed", false, signin.AuthNetwork, signin.ReasonListenFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"network navigation failed", false, signin.AuthNetwork, signin.ReasonNavigateFailed, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"network failure with a password sentence", false, signin.AuthNetwork, signin.ReasonNetworkFailed, hostile, verifyToneInfo, verifyTitleNotCompleted},
		{"network failure without a reason code", false, signin.AuthNetwork, signin.ReasonNone, "x", verifyToneInfo, verifyTitleNotCompleted},
		{"in-progress note", false, signin.AuthNone, signin.ReasonNone, "正在验证…", verifyTonePlain, ""},
		{"success", true, signin.AuthNone, signin.ReasonNone, "", verifyToneSuccess, verifyTitleSuccess},
		{"success ignores the text", true, signin.AuthUnknown, signin.ReasonUnknownBusinessCode, hostile, verifyToneSuccess, verifyTitleSuccess},
	} {
		box := verifyPresentation(tc.ok, tc.issue, tc.reason, tc.text)
		if box.Tone != tc.wantTone || box.Title != tc.wantTitle {
			t.Errorf("%s: tone=%v title=%q, want %v/%q", tc.name, box.Tone, box.Title, tc.wantTone, tc.wantTitle)
		}
		if box.Tone == verifyToneSuccess {
			if box.Text != verifySuccessText {
				t.Errorf("%s: success text = %q", tc.name, box.Text)
			}
			for _, bad := range []string{hostile, "密码错误"} {
				if strings.Contains(box.Text, bad) {
					t.Errorf("%s: success text carries a verdict: %q", tc.name, box.Text)
				}
			}
		} else if box.Text != tc.text {
			t.Errorf("%s: text = %q, want %q", tc.name, box.Text, tc.text)
		}
		if box.Tone == verifyTonePlain && box.Title != "" {
			t.Errorf("%s: a plain outcome must not get a heading: %q", tc.name, box.Title)
		}
	}
	// A red-hat sentence on a plain outcome never becomes an information box,
	// and vice versa: the tone is structural, the text is incidental.
	if verifyPresentation(false, signin.AuthCredentialsRejected, signin.ReasonNone, "认证服务返回了暂未识别的结果").Tone != verifyTonePlain {
		t.Fatal("message text decided the tone")
	}
}

// Only the two information families may wear the blue box; every other issue
// keeps ordinary text with no heading, whatever reason code rides along — the
// credential verdicts, the lock, captcha, the identified business states, a
// cancel and a run that never started. Nothing besides an unclassified or a
// network outcome may drift in.
func TestOnlyUnclassifiedAndNetworkWearTheInformationBox(t *testing.T) {
	for _, issue := range []signin.AuthIssue{signin.AuthCredentialsRejected, signin.AuthLocked,
		signin.AuthCaptcha, signin.AuthActionRequired, signin.AuthBusinessOther,
		signin.AuthCanceled, signin.AuthNone} {
		for _, reason := range []signin.VerifyReason{signin.ReasonNone, signin.ReasonCanceled,
			signin.ReasonNetworkFailed, signin.ReasonListenFailed, signin.ReasonUnknownBusinessCode} {
			if box := verifyPresentation(false, issue, reason, "普通说明"); box.Tone != verifyTonePlain || box.Title != "" {
				t.Errorf("%s/%s: tone=%v title=%q, want plain text without a heading", issue, reason, box.Tone, box.Title)
			}
		}
	}
	for _, issue := range []signin.AuthIssue{signin.AuthUnknown, signin.AuthNetwork} {
		if box := verifyPresentation(false, issue, signin.ReasonNone, "说明"); box.Tone != verifyToneInfo {
			t.Errorf("%s: tone=%v, want the information box", issue, box.Tone)
		}
	}
}

// The network outcomes the verification flow really emits — a listen failure, a
// navigation failure and a failed request — must reach the card as the blue
// information box. The last case walks the same path a real result takes
// (finishLoginVerification → verifyBox → the rendered card), so the rule is
// proven for the production result itself and not only for an AuthUnknown
// stand-in.
func TestNetworkFailuresReachTheCardAsInformationBox(t *testing.T) {
	// The (Issue, ReasonCode) pairs are the ones internal/signin emits:
	// listenForAuth, navigateToCAS and the request-failure event. The flow
	// reports the network family with the issue-level sentence, and the listen
	// and navigate call sites attach their own slightly more specific fixed
	// sentence; this test only requires that whichever fixed sentence came with
	// the result is shown unchanged.
	for _, tc := range []struct {
		name   string
		reason signin.VerifyReason
	}{
		{"listen failed", signin.ReasonListenFailed},
		{"navigation failed", signin.ReasonNavigateFailed},
		{"request failed", signin.ReasonNetworkFailed},
	} {
		text := signin.IssueText(signin.AuthNetwork)
		box := verifyPresentation(false, signin.AuthNetwork, tc.reason, text)
		if box.Tone != verifyToneInfo || box.Title != verifyTitleNotCompleted {
			t.Errorf("%s: tone=%v title=%q, want the information box headed %q",
				tc.name, box.Tone, box.Title, verifyTitleNotCompleted)
		}
		if box.Text != text {
			t.Errorf("%s: the specific explanation was not kept: %q", tc.name, box.Text)
		}
	}

	m := demoModel("network-failure")
	if box := m.verifyBox(); box.Tone != verifyToneInfo {
		t.Fatalf("a network failure drew tone %v instead of the information box", box.Tone)
	}
	if title, _ := m.authBannerText(); title != "" {
		t.Fatalf("a network failure raised the credential banner: %q", title)
	}
	if m.authIssue != signin.AuthNone {
		t.Fatalf("a network failure recorded a credential issue: %s", m.authIssue)
	}
	if m.verifyMessage != signin.IssueText(signin.AuthNetwork) {
		t.Fatalf("the explanation was replaced on the way to the card: %q", m.verifyMessage)
	}
	if strings.Contains(m.verifyMessage, "密码错误") {
		t.Fatalf("a network failure read as a password verdict: %q", m.verifyMessage)
	}
	tt := ui.NewTester(m.view, 440, 1100)
	tt.Frame()
	if !tt.HasText(verifyTitleNotCompleted) {
		t.Fatal("the information heading is missing from the rendered card")
	}
	if !tt.HasText(signin.IssueText(signin.AuthNetwork)) {
		t.Fatal("the explanation is missing from the rendered card")
	}
	for _, unwanted := range []string{verifyTitleUnclassified, verifyTitleSuccess, verifySuccessText} {
		if tt.HasText(unwanted) {
			t.Fatalf("a network failure rendered %q", unwanted)
		}
	}
}

// The outcomes the bounded page-prompt look can produce must land in the card
// like any other result: a verdict the login page itself confirmed keeps the red
// banner and draws no box, and a generic page rejection stays an information box
// with its own fixed sentence — never a password verdict.
func TestPagePromptRefinementsReachTheCard(t *testing.T) {
	confirmed := demoModel("unclassified")
	request := confirmed.beginLoginVerification()
	confirmed.finishLoginVerification(request, signin.VerificationResult{
		Issue:      signin.AuthCredentialsRejected,
		Reason:     signin.IssueText(signin.AuthCredentialsRejected),
		ReasonCode: signin.ReasonPagePasswordCounter,
	})
	if title, _ := confirmed.authBannerText(); !strings.Contains(title, "账号或密码错误") {
		t.Fatalf("a page-confirmed credential verdict lost its banner: %q", title)
	}
	if box := confirmed.verifyBox(); box.Tone != verifyTonePlain {
		t.Fatalf("a page-confirmed credential verdict drew a %v box", box.Tone)
	}

	locked := demoModel("page-lock")
	if title, _ := locked.authBannerText(); !strings.Contains(title, "锁定") {
		t.Fatalf("a page-confirmed lock lost its banner: %q", title)
	}
	if box := locked.verifyBox(); box.Tone != verifyTonePlain {
		t.Fatalf("a page-confirmed lock drew a %v box", box.Tone)
	}
	if strings.Contains(locked.verifyMessage, "密码错误") {
		t.Fatalf("a lock was worded as a password verdict: %q", locked.verifyMessage)
	}

	generic := demoModel("unclassified")
	genericRequest := generic.beginLoginVerification()
	generic.finishLoginVerification(genericRequest, signin.VerificationResult{
		Issue:      signin.AuthUnknown,
		Reason:     signin.UserText(signin.ReasonPageGenericRejection),
		ReasonCode: signin.ReasonPageGenericRejection,
	})
	if title, _ := generic.authBannerText(); title != "" {
		t.Fatalf("a generic page rejection raised the credential banner: %q", title)
	}
	if box := generic.verifyBox(); box.Tone != verifyToneInfo || box.Title != verifyTitleUnconfirmed {
		t.Fatalf("a generic page rejection drew tone=%v title=%q", box.Tone, box.Title)
	}
	if strings.Contains(generic.verifyMessage, "密码错误") {
		t.Fatalf("a generic page rejection was worded as a password verdict: %q", generic.verifyMessage)
	}
	tt := ui.NewTester(generic.view, 440, 1100)
	tt.Frame()
	if !tt.HasText(signin.UserText(signin.ReasonPageGenericRejection)) {
		t.Fatal("the generic rejection sentence is missing from the rendered card")
	}
	for _, unwanted := range []string{verifyTitleSuccess, verifySuccessText} {
		if tt.HasText(unwanted) {
			t.Fatalf("a generic page rejection rendered %q", unwanted)
		}
	}
}

// Both appearances must keep the box readable: this is the checkable half of
// "colour never carries the state alone".
func TestVerifyBoxColorsPrintable(t *testing.T) {
	for _, th := range []*ui.Theme{ui.LightTheme(), ui.DarkTheme()} {
		for _, tone := range []verifyTone{verifyToneInfo, verifyToneSuccess} {
			bg, fg, border := verifyBoxColors(th, tone)
			if contrast, ok := contrastRatio(fg, bg); !ok || contrast < 4.5 {
				t.Errorf("dark=%v tone=%d: contrast %.2f below 4.5", th.Dark, tone, contrast)
			}
			if border == bg || border == fg {
				t.Errorf("dark=%v tone=%d: border invisible against its own box", th.Dark, tone)
			}
		}
	}
	lightBG, _, _ := verifyBoxColors(ui.LightTheme(), verifyToneInfo)
	darkBG, _, _ := verifyBoxColors(ui.DarkTheme(), verifyToneInfo)
	if lightBG == darkBG {
		t.Fatal("the information box ignores the appearance")
	}
}

// ltLum and contrastRatio make the readability requirement measurable instead of
// a matter of taste.
func ltLum(c ui.Color) float64 {
	ch := func(v uint8) float64 {
		s := float64(v) / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(c.R) + 0.7152*ch(c.G) + 0.0722*ch(c.B)
}

func contrastRatio(a, b ui.Color) (float64, bool) {
	la, lb := ltLum(a), ltLum(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), a != b
}

// The blue box lands inside the account card, under the button area, wraps its
// explanation and never overflows the window.
func TestVerifyResultBoxRendersBelowTheButtons(t *testing.T) {
	m := demoModel("unclassified")
	if title, _ := m.authBannerText(); title != "" {
		t.Fatalf("an unclassified result raised the red banner: %q", title)
	}
	tt := ui.NewTester(m.view, 440, 1100)
	tt.Frame()
	for _, want := range []string{verifyTitleUnclassified, signin.UserText(signin.ReasonUnknownBusinessCode), verifySuccessText} {
		if want == verifySuccessText {
			if tt.HasText(want) {
				t.Fatal("a success line appeared for an unclassified result")
			}
			continue
		}
		if !tt.HasText(want) {
			t.Fatalf("the information box is missing %q", want)
		}
	}
	btn, ok := tt.Find("验证登录")
	if !ok {
		t.Fatal("verify button not found")
	}
	title, ok := tt.Find(verifyTitleUnclassified)
	if !ok {
		t.Fatal("information heading not found")
	}
	if title.Y <= btn.Y+btn.H {
		t.Fatalf("the box is not below the button area: box=%+v button=%+v", title, btn)
	}
	if title.X < 0 || title.X+title.W > 440 {
		t.Fatalf("the box overflows the window: %+v", title)
	}
	body, ok := tt.Find(signin.UserText(signin.ReasonUnknownBusinessCode))
	if !ok {
		t.Fatal("explanation not found")
	}
	if body.H < 24 {
		t.Fatalf("the explanation did not wrap onto two lines: %+v", body)
	}
	if body.X < 0 || body.X+body.W > 440 {
		t.Fatalf("the explanation overflows the window: %+v", body)
	}
	if m.verifyBox().Tone != verifyToneInfo {
		t.Fatalf("tone = %v", m.verifyBox().Tone)
	}
}

// Banner-class and ordinary outcomes keep ordinary text: no information box, no
// success box, and the red banner still carries the credential verdict.
func TestNoBoxForBannerAndPlainOutcomes(t *testing.T) {
	for _, tc := range []struct {
		kind      string
		wantTitle string
	}{
		{"verification-error", "账号或密码错误"},
	} {
		m := demoModel(tc.kind)
		title, _ := m.authBannerText()
		if !strings.Contains(title, tc.wantTitle) {
			t.Fatalf("%s: banner = %q", tc.kind, title)
		}
		if box := m.verifyBox(); box.Tone != verifyTonePlain {
			t.Fatalf("%s: tone = %v, want plain", tc.kind, box.Tone)
		}
		tt := ui.NewTester(m.view, 440, 1100)
		tt.Frame()
		for _, unwanted := range []string{verifyTitleUnclassified, verifyTitleNotCompleted, verifyTitleUnconfirmed, verifyTitleSuccess} {
			if tt.HasText(unwanted) {
				t.Fatalf("%s: unexpected box heading %q", tc.kind, unwanted)
			}
		}
	}
}

// Stale, canceled and locked outcomes must not leave a box behind, and the
// successful box must not survive a new edit either.
func TestStaleCanceledAndLockedLeaveNoBox(t *testing.T) {
	m := demoModel("unclassified")
	if m.verifyBox().Tone != verifyToneInfo {
		t.Fatal("setup: expected an information box")
	}
	m.credentialsEdited()
	if m.verifyBox().Tone != verifyTonePlain {
		t.Fatal("editing the input kept the information box")
	}

	stale := demoModel("unclassified")
	request := stale.beginLoginVerification()
	// Editing while a verification is running also asks the controller to
	// cancel it; the demo model panics on actions, so it is stubbed here.
	stale.act.CancelVerify = func() {}
	stale.id = "DEMO-000002"
	stale.credentialsEdited()
	stale.finishLoginVerification(request, signin.VerificationResult{
		Issue:      signin.AuthUnknown,
		Reason:     signin.UserText(signin.ReasonUnknownBusinessCode),
		ReasonCode: signin.ReasonUnknownBusinessCode,
	})
	if stale.verifyBox().Tone != verifyTonePlain || strings.Contains(stale.verifyMessage, "暂未识别") {
		t.Fatalf("a stale result left a box: %q", stale.verifyMessage)
	}

	canceled := demoModel("unclassified")
	canceled.verifyCanceled = true
	canceled.finishLoginVerification(canceled.verifyRequest, signin.VerificationResult{
		OK: true, Reason: "账号密码验证通过（CAS 已签发新认证票据）",
	})
	if canceled.verifyBox().Tone != verifyTonePlain {
		t.Fatal("a late success drew a green box after cancel")
	}

	locked := &model{id: "DEMO-000001", pass: "demo-only"}
	locked.setAuthIssue(signin.AuthLocked, "verify", credentialIdentity(locked.id, locked.pass))
	locked.verifyIssue, locked.verifyReason = signin.AuthLocked, signin.ReasonNone
	locked.verifyMessage = "账号已锁定，请稍后重试或联系学校管理员"
	if locked.verifyBox().Tone != verifyTonePlain {
		t.Fatal("a locked account drew an information box")
	}
	if title, _ := locked.authBannerText(); !strings.Contains(title, "锁定") {
		t.Fatalf("locked banner = %q", title)
	}
}

// A cleanup failure stays an application-wide block: the banner keeps saying so
// and the outcome is never downgraded to an ordinary blue notice.
func TestCleanupFailureStaysBlocking(t *testing.T) {
	m := demoModel("unclassified")
	request := m.beginLoginVerification()
	m.finishLoginVerification(request, signin.VerificationResult{CleanupFailed: true})
	if !m.cleanupWarning {
		t.Fatal("cleanup failure did not latch the block")
	}
	if box := m.verifyBox(); box.Tone != verifyTonePlain {
		t.Fatalf("cleanup failure was turned into a %v box", box.Tone)
	}
	title, _ := m.authBannerText()
	if !strings.Contains(title, "清理") {
		t.Fatalf("cleanup banner = %q", title)
	}
}

// Every heading and the success line are compile-time constants: the UI never
// interpolates server text, a business code, a hash or a ticket.
func TestVerifyHeadingsAreFixed(t *testing.T) {
	allowed := map[string]bool{
		verifyTitleUnclassified: true, verifyTitleNotCompleted: true,
		verifyTitleUnconfirmed: true, verifyTitleSuccess: true, "": true,
	}
	reasons := []signin.VerifyReason{
		signin.ReasonNone, signin.ReasonUnknownBusinessCode, signin.ReasonBodyReadFailed,
		signin.ReasonBodyReadTimeout, signin.ReasonBodyResourceGone, signin.ReasonBodyEmpty,
		signin.ReasonResponseBodyTooLarge, signin.ReasonResponseSchemaUnknown,
		signin.ReasonResponseEvidenceMissing, signin.ReasonHTTPStatusUnexpected,
		signin.ReasonResponseNotReceived, signin.ReasonListenFailed, signin.ReasonNavigateFailed,
		signin.ReasonVerificationTimeout, signin.ReasonLaunchFailed, signin.ReasonCASFormTimeout,
		signin.ReasonLoginClickFailed, signin.ReasonTicketRequestNotSeen, signin.ReasonNetworkFailed,
		signin.ReasonCleanupUnconfirmed, signin.ReasonCanceled, signin.ReasonCASFormMissing,
	}
	// Both information families must pick their heading from this fixed set: the
	// heading never carries server text, whatever the outcome was.
	for _, issue := range []signin.AuthIssue{signin.AuthUnknown, signin.AuthNetwork} {
		for _, reason := range reasons {
			box := verifyPresentation(false, issue, reason, "TGT-secret-hunter2")
			if !allowed[box.Title] {
				t.Errorf("%s/%s: heading %q is not a fixed constant", issue, reason, box.Title)
			}
			if strings.Contains(box.Title, "TGT-") || strings.Contains(box.Title, "hunter2") {
				t.Errorf("%s/%s: heading carries server content: %q", issue, reason, box.Title)
			}
		}
	}
	if strings.Contains(verifySuccessText, "签到，") == false {
		t.Fatal("the success line lost its 'not signed in' clarification")
	}
	if !strings.Contains(verifySuccessText, "未执行签到") || !strings.Contains(verifySuccessText, "未自动保存") {
		t.Fatalf("the success line must state both facts: %q", verifySuccessText)
	}
}
