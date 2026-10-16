package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Fingerprints stay in memory, keyed per process; never persist password hashes.
var credentialKey = func() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic("cannot initialize credential identity")
	}
	return k
}()

type credentialToken [32]byte

func credentialIdentity(id, pass string) credentialToken {
	h := hmac.New(sha256.New, credentialKey[:])
	var size [8]byte
	for _, s := range []string{id, pass} {
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		h.Write(size[:])
		h.Write([]byte(s))
	}
	var out credentialToken
	copy(out[:], h.Sum(nil))
	return out
}

type loginUIState struct {
	inputRevision, verifyRequest, verifyRevision                uint64
	verifying, verifyCanceled, verifyOK, saving, cleanupWarning bool
	verifyMessage                                               string
	// Structured outcome of the last verification. The card's presentation is
	// decided from these fields only — never by matching the message text — so
	// a sentence that happens to mention a password can never repaint a result.
	verifyIssue    signin.AuthIssue
	verifyReason   signin.VerifyReason
	verifyIdentity credentialToken
	// The visible verification warning never destroys the saved-account warning.
	authIssue         signin.AuthIssue
	authSource        string
	authIdentity      credentialToken
	automaticIssue    signin.AuthIssue
	automaticIdentity credentialToken
}
type loginController struct {
	operationMu      sync.Mutex
	scheduledPending bool
	operationBlocked atomic.Bool
	verifyCancel     context.CancelFunc // UI thread only
}

func (m *model) restoreAutomaticAuth() {
	m.authIssue = m.automaticIssue
	m.authIdentity = m.automaticIdentity
	m.authSource = ""
	if m.automaticIssue != signin.AuthNone {
		m.authSource = "automatic"
	}
}
func (m *model) clearAuthIdentity(token credentialToken) {
	if m.automaticIdentity == token {
		m.automaticIssue = signin.AuthNone
	}
	if m.authIdentity == token {
		m.restoreAutomaticAuth()
	}
}
func (m *model) credentialsEdited() {
	m.inputRevision++
	m.verifyOK = false
	m.verifyIssue, m.verifyReason = signin.AuthNone, signin.ReasonNone
	m.verifyMessage = "输入已修改，请重新验证；验证不会自动保存。"
	if m.authSource == "verify" {
		m.restoreAutomaticAuth()
	}
	if m.verifying && m.act.CancelVerify != nil {
		m.act.CancelVerify()
	}
}
func (m *model) beginLoginVerification() uint64 {
	m.verifyRequest++
	m.verifyRevision = m.inputRevision
	m.verifyIdentity = credentialIdentity(m.id, m.pass)
	m.verifying = true
	m.verifyCanceled = false
	m.verifyOK = false
	m.verifyIssue, m.verifyReason = signin.AuthNone, signin.ReasonNone
	m.verifyMessage = "正在验证学工系统登录…仅登录，不签到。"
	return m.verifyRequest
}
func (m *model) finishLoginVerification(request uint64, res signin.VerificationResult) {
	// Cleanup is an application-wide safety condition, even for a canceled/stale input.
	if res.CleanupFailed {
		m.cleanupWarning = true
		m.verifyOK = false
		m.verifyIssue, m.verifyReason = signin.AuthNone, signin.ReasonNone
		m.verifyMessage = "验证浏览器清理未确认，请退出程序后重新打开。"
	}
	if request != m.verifyRequest {
		return
	}
	m.verifying = false
	if res.CleanupFailed {
		return
	}
	if m.verifyRevision != m.inputRevision || m.verifyIdentity != credentialIdentity(m.id, m.pass) {
		m.verifyOK = false
		m.verifyIssue, m.verifyReason = signin.AuthNone, signin.ReasonNone
		m.verifyMessage = "输入已修改，上次验证结果已丢弃，请重新验证。"
		return
	}
	if m.verifyCanceled {
		m.verifyOK = false
		m.verifyIssue, m.verifyReason = signin.AuthNone, signin.ReasonNone
		m.verifyMessage = "验证已取消。"
		return
	}
	m.verifyOK = res.OK
	m.verifyIssue, m.verifyReason = res.Issue, res.ReasonCode
	m.verifyMessage = res.Reason
	if res.OK {
		m.verifyMessage = "登录验证通过；仅代表当前账号密码可用，尚未签到。修改后请另点保存。"
		m.clearAuthIdentity(m.verifyIdentity)
	} else {
		m.setAuthIssue(res.Issue, "verify", m.verifyIdentity)
	}
}
func (m *model) setAuthIssue(issue signin.AuthIssue, source string, identity credentialToken) {
	if issue != signin.AuthCredentialsRejected && issue != signin.AuthLocked {
		return
	}
	if source == "automatic" {
		m.automaticIssue = issue
		m.automaticIdentity = identity
		if m.authSource == "verify" {
			return
		}
	}
	m.authIssue = issue
	m.authSource = source
	m.authIdentity = identity
}
func (m *model) applySignInAuthentication(res signin.Result, attempted, current credentialToken) {
	if attempted != current {
		return
	}
	if res.OK {
		m.clearAuthIdentity(attempted)
		return
	}
	m.setAuthIssue(res.AuthIssue, "automatic", attempted)
}
func (m *model) savedCredentialsChanged(id, pass string) {
	token := credentialIdentity(id, pass)
	if m.automaticIdentity != token {
		m.automaticIssue = signin.AuthNone
	}
	if m.authSource == "automatic" {
		m.restoreAutomaticAuth()
	}
}
func (m *model) finishCredentialSave(id, pass string) {
	m.saving = false
	m.studentID = id
	m.hasCreds = pass != ""
	m.storedID = id
	m.storedPass = pass
	m.savedCredentialsChanged(id, pass)
	m.notice = "已保存"
	if m.id != id || m.pass != pass {
		m.notice = "上一份输入已保存；当前输入已修改，尚未保存。"
	}
}
func (m *model) authBannerText() (string, string) {
	if m.cleanupWarning {
		return "验证浏览器清理异常，操作已暂停", "请从托盘退出程序后重新打开；未确认退出前，不会继续启动登录或签到。"
	}
	if m.authIssue == signin.AuthLocked {
		return "账号已被锁定或暂时停用", "请先到学工系统处理账号状态；不要连续尝试密码。"
	}
	if m.authIssue != signin.AuthCredentialsRejected {
		return "", ""
	}
	if m.authSource == "automatic" {
		return "账号或密码错误，自动签到无法登录", "请检查已保存的学号和学工密码，修改后重新验证并保存。"
	}
	return "账号或密码错误，请检查后重试", "学工系统明确拒绝了本次登录。请检查学号和密码；验证不会自动保存。"
}

// verifyTone is how a verification outcome is presented in the card.
type verifyTone int

const (
	// verifyTonePlain is ordinary secondary text: in-progress, canceled, stale
	// input, and the outcomes the top banner already emphasises.
	verifyTonePlain verifyTone = iota
	// verifyToneInfo is the blue information box: an outcome that is neither a
	// credential verdict nor a success — the unclassified family and the
	// network family.
	verifyToneInfo
	// verifyToneSuccess is the green success box.
	verifyToneSuccess
)

// Fixed texts. A title or the success line is always one of these constants:
// no server text, business code, hash, URL, body or ticket is ever interpolated.
const (
	verifyTitleUnclassified = "ⓘ 认证结果暂未识别"
	verifyTitleNotCompleted = "ⓘ 暂时无法完成验证"
	verifyTitleUnconfirmed  = "ⓘ 认证结果暂时无法确认"
	verifyTitleSuccess      = "✓ 账号密码验证通过"
	verifySuccessText       = "本次仅验证登录，未执行签到，也未自动保存当前输入。"
)

// verifyBox is the presentation of one verification outcome.
type verifyBox struct {
	Tone  verifyTone
	Title string
	Text  string
}

// verifyPresentation decides how the last verification is shown, from the
// structured outcome alone: OK, Issue and ReasonCode decide the tone and the
// title, and the message text is only ever passed through for the plain and
// information cases. Text matching is deliberately absent: a message that
// happens to contain "账号或密码错误" cannot turn an unclassified result red.
func verifyPresentation(ok bool, issue signin.AuthIssue, reason signin.VerifyReason, text string) verifyBox {
	if ok {
		return verifyBox{Tone: verifyToneSuccess, Title: verifyTitleSuccess, Text: verifySuccessText}
	}
	// The information box covers every outcome that is neither a credential
	// verdict nor a success and that the top banner does not already carry: the
	// unclassified family, and the network family. A listen, navigation or
	// request failure is not a password verdict either, so it may not be shown
	// as ordinary text — the outcome is not "nothing to report", it is "this
	// run produced no result", and the explanation that came with the result is
	// kept verbatim.
	if issue == signin.AuthUnknown || issue == signin.AuthNetwork {
		return verifyBox{Tone: verifyToneInfo, Title: verifyInfoTitle(issue, reason), Text: text}
	}
	// Credential rejection and lock are carried by the top red banner; captcha
	// and the identified business states keep their own wording, and a canceled
	// or cleanup-blocked run keeps the plain sentence the controller wrote: no
	// box, and never the success or the information styling.
	return verifyBox{Tone: verifyTonePlain, Text: text}
}

// verifyInfoTitle picks the fixed heading for one information-box outcome, from
// its issue and its reason code. The three families stay distinct: an unread code
// is not a connection problem, and a response we did read is not a request we
// never completed.
func verifyInfoTitle(issue signin.AuthIssue, reason signin.VerifyReason) string {
	switch reason {
	case signin.ReasonUnknownBusinessCode:
		return verifyTitleUnclassified
	case signin.ReasonListenFailed, signin.ReasonNavigateFailed, signin.ReasonNetworkFailed,
		signin.ReasonVerificationTimeout, signin.ReasonTicketRequestNotSeen,
		signin.ReasonResponseNotReceived, signin.ReasonLaunchFailed,
		signin.ReasonCASFormTimeout, signin.ReasonCASPageNotTrusted, signin.ReasonCASFormMissing,
		signin.ReasonLoginButtonMissing, signin.ReasonLoginButtonNotVisible,
		signin.ReasonLoginButtonNotClicked, signin.ReasonLoginClickFailed:
		return verifyTitleNotCompleted
	}
	// A network-family result never completed whatever reason code it carries:
	// the verification never reached a verdict to confirm or to read.
	if issue == signin.AuthNetwork {
		return verifyTitleNotCompleted
	}
	return verifyTitleUnconfirmed
}

// verifyBoxColors keeps the information and success boxes readable in both
// appearances. The success colours reuse the palette already used for the
// success line and the theme's own Success accent.
func verifyBoxColors(t *ui.Theme, tone verifyTone) (bg, fg, border ui.Color) {
	if tone == verifyToneSuccess {
		if t.Dark {
			return ui.Hex("#0F2A18"), ui.Hex("#BBF7D0"), t.Success
		}
		return ui.Hex("#F0FDF4"), ui.Hex("#16803C"), t.Success
	}
	if t.Dark {
		return ui.Hex("#172554"), ui.Hex("#DBEAFE"), ui.Hex("#3B82F6")
	}
	return ui.Hex("#EFF6FF"), ui.Hex("#1E40AF"), ui.Hex("#93C5FD")
}

// verifyResultBox renders the structured presentation: an icon-and-title
// heading plus a wrapping explanation, so the state never depends on colour
// alone.
func verifyResultBox(c *ui.Context, t *ui.Theme, box verifyBox) {
	bg, fg, border := verifyBoxColors(t, box.Tone)
	ui.Column(c).FillWidth().Padding(9, 11).Gap(3).Radius(8).Background(bg).Border(1, border).Children(func() {
		ui.Text(c, box.Title).FontSize(12.5).Bold().TextColor(fg).Wrap()
		ui.Text(c, box.Text).FontSize(12).TextColor(fg).Wrap()
	})
}

// verifyBox returns the presentation of the current verification state.
func (m *model) verifyBox() verifyBox {
	return verifyPresentation(m.verifyOK, m.verifyIssue, m.verifyReason, m.verifyMessage)
}

func (m *model) authBanner(c *ui.Context) {
	title, detail := m.authBannerText()
	if title == "" {
		return
	}
	ui.Column(c).FillWidth().Padding(14).Gap(5).Background(ui.Hex("#B91C1C")).Children(func() {
		ui.Text(c, "！ "+title).FontSize(17).TextColor(ui.Hex("#FFFFFF")).Wrap()
		ui.Text(c, detail).FontSize(12).TextColor(ui.Hex("#FFFFFF")).Wrap()
	})
}

// Reservation and acquisition share a mutex: a verifier cannot consume a
// scheduled ticket already durably claimed before its random delay.
func (a *app) claimScheduled(now time.Time, cfg store.Settings, account string, hasCredentials bool) (*scheduleTicket, error) {
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	ticket, err := a.ledger.claim(now, cfg, account, hasCredentials, a.running.Load() || a.scheduledPending || a.operationBlocked.Load())
	if ticket != nil {
		a.scheduledPending = true
	}
	return ticket, err
}
func (a *app) acquireOperation(scheduled bool) bool {
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if a.operationBlocked.Load() || (a.scheduledPending && !scheduled) {
		return false
	}
	if scheduled {
		a.scheduledPending = false
	}
	return a.running.CompareAndSwap(false, true)
}

// verifyDiag records the single de-identified summary line of one verification.
// It is on by default — an inconclusive verification used to leave no trace at
// all — and DORMSIGN_VERIFY_DIAG=0 turns it back off. The line carries only
// fixed enums, bounded numbers and a short request hash.
func (a *app) verifyDiag(line string) {
	if line == "" || strings.HasPrefix(os.Getenv("DORMSIGN_VERIFY_DIAG"), "0") {
		return
	}
	a.log.Add(line)
}

func (a *app) verifyLogin(id, pass string) {
	if strings.TrimSpace(id) == "" || pass == "" {
		a.m.verifyMessage = "请先填写学号和密码。"
		a.post(func() {})
		return
	}
	if a.m.verifying {
		return
	}
	if !a.acquireOperation(false) {
		a.m.verifyMessage = "签到正在运行／即将开始，或操作已暂停；请查看顶部提示。"
		a.post(func() {})
		return
	}
	// Freeze visible inputs; no implicit Save or stored credentials lookup.
	cfg := a.store.Load()
	ctx, cancel := context.WithCancel(context.Background())
	a.verifyCancel = cancel
	request := a.m.beginLoginVerification()
	a.syncTray()
	a.post(func() {})
	go func() {
		defer cancel()
		res := signin.VerifyLoginWithDiag(ctx, cfg, id, pass, signin.VerifyOptions{Solver: a.solver, Diag: a.verifyDiag})
		if res.CleanupFailed {
			a.operationBlocked.Store(true)
		}
		// Keep busy until the corresponding UI completion. A cleanup failure leaves
		// operationBlocked latched until process restart, even if inputs changed.
		a.post(func() {
			a.verifyCancel = nil
			a.m.finishLoginVerification(request, res)
			a.running.Store(false)
			a.syncTray()
		})
	}()
}
func (a *app) cancelLoginVerification() {
	if !a.m.verifying {
		return
	}
	a.m.verifyCanceled = true
	a.m.verifyMessage = "正在取消验证并关闭验证浏览器…"
	if a.verifyCancel != nil {
		a.verifyCancel()
	}
	a.post(func() {})
}
