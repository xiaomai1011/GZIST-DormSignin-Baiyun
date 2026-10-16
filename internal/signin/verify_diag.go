// Bounded, de-identified progress reporting for one login verification.
//
// The verification path used to be a black box: every inconclusive outcome read
// the same to the user and left nothing behind. This file adds a fixed stage and
// reason vocabulary so a single run can be explained afterwards.
//
// Failure stages are latched: the first failure fixes failed_stage, and neither
// result classification nor browser cleanup can overwrite it afterwards. The
// cleanup outcome is recorded separately (cleanup=ok/failed), so one summary
// line can carry both "where it broke" and "did the teardown finish".
//
// Concurrency: the same trace is touched by the observation callbacks, the
// async response-body reader and the main verification flow, so every method
// takes the trace mutex. The latch ("first failure wins") is therefore atomic.
//
// It is deliberately impossible to record sensitive data here: the only fields
// are fixed enums, bounded numbers, booleans, a short hash of the CDP request
// id, and a bounded duration. Underlying error texts are classified into a
// fixed whitelist and never logged. Credentials, cookies, TGT/ST values, URLs,
// request or response bodies, captcha images and page text must never be added.
package signin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chromedp/cdproto/cdp"
)

// VerifyStage is a fixed, non-sensitive progress marker. Only these values may
// reach a log. Operations mark the stage *before* they run; milestones after
// they succeed.
type VerifyStage string

const (
	StageLaunchProfile  VerifyStage = "launch_profile"
	StageBrowserReady   VerifyStage = "browser_ready"
	StageNetworkListen  VerifyStage = "network_listen"
	StageNavigateCAS    VerifyStage = "navigate_cas"
	StageOpenCAS        VerifyStage = "open_cas"
	StageCASFormReady   VerifyStage = "cas_form_ready"
	StageCaptchaLoaded  VerifyStage = "captcha_loaded"
	StageCaptchaSolved  VerifyStage = "captcha_solved"
	StageCredsFilling   VerifyStage = "credentials_filling"
	StageCredsFilled    VerifyStage = "credentials_filled"
	StageTicketArmed    VerifyStage = "ticket_request_armed"
	StageLoginClicking  VerifyStage = "login_clicking"
	StageLoginClicked   VerifyStage = "login_clicked"
	StageAwaitResponse  VerifyStage = "await_auth_response"
	StageTicketResponse VerifyStage = "ticket_response_received"
	StageClassified     VerifyStage = "result_classified"
	StageCleanup        VerifyStage = "browser_cleanup"
)

// VerifyReason is the fixed internal reason behind a non-success result.
type VerifyReason string

const (
	ReasonNone                    VerifyReason = ""
	ReasonLaunchFailed            VerifyReason = "launch_failed"
	ReasonListenFailed            VerifyReason = "network_listen_failed"
	ReasonNavigateFailed          VerifyReason = "navigation_failed"
	ReasonCASFormTimeout          VerifyReason = "cas_form_timeout"
	ReasonCAPTCHANotFound         VerifyReason = "captcha_not_found"
	ReasonCAPTCHASolveFailed      VerifyReason = "captcha_solve_failed"
	ReasonCASPageNotTrusted       VerifyReason = "cas_page_not_trusted"
	ReasonCASFormMissing          VerifyReason = "cas_form_missing"
	ReasonLoginButtonMissing      VerifyReason = "login_button_missing"
	ReasonLoginButtonNotVisible   VerifyReason = "login_button_not_visible"
	ReasonLoginClickFailed        VerifyReason = "login_click_failed"
	ReasonLoginButtonNotClicked   VerifyReason = "login_button_not_clicked"
	ReasonTicketRequestNotSeen    VerifyReason = "ticket_request_not_observed"
	ReasonHTTPStatusUnexpected    VerifyReason = "http_status_unexpected"
	ReasonResponseNotReceived     VerifyReason = "response_not_received"
	ReasonResponseBodyUnavail     VerifyReason = "response_body_unavailable"
	ReasonBodyReadFailed          VerifyReason = "body_read_failed"
	ReasonBodyReadTimeout         VerifyReason = "body_read_timeout"
	ReasonBodyResourceGone        VerifyReason = "body_resource_gone"
	ReasonBodyEmpty               VerifyReason = "body_empty"
	ReasonResponseBodyTooLarge    VerifyReason = "response_body_too_large"
	ReasonResponseSchemaUnknown   VerifyReason = "response_schema_unknown"
	ReasonUnknownBusinessCode     VerifyReason = "unknown_business_code"
	ReasonResponseEvidenceMissing VerifyReason = "response_evidence_missing"
	ReasonVerificationTimeout     VerifyReason = "verification_timeout"
	ReasonNetworkFailed           VerifyReason = "network_failed"
	// Page-prompt reasons: the response body carried no code we could classify,
	// but the login page's own error regions named the outcome afterwards. They
	// are separate reasons so the refinement is auditable and never silently
	// merged into the response verdict.
	ReasonPageAuthPrompt       VerifyReason = "page_auth_prompt"
	ReasonPagePasswordCounter  VerifyReason = "page_password_counter"
	ReasonPagePasswordLocked   VerifyReason = "page_password_locked"
	ReasonPageGenericRejection VerifyReason = "page_generic_rejection"
	ReasonCanceled                VerifyReason = "canceled"
	ReasonCleanupUnconfirmed      VerifyReason = "cleanup_unconfirmed"
)

// VerifyErrClass is a fixed, whitelisted classification of an underlying
// operation error. The error text itself is never logged — only this token is.
type VerifyErrClass string

const (
	ErrClassNone         VerifyErrClass = ""
	ErrClassDNS          VerifyErrClass = "dns_failed"
	ErrClassConnTimeout  VerifyErrClass = "connection_timeout"
	ErrClassConnRefused  VerifyErrClass = "connection_refused"
	ErrClassConnReset    VerifyErrClass = "connection_reset"
	ErrClassTLS          VerifyErrClass = "tls_failed"
	ErrClassTargetClosed VerifyErrClass = "target_closed"
	ErrClassCDP          VerifyErrClass = "cdp_failed"
	ErrClassCanceled     VerifyErrClass = "canceled"
	ErrClassUnknown      VerifyErrClass = "unknown"
)

// classifyOpError maps an underlying error to the fixed whitelist. Typed checks
// come first; Chromium network error codes next (navigation failures surface
// them verbatim); a bounded keyword pass is the last resort. The message is
// only read in-process for classification and never reaches a log or the UI.
func classifyOpError(err error) VerifyErrClass {
	if err == nil {
		return ErrClassNone
	}
	if errors.Is(err, context.Canceled) {
		return ErrClassCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrClassConnTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrClassConnTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ErrClassConnRefused
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return ErrClassConnReset
	}
	var cdpe cdp.Error
	if errors.As(err, &cdpe) {
		return ErrClassCDP
	}
	return classifyErrorText(err.Error())
}

// classifyErrorText maps known error-text shapes onto the whitelist. Unknown
// stays unknown: a guess must never look like evidence.
func classifyErrorText(msg string) VerifyErrClass {
	s := strings.ToLower(msg)
	if c, hit := classifyChromiumCode(s); hit {
		return c
	}
	switch {
	case strings.Contains(s, "no such host"), strings.Contains(s, "lookup "), strings.Contains(s, "dns"):
		return ErrClassDNS
	case strings.Contains(s, "refused"):
		return ErrClassConnRefused
	case strings.Contains(s, "reset by peer"), strings.Contains(s, "connection reset"):
		return ErrClassConnReset
	case strings.Contains(s, "tls:"), strings.Contains(s, "x509"), strings.Contains(s, "certificate"):
		return ErrClassTLS
	case strings.Contains(s, "target closed"), strings.Contains(s, "browser has crashed"),
		strings.Contains(s, "closed network connection"), strings.Contains(s, "broken pipe"):
		return ErrClassTargetClosed
	case strings.Contains(s, "timed out"), strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return ErrClassConnTimeout
	case strings.Contains(s, "websocket"), strings.Contains(s, "devtools"), strings.Contains(s, "cdp"),
		strings.Contains(s, "invalid context"), strings.Contains(s, "executor"):
		return ErrClassCDP
	}
	return ErrClassUnknown
}

// classifyChromiumCode extracts the first complete `net::ERR_*` token and maps
// **whole tokens only**. The second return value reports whether a Chromium
// code was present at all: when it was but the token is not whitelisted, the
// result is unknown and the surrounding text must not re-classify it (a
// message like "net::ERR_FOO … dns timeout" stays unknown, not dns_failed).
func classifyChromiumCode(s string) (VerifyErrClass, bool) {
	const prefix = "net::err_"
	s = strings.ToLower(s)
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ErrClassUnknown, false
	}
	rest := s[idx+len(prefix):]
	end := len(rest)
	for i, r := range rest {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			end = i
			break
		}
	}
	switch prefix + rest[:end] {
	case "net::err_name_not_resolved":
		return ErrClassDNS, true
	case "net::err_connection_refused":
		return ErrClassConnRefused, true
	case "net::err_connection_reset":
		return ErrClassConnReset, true
	case "net::err_connection_timed_out", "net::err_timed_out":
		return ErrClassConnTimeout, true
	case "net::err_cert_authority_invalid", "net::err_cert_common_name_invalid",
		"net::err_cert_date_invalid", "net::err_cert_name_constraint_violation",
		"net::err_ssl_protocol_error":
		return ErrClassTLS, true
	case "net::err_aborted":
		return ErrClassCanceled, true
	}
	return ErrClassUnknown, true
}

// contextErrClass classifies a caller-context termination. User cancellation is
// never reported as a network problem; a budget timeout maps to the timeout
// class (the reason code verification_timeout disambiguates the source).
func contextErrClass(ctx context.Context) VerifyErrClass {
	switch {
	case ctx.Err() == nil:
		return ErrClassNone
	case ctx.Err() == context.Canceled:
		return ErrClassCanceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrClassConnTimeout
	}
	return ErrClassNone
}

// classifyBodyReadError splits the formerly lumped response-body failures into
// fixed, distinguishable reasons. The raw error text is only read in-process.
//
// Evidence base: CDP answers Network.getResponseBody for a request whose
// navigation has already committed with an error ("No data found for resource
// with given identifier"); a stalled session surfaces as the read budget's
// deadline. These two are the shapes behind real verification logs.
func classifyBodyReadError(err error) VerifyReason {
	if err == nil {
		return ReasonBodyEmpty
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonBodyReadTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ReasonBodyReadTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ReasonCanceled
	}
	var cdpe cdp.Error
	if errors.As(err, &cdpe) && strings.Contains(strings.ToLower(cdpe.Error()), "no data found for resource") {
		return ReasonBodyResourceGone
	}
	if strings.Contains(strings.ToLower(err.Error()), "no data found for resource") {
		return ReasonBodyResourceGone
	}
	return ReasonBodyReadFailed
}

// responseShape is the de-identified protocol snapshot of one auth response:
// booleans and a bounded hash only. The business-code VALUE itself is untrusted
// server data and never recorded — the hash merely lets two runs with the same
// unknown code be correlated without revealing it.
type responseShape struct {
	topTGT     bool
	topTicket  bool
	dataObject bool
	// codePresent is the diagnostic fact: the data.code key exists at all.
	// codeTruthy is the behavioural fact: the client's `if (data.code)` test —
	// JavaScript truthiness — would take its business-code branch. They are
	// deliberately separate: {"code":0} and {"code":false} exist but are falsy,
	// so the client ignores them and ticket evidence must still be checked.
	codePresent bool
	codeTruthy  bool
	codeKnown   bool
	codeType    string // "str" | "num" | "bool" | "null" | "other"
	codeHash    string // first 8 hex of sha256(code string form), "" when not comparable
}

func (s responseShape) codeState() string {
	switch {
	case !s.codePresent:
		return "none"
	case !s.codeTruthy:
		return "falsy"
	case s.codeKnown:
		return "known"
	}
	return "unlisted"
}

func (s responseShape) hashOrNone() string {
	if s.codeHash == "" {
		return "none"
	}
	return s.codeHash
}

// businessCode is what the client's `if (data.code)` test sees, split into the
// two facts that must not be confused: whether the key exists, and whether the
// client would actually take its business-code branch.
type businessCode struct {
	Present bool   // the data.code key exists
	Truthy  bool   // JavaScript truthiness — the client would enter its code branch
	Value   string // exact comparison key when the value is comparable, else ""
	Kind    string // "str" | "num" | "bool" | "null" | "other"
}

// extractBusinessCode reads the business code exactly where the public client
// reads it — data.code — and reports both facts above.
//
// The client's test is JavaScript truthiness (`if (r.data.data.code)`), and the
// falsy values are: false, 0, -0, NaN, "" and null. Of those, JSON can carry
// false, 0/-0, "" and null; NaN is not representable in JSON, and an empty
// object/array is TRUTHY in JavaScript. Getting this wrong is not cosmetic: if a
// falsy code were treated as a business code, a response carrying a valid ticket
// alongside {"code":0} would be stopped as "unknown" instead of being judged on
// its ticket evidence.
//
// Matching itself is byte-exact: the value is never trimmed or case-folded.
func extractBusinessCode(data json.RawMessage) businessCode {
	if len(data) == 0 || string(data) == "null" {
		return businessCode{}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return businessCode{}
	}
	raw, ok := obj["code"]
	if !ok {
		return businessCode{}
	}
	out := businessCode{Present: true}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		out.Kind = "null" // no value: falsy, like the absent case
		return out
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		out.Kind = "str"
		out.Value = str
		out.Truthy = str != "" // "" is falsy; even "0" is a truthy non-empty string
		return out
	}
	if n, err := strconv.ParseFloat(trimmed, 64); err == nil {
		out.Kind = "num"
		out.Value = trimmed
		out.Truthy = n != 0 // 0 and -0 are falsy, every other number is truthy
		return out
	}
	switch trimmed {
	case "true":
		out.Kind, out.Truthy = "bool", true
		return out
	case "false":
		out.Kind = "bool" // falsy
		return out
	}
	out.Kind, out.Truthy = "other", true // {} and [] are truthy in JavaScript
	return out
}

// inspectResponseShape reads the public CAS contract shapes without recording
// any server text: does the body carry top-level tickets, is data an object,
// does it carry a code, of which JSON type, and is that code one we know.
func inspectResponseShape(body []byte) responseShape {
	var v struct {
		TGT    string          `json:"tgt"`
		Ticket string          `json:"ticket"`
		Data   json.RawMessage `json:"data"`
	}
	shape := responseShape{}
	if json.Unmarshal(body, &v) != nil {
		return shape
	}
	shape.topTGT = strings.HasPrefix(v.TGT, "TGT-")
	shape.topTicket = strings.HasPrefix(v.Ticket, "ST-")
	if len(v.Data) == 0 || string(v.Data) == "null" {
		return shape
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(v.Data, &obj) != nil {
		return shape
	}
	shape.dataObject = true
	code := extractBusinessCode(v.Data)
	if !code.Present {
		return shape
	}
	shape.codePresent = true
	shape.codeTruthy = code.Truthy
	shape.codeType = code.Kind
	if code.Value == "" {
		return shape
	}
	_, shape.codeKnown = businessIssue(code.Value)
	sum := sha256.Sum256([]byte(code.Value))
	shape.codeHash = hex.EncodeToString(sum[:])[:8]
	return shape
}

// Bounds. A diagnostic must not be able to grow without limit.
const (
	maxDiagBytes   = 1 << 20
	maxDiagElapsed = 600 * time.Second
)

// verifyTrace collects the bounded facts of one run and emits exactly one
// summary line at the end. All access is mutex-guarded: the observation
// callbacks, the async body reader and the main flow share one instance.
type verifyTrace struct {
	mu          sync.Mutex
	stage       VerifyStage
	failed      bool
	failedStage VerifyStage
	reason      VerifyReason
	errClass    VerifyErrClass
	cleanup     string
	status      int64
	bodySize    int
	trusted     string // "true" | "false" | "unknown" — written only from real evidence
	cached      string
	seen        bool
	reqHash     string
	codeShape   string // "<state>/<type>/<hash>" — bounded, de-identified
	release     string // pause release outcome: "ok" | "failed" | "uncertain"
	shutdown    string // interception lifecycle outcome (fixed enum)
	leftover    int    // pauses at shutdown whose release we did NOT confirm
	// prompt is the outcome of the bounded page-prompt look (fixed enum). It is
	// the only place the refinement is visible: the summary's reason stays the
	// first reason latched, so a response verdict is never overwritten by it.
	prompt  string
	started time.Time
	emit    func(string)
	// frozen is the diagnostic finalization boundary: once the summary has been
	// produced the reported state must not change any more. Post-freeze write
	// attempts are counted (postFreeze) instead of applied, so the guarantee is
	// observable rather than merely assumed.
	frozen     bool
	postFreeze int
}

// Shutdown lifecycle states — one fixed enum, never free text.
const (
	ShutdownOK           = "ok"             // sealed, drained, swept, unloaded
	ShutdownPartial      = "partial"        // sealed, but some late pauses were not released
	ShutdownTimeout      = "timeout"        // in-flight work did not finish inside the bound
	ShutdownAborted      = "aborted"        // caller budget ended first; unload left to teardown
	ShutdownUnloadFailed = "disable_failed" // the Fetch.disable command itself failed
)

// Page-prompt outcomes — one fixed enum, never page text, never server text.
const (
	PromptNone             = "none"             // the page path was not applicable to this outcome
	PromptSnapshotFailed   = "snapshot_failed"  // no pre-submission snapshot: page sentences are unusable
	PromptInterrupted      = "interrupted"      // cancel/budget ended the look
	PromptNoNewSentence    = "no_new_sentence"  // nothing new or visible inside the look budget
	PromptCredential       = "credential"       // the page named a rejected credential
	PromptLocked           = "locked"           // the page named a lock or a disabled account
	PromptCaptcha          = "captcha"          // the page named a captcha failure
	PromptPasswordCounter  = "password_counter" // the page's wrong-password counter sentence
	PromptPasswordLock     = "password_lock"    // the counter sentence that announces a lock
	PromptGenericRejection = "generic"          // the page said "login failed" and nothing more
)

// promptKind maps a refined verdict onto the fixed enum. The page text itself is
// never recorded.
func promptKind(issue AuthIssue, reason VerifyReason) string {
	switch reason {
	case ReasonPagePasswordCounter:
		return PromptPasswordCounter
	case ReasonPagePasswordLocked:
		return PromptPasswordLock
	case ReasonPageGenericRejection:
		return PromptGenericRejection
	}
	switch issue {
	case AuthCredentialsRejected:
		return PromptCredential
	case AuthLocked:
		return PromptLocked
	case AuthCaptcha:
		return PromptCaptcha
	}
	return PromptNone
}

// pagePrompt records the page-prompt outcome under the same freeze discipline as
// every other diagnostic write.
func (t *verifyTrace) pagePrompt(kind string) {
	if t == nil || kind == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.prompt = kind
}

// shutdownState records the outcome of the interception shutdown.
func (t *verifyTrace) shutdownState(state string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if t.shutdown == "" {
		t.shutdown = state
	}
}

// leftoverCount records how many pauses were left without a confirmed release
// at the shutdown boundary (sweep failures, unattempted sweep entries, queue
// overflow, post-sweep arrivals). Zero is the only value that means "all of the
// pauses we ever saw were released by us".
func (t *verifyTrace) leftoverCount(n int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.leftover = n
}

// releaseUncertain records that a pause could not be released with confidence.
// A definite failure outranks the uncertainty.
func (t *verifyTrace) releaseUncertain() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if t.release != "failed" {
		t.release = "uncertain"
	}
}

// freeze makes the reported state immutable. It is the diagnostic finalization
// boundary: late background work can no longer rewrite what was reported.
func (t *verifyTrace) freeze() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frozen = true
}

// releaseDone records whether a paused request was successfully released —
// kept separate from the auth result so a capture verdict and a release
// failure never overwrite each other.
func (t *verifyTrace) releaseDone(ok bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if ok {
		// Precedence: failed > uncertain > ok. A late success neither erases a
		// failure nor softens an earlier uncertainty.
		if t.release == "" {
			t.release = "ok"
		}
		return
	}
	t.release = "failed"
}

func newVerifyTrace(emit func(string)) *verifyTrace {
	return &verifyTrace{stage: StageLaunchProfile, started: time.Now(), emit: emit}
}

// at records forward progress. Once a failure is latched the stage is frozen:
// neither classification nor cleanup may move it.
func (t *verifyTrace) at(s VerifyStage) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if t.failed {
		return
	}
	t.stage = s
}

// failHere atomically latches the first failure: the stage where it happened,
// one fixed reason and one whitelisted error class. A reason of none latches
// the stage alone (e.g. a definitive DOM verdict needs no process reason).
// Later calls are ignored, so "first failure wins" holds under concurrency,
// not just under the paths the current tests happen to cover.
func (t *verifyTrace) failHere(r VerifyReason, c VerifyErrClass) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if t.failed {
		return
	}
	t.failed = true
	t.failedStage = t.stage
	if r != ReasonNone && t.reason == ReasonNone {
		t.reason = r
	}
	if c != "" && t.errClass == "" {
		t.errClass = c
	}
}

// cleanupDone records the teardown outcome separately from any failure.
func (t *verifyTrace) cleanupDone(ok bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.cleanup = "ok"
	if !ok {
		t.cleanup = "failed"
	}
}

// why records the first reason only: one run has exactly one fixed explanation.
func (t *verifyTrace) why(r VerifyReason) {
	if t == nil || r == ReasonNone {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	if t.reason == ReasonNone {
		t.reason = r
	}
}

// requestID stores a short hash so two runs can be told apart without keeping
// the identifier itself.
func (t *verifyTrace) requestID(id string) {
	if t == nil || id == "" {
		return
	}
	sum := sha256.Sum256([]byte(id))
	hash := hex.EncodeToString(sum[:])[:8]
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.reqHash = hash
	t.seen = true
}

// boolStr renders a boolean for the trace; absence of evidence must be
// recorded as "unknown", never silently as false.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (t *verifyTrace) response(status int64, size int, trusted, cached string) {
	if t == nil {
		return
	}
	if size > maxDiagBytes {
		size = maxDiagBytes
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.status = status
	t.bodySize = size
	t.trusted = trusted
	t.cached = cached
}

// shape records the de-identified response protocol snapshot (booleans, a
// JSON-type enum and a bounded hash — never server text or code values).
func (t *verifyTrace) shape(f responseShape) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.frozen {
		t.postFreeze++
		return
	}
	t.codeShape = f.codeState() + "/" + f.codeType + "/" + f.hashOrNone()
}

func (t *verifyTrace) summary() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.summaryLocked()
}

func (t *verifyTrace) summaryLocked() string {
	elapsed := 0.0
	if !t.started.IsZero() {
		elapsed = time.Since(t.started).Seconds()
		if elapsed < 0 || elapsed > maxDiagElapsed.Seconds() {
			elapsed = maxDiagElapsed.Seconds()
		}
	}
	reason, req := t.reason, t.reqHash
	if reason == ReasonNone {
		reason = "none"
	}
	if req == "" {
		req = "none"
	}
	failedStage, class, cleanup := string(t.failedStage), string(t.errClass), t.cleanup
	if failedStage == "" {
		failedStage = "none"
	}
	if class == "" {
		class = "none"
	}
	if cleanup == "" {
		cleanup = "none"
	}
	shape := t.codeShape
	if shape == "" {
		shape = "none"
	}
	release := t.release
	if release == "" {
		release = "none"
	}
	trusted, cached := t.trusted, t.cached
	if trusted == "" {
		trusted = "unknown"
	}
	if cached == "" {
		cached = "unknown"
	}
	shutdown := t.shutdown
	if shutdown == "" {
		shutdown = "none"
	}
	prompt := t.prompt
	if prompt == "" {
		prompt = PromptNone
	}
	return fmt.Sprintf("验证诊断: stage=%s failed_stage=%s reason=%s error_class=%s cleanup=%s release=%s shutdown=%s leftover=%d code=%s http=%d bytes=%d trusted=%s cached=%s req=%s prompt=%s elapsed=%.1fs",
		t.stage, failedStage, reason, class, cleanup, release, shutdown, t.leftover, shape, t.status, t.bodySize, trusted, cached, req, prompt, elapsed)
}

// finish produces the single summary line and freezes the diagnostic: the
// reported state is final, and any later background write is counted instead
// of applied. Freezing and rendering happen under one lock, so no write can
// slip in between the rendered values and the freeze.
func (t *verifyTrace) finish() {
	if t == nil || t.emit == nil {
		return
	}
	t.mu.Lock()
	t.frozen = true
	line := t.summaryLocked()
	t.mu.Unlock()
	t.emit(line)
}
