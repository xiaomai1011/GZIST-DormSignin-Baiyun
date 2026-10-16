package signin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/io"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

const verifyCAS = "https://ids.gzist.edu.cn/lyuapServer/login"
const maxAuthBody = 64 * 1024

// responseBodyBudget bounds the post-click body read so a stalled CDP call can
// never outlive the verification budget or block the event reader.
const responseBodyBudget = 8 * time.Second

// verifyFormBudget bounds how long we wait for the CAS form to render.
const verifyFormBudget = 45 * time.Second

func verificationIssue(i AuthIssue) VerificationResult {
	return VerificationResult{Issue: i, Reason: authReason(i)}
}

// verificationReply attaches the fixed internal reason to a result.
func verificationReply(i AuthIssue, code VerifyReason) VerificationResult {
	res := verificationIssue(i)
	res.ReasonCode = code
	return res
}

// verificationText attaches a fixed, safe message that is more specific than
// the issue-wide default. The text is a compile-time constant, never error text.
func verificationText(i AuthIssue, code VerifyReason, text string) VerificationResult {
	res := verificationReply(i, code)
	res.Reason = text
	return res
}

// finalResultForUser is the one place where a verification outcome becomes the
// text the card shows. It exists because the previous code overwrote every
// AuthUnknown result with a single generic sentence, discarding the specific
// reason that had just been established.
//
// Contract:
//   - a reason-specific fixed text is attached for the unknown family, so an
//     unlisted business code, an unreadable body, a timeout and a missing
//     response read differently;
//   - only AuthCredentialsRejected may ever imply a wrong password, and that
//     text is set by its own classifier, never here;
//   - the text is a constant: nothing derived from the server (code value,
//     hash, error text, ticket, URL) is interpolated.
func finalResultForUser(res VerificationResult) VerificationResult {
	if !res.OK && res.Issue == AuthUnknown {
		res.Reason = unknownReasonText(res.ReasonCode)
	}
	return res
}

func verificationContextIssue(ctx context.Context) VerificationResult {
	if ctx.Err() == context.Canceled {
		return verificationReply(AuthCanceled, ReasonCanceled)
	}
	// The outer budget elapsed: this is a timeout, not a credential answer.
	return verificationReply(AuthUnknown, ReasonVerificationTimeout)
}

// returnContextIssue classifies a caller-context termination and latches it.
// User cancellation and budget timeouts stay distinct from network failures.
func returnContextIssue(trace *verifyTrace, ctx context.Context) VerificationResult {
	res := verificationContextIssue(ctx)
	trace.failHere(res.ReasonCode, contextErrClass(ctx))
	return trace.done(res)
}

// VerifyOptions carries the injectable parts of one verification run.
type VerifyOptions struct {
	Solver *captcha.Solver
	// Diag receives exactly one sanitized summary line per run. Nil disables it;
	// the line never contains credentials, tickets, URLs, bodies or page text.
	Diag func(string)
}

// VerifyLogin deliberately never invokes Runner.Run, geolocation, ledger or sign-in actions.
// A new disposable profile prevents existing cookies from passing this password check.
func VerifyLogin(ctx context.Context, cfg store.Settings, id, pass string, solver *captcha.Solver) VerificationResult {
	return VerifyLoginWithDiag(ctx, cfg, id, pass, VerifyOptions{Solver: solver})
}

// VerifyLoginWithDiag is VerifyLogin plus the bounded, de-identified trace.
func VerifyLoginWithDiag(ctx context.Context, cfg store.Settings, id, pass string, opts VerifyOptions) (result VerificationResult) {
	trace := newVerifyTrace(opts.Diag)
	defer trace.finish()

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return trace.done(verificationContextIssue(ctx))
	}
	if opts.Solver == nil {
		return trace.done(verificationReply(AuthUnknown, ReasonLaunchFailed))
	}
	if strings.TrimSpace(id) == "" || pass == "" {
		return trace.done(VerificationResult{Issue: AuthUnknown, Reason: "请先填写学号和密码"})
	}
	dir, err := os.MkdirTemp("", "dormsign-verify-")
	if err != nil {
		trace.failHere(ReasonLaunchFailed, classifyOpError(err))
		return trace.done(verificationText(AuthUnknown, ReasonLaunchFailed, "验证环境初始化失败，无法判断账号密码"))
	}
	cfg.UserData = dir
	sess, err := edge.LaunchContext(ctx, cfg)
	// LaunchContext(nil,error) does not prove process-tree cleanup; retain directory
	// and require application restart, even if the parent was canceled meanwhile.
	if err != nil || sess == nil {
		trace.failHere(ReasonLaunchFailed, classifyOpError(err))
		trace.cleanupDone(false) // the temp directory may remain; cleanup is unconfirmed
		res := verificationText(AuthUnknown, ReasonLaunchFailed, "验证浏览器启动失败，无法判断账号密码；为防残留进程，请退出程序后重新打开再试")
		res.CleanupFailed = true
		return trace.done(res)
	}
	trace.at(StageBrowserReady)
	defer func() {
		finishVerificationCleanup(&result, dir, sess.Close, os.RemoveAll)
		trace.cleanupDone(!result.CleanupFailed)
		if result.CleanupFailed {
			trace.why(ReasonCleanupUnconfirmed)
		}
	}()
	runCtx, stop := runContext(ctx, sess.Ctx, 90*time.Second)
	defer stop()
	return trace.done(verifyBrowser(runCtx, cfg, id, pass, opts.Solver, trace))
}

// done records the fixed reason. On success the run advances to the
// classification stage; on failure the stage stays where it broke.
func (t *verifyTrace) done(res VerificationResult) VerificationResult {
	if res.OK {
		t.at(StageClassified)
	}
	t.why(res.ReasonCode)
	return res
}

func cleanupVerification(dir string, closeSession func() error, remove func(string) error) error {
	if err := closeSession(); err != nil {
		return err
	}
	return remove(dir)
}

func verificationCleanupFailure() VerificationResult {
	return VerificationResult{Issue: AuthUnknown, CleanupFailed: true, ReasonCode: ReasonCleanupUnconfirmed,
		Reason: "验证浏览器或临时目录未能确认清理完成；请退出并重新启动程序后再操作"}
}

// A deferred pointer update keeps the safety latch even after a successful or
// canceled named return — but it must not erase an earlier failure: the latch
// is additive and the original issue, reason and diagnostics stay intact.
func finishVerificationCleanup(result *VerificationResult, dir string, closeSession func() error, remove func(string) error) {
	if cleanupVerification(dir, closeSession, remove) == nil {
		return
	}
	if result.Issue == AuthNone && !result.OK && result.ReasonCode == ReasonNone {
		// Nothing else went wrong: the cleanup failure is the whole story.
		*result = verificationCleanupFailure()
		return
	}
	result.CleanupFailed = true
}

func ticketEndpoint(raw string) bool {
	if !schoolURL(raw, "ids.gzist.edu.cn") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Path == "/lyuapServer/v1/tickets" && u.RawQuery == "" && u.Fragment == ""
}

// ticketEvidence is the only accepted proof of a successful authentication:
// a freshly issued TGT and ST together. Prefix and minimum length are required.
func ticketEvidence(tgt, ticket string) bool {
	return strings.HasPrefix(tgt, "TGT-") && len(tgt) > 4 &&
		strings.HasPrefix(ticket, "ST-") && len(ticket) > 3
}

// classifyTicketResponse reads the public CAS client contract: a business code at
// data.code, otherwise a positive TGT/ST pair. The client reads the pair at the
// top level; envelope variants that nest it under data are accepted too, but they
// must still carry the TGT-/ST- prefixes. Everything else stays unknown, and a
// code we do not know is never reported as a wrong password.
// (Implementation moved to classifyTicketResponseDetailed, which also returns
// the de-identified response shape for the trace.)

// classifyTicketResponse keeps the pure single-value form used by tests.
func classifyTicketResponse(status int64, body []byte) VerificationResult {
	res, _ := classifyTicketResponseDetailed(status, body)
	return res
}

// classifyTicketResponseDetailed also returns the de-identified shape snapshot
// for the trace. Precedence follows the public client exactly: a data.code
// object is handled BEFORE any ticket reading — the school's own login page
// never consults tgt/ticket once a code is present, so an explicit failure code
// must not be overridden by stray ticket-looking strings.
func classifyTicketResponseDetailed(status int64, body []byte) (VerificationResult, responseShape) {
	shape := inspectResponseShape(body)
	if status != 200 && status != 201 {
		return verificationReply(AuthUnknown, ReasonHTTPStatusUnexpected), shape
	}
	if len(body) == 0 {
		return verificationReply(AuthUnknown, ReasonResponseBodyUnavail), shape
	}
	if len(body) > maxAuthBody {
		return verificationReply(AuthUnknown, ReasonResponseBodyTooLarge), shape
	}
	var v struct {
		TGT    string          `json:"tgt"`
		Ticket string          `json:"ticket"`
		Data   json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &v) != nil {
		return verificationReply(AuthUnknown, ReasonResponseSchemaUnknown), shape
	}
	var nested struct {
		TGT    string `json:"tgt"`
		Ticket string `json:"ticket"`
	}
	if len(v.Data) > 0 && string(v.Data) != "null" {
		// The code is read through the same extractor as the shape record, so
		// classification and diagnostics can never disagree about which code
		// was seen. A present-but-unlisted code — string, number or boolean,
		// exactly like the client's truthiness test — is a business outcome we
		// cannot name: unknown, never a password verdict.
		// Only a TRUTHY code takes the client's code branch. A present but
		// falsy value (0, -0, false, "", null) is ignored by the client exactly
		// like an absent one, so ticket evidence below must still be judged.
		if code := extractBusinessCode(v.Data); code.Truthy {
			issue, known := businessIssue(code.Value)
			if !known {
				return verificationReply(AuthUnknown, ReasonUnknownBusinessCode), shape
			}
			return verificationIssue(issue), shape
		}
		// data may still be the business envelope (an object) holding nested
		// ticket evidence; that is checked below.
		var obj map[string]json.RawMessage
		if json.Unmarshal(v.Data, &obj) == nil {
			_ = json.Unmarshal(v.Data, &nested)
		}
	}
	if ticketEvidence(v.TGT, v.Ticket) || ticketEvidence(nested.TGT, nested.Ticket) {
		return VerificationResult{OK: true, Reason: "账号密码验证通过（CAS 已签发新认证票据）"}, shape
	}
	return verificationReply(AuthUnknown, ReasonResponseSchemaUnknown), shape
}

// trustedAuthURL is the exact auth endpoint; the Fetch interception pattern
// matches it literally so no other request is ever paused.
const trustedAuthURL = "https://ids.gzist.edu.cn/lyuapServer/v1/tickets"

// errBodyLimitExceeded marks a paused body stream that grew past the cap.
var errBodyLimitExceeded = errors.New("response body exceeds the capture limit")

type authObservation struct {
	mu      sync.Mutex
	armed   bool
	request network.RequestID
	status  int64
	valid   bool
	decoded int64
	out     chan VerificationResult
	trace   *verifyTrace
	// done latches the first final result so repeated LoadingFinished events
	// cannot produce a second one.
	done bool
	// fetchBody is injectable: tests never need a real CDP session, and the
	// production read is bounded by a timeout instead of stalling the reader.
	fetchBody func(context.Context, network.RequestID) ([]byte, error)
	// Injected trust predicates for loopback tests; nil = production defaults.
	matchEndpoint func(string) bool
	matchDocument func(string) bool
	// pagePrompt reads the fixed error regions of the trusted login page. It is
	// injectable because a loopback page is not the school's host, and it is
	// strictly typed: a read reports whether the document could be read at all,
	// separately from what it showed. nil = production reader.
	pagePrompt func(context.Context) promptRead
	// Fetch interception: the navigation-proof capture path. fetchOn records a
	// successful Fetch.enable; takeBody/release are injectable for tests.
	fetchOn      bool
	fetchPattern string
	takeBody     func(context.Context, fetch.RequestID) ([]byte, error)
	release      func(context.Context, *fetch.EventRequestPaused, []byte, error) bool
	// Shutdown coordination: one lock, one counter, one seal.
	//   sealed  — set once; after it the listener starts NO new async work
	//             (late pauses go to the synchronous sweep instead);
	//   pending — async pause tasks currently running;
	//   settled — closed when sealed && pending == 0.
	// The listener's check-and-increment and disableFetch's seal-and-check run
	// under the same mutex, so there is no window in which a task can still
	// start after the counter was observed to be zero.
	sealed  bool
	pending int
	settled chan struct{}
	// dropped holds pauses that arrived after the seal. They are released by a
	// synchronous, bounded sweep inside the shutdown — never by a goroutine
	// that could outlive it. droppedLost counts any that could not be held
	// (beyond the bound) or that arrived after the sweep had already run: for
	// those the interception no longer exists, so Chromium resumes them by
	// itself, and the count keeps the fact observable instead of forgotten.
	dropped     []*fetch.EventRequestPaused
	droppedLost int
	swept       bool
	// unload is the injectable Fetch.disable command, so tests can assert the
	// unload ordering without a CDP session. nil = production.
	unload func(context.Context) error
	// Network-side response evidence, set by EventResponseReceived. The fetch
	// capture path waits for it before trusting a body: cache/Service-Worker
	// status is only known here.
	respSeen   bool
	respValid  bool
	respCached bool
}

func (o *authObservation) endpointOK(raw string) bool {
	if o.matchEndpoint != nil {
		return o.matchEndpoint(raw)
	}
	return ticketEndpoint(raw)
}

func (o *authObservation) documentOK(raw string) bool {
	if o.matchDocument != nil {
		return o.matchDocument(raw)
	}
	return casLoginURL(raw)
}

func (o *authObservation) arm() { o.mu.Lock(); o.armed = true; o.mu.Unlock() }

func (o *authObservation) emit(r VerificationResult) {
	select {
	case o.out <- r:
	default:
	}
}

// finalize delivers the single final result of this observation.
func (o *authObservation) finalizeLocked(r VerificationResult) {
	if o.done {
		return
	}
	o.done = true
	o.emit(r)
}

func (o *authObservation) finalize(r VerificationResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finalizeLocked(r)
}

// body performs the bounded response read.
func (o *authObservation) body(ctx context.Context, id network.RequestID) ([]byte, error) {
	if o.fetchBody != nil {
		return o.fetchBody(ctx, id)
	}
	return network.GetResponseBody(id).Do(exec(ctx))
}

func (o *authObservation) listen(ctx context.Context, ev any) {
	// Fetch pauses carry a release obligation even after the result is final,
	// so they are handled before the one-shot done check.
	if e, ok := ev.(*fetch.EventRequestPaused); ok {
		// The CDP event reader must never block on commands: all fetch work —
		// bounded stream read, release, classification — happens in a goroutine
		// with its own budget. Registration and the seal check share one lock,
		// so no handler can start after the shutdown boundary was observed.
		if !o.registerPause(e) {
			// Past the final boundary: starting another goroutine here would be
			// exactly the untracked work the seal forbids. The pause is queued
			// for the synchronous, bounded release sweep that runs before Fetch
			// is unloaded, so it is still released — just never in the
			// background.
			return
		}
		go func() {
			defer o.finishPause()
			o.handlePaused(ctx, e)
		}()
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		return
	}
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		// Only a fresh POST from this page, to the trusted endpoint, counts.
		if o.armed && o.request == "" && e.Request.Method == "POST" && o.endpointOK(e.Request.URL) && o.documentOK(e.DocumentURL) {
			o.request = e.RequestID
			if o.trace != nil {
				o.trace.requestID(string(e.RequestID))
			}
		}
	case *network.EventResponseReceived:
		if e.RequestID == o.request && o.request != "" {
			// With Fetch interception active the response URL can be empty
			// (the response is withheld until the pause is released). An empty
			// URL adds no redirect information, so the already-verified request
			// endpoint stands; a non-empty URL must still match.
			urlOK := e.Response.URL == "" || o.endpointOK(e.Response.URL)
			// Both views are written from the same evidence: o.valid feeds the
			// legacy network path, o.respValid feeds the fetch capture path —
			// they must never diverge.
			o.valid = urlOK && !e.Response.FromDiskCache && !e.Response.FromServiceWorker
			o.respValid = o.valid
			o.status = e.Response.Status
			o.respSeen = true
			o.respCached = e.Response.FromDiskCache || e.Response.FromServiceWorker
			if o.trace != nil {
				o.trace.response(e.Response.Status, 0, boolStr(o.valid), boolStr(o.respCached))
			}
		}
	case *network.EventDataReceived:
		if e.RequestID == o.request && o.request != "" {
			o.decoded += e.DataLength
		}
	case *network.EventLoadingFailed:
		if e.RequestID == o.request && o.request != "" {
			o.finalizeLocked(verificationReply(AuthNetwork, ReasonNetworkFailed))
		}
	case *network.EventLoadingFinished:
		if e.RequestID != o.request || o.request == "" {
			return
		}
		if o.fetchOn {
			// The interception path owns the verdict. LoadingFinished must not
			// finalize here at all: with interception the evidence events can
			// be dispatched out of order (respReceived may lag LoadingFinished
			// until the pause is released), so o.valid may still be unset.
			return
		}
		if !o.valid {
			o.finalizeLocked(verificationReply(AuthUnknown, ReasonResponseNotReceived))
			return
		}
		if o.decoded > maxAuthBody || e.EncodedDataLength > maxAuthBody {
			o.finalizeLocked(verificationReply(AuthUnknown, ReasonResponseBodyTooLarge))
			return
		}
		request, status, trusted := o.request, o.status, o.valid
		// CDP callbacks must not block the event reader. No bodies/tickets are logged.
		go func() {
			bctx, cancel := context.WithTimeout(ctx, responseBodyBudget)
			defer cancel()
			b, err := o.body(bctx, request)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					o.finalize(verificationReply(AuthCanceled, ReasonCanceled))
					return
				}
				reason := classifyBodyReadError(err)
				if o.trace != nil {
					o.trace.failHere(reason, classifyOpError(err))
				}
				o.finalize(verificationReply(AuthUnknown, reason))
				return
			}
			if len(b) == 0 {
				if o.trace != nil {
					o.trace.failHere(ReasonBodyEmpty, ErrClassNone)
				}
				o.finalize(verificationReply(AuthUnknown, ReasonBodyEmpty))
				return
			}
			if len(b) > maxAuthBody {
				o.finalize(verificationReply(AuthUnknown, ReasonResponseBodyTooLarge))
				return
			}
			res, shape := classifyTicketResponseDetailed(status, b)
			if o.trace != nil {
				o.trace.shape(shape)
				o.trace.response(status, len(b), boolStr(trusted), "false")
				o.trace.at(StageTicketResponse)
			}
			o.finalize(res)
		}()
	}
}

// enableFetch arms the navigation-proof capture: intercept exactly the trusted
// auth endpoint at the response stage, before the page can redirect away.
func (o *authObservation) enableFetch(ctx context.Context) error {
	pattern := o.fetchPattern
	if pattern == "" {
		pattern = trustedAuthURL
	}
	err := fetch.Enable().WithPatterns([]*fetch.RequestPattern{{
		URLPattern:   pattern,
		RequestStage: fetch.RequestStageResponse,
	}}).Do(exec(ctx))
	if err == nil {
		o.mu.Lock()
		o.fetchOn = true
		o.mu.Unlock()
	}
	return err
}

// maxDroppedPauses bounds the pauses held for the post-seal sweep; beyond it a
// hostile event stream could otherwise extend the shutdown indefinitely.
const maxDroppedPauses = 64

// registerPause takes a slot for an async pause handler. It returns false when
// the shutdown has already sealed — in that case the pause is queued for the
// synchronous sweep instead of being started. Check and increment share one
// lock, which is what makes "no task starts after the wait" hold.
func (o *authObservation) registerPause(ev *fetch.EventRequestPaused) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sealed {
		if !o.swept && len(o.dropped) < maxDroppedPauses {
			o.dropped = append(o.dropped, ev)
		} else {
			o.droppedLost++
		}
		return false
	}
	o.pending++
	return true
}

// finishPause releases the slot taken by registerPause and closes the settled
// channel once the seal is in place and nothing is running any more.
func (o *authObservation) finishPause() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pending--
	if o.sealed && o.pending == 0 {
		o.closeSettledLocked()
	}
}

func (o *authObservation) settleChanLocked() chan struct{} {
	if o.settled == nil {
		o.settled = make(chan struct{})
	}
	return o.settled
}

func (o *authObservation) closeSettledLocked() {
	ch := o.settleChanLocked()
	select {
	case <-ch: // already closed
	default:
		close(ch)
	}
}

// awaitSettled waits, bounded, for in-flight pause work to finish after the
// seal. True means every registered task completed inside the bound.
func (o *authObservation) awaitSettled(ctx context.Context, settled chan struct{}) bool {
	timer := time.NewTimer(responseBodyBudget + releaseBudget + streamCloseBudget)
	defer timer.Stop()
	select {
	case <-settled:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

// sweepBudget bounds the WHOLE post-seal release sweep, not each release: a
// queue of stalled releases must not add up to minutes of shutdown latency.
const sweepBudget = 2 * time.Second

// sweepOutcome is the honest accounting of the pauses that were not handled by
// a normal capture: confirmed releases, failures the command reported, and
// pauses left without any release attempt (queue bound, budget, or a dead
// caller budget). The last group is handed to the session teardown.
type sweepOutcome struct {
	released    int
	failed      int
	unconfirmed int
}

// sweepDropped releases the pauses that arrived after the seal. It runs
// synchronously inside the shutdown — no goroutine outlives it — and never
// reads a response stream: a body-less fulfill makes Chromium serve the
// original body itself, so the page still receives its response while no
// stream handle is ever opened. Every release shares ONE budget; whatever does
// not fit is reported as unconfirmed instead of extending the shutdown.
func (o *authObservation) sweepDropped(ctx context.Context) sweepOutcome {
	o.mu.Lock()
	queued, lost := o.dropped, o.droppedLost
	o.dropped, o.droppedLost = nil, 0
	o.swept = true
	o.mu.Unlock()

	out := sweepOutcome{unconfirmed: lost}
	if len(queued) == 0 {
		return out
	}
	if ctx.Err() != nil {
		// The caller's budget is already gone: spend no further time here.
		// These are reported unconfirmed and left to the session teardown.
		out.unconfirmed += len(queued)
		return out
	}
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), sweepBudget)
	defer scancel()
	for i, ev := range queued {
		if sctx.Err() != nil {
			out.unconfirmed += len(queued) - i
			break
		}
		if o.release(sctx, ev, nil, nil) {
			out.released++
		} else if sctx.Err() != nil {
			// Cut off by the shared budget: unconfirmed, not a reported failure.
			out.unconfirmed++
		} else {
			out.failed++
		}
	}
	return out
}

// takePostSweepLeftover reports the pauses that arrived after the sweep
// snapshot (with the sweep done, every further pause is counted in droppedLost).
// It is read at the unload boundary so the reported state never claims more than
// the snapshot proved. Nothing can observe an arrival after the session itself
// is gone.
func (o *authObservation) takePostSweepLeftover() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := o.droppedLost
	o.droppedLost = 0
	return n
}

func (o *authObservation) unloadFetch(ctx context.Context) error {
	if o.unload != nil {
		return o.unload(ctx)
	}
	return fetch.Disable().Do(exec(ctx))
}

// disableFetch tears the interception down in a fixed order and records the
// outcome:
//  1. seal — stop starting any async pause work (captures and releases alike);
//  2. bounded wait for the work already registered;
//  3. synchronous, bounded release sweep for the pauses that arrived after the
//     seal (they are never handed to a goroutine that could outlive this);
//  4. unload Fetch, then record exactly one lifecycle state, with the leftover
//     count re-read at this boundary so late arrivals are included.
//
// Failure at any stage is reported as such — never as a clean shutdown.
func (o *authObservation) disableFetch(ctx context.Context) {
	o.mu.Lock()
	o.sealed = true
	if o.pending == 0 {
		o.closeSettledLocked()
	}
	settled := o.settleChanLocked()
	o.mu.Unlock()

	drained := o.awaitSettled(ctx, settled)
	out := o.sweepDropped(ctx)

	state := ShutdownOK
	switch {
	case ctx.Err() != nil:
		state = ShutdownAborted
	case !drained:
		state = ShutdownTimeout
	case out.failed > 0 || out.unconfirmed > 0:
		state = ShutdownPartial
	}
	if ctx.Err() == nil {
		if err := o.unloadFetch(ctx); err != nil {
			state = ShutdownUnloadFailed
		}
	}
	// Final accounting at the unload boundary: pauses that arrived after the
	// sweep snapshot are counted here, so "everything cleaned up" is never
	// reported from a stale snapshot.
	out.unconfirmed += o.takePostSweepLeftover()
	if state == ShutdownOK && out.unconfirmed > 0 {
		state = ShutdownPartial
	}
	if o.trace != nil {
		switch {
		case out.failed > 0:
			o.trace.releaseDone(false)
		case out.unconfirmed > 0:
			o.trace.releaseUncertain()
		}
		o.trace.leftoverCount(out.failed + out.unconfirmed)
		o.trace.shutdownState(state)
	}
}

// readPausedBody drains the paused response body through the bounded stream,
// closing the stream explicitly whether the read succeeds or not.
func (o *authObservation) readPausedBody(ctx context.Context, id fetch.RequestID) ([]byte, error) {
	if o.takeBody != nil {
		return o.takeBody(ctx, id)
	}
	stream, err := fetch.TakeResponseBodyAsStream(id).Do(exec(ctx))
	if err != nil {
		return nil, err
	}
	defer func() {
		// The stream handle must not leak; closing is best-effort and safe
		// even when the caller context is already dead.
		cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), streamCloseBudget)
		defer ccancel()
		_ = io.Close(stream).Do(exec(cctx))
	}()
	var out []byte
	for {
		var res io.ReadReturns
		if err := cdp.Execute(exec(ctx), io.CommandRead, io.Read(stream), &res); err != nil {
			return nil, err
		}
		chunk := res.Data
		if res.Base64encoded {
			dec, derr := base64.StdEncoding.DecodeString(chunk)
			if derr != nil {
				return nil, derr
			}
			chunk = string(dec)
		}
		out = append(out, chunk...)
		if len(out) > maxAuthBody {
			return nil, errBodyLimitExceeded
		}
		if res.EOF {
			break
		}
	}
	return out, nil
}

// releaseBudget bounds the release command independently of the read budget:
// a read that consumed its whole budget must still be able to release the
// paused request on a fresh, short-lived context that keeps the executor
// binding (WithoutCancel) but ignores the dead read deadline.
const releaseBudget = 3 * time.Second

const streamCloseBudget = 2 * time.Second

// releasePausedCDP is the production release: fulfill with the ORIGINAL
// response (status, headers, body) so the page proceeds exactly as if no
// interception had happened; on a failed body read it fails the request
// instead — the page's own fetch rejects cleanly rather than hanging.
// Fetch.fulfillRequest expects the body base64-encoded (Chromium decodes it
// with fromBase64), so the captured text is encoded here. The returned bool
// is recorded as the trace's separate release outcome.
// releasePausedCDP is the production release. The CALLER owns the budget: this
// function never extends or re-creates a deadline, so a shared sweep budget is
// genuinely shared (see sweepBudget). Call sites that must survive an expired
// read budget hand in a context from releaseContext.
func (o *authObservation) releasePausedCDP(ctx context.Context, ev *fetch.EventRequestPaused, body []byte, readErr error) bool {
	if ctx.Err() != nil {
		return false
	}
	if readErr != nil {
		if err := fetch.FailRequest(ev.RequestID, network.ErrorReasonFailed).Do(exec(ctx)); err != nil {
			return false
		}
		return true
	}
	params := fetch.FulfillRequest(ev.RequestID, ev.ResponseStatusCode)
	if len(ev.ResponseHeaders) > 0 {
		params = params.WithResponseHeaders(ev.ResponseHeaders)
	}
	if len(body) > 0 {
		params = params.WithBody(base64.StdEncoding.EncodeToString(body))
	}
	return params.Do(exec(ctx)) == nil
}

// releaseContext bounds ONE release command for callers that must not inherit
// the read budget (which may already be exhausted). WithoutCancel keeps the CDP
// executor binding; the caller's deadline is deliberately dropped here, so the
// ctx handed to o.release is always a context the call site is willing to spend.
func (o *authObservation) releaseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), releaseBudget)
}

// evidenceGrace bounds how long the capture path waits for the network-side
// response evidence (cache/Service-Worker trust facts) after a correlated
// pause. The evidence normally precedes the pause; the grace only covers
// scheduling skew.
const evidenceGrace = 2 * time.Second

func (o *authObservation) awaitResponseEvidence(ctx context.Context) bool {
	deadline := time.Now().Add(evidenceGrace)
	for {
		o.mu.Lock()
		seen := o.respSeen
		o.mu.Unlock()
		if seen || ctx.Err() != nil {
			return seen
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// handlePaused is the single fetch pause handler. Trust is restored to the
// same strength as the network path: a pause is only evidence when it can be
// correlated with the verified network request (same NetworkID as the
// RequestWillBeSent we already checked against the trusted CAS document and
// exact endpoint). Unpausable correlation means release-only, never success.
// The release outcome is recorded separately from the auth verdict.
func (o *authObservation) handlePaused(ctx context.Context, ev *fetch.EventRequestPaused) {

	// Correlate: Fetch pauses expose NetworkID — the id the request carries in
	// Network.requestWillBeSent. A pause before its request event (or for an
	// unrelated request) cannot be trusted evidence.
	o.mu.Lock()
	correlated := o.armed && o.request != "" && string(ev.NetworkID) == string(o.request)
	trusted := correlated && !o.done
	o.mu.Unlock()
	status := ev.ResponseStatusCode

	// The read has its own budget; the release runs afterwards on a fresh
	// short context, so a timed-out read can still release the page. cancel
	// is deferred: the canceled-vs-error classification below must inspect
	// bctx before any manual cancellation poisons it.
	bctx, cancel := context.WithTimeout(ctx, responseBodyBudget)
	defer cancel()
	body, err := o.readPausedBody(bctx, ev.RequestID)
	rctx, rcancel := o.releaseContext(ctx)
	releaseOK := o.release(rctx, ev, body, err)
	rcancel()
	if o.trace != nil {
		o.trace.releaseDone(releaseOK)
	}

	if !trusted || (status != 200 && status != 201) {
		return // released, but not our evidence
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(bctx.Err(), context.Canceled) {
			o.finalize(verificationReply(AuthCanceled, ReasonCanceled))
			return
		}
		reason := ReasonBodyReadFailed
		if errors.Is(err, errBodyLimitExceeded) {
			reason = ReasonResponseBodyTooLarge
		} else {
			reason = classifyBodyReadError(err)
		}
		if o.trace != nil {
			o.trace.failHere(reason, classifyOpError(err))
		}
		o.finalize(verificationReply(AuthUnknown, reason))
		return
	}
	if len(body) == 0 {
		if o.trace != nil {
			o.trace.failHere(ReasonBodyEmpty, ErrClassNone)
		}
		o.finalize(verificationReply(AuthUnknown, ReasonBodyEmpty))
		return
	}
	if len(body) > maxAuthBody {
		o.finalize(verificationReply(AuthUnknown, ReasonResponseBodyTooLarge))
		return
	}
	// Trust facts come from the network response evidence only — never
	// fabricated on the capture path. Cache/Service-Worker status is unknown
	// until EventResponseReceived confirms it.
	if !o.awaitResponseEvidence(ctx) {
		if o.trace != nil {
			o.trace.failHere(ReasonResponseEvidenceMissing, ErrClassNone)
		}
		o.finalize(verificationReply(AuthUnknown, ReasonResponseEvidenceMissing))
		return
	}
	o.mu.Lock()
	valid, cached := o.respValid, o.respCached
	o.mu.Unlock()
	if !valid {
		// The network evidence says this response was cached, service-worker
		// served or from a non-trusted endpoint: not admissible.
		o.finalize(verificationReply(AuthUnknown, ReasonResponseNotReceived))
		return
	}
	res, shape := classifyTicketResponseDetailed(status, body)
	if o.trace != nil {
		o.trace.shape(shape)
		o.trace.response(status, len(body), boolStr(valid), boolStr(cached))
		o.trace.at(StageTicketResponse)
	}
	o.finalize(res)
}

// listenForAuth enables network observation before any submission can happen.
// The stage is set before the attempt. The failure latch is applied only when
// the caller context is still alive: a cancellation or timeout that surfaces
// through ctx.Err() must win over the operation error, so the outer
// returnContextIssue classifies it as canceled/timeout instead of network.
func listenForAuth(ctx context.Context, trace *verifyTrace) error {
	trace.at(StageNetworkListen)
	err := network.Enable().WithMaxTotalBufferSize(maxAuthBody * 2).WithMaxResourceBufferSize(maxAuthBody).Do(exec(ctx))
	if err != nil && ctx.Err() == nil {
		trace.failHere(ReasonListenFailed, classifyOpError(err))
	}
	return err
}

// navigateToCAS opens the CAS login page. Same pre-set stage discipline.
func navigateToCAS(ctx context.Context, trace *verifyTrace) error {
	trace.at(StageNavigateCAS)
	err := func() error {
		// A context without a bound CDP session must fail, not panic:
		// chromedp.Navigate dereferences the context directly.
		if chromedp.FromContext(ctx) == nil {
			return errors.New("invalid context")
		}
		return chromedp.Navigate(verifyCAS + "?service=" + url.QueryEscape("https://xsfw.gzist.edu.cn/xsfw/sys/swmzncqapp/*default/index.do")).Do(exec(ctx))
	}()
	if err != nil && ctx.Err() == nil {
		trace.failHere(ReasonNavigateFailed, classifyOpError(err))
	}
	return err
}

func verifyBrowser(ctx context.Context, cfg store.Settings, id, pass string, solver *captcha.Solver, trace *verifyTrace) VerificationResult {
	o := &authObservation{out: make(chan VerificationResult, 1), trace: trace}
	o.release = o.releasePausedCDP
	chromedp.ListenTarget(ctx, func(ev any) { o.listen(ctx, ev) })
	// Enabled before the form is touched so no submission can be missed.
	if err := listenForAuth(ctx, trace); err != nil {
		if ctx.Err() != nil {
			return returnContextIssue(trace, ctx)
		}
		return verificationText(AuthNetwork, ReasonListenFailed, "验证浏览器连接失败，无法判断账号密码")
	}
	if err := navigateToCAS(ctx, trace); err != nil {
		if ctx.Err() != nil {
			return returnContextIssue(trace, ctx)
		}
		return verificationText(AuthNetwork, ReasonNavigateFailed, "无法打开统一认证登录页，无法判断账号密码")
	}
	trace.at(StageOpenCAS)
	formDeadline := time.Now().Add(verifyFormBudget)
	for {
		ready, err := formReady(ctx)
		if err == nil && ready {
			break
		}
		if ctx.Err() != nil {
			return returnContextIssue(trace, ctx)
		}
		if time.Now().After(formDeadline) {
			trace.failHere(ReasonCASFormTimeout, ErrClassNone)
			return verificationText(AuthUnknown, ReasonCASFormTimeout, "登录页未能在限定时间内加载完成")
		}
		if sleepCtx(ctx, 250*time.Millisecond) != nil {
			return returnContextIssue(trace, ctx)
		}
	}
	trace.at(StageCASFormReady)
	r := Runner{Cfg: cfg, Solver: solver}
	threshold := cfg.ConfThr
	if threshold <= 0 {
		threshold = .55
	}
	answer, reason := "", ReasonNone
	for n := 0; n < 3; n++ {
		if ctx.Err() != nil {
			return returnContextIssue(trace, ctx)
		}
		if ready, err := formReady(ctx); err != nil || !ready {
			trace.failHere(ReasonCASFormMissing, ErrClassNone)
			return verificationReply(AuthUnknown, ReasonCASFormMissing)
		}
		du := extractLoginCaptcha(ctx)
		if len(du) < 2*1024*1024 {
			trace.at(StageCaptchaLoaded)
			solved := r.solveDataURL(du)
			if solved.OK && solved.MinScore >= threshold {
				answer = solved.Ans
				trace.at(StageCaptchaSolved)
				break
			}
			reason = ReasonCAPTCHASolveFailed
		} else {
			reason = ReasonCAPTCHANotFound
		}
		if n < 2 {
			refreshLoginCaptcha(ctx)
			if sleepCtx(ctx, 600*time.Millisecond) != nil {
				return returnContextIssue(trace, ctx)
			}
		}
	}
	if answer == "" {
		trace.failHere(reason, ErrClassNone)
		return verificationReply(AuthCaptcha, reason)
	}
	// "Filling credentials" is an operation, not a milestone: the stage moves
	// to it before the first write, so a failed write reports this exact stage
	// instead of the previous captcha milestone.
	trace.at(StageCredsFilling)
	for _, f := range []struct{ sel, val string }{{"#userName", id}, {"#password", pass}, {"#captcha", answer}} {
		if ctx.Err() != nil {
			return returnContextIssue(trace, ctx)
		}
		if !setReactValue(ctx, f.sel, f.val) {
			trace.failHere(ReasonCASFormMissing, ErrClassNone)
			return verificationReply(AuthUnknown, ReasonCASFormMissing)
		}
	}
	trace.at(StageCredsFilled)
	if ctx.Err() != nil {
		return returnContextIssue(trace, ctx)
	}
	// The page-prompt snapshot is taken immediately BEFORE the single submission.
	// Every page sentence read for this run — both the wait loop's poll and the
	// bounded look after the response — is checked against it, so a sentence that
	// was already visible cannot decide the attempt. A snapshot that cannot be
	// taken disables the page path for this run entirely; the submission and the
	// response verdict are unaffected.
	snap := snapshotPagePrompt(o.readPagePrompt(ctx))
	if !snap.sampled {
		trace.pagePrompt(PromptSnapshotFailed)
	}
	o.arm()
	trace.at(StageTicketArmed)
	// Navigation-proof capture: intercept exactly the trusted auth endpoint at
	// the response stage, so the body is read before the page can redirect.
	// On enable failure the legacy post-LoadingFinished read stays as fallback.
	if err := o.enableFetch(ctx); err == nil {
		defer o.disableFetch(ctx)
	}
	// Same discipline for the single submission click.
	trace.at(StageLoginClicking)
	var clicked int
	if err := chromedp.Evaluate(verifyClickLoginJS, &clicked).Do(exec(ctx)); err != nil {
		trace.failHere(ReasonLoginClickFailed, classifyOpError(err))
		return verificationReply(AuthUnknown, ReasonLoginClickFailed)
	}
	if clicked != 1 {
		reason := clickFailureReason(clicked)
		trace.failHere(reason, ErrClassNone)
		return verificationReply(AuthUnknown, reason)
	}
	trace.at(StageLoginClicked)
	// Exactly one password submission, including unknown network outcomes.
	trace.at(StageAwaitResponse)
	return o.awaitAuthResult(ctx, trace, snap)
}

// clickFailureReason keeps the distinct DOM outcomes distinct instead of
// collapsing them into one unexplained unknown.
func clickFailureReason(code int) VerifyReason {
	switch code {
	case 0:
		return ReasonCASPageNotTrusted
	case 3:
		return ReasonCASFormMissing
	case 4:
		return ReasonLoginButtonMissing
	case 5:
		return ReasonLoginButtonNotVisible
	case 6:
		return ReasonLoginClickFailed
	default:
		return ReasonLoginButtonNotClicked
	}
}
