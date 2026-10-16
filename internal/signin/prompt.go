package signin

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// The bound of ONE page-prompt look. The look is short on purpose: it only has to
// cover the gap between releasing the captured response and the page's own error
// modal being rendered. It never extends the caller's budget — the whole look,
// every read inside it and every wait between reads all run on a child of the
// caller's context, so a stalled CDP call cannot turn a two-second look into a
// full-budget stall.
const (
	pagePromptBudget = 2 * time.Second
	pagePromptPoll   = 120 * time.Millisecond
)

// authWaitPoll is how often the fixed error regions are re-read while the
// submission is still being awaited.
const authWaitPoll = 250 * time.Millisecond

// casErrorRegionsJS is the only place a page prompt may EVER be read from: the
// dedicated error modal the public CAS client renders for a rejected login, the
// inline error message spans, and the legacy #errorMsg element. Each region is
// filtered for real visibility, so a hidden or collapsed element is never
// evidence. The page body, help text and form validation messages are never
// scanned.
const casErrorRegionsJS = `Array.from(document.querySelectorAll('.ant-modal-confirm-error .ant-modal-confirm-content,.ant-message-error span,#errorMsg')).filter(function(e){var r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility==='visible'&&s.display!=='none'}).map(function(e){return (e.innerText||'').trim()})`

// casPagePromptJS reads the fixed error regions of the TRUSTED login page. It
// reports two independent facts: whether the document could be read at all
// (sampled) and what it showed (parts). A different host, a non-https origin, a
// page the flow navigated away to, or a failed read all report sampled=false —
// an unreadable document is NOT the same as a document with no prompt, and the
// callers must be able to tell them apart.
const casPagePromptJS = `(function(){
 if(!` + casPageTrustJS + `)return '{"sampled":false}';
 return JSON.stringify({"sampled":true,"parts":(` + casErrorRegionsJS + `)});
})()`

// promptRead is one read of the fixed error regions.
//
//	sampled=false           the document could not be read (not the trusted CAS
//	                        page, a failed command, a dead context);
//	sampled=true, no parts  the trusted document was read and showed nothing.
type promptRead struct {
	sampled bool
	parts   []string
}

func parsePromptRead(raw string) promptRead {
	var v struct {
		Sampled bool     `json:"sampled"`
		Parts   []string `json:"parts"`
	}
	if json.Unmarshal([]byte(raw), &v) != nil {
		return promptRead{}
	}
	parts := make([]string, 0, len(v.Parts))
	for _, part := range v.Parts {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}
	return promptRead{sampled: v.Sampled, parts: parts}
}

// casPagePrompt is the production reader. It reads text and nothing else: no
// click, no typing, no reload, no captcha refresh, no request of any kind. The
// caller's context bounds the command.
func casPagePrompt(ctx context.Context) promptRead {
	if ctx.Err() != nil {
		return promptRead{}
	}
	var raw string
	if err := chromedp.Evaluate(casPagePromptJS, &raw).Do(exec(ctx)); err != nil {
		return promptRead{}
	}
	return parsePromptRead(raw)
}

// The fixed sentences the public CAS client itself renders on a rejected login.
// They are compile-time constants copied verbatim from the school's own
// frontend bundle (the saved public build, sha256 c418f62b…, offsets ~17885
// CODEFALSE / ~19042 NOUSER / ~19488 USERLOCK / ~20121 the unlisted-code else
// branch / ~21159 the response-without-evidence else branch). Nothing here is
// derived from a response, a code value or server text.
//
// Deliberately absent: any sentence that would let a generic failure read as a
// wrong password. The unlisted-code branch renders "请检查账号或密码是否正确",
// which is a request to check, not a verdict — it stays a generic rejection.
const (
	promptGenericAccountPass = "请检查账号或密码是否正确"
	promptGenericPassword    = "请检查账号密码是否正确"
)

// The two wrong-password counter sentences the unlisted-code branch builds:
//
//	"密码已连续错误【"+q+"】次，账号锁定。"
//	"密码已连续错误【"+q+"】次，连续错误【"+P+"】次账号将被锁定。"
//
// where P and q are the two server values from data.split(","). Both are matched
// IN FULL: the digits and the fixed ending are required. A partial overlap (the
// bare prefix, a missing count, extra prose, a non-numeric count) stays unknown
// instead of inheriting a verdict it was never shown to have. Only the presence
// of the counts is read; their values are never used, logged or shown.
var (
	promptCounterLocked = regexp.MustCompile(`^密码已连续错误【[0-9]{1,3}】次，账号锁定。$`)
	promptCounterWarn   = regexp.MustCompile(`^密码已连续错误【[0-9]{1,3}】次，连续错误【[0-9]{1,3}】次账号将被锁定。$`)
)

// promptSnapshot is the state of the fixed error regions BEFORE this submission.
//
// sampled=false means the snapshot could not be taken. Nothing on the page can
// then be attributed to this attempt, so neither reader may use any sentence: an
// unreadable page is not an empty page. The run keeps the verdict of the trusted
// response, and the submission itself is never affected.
type promptSnapshot struct {
	sampled bool
	before  map[string]bool
}

func snapshotPagePrompt(r promptRead) promptSnapshot {
	snap := promptSnapshot{sampled: r.sampled}
	if !r.sampled {
		return snap
	}
	snap.before = make(map[string]bool, len(r.parts))
	for _, part := range r.parts {
		snap.before[part] = true
	}
	return snap
}

// fresh reports whether one sentence is new relative to the snapshot. With a
// failed snapshot nothing is fresh, by construction.
func (s promptSnapshot) fresh(part string) bool {
	return s.sampled && part != "" && !s.before[part]
}

// classifyPagePrompt maps the visible sentences of the fixed error regions onto
// a category. It accepts a sentence only when the snapshot succeeded, when the
// sentence is new relative to it, and when its meaning is one we can verify:
//
//	an exact sentence the CAS client renders for a named cause
//	  -> that cause (credential rejection, lock, captcha);
//	the wrong-password counter sentence, in either of its two exact forms
//	  -> a lock when the sentence announces one, otherwise a credential
//	     rejection;
//	the two generic "check your account/password" sentences
//	  -> a generic rejection: the page says the login did not pass, not that the
//	     password is wrong.
//
// Anything else — help text, a partial overlap, server-shaped text, an empty
// region — yields no verdict, and the run keeps the result it already had.
func classifyPagePrompt(parts []string, snap promptSnapshot) (AuthIssue, VerifyReason, bool) {
	if !snap.sampled {
		return AuthNone, ReasonNone, false
	}
	for _, part := range parts {
		if !snap.fresh(part) {
			continue
		}
		if issue := ClassifyAuthMessage(part); issue != AuthNone {
			return issue, ReasonPageAuthPrompt, true
		}
		switch {
		case promptCounterLocked.MatchString(part):
			return AuthLocked, ReasonPagePasswordLocked, true
		case promptCounterWarn.MatchString(part):
			return AuthCredentialsRejected, ReasonPagePasswordCounter, true
		case part == promptGenericAccountPass || part == promptGenericPassword:
			return AuthUnknown, ReasonPageGenericRejection, true
		}
	}
	return AuthNone, ReasonNone, false
}

// definitivePrompt reports whether a page verdict is one the page states
// outright and may therefore end the wait for the response. A generic sentence
// is not: the response may still name the cause.
func definitivePrompt(issue AuthIssue) bool {
	return issue == AuthCredentialsRejected || issue == AuthLocked || issue == AuthCaptcha
}

// readPagePrompt is the injectable reader. The field is nil in production.
func (o *authObservation) readPagePrompt(ctx context.Context) promptRead {
	if o.pagePrompt != nil {
		return o.pagePrompt(ctx)
	}
	return casPagePrompt(ctx)
}

// pageVerdict is one read of the fixed error regions during the wait, under its
// own short bound. It returns a verdict only for a definitive cause the page
// names about THIS submission: the same snapshot gate as the bounded look, so a
// leftover modal from an earlier attempt can never decide the run — neither
// while waiting for the response nor after it.
//
// The contexts are re-checked AFTER the read returns, not only before it: a read
// that comes back with a usable sentence exactly as the caller's context ends (or
// as this read's own bound runs out) is not evidence, and is never adopted.
func (o *authObservation) pageVerdict(ctx context.Context, snap promptSnapshot) (AuthIssue, VerifyReason, bool) {
	if !snap.sampled {
		return AuthNone, ReasonNone, false
	}
	rctx, cancel := context.WithTimeout(ctx, pagePromptBudget)
	defer cancel()
	read := o.readPagePrompt(rctx)
	if ctx.Err() != nil || rctx.Err() != nil {
		return AuthNone, ReasonNone, false
	}
	if !read.sampled {
		return AuthNone, ReasonNone, false
	}
	issue, reason, matched := classifyPagePrompt(read.parts, snap)
	if !matched || !definitivePrompt(issue) {
		return AuthNone, ReasonNone, false
	}
	return issue, reason, true
}

// promptExpired ends a look: the caller's context keeps priority, so cancel and
// the total budget still own the outcome; the look's own deadline only means
// that nothing new was seen.
func (o *authObservation) promptExpired(ctx context.Context, res VerificationResult) (VerificationResult, bool) {
	if ctx.Err() != nil {
		o.trace.pagePrompt(PromptInterrupted)
		return res, true
	}
	o.trace.pagePrompt(PromptNoNewSentence)
	return res, false
}

// observePagePrompt gives ONE bounded look at the page's own error regions, and
// only for the single outcome that needs it: a trusted, correctly correlated
// response whose business code we could not classify.
//
// Why the look is necessary — code evidence, not a guess: handlePaused releases
// the paused response BEFORE the verdict is delivered (release, then finalize),
// and the wait returns on the first result it reads. The error modal is rendered
// by the page's own script from that response, so a response decided first
// leaves the modal unread; the wait loop's own poll can only ever see a prompt
// that already existed while it was still waiting.
//
// What it refuses to do: click, type, reload, refresh the captcha, resubmit, or
// read anything outside the fixed error regions. The text is classified in
// memory and dropped — never logged, never shown, never interpolated.
//
// The returned bool reports a caller-context termination, so cancel and the
// total budget keep their existing priority over this refinement.
func (o *authObservation) observePagePrompt(ctx context.Context, res VerificationResult, snap promptSnapshot) (VerificationResult, bool) {
	if res.OK || res.Issue != AuthUnknown || res.ReasonCode != ReasonUnknownBusinessCode {
		return res, false
	}
	// Without a snapshot nothing on the page can be attributed to this attempt,
	// so the look is abandoned outright: the response verdict stands, and no time
	// is spent reading a page we could not compare against.
	if !snap.sampled {
		return res, false
	}
	// One child bounds the whole look, every read inside it and every wait
	// between reads: the two seconds are a real ceiling, not a check after the
	// fact.
	lookCtx, cancel := context.WithTimeout(ctx, pagePromptBudget)
	defer cancel()
	for {
		if ctx.Err() != nil {
			return o.promptExpired(ctx, res)
		}
		read := o.readPagePrompt(lookCtx)
		// The contexts are re-checked AFTER the read returns: a sentence that
		// arrives as the caller's context ends, or after this look's own budget
		// ran out, is not evidence about anything. The caller's context keeps
		// priority, so cancel and the total budget still report as such; only the
		// look's own deadline means "nothing new was seen".
		if ctx.Err() != nil || lookCtx.Err() != nil {
			return o.promptExpired(ctx, res)
		}
		if read.sampled {
			if issue, reason, matched := classifyPagePrompt(read.parts, snap); matched {
				o.trace.pagePrompt(promptKind(issue, reason))
				return verificationReply(issue, reason), false
			}
		}
		if sleepCtx(lookCtx, pagePromptPoll) != nil {
			return o.promptExpired(ctx, res)
		}
	}
}

// awaitAuthResult is the wait after the single submission: the first decision
// wins.
//
//	A definitive page verdict may end the wait early, but only a sentence that is
//	new relative to this submission's snapshot, and only for a cause the page
//	states outright — a leftover modal from an earlier attempt and a generic
//	"login failed" sentence can never decide the run.
//
//	The response is the primary evidence: when it arrives the verdict is finalized
//	through finalResultForUser, with the bounded look as the only refinement.
//
//	Cancel and the total budget win over both — and that is re-checked, not
//	assumed from the order of the select cases: when a cancellation and a result
//	become ready at the same moment Go may pick either, so the context is
//	inspected again before any verdict is adopted.
func (o *authObservation) awaitAuthResult(ctx context.Context, trace *verifyTrace, snap promptSnapshot) VerificationResult {
	ticker := time.NewTicker(authWaitPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return returnContextIssue(trace, ctx)
		case result := <-o.out:
			// The select above does not order its ready cases: a context that
			// ended together with the response still wins.
			if ctx.Err() != nil {
				return returnContextIssue(trace, ctx)
			}
			if !result.OK {
				trace.failHere(result.ReasonCode, ErrClassNone)
			}
			// One bounded look at the page's own error regions, only for a
			// response whose code we could not classify, so a prompt the page
			// renders after the release is not lost. Cancel and the total
			// budget keep their priority over it.
			refined, interrupted := o.observePagePrompt(ctx, result, snap)
			if interrupted {
				return returnContextIssue(trace, ctx)
			}
			return finalResultForUser(refined)
		case <-ticker.C:
			issue, reason, ok := o.pageVerdict(ctx, snap)
			if !ok {
				continue
			}
			// Same discipline for a page verdict: it is adopted only while the
			// caller's context is still alive.
			if ctx.Err() != nil {
				return returnContextIssue(trace, ctx)
			}
			trace.failHere(reason, ErrClassNone)
			trace.pagePrompt(promptKind(issue, reason))
			return verificationReply(issue, reason)
		}
	}
}
