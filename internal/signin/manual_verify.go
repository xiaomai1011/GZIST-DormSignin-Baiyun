package signin

// Visible-browser mode: the school's two-factor page is finished by a human in
// the very session the run launched. This file is the read-only half of that —
// it polls the page, and it never fills, clicks, requests a code or submits the
// credentials again. The decision "this is the two-factor page" already exists
// (twoVerifyURL); what is new here is what to do once it is on screen and a
// window is actually visible.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	// manualVerifyPoll is the read cadence while a person works. A person takes
	// tens of seconds, so this costs nothing and keeps the page quiet.
	manualVerifyPoll = 1 * time.Second
	// manualVerifyMaxReadErrors is how many consecutive failed reads mean the
	// page can no longer be read. It is deliberately small, and it is only that:
	// a run of misses does not prove the window was closed (the page may have
	// hung or the connection may have stalled), so it is reported as "closed or
	// disconnected", never as a confirmed cause.
	manualVerifyMaxReadErrors = 3
)

// manualVerifyVerdict is what ended the wait. Each value has exactly one cause,
// because "the run was canceled", "the budget ran out", "the late line passed",
// "the window is gone" and "the human finished" must never be reported as each
// other.
type manualVerifyVerdict int

const (
	manualVerifyReached      manualVerifyVerdict = iota // trusted business page: resume the normal flow, once
	manualVerifyCanceled                                // the caller canceled the run
	manualVerifyBudget                                  // this run's own budget is spent
	manualVerifyStopped                                 // the late line passed: never sign after it
	manualVerifyDisconnected                            // page unreadable or the session context ended: closed or disconnected, not proven which
	manualVerifyUnsupported                             // some other site: do not keep waiting on it
)

func (v manualVerifyVerdict) String() string {
	switch v {
	case manualVerifyReached:
		return "reached"
	case manualVerifyCanceled:
		return "canceled"
	case manualVerifyBudget:
		return "budget"
	case manualVerifyStopped:
		return "late_line"
	case manualVerifyDisconnected:
		return "disconnected"
	case manualVerifyUnsupported:
		return "unsupported"
	}
	return "unknown"
}

// manualVerifyDiag is the desensitized record of one wait: counts, timings and
// the safe page category only. No URL, no query, no page text.
type manualVerifyDiag struct {
	Elapsed    time.Duration
	Reads      int
	ReadErrors int
	LastRead   string // safeDiagnosticError of the last failed read
	Page       string // safePageCategory of the last readable page
}

// manualVerifyPageIsAllowed keeps the wait on the two hosts this flow can
// legitimately pass through: the identity provider (login, two-factor and its
// intermediate pages) and the student-affairs system. Anything else is reported
// instead of being waited on, so a stray redirect cannot be read as progress.
func manualVerifyPageIsAllowed(raw string) bool {
	// schoolURL is the same rule the rest of the flow trusts a page by: https,
	// the exact official host, no userinfo in the URL, and the default port or
	// 443. A page that is merely on the right hostname is not enough here.
	return schoolURL(raw, "ids.gzist.edu.cn") || schoolURL(raw, "xsfw.gzist.edu.cn")
}

// manualVerifyStop classifies a finished context. A read in flight can outlive
// the cancel or the late line, so this is checked before and after every read.
// manualVerifyStop asks the two participants themselves, not just the merged ctx.
// A context keeps the cause of whichever cancel came first, and the caller's
// cancel reaches the merged ctx through an asynchronous AfterFunc, so the merged
// value can be both stale and misattributed: it may say "canceled" because the
// browser closed first, while the caller has since passed the late line, and it
// may still look alive for a moment after the caller actually stopped. Reading
// origins directly removes both races.
func manualVerifyStop(ctx context.Context, origins runOrigins, start time.Time, diag *manualVerifyDiag) (manualVerifyVerdict, bool) {
	diag.Elapsed = time.Since(start)
	// The caller's own state decides first: the late line is a fact about the
	// run, and an explicit stop must not be missed while its propagation is
	// still pending.
	if origins.caller != nil && origins.caller.Err() != nil {
		switch cause := context.Cause(origins.caller); {
		case errors.Is(cause, errLateLine):
			return manualVerifyStopped, true
		case errors.Is(cause, context.DeadlineExceeded):
			// The caller's own deadline is somebody else's budget, not a stop.
			return manualVerifyBudget, true
		}
		return manualVerifyCanceled, true
	}
	// Our own budget is a fact about this run, not about the browser.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return manualVerifyBudget, true
	}
	// In production ctx is derived from the session's browser context (see
	// runContext), so a browser that closes cancels this wait without ever
	// reaching the read-failure branch. Nothing distinguishes "window closed"
	// from "connection lost", so both keep the one honest name.
	if origins.browser != nil && origins.browser.Err() != nil {
		return manualVerifyDisconnected, true
	}
	if ctx.Err() == nil {
		return 0, false
	}
	return manualVerifyCanceled, true
}

// waitForManualVerification polls a page a human is working on until it reaches
// the trusted business page. It reads and sleeps; that is all. Cancellation, the
// run budget and the late line keep their usual priority, and the wait never
// extends any of them.
func waitForManualVerification(ctx context.Context, origins runOrigins, poll time.Duration, ops loginPageOps) (manualVerifyVerdict, manualVerifyDiag) {
	start := time.Now()
	var diag manualVerifyDiag
	if ops.probe == nil || ops.sleep == nil {
		return manualVerifyDisconnected, diag
	}
	failures := 0
	for {
		if v, done := manualVerifyStop(ctx, origins, start, &diag); done {
			return v, diag
		}
		state, probeErr := ops.probe(ctx)
		// The read may have outlived a cancel or the late line: that wins over
		// whatever page it happened to return.
		if v, done := manualVerifyStop(ctx, origins, start, &diag); done {
			return v, diag
		}
		if probeErr != nil {
			diag.ReadErrors++
			failures++
			diag.LastRead = safeDiagnosticError(probeErr)
			if failures >= manualVerifyMaxReadErrors {
				return manualVerifyDisconnected, diag
			}
		} else {
			failures = 0
			diag.Reads++
			diag.Page = safePageCategory(state.URL)
			if schoolURL(state.URL, "xsfw.gzist.edu.cn") {
				return manualVerifyReached, diag
			}
			if !manualVerifyPageIsAllowed(state.URL) {
				return manualVerifyUnsupported, diag
			}
		}
		if err := ops.sleep(ctx, poll); err != nil {
			if v, done := manualVerifyStop(ctx, origins, start, &diag); done {
				return v, diag
			}
			return manualVerifyCanceled, diag
		}
	}
}

// manualVerifyDiagLine is the one log line a wait produces. Fixed enumerations
// only; it is safe to paste and tells the next reader how the wait ended.
func manualVerifyDiagLine(v manualVerifyVerdict, diag manualVerifyDiag) string {
	page := diag.Page
	if page == "" {
		page = "none"
	}
	return fmt.Sprintf("人工验证等待: verdict=%s elapsed=%.1fs reads=%d read_err=%d page=%s",
		v, diag.Elapsed.Seconds(), diag.Reads, diag.ReadErrors, page)
}
