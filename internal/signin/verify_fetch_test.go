package signin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
)

// waitResult drains the single final result with a bounded wait.
func waitResult(t *testing.T, o *authObservation) VerificationResult {
	t.Helper()
	select {
	case r := <-o.out:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no final result within 3s")
	}
	return VerificationResult{}
}

func pausedEvent(id, netID string, url, method string, status int64) *fetch.EventRequestPaused {
	return &fetch.EventRequestPaused{
		RequestID:          fetch.RequestID(id),
		NetworkID:          network.RequestID(netID),
		Request:            &network.Request{URL: url, Method: method},
		ResourceType:       network.ResourceTypeXHR,
		ResponseStatusCode: status,
	}
}

// correlatedObservation arms the observation and pins the verified network
// request id, mirroring the production RequestWillBeSent association.
func correlatedObservation(t *testing.T, takeBody func(context.Context, fetch.RequestID) ([]byte, error),
	release func(context.Context, *fetch.EventRequestPaused, []byte, error) bool) *authObservation {
	t.Helper()
	o := &authObservation{out: make(chan VerificationResult, 1), armed: true,
		takeBody: takeBody, release: release}
	o.request = network.RequestID("net-verified")
	// Preset the network-side response evidence (what EventResponseReceived
	// provides in production): trusted, not cache/service-worker served.
	o.respSeen, o.respValid = true, true
	return o
}

// The fetch capture path: an armed trusted pause is read, released via a clean
// passthrough, and produces exactly one success — even though a real flow would
// navigate away right after (that is the whole point of the interception).
func TestFetchPauseCapturesTicketsBody(t *testing.T) {
	var released []string
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(_ context.Context, ev *fetch.EventRequestPaused, body []byte, _ error) bool {
			released = append(released, string(ev.RequestID)+"|"+string(body))
			return true
		})
	ctx := context.Background()
	o.listen(ctx, pausedEvent("f-1", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if !r.OK {
		t.Fatalf("captured body must classify as success: %+v", r)
	}
	if len(released) != 1 || released[0] != "f-1|"+`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}` {
		t.Fatalf("release must be a single clean passthrough of the original body: %q", released)
	}
}

// A pause that cannot be correlated with the verified network request is
// released but never treated as evidence — the fetch path must not weaken
// the trust conditions of the network path.
func TestFetchPauseUncorrelatedIsReleasedWithoutCapture(t *testing.T) {
	var released, captured atomic.Int32
	releasedOne := make(chan struct{})
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			captured.Add(1)
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool {
			released.Add(1)
			close(releasedOne)
			return true
		})
	ctx := context.Background()
	// Same trusted URL, but a different network id: no correlation.
	o.listen(ctx, pausedEvent("f-9", "net-other", trustedAuthURL, "POST", 200))
	select {
	case r := <-o.out:
		t.Fatalf("uncorrelated pause must not produce a result: %+v", r)
	case <-releasedOne:
		// Read+release completed; happens-before holds for the counters.
	case <-time.After(3 * time.Second):
		t.Fatal("pause was never released")
	}
	if released.Load() != 1 || captured.Load() != 1 {
		t.Fatalf("release-only passthrough expected: released=%d captured=%d", released.Load(), captured.Load())
	}
}

// A failed release is recorded in the trace without touching the auth verdict.
func TestFetchPauseReleaseFailureRecorded(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return false })
	o.trace = tr
	o.listen(context.Background(), pausedEvent("f-6", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if !r.OK {
		t.Fatalf("auth verdict must be independent of release outcome: %+v", r)
	}
	tr.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "release=failed") {
		t.Fatalf("release failure must be recorded: %v", lines)
	}
}

// The interception pattern only ever pauses the trusted endpoint, but any
// pause must still be released; an untrusted one is released without capture.
func TestFetchPauseReleasesWithoutCapture(t *testing.T) {
	var reads atomic.Int32
	done := make(chan struct{})
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			reads.Add(1)
			return []byte(`{"whatever":true}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { close(done); return true })
	o.listen(context.Background(), pausedEvent("f-2", "net-verified", "https://evil.example.com/v1/tickets", "POST", 200))
	select {
	case r := <-o.out:
		t.Fatalf("untrusted pause must not produce a result: %+v", r)
	case <-done:
		// Release (and therefore the read) has completed; happens-before holds.
	case <-time.After(3 * time.Second):
		t.Fatal("pause was never released")
	}
	if reads.Load() != 1 {
		t.Fatalf("body must still be read once for the passthrough: %d", reads.Load())
	}
}

// A read failure on the capture path releases with a failure and reports the
// specific read classification; a canceled read reports cancellation.
func TestFetchPauseReadErrors(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		want  VerificationResult
		noRes bool
	}{
		{"generic read error", errors.New("stream broke with private detail"),
			verificationReply(AuthUnknown, ReasonBodyReadFailed), false},
		{"resource gone", errors.New("No data found for resource with given identifier"),
			verificationReply(AuthUnknown, ReasonBodyResourceGone), false},
		{"budget timeout", context.DeadlineExceeded,
			verificationReply(AuthUnknown, ReasonBodyReadTimeout), false},
		{"canceled", context.Canceled,
			verificationReply(AuthCanceled, ReasonCanceled), false},
	}
	for _, tc := range cases {
		var released int
		o := correlatedObservation(t,
			func(context.Context, fetch.RequestID) ([]byte, error) { return nil, tc.err },
			func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { released++; return true })
		o.listen(context.Background(), pausedEvent("f-3", "net-verified", trustedAuthURL, "POST", 200))
		r := waitResult(t, o)
		if r.ReasonCode != tc.want.ReasonCode || r.Issue != tc.want.Issue {
			t.Errorf("%s: got %+v", tc.name, r)
		}
		if released != 1 {
			t.Errorf("%s: pause must be released once, got %d", tc.name, released)
		}
	}
}

// Oversized captured bodies are refused and never classified as success.
func TestFetchPauseOversize(t *testing.T) {
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return append([]byte(`{"tgt":"TGT-x","ticket":"ST-y"},`), make([]byte, maxAuthBody)...), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return true })
	o.listen(context.Background(), pausedEvent("f-4", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if r.OK || r.ReasonCode != ReasonResponseBodyTooLarge {
		t.Fatalf("oversize capture: %+v", r)
	}
}

// The shape snapshot records only booleans, a JSON type and a bounded hash —
// the unknown code's VALUE never reaches the trace.
func TestShapeDiagnosticsOnUnlistedCode(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(s string) { lines = append(lines, s) })
	secret := "SOME_SERVER_SIDE_CODE_9x"
	body, _ := json.Marshal(map[string]any{"data": map[string]any{"code": secret, "data": "5,2"}})
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) { return body, nil },
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return true })
	o.trace = tr
	o.listen(context.Background(), pausedEvent("f-5", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if r.OK || r.ReasonCode != ReasonUnknownBusinessCode {
		t.Fatalf("unlisted code: %+v", r)
	}
	tr.finish()
	if len(lines) != 1 {
		t.Fatalf("exactly one summary line expected: %v", lines)
	}
	line := lines[0]
	if !strings.Contains(line, "code=unlisted/str/") {
		t.Fatalf("shape must mark an unlisted string code: %s", line)
	}
	shape := inspectResponseShape(body)
	if shape.codeHash == "" || !strings.Contains(line, "code=unlisted/str/"+shape.codeHash) {
		t.Fatalf("hash must be present and stable: %s / %s", line, shape.codeHash)
	}
	for _, bad := range []string{secret, "SOME_SERVER", "5,2"} {
		if strings.Contains(line, bad) {
			t.Fatalf("code value leaked into the trace: %s", line)
		}
	}
	// Same code twice → same hash (correlation without disclosure).
	again := inspectResponseShape(body)
	if again.codeHash != shape.codeHash {
		t.Fatal("hash must be deterministic for the same code")
	}
}

func TestInspectResponseShapeBasics(t *testing.T) {
	known := inspectResponseShape([]byte(`{"tgt":"TGT-a","ticket":"ST-b"}`))
	if !known.topTGT || !known.topTicket || known.codePresent {
		t.Fatalf("success shape: %+v", known)
	}
	num := inspectResponseShape([]byte(`{"data":{"code":42}}`))
	if !num.dataObject || num.codeType != "num" || num.codeKnown {
		t.Fatalf("numeric code shape: %+v", num)
	}
	str := inspectResponseShape([]byte(`{"data":{"code":"NOUSER"}}`))
	if str.codeType != "str" || !str.codeKnown || str.codeState() != "known" {
		t.Fatalf("known code shape: %+v", str)
	}
	bad := inspectResponseShape([]byte(`not json at all`))
	if bad.dataObject || bad.codePresent {
		t.Fatalf("non-json shape: %+v", bad)
	}
}

func TestClassifyBodyReadError(t *testing.T) {
	cases := []struct {
		err  error
		want VerifyReason
	}{
		{nil, ReasonBodyEmpty},
		{context.DeadlineExceeded, ReasonBodyReadTimeout},
		{errors.New("No data found for resource with given identifier"), ReasonBodyResourceGone},
		{errors.New("something else"), ReasonBodyReadFailed},
		{context.Canceled, ReasonCanceled},
	}
	for _, tc := range cases {
		if got := classifyBodyReadError(tc.err); got != tc.want {
			t.Errorf("classifyBodyReadError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// Network-side evidence is mandatory: a cached or service-worker-served
// response must never be classified as success, even when the capture path
// holds a well-formed tickets body.
func TestFetchPauseRejectsCacheEvidence(t *testing.T) {
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return true })
	o.mu.Lock()
	o.respSeen, o.respValid, o.respCached = true, false, true // cache-served evidence
	o.mu.Unlock()
	o.listen(context.Background(), pausedEvent("f-7", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if r.OK || r.ReasonCode != ReasonResponseNotReceived {
		t.Fatalf("cache-served response must not authenticate: %+v", r)
	}
}

// No network evidence at all → unknown with the dedicated reason; the capture
// path must not fabricate trusted/cached facts.
func TestFetchPauseWithoutEvidenceStaysUnknown(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return true })
	o.trace = tr
	o.respSeen, o.respValid = false, false // no EventResponseReceived yet
	o.listen(context.Background(), pausedEvent("f-8", "net-verified", trustedAuthURL, "POST", 200))
	r := waitResult(t, o)
	if r.OK || r.ReasonCode != ReasonResponseEvidenceMissing {
		t.Fatalf("missing evidence: %+v", r)
	}
	tr.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "trusted=unknown cached=unknown") {
		t.Fatalf("absent evidence must be recorded as unknown: %v", lines)
	}
}

// traceState reads the diagnostic state directly — the shutdown guarantees are
// about reported state, so the tests must assert that state, not just count
// emitter callbacks (releaseDone/shutdownState update state without emitting).
func traceState(t *testing.T, tr *verifyTrace) (release, shutdown string, frozen bool, postFreeze int) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.release, tr.shutdown, tr.frozen, tr.postFreeze
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Deterministic shutdown-coordination test. Every step is driven by an explicit
// barrier, and the late pause is injected *during* the shutdown window — not
// after disableFetch already returned, which would miss the race entirely.
//  1. a capture is parked mid-read by the test;
//  2. disableFetch must NOT return while that read is in flight;
//  3. a pause arriving during that window must start no stream read and must
//     not be released in the background;
//  4. after the parked read completes, the shutdown drains, sweeps the late
//     pause synchronously, and only then unloads Fetch;
//  5. the reported diagnostic state (not just the emitter count) records it.
func TestFetchShutdownCoordinatesInFlightAndLatePauses(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })

	var reads, releases, unloads atomic.Int32
	var readDone atomic.Bool
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})

	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			reads.Add(1)
			close(readStarted)
			<-releaseRead // parked mid-read under test control
			readDone.Store(true)
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool {
			releases.Add(1)
			return true
		})
	o.trace = tr
	o.unload = func(context.Context) error {
		// Ordering evidence: the unload must never run under a live capture read.
		if !readDone.Load() {
			t.Error("Fetch was unloaded while a capture read was still in flight")
		}
		unloads.Add(1)
		return nil
	}
	ctx := context.Background()

	// 1. a capture is parked mid-read.
	o.listen(ctx, pausedEvent("f-in", "net-verified", trustedAuthURL, "POST", 200))
	<-readStarted

	// 2. shutdown must block while that read is in flight.
	disabled := make(chan struct{})
	go func() {
		o.disableFetch(ctx)
		close(disabled)
	}()
	select {
	case <-disabled:
		t.Fatal("disableFetch returned while a capture read was still in flight")
	case <-time.After(150 * time.Millisecond):
		// correct: still draining the in-flight handler
	}

	// 3. a pause arriving inside the shutdown window: no new read, no
	//    background release (the sweep has not run yet — it is gated on the
	//    in-flight work finishing).
	o.listen(ctx, pausedEvent("f-late", "net-verified", trustedAuthURL, "POST", 200))
	if reads.Load() != 1 {
		t.Fatalf("the late pause must not start a stream read: reads=%d", reads.Load())
	}
	if releases.Load() != 0 {
		t.Fatalf("the late pause must not be released in the background: %d", releases.Load())
	}
	if unloads.Load() != 0 {
		t.Fatalf("nothing may be unloaded mid-shutdown: %d", unloads.Load())
	}

	// 4. let the parked read finish: drain, sweep, then unload.
	close(releaseRead)
	select {
	case <-disabled:
	case <-time.After(5 * time.Second):
		t.Fatal("disableFetch never returned after the in-flight capture finished")
	}
	if reads.Load() != 1 {
		t.Fatalf("exactly one stream read overall: %d", reads.Load())
	}
	if releases.Load() != 2 {
		t.Fatalf("in-flight capture + swept late pause = two releases: %d", releases.Load())
	}
	if unloads.Load() != 1 {
		t.Fatalf("exactly one unload: %d", unloads.Load())
	}

	// 5. the diagnostic state itself records a clean, honest shutdown.
	release, shutdown, frozen, postFreeze := traceState(t, tr)
	if release != "ok" {
		t.Fatalf("release state = %q, want ok", release)
	}
	if shutdown != ShutdownOK {
		t.Fatalf("shutdown state = %q, want %q", shutdown, ShutdownOK)
	}
	if frozen {
		t.Fatal("the trace must not be frozen before the summary is produced")
	}
	if postFreeze != 0 {
		t.Fatalf("no write may be refused before the freeze: %d", postFreeze)
	}

	// 6. the summary is the finalization boundary: state is frozen, and any
	//    later background write is refused instead of applied.
	tr.finish()
	if len(lines) != 1 {
		t.Fatalf("exactly one summary line expected: %v", lines)
	}
	if !strings.Contains(lines[0], "release=ok") || !strings.Contains(lines[0], "shutdown=ok") {
		t.Fatalf("summary must report the clean shutdown: %s", lines[0])
	}
	tr.releaseDone(false)
	tr.shutdownState(ShutdownTimeout)
	tr.at(StageCleanup)
	release, shutdown, frozen, postFreeze = traceState(t, tr)
	if !frozen {
		t.Fatal("the trace must be frozen once the summary was produced")
	}
	if release != "ok" || shutdown != ShutdownOK {
		t.Fatalf("a frozen diagnostic changed: release=%q shutdown=%q", release, shutdown)
	}
	if postFreeze != 3 {
		t.Fatalf("refused post-freeze writes must be counted: %d", postFreeze)
	}
	if tr.summary() != lines[0] {
		t.Fatalf("summary changed after the freeze://n%s//n%s", lines[0], tr.summary())
	}
}

// A canceled caller budget must not be reported as a clean shutdown: the
// unload is left to the session teardown, the state says so, and the straggler
// that finishes afterwards cannot rewrite the reported summary.
func TestFetchShutdownAbortedCannotRewriteReportedState(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	var releases, unloads atomic.Int32
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	stragglerReleased := make(chan struct{})

	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			close(readStarted)
			<-releaseRead
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool {
			if releases.Add(1) == 1 {
				close(stragglerReleased)
			}
			return true
		})
	o.trace = tr
	o.unload = func(context.Context) error { unloads.Add(1); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	o.listen(ctx, pausedEvent("f-in", "net-verified", trustedAuthURL, "POST", 200))
	<-readStarted

	cancel()
	o.disableFetch(ctx) // budget gone: seal, report, leave the unload to teardown
	if unloads.Load() != 0 {
		t.Fatalf("a dead budget must not unload Fetch: %d", unloads.Load())
	}
	_, shutdown, _, _ := traceState(t, tr)
	if shutdown != ShutdownAborted {
		t.Fatalf("shutdown state = %q, want %q", shutdown, ShutdownAborted)
	}

	// The summary is produced while the straggler is still unfinished.
	tr.finish()
	line := lines[0]
	if !strings.Contains(line, "shutdown=aborted") {
		t.Fatalf("summary must not claim a clean shutdown: %s", line)
	}

	// Now let the straggler complete: its late writes must be refused, and the
	// reported summary must stay byte-identical.
	close(releaseRead)
	select {
	case <-stragglerReleased:
	case <-time.After(5 * time.Second):
		t.Fatal("the straggler never released its pause")
	}
	waitFor(t, "the straggler's late writes to be refused", func() bool {
		_, _, _, postFreeze := traceState(t, tr)
		return postFreeze > 0
	})
	if tr.summary() != line {
		t.Fatalf("a late straggler rewrote the reported summary://n%s//n%s", line, tr.summary())
	}
	if len(lines) != 1 {
		t.Fatalf("no second summary line may be emitted: %v", lines)
	}
}

// An unload failure is a shutdown failure — and its text never reaches the log.
func TestFetchShutdownRecordsUnloadFailure(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-x","ticket":"ST-y"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool { return true })
	o.trace = tr
	o.unload = func(context.Context) error { return errors.New("private cdp session detail") }

	o.disableFetch(context.Background())
	_, shutdown, _, _ := traceState(t, tr)
	if shutdown != ShutdownUnloadFailed {
		t.Fatalf("shutdown state = %q, want %q", shutdown, ShutdownUnloadFailed)
	}
	tr.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "shutdown=disable_failed") {
		t.Fatalf("summary must report the unload failure: %v", lines)
	}
	if strings.Contains(lines[0], "private") || strings.Contains(lines[0], "cdp session") {
		t.Fatalf("error text leaked into the diagnostic: %s", lines[0])
	}
}

// The freeze is the diagnostic finalization boundary: every mutator refuses to
// apply a write afterwards, counts it, and the rendered summary cannot change.
func TestDiagnosticFreezesAfterSummary(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	tr.at(StageTicketArmed)
	tr.releaseDone(true)
	tr.shutdownState(ShutdownOK)
	tr.finish()
	before := lines[0]

	tr.releaseDone(false)
	tr.shutdownState(ShutdownTimeout)
	tr.releaseUncertain()
	tr.failHere(ReasonCanceled, ErrClassNone)
	tr.cleanupDone(false)
	tr.response(500, 10, "false", "false")
	tr.requestID("late-request-id")
	tr.shape(responseShape{codePresent: true, codeType: "str", codeHash: "deadbeef"})

	release, shutdown, frozen, postFreeze := traceState(t, tr)
	if !frozen {
		t.Fatal("trace must be frozen after the summary")
	}
	if release != "ok" || shutdown != ShutdownOK {
		t.Fatalf("frozen state changed: release=%q shutdown=%q", release, shutdown)
	}
	if postFreeze != 8 {
		t.Fatalf("all eight post-freeze writes must be refused and counted: %d", postFreeze)
	}
	if tr.summary() != before {
		t.Fatalf("summary changed after the freeze://n%s//n%s", before, tr.summary())
	}
	if len(lines) != 1 {
		t.Fatalf("exactly one line may be emitted: %v", lines)
	}
}

// sawSeal waits for the shutdown seal, so a test can inject pauses precisely
// inside the closing window instead of racing disableFetch's start.
func sawSeal(t *testing.T, o *authObservation) {
	t.Helper()
	waitFor(t, "the shutdown seal", func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		return o.sealed
	})
}

// The sweep has ONE budget for all of its releases. Without it a queue of
// stalled releases would cost 64 x 3s of shutdown latency; with it the whole
// thing is bounded by sweepBudget and the rest is reported unconfirmed.
func TestFetchSweepSharesOneBudget(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })

	var reads, stalled atomic.Int32
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})

	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			reads.Add(1)
			close(readStarted)
			<-releaseRead
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(ctx context.Context, _ *fetch.EventRequestPaused, body []byte, _ error) bool {
			if body == nil {
				// A sweep release: stall until the SHARED budget expires. If the
				// implementation gave every release its own budget, this would
				// happen once per queued pause instead of once overall.
				stalled.Add(1)
				<-ctx.Done()
				return false
			}
			return true
		})
	o.trace = tr
	o.unload = func(context.Context) error { return nil }
	ctx := context.Background()

	o.listen(ctx, pausedEvent("f-in", "net-verified", trustedAuthURL, "POST", 200))
	<-readStarted

	disabled := make(chan struct{})
	go func() {
		o.disableFetch(ctx)
		close(disabled)
	}()
	sawSeal(t, o)

	// Three pauses queue up behind the seal while the capture is still in flight.
	for i := 0; i < 3; i++ {
		o.listen(ctx, pausedEvent(fmt.Sprintf("f-late%d", i), "net-verified", trustedAuthURL, "POST", 200))
	}
	if reads.Load() != 1 {
		t.Fatalf("swept pauses must never read a stream: reads=%d", reads.Load())
	}

	start := time.Now()
	close(releaseRead)
	select {
	case <-disabled:
	case <-time.After(20 * time.Second):
		t.Fatal("disableFetch never returned")
	}
	elapsed := time.Since(start)
	if elapsed > sweepBudget+3*time.Second {
		t.Fatalf("shutdown spent %v on 3 stalled releases: the sweep budget is not shared", elapsed)
	}
	if stalled.Load() != 1 {
		t.Fatalf("exactly one release may stall before the shared budget is spent: %d", stalled.Load())
	}

	release, shutdown, _, _ := traceState(t, tr)
	if release != "uncertain" {
		t.Fatalf("unconfirmed releases must not be reported as clean: %q", release)
	}
	if shutdown != ShutdownPartial {
		t.Fatalf("shutdown state = %q, want %q", shutdown, ShutdownPartial)
	}
	tr.finish()
	if !strings.Contains(lines[0], "leftover=3") {
		t.Fatalf("all three unconfirmed pauses must be counted: %s", lines[0])
	}
	if strings.Contains(lines[0], "shutdown=ok") {
		t.Fatalf("a partial sweep must never report a clean shutdown: %s", lines[0])
	}
}

// A pause arriving at the unload boundary is counted too: the state must not be
// reported from the sweep-time snapshot.
func TestFetchLateArrivalDuringUnloadIsRecorded(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	var released atomic.Int32
	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-x","ticket":"ST-y"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool {
			released.Add(1)
			return true
		})
	o.trace = tr
	injected := false
	o.unload = func(ctx context.Context) error {
		// The sweep has already run: this pause can only be accounted for by the
		// final re-read at the unload boundary.
		o.listen(ctx, pausedEvent("f-post", "net-verified", trustedAuthURL, "POST", 200))
		injected = true
		return nil
	}

	o.disableFetch(context.Background())
	if !injected {
		t.Fatal("unload was never called")
	}
	if released.Load() != 0 {
		t.Fatalf("a post-sweep pause is left to the teardown, not released here: %d", released.Load())
	}
	release, shutdown, _, _ := traceState(t, tr)
	if shutdown != ShutdownPartial {
		t.Fatalf("a post-sweep pause must not be reported as clean: %q", shutdown)
	}
	if release != "uncertain" {
		t.Fatalf("release state = %q, want uncertain", release)
	}
	tr.finish()
	if !strings.Contains(lines[0], "leftover=1") {
		t.Fatalf("the post-sweep arrival must be counted: %s", lines[0])
	}
}

// A canceled caller budget must not buy the sweep any extra time: the queued
// pauses are reported unconfirmed and handed to the session teardown.
func TestFetchSweepSpendsNoTimeAfterCancel(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	var discarded atomic.Int32
	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})

	o := correlatedObservation(t,
		func(context.Context, fetch.RequestID) ([]byte, error) {
			close(readStarted)
			<-releaseRead
			return []byte(`{"tgt":"TGT-loop-1","ticket":"ST-loop-1"}`), nil
		},
		func(context.Context, *fetch.EventRequestPaused, []byte, error) bool {
			discarded.Add(1)
			return true
		})
	o.trace = tr
	o.unload = func(context.Context) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	o.listen(ctx, pausedEvent("f-in", "net-verified", trustedAuthURL, "POST", 200))
	<-readStarted

	disabled := make(chan struct{})
	go func() {
		o.disableFetch(ctx)
		close(disabled)
	}()
	sawSeal(t, o)
	for i := 0; i < 3; i++ {
		o.listen(ctx, pausedEvent(fmt.Sprintf("f-late%d", i), "net-verified", trustedAuthURL, "POST", 200))
	}

	cancel()
	start := time.Now()
	close(releaseRead)
	select {
	case <-disabled:
	case <-time.After(10 * time.Second):
		t.Fatal("disableFetch never returned after cancel")
	}
	if spent := time.Since(start); spent > time.Second {
		t.Fatalf("a canceled budget still spent %v in the shutdown", spent)
	}

	release, shutdown, _, _ := traceState(t, tr)
	if shutdown != ShutdownAborted {
		t.Fatalf("shutdown state = %q, want %q", shutdown, ShutdownAborted)
	}
	if release != "uncertain" {
		t.Fatalf("release state = %q, want uncertain", release)
	}
	tr.finish()
	if !strings.Contains(lines[0], "leftover=3") {
		t.Fatalf("queued pauses must be counted as unconfirmed: %s", lines[0])
	}
}
