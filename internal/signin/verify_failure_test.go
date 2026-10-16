package signin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureTrace returns a trace plus a pointer to the single summary line it
// emits on finish.
func captureTrace() (*verifyTrace, *string) {
	line := ""
	tr := newVerifyTrace(func(s string) { line = s })
	return tr, &line
}

func assertNoLeaks(t *testing.T, line string) {
	t.Helper()
	for _, bad := range []string{"http://", "https://", "@", "TGT-", "ST-", "password", "userName", "\n",
		"secret-ticket", "ST-leak", "TGT-leak"} {
		if strings.Contains(line, bad) {
			t.Fatalf("summary leaked %q: %s", bad, line)
		}
	}
}

// 1. A network-listen failure keeps the trace at the exact stage, with the
// dedicated reason, and never advances afterwards.
func TestListenFailureStopsAtNetworkListenStage(t *testing.T) {
	tr, line := captureTrace()
	if err := listenForAuth(context.Background(), tr); err == nil {
		t.Fatal("an executor-less context must fail the listen step")
	}
	// Later bookkeeping must not overwrite the latched stage.
	tr.at(StageClassified)
	tr.cleanupDone(true)
	tr.finish()
	for _, want := range []string{"stage=network_listen", "failed_stage=network_listen",
		"reason=network_listen_failed", "cleanup=ok"} {
		if !strings.Contains(*line, want) {
			t.Fatalf("summary missing %q: %s", want, *line)
		}
	}
	if strings.Contains(*line, "stage=result_classified") || strings.Contains(*line, "stage=browser_cleanup") {
		t.Fatalf("failure stage was overwritten: %s", *line)
	}
	assertNoLeaks(t, *line)
}

// 2. A navigation failure is distinct from a listen failure and keeps its
// sanitized error classification.
func TestNavigateFailureIsDistinctAndClassified(t *testing.T) {
	tr, line := captureTrace()
	if err := navigateToCAS(context.Background(), tr); err == nil {
		t.Fatal("an executor-less context must fail the navigation step")
	}
	tr.finish()
	for _, want := range []string{"stage=navigate_cas", "failed_stage=navigate_cas", "reason=navigation_failed"} {
		if !strings.Contains(*line, want) {
			t.Fatalf("summary missing %q: %s", want, *line)
		}
	}
	if strings.Contains(*line, "network_listen") {
		t.Fatalf("navigation failure must not be reported as a listen failure: %s", *line)
	}
	// The executor-less path yields a fixed CDP-shaped class, never "none".
	if strings.Contains(*line, "error_class=none") {
		t.Fatalf("a concrete navigation error must be classified: %s", *line)
	}
	assertNoLeaks(t, *line)
}

// 3. An error whose text embeds secrets (URL, ticket, password) contributes
// only its whitelisted class token to the log.
func TestErrorClassificationNeverLeaksSecrets(t *testing.T) {
	tr, line := captureTrace()
	tr.at(StageNavigateCAS)
	hostile := errors.New(`Get "https://ids.gzist.edu.cn/lyuapServer/login?service=x&password=abc123&ticket=ST-leak&TGT-leak": dial tcp: connection refused`)
	tr.failHere(ReasonNavigateFailed, classifyOpError(hostile))
	tr.finish()
	assertNoLeaks(t, *line)
	if !strings.Contains(*line, "error_class=connection_refused") {
		t.Fatalf("refused error must map to connection_refused: %s", *line)
	}
}

// The whitelist itself: typed and textual shapes, and unknown stays unknown.
func TestClassifyOpErrorWhitelist(t *testing.T) {
	cases := []struct {
		err  error
		want VerifyErrClass
	}{
		{nil, ErrClassNone},
		{context.Canceled, ErrClassCanceled},
		{context.DeadlineExceeded, ErrClassConnTimeout},
		{fmt.Errorf("wrap: %w", context.DeadlineExceeded), ErrClassConnTimeout},
		{errors.New("dial tcp 1.2.3.4:443: connectex: No connection could be made because the target machine actively refused it."), ErrClassConnRefused},
		{errors.New("read tcp: connection reset by peer"), ErrClassConnReset},
		{errors.New("lookup ids.gzist.edu.cn: no such host"), ErrClassDNS},
		{errors.New("remote error: tls: handshake failure"), ErrClassTLS},
		{errors.New("x509: certificate signed by unknown authority"), ErrClassTLS},
		{errors.New("websocket: close sent"), ErrClassCDP},
		{errors.New("invalid context"), ErrClassCDP},
		{errors.New("target closed"), ErrClassTargetClosed},
		{errors.New("use of closed network connection"), ErrClassTargetClosed},
		{errors.New("something entirely novel"), ErrClassUnknown},
	}
	for _, tc := range cases {
		if got := classifyOpError(tc.err); got != tc.want {
			t.Errorf("classifyOpError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	// A timeout net.Error is typed, not textual.
	if got := classifyOpError(errNetTimeout{}); got != ErrClassConnTimeout {
		t.Errorf("net timeout must map to connection_timeout, got %q", got)
	}
}

type errNetTimeout struct{}

func (errNetTimeout) Error() string   { return "i/o timeout" }
func (errNetTimeout) Timeout() bool   { return true }
func (errNetTimeout) Temporary() bool { return true }

// Chromium network error codes surface verbatim in navigation failures and
// must map precisely — they are the whole point of the error classification.
func TestClassifyChromiumErrorCodes(t *testing.T) {
	cases := []struct {
		msg  string
		want VerifyErrClass
	}{
		{"Failed navigating: net::ERR_NAME_NOT_RESOLVED", ErrClassDNS},
		{"Failed navigating: net::ERR_CONNECTION_REFUSED", ErrClassConnRefused},
		{"Failed navigating: net::ERR_CONNECTION_RESET", ErrClassConnReset},
		{"Failed navigating: net::ERR_TIMED_OUT", ErrClassConnTimeout},
		{"Failed navigating: net::ERR_CONNECTION_TIMED_OUT", ErrClassConnTimeout},
		{"Failed navigating: net::ERR_CERT_AUTHORITY_INVALID", ErrClassTLS},
		{"Failed navigating: net::ERR_SSL_PROTOCOL_ERROR", ErrClassTLS},
		{"net::ERR_ABORTED", ErrClassCanceled},
		{"net::ERR_SOMETHING_ELSE", ErrClassUnknown},
		{"no chromium code here", ErrClassUnknown},
	}
	for _, tc := range cases {
		if got := classifyErrorText(tc.msg); got != tc.want {
			t.Errorf("classifyErrorText(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

// Whole-token matching: a known code with an extra suffix must NOT inherit its
// classification, an unlisted code must stay unknown even when the surrounding
// text contains whitelist keywords, and token extraction stops at punctuation.
func TestChromiumTokenBoundaries(t *testing.T) {
	cases := []struct {
		msg  string
		want VerifyErrClass
	}{
		{"net::ERR_CONNECTION_RESET_OTHER", ErrClassUnknown},              // suffix must not inherit reset
		{"net::ERR_CERT_SOMETHING_NEW", ErrClassUnknown},                  // unlisted cert code stays unknown
		{"net::ERR_FOO_BAR dns timeout refused reset", ErrClassUnknown},   // surroundings must not re-classify
		{"net::err_connection_resetx", ErrClassUnknown},                   // glued suffix changes the token
		{"net::ERR_NAME_NOT_RESOLVED;", ErrClassDNS},                      // token ends at punctuation
		{"net::err_timed_out", ErrClassConnTimeout},                       // lowercase verbatim
		{"before net::ERR_CONNECTION_REFUSED after", ErrClassConnRefused}, // extraction inside prose
	}
	for _, tc := range cases {
		if got := classifyErrorText(tc.msg); got != tc.want {
			t.Errorf("classifyErrorText(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
	// And the direct contract: presence of a code is reported even when unlisted.
	if _, hit := classifyChromiumCode("net::ERR_WHATEVER"); !hit {
		t.Fatal("an unlisted Chromium code must still be reported as present")
	}
	if _, hit := classifyChromiumCode("plain error text"); hit {
		t.Fatal("no Chromium code must mean no hit")
	}
}

// Cancellation and timeouts must be classified before any operation failure is
// latched: the full "operation returns error → outer handles ctx" chain must
// end in canceled/timeout, never in a network reason.
func TestContextTerminationWinsOverOperationError(t *testing.T) {
	// Canceled: navigateToCAS must not latch, returnContextIssue must.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr, line := captureTrace()
	if err := navigateToCAS(ctx, tr); err == nil {
		t.Fatal("canceled context must fail the navigation step")
	}
	if tr.failed {
		t.Fatalf("cancellation latched as an operation failure: %s", *line)
	}
	res := returnContextIssue(tr, ctx)
	if res.Issue != AuthCanceled || res.ReasonCode != ReasonCanceled {
		t.Fatalf("cancellation result: %+v", res)
	}
	tr.finish()
	if !strings.Contains(*line, "reason=canceled") || !strings.Contains(*line, "error_class=canceled") {
		t.Fatalf("cancellation must win in the log too: %s", *line)
	}
	if strings.Contains(*line, "navigation_failed") {
		t.Fatalf("log says navigation failure while UI says canceled: %s", *line)
	}

	// Budget timeout: same chain, distinct classification with a class token.
	tctx, tcancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer tcancel()
	<-tctx.Done()
	tr2, line2 := captureTrace()
	if err := navigateToCAS(tctx, tr2); err == nil {
		t.Fatal("expired context must fail the navigation step")
	}
	if tr2.failed {
		t.Fatalf("timeout latched as an operation failure: %s", *line2)
	}
	res = returnContextIssue(tr2, tctx)
	if res.ReasonCode != ReasonVerificationTimeout {
		t.Fatalf("timeout result: %+v", res)
	}
	tr2.finish()
	if !strings.Contains(*line2, "reason=verification_timeout") || !strings.Contains(*line2, "error_class=connection_timeout") {
		t.Fatalf("timeout must carry its own reason and class: %s", *line2)
	}
}

// The trace is shared by observation callbacks, the async body reader and the
// main flow: hammer every method concurrently and finish once. Run with -race
// to prove the mutex actually guards the latch.
func TestVerifyTraceConcurrentAccess(t *testing.T) {
	tr, line := captureTrace()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			tr.at(StageNavigateCAS)
			tr.at(StageAwaitResponse)
			tr.why(ReasonNavigateFailed)
			tr.requestID(fmt.Sprintf("req-%d", n))
			tr.response(200, 128, "true", "false")
			tr.failHere(ReasonNavigateFailed, ErrClassConnReset)
			tr.cleanupDone(true)
			_ = tr.summary()
		}(i)
	}
	wg.Wait()
	tr.finish()
	if *line == "" {
		t.Fatal("summary must be emitted")
	}
	if !strings.Contains(*line, "failed_stage=") || strings.Contains(*line, "failed_stage=none") {
		t.Fatalf("concurrent failures must latch exactly one stage: %s", *line)
	}
	assertNoLeaks(t, *line)
}

// First-failure-wins under concurrency: exactly one latch survives, and no
// later progress marker or cleanup can move the stage afterwards.
func TestConcurrentFailLatchIsSingle(t *testing.T) {
	tr, line := captureTrace()
	tr.at(StageNavigateCAS) // the stage the concurrent failures happen in
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			tr.failHere(ReasonNavigateFailed, ErrClassNone)
		}(i)
	}
	close(start)
	wg.Wait()
	tr.at(StageClassified) // must be ignored
	tr.at(StageCleanup)    // must be ignored
	tr.finish()
	if !strings.Contains(*line, "failed_stage=navigate_cas") {
		t.Fatalf("latch stage wrong: %s", *line)
	}
	if strings.Contains(*line, "stage=result_classified") || strings.Contains(*line, "stage=browser_cleanup") {
		t.Fatalf("stage advanced after latch: %s", *line)
	}
}

// 4+5. Cleanup bookkeeping: success changes nothing; failure latches without
// erasing the original failure; a storyless run reports cleanup as its cause.
func TestCleanupPreservesOriginalFailure(t *testing.T) {
	okClose := func() error { return nil }
	okRemove := func(string) error { return nil }
	failClose := func() error { return errors.New("close failed with profile path D:\\x\\y") }

	original := verificationReply(AuthNetwork, ReasonListenFailed)

	// Cleanup succeeds: the original failure stands untouched.
	res := original
	finishVerificationCleanup(&res, "dir", okClose, okRemove)
	if res.Issue != AuthNetwork || res.ReasonCode != ReasonListenFailed || res.CleanupFailed {
		t.Fatalf("successful cleanup must not alter the result: %+v", res)
	}

	// Cleanup fails: the latch is additive and the original stays.
	res = original
	finishVerificationCleanup(&res, "dir", failClose, okRemove)
	if !res.CleanupFailed {
		t.Fatal("cleanup failure must latch CleanupFailed")
	}
	if res.Issue != AuthNetwork || res.ReasonCode != ReasonListenFailed {
		t.Fatalf("cleanup failure must not erase the original failure: %+v", res)
	}

	// A canceled result keeps its identity too.
	res = verificationReply(AuthCanceled, ReasonCanceled)
	finishVerificationCleanup(&res, "dir", failClose, okRemove)
	if !res.CleanupFailed || res.Issue != AuthCanceled {
		t.Fatalf("canceled result must survive a cleanup failure: %+v", res)
	}

	// Nothing else went wrong: the cleanup failure is the whole story.
	res = VerificationResult{}
	finishVerificationCleanup(&res, "dir", failClose, okRemove)
	if !res.CleanupFailed || res.ReasonCode != ReasonCleanupUnconfirmed {
		t.Fatalf("storyless run must report cleanup unconfirmed: %+v", res)
	}
}

// 6. Caller cancellation and budget timeouts classify separately, and a
// canceled context never records a network failure.
func TestCanceledAndTimeoutAreDistinct(t *testing.T) {
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := verificationContextIssue(cctx)
	if res.Issue != AuthCanceled || res.ReasonCode != ReasonCanceled {
		t.Fatalf("cancellation: %+v", res)
	}
	tctx, tcancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer tcancel()
	<-tctx.Done()
	res = verificationContextIssue(tctx)
	if res.Issue != AuthUnknown || res.ReasonCode != ReasonVerificationTimeout {
		t.Fatalf("timeout: %+v", res)
	}
	if contextErrClass(cctx) != ErrClassCanceled {
		t.Fatal("cancellation must map to the canceled class, not a network one")
	}

	// navigateToCAS on a canceled context records no failure latch at all:
	// returnContextIssue is responsible for the classification.
	tr, line := captureTrace()
	ctx, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := navigateToCAS(ctx, tr); err == nil {
		t.Fatal("canceled context must fail the navigation step")
	}
	if tr.failed {
		t.Fatalf("cancellation must not be latched as an operation failure: %s", *line)
	}
}

// 7. Unknown stays unknown end to end: an unclassifiable error produces the
// unknown class and never a credential verdict.
func TestUnknownErrorStaysUnknown(t *testing.T) {
	if got := classifyOpError(errors.New(" utterly novel ")); got != ErrClassUnknown {
		t.Fatalf("unclassifiable error must stay unknown, got %q", got)
	}
	res := classifyTicketResponse(200, []byte(`{"data":{"code":"SOMETHINGNEW"}}`))
	if res.OK || res.Issue != AuthUnknown {
		t.Fatalf("unknown business code must stay unknown: %+v", res)
	}
	if res.Issue == AuthCredentialsRejected {
		t.Fatal("an unknown code must never be reported as a wrong password")
	}
}

// 8. The observation emits exactly one final result even if more finish events
// arrive.
func TestObservationResultIsOneShot(t *testing.T) {
	o := &authObservation{out: make(chan VerificationResult, 4)}
	o.finalizeLocked(verificationReply(AuthUnknown, ReasonResponseNotReceived))
	o.finalizeLocked(verificationReply(AuthUnknown, ReasonResponseBodyUnavail))
	o.finalizeLocked(VerificationResult{OK: true})
	select {
	case r := <-o.out:
		if r.OK || r.ReasonCode != ReasonResponseNotReceived {
			t.Fatalf("first result must win: %+v", r)
		}
	default:
		t.Fatal("no result emitted")
	}
	if extra := len(o.out); extra != 0 {
		t.Fatalf("later results must be dropped, got %d", extra)
	}
}

// 9. Structural guard: the click submission exists exactly once in the verify
// flow, so no failure branch can submit the password a second time.
func TestSingleSubmissionCallSite(t *testing.T) {
	src, err := os.ReadFile("verify.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), "verifyClickLoginJS"); n != 1 {
		t.Fatalf("verifyClickLoginJS must be evaluated exactly once in verify.go, found %d", n)
	}
	// The observation gate stays first-wins regardless of event ordering.
	if !ticketEndpoint("https://ids.gzist.edu.cn/lyuapServer/v1/tickets") {
		t.Fatal("trusted endpoint check regressed")
	}
	if _, err := url.Parse("https://ids.gzist.edu.cn/lyuapServer/v1/tickets"); err != nil {
		t.Fatal(err)
	}
}

// The latched failure stage also survives trace.done on a failing result —
// the exact overwrite that produced the old "stage=browser_cleanup" symptom.
func TestDoneDoesNotAdvanceFailedStage(t *testing.T) {
	tr, line := captureTrace()
	tr.at(StageNavigateCAS)
	tr.failHere(ReasonNavigateFailed, ErrClassConnTimeout)
	res := verificationReply(AuthNetwork, ReasonNavigateFailed)
	out := tr.done(res)
	if out.Issue != AuthNetwork {
		t.Fatalf("result must pass through: %+v", out)
	}
	tr.at(StageCleanup) // legacy callers may still try
	tr.finish()
	for _, want := range []string{"stage=navigate_cas", "failed_stage=navigate_cas", "reason=navigation_failed"} {
		if !strings.Contains(*line, want) {
			t.Fatalf("summary missing %q: %s", want, *line)
		}
	}
	if strings.Contains(*line, "stage=browser_cleanup") {
		t.Fatalf("cleanup must not take over the stage field: %s", *line)
	}
}
