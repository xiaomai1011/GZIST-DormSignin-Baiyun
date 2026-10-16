package signin

import (
	"context"
	"errors"
	"fmt"
	"github.com/chromedp/cdproto/network"
	"strings"
	"testing"
	"time"
)

func obsRequest(id network.RequestID, docURL, url, method string) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{RequestID: id, DocumentURL: docURL,
		Request: &network.Request{URL: url, Method: method}}
}

func obsResponse(id network.RequestID, url string, status int64, cache, sw bool) *network.EventResponseReceived {
	return &network.EventResponseReceived{RequestID: id,
		Response: &network.Response{URL: url, Status: status, FromDiskCache: cache, FromServiceWorker: sw}}
}

func obsFinished(id network.RequestID, encoded float64) *network.EventLoadingFinished {
	return &network.EventLoadingFinished{RequestID: id, EncodedDataLength: encoded}
}

const trustedTickets = "https://ids.gzist.edu.cn/lyuapServer/v1/tickets"

func newTestObservation(fetch func(context.Context, network.RequestID) ([]byte, error)) *authObservation {
	return &authObservation{out: make(chan VerificationResult, 1), fetchBody: fetch}
}

// captureAndRespond feeds a fresh submission plus its response and the finish
// event, then returns the single final result.
func captureAndRespond(t *testing.T, o *authObservation, id network.RequestID, url string, status int64, cache, sw bool) VerificationResult {
	t.Helper()
	ctx := context.Background()
	o.arm()
	o.listen(ctx, obsRequest(id, verifyCAS, trustedTickets, "POST"))
	if o.request != id {
		t.Fatalf("submission not captured: %q", o.request)
	}
	o.listen(ctx, obsResponse(id, url, status, cache, sw))
	o.listen(ctx, obsFinished(id, 256))
	select {
	case r := <-o.out:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("no final result produced")
	}
	return VerificationResult{}
}

func TestObservationClassifiesPositiveTickets(t *testing.T) {
	o := newTestObservation(func(context.Context, network.RequestID) ([]byte, error) {
		return []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`), nil
	})
	if r := captureAndRespond(t, o, "req-1", trustedTickets, 200, false, false); !r.OK {
		t.Fatalf("positive tickets not accepted: %+v", r)
	}
}

// A stale (pre-arm) or foreign identifier must never complete the current run.
func TestObservationRejectsStaleAndForeignResponses(t *testing.T) {
	o := newTestObservation(func(context.Context, network.RequestID) ([]byte, error) {
		return []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`), nil
	})
	ctx := context.Background()
	o.arm()
	o.listen(ctx, obsRequest("want", verifyCAS, trustedTickets, "POST"))
	o.listen(ctx, obsResponse("other", trustedTickets, 200, false, false))
	o.listen(ctx, obsFinished("other", 256))
	select {
	case r := <-o.out:
		t.Fatalf("foreign request completed the run: %+v", r)
	default:
	}
	o.listen(ctx, obsResponse("want", trustedTickets, 200, false, false))
	o.listen(ctx, obsFinished("want", 256))
	select {
	case r := <-o.out:
		if !r.OK {
			t.Fatalf("own request not accepted: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("own request never completed")
	}
}

// Only one final result may be produced, however many finish events arrive.
func TestObservationProducesSingleResult(t *testing.T) {
	var reads int
	o := newTestObservation(func(context.Context, network.RequestID) ([]byte, error) {
		reads++
		return []byte(`{"data":{"code":"NOUSER"}}`), nil
	})
	r := captureAndRespond(t, o, "req-2", trustedTickets, 200, false, false)
	if r.Issue != AuthCredentialsRejected {
		t.Fatalf("unexpected %+v", r)
	}
	// Late duplicates must not produce a second result or another body read.
	o.listen(context.Background(), obsFinished("req-2", 256))
	if reads != 1 {
		t.Fatalf("body read %d times, want 1", reads)
	}
	select {
	case extra := <-o.out:
		t.Fatalf("second result produced: %+v", extra)
	default:
	}
}

func TestObservationRejectsUntrustedResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		cach bool
		sw   bool
	}{
		{"wrong host", "https://evil.example/lyuapServer/v1/tickets", false, false},
		{"query string", trustedTickets + "?x=1", false, false},
		{"disk cache", trustedTickets, true, false},
		{"service worker", trustedTickets, false, true},
	} {
		bodyRead := false
		o := newTestObservation(func(context.Context, network.RequestID) ([]byte, error) {
			bodyRead = true
			return nil, errors.New("unreachable")
		})
		r := captureAndRespond(t, o, "req-3", tc.url, 200, tc.cach, tc.sw)
		if r.OK || r.ReasonCode != ReasonResponseNotReceived {
			t.Errorf("%s: unexpected %+v", tc.name, r)
		}
		if bodyRead {
			t.Errorf("%s: body must not be read for an untrusted response", tc.name)
		}
	}
}

func TestObservationBodyReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fetch func(context.Context, network.RequestID) ([]byte, error)
		want  VerifyReason
	}{
		{"read error", func(context.Context, network.RequestID) ([]byte, error) {
			return nil, errors.New("cdp failure with private detail")
		}, ReasonBodyReadFailed},
		{"resource gone after navigation", func(context.Context, network.RequestID) ([]byte, error) {
			return nil, errors.New("No data found for resource with given identifier")
		}, ReasonBodyResourceGone},
		{"read budget timeout", func(context.Context, network.RequestID) ([]byte, error) {
			return nil, fmt.Errorf("read stalled: %w", context.DeadlineExceeded)
		}, ReasonBodyReadTimeout},
		{"empty body", func(context.Context, network.RequestID) ([]byte, error) {
			return nil, nil
		}, ReasonBodyEmpty},
		{"oversize body", func(context.Context, network.RequestID) ([]byte, error) {
			return make([]byte, maxAuthBody+1), nil
		}, ReasonResponseBodyTooLarge},
	} {
		o := newTestObservation(tc.fetch)
		r := captureAndRespond(t, o, "req-4", trustedTickets, 200, false, false)
		if r.OK || r.ReasonCode != tc.want {
			t.Errorf("%s: unexpected %+v", tc.name, r)
		}
		// Error detail must never reach the user-facing text.
		if r.Reason != authReason(AuthUnknown) || r.Reason != verificationReply(AuthUnknown, tc.want).Reason {
			t.Errorf("%s: unsafe reason text %q", tc.name, r.Reason)
		}
	}
}

// A declared oversize response is refused before any body read.
func TestObservationRefusesOversizeBeforeReading(t *testing.T) {
	bodyRead := false
	o := newTestObservation(func(context.Context, network.RequestID) ([]byte, error) {
		bodyRead = true
		return nil, errors.New("unreachable")
	})
	ctx := context.Background()
	o.arm()
	o.listen(ctx, obsRequest("req-5", verifyCAS, trustedTickets, "POST"))
	o.listen(ctx, obsResponse("req-5", trustedTickets, 200, false, false))
	o.listen(ctx, obsFinished("req-5", float64(maxAuthBody+1)))
	select {
	case r := <-o.out:
		if r.Issue != AuthUnknown || r.ReasonCode != ReasonResponseBodyTooLarge {
			t.Fatalf("unexpected %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
	if bodyRead {
		t.Fatal("body must not be read once the size is already known to be too large")
	}
}

// The body read gets its own bound, so a stalled CDP call cannot outlive the run.
func TestObservationBodyReadIsBounded(t *testing.T) {
	deadline := time.Time{}
	o := newTestObservation(func(ctx context.Context, _ network.RequestID) ([]byte, error) {
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("body read must run under a deadline")
		}
		deadline = d
		return []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`), nil
	})
	if r := captureAndRespond(t, o, "req-6", trustedTickets, 200, false, false); !r.OK {
		t.Fatalf("unexpected %+v", r)
	}
	if deadline.IsZero() || time.Until(deadline) > responseBodyBudget+time.Second {
		t.Fatalf("deadline not bounded by responseBodyBudget: %v", deadline)
	}
}

func TestObservationIgnoresUnrelatedRequests(t *testing.T) {
	for _, tc := range []struct {
		name, doc, url, method string
	}{
		{"cas document mismatch", "https://portal.gzist.edu.cn/", trustedTickets, "POST"},
		{"other endpoint", verifyCAS, "https://ids.gzist.edu.cn/lyuapServer/kaptcha", "POST"},
		{"wrong method", verifyCAS, trustedTickets, "GET"},
	} {
		o := newTestObservation(nil)
		o.arm()
		o.listen(context.Background(), obsRequest("x", tc.doc, tc.url, tc.method))
		if o.request != "" {
			t.Errorf("%s: unrelated request captured", tc.name)
		}
	}
}

func TestObservationNetworkFailureIsDistinct(t *testing.T) {
	o := newTestObservation(nil)
	ctx := context.Background()
	o.arm()
	o.listen(ctx, obsRequest("req-7", verifyCAS, trustedTickets, "POST"))
	o.listen(ctx, &network.EventLoadingFailed{RequestID: "req-7"})
	select {
	case r := <-o.out:
		if r.Issue != AuthNetwork || r.OK || r.ReasonCode != ReasonNetworkFailed {
			t.Fatalf("unexpected %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no result")
	}
	// A network failure must never be reported as a wrong password.
	if r := verificationReply(AuthNetwork, ReasonNetworkFailed); r.Issue == AuthCredentialsRejected {
		t.Fatal("network failure classified as credential rejection")
	}
}

func TestObservationTraceRecordsOnlyFixedFacts(t *testing.T) {
	var line string
	tr := newVerifyTrace(func(s string) { line = s })
	o := &authObservation{out: make(chan VerificationResult, 1), trace: tr,
		fetchBody: func(context.Context, network.RequestID) ([]byte, error) {
			return []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`), nil
		}}
	if r := captureAndRespond(t, o, "req-8", trustedTickets, 200, false, false); !r.OK {
		t.Fatalf("unexpected %+v", r)
	}
	tr.finish()
	for _, want := range []string{"stage=ticket_response_received", "http=200", "trusted=true", "req=" + tr.reqHash} {
		if !strings.Contains(line, want) {
			t.Fatalf("trace missing %q: %s", want, line)
		}
	}
	for _, bad := range []string{"TGT-abc", "ST-abc", trustedTickets, "req-8"} {
		if strings.Contains(line, bad) {
			t.Fatalf("trace leaked %q: %s", bad, line)
		}
	}
}
