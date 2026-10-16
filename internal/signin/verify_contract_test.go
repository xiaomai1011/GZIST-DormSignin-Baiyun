package signin

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The CAS client emits a fixed set of business codes. Each known code must land
// in its own safe category; a code we do not know must stay unknown so a new
// server answer can never be reported to the user as a wrong password.
func TestTicketBusinessCodeMatrix(t *testing.T) {
	for _, tc := range []struct {
		code  string
		issue AuthIssue
	}{
		{"NOUSER", AuthCredentialsRejected},
		{"CODEFALSE", AuthCaptcha},
		{"USERLOCK", AuthLocked},
		{"USERDISABLED", AuthLocked},
		{"TWOVERIFY", AuthActionRequired},
		{"ISPHONEOREMAILORANSWER", AuthActionRequired},
		{"PEOPLEMOREACCOUNT", AuthActionRequired},
		{"NETWORKCOMMITMENT", AuthActionRequired},
		{"ISMODIFYPASS", AuthActionRequired},
		{"ISBINDWX", AuthActionRequired},
		{"NOAUTHORIZATION", AuthBusinessOther},
		{"NOREGISTER", AuthBusinessOther},
		{"USERNOTONLY", AuthBusinessOther},
	} {
		r := classifyTicketResponse(200, []byte(fmt.Sprintf(`{"data":{"code":%q}}`, tc.code)))
		if r.OK || r.Issue != tc.issue || r.ReasonCode != ReasonNone {
			t.Errorf("%s: unexpected result %+v", tc.code, r)
		}
		if strings.Contains(r.Reason, "密码错误") && tc.issue != AuthCredentialsRejected {
			t.Errorf("%s: non-credential code described as a wrong password: %q", tc.code, r.Reason)
		}
	}
	// Unknown business codes stay unknown and keep a fixed reason.
	for _, code := range []string{"", "SOMETHINGNEW", "NEWCODE2026"} {
		body := `{"data":{"code":"SOMETHINGNEW"}}`
		if code == "" {
			body = `{"data":{"code":""}}`
		}
		r := classifyTicketResponse(200, []byte(body))
		if r.OK || r.Issue != AuthUnknown {
			t.Fatalf("%q: unknown code not unknown: %+v", code, r)
		}
		if code != "" && r.ReasonCode != ReasonUnknownBusinessCode {
			t.Fatalf("%q: missing unknown_business_code: %+v", code, r)
		}
	}
}

// A credential answer never comes from anything but the dedicated codes.
func TestAuthClassifyNeverInventsCredentialRejection(t *testing.T) {
	for _, text := range []string{"请检查账号或密码是否正确", "密码已连续错误【2】次，连续错误【5】次账号将被锁定。",
		"账号锁定至:2099-01-01，请稍后重新登录或联系管理员处理。"} {
		issue := ClassifyAuthMessage(text)
		if strings.HasPrefix(text, "请检查账号") || strings.HasPrefix(text, "密码已连续") {
			if issue != AuthNone {
				t.Fatalf("%q must stay unclassified, got %s", text, issue)
			}
			continue
		}
		if issue != AuthLocked {
			t.Fatalf("%q must classify as locked, got %s", text, issue)
		}
	}
	if ClassifyAuthMessage("账号被停用，请联系相关管理员处理。") != AuthLocked {
		t.Fatal("disabled account text must classify as locked/disabled")
	}
}

// Positive evidence requires a TGT/ST pair with both prefixes at one consistent
// location; every other shape is an explained unknown rather than a silent one.
func TestTicketResponseShapeMatrix(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
		code VerifyReason
	}{
		{"top-level pair", `{"tgt":"TGT-abc","ticket":"ST-abc"}`, true, ReasonNone},
		{"nested pair", `{"data":{"tgt":"TGT-abc","ticket":"ST-abc"}}`, true, ReasonNone},
		{"non-object data with top-level pair", `{"data":"ST-abc","tgt":"TGT-abc","ticket":"ST-abc"}`, true, ReasonNone},
		{"missing ticket", `{"tgt":"TGT-abc"}`, false, ReasonResponseSchemaUnknown},
		{"missing tgt", `{"ticket":"ST-abc"}`, false, ReasonResponseSchemaUnknown},
		{"prefixes wrong", `{"tgt":"abc","ticket":"abc"}`, false, ReasonResponseSchemaUnknown},
		{"too short", `{"tgt":"TGT-","ticket":"ST-"}`, false, ReasonResponseSchemaUnknown},
		{"null data", `{"data":null}`, false, ReasonResponseSchemaUnknown},
		{"empty object", `{}`, false, ReasonResponseSchemaUnknown},
		{"plain string", `"TGT-abc"`, false, ReasonResponseSchemaUnknown},
		{"html", `<html>个人查寝</html>`, false, ReasonResponseSchemaUnknown},
	} {
		r := classifyTicketResponse(200, []byte(tc.body))
		if r.OK != tc.ok || r.ReasonCode != tc.code {
			t.Errorf("%s: unexpected %+v", tc.name, r)
		}
	}
	// A recognised code outranks a positive-looking pair.
	if r := classifyTicketResponse(200, []byte(`{"tgt":"TGT-abc","ticket":"ST-abc","data":{"code":"NOUSER"}}`)); r.OK || r.Issue != AuthCredentialsRejected {
		t.Fatalf("code must outrank tickets: %+v", r)
	}
}

func TestTicketResponseStatusAndSizeReasons(t *testing.T) {
	for _, status := range []int64{199, 204, 301, 403, 500} {
		r := classifyTicketResponse(status, []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`))
		if r.OK || r.ReasonCode != ReasonHTTPStatusUnexpected || r.Issue != AuthUnknown {
			t.Fatalf("status %d: unexpected %+v", status, r)
		}
	}
	for _, status := range []int64{200, 201} {
		if r := classifyTicketResponse(status, []byte(`{"tgt":"TGT-abc","ticket":"ST-abc"}`)); !r.OK {
			t.Fatalf("status %d must be accepted: %+v", status, r)
		}
	}
	if r := classifyTicketResponse(200, nil); r.ReasonCode != ReasonResponseBodyUnavail || r.OK {
		t.Fatalf("empty body: %+v", r)
	}
	if r := classifyTicketResponse(200, []byte(strings.Repeat(" ", maxAuthBody+1))); r.ReasonCode != ReasonResponseBodyTooLarge || r.OK {
		t.Fatalf("oversize body: %+v", r)
	}
}

// No non-credential outcome may be worded as a wrong password. The verification
// result text is what the user reads, so this wording is a safety property.
func TestNonCredentialReasonsNeverClaimPasswordError(t *testing.T) {
	for _, issue := range []AuthIssue{AuthCaptcha, AuthLocked, AuthActionRequired, AuthBusinessOther,
		AuthNetwork, AuthCanceled, AuthUnknown} {
		msg := authReason(issue)
		if msg == "" {
			t.Fatalf("%s has no user text", issue)
		}
		if strings.Contains(msg, "密码错误") {
			t.Fatalf("%s described as a wrong password: %q", issue, msg)
		}
		if issue != AuthUnknown && strings.Contains(msg, "不确定") {
			t.Fatalf("%s must be more explicit than 'inconclusive': %q", issue, msg)
		}
	}
	if msg := authReason(AuthCredentialsRejected); !strings.Contains(msg, "账号或密码错误") {
		t.Fatalf("credential rejection must say so explicitly: %q", msg)
	}
	if authReason(AuthActionRequired) == authReason(AuthBusinessOther) {
		t.Fatal("distinct categories must read differently")
	}
}

func TestClickFailureReasonIsSpecific(t *testing.T) {
	want := map[int]VerifyReason{
		0: ReasonCASPageNotTrusted, 3: ReasonCASFormMissing, 4: ReasonLoginButtonMissing,
		5: ReasonLoginButtonNotVisible, 6: ReasonLoginClickFailed, 7: ReasonLoginButtonNotClicked,
	}
	for code, reason := range want {
		if got := clickFailureReason(code); got != reason {
			t.Errorf("code %d: got %s want %s", code, got, reason)
		}
	}
	if ReasonCASPageNotTrusted == ReasonCASFormMissing {
		t.Fatal("distinct DOM outcomes must not collapse into one reason")
	}
}

// The trace is the only new log surface; it must stay bounded and free of
// anything that could carry credentials, tickets, URLs or page text.
func TestVerifyTraceIsDeidentifiedAndBounded(t *testing.T) {
	var lines []string
	tr := newVerifyTrace(func(s string) { lines = append(lines, s) })
	tr.at(StageTicketArmed)
	tr.requestID("some-cdp-request-id-0123456789")
	if !tr.seen || len(tr.reqHash) != 8 {
		t.Fatalf("request id must be stored as a short hash: %+v", tr)
	}
	if strings.Contains(tr.reqHash, "-") || tr.reqHash == "some-cdp-request-id-0123456789" {
		t.Fatal("request id must not be kept verbatim")
	}
	tr.why(ReasonTicketRequestNotSeen)
	tr.why(ReasonNetworkFailed) // first reason wins
	tr.response(200, maxDiagBytes+5000, "true", "false")
	tr.finish()

	if len(lines) != 1 {
		t.Fatalf("exactly one summary line expected, got %d", len(lines))
	}
	got := lines[0]
	for _, want := range []string{"stage=ticket_request_armed", "reason=ticket_request_not_observed",
		"http=200", "trusted=true", "cached=false", "req=" + tr.reqHash} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q: %s", want, got)
		}
	}
	if !strings.Contains(got, fmt.Sprintf("bytes=%d", maxDiagBytes)) {
		t.Fatalf("body size must be clamped: %s", got)
	}
	for _, forbidden := range []string{"http://", "https://", "@", "TGT-", "ST-", "password", "userName", "\n"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("summary leaked %q: %s", forbidden, got)
		}
	}
}

func TestVerifyTraceDisabledAndNilSafe(t *testing.T) {
	var nilTrace *verifyTrace
	nilTrace.at(StageOpenCAS)
	nilTrace.why(ReasonNetworkFailed)
	nilTrace.requestID("x")
	nilTrace.finish()
	if s := nilTrace.summary(); s != "" {
		t.Fatalf("nil trace must stay silent, got %q", s)
	}
	if newVerifyTrace(nil).summary() == "" {
		t.Fatal("summary must be computable without an emitter")
	}
	tr := newVerifyTrace(nil)
	tr.finish() // must not panic without an emitter
}

func TestVerifyTraceBoundedElapsed(t *testing.T) {
	tr := newVerifyTrace(nil)
	tr.started = time.Now().Add(-10 * time.Hour)
	if got := tr.summary(); !strings.Contains(got, "elapsed=600.0s") {
		t.Fatalf("elapsed must be bounded: %s", got)
	}
}
