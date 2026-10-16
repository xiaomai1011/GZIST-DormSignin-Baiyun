package signin

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The public CAS client compares data.code against exactly these literals. The
// mapping must contain all of them (or a client-visible error would fall into
// the unknown family) and nothing that the client does not emit.
func TestBusinessCodeSetMatchesPublicClient(t *testing.T) {
	want := map[string]AuthIssue{
		"NOUSER":                 AuthCredentialsRejected,
		"CODEFALSE":              AuthCaptcha,
		"USERLOCK":               AuthLocked,
		"USERDISABLED":           AuthLocked,
		"TWOVERIFY":              AuthActionRequired,
		"ISPHONEOREMAILORANSWER": AuthActionRequired,
		"PEOPLEMOREACCOUNT":      AuthActionRequired,
		"NETWORKCOMMITMENT":      AuthActionRequired,
		"ISMODIFYPASS":           AuthActionRequired,
		"ISBINDWX":               AuthActionRequired,
		"NOAUTHORIZATION":        AuthBusinessOther,
		"NOREGISTER":             AuthBusinessOther,
		"USERNOTONLY":            AuthBusinessOther,
	}
	if len(want) != 13 {
		t.Fatalf("the client emits 13 distinct codes, test lists %d", len(want))
	}
	for code, issue := range want {
		got, known := businessIssue(code)
		if !known || got != issue {
			t.Errorf("%s: got (%s,%v), want (%s,true)", code, got, known, issue)
		}
	}
}

// Anything the client does not emit must stay unknown, and matching must be an
// exact comparison: no case folding, no trimming, no substring probing. A code
// that merely looks like a known one must never inherit its meaning.
func TestBusinessCodeMatchingIsExact(t *testing.T) {
	for _, code := range []string{
		"nouser", "NoUser", " NOUSER", "NOUSER ", "NOUSER\n",
		"NOUSER2", "NOUSERX", "XNOUSER", "NO_USER", "USERLOCKED", "CODEFALSE1",
		"USERLOCK_OTHER", "诺USER", "NO", "USER", "",
		"PASSWORD", "PWDERROR", "LOGINFAIL", "ERR_PASSWORD",
	} {
		if issue, known := businessIssue(code); known {
			t.Errorf("%q must stay unknown, got %s", code, issue)
		}
	}
}

// The reason that was actually observed: an unlisted code stays unknown, is
// reported with the dedicated reason, and is never described as a wrong
// password — even though the response was HTTP 200 and came from a trusted
// endpoint.
func TestUnlistedBusinessCodeIsNotCredentialRejection(t *testing.T) {
	// Fictional code with the same shape as the real one: a short string.
	body := []byte(`{"data":{"code":"ZZUNKNOWNCODE"}}`)
	res, shape := classifyTicketResponseDetailed(200, body)
	if res.OK {
		t.Fatal("an unlisted code must never be a success")
	}
	if res.Issue != AuthUnknown {
		t.Fatalf("issue = %s, want unknown", res.Issue)
	}
	if res.ReasonCode != ReasonUnknownBusinessCode {
		t.Fatalf("reason = %s, want unknown_business_code", res.ReasonCode)
	}
	if shape.codeState() != "unlisted" || shape.codeType != "str" || shape.codeKnown {
		t.Fatalf("shape not recorded as unlisted string: %+v", shape)
	}
	final := finalResultForUser(res)
	if strings.Contains(final.Reason, "密码错误") || strings.Contains(final.Reason, "账号或密码错误") {
		t.Fatalf("unlisted code reported as a password verdict: %q", final.Reason)
	}
	if !strings.Contains(final.Reason, "暂未识别") {
		t.Fatalf("expected the dedicated text, got %q", final.Reason)
	}
}

// The hash in the diagnostics is a truncation of sha256 over the code VALUE.
// Pinning the convention is what makes the offline forensic check meaningful:
// if it drifted, "the code is not among the client's literals" would be a false
// negative.
func TestShapeHashIsTruncatedSha256OfCodeValue(t *testing.T) {
	for _, code := range []string{"NOUSER", "ZZUNKNOWNCODE", "12345", "a b", "0", "   "} {
		sum := sha256.Sum256([]byte(code))
		want := hex.EncodeToString(sum[:])[:8]
		shape := inspectResponseShape([]byte(`{"data":{"code":"` + code + `"}}`))
		if shape.codeHash != want {
			t.Fatalf("code %q: hash = %s, want %s", code, shape.codeHash, want)
		}
	}
}

// Where the code lives, and what the client's truthiness test does with it.
// "present" is a diagnostic fact, "truthy" is the behavioural one: {"code":0}
// exists but the client ignores it, so it must NOT be treated as a code.
func TestBusinessCodeLevelAndTypeDoNotMisfire(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        string
		codePresent bool
		codeTruthy  bool
		codeType    string
		wantReason  VerifyReason
	}{
		{"code at top level only", `{"code":"NOUSER"}`, false, false, "", ReasonResponseSchemaUnknown},
		{"code nested twice", `{"data":{"data":{"code":"NOUSER"}}}`, false, false, "", ReasonResponseSchemaUnknown},
		{"data is a string", `{"data":"NOUSER"}`, false, false, "", ReasonResponseSchemaUnknown},
		{"code in a sibling field", `{"data":{"msg":"NOUSER"}}`, false, false, "", ReasonResponseSchemaUnknown},
		{"null code", `{"data":{"code":null}}`, true, false, "null", ReasonResponseSchemaUnknown},
		{"empty string code", `{"data":{"code":""}}`, true, false, "str", ReasonResponseSchemaUnknown},
		{"zero code", `{"data":{"code":0}}`, true, false, "num", ReasonResponseSchemaUnknown},
		{"negative zero code", `{"data":{"code":-0}}`, true, false, "num", ReasonResponseSchemaUnknown},
		{"exponent zero code", `{"data":{"code":0e0}}`, true, false, "num", ReasonResponseSchemaUnknown},
		{"false code", `{"data":{"code":false}}`, true, false, "bool", ReasonResponseSchemaUnknown},
		{"string zero code", `{"data":{"code":"0"}}`, true, true, "str", ReasonUnknownBusinessCode},
		{"numeric code", `{"data":{"code":12345}}`, true, true, "num", ReasonUnknownBusinessCode},
		{"boolean code", `{"data":{"code":true}}`, true, true, "bool", ReasonUnknownBusinessCode},
		{"object code", `{"data":{"code":{"inner":"NOUSER"}}}`, true, true, "other", ReasonUnknownBusinessCode},
		{"empty array code", `{"data":{"code":[]}}`, true, true, "other", ReasonUnknownBusinessCode},
		{"blank string code", `{"data":{"code":"   "}}`, true, true, "str", ReasonUnknownBusinessCode},
		{"unknown string code", `{"data":{"code":"NOUSER2"}}`, true, true, "str", ReasonUnknownBusinessCode},
	} {
		res, shape := classifyTicketResponseDetailed(200, []byte(tc.body))
		if res.Issue == AuthCredentialsRejected {
			t.Fatalf("%s: misread as credential rejection", tc.name)
		}
		if shape.codePresent != tc.codePresent || shape.codeTruthy != tc.codeTruthy {
			t.Errorf("%s: present=%v truthy=%v, want %v/%v",
				tc.name, shape.codePresent, shape.codeTruthy, tc.codePresent, tc.codeTruthy)
		}
		if tc.codeType != "" && shape.codeType != tc.codeType {
			t.Errorf("%s: codeType = %q, want %q", tc.name, shape.codeType, tc.codeType)
		}
		if res.ReasonCode != tc.wantReason {
			t.Errorf("%s: reason = %s, want %s", tc.name, res.ReasonCode, tc.wantReason)
		}
	}
	// A falsy code is reported as such instead of being folded into "unlisted".
	falsy := inspectResponseShape([]byte(`{"data":{"code":0}}`))
	if falsy.codeState() != "falsy" || falsy.codeHash == "" {
		t.Fatalf("falsy code not recorded honestly: %+v", falsy)
	}
	// The value itself is matched byte-for-byte: no trimming, so a padded code
	// keeps its own identity and hash rather than becoming the bare code.
	padded := inspectResponseShape([]byte(`{"data":{"code":" NOUSER "}}`))
	bare := inspectResponseShape([]byte(`{"data":{"code":"NOUSER"}}`))
	if padded.codeKnown || padded.codeHash == bare.codeHash {
		t.Fatalf("a padded code must not borrow the bare code's identity: %+v", padded)
	}
}

// The falsy/non-falsy boundary decides whether ticket evidence is still read:
// {"code":0} next to a valid TGT/ST pair must still authenticate, while a
// truthy unlisted code keeps the code-first precedence.
func TestFalsyCodeDoesNotHideTicketEvidence(t *testing.T) {
	const tickets = `"tgt":"TGT-fake","ticket":"ST-fake"`
	for _, tc := range []struct {
		name    string
		body    string
		wantOK  bool
		wantIss AuthIssue
		wantRsn VerifyReason
	}{
		{"zero code", `{` + tickets + `,"data":{"code":0}}`, true, AuthNone, ReasonNone},
		{"negative zero code", `{` + tickets + `,"data":{"code":-0}}`, true, AuthNone, ReasonNone},
		{"false code", `{` + tickets + `,"data":{"code":false}}`, true, AuthNone, ReasonNone},
		{"empty string code", `{` + tickets + `,"data":{"code":""}}`, true, AuthNone, ReasonNone},
		{"null code", `{` + tickets + `,"data":{"code":null}}`, true, AuthNone, ReasonNone},
		{"absent code", `{` + tickets + `,"data":{}}`, true, AuthNone, ReasonNone},
		{"string zero code", `{` + tickets + `,"data":{"code":"0"}}`, false, AuthUnknown, ReasonUnknownBusinessCode},
		{"truthy number code", `{` + tickets + `,"data":{"code":5}}`, false, AuthUnknown, ReasonUnknownBusinessCode},
		{"true code", `{` + tickets + `,"data":{"code":true}}`, false, AuthUnknown, ReasonUnknownBusinessCode},
		{"known code beats ticket", `{` + tickets + `,"data":{"code":"NOUSER"}}`, false, AuthCredentialsRejected, ReasonNone},
		{"known captcha code beats ticket", `{` + tickets + `,"data":{"code":"CODEFALSE"}}`, false, AuthCaptcha, ReasonNone},
	} {
		res := classifyTicketResponse(200, []byte(tc.body))
		if res.OK != tc.wantOK || res.Issue != tc.wantIss || res.ReasonCode != tc.wantRsn {
			t.Errorf("%s: ok=%v issue=%s reason=%s (want ok=%v issue=%s reason=%s)",
				tc.name, res.OK, res.Issue, res.ReasonCode, tc.wantOK, tc.wantIss, tc.wantRsn)
		}
	}
	// A falsy code without any ticket evidence stays unresolved — never success.
	for _, body := range []string{`{"data":{"code":0}}`, `{"data":{"code":false}}`, `{"data":{"code":""}}`} {
		res := classifyTicketResponse(200, []byte(body))
		if res.OK || res.ReasonCode != ReasonResponseSchemaUnknown {
			t.Errorf("%s: falsy code invented an outcome: %+v", body, res)
		}
	}
}

// The final user text must be reason-specific: the previous implementation
// overwrote every unknown with one generic sentence, erasing the reason that
// had just been established.
func TestFinalUserTextIsReasonSpecific(t *testing.T) {
	reasons := []VerifyReason{
		ReasonUnknownBusinessCode,
		ReasonResponseBodyUnavail,
		ReasonBodyReadFailed,
		ReasonBodyReadTimeout,
		ReasonResponseNotReceived,
		ReasonHTTPStatusUnexpected,
		ReasonResponseSchemaUnknown,
		ReasonResponseEvidenceMissing,
		ReasonTicketRequestNotSeen,
		ReasonCASFormTimeout,
	}
	seen := map[string]VerifyReason{}
	const oldBlanket = "未取得明确认证结果，请勿连续重试"
	for _, code := range reasons {
		got := finalResultForUser(verificationReply(AuthUnknown, code)).Reason
		want := unknownReasonText(code)
		if got != want {
			t.Errorf("%s: text = %q, want %q", code, got, want)
		}
		if strings.Contains(got, oldBlanket) {
			t.Errorf("%s: still collapsed into the generic sentence", code)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s share one text: %q", code, prev, got)
		}
		seen[got] = code
	}
}

// Only a credential rejection may imply a wrong password. Every other outcome —
// including all the unknown reasons — must keep a text that does not.
func TestOnlyCredentialRejectionImpliesPasswordError(t *testing.T) {
	credential := finalResultForUser(verificationReply(AuthCredentialsRejected, ReasonNone))
	if !strings.Contains(credential.Reason, "密码错误") {
		t.Fatalf("the credential text lost its meaning: %q", credential.Reason)
	}
	others := []VerificationResult{
		verificationReply(AuthUnknown, ReasonUnknownBusinessCode),
		verificationReply(AuthUnknown, ReasonResponseBodyUnavail),
		verificationReply(AuthUnknown, ReasonBodyReadTimeout),
		verificationReply(AuthUnknown, ReasonResponseNotReceived),
		verificationReply(AuthUnknown, ReasonVerificationTimeout),
		verificationReply(AuthUnknown, ReasonNone),
		verificationReply(AuthCaptcha, ReasonCAPTCHASolveFailed),
		verificationReply(AuthLocked, ReasonNone),
		verificationReply(AuthActionRequired, ReasonNone),
		verificationReply(AuthBusinessOther, ReasonNone),
		verificationReply(AuthNetwork, ReasonNetworkFailed),
		verificationReply(AuthCanceled, ReasonCanceled),
	}
	for _, res := range others {
		final := finalResultForUser(res)
		if final.Issue == AuthCredentialsRejected {
			t.Fatalf("non-credential issue was promoted: %+v", final)
		}
		for _, bad := range []string{"密码错误", "账号或密码错误", "密码不正确"} {
			if strings.Contains(final.Reason, bad) {
				t.Errorf("%s/%s reported as a password verdict: %q", res.Issue, res.ReasonCode, final.Reason)
			}
		}
		if strings.TrimSpace(final.Reason) == "" {
			t.Errorf("%s/%s produced an empty text", res.Issue, res.ReasonCode)
		}
	}
}

// Every reason text is a fixed constant: no server text, no code value, no
// hash, no URL, no ticket, no digits.
func TestReasonTextsAreFixedAndDeidentified(t *testing.T) {
	all := []VerifyReason{
		ReasonNone, ReasonLaunchFailed, ReasonListenFailed, ReasonNavigateFailed,
		ReasonCASFormTimeout, ReasonCAPTCHANotFound, ReasonCAPTCHASolveFailed,
		ReasonCASPageNotTrusted, ReasonCASFormMissing, ReasonLoginButtonMissing,
		ReasonLoginButtonNotVisible, ReasonLoginClickFailed, ReasonLoginButtonNotClicked,
		ReasonTicketRequestNotSeen, ReasonHTTPStatusUnexpected, ReasonResponseNotReceived,
		ReasonResponseBodyUnavail, ReasonBodyReadFailed, ReasonBodyReadTimeout,
		ReasonBodyResourceGone, ReasonBodyEmpty, ReasonResponseBodyTooLarge,
		ReasonResponseSchemaUnknown, ReasonUnknownBusinessCode, ReasonResponseEvidenceMissing,
		ReasonVerificationTimeout, ReasonNetworkFailed, ReasonCanceled, ReasonCleanupUnconfirmed,
	}
	for _, code := range all {
		text := unknownReasonText(code)
		if strings.TrimSpace(text) == "" {
			t.Fatalf("%s: empty text", code)
		}
		for _, bad := range []string{"http", "://", "TGT-", "ST-", "=", "{", "}"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: text carries protocol detail %q: %s", code, bad, text)
			}
		}
		for _, r := range text {
			if r >= '0' && r <= '9' {
				t.Errorf("%s: text carries a digit (could be a code/hash): %s", code, text)
			}
		}
	}
}

// Hostile server content must not reach the user text nor the diagnostics:
// the code value, the envelope and any injected secret stay out.
func TestHostileServerContentNeverReachesTheUser(t *testing.T) {
	const hostile = "TGT-secret-PW-hunter2"
	body := []byte(`{"data":{"code":"` + hostile + `","tips":"hunter2"}}`)
	res, shape := classifyTicketResponseDetailed(200, body)
	if res.ReasonCode != ReasonUnknownBusinessCode {
		t.Fatalf("reason = %s", res.ReasonCode)
	}
	final := finalResultForUser(res)
	for _, leak := range []string{hostile, "hunter2", "TGT-", "tips"} {
		if strings.Contains(final.Reason, leak) {
			t.Fatalf("server content leaked into the user text: %q", final.Reason)
		}
	}

	var lines []string
	tr := newVerifyTrace(func(l string) { lines = append(lines, l) })
	tr.shape(shape)
	tr.response(200, len(body), "true", "false")
	tr.failHere(res.ReasonCode, ErrClassNone)
	tr.requestID("req-1")
	tr.finish()
	if len(lines) != 1 {
		t.Fatalf("expected one summary line, got %v", lines)
	}
	for _, leak := range []string{hostile, "hunter2", "tips", `"code"`} {
		if strings.Contains(lines[0], leak) {
			t.Fatalf("server content leaked into the diagnostics: %s", lines[0])
		}
	}
	if !strings.Contains(lines[0], "code=unlisted/str/") {
		t.Fatalf("the shape record must still identify the class: %s", lines[0])
	}
}

// Structural guard for the regression itself: the outcome must be routed through
// finalResultForUser, and the blanked-out generic assignment must not come back.
// The wait now lives in awaitAuthResult (prompt.go), which is where the refined
// result — the response verdict, or the one the bounded page look replaced it
// with — is finalized; verifyBrowser must delegate to it.
func TestVerifyBrowserDelegatesFinalText(t *testing.T) {
	verifySrc, err := os.ReadFile("verify.go")
	if err != nil {
		t.Skipf("source not available: %v", err)
	}
	promptSrc, err := os.ReadFile("prompt.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(promptSrc), "return finalResultForUser(refined)") {
		t.Fatal("the refined outcome is no longer routed through finalResultForUser")
	}
	if !strings.Contains(string(verifySrc), "o.awaitAuthResult(ctx, trace, snap)") {
		t.Fatal("verifyBrowser no longer delegates the wait to awaitAuthResult")
	}
	// Defined once in verify.go, called once in the wait.
	if n := strings.Count(string(verifySrc)+string(promptSrc), "finalResultForUser("); n != 2 {
		t.Fatalf("finalResultForUser should be defined once and called once, found %d mentions", n)
	}
	if strings.Contains(string(verifySrc), `result.Reason = "未取得明确认证结果`) {
		t.Fatal("the blanket AuthUnknown override is back")
	}
}
