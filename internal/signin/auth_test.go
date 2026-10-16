package signin

import (
	"context"
	"errors"
	"github.com/chromedp/cdproto/network"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
	"strings"
	"testing"
)

func TestAuthClassifierStrict(t *testing.T) {
	for _, tc := range []struct {
		text string
		want AuthIssue
	}{
		{"用户名或密码错误。", AuthCredentialsRejected}, {"密码错误", AuthCredentialsRejected},
		{"账号锁定至:2099-01-01，请稍后重新登录或联系管理员处理。", AuthLocked},
		{"验证码错误", AuthCaptcha}, {"网络超时", AuthNone}, {"请检查账号密码是否正确", AuthNone},
		{"如遇密码错误请重置密码", AuthNone}, {"登录失败", AuthNone}, {"密码错误帮助", AuthNone},
	} {
		if got := ClassifyAuthMessage(tc.text); got != tc.want {
			t.Errorf("%q: got %s want %s", tc.text, got, tc.want)
		}
	}
}
func TestTicketContract(t *testing.T) {
	for _, tc := range []struct {
		body  string
		issue AuthIssue
		ok    bool
	}{
		{`{"tgt":"TGT-fake","ticket":"ST-fake"}`, AuthNone, true},
		{`{"data":{"code":"NOUSER"}}`, AuthCredentialsRejected, false},
		{`{"data":{"code":"CODEFALSE"}}`, AuthCaptcha, false},
		{`{"data":{"code":"USERLOCK"}}`, AuthLocked, false},
		{`{"data":{"code":"TWOVERIFY"}}`, AuthActionRequired, false},
		{`{"tgt":"TGT-fake","ticket":"ST-fake","data":{"code":"NOUSER"}}`, AuthCredentialsRejected, false},
		{`{"success":true}`, AuthUnknown, false}, {`{"ticket":"ST-fake"}`, AuthUnknown, false}, {`"TGT-fake"`, AuthUnknown, false},
		{`<html>个人查寝</html>`, AuthUnknown, false},
	} {
		r := classifyTicketResponse(200, []byte(tc.body))
		if r.OK != tc.ok || r.Issue != tc.issue {
			t.Errorf("unexpected result: %+v", r)
		}
	}
	if classifyTicketResponse(500, []byte(`{"tgt":"TGT-fake","ticket":"ST-fake"}`)).OK {
		t.Fatal("HTTP failure accepted")
	}
	if classifyTicketResponse(200, []byte(strings.Repeat(" ", maxAuthBody+1))).OK {
		t.Fatal("large body accepted")
	}
}
func TestTicketEndpointTrust(t *testing.T) {
	if !ticketEndpoint("https://ids.gzist.edu.cn/lyuapServer/v1/tickets") {
		t.Fatal("trusted rejected")
	}
	for _, s := range []string{"http://ids.gzist.edu.cn/lyuapServer/v1/tickets", "https://ids.gzist.edu.cn.evil/lyuapServer/v1/tickets", "https://ids.gzist.edu.cn:444/lyuapServer/v1/tickets", "https://evil@ids.gzist.edu.cn/lyuapServer/v1/tickets", "https://ids.gzist.edu.cn/lyuapServer/v1/tickets?x=1"} {
		if ticketEndpoint(s) {
			t.Fatal("untrusted accepted")
		}
	}
}
func TestVerificationCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		closed, removed := false, false
		err := cleanupVerification("owned", func() error {
			closed = true
			if fail {
				return errors.New("still running")
			}
			return nil
		}, func(s string) error {
			if !closed || s != "owned" {
				t.Fatal("unsafe cleanup")
			}
			removed = true
			return nil
		})
		if removed == fail || (err != nil) != fail {
			t.Fatal("cleanup condition or error propagation wrong")
		}
	}
}
func TestVerificationCleanupOverridesNamedReturn(t *testing.T) {
	for _, failure := range []string{"close", "remove", "none"} {
		for _, initial := range []VerificationResult{{OK: true}, {Issue: AuthCanceled}} {
			removed := false
			run := func() (result VerificationResult) {
				defer finishVerificationCleanup(&result, "owned", func() error {
					if failure == "close" {
						return errors.New("private path and process detail")
					}
					return nil
				}, func(string) error {
					removed = true
					if failure == "remove" {
						return errors.New("private directory detail")
					}
					return nil
				})
				return initial
			}
			result := run()
			if failure == "none" {
				if result != initial {
					t.Fatal("clean return changed")
				}
				continue
			}
			// The latch is additive: CleanupFailed must be set for the
			// application-wide block, but the original outcome is preserved so
			// the diagnostics keep the real failure stage (task: 保留原始失败阶段).
			if !result.CleanupFailed {
				t.Fatalf("cleanup did not latch the safety block: %+v", result)
			}
			if result.OK != initial.OK || result.Issue != initial.Issue || result.ReasonCode != initial.ReasonCode {
				t.Fatalf("cleanup erased the original outcome: %+v (was %+v)", result, initial)
			}
			if failure == "close" && removed {
				t.Fatal("directory removed despite surviving session")
			}
		}
	}
}

func TestVerificationCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := VerifyLogin(ctx, store.Settings{}, "fake", "fake", nil); r.OK || r.Issue != AuthCanceled || r.CleanupFailed {
		t.Fatal(r)
	}
}
func TestRecoveryAuthResult(t *testing.T) {
	r, ok := resultForRecovery(&authIssueError{issue: AuthCredentialsRejected})
	if !ok || r.AuthIssue != AuthCredentialsRejected || r.Exit != 3 {
		t.Fatal(r)
	}
}
func TestObservationFreshSubmissionAndNetwork(t *testing.T) {
	o := &authObservation{out: make(chan VerificationResult, 1)}
	request := &network.EventRequestWillBeSent{RequestID: "fake", DocumentURL: verifyCAS, Request: &network.Request{URL: "https://ids.gzist.edu.cn/lyuapServer/v1/tickets", Method: "POST"}}
	o.listen(context.Background(), request)
	if o.request != "" {
		t.Fatal("pre-submit request captured")
	}
	o.arm()
	o.listen(context.Background(), request)
	if o.request != "fake" {
		t.Fatal("new submission not captured")
	}
	o.listen(context.Background(), &network.EventLoadingFailed{RequestID: "fake"})
	if r := <-o.out; r.Issue != AuthNetwork || r.OK {
		t.Fatal(r)
	}
}
