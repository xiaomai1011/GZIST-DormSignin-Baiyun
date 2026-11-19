package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

func TestBusinessEntryCategoriesAreExactAndRedacted(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{recoveryTestURL, "stable-full-entry"},
		{"https://xsfw.gzist.edu.cn/index.do#/xscq/grcq", "stable-short-entry"},
		{"https://xsfw.gzist.edu.cn/index.do?ticket=PRIVATE#/xscq/grcq", "entry-with-query"},
		{"https://xsfw.gzist.edu.cn/index.do?#/xscq/grcq", "entry-with-query"},
		{"https://xsfw.gzist.edu.cn/index.do#/xscq/grcqPRIVATE", "entry-other-route"},
		{"https://xsfw.gzist.edu.cn/PRIVATE#/xscq/grcq", "other-path"},
		{"https://xsfw.gzist.edu.cn:444/index.do#/xscq/grcq", "not-business"},
		{"https://PRIVATE@xsfw.gzist.edu.cn/index.do#/xscq/grcq", "not-business"},
		{"https://evil.invalid/PRIVATE", "not-business"},
	} {
		if got := businessEntryCategory(tc.raw); got != tc.want {
			t.Fatalf("category=%q want=%q", got, tc.want)
		}
	}
}

func TestBusinessTargetEvidenceUsesOnlyBoundTarget(t *testing.T) {
	if businessTargetTag(context.Background()) != "unavailable" {
		t.Fatal("unexpected target")
	}
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	c := chromedp.FromContext(ctx)
	// NewContext is lazy: creating this value starts no browser.
	c.Target = &chromedp.Target{TargetID: target.ID("PRIVATE-TARGET-A")}
	a := businessTargetTag(ctx)
	if len(a) != 12 || strings.Contains(a, "PRIVATE") || a != businessTargetTag(ctx) {
		t.Fatal("unstable or raw target", a)
	}
	c.Target.TargetID = target.ID("PRIVATE-TARGET-B")
	if a == businessTargetTag(ctx) {
		t.Fatal("different targets collapsed")
	}
	c.Target = nil // no session was allocated
}

func TestBusinessProgressFourCharactersAreTwelveBytes(t *testing.T) {
	var line string
	r := &Runner{Log: func(s string) { line = s }}
	r.step6Progress(120*time.Second, pageState{URL: recoveryTestURL, Text: "个人查寝"}, false, nil)
	for _, want := range []string{"文本长度=12 bytes", "字符数=4", "入口=stable-full-entry"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %s in %s", want, line)
		}
	}
	if strings.Contains(line, "个人查寝") {
		t.Fatal("raw body leaked")
	}
}

func TestBusinessWaitPhaseEvidenceAndBudget(t *testing.T) {
	var logs []string
	r := &Runner{Log: func(s string) { logs = append(logs, s) }}
	probes := 0
	_, elapsed, err := r.waitBusinessPhase(context.Background(), "recovery-wait", 20*time.Millisecond, func(context.Context) (pageState, error) {
		probes++
		return pageState{URL: recoveryTestURL, Text: "个人查寝"}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || elapsed < 20*time.Millisecond || elapsed > time.Second || probes != 1 {
		t.Fatalf("elapsed=%v err=%v probes=%d", elapsed, err, probes)
	}
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"phase=recovery-wait", "target=unavailable", "入口=stable-full-entry", "deadline-exceeded"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
	if strings.Contains(joined, "个人查寝") {
		t.Fatal("raw body leaked")
	}
}

func TestBusinessSuccessOutcomesKeepOKButSeparateEvidence(t *testing.T) {
	var logs []string
	r := &Runner{Log: func(s string) { logs = append(logs, s) }}
	observed := r.observedSignedResult()
	submitted := r.submittedConfirmedResult()
	if !observed.OK || !submitted.OK || observed.Exit != 0 || submitted.Exit != 0 || observed.Outcome != OutcomeObservedSigned || submitted.Outcome != OutcomeSubmittedConfirmed {
		t.Fatalf("observed=%+v submitted=%+v", observed, submitted)
	}
	if !strings.Contains(logs[0], "本轮未提交") || !strings.Contains(logs[1], "未关联服务端请求") {
		t.Fatal(logs)
	}
}

func TestRouteRepairUsesSameTrustedOriginAsReadiness(t *testing.T) {
	for _, raw := range []string{
		"http://xsfw.gzist.edu.cn/index.do",
		"https://xsfw.gzist.edu.cn:444/index.do",
		"https://user@xsfw.gzist.edu.cn/index.do",
		"https://xsfw.gzist.edu.cn.evil.invalid/index.do",
	} {
		ready, repair := pageWaitPolicy(pageState{URL: raw}, 4*time.Second, false)
		if ready || repair {
			t.Fatalf("untrusted repair allowed: %s", raw)
		}
	}
	for _, guard := range []string{"location.protocol==='https:'", "location.hostname==='xsfw.gzist.edu.cn'", "location.port==='443'", ".username", ".password"} {
		if !strings.Contains(repairPageRouteJS, guard) {
			t.Fatal("missing atomic guard", guard)
		}
	}
}
