package signin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// unclassifiedCodeResult is the one outcome the page look may refine: a trusted
// response whose business code we could not classify.
var unclassifiedCodeResult = VerificationResult{
	Issue:      AuthUnknown,
	ReasonCode: ReasonUnknownBusinessCode,
}

// snapOK is a successful pre-submission snapshot. snapFailed is one that could
// not be taken at all.
func snapOK(before ...string) promptSnapshot {
	return snapshotPagePrompt(promptRead{sampled: true, parts: before})
}
func snapFailed() promptSnapshot { return snapshotPagePrompt(promptRead{}) }

// scriptedReader is a reader whose answer is fixed: it returns the given
// sentences (or reports that the page could not be read) and counts how often it
// was asked.
type scriptedReader struct {
	sentences []string
	sampled   bool
	calls     int
}

func (s *scriptedReader) read(context.Context) promptRead {
	s.calls++
	return promptRead{sampled: s.sampled, parts: s.sentences}
}

func promptTestObservation(reader func(context.Context) promptRead, lines *[]string) *authObservation {
	o := &authObservation{out: make(chan VerificationResult, 1), pagePrompt: reader}
	if lines != nil {
		o.trace = newVerifyTrace(func(l string) { *lines = append(*lines, l) })
	}
	return o
}

// The sentences are matched exactly, and each one keeps its verified meaning: a
// named cause becomes that cause, the wrong-password counter sentence becomes a
// credential rejection — or a lock when it announces one — and the two generic
// "check your account or password" sentences stay generic, never a verdict.
func TestClassifyPagePromptVerifiedSentences(t *testing.T) {
	for _, tc := range []struct {
		text      string
		wantIssue AuthIssue
		wantCode  VerifyReason
		want      bool
	}{
		{"用户名或密码错误。", AuthCredentialsRejected, ReasonPageAuthPrompt, true},
		{"密码错误", AuthCredentialsRejected, ReasonPageAuthPrompt, true},
		{"账号或密码错误", AuthCredentialsRejected, ReasonPageAuthPrompt, true},
		{"账号锁定至:2026-10-16 12:00，请稍后重新登录或联系管理员处理。", AuthLocked, ReasonPageAuthPrompt, true},
		{"账号被停用，请联系相关管理员处理。", AuthLocked, ReasonPageAuthPrompt, true},
		{"验证码错误", AuthCaptcha, ReasonPageAuthPrompt, true},
		// The two counter sentences, matched in full. The one that announces a
		// lock is a lock: the advice is to stop retrying, not to retype.
		{"密码已连续错误【3】次，账号锁定。", AuthLocked, ReasonPagePasswordLocked, true},
		{"密码已连续错误【3】次，连续错误【5】次账号将被锁定。", AuthCredentialsRejected, ReasonPagePasswordCounter, true},
		{"密码已连续错误【12】次，连续错误【100】次账号将被锁定。", AuthCredentialsRejected, ReasonPagePasswordCounter, true},
		// The unlisted-code branch of the school client renders exactly this: it
		// asks the user to check, it does not name a wrong password.
		{"请检查账号或密码是否正确", AuthUnknown, ReasonPageGenericRejection, true},
		{"请检查账号密码是否正确", AuthUnknown, ReasonPageGenericRejection, true},
		// Everything below is NOT evidence: help text, a fragment, a partial
		// counter overlap, a non-numeric count, extra prose, an empty region or a
		// sentence that merely mentions a password. None may hint at a verdict.
		{"密码已连续错误次数统计", AuthNone, ReasonNone, false},
		{"密码已连续错误【3】次", AuthNone, ReasonNone, false},
		{"密码已连续错误【3】次，", AuthNone, ReasonNone, false},
		{"密码已连续错误【三】次，账号锁定。", AuthNone, ReasonNone, false},
		{"密码已连续错误【1234】次，账号锁定。", AuthNone, ReasonNone, false},
		{"密码已连续错误【3】次，账号锁定", AuthNone, ReasonNone, false},
		{"密码已连续错误【3】次，账号锁定。请重试", AuthNone, ReasonNone, false},
		{"已连续错误，密码已连续错误【3】次，账号锁定。", AuthNone, ReasonNone, false},
		{"请先阅读：密码已连续错误【3】次，账号锁定。", AuthNone, ReasonNone, false},
		{"忘记密码？", AuthNone, ReasonNone, false},
		{"请输入密码", AuthNone, ReasonNone, false},
		{"密码错误次数：3", AuthNone, ReasonNone, false},
		{"密码", AuthNone, ReasonNone, false},
		{"", AuthNone, ReasonNone, false},
		{"登录", AuthNone, ReasonNone, false},
		{"用户名或密码错误，请检查", AuthNone, ReasonNone, false},
		{"TGT-secret-hunter2", AuthNone, ReasonNone, false},
		{"https://ids.gzist.edu.cn/lyuapServer/login?ticket=ST-x", AuthNone, ReasonNone, false},
	} {
		issue, code, ok := classifyPagePrompt([]string{tc.text}, snapOK())
		if ok != tc.want || issue != tc.wantIssue || code != tc.wantCode {
			t.Errorf("%q: got (%s, %s, %v), want (%s, %s, %v)",
				tc.text, issue, code, ok, tc.wantIssue, tc.wantCode, tc.want)
		}
	}
}

// A sentence that was already on the page before the submission is not evidence
// about this attempt: the snapshot removes it, and only a new one is accepted.
func TestPagePromptSnapshotBlocksAReusedPrompt(t *testing.T) {
	stale := "用户名或密码错误。"
	if _, _, ok := classifyPagePrompt([]string{stale}, snapOK(stale)); ok {
		t.Fatal("a stale prompt was accepted as evidence for this attempt")
	}
	// The same sentence is evidence only when it is new.
	if _, code, ok := classifyPagePrompt([]string{stale}, snapOK()); !ok || code != ReasonPageAuthPrompt {
		t.Fatal("a new prompt was not accepted")
	}
	// A page that already showed one message and now shows another: the new
	// sentence wins, the old one is still ignored.
	mixed := []string{"请检查账号或密码是否正确", "用户名或密码错误。"}
	issue, code, ok := classifyPagePrompt(mixed, snapOK("请检查账号或密码是否正确"))
	if !ok || issue != AuthCredentialsRejected || code != ReasonPageAuthPrompt {
		t.Fatalf("the new sentence was not the one used: (%s, %s, %v)", issue, code, ok)
	}
	// Nothing is read when the snapshot already contains every sentence.
	if _, _, ok := classifyPagePrompt(mixed, snapOK(mixed...)); ok {
		t.Fatal("a fully stale page produced a verdict")
	}
}

// A snapshot that could not be taken is not an empty page: no sentence may be
// used, and the submission and its response verdict are not affected either.
func TestFailedSnapshotDisablesThePagePath(t *testing.T) {
	if _, _, ok := classifyPagePrompt([]string{"用户名或密码错误。"}, snapFailed()); ok {
		t.Fatal("a failed snapshot must not accept any sentence")
	}
	reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
	o := promptTestObservation(reader.read, nil)
	// The wait loop's poll refuses without reading the page at all.
	if _, _, ok := o.pageVerdict(context.Background(), snapFailed()); ok || reader.calls != 0 {
		t.Fatalf("page verdict without a snapshot: ok=%v reads=%d", ok, reader.calls)
	}
	// The bounded look refuses too, and keeps the response verdict.
	var lines []string
	o2 := promptTestObservation(reader.read, &lines)
	got, interrupted := o2.observePagePrompt(context.Background(), unclassifiedCodeResult, snapFailed())
	if interrupted || got != unclassifiedCodeResult || reader.calls != 0 {
		t.Fatalf("bounded look without a snapshot: %+v interrupted=%v reads=%d", got, interrupted, reader.calls)
	}
	// The wait still finalizes the trusted response.
	o3 := promptTestObservation(reader.read, nil)
	sent := verificationReply(AuthUnknown, ReasonBodyReadFailed)
	go func() { o3.out <- sent }()
	if got3 := o3.awaitAuthResult(context.Background(), o3.trace, snapFailed()); got3 != finalResultForUser(sent) {
		t.Fatalf("the response verdict was lost to a failed snapshot: %+v", got3)
	}
}

// The look is scoped to the one outcome that needs it. A success, a credential
// verdict, a lock, a captcha failure, a network failure and every other unknown
// reason must be returned untouched — and the page must not even be read.
func TestPagePromptLookIsScopedToTheUnlistedCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  VerificationResult
	}{
		{"success", VerificationResult{OK: true}},
		{"credential rejection", verificationReply(AuthCredentialsRejected, ReasonNone)},
		{"locked", verificationReply(AuthLocked, ReasonNone)},
		{"captcha", verificationReply(AuthCaptcha, ReasonCAPTCHASolveFailed)},
		{"network failure", verificationReply(AuthNetwork, ReasonNetworkFailed)},
		{"body read failure", verificationReply(AuthUnknown, ReasonBodyReadFailed)},
		{"unclassified contract", verificationReply(AuthUnknown, ReasonResponseSchemaUnknown)},
		{"canceled", verificationReply(AuthCanceled, ReasonCanceled)},
	} {
		reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
		o := promptTestObservation(reader.read, nil)
		got, interrupted := o.observePagePrompt(context.Background(), tc.res, snapOK())
		if interrupted || got != tc.res {
			t.Errorf("%s: result was refined to %+v (interrupted=%v)", tc.name, got, interrupted)
		}
		if reader.calls != 0 {
			t.Errorf("%s: the page was read %d times for an outcome that needs no look", tc.name, reader.calls)
		}
	}
	// The one outcome that does need it.
	reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
	var lines []string
	o := promptTestObservation(reader.read, &lines)
	got, interrupted := o.observePagePrompt(context.Background(), unclassifiedCodeResult, snapOK())
	if interrupted {
		t.Fatal("an available prompt must not report an interruption")
	}
	if got.Issue != AuthCredentialsRejected || got.ReasonCode != ReasonPageAuthPrompt {
		t.Fatalf("the page-confirmed verdict was not adopted: %+v", got)
	}
	if got.Reason != authReason(AuthCredentialsRejected) {
		t.Fatalf("the refinement must carry the fixed credential text: %q", got.Reason)
	}
	if reader.calls != 1 {
		t.Fatalf("one read is enough when the prompt is already there, got %d", reader.calls)
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=credential") {
		t.Fatalf("the refinement must be visible as a fixed enum: %v", lines)
	}
}

// No prompt, an unverifiable prompt or a page that cannot be read: the run keeps
// the unclassified verdict, the look stays inside its own budget, and the fact is
// recorded as a fixed enum.
func TestPagePromptLookIsBoundedAndStaysUnknown(t *testing.T) {
	for _, tc := range []struct {
		name      string
		sentences []string
		sampled   bool
	}{
		{"no prompt at all", nil, true},
		{"unverifiable prompt", []string{"正在登录中…", "密码错误次数：3"}, true},
		{"unreadable page", []string{"用户名或密码错误。"}, false},
	} {
		reader := &scriptedReader{sentences: tc.sentences, sampled: tc.sampled}
		var lines []string
		o := promptTestObservation(reader.read, &lines)
		start := time.Now()
		got, interrupted := o.observePagePrompt(context.Background(), unclassifiedCodeResult, snapOK())
		elapsed := time.Since(start)
		if interrupted || got != unclassifiedCodeResult {
			t.Errorf("%s: the run did not stay unknown: %+v (interrupted=%v)", tc.name, got, interrupted)
		}
		if elapsed < pagePromptBudget || elapsed > pagePromptBudget+time.Second {
			t.Errorf("%s: the look took %v, want it bounded by %v", tc.name, elapsed, pagePromptBudget)
		}
		o.trace.finish()
		if len(lines) != 1 || !strings.Contains(lines[0], "prompt=no_new_sentence") {
			t.Errorf("%s: summary = %v", tc.name, lines)
		}
	}
}

// The two seconds are a real ceiling, not a check after the fact: a read that
// blocks until its context ends must end the look at the look's own bound, keep
// the unknown result, and not be reported as a cancellation of the run.
func TestPagePromptLookBoundsAStalledRead(t *testing.T) {
	blocked := func(ctx context.Context) promptRead {
		<-ctx.Done()
		return promptRead{}
	}
	var lines []string
	o := promptTestObservation(blocked, &lines)
	start := time.Now()
	got, interrupted := o.observePagePrompt(context.Background(), unclassifiedCodeResult, snapOK())
	elapsed := time.Since(start)
	if interrupted {
		t.Fatal("the caller's context was alive: a stalled read must not look like a cancellation")
	}
	if got != unclassifiedCodeResult {
		t.Fatalf("the result must stay unknown: %+v", got)
	}
	if elapsed > pagePromptBudget+time.Second {
		t.Fatalf("a stalled read outlived the look bound: %v", elapsed)
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=no_new_sentence") {
		t.Fatalf("summary = %v", lines)
	}
}

// Cancel and the total budget keep their priority: the look ends at once, tells
// the caller to use the context outcome, and never changes the result itself —
// whether the read returns promptly or is stalled inside the call.
func TestPagePromptLookYieldsToCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader func(context.Context) promptRead
	}{
		{"prompt read returns nothing", func(context.Context) promptRead {
			return promptRead{sampled: true}
		}},
		{"prompt read is stalled", func(ctx context.Context) promptRead {
			<-ctx.Done()
			return promptRead{}
		}},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		var lines []string
		o := promptTestObservation(tc.reader, &lines)
		go func() {
			time.Sleep(150 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		got, interrupted := o.observePagePrompt(ctx, unclassifiedCodeResult, snapOK())
		elapsed := time.Since(start)
		cancel()
		if !interrupted {
			t.Fatalf("%s: a canceled look must tell the caller to use the context outcome", tc.name)
		}
		if got != unclassifiedCodeResult {
			t.Fatalf("%s: a canceled look must not update the result: %+v", tc.name, got)
		}
		if elapsed > time.Second {
			t.Fatalf("%s: cancellation must end the look promptly, took %v", tc.name, elapsed)
		}
		o.trace.finish()
		if len(lines) != 1 || !strings.Contains(lines[0], "prompt=interrupted") {
			t.Fatalf("%s: summary = %v", tc.name, lines)
		}
	}
	// Already-canceled context: no read happens at all.
	reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
	dead, deadCancel := context.WithCancel(context.Background())
	deadCancel()
	o := promptTestObservation(reader.read, nil)
	if _, interrupted := o.observePagePrompt(dead, unclassifiedCodeResult, snapOK()); !interrupted || reader.calls != 0 {
		t.Fatalf("an already-canceled context must stop the look before any read (reads=%d)", reader.calls)
	}
}

// The complete wait, not just the look: while the response is still on its way, a
// leftover credential modal that stays visible must never decide the run — the
// poll reads the page several times and still keeps waiting.
func TestWaitIgnoresAStaleModalWhileTheResponseIsSlow(t *testing.T) {
	stale := "用户名或密码错误。"
	reader := &scriptedReader{sentences: []string{stale}, sampled: true}
	var lines []string
	o := promptTestObservation(reader.read, &lines)
	want := verificationReply(AuthUnknown, ReasonBodyReadFailed)
	go func() {
		time.Sleep(3 * authWaitPoll) // older than three polls
		o.out <- want
	}()
	got := o.awaitAuthResult(context.Background(), o.trace, snapOK(stale))
	if got != finalResultForUser(want) {
		t.Fatalf("the leftover modal decided the run: %+v", got)
	}
	if reader.calls < 2 {
		t.Fatalf("the wait must have polled the page before the response, reads=%d", reader.calls)
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=none") {
		t.Fatalf("summary = %v", lines)
	}
}

// A definitive verdict the page states about THIS submission may end the wait
// without a response — that is what the poll is for.
func TestWaitAcceptsANewDefinitivePageVerdict(t *testing.T) {
	reader := &scriptedReader{sentences: []string{"账号锁定至:2026-10-16 12:00，请稍后重新登录或联系管理员处理。"}, sampled: true}
	var lines []string
	o := promptTestObservation(reader.read, &lines)
	start := time.Now()
	got := o.awaitAuthResult(context.Background(), o.trace, snapOK())
	if got.Issue != AuthLocked || got.Reason != authReason(AuthLocked) {
		t.Fatalf("the page verdict was not adopted: %+v", got)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("the poll should have decided the wait quickly, took %v", time.Since(start))
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=locked") {
		t.Fatalf("summary = %v", lines)
	}
}

// A generic "login failed" sentence is not a verdict: it must never end the wait
// on its own, because the response may still name the cause.
func TestWaitDoesNotLetAGenericSentenceDecideAlone(t *testing.T) {
	reader := &scriptedReader{sentences: []string{"请检查账号或密码是否正确"}, sampled: true}
	o := promptTestObservation(reader.read, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := o.awaitAuthResult(ctx, o.trace, snapOK())
	if got.Issue == AuthCredentialsRejected {
		t.Fatalf("a generic sentence became a password verdict: %+v", got)
	}
	if got.ReasonCode != ReasonVerificationTimeout && got.ReasonCode != ReasonCanceled {
		t.Fatalf("the wait must end on the caller's budget, got %+v", got)
	}
	if reader.calls < 2 {
		t.Fatalf("the poll must have read the page repeatedly, reads=%d", reader.calls)
	}
}

// A cancellation that lands DURING a page read must win over a sentence the read
// still returned: the contexts are re-checked after every read, in both readers
// and in the wait itself.
func TestPagePromptReadCannotOutrunCancellation(t *testing.T) {
	const sentence = "用户名或密码错误。"
	// The worst case: the read cancels the caller's context and THEN answers with a
	// valid, timely sentence.
	canceling := func(cancel context.CancelFunc) func(context.Context) promptRead {
		return func(context.Context) promptRead {
			cancel()
			return promptRead{sampled: true, parts: []string{sentence}}
		}
	}
	// 1. The bounded look.
	ctx, cancel := context.WithCancel(context.Background())
	var lines []string
	o := promptTestObservation(canceling(cancel), &lines)
	got, interrupted := o.observePagePrompt(ctx, unclassifiedCodeResult, snapOK())
	cancel()
	if !interrupted || got != unclassifiedCodeResult {
		t.Fatalf("the look adopted a sentence read under a canceled caller: %+v", got)
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=interrupted") {
		t.Fatalf("summary = %v", lines)
	}
	// 2. The wait loop's own read.
	ctx2, cancel2 := context.WithCancel(context.Background())
	o2 := promptTestObservation(canceling(cancel2), nil)
	if issue, _, ok := o2.pageVerdict(ctx2, snapOK()); ok {
		t.Fatalf("the poll adopted a sentence read under a canceled caller: %s", issue)
	}
	cancel2()
	// 3. The complete wait: the cancellation must still be what comes out.
	ctx3, cancel3 := context.WithCancel(context.Background())
	o3 := promptTestObservation(canceling(cancel3), nil)
	got3 := o3.awaitAuthResult(ctx3, o3.trace, snapOK())
	if got3.Issue != AuthCanceled || got3.ReasonCode != ReasonCanceled {
		t.Fatalf("the wait did not report the cancellation: %+v", got3)
	}
}

// A read that only answers after the look's own budget ran out must not be
// adopted either: the caller is still alive, so the run keeps its original
// unclassified result — and the wait still ends on the caller's own clock.
func TestPagePromptReadCannotOutrunTheLookBudget(t *testing.T) {
	const sentence = "用户名或密码错误。"
	// Waits for the bounded context handed in, then answers with a valid sentence.
	late := func(ctx context.Context) promptRead {
		<-ctx.Done()
		return promptRead{sampled: true, parts: []string{sentence}}
	}
	// 1. The bounded look.
	var lines []string
	o := promptTestObservation(late, &lines)
	start := time.Now()
	got, interrupted := o.observePagePrompt(context.Background(), unclassifiedCodeResult, snapOK())
	if interrupted || got != unclassifiedCodeResult {
		t.Fatalf("a sentence read after the look's budget was adopted: %+v", got)
	}
	if elapsed := time.Since(start); elapsed > pagePromptBudget+time.Second {
		t.Fatalf("the look outlived its own budget: %v", elapsed)
	}
	o.trace.finish()
	if len(lines) != 1 || !strings.Contains(lines[0], "prompt=no_new_sentence") {
		t.Fatalf("summary = %v", lines)
	}
	// 2. The wait loop's own read.
	o2 := promptTestObservation(late, nil)
	if issue, _, ok := o2.pageVerdict(context.Background(), snapOK()); ok {
		t.Fatalf("the poll adopted a sentence read after its own bound: %s", issue)
	}
	// 3. The complete wait: the late sentence never becomes the verdict, and the
	// caller's own timeout decides.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	o3 := promptTestObservation(late, nil)
	got3 := o3.awaitAuthResult(ctx, o3.trace, snapOK())
	if got3.Issue == AuthCredentialsRejected {
		t.Fatalf("a late sentence decided the run: %+v", got3)
	}
	if got3.ReasonCode != ReasonVerificationTimeout {
		t.Fatalf("expected the caller's budget timeout, got %+v", got3)
	}
}

// When a cancellation and a result become ready at the same moment, Go may pick
// either select case — the OUTCOME must not depend on that: the context is
// re-checked before any verdict is adopted, for the response and for a page
// verdict alike.
func TestAwaitResultPrefersTheContextWhenBothAreReady(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  VerificationResult
	}{
		{"credential verdict waiting", verificationReply(AuthCredentialsRejected, ReasonNone)},
		{"success waiting", VerificationResult{OK: true}},
		{"unclassified response waiting", unclassifiedCodeResult},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
		o := promptTestObservation(reader.read, nil)
		o.out <- tc.res // the result is already available
		cancel()        // and so is the cancellation
		got := o.awaitAuthResult(ctx, o.trace, snapOK())
		if got.Issue != AuthCanceled || got.ReasonCode != ReasonCanceled {
			t.Fatalf("%s: a canceled run adopted a result: %+v", tc.name, got)
		}
		if reader.calls != 0 {
			t.Fatalf("%s: a canceled run read the page %d times", tc.name, reader.calls)
		}
	}
	// And a page verdict: a canceled look refuses even a new, usable sentence.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := promptTestObservation(func(context.Context) promptRead {
		return promptRead{sampled: true, parts: []string{"用户名或密码错误。"}}
	}, nil)
	if got, interrupted := o.observePagePrompt(ctx, unclassifiedCodeResult, snapOK()); !interrupted || got != unclassifiedCodeResult {
		t.Fatalf("a canceled look adopted a usable sentence: %+v", got)
	}
}

// The page text lives in memory only: the summary carries one fixed enum and
// never the sentence, a code, a ticket or a URL.
func TestPagePromptNeverReachesTheDiagnostics(t *testing.T) {
	reader := &scriptedReader{sentences: []string{"用户名或密码错误。"}, sampled: true}
	var lines []string
	o := promptTestObservation(reader.read, &lines)
	if _, interrupted := o.observePagePrompt(context.Background(), unclassifiedCodeResult, snapOK()); interrupted {
		t.Fatal("unexpected interruption")
	}
	o.trace.finish()
	if len(lines) != 1 {
		t.Fatalf("exactly one summary line expected: %v", lines)
	}
	line := lines[0]
	if !strings.Contains(line, "prompt=credential") {
		t.Fatalf("summary = %s", line)
	}
	for _, bad := range []string{"密码", "用户名", "http://", "https://", "TGT-", "ST-", "\n"} {
		if strings.Contains(line, bad) {
			t.Fatalf("the page text leaked into the diagnostics (%q): %s", bad, line)
		}
	}
}

// Structural guards: the region list is the only thing read, the reader cannot
// click or submit anything, the read outcomes stay distinguishable, and the
// trusted-document rule has exactly one definition in the package.
func TestPagePromptReaderIsPassiveAndScoped(t *testing.T) {
	for _, want := range []string{
		".ant-modal-confirm-error .ant-modal-confirm-content",
		".ant-message-error span",
		"#errorMsg",
		"getBoundingClientRect",
	} {
		if !strings.Contains(casErrorRegionsJS, want) {
			t.Errorf("the region list lost %q: %s", want, casErrorRegionsJS)
		}
	}
	if !strings.Contains(casPagePromptJS, casPageTrustJS) {
		t.Fatal("the prompt reader does not re-check that the document is the trusted login page")
	}
	// The reader must be able to say "could not read" and "read, nothing there"
	// differently, and it must stay passive.
	for _, want := range []string{`"sampled":false`, `"sampled":true`} {
		if !strings.Contains(casPagePromptJS, want) {
			t.Errorf("the prompt reader no longer distinguishes its read outcomes (%q)", want)
		}
	}
	for _, forbidden := range []string{"click(", "submit(", "dispatchEvent", "location.reload", "location.href", "value=", "document.body"} {
		if strings.Contains(casPagePromptJS, forbidden) {
			t.Errorf("the prompt reader must stay passive, found %q", forbidden)
		}
	}
	// One definition of the trust rule, in production and in the readers alike.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	if n := strings.Count(src.String(), "location.hostname==='ids.gzist.edu.cn'"); n != 1 {
		t.Fatalf("the trusted-login-page rule must have exactly one definition, found %d", n)
	}
	// Every page-error read in the independent verification is snapshot-gated:
	// the raw DOM classifier must not be called from the verification flow any
	// more, or a leftover modal could decide it again.
	verifySrc, err := os.ReadFile("verify.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(verifySrc), "loginDOMIssue(") {
		t.Fatal("verify.go still reads page errors without the submission snapshot")
	}
}
