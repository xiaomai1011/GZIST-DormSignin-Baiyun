// Package signin runs one dorm-sign-in attempt end to end, mirroring
// daily-signin2.ps1: time guards → headless Edge → location override →
// login-state probe → auto login (credentials + captcha) → page ready →
// safety gates → trusted click → success check → screenshot. The visible
// window / hidden-desktop / pixel-probing layers of the original are
// gone by design: headless mode is the only mode, so clicks are always
// CDP page coordinates.
package signin

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chromedp/chromedp"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Result of one run. Exit mirrors the PowerShell exit codes so logs stay
// comparable: 0 ok / already signed, 3 need human, 5 config, 7 location,
// 8 time guard, 9 no browser.
type Result struct {
	Outcome   ResultOutcome
	AuthIssue AuthIssue
	OK        bool
	Reason    string
	Exit      int
	Neutral   bool // an expected non-run (off-hours / past late-line) — not an error
}

type Runner struct {
	Cfg     store.Settings
	Log     func(string)
	Notify  func(title, body string)
	ShotDir string
	Solver  *captcha.Solver
	Creds   CredsFunc

	// Hosts owns the application's resident browsers. It is nil outside the
	// application (and in private mode), where openBrowser dials the state file
	// directly or starts a private Edge.
	Hosts *browserhost.Manager

	// driver replaces the browser page surface. Only the offline tests that
	// count submissions set it; production leaves it nil.
	driver *loginDriver

	// origins is set per run (see Run) so the manual wait can name who ended it.
	// Runs are serialized by the caller, so one value per Runner is enough.
	origins runOrigins

	// hostClient is the resident host of the current run, set by openBrowser
	// and cleared when the run ends. It is nil in private mode; only the
	// resident host has a window that can be hidden between tasks.
	hostClient *browserhost.Client
}

// clickSignFn is the business submission seam: production uses the method, and
// tests use it to prove that a refused run submits nothing at all.
var clickSignFn = (*Runner).clickSign

// runNow is a seam so tests can place a run inside the attendance window
// without touching the real clock of the machine running them.
var runNow = time.Now

func (r *Runner) log(s string) {
	if r.Log != nil {
		r.Log(s)
	}
}

// notify mirrors r.Notify so the wait can be announced without a nil check.
func (r *Runner) notify(title, body string) {
	if r.Notify != nil {
		r.Notify(title, body)
	}
}

// step6ProgressEvery is how often the business-page wait says what it sees. The
// budget itself is unchanged: this only makes an existing wait readable.
const step6ProgressEvery = 15 * time.Second

// step6Progress reports one snapshot of the business-page wait. Without it a
// long wait and a stuck run look identical in the log — on 2026-10-25 a live run
// was killed at ~100 s into this wait and left no evidence either way.
func (r *Runner) step6Progress(elapsed time.Duration, s pageState, repaired bool, readErr error) {
	errText := "无"
	if readErr != nil {
		errText = safeDiagnosticError(readErr)
	}
	r.log(fmt.Sprintf("  步骤6 进展: 已等待 %.0fs，页面=%s，文本长度=%d bytes，字符数=%d，入口=%s，查寝文本=%v，点击签到=%v，路由修复=%v，最近读取错误=%s",
		elapsed.Seconds(), safePageCategory(s.URL), len(s.Text), utf8.RuneCountInString(s.Text), businessEntryCategory(s.URL),
		strings.Contains(s.Text, "查寝时间段"), strings.Contains(s.Text, "点击签到"), repaired, errText))
}

// manualVerification is what visible mode does when the school asks for its own
// two-factor step: it announces it, then waits read-only for a human to finish
// in the window this run launched. handled means the caller must return res as
// the outcome of the run: the flow is either resumed exactly once (via loginOK)
// or stopped with the reason that actually applies.
//
// Resident mode reveals only its bound main window before waiting. The window
// stays visible for this run; final lease cleanup hides it after the task ends.
func (r *Runner) manualVerification(ctx context.Context, ops loginPageOps, loginOK *bool) (Result, bool) {
	if !r.Cfg.VisibleBrowser && !r.Cfg.ResidentBrowser {
		return Result{}, false
	}
	var diag manualVerifyDiag
	verdict, stopped := manualVerifyStop(ctx, r.origins, time.Now(), &diag)
	if !stopped {
		if err := r.revealVerificationWindow(ctx); err != nil {
			if v, done := manualVerifyStop(ctx, r.origins, time.Now(), &diag); done {
				if v == manualVerifyStopped {
					return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}, true
				}
				if v == manualVerifyDisconnected {
					return Result{Reason: "浏览器连接中断，验证窗口未显示", Exit: 9}, true
				}
				return canceledResult(ctx), true
			}
			r.log("  二次验证窗口显示失败，本轮停止：" + safeDiagnosticError(err))
			r.notify("需要人工处理：验证窗口显示失败", errManualWindow.Error())
			return Result{Reason: errManualWindow.Error(), Exit: 9}, true
		}
		if r.Cfg.ResidentBrowser {
			r.log("  学校要求二次验证（手机／密保）—— 已显示本轮验证窗口，请自行完成；等待期间保持可见")
			r.notify("请在已显示的窗口完成二次验证", "已显示本轮学校验证页面。请完成手机／密保验证，程序随后继续签到；本轮结束才重新隐藏。")
		} else {
			r.log("  学校要求二次验证（手机／密保）—— 请在浏览器窗口里自行完成；程序只读取页面，不填写、不点击、不发送短信")
			r.notify("需要人工完成二次验证", "学校要求手机／密保验证。请在浏览器窗口里完成，程序会继续后面的签到流程。")
		}
		// Keep the actual browser window visible through authentication and business
		// readiness. Never reveal every native Chromium window belonging to a PID.
		verdict, diag = waitForManualVerification(ctx, r.origins, manualVerifyPoll, ops)
	}
	r.log(manualVerifyDiagLine(verdict, diag))
	switch verdict {
	case manualVerifyReached:
		r.logBusinessPhase(ctx, "auth-reached")
		// Resume, do not conclude: the normal business-page check and sign-in
		// still run afterwards, once, and only this session's page is believed.
		*loginOK = true
		r.log("  人工已完成二次验证，进入业务页 —— 继续业务页就绪检查与签到（仅此一次）")
		return Result{OK: true, Reason: "人工完成二次验证后继续签到"}, true
	case manualVerifyStopped:
		// Do not ask ctx for the reason here: the merged ctx may have kept the
		// browser's cancel cause, so a late line has to be mapped from the
		// verdict itself and not from whatever canceled this context first.
		return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}, true
	case manualVerifyCanceled:
		return canceledResult(ctx), true
	case manualVerifyBudget:
		return Result{Reason: "人工验证等待结束：本轮预算已用尽，二次验证未完成（未提交任何内容，不算完成）", Exit: 5}, true
	case manualVerifyDisconnected:
		return Result{Reason: "浏览器已关闭或连接中断，人工验证未完成（本轮不再等待，也不重试）", Exit: 9}, true
	}
	return Result{Reason: "人工验证后停留在不受支持的页面 —— 停止本轮，未提交任何内容", Exit: 3}, true
}

// stopOnGate turns a read-only gate verdict into the run's outcome. The
// two-factor page is the one stop that a visible window can turn into a wait;
// every other stop keeps the previous, single meaning.
func (r *Runner) stopOnGate(ctx context.Context, ops loginPageOps, loginOK *bool, verdict loginSubmitVerdict, diag loginSubmitDiag) Result {
	if verdict == loginSubmitActionRequired {
		if res, handled := r.manualVerification(ctx, ops, loginOK); handled {
			return res
		}
	}
	return loginSubmitFailure(verdict, diag)
}

// success keywords — only these exact phrases count as signed.
var successKws = []string{"无需重复签到", "您已签到成功", "签到成功"}

func (r *Runner) Run(ctx context.Context, manual bool) (out Result) {
	if ctx.Err() != nil {
		return canceledResult(ctx)
	}
	cfg := r.Cfg

	// ---- time guards (gate 0, before anything else) ----
	now := runNow()
	late := parseHM(cfg.LateLine, 23, 0)
	deadline := time.Date(now.Year(), now.Month(), now.Day(), late[0], late[1], 0, 0, now.Location())
	if now.Hour() < 21 {
		r.log(fmt.Sprintf("!! 当前 %02d:%02d 不在考勤时段(%s) —— 放弃签到", now.Hour(), now.Minute(), cfg.AttWindow))
		r.log("   (手动测试时该结果属正常)")
		return Result{Reason: fmt.Sprintf("不在考勤时段(%s) —— 到点会自动签", cfg.AttWindow), Exit: 8, Neutral: true}
	}
	if !now.Before(deadline) {
		r.log(fmt.Sprintf("!! 已过晚归线 %s —— 放弃签到，避免留下晚归记录", cfg.LateLine))
		return Result{Reason: "已过晚归线 " + cfg.LateLine + "（今晚不再尝试）", Exit: 8, Neutral: true}
	}

	// Carry the late line through every CDP action, including delayed dialog
	// submissions: a run starting before 23:00 must not keep clicking afterward.
	ctx, stopAtLateLine := beforeLateLine(ctx, deadline)
	defer stopAtLateLine()

	// ---- launch headless Edge (or lease the resident one) ----
	sess, release, err := r.openBrowser(ctx)
	defer func() { r.hostClient = nil }()
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		r.log("!! " + err.Error())
		return Result{Reason: err.Error(), Exit: 9}
	}
	defer func() {
		var cleanupErr error
		if release != nil {
			cleanupErr = release()
		} else {
			cleanupErr = sess.Close()
		}
		if cleanupErr != nil {
			r.log("!! 浏览器任务清理未确认: " + safeDiagnosticError(cleanupErr))
			out = Result{Reason: "浏览器任务清理未确认，本轮停止（签到结果请人工核实）", Exit: 9}
		}
	}()
	r.log(fmt.Sprintf("  Edge 已启动: PID=%d, UserData=%s", sess.PID, sess.UserData))
	caller := ctx
	ctx, cancel := runContext(caller, sess.Ctx, 8*time.Minute)
	r.origins = runOrigins{caller: caller, browser: sess.Ctx}
	defer cancel()

	// ---- location override BEFORE navigation (step 2.5) ----
	injectedEarly := false
	if cfg.GeoOn {
		if err := emulationSetGeo(ctx, cfg.Lat, cfg.Lon, cfg.AccM); err == nil {
			injectedEarly = true
			r.log(fmt.Sprintf("  定位已在页面加载前注入: %v, %v", cfg.Lat, cfg.Lon))
		} else {
			r.log("  定位提前注入失败，稍后兜底注入: " + err.Error())
		}
	}

	// ---- resident entry / private navigation ----
	if err := r.prepareRunEntry(ctx, deadline, sess.TargetID); err != nil {
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if errors.Is(err, errLateLine) {
			return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}
		}
		return Result{Reason: "打开页面失败：入口检查或导航未完成", Exit: 9}
	}

	// ---- step 3: login-state probe (watch CAS redirect, 4s early call) ----
	loginOK := false
	readyOps := browserLoginPageOps()
	ready, readyDiag := waitLoginReady(ctx, readyOps, 30*time.Second, 4*time.Second)
	r.log(loginReadyLine("step3", ready, readyDiag))
	if ready != loginReadyForm {
		res := r.finishLoginReady(ctx, readyOps, &loginOK, ready)
		if !res.OK {
			return res
		}
	}

	// ---- step 4: auto login with stored credentials ----
	if !loginOK {
		if cfg.AutoLogin {
			if res := r.autoLogin(ctx, &loginOK); res.OK {
				loginOK = true
			} else if res.Exit != 0 {
				return res
			}
		}
		if !loginOK {
			r.Notify("需要人工登录", "自动登录未完成。请打开程序主窗口，在账号卡片里确认学号密码已保存，然后点「立即签到」。")
			return Result{Reason: "自动登录未完成，需要人工", Exit: 3}
		}
	}
	r.log("  检测到登录成功 ✓")
	if err := sleepCtx(ctx, 800*time.Millisecond); err != nil {
		return canceledResult(ctx)
	}

	// ---- step 5: fallback location injection ----
	if cfg.GeoOn && !injectedEarly {
		if err := emulationSetGeo(ctx, cfg.Lat, cfg.Lon, cfg.AccM); err == nil {
			r.log("  步骤5: 兜底注入定位完成")
			// reload once so the page re-reads the position
			if err := chromedp.Reload().Do(exec(ctx)); err == nil {
				if err := sleepCtx(ctx, 2*time.Second); err != nil {
					return canceledResult(ctx)
				}
			}
		}
	}

	// ---- step 6: wait for business content ----
	last, elapsed, waitErr := r.waitBusinessPhase(ctx, "initial-wait", pageWaitBudget, probePage)
	if waitErr != nil {
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		r.log("  !! 页面未就绪。最后观测 URL: " + safePageURL(last.URL))
		r.log(fmt.Sprintf("  !! 最后观测页面文本长度: %d", len(last.Text)))
		r.log("  !! " + pageWaitFailure(elapsed, waitErr).Reason)
		last, elapsed, waitErr = r.recoverStep6(ctx, deadline, last, elapsed, waitErr)
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if errors.Is(waitErr, errLateLine) {
			return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}
		}
		if waitErr != nil {
			if res, ok := resultForRecovery(waitErr); ok {
				return res
			}
			res := pageWaitFailure(elapsed, waitErr)
			r.log("  !! " + res.Reason)
			return res
		}
	}
	// An already-confirmed success must not be lost to a later read or geo reload.
	if hit := hitKeyword(last.Text); hit != "" {
		r.log(">>> " + hit)
		return r.observedSignedResult()
	}
	r.log(fmt.Sprintf("  步骤6: 页面就绪 ✓（耗时 %.1fs）", elapsed.Seconds()))
	if err := sleepCtx(ctx, 800*time.Millisecond); err != nil {
		return canceledResult(ctx)
	}
	txt := pageText(ctx)
	if hit := hitKeyword(txt); hit != "" {
		r.log(">>> " + hit)
		return r.observedSignedResult()
	}
	r.log("  定位校验: " + geoVerdict(txt))

	// ---- step 6.5: geo verdict repair (original 2026-09-28 fix) ----
	// The site may run its geolocation check before our injected coords
	// are in effect and cache "不在考勤范围". One reload makes it re-judge
	// with the injected position.
	geoFix := 0
	for geoFix < 2 && strings.Contains(txt, "不在考勤范围") {
		geoFix++
		r.log(fmt.Sprintf("  !! 页面显示「不在考勤范围」-> 注入后重载一次让站点重新判定（第 %d 次）", geoFix))
		reloadIgnoreCache(ctx)
		dlG := time.Now().Add(40 * time.Second)
		for time.Now().Before(dlG) {
			if err := sleepCtx(ctx, 700*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			txt = pageText(ctx)
			if hit := hitKeyword(txt); hit != "" {
				r.log(">>> " + hit)
				return r.observedSignedResult()
			}
			if strings.Contains(txt, "点击签到") {
				break
			}
		}
		if strings.Contains(txt, "你已进入考勤登记范围") {
			r.log(fmt.Sprintf("  重载后: 已进入考勤登记范围 ✓ 定位判定修正成功（第 %d 次）", geoFix))
			break
		}
	}

	// ---- step 7 guards ----
	if hit := hitKeyword(txt); hit != "" {
		r.log(">>> " + hit)
		return r.observedSignedResult()
	}
	// gate 2: location must pass
	if cfg.GeoMust && strings.Contains(txt, "不在考勤范围") {
		r.log("!! 定位校验未通过（页面显示「不在考勤范围」）—— 拒绝点击")
		return Result{Reason: "页面显示「不在考勤范围」（定位校验未通过）", Exit: 7}
	}

	// wait for the button to be active (page-text verdict, like the
	// hidden-mode rewrite of the original)
	maxWait := 360 * time.Second
	nowH := time.Now().Hour()
	if nowH < 21 && nowH >= 0 {
		maxWait = 40 * time.Second
	}
	deadline7 := time.Now().Add(maxWait)
	signOK := false
	submissionAttempted := false
	for time.Now().Before(deadline7) {
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return canceledResult(ctx)
		}
		t2 := pageText(ctx)
		if hit := hitKeyword(t2); hit != "" {
			r.log(">>> " + hit)
			if submissionAttempted {
				return r.submittedConfirmedResult()
			}
			return r.observedSignedResult()
		}
		if strings.Contains(t2, "非考勤时段") {
			r.log("  页面显示「非考勤时段」—— 无需继续等待，退出")
			break
		}
		if strings.Contains(t2, "不在考勤范围") {
			r.log("  页面显示「不在考勤范围」—— 无需继续等待，退出")
			return Result{Reason: "页面显示「不在考勤范围」（定位校验未通过）", Exit: 7}
		}
		if !strings.Contains(t2, "点击签到") {
			continue // not active yet
		}
		// safety gate 3: five-point check before clicking
		if reason := clickSafety(ctx, t2); reason != "" {
			r.log("  !! 点击前检查未通过: " + reason)
			if strings.Contains(reason, "不在考勤范围") || strings.Contains(reason, "非考勤时段") || strings.Contains(reason, "已签到") {
				return Result{Reason: reason, Exit: 7}
			}
			continue
		}
		if !time.Now().Before(deadline) {
			return Result{Reason: errLateLine.Error(), Exit: 8, Neutral: true}
		}
		r.log("  安全检查通过（页面/域名/定位/时段均正常），开始点击...")
		submissionAttempted = true
		if err := clickSignFn(r, ctx, cfg); err != nil {
			r.log("  点击失败: " + safeDiagnosticError(err))
			if ctx.Err() != nil {
				return canceledResult(ctx)
			}
			return Result{Reason: "签到点击未确认完成，本轮停止且不重复提交", Exit: 5}
		}
		hit, after, observeErr := waitSignResult(ctx, 30*time.Second, 500*time.Millisecond, pageText,
			func(observeCtx context.Context, attempt int) {
				r.log(fmt.Sprintf("  检测到签到弹窗验证码 -> 第 %d 次处理（最多3次）", attempt))
				if r.handleSignCaptcha(observeCtx) {
					r.log("  弹窗验证码已处理")
				}
			})
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if observeErr != nil {
			r.log(fmt.Sprintf("  点击后未确认成功。最后页面文本长度: %d", len(after)))
			return Result{Reason: "点击后30秒内未确认成功，本轮不重复提交（详见日志）", Exit: 5}
		}
		signOK = true
		r.log(">>> " + hit)
		break
	}
	if !signOK {
		return Result{Reason: "未检测到签到成功（详见日志）", Exit: 5}
	}
	r.saveShot(ctx, "final")
	if r.Notify != nil {
		r.Notify("签到成功", "智能查寝签到已完成 ✓")
	}
	return r.submittedConfirmedResult()
}

// ---------- auto login ----------

// autoLogin submits the stored credentials at most CapMaxTry times. It only ever
// submits again after the login page itself said — about that very submission —
// that the captcha was wrong: "no answer" is not evidence, so the run stops
// instead of buying another blind submission with a fresh captcha image.
func (r *Runner) autoLogin(ctx context.Context, loginOK *bool) Result {
	d := browserLoginDriver(r.solveDataURL)
	if r.driver != nil {
		d = *r.driver
	}
	return r.autoLoginWith(ctx, loginOK, d.withDefaults())
}

// autoLoginWith runs one login against the injected page surface. Every page
// write, the captcha fill and the login click are guarded by stopIfCanceled:
// cancellation, the 8-minute run budget and the late line all travel in ctx (see
// runContext and beforeLateLine) and must win over any verdict that a read
// produced while the run was already being stopped.
func (r *Runner) autoLoginWith(ctx context.Context, loginOK *bool, d loginDriver) (out Result) {
	cfg := r.Cfg
	ops := d.ops
	// Any widening done below is undone before this function returns, so every
	// exit — success, two-factor, cancel, timeout — hands the caller the original
	// viewport. A restore that cannot be confirmed never lets a success stand:
	// the business page is laid out at that viewport and the sign-in must not run
	// on a page whose metrics are unknown.
	var vp widened
	defer func() {
		if !vp.Applied || d.restore == nil {
			return
		}
		if err := d.restore(ctx, vp); err != nil {
			r.log("  !! 恢复原视口失败: " + err.Error())
			// The login may have been reported through loginOK rather than through
			// the Result (see the submit loop), so both have to be withdrawn: a
			// success standing on unknown viewport metrics is not a success.
			if out.OK || (loginOK != nil && *loginOK) {
				if loginOK != nil {
					*loginOK = false
				}
				out = Result{Reason: "登录已成功，但恢复原视口失败：" + err.Error() + "；本轮停止，未继续签到", Exit: 9}
			}
			return
		}
		r.log(fmt.Sprintf("  已恢复原视口 %dx%d", vp.Original.Width, vp.Original.Height))
	}()
	id, pass, err := r.credentials()
	if err != nil {
		r.log("  账号密码未配置 —— 无法自动登录")
		return Result{Reason: "未配置学号密码（请在账号卡片填写保存）", Exit: 3}
	}
	ready, readyDiag := waitLoginReady(ctx, ops, 30*time.Second, 0)
	r.log(loginReadyLine("pre_form", ready, readyDiag))
	if ready != loginReadyForm {
		return r.finishLoginReady(ctx, ops, loginOK, ready)
	}
	r.log("  登录表单就绪")
	// The school renders 「记住密码」 only on its desktop layout (CSS viewport
	// wider than 980px), so the app's 430px window hides it. Widen for the login
	// only, and only on the trusted login page; the fields are located again on
	// the new layout instead of reusing anything from the narrow one.
	if d.widen != nil && cfg.RememberPassword {
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		trusted := false
		if ops.probe != nil {
			st, probeErr := ops.probe(ctx)
			if res, stopped := stopIfCanceled(ctx); stopped {
				return res
			}
			trusted = probeErr == nil && casLoginURL(st.URL)
		}
		if !trusted {
			r.log("  不在可信登录页 —— 跳过视口切换，未改动页面")
		} else {
			w, widenErr := d.widen(ctx)
			vp = w
			if widenErr != nil {
				r.log("  登录页切宽失败: " + safeDiagnosticError(widenErr) + "（「记住密码」可能因窄屏不渲染）")
			} else if w.Applied {
				r.log(fmt.Sprintf("  登录页已切到桌面宽度 %dpx（原 %dx%d），等待布局稳定",
					widenViewportWidth, w.Original.Width, w.Original.Height))
				if !waitFormStableAfterWiden(ctx, ops) {
					if res, stopped := stopIfCanceled(ctx); stopped {
						return res
					}
					r.log("  切宽后未见稳定的登录表单")
					return Result{}
				}
			} else {
				r.log(fmt.Sprintf("  登录页已是桌面宽度 %dpx，无需切换", w.Original.Width))
			}
		}
	}
	// landed records a redirect seen outside a submission window: the answer to
	// the previous attempt arrived after its window closed. That is success, not
	// a page we stopped trusting.
	landed := func() Result {
		*loginOK = true
		r.log("  自动登录成功 ✓（跳转在观察窗口关闭之后落地）")
		return Result{OK: true, Reason: "登录成功"}
	}
	// Tick the school's own 「记住密码」 box before anything is typed: the option is
	// independent of the credentials, so handling it first keeps a tick-driven
	// re-render from landing between the fill and the submit. A box that is missing
	// or does not take is recorded and the login goes on — it is a convenience, not
	// a credential, and only an untrusted page, a cancellation or a timeout may
	// stop the sign-in (viewport restore failure is the one stop this feature adds,
	// and it applies after the login, before business sign-in).
	switch {
	case !cfg.RememberPassword:
		r.log("  「记住密码」未启用（设置项关闭）")
	case d.remember == nil:
		r.log("  「记住密码」无法勾选（本驱动不支持）；程序未改动页面状态")
	default:
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		out := d.remember(ctx)
		// A cancel or the late line that arrived during the click wins.
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		r.log(rememberLine(out))
		// Whatever the box did, the login goes on: a box that is missing or did not
		// take is not a credential error and not a reason to give up today's
		// sign-in. It is recorded, and the option is never clicked twice.
		if out != rememberChecked && out != rememberAlreadyOn {
			r.log("  本次未确认启用「记住密码」：" + rememberNotEnabledNote(out))
		}
	}
	// fill credentials directly (React-compatible native setter)
	for _, f := range []struct{ sel, val string }{
		{"#userName", id},
		{"#password", pass},
	} {
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		verdict, diag := pageRead(ctx, &ops, "pre_fill", r.log)
		// The read may have outlived a cancel or the late line: that wins.
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		switch gateActionFor(verdict) {
		case gateLanded:
			return landed()
		case gateStop:
			return r.stopOnGate(ctx, ops, loginOK, verdict, diag)
		}
		if err := d.writeInput(ctx, f.sel, f.val); err != nil {
			if ctx.Err() != nil {
				return canceledResult(ctx)
			}
			return Result{Reason: "登录输入动作未确认完成，本轮停止", Exit: 3}
		}
	}
	r.log("  账号密码已填写 ✓")

	capMax := cfg.CapMaxTry
	if capMax <= 0 {
		capMax = 8
	}
	thr := cfg.ConfThr
	if thr <= 0 {
		thr = 0.55
	}
	for try := 1; try <= capMax && !*loginOK; try++ {
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		verdict, diag := pageRead(ctx, &ops, "pre_submit", r.log)
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		switch gateActionFor(verdict) {
		case gateLanded:
			return landed()
		case gateStop:
			return r.stopOnGate(ctx, ops, loginOK, verdict, diag)
		}

		du := d.extract(ctx)
		if du == "" || du == "WAIT" || strings.HasPrefix(du, "ERR:") {
			r.log(fmt.Sprintf("  [%d/%d] 验证码图提取失败 -> 刷新重试", try, capMax))
			if try >= capMax {
				break
			}
			if res, stopped := stopIfCanceled(ctx); stopped {
				return res
			}
			d.refresh(ctx)
			if err := ops.sleep(ctx, 600*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			continue
		}
		solved := d.solve(du)
		if !solved.OK || solved.MinScore < thr {
			det := solved.Reason
			if solved.OK {
				det = fmt.Sprintf("置信度低(%.3f)", solved.MinScore)
			}
			r.log(fmt.Sprintf("  [%d/%d] 识别不可信(%s) -> 换一张, 绝不瞎填", try, capMax, det))
			if try >= capMax {
				break
			}
			if res, stopped := stopIfCanceled(ctx); stopped {
				return res
			}
			d.refresh(ctx)
			if err := ops.sleep(ctx, 600*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			continue
		}
		r.log(fmt.Sprintf("  [%d/%d] 识别: %s = %s（置信度 %.3f/余量 %.3f）",
			try, capMax, solved.Expr, solved.Ans, solved.MinScore, solved.MinMargin))
		// Guard and mutate the CAS input in one page evaluation; no stale
		// mouse coordinates can spill onto a newly redirected business page.
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res // never type an answer into a run that is already stopping
		}
		if err := d.writeInput(ctx, "#captcha", solved.Ans); err != nil {
			// Distinguish "the write was refused because this is no longer the
			// login page" from "the field is missing on a login page we trust".
			fillVerdict, fillDiag := pageRead(ctx, &ops, "pre_captcha_fill", r.log)
			if res, stopped := stopIfCanceled(ctx); stopped {
				return res
			}
			switch gateActionFor(fillVerdict) {
			case gateLanded:
				return landed()
			case gateProceed:
				return Result{Reason: "登录验证码输入框无法写入，停止自动登录", Exit: 3}
			}
			return r.stopOnGate(ctx, ops, loginOK, fillVerdict, fillDiag)
		}
		if err := ops.sleep(ctx, 250*time.Millisecond); err != nil {
			return canceledResult(ctx)
		}
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		verdict, diag = pageRead(ctx, &ops, "pre_click", r.log)
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		switch gateActionFor(verdict) {
		case gateLanded:
			return landed()
		case gateStop:
			return r.stopOnGate(ctx, ops, loginOK, verdict, diag)
		}
		issue := d.terminal(ctx)
		// The terminal read is a page read: a cancel or the late line that fired
		// while it was in flight wins over the credential verdict it happened to
		// return. Nothing is clicked in a run that is already stopping.
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		if issue != AuthNone {
			return authResult(issue)
		}
		// Snapshot the login page's own error region as it is right BEFORE this
		// click, together with whether that read worked. Storing the filtered
		// evidence of the previous read would hide the very text this submission
		// has to be compared against; storing a failed read as an empty region
		// would let a stale 验证码错误 pass for the answer to this click.
		ops = ops.withSnapshot(ops.rawIssue(ctx))
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		if err := d.submit(ctx); err != nil {
			if ctx.Err() != nil {
				return canceledResult(ctx)
			}
			return Result{Reason: "登录点击结果未确认，本轮停止且不重复提交", Exit: 3}
		}
		// One submission is observed for its own budget; the submission count
		// (capMax), the run budget and the late line are unchanged and still apply.
		obsVerdict, obsDiag, obsErr := observeLoginSubmit(ctx, loginRedirectBudget, loginRedirectPoll, ops)
		if obsErr != nil {
			return canceledResult(ctx)
		}
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res // a cancel must not be overwritten by the verdict just read
		}
		r.log(loginDiagLine("submit_wait", obsVerdict, obsDiag))
		switch obsVerdict {
		case loginSubmitAccepted:
			*loginOK = true
			r.log(fmt.Sprintf("  自动登录成功 ✓（第 %d 次尝试，提交后 %.1fs 落定）", try, obsDiag.Elapsed.Seconds()))
		case loginSubmitCaptchaRejected:
			// The login page's own error region said the captcha was wrong about
			// THIS submission. That is the only evidence that may buy another
			// submission, and it stays bounded by capMax and by ctx.
			r.log(fmt.Sprintf("  [%d/%d] 登录页明确提示验证码错误 -> 换一张再试（不重复提交同一张图）", try, capMax))
			if try >= capMax {
				return loginSubmitFailure(obsVerdict, obsDiag)
			}
		case loginSubmitActionRequired:
			// The school's own two-factor page. The submission was received; the
			// next step is a human with a phone. Nothing here is captcha evidence,
			// so no refresh and no second submit.
			if res, handled := r.manualVerification(ctx, ops, loginOK); handled {
				return res
			}
			r.log("  学校要求二次验证（手机／密保）—— 本轮不重复提交，需人工完成")
			return loginSubmitFailure(obsVerdict, obsDiag)
		case loginSubmitPending:
			// The window closed with the login page still there and no answer
			// about this submission. Submitting again would be a blind submit and
			// a fresh captcha would only produce a second one, so the run stops
			// and reports the outcome as unknown.
			r.log(fmt.Sprintf("  [%d/%d] 提交后 %.1fs 内未取得可信结论（仍是登录页、页面未给出任何结论） -> 停止自动提交，不再换验证码重试",
				try, capMax, obsDiag.Elapsed.Seconds()))
			return loginSubmitFailure(obsVerdict, obsDiag)
		default:
			return loginSubmitFailure(obsVerdict, obsDiag)
		}
		if *loginOK {
			break
		}
		if res, stopped := stopIfCanceled(ctx); stopped {
			return res
		}
		d.refresh(ctx)
		if err := ops.sleep(ctx, 600*time.Millisecond); err != nil {
			return canceledResult(ctx)
		}
	}
	return Result{}
}

func (r *Runner) credentials() (string, string, error) {
	if r.Creds != nil {
		return r.Creds()
	}
	return "", "", fmt.Errorf("无凭据来源")
}

// ---------- helpers ----------

func pageText(ctx context.Context) string {
	var t string
	chromedp.Evaluate(`(function(){var t=document.body?document.body.innerText:'';return t.replace(/\s+/g,' ');})()`, &t).
		Do(exec(ctx))
	return t
}

func hostTitle(ctx context.Context) (host, title string) {
	chromedp.Evaluate(`(function(){return location.host + ' | ' + document.title})()`, &title).Do(exec(ctx))
	parts := strings.SplitN(title, " | ", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", title
}

func formReady(ctx context.Context) (bool, error) {
	var v int
	err := chromedp.Evaluate(`(function(){`+casPageGuardJS+`
 var u=document.querySelector('#userName'),p=document.querySelector('#password');
 function visible(e){if(!e||e.disabled)return false;var r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden'&&s.visibility!=='collapse'&&s.opacity!=='0';}
 return visible(u)&&visible(p)?1:0;
 })()`, &v).Do(exec(ctx))
	return v == 1, err
}

// setReactValue writes into an input the way React notices: the native
// value setter + an input event (from the original HandleSignCaptcha).
func setReactValue(ctx context.Context, sel, val string) bool {
	return setReactValueChecked(ctx, sel, val) == nil
}

// selCenter returns the element center via getBoundingClientRect.
func selCenter(ctx context.Context, sel string) (float64, float64) {
	var pt []float64
	chromedp.Evaluate(fmt.Sprintf(
		`(function(){var e=document.querySelector('%s');if(!e)return null;var r=e.getBoundingClientRect();if(!(r.width>0))return null;return [r.x+r.width/2, r.y+r.height/2]})()`, sel), &pt).Do(exec(ctx))
	if len(pt) == 2 {
		return pt[0], pt[1]
	}
	return -1, -1
}

func extractLoginCaptcha(ctx context.Context) string {
	var du string
	chromedp.Evaluate(fmt.Sprintf(edge.DataURLScreenshotJS, ""), &du).Do(exec(ctx))
	return du
}

// casVisibleFnJS defines visible() only. Callers decide their own return codes;
// sharing the definition keeps the visibility rules identical everywhere.
const casVisibleFnJS = `
function visible(e){if(!e||e.disabled)return false;var r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden'&&s.visibility!=='collapse'&&s.opacity!=='0';}
`
const casVisibleFormJS = `
var u=document.querySelector('#userName'),p=document.querySelector('#password');
` + casVisibleFnJS + `if(!visible(u)||!visible(p))return 0;
`
const refreshLoginCaptchaJS = `(function(){` + casPageGuardJS + casVisibleFormJS + `
var i=document.querySelector('img[src^="data:image"]');if(!visible(i))return 0;i.click();return 1;
})()`

func refreshLoginCaptcha(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	chromedp.Evaluate(refreshLoginCaptchaJS, nil).Do(exec(ctx))
}

// rememberMeDOMJS is the DOM half of the 「记住密码」 handling and the piece that
// actually runs against a page; rememberMeJS wraps it with the page-trust and
// visible-form gates. It is kept separate so the DOM behaviour can be exercised
// on a local page in the offline test, without loosening the gates.
//
//	0 = no such checkbox on this page (or the option is invisible to a person)
//	1 = ticked by this call
//	2 = already ticked
//	3 = present and unticked, but the click did not take (disabled, or the page
//	    put the tick back)
const rememberMeDOMJS = `
var c=document.getElementById('rememberMe');
if(!c){
  var ls=[].filter.call(document.querySelectorAll('label'),function(l){
    var t=(l.innerText||'').replace(/\s+/g,'');
    return t==='记住密码'||t==='七天之内记住密码';
  });
  if(ls.length)c=ls[0].querySelector('input[type="checkbox"]');
}
if(!c||c.type!=='checkbox')return 0;
// A custom-styled box usually hides the native input (opacity:0, or zero size)
// and paints the tick on the wrapper. A person can still see the option, so the
// wrapper's visibility counts; the click itself still goes to the real input, so
// the page's own handlers run exactly as they would for a human click.
var w=c.closest('label')||c.parentElement;
if(!visible(c)&&!(w&&visible(w)))return 0;
if(c.checked)return 2;
try{c.click();}catch(e){return 3;}
return c.checked?1:3;
`

// rememberMeJS ticks the school's own 「记住密码」 checkbox. The element is the
// form field the school's own bundle registers as rememberMe (its value is sent
// in the POST /lyuapServer/v1/tickets body alongside userName/passWord/vcodes),
// and its label is locale.remember_pass — 「记住密码」 or 「七天之内记住密码」.
// The box only exists while the server sets locale.isRememberPass to "1", so
// "absent" is a normal outcome, not an error.
//
// Nothing is written directly into the checkbox state: the click is a real click,
// so the page's change event and form value follow from it.
const rememberMeJS = `(function(){` + casPageGuardJS + casVisibleFormJS + rememberMeDOMJS + `})()`

// rememberNotEnabledNote says, for the operator, why this run cannot claim the
// option was enabled. It never turns that into a login failure: 「记住密码」 is an
// optional convenience, and a page without a usable control is a fact to record,
// not a reason to stop the sign-in (that reason only exists for credentials,
// two-factor and pages we cannot trust).
func rememberNotEnabledNote(out rememberOutcome) string {
	switch out {
	case rememberAbsent:
		return "页面上没有可操作的官方控件（可能服务端未下发该字段）"
	case rememberWriteFailed:
		return "点击后仍未勾上（可能被禁用或被页面回退）"
	default:
		return "结果无法确认"
	}
}

// checkRememberMe reports what the official checkbox did. A failed read or a
// failed click never aborts the login: the run still submits and still reports
// whichever page it lands on.
func checkRememberMe(ctx context.Context) rememberOutcome {
	var code int
	if err := chromedp.Evaluate(rememberMeJS, &code).Do(exec(ctx)); err != nil {
		return rememberWriteFailed
	}
	switch code {
	case 1:
		return rememberChecked
	case 2:
		return rememberAlreadyOn
	case 0:
		return rememberAbsent
	default:
		return rememberWriteFailed
	}
}

// verifyClickLoginJS is the verification-only click. It shares casPageGuardJS
// with the sign-in path (which keeps "0 = not the trusted CAS login page") but
// reports the remaining DOM outcomes separately, so a failed click can be
// explained instead of collapsing into one anonymous unknown.
//
//	0 = not the trusted CAS login page
//	1 = clicked
//	3 = credentials form missing or not visible
//	4 = login button not found
//	5 = login button not visible or disabled
//	6 = click threw
const verifyClickLoginJS = `(function(){` + casPageGuardJS + casVisibleFnJS + `
var u=document.querySelector('#userName'),p=document.querySelector('#password');
if(!visible(u)||!visible(p))return 3;
var b=[].filter.call(document.querySelectorAll('button'),function(x){return (x.innerText||'').replace(/\s+/g,'')==='登录'})[0];
if(!b)b=document.querySelector('button.ant-btn-primary');
if(!b)return 4;
if(!visible(b))return 5;
try{b.click();}catch(e){return 6;}
return 1;
})()`

func geoVerdict(txt string) string {
	switch {
	case strings.Contains(txt, "你已进入考勤登记范围"):
		return "已进入考勤登记范围 ✓"
	case strings.Contains(txt, "不在考勤范围"):
		return "页面显示「不在考勤范围」"
	case strings.Contains(txt, "非考勤时段"):
		return "非考勤时段，页面不显示范围提示（正常）"
	default:
		return "页面未含范围提示文字"
	}
}

func alreadySigned(txt string) (string, bool) {
	for _, k := range successKws {
		if strings.Contains(txt, k) {
			return k, true
		}
	}
	return "", false
}

func hitKeyword(txt string) string {
	for _, k := range successKws {
		if strings.Contains(txt, k) {
			return k
		}
	}
	return ""
}

// Headless pages have a document title, not the original PS window title.
// Validate the live hostname instead; a normal title such as 个人查寝 is valid.
func clickSafety(ctx context.Context, pageTxt string) string {
	var host string
	if err := chromedp.Evaluate(`location.hostname`, &host).Do(exec(ctx)); err != nil {
		return "读取页面地址失败，拒绝点击: " + err.Error()
	}
	return clickSafetyHost(host, pageTxt)
}

func clickSafetyHost(host, pageTxt string) string {
	if host != "xsfw.gzist.edu.cn" {
		return "当前页面不是学工系统: " + host
	}
	if !strings.Contains(pageTxt, "点击签到") {
		return "页面未见「点击签到」按钮"
	}
	if strings.Contains(pageTxt, "不在考勤范围") {
		return "页面显示「不在考勤范围」"
	}
	if s, _ := alreadySigned(pageTxt); s != "" {
		return "页面显示已签到（" + s + "）"
	}
	if strings.Contains(pageTxt, "非考勤时段") {
		return "页面显示「非考勤时段」"
	}
	return ""
}

// clickSign never substitutes configured coordinates for a missing control.
func (r *Runner) clickSign(ctx context.Context, _ store.Settings) error {
	return clickSignWith(ctx, evaluateAction, sendMouseEvent, sleepCtx)
}

// handleSignCaptcha answers the (rare) sign-dialog captcha — best effort,
// mirroring Invoke-HandleSignCaptcha.
func (r *Runner) handleSignCaptcha(ctx context.Context) bool {
	var m map[string]any
	chromedp.Evaluate(`(function(){
  var imgs=[].filter.call(document.querySelectorAll('img'),function(im){
    var r=im.getBoundingClientRect();
    if(!(r.width>=40&&r.width<=220&&r.height>=16&&r.height<=90)) return false;
    var s=im.src||'';
    return s.indexOf('data:image')===0 || /captcha|yzm|verify/i.test(s) || /captcha|yzm|verify/i.test(im.className||'');
  });
  if(!imgs.length) return null;
  var im=imgs[imgs.length-1];
  var inp=null, p=im.parentElement;
  while(p && !inp && p!==document.body){ inp=p.querySelector('input[type="text"],input:not([type])'); p=p.parentElement; }
  if(!inp) return null;
  var scope=im.closest('div[class*="modal"],div[class*="Modal"],div[class*="dialog"],div[class*="popup"],div[role="dialog"]') || document;
  var btn=null;
  var bs=[].filter.call(scope.querySelectorAll('button'),function(b){var t=(b.innerText||'').replace(/\s+/g,'');return t==='确定'||t==='确认'||t==='提交'});
  if(bs.length) btn=bs[bs.length-1];
  if(!btn) return null;
  var ri=im.getBoundingClientRect(), rn=inp.getBoundingClientRect(), rb=btn.getBoundingClientRect();
  return {ix:ri.x, iy:ri.y, nx:rn.x+rn.width/2, ny:rn.y+rn.height/2, bx:rb.x+rb.width/2, by:rb.y+rb.height/2};
})()`, &m).Do(exec(ctx))
	if m == nil {
		return false
	}
	ix, _ := m["ix"].(float64)
	iy, _ := m["iy"].(float64)
	var du string
	chromedp.Evaluate(fmt.Sprintf(`(function(){
  var imgs=[].filter.call(document.querySelectorAll('img'),function(im){var r=im.getBoundingClientRect();return Math.round(r.x)===%d&&Math.round(r.y)===%d;});
  var img=imgs[0]; if(!img||!img.naturalWidth) return null;
  var c=document.createElement('canvas'); var s=4;
  c.width=img.naturalWidth*s; c.height=img.naturalHeight*s;
  var ctx=c.getContext('2d'); ctx.imageSmoothingEnabled=false;
  ctx.drawImage(img,0,0,c.width,c.height);
  return c.toDataURL('image/png');})()`, int(ix), int(iy)), &du).Do(exec(ctx))
	if !strings.HasPrefix(du, "data:image") {
		return false
	}
	res := r.solveDataURL(du)
	if !res.OK {
		r.log("  弹窗验证码识别失败: " + res.Reason)
		return false
	}
	r.log("  弹窗验证码识别: " + res.Expr + " = " + res.Ans)
	bx, _ := m["bx"].(float64)
	by, _ := m["by"].(float64)
	nx, _ := m["nx"].(float64)
	ny, _ := m["ny"].(float64)
	if !setReactValueAt(ctx, nx, ny, res.Ans) {
		return false
	}
	if err := sleepCtx(ctx, 300*time.Millisecond); err != nil {
		return false
	}
	return dispatchMouseClick(ctx, bx, by) == nil
}

// setReactValueAt writes into the text input at the given page point.
func setReactValueAt(ctx context.Context, x, y float64, val string) bool {
	var ok int
	chromedp.Evaluate(fmt.Sprintf(`(function(){
  var e=document.elementFromPoint(%d,%d);var inp=null,p=e;
  while(p && !inp && p!==document.body){ inp=p.querySelector?p.querySelector('input[type="text"],input:not([type])'):null; p=p.parentElement; }
  if(!inp) return 0;
  var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
  setter.call(inp,%q); inp.dispatchEvent(new Event('input',{bubbles:true}));
  return 1;})()`, int(x), int(y), val), &ok).Do(exec(ctx))
	return ok == 1
}

func (r *Runner) solveDataURL(du string) captcha.Result {
	const prefix = "base64,"
	i := strings.Index(du, prefix)
	if i < 0 {
		return captcha.Result{Reason: "不是 base64 图片"}
	}
	raw, err := base64.StdEncoding.DecodeString(du[i+len(prefix):])
	if err != nil {
		return captcha.Result{Reason: "base64 解码失败"}
	}
	img, err := png.Decode(strings.NewReader(string(raw)))
	if err != nil {
		return captcha.Result{Reason: "png 解码失败: " + err.Error()}
	}
	return r.Solver.Solve(img)
}

func (r *Runner) saveShot(ctx context.Context, name string) {
	if r.ShotDir == "" {
		return
	}
	var buf []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&buf)); err != nil {
		return
	}
	os.MkdirAll(r.ShotDir, 0o755)
	p := filepath.Join(r.ShotDir, time.Now().Format("20060102-150405")+"-"+name+".png")
	os.WriteFile(p, buf, 0o644)
	r.log("  已存证: " + filepath.Base(p))
}

func clampText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func parseHM(s string, defH, defM int) [2]int {
	var h, m int
	if n, _ := fmt.Sscanf(s, "%d:%d", &h, &m); n == 2 {
		return [2]int{h, m}
	}
	return [2]int{defH, defM}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return ctx.Err()
	}
}
