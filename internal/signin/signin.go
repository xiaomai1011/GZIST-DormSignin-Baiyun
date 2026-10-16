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

	"github.com/chromedp/chromedp"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Result of one run. Exit mirrors the PowerShell exit codes so logs stay
// comparable: 0 ok / already signed, 3 need human, 5 config, 7 location,
// 8 time guard, 9 no browser.
type Result struct {
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
}

func (r *Runner) log(s string) {
	if r.Log != nil {
		r.Log(s)
	}
}

// success keywords — only these exact phrases count as signed.
var successKws = []string{"无需重复签到", "您已签到成功", "签到成功"}

func (r *Runner) Run(ctx context.Context, manual bool) Result {
	if ctx.Err() != nil {
		return canceledResult(ctx)
	}
	cfg := r.Cfg

	// ---- time guards (gate 0, before anything else) ----
	now := time.Now()
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

	// ---- launch headless Edge ----
	sess, err := edge.LaunchContext(ctx, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		r.log("!! " + err.Error())
		return Result{Reason: err.Error(), Exit: 9}
	}
	defer func() {
		if err := sess.Close(); err != nil {
			r.log("!! Edge 进程树清理失败（目录锁保留至程序退出）: " + err.Error())
		}
	}()
	r.log(fmt.Sprintf("  Edge 已启动: PID=%d, UserData=%s", sess.PID, sess.UserData))
	ctx, cancel := runContext(ctx, sess.Ctx, 8*time.Minute)
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

	// ---- navigate ----
	if err := chromedp.Navigate(cfg.URL).Do(exec(ctx)); err != nil {
		return Result{Reason: "打开页面失败: " + err.Error(), Exit: 9}
	}

	// ---- step 3: login-state probe (watch CAS redirect, 4s early call) ----
	loginOK := false
	deadline3 := time.Now().Add(30 * time.Second)
	var loginForm formVisibility
	for time.Now().Before(deadline3) {
		if err := sleepCtx(ctx, 300*time.Millisecond); err != nil {
			return canceledResult(ctx)
		}
		state, probeErr := probePage(ctx)
		if probeErr == nil && schoolURL(state.URL, "xsfw.gzist.edu.cn") {
			loginOK = true
			break
		}
		visible, formErr := formReady(ctx)
		if loginForm.stable(time.Now(), formErr == nil && visible) {
			break // The form has remained visible for four uninterrupted seconds.
		}
	}
	if !loginOK {
		if ok, _ := formReady(ctx); ok {
			r.log("  登录表单渲染后仍无跳转 -> 判定会话失效（提前结束宽限）")
		} else {
			r.log("  步骤3: 等待跳转超时")
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
	last, elapsed, waitErr := waitBusinessPage(ctx, pageWaitBudget, 500*time.Millisecond, probePage, repairPageRoute)
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
		return Result{OK: true, Reason: "今日已签到，无需再签"}
	}
	r.log(fmt.Sprintf("  步骤6: 页面就绪 ✓（耗时 %.1fs）", elapsed.Seconds()))
	if err := sleepCtx(ctx, 800*time.Millisecond); err != nil {
		return canceledResult(ctx)
	}
	txt := pageText(ctx)
	if hit := hitKeyword(txt); hit != "" {
		r.log(">>> " + hit)
		return Result{OK: true, Reason: "今日已签到，无需再签"}
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
				return Result{OK: true, Reason: "今日已签到，无需再签"}
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
		return Result{OK: true, Reason: "今日已签到，无需再签"}
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
	for time.Now().Before(deadline7) {
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return canceledResult(ctx)
		}
		t2 := pageText(ctx)
		if hit := hitKeyword(t2); hit != "" {
			signOK = true
			r.log(">>> " + hit)
			break
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
		if err := r.clickSign(ctx, cfg); err != nil {
			r.log("  点击失败: " + err.Error())
			continue
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
	return Result{OK: true, Reason: "签到成功"}
}

// ---------- auto login ----------

func (r *Runner) autoLogin(ctx context.Context, loginOK *bool) Result {
	cfg := r.Cfg
	id, pass, err := r.credentials()
	if err != nil {
		r.log("  账号密码未配置 —— 无法自动登录")
		return Result{Reason: "未配置学号密码（请在账号卡片填写保存）", Exit: 3}
	}
	// wait for the login form
	formOk := false
	dl := time.Now().Add(30 * time.Second)
	for time.Now().Before(dl) {
		if err := sleepCtx(ctx, 300*time.Millisecond); err != nil {
			return canceledResult(ctx)
		}
		if ok, _ := formReady(ctx); ok {
			formOk = true
			break
		}
	}
	if !formOk {
		r.log("  30s 内未见登录表单")
		return Result{}
	}
	r.log("  登录表单就绪")
	// fill credentials directly (React-compatible native setter)
	for _, f := range []struct{ sel, val string }{
		{"#userName", id},
		{"#password", pass},
	} {
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if ready, err := formReady(ctx); err != nil || !ready {
			return Result{Reason: "登录页面或表单不再可信，停止自动登录", Exit: 3}
		}
		if !setReactValue(ctx, f.sel, f.val) {
			r.log("  填写 " + f.sel + " 失败")
			return Result{}
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
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if ready, err := formReady(ctx); err != nil || !ready {
			return Result{Reason: "登录页面或表单不再可信，停止自动登录", Exit: 3}
		}
		if issue := terminalDOMAuth(ctx); issue != AuthNone {
			return authResult(issue)
		}

		du := extractLoginCaptcha(ctx)
		if du == "" || du == "WAIT" || strings.HasPrefix(du, "ERR:") {
			r.log(fmt.Sprintf("  [%d/%d] 验证码图提取失败 -> 刷新重试", try, capMax))
			if try >= capMax {
				break
			}
			refreshLoginCaptcha(ctx)
			if err := sleepCtx(ctx, 600*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			continue
		}
		res := r.solveDataURL(du)
		if !res.OK || res.MinScore < thr {
			det := res.Reason
			if res.OK {
				det = fmt.Sprintf("置信度低(%.3f)", res.MinScore)
			}
			r.log(fmt.Sprintf("  [%d/%d] 识别不可信(%s) -> 换一张, 绝不瞎填", try, capMax, det))
			if try >= capMax {
				break
			}
			refreshLoginCaptcha(ctx)
			if err := sleepCtx(ctx, 600*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			continue
		}
		r.log(fmt.Sprintf("  [%d/%d] 识别: %s = %s（置信度 %.3f/余量 %.3f）",
			try, capMax, res.Expr, res.Ans, res.MinScore, res.MinMargin))
		// Guard and mutate the CAS input in one page evaluation; no stale
		// mouse coordinates can spill onto a newly redirected business page.
		if !setReactValue(ctx, "#captcha", res.Ans) {
			return Result{Reason: "登录验证码表单不再可信，停止自动登录", Exit: 3}
		}
		if err := sleepCtx(ctx, 250*time.Millisecond); err != nil {
			return canceledResult(ctx)
		}
		if ctx.Err() != nil {
			return canceledResult(ctx)
		}
		if ready, err := formReady(ctx); err != nil || !ready {
			return Result{Reason: "登录页面或表单不再可信，停止自动登录", Exit: 3}
		}
		if issue := terminalDOMAuth(ctx); issue != AuthNone {
			return authResult(issue)
		}
		clickLoginButton(ctx)
		deadlineL := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadlineL) {
			if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
				return canceledResult(ctx)
			}
			if issue := terminalDOMAuth(ctx); issue != AuthNone {
				return authResult(issue)
			}
			state, probeErr := probePage(ctx)
			if probeErr == nil && schoolURL(state.URL, "xsfw.gzist.edu.cn") {
				*loginOK = true
				r.log(fmt.Sprintf("  自动登录成功 ✓（第 %d 次尝试）", try))
				break
			}
		}
		if *loginOK {
			break
		}
		r.log(fmt.Sprintf("  [%d/%d] 提交后未跳转(验证码可能不对)", try, capMax))
		if try >= capMax {
			break
		}
		refreshLoginCaptcha(ctx)
		if err := sleepCtx(ctx, 600*time.Millisecond); err != nil {
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
	var ok int
	expr := fmt.Sprintf(`(function(){`+casPageGuardJS+`
  var e=document.querySelector('%s');if(!e)return 0;
  var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
  setter.call(e,%q); e.dispatchEvent(new Event('input',{bubbles:true}));
  return 1;})()`, sel, val)
	chromedp.Evaluate(expr, &ok).Do(exec(ctx))
	return ok == 1
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

const clickLoginButtonJS = `(function(){` + casPageGuardJS + casVisibleFormJS + `
var b=[].filter.call(document.querySelectorAll('button'),function(x){return (x.innerText||'').replace(/\s+/g,'')==='登录'})[0];
if(!b)b=document.querySelector('button.ant-btn-primary');if(!visible(b))return 0;b.click();return 1;
})()`

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

func clickLoginButton(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	chromedp.Evaluate(clickLoginButtonJS, nil).Do(exec(ctx))
}

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

// clickSign clicks 「点击签到」: DOM feature first (a.erweima-bksy), then
// by text, then the configured page coordinate — the original's ladder.
func (r *Runner) clickSign(ctx context.Context, cfg store.Settings) error {
	var pt []float64
	chromedp.Evaluate(`(function(){
  var e=document.querySelector('a.erweima-bksy,.erweima-bksy');
  if(!e){var a=document.querySelectorAll('a,button,div,span');
    for(var i=0;i<a.length;i++){var t=(a[i].innerText||'').replace(/\s+/g,'');if(t==='点击签到'){e=a[i];break}}}
  if(!e)return null;
  var r=e.getBoundingClientRect();if(!(r.width>0))return null;
  return [r.x+r.width/2, r.y+r.height/2]})()`, &pt).Do(exec(ctx))
	if len(pt) != 2 {
		chromedp.Evaluate(fmt.Sprintf(
			`(function(){var e=document.elementFromPoint(%d,%d);if(!e)return null;var r=e.getBoundingClientRect();return [r.x+r.width/2, r.y+r.height/2]})()`,
			cfg.ClickSignX, cfg.ClickSignY), &pt).Do(exec(ctx))
	}
	if len(pt) != 2 {
		return fmt.Errorf("找不到签到按钮")
	}
	dispatchMouseClick(ctx, pt[0], pt[1])
	return nil
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
	sleepCtx(ctx, 300*time.Millisecond)
	dispatchMouseClick(ctx, bx, by)
	return true
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
