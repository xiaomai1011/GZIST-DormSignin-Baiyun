// Edge/CAS application entry for the 2.0.20 stability release.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/art"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

const appTitle = "GZIST DormSignin"

// Identifies this local repair even before a release tag is created.
const repairBuild = "fresh-auth-auto-show-r1"

// newHostManager builds the resident manager. It is a variable so the
// application tests can drive the real coordination code without launching Edge.
var newHostManager = func() *browserhost.Manager {
	return browserhost.NewManager(false)
}

func buildIdentity() string {
	parts := []string{"修复构建: " + repairBuild}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
				parts = append(parts, setting.Key+"="+setting.Value)
			}
		}
	}
	return strings.Join(parts, " ")
}

type app struct {
	loginController
	updateController
	log    *applog.Log
	store  *store.Store
	m      *model
	solver *captcha.Solver

	// hosts owns the resident browsers: one per account, started by the first
	// resident run and kept until exit or an account switch.
	hosts *browserhost.Manager

	// stateMu guards residentBroken and pendingSwitch: runs finish on their own
	// goroutine while a settings save can land at the same moment.
	stateMu sync.Mutex
	// residentBroken records a resident-browser cleanup that could not be
	// confirmed. While it is set no run may start: a browser that may still be
	// alive must not have a second one started next to it.
	residentBroken error
	// pendingSwitch is the account whose resident browser could not be closed
	// while a task was running; it is applied when that task ends.
	pendingSwitch *store.Settings

	win  *mygo.Window
	tray *mygo.Tray
	menu *mygo.Menu

	ledger  *scheduleLedger
	running atomic.Bool
	breathe bool // tray star breathes while monitoring (idle & armed)
}

func main() {
	selftest := flag.Bool("selftest", false, "run a read-only self check and exit")
	browserTest := flag.Bool("browser-selftest", false, "test local Edge lifecycle only; never visit the sign-in site")
	residentTest := flag.Bool("resident-selftest", false, "test the resident host lifecycle with a throwaway profile; never visit the sign-in site")
	sessionProbe := flag.Bool("session-probe", false, "one navigation to the fixed school CAS entry; report whether the saved session still recovers; never fills a form, never retries")
	probeProfile := flag.String("session-probe-profile", "", "absolute profile base directory for -session-probe (default: the configured userData, resolved by the program directory); the account segment is appended exactly once")
	probeDryRun := flag.Bool("session-probe-dry-run", false, "with -session-probe: resolve and check the profile, print it, then exit without launching a browser or taking the lock")
	flag.Parse()
	// -session-probe-profile on its own is a mistake, not a no-op: acting on it
	// silently would go on to start the tray and the scheduler, which can sign in
	// for real. The check is by presence, so an empty value cannot slip through.
	profileFlagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "session-probe-profile" {
			profileFlagSet = true
		}
	})
	mode, err := resolveProcessMode(*sessionProbe, *probeDryRun, profileFlagSet)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch mode {
	case modeProbeDryRun:
		os.Exit(runSessionProbe(*probeProfile, true))
	case modeProbe:
		os.Exit(runSessionProbe(*probeProfile, false))
	}
	if *browserTest {
		if err := runBrowserSelftest(); err != nil {
			os.Exit(1)
		}
		return
	}
	if *residentTest {
		if err := runResidentSelftest(); err != nil {
			os.Exit(1)
		}
		return
	}
	if *selftest {
		runSelftest()
		return
	}

	if !mygo.App.RequestSingleInstanceLock() {
		return
	}
	a := &app{}
	mygo.App.OnSecondInstance(func([]string, string) { a.showWindow() })
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.WhenReady(a.ready)
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func (a *app) ready() {
	dataDir, _ := mygo.App.Path(mygo.PathUserData)
	logDir, _ := mygo.App.Path(mygo.PathLogs)
	a.log = applog.New(logDir)
	a.store = store.New(dataDir)
	var ledgerErr error
	a.ledger, ledgerErr = openScheduleLedger(filepath.Join(dataDir, "schedule-state.json"))
	if ledgerErr != nil {
		a.log.Add("签到状态读取失败（无法恢复此前成功记录）：" + ledgerErr.Error())
	}
	a.log.Printf("GZIST DormSignin v%s 启动 (%s/%s)", mygo.App.Version(), runtime.GOOS, runtime.GOARCH)
	a.log.Add(buildIdentity())
	if exe, err := os.Executable(); err == nil {
		a.log.Add("运行文件: " + exe)
	}
	if profile, err := edge.ProfilePath(a.store.Load()); err == nil {
		a.log.Add("Edge 专用目录基路径（签到使用 accounts-v1 下的账号隔离目录）: " + profile)
	}

	if msg := a.importLegacy(); msg != "" {
		a.log.Add(msg)
	}
	solver, err := captcha.New(filepath.Join(dataDir, "templates-g.cache"))
	if err != nil {
		a.log.Add("验证码模板初始化失败: " + err.Error())
	}
	a.solver = solver

	cfg := a.store.Load()
	a.hosts = newHostManager()
	id, pass, _ := a.store.Credentials()
	a.m = &model{
		cfg:        cfg,
		studentID:  id,
		id:         id,
		pass:       pass,
		storedID:   id,
		storedPass: pass,
		hasCreds:   id != "" && pass != "",
		autostart:  mygo.App.OpenAtLogin(),
		version:    mygo.App.Version(),
	}
	a.m.act = actions{
		Verify:       a.verifyLogin,
		CancelVerify: a.cancelLoginVerification,
		Save:         a.save,
		Sign:         a.signNow,
		SetHoliday:   a.setHoliday,
		SetAutoSign:  a.setAutoSign,
		SetAutostart: a.setAutostart,
		SetResident:  a.setResident,
		ShowBrowser:  func() { a.controlResidentWindow(true) },
		HideBrowser:  func() { a.controlResidentWindow(false) },
		OpenLogs:     func() { mygo.Shell.ShowItemInFolder(a.log.Path()) },
	}
	a.m.logs = a.log.Lines()

	a.makeTray()
	a.syncTray() // set the real state right away: star breathing, not the blank icon
	go a.breathingLoop()
	go a.scheduleLoop()
	a.initUpdates(dataDir)

	if id == "" || pass == "" {
		a.showWindow() // first run: ask for credentials
	} else if !mygo.App.WasOpenedAtLogin() {
		a.showWindow()
	}
}

// Claims are durable before jitter; success is independent of attempted slots.
func (a *app) scheduleLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		a.post(func() { a.syncTray() })
		cfg := a.store.Load()
		id, pass, _ := a.store.Credentials()
		ticket, err := a.claimScheduled(time.Now(), cfg, accountKey(id), id != "" && pass != "")
		if err != nil {
			a.log.Add("定时槽位保存失败，本槽位不执行：" + err.Error())
			continue
		}
		if ticket == nil {
			continue
		}
		time.Sleep(time.Duration(rand.Intn(90)) * time.Second)
		a.runAttempt(context.Background(), false, ticket)
	}
}

func (a *app) runOnce(ctx context.Context, manual bool) signin.Result {
	return a.runAttempt(ctx, manual, nil)
}

func (a *app) runAttempt(ctx context.Context, manual bool, ticket *scheduleTicket) signin.Result {
	if err := a.residentStop(); err != nil {
		res := signin.Result{Reason: "常驻浏览器清理未确认，本次不执行：" + err.Error(), Exit: 9}
		a.log.Add(res.Reason)
		a.post(func() { a.m.setResult(false, false, res.Reason) })
		return res
	}
	if !a.acquireOperation(ticket != nil) {
		a.post(func() { a.m.notice = "签到或登录验证正在运行／即将开始，请稍后。" })
		return signin.Result{Neutral: true, Reason: "签到或登录验证正在运行／即将开始，已忽略重复请求"}
	}
	defer func() {
		a.running.Store(false)
		a.applyPendingSwitch()
		a.post(func() { a.syncTray() })
	}()
	cfg := a.store.Load()
	id, pass, credErr := a.store.Credentials()
	started := time.Now()
	account, date := accountKey(id), started.Format("2006-01-02")
	if !manual && !a.ledger.eligible(ticket, started, cfg, account, credErr == nil && id != "" && pass != "", false) {
		return signin.Result{Neutral: true, Reason: "定时条件已变化，已跳过本槽位"}
	}
	var setupErr error
	cfg, setupErr = accountSettings(cfg, id, pass, credErr)
	if setupErr != nil {
		res := signin.Result{Reason: setupErr.Error(), Exit: 9}
		a.log.Add("签到启动前检查失败：" + res.Reason)
		a.post(func() {
			a.syncTray()
			if a.m.statusAccount == account && a.m.statusDate == date {
				a.m.setResult(res.OK, res.Neutral, res.Reason)
			}
		})
		return res
	}
	a.post(func() { a.syncTray() })
	r := &signin.Runner{
		Cfg:     cfg,
		Log:     a.log.Add,
		Notify:  a.notify,
		ShotDir: filepath.Join(baseDir(), "shots"),
		Solver:  a.solver,
		Hosts:   a.hosts,
		// Freeze the attempted identity: a settings edit during login must not
		// attribute the result to a different account.
		Creds: func() (string, string, error) { return id, pass, credErr },
	}
	a.log.Add(fmt.Sprintf("======== 签到开始（%s，触发=%s）========", nowHM(), map[bool]string{true: "手动", false: "定时"}[manual]))
	res := r.Run(ctx, manual)
	mark := "OK"
	if !res.OK {
		mark = fmt.Sprintf("未完成(exit %d)", res.Exit)
	}
	a.log.Add(fmt.Sprintf("======== 结束：%s | %s ========", mark, res.Reason))
	if res.OK {
		if err := a.ledger.confirm(account, date); err != nil {
			a.log.Add("今日成功状态保存失败（本次运行仍停止自动重试，重启后可能无法恢复）：" + err.Error())
		}
	}
	a.post(func() {
		a.syncTray()
		// A queued completion from yesterday or another account must not
		// overwrite the current account's notice or credential warning.
		if a.m.statusAccount == account && a.m.statusDate == date {
			a.m.setResult(res.OK, res.Neutral, res.Reason)
			currentID, currentPass, err := a.store.Credentials()
			if err == nil {
				a.m.applySignInAuthentication(res, credentialIdentity(id, pass), credentialIdentity(currentID, currentPass))
			}
		}
	})
	return res
}

func (a *app) signNow() {
	if a.running.Load() {
		a.m.notice = "签到或登录验证正在运行…"
		return
	}
	id, pass, _ := a.store.Credentials()
	if id == "" || pass == "" {
		a.m.notice = "请先在账号卡片填写学号和密码"
		a.post(func() { a.syncTray() })
		return
	}
	go a.runOnce(context.Background(), true)
}

func (a *app) setAutoSign(on bool) {
	cfg := a.store.Load()
	cfg.Holiday = !on
	if err := a.store.Save(cfg); err != nil {
		a.m.notice = "保存失败：" + err.Error()
	} else {
		a.m.cfg = a.store.Load()
		a.m.notice = ""
		a.log.Add("自动签到：" + map[bool]string{true: "运行中", false: "已停用（假期模式）"}[on])
	}
	a.m.autostart = mygo.App.OpenAtLogin()
	a.syncTray()
	a.post(func() {})
}

func (a *app) setHoliday(on bool) {
	cfg := a.store.Load()
	cfg.Holiday = on
	err := a.store.Save(cfg)
	if err != nil {
		a.m.notice = "保存失败：" + err.Error()
	} else {
		a.m.cfg = cfg
		a.m.notice = ""
		if on {
			a.log.Add("已开启假期模式：自动签到停用（回校后记得关闭）")
		} else {
			a.log.Add("已关闭假期模式：自动签到恢复")
		}
	}
	a.m.cfg = a.store.Load()
	a.syncTray()
	a.post(func() {})
}

func (a *app) setVisibleBrowser(on bool) {
	cfg := a.store.Load()
	cfg.VisibleBrowser = on
	if err := a.store.Save(cfg); err != nil {
		a.m.notice = "保存失败：" + err.Error()
	} else {
		a.m.neutral = true
		if on {
			// The warning is part of the setting, not a footnote: a visible run
			// still starts by itself at the scheduled time, and with nobody at the
			// keyboard it simply waits out the run budget and reports "not finished".
			a.m.notice = "可见浏览器已开启：学校要求二次验证时会弹出窗口，由你完成手机／密保验证，程序只读等待后继续。" +
				"注意：可见模式不等于暂停自动签到，定时任务同样会弹出浏览器；没有人在场时只会等到本轮预算结束。"
			a.log.Add("浏览器模式：可见（二次验证需人工完成；不影响自动签到）")
		} else {
			a.m.notice = "浏览器模式已改回隐藏：独立隐藏模式遇到二次验证只提醒；常驻模式进入人工验证阶段仍会显示对应窗口，由本人完成验证。"
			a.log.Add("浏览器模式：隐藏")
		}
	}
	a.m.cfg = a.store.Load()
	a.syncTray()
	a.post(func() {})
}

func (a *app) setRememberPassword(on bool) {
	cfg := a.store.Load()
	cfg.RememberPassword = on
	if err := a.store.Save(cfg); err != nil {
		a.m.notice = "保存失败：" + err.Error()
	} else {
		a.m.neutral = true
		if on {
			// No promise here: the checkbox is sent to the school, and whether the
			// server reduces two-factor checks for a remembered login is not
			// something this program can guarantee.
			a.m.notice = "已开启：登录时会勾选学校页面上的「记住密码」。这只是学校提供的官方选项，服务端是否因此减少二次验证尚未验证；仍需以每次运行的日志为准。"
			a.log.Add("记住密码：登录时勾选学校官方选项（效果由服务端决定，未经验证）")
		} else {
			// The program never clears the box either: "off" means "do not touch
			// the page", so a server-rendered pre-ticked box still submits as it is.
			a.m.notice = "已关闭自动勾选；学校页面原有选中状态不由程序修改。"
			a.log.Add("记住密码：不修改页面原有选中状态")
		}
	}
	a.m.cfg = a.store.Load()
	a.syncTray()
	a.post(func() {})
}

func (a *app) setAutostart(on bool) {
	if err := mygo.App.SetOpenAtLogin(on); err != nil {
		a.m.notice = "开机自启设置失败：" + err.Error()
	} else {
		a.log.Add("开机自启：" + map[bool]string{true: "已开启", false: "已关闭"}[on])
	}
	a.m.autostart = mygo.App.OpenAtLogin()
	a.syncTray()
	a.post(func() {})
}

// residentStop reports a cleanup that could not be confirmed. Every run checks
// it first: starting a second browser next to one that may still be alive is
// exactly what the resident protocol forbids.
func (a *app) residentStop() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	return a.residentBroken
}

func (a *app) blockRuns(err error) {
	a.stateMu.Lock()
	a.residentBroken = err
	a.stateMu.Unlock()
}

// applyPendingSwitch retries an account switch that was refused while a task
// held the lease. It runs when that task has ended.
func (a *app) applyPendingSwitch() {
	a.stateMu.Lock()
	pending := a.pendingSwitch
	a.stateMu.Unlock()
	if pending == nil || a.hosts == nil {
		return
	}
	err := a.hosts.Switch(*pending)
	switch {
	case err == nil:
		a.stateMu.Lock()
		if a.pendingSwitch == pending {
			a.pendingSwitch = nil
		}
		a.stateMu.Unlock()
		a.log.Add("任务已结束：常驻浏览器已切换到新账号")
	case errors.Is(err, browserhost.ErrSwitchBusy):
		// Another queued run still holds it; the next completion tries again.
	default:
		a.blockRuns(err)
		a.log.Add("任务结束后切换常驻浏览器失败，后续任务已停止：" + err.Error())
		a.post(func() {
			a.m.setResult(false, false, "常驻浏览器切换失败，后续任务已停止："+err.Error())
		})
	}
}

// setResident turns the resident mode on or off and reports the outcome in the
// tray. Persistence and host lifecycle live in applyResidentSetting so the
// account and mode cycles can be tested without the UI.
func (a *app) setResident(on bool) {
	if a.m.windowBusy {
		a.m.windowMessage = "窗口操作正在进行，请稍后切换常驻浏览器。"
		return
	}
	if a.running.Load() {
		a.m.notice = "签到或登录验证正在运行，等本次结束后再切换常驻浏览器。"
		a.syncTray()
		a.post(func() {})
		return
	}
	if on {
		if err := a.residentStop(); err != nil {
			a.m.notice = "上次常驻浏览器清理未确认，不能重新开启；请重启程序后再试。"
			a.syncTray()
			a.post(func() {})
			return
		}
	}
	err := a.applyResidentSetting(on)
	switch {
	case err != nil:
		a.blockRuns(err)
		a.m.notice = "常驻浏览器设置保存失败或宿主清理未确认，后续任务已停止：" + err.Error() + "。请重启程序后重试。"
		a.log.Add("切换常驻浏览器失败，后续任务已停止：" + err.Error())
	case on:
		a.m.neutral = true
		a.m.notice = "常驻浏览器已开启：任务之间复用同一个 Edge 进程（首次任务按需启动，不会预先打开登录页）。宿主不可用、身份不符或清理未确认时，本次任务直接停止，不会改用独立浏览器。"
		a.log.Add("常驻浏览器：已开启（任务间复用；失败即停止本次任务）")
	default:
		a.m.neutral = true
		a.m.notice = "常驻浏览器已关闭：后续任务使用独立浏览器（仅本次运行）。"
		a.log.Add("常驻浏览器：已关闭，宿主已清理")
	}
	a.syncTray()
	a.post(func() {})
}

// applyResidentSetting persists the mode and reconciles the hosts. Enabling only
// swaps in a fresh manager: no browser starts until the next task asks for one.
// Disabling closes every host and refuses to report success when a close cannot
// be confirmed.
func (a *app) applyResidentSetting(on bool) error {
	cfg := a.store.Load()
	cfg.ResidentBrowser = on
	if err := a.store.Save(cfg); err != nil {
		return err
	}
	if a.m != nil {
		a.m.cfg = a.store.Load()
	}
	if on {
		// A manager that was closed when the mode was switched off cannot start
		// anything; a fresh one has no hosts and no stale close result.
		a.hosts = newHostManager()
		return nil
	}
	if a.hosts == nil {
		return nil
	}
	return a.hosts.CloseAll()
}

// save writes credentials and merges UI-visible settings.
func (a *app) save(id, pass string) {
	if a.m.saving || a.m.windowBusy {
		return
	}
	if id == "" {
		a.m.notice = "学号不能为空"
		return
	}
	if pass == "" && !a.m.hasCreds {
		a.m.notice = "第一次设置请同时填写密码"
		return
	}
	a.m.saving = true
	a.m.notice = "保存中…"
	a.post(func() {})
	go func() {
		if pass == "" {
			a.store.DeleteCredentials()
			a.log.Add("账号已清除")
		} else {
			if insecure, err := a.store.SetCredentials(id, pass); err != nil {
				a.post(func() { a.m.saving = false; a.m.notice = "保存失败：" + err.Error() })
				return
			} else if insecure {
				a.log.Add("系统凭据管理器不可用，密码以明文（权限 0600）保存在本机")
			}
			a.log.Printf("账号已保存（学号=%s）", id)
		}
		a.reconcileResidentAfterCredentialChange(a.store.Load(), id, pass)
		a.post(func() {
			a.m.finishCredentialSave(id, pass)
			a.syncTray()
		})
	}()
}

// reconcileResidentAfterCredentialChange keeps the resident hosts in step with
// the account that was just saved. Clearing the account closes every host and
// installs a fresh manager, so saving a new account afterwards does not run
// into a manager that was permanently closed.
func (a *app) reconcileResidentAfterCredentialChange(current store.Settings, id, pass string) {
	if a.hosts == nil || !current.ResidentBrowser {
		return
	}
	if pass == "" {
		if err := a.hosts.CloseAll(); err != nil {
			a.blockRuns(err)
			a.log.Add("账号已清除，但常驻浏览器清理未确认，后续任务已停止：" + err.Error())
			return
		}
		a.hosts = newHostManager()
		a.stateMu.Lock()
		a.pendingSwitch = nil
		a.stateMu.Unlock()
		a.log.Add("账号已清除：常驻浏览器已关闭")
		return
	}
	cfg, cfgErr := accountSettings(current, id, pass, nil)
	if cfgErr != nil {
		a.blockRuns(cfgErr)
		a.log.Add("账号切换时无法解析新账号配置，后续任务已停止：" + cfgErr.Error())
		return
	}
	if err := a.hosts.Switch(cfg); err != nil {
		if errors.Is(err, browserhost.ErrSwitchBusy) {
			pending := cfg
			a.stateMu.Lock()
			a.pendingSwitch = &pending
			a.stateMu.Unlock()
			a.log.Add("账号已保存；常驻浏览器仍被任务占用，将在任务结束后切换")
			return
		}
		a.blockRuns(err)
		a.log.Add("账号切换时关闭旧常驻浏览器失败，后续任务已停止：" + err.Error())
		return
	}
	a.stateMu.Lock()
	a.pendingSwitch = nil
	a.stateMu.Unlock()
	a.log.Add("账号已保存：常驻浏览器已切换到新账号")
}

func (a *app) importLegacy() string {
	return a.store.ImportLegacy()
}

// quitApplication closes the resident browsers before the process leaves: a
// host removes its state file only on a clean close, and the next start must
// not find a state file pointing at a dead port.
func (a *app) quitApplication() {
	if a.hosts != nil {
		if err := a.hosts.CloseAll(); err != nil {
			a.log.Add("退出时关闭常驻浏览器失败：" + err.Error())
		}
	}
	mygo.App.Quit()
}

func (a *app) notify(title, body string) {
	if !mygo.NotificationsSupported() {
		return
	}
	mygo.RunOnMain(func() {
		n := mygo.NewNotification(mygo.NotificationOptions{Title: title, Body: body})
		n.OnClick(a.showWindow)
		if err := n.Show(); err != nil {
			a.log.Printf("通知发送失败: %v", err)
		}
	})
}

func (a *app) post(fn func()) {
	mygo.RunOnMain(func() {
		fn()
		if a.win != nil && !a.win.IsDestroyed() {
			a.win.Invalidate()
		}
	})
}

func (a *app) showWindow() {
	if a.win != nil && !a.win.IsDestroyed() {
		a.win.Show()
		a.win.Focus()
		mygo.App.Focus()
		return
	}
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:     appTitle,
		Width:     440,
		Height:    760,
		MinWidth:  380,
		MinHeight: 520,
		StateKey:  "main",
		Content:   ui.View(a.m.view),
	})
	mygo.App.Focus()
}

func (a *app) makeTray() {
	a.menu = mygo.NewMenu([]*mygo.MenuItem{
		{ID: "status", Label: "待命中", Disabled: true},
		mygo.Separator(),
		{ID: "sign", Label: "立即签到", Click: func(*mygo.MenuItem, *mygo.Window) { a.signNow() }},
		{Label: "打开主窗口", Click: func(*mygo.MenuItem, *mygo.Window) { a.showWindow() }},
		{Label: "检查程序更新", Click: func(*mygo.MenuItem, *mygo.Window) { a.showWindow(); a.checkProgramUpdate(true) }},
		mygo.Separator(),
		{ID: "autostart", Label: "开机自启", Type: mygo.MenuItemCheckbox, Checked: a.m.autostart,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setAutostart(it.Checked) }},
		{ID: "holiday", Label: "假期模式（停用签到）", Type: mygo.MenuItemCheckbox, Checked: a.m.cfg.Holiday,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setHoliday(it.Checked) }},
		{ID: "visible", Label: "可见浏览器（二次验证由人完成）", Type: mygo.MenuItemCheckbox, Checked: a.m.cfg.VisibleBrowser,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setVisibleBrowser(it.Checked) }},
		{ID: "remember", Label: "勾选学校「记住密码」", Type: mygo.MenuItemCheckbox, Checked: a.m.cfg.RememberPassword,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setRememberPassword(it.Checked) }},
		{ID: "resident", Label: "常驻浏览器（任务间复用）", Type: mygo.MenuItemCheckbox, Checked: a.m.cfg.ResidentBrowser,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setResident(it.Checked) }},
		mygo.Separator(),
		{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { a.quitApplication() }},
	})
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           art.TrayIcon(art.TrayOff, runtime.GOOS == "darwin"),
		IconIsTemplate: runtime.GOOS == "darwin",
		ToolTip:        appTitle + " · 白云校区",
		Menu:           a.menu,
	})
	if err != nil {
		a.log.Printf("无法创建托盘图标: %v", err)
		return
	}
	a.tray = tray
	if runtime.GOOS == "windows" {
		tray.OnClick(a.showWindow)
	}
}

// syncTray mirrors the model into the tray (main thread). While armed
// and idle the star breathes (bright ⇄ dark gold every 1.5s) so the user
// can tell the program is alive — it covers ~99% of the time.
func (a *app) syncTray() {
	id, pass, _ := a.store.Credentials()
	now := time.Now()
	account := accountKey(id)
	a.m.cfg = a.store.Load()
	a.m.syncSuccess(account, now, pass != "" && a.ledger.succeeded(account, now))
	if a.tray == nil {
		return
	}
	mac := runtime.GOOS == "darwin"
	label := "未配置账号 —— 请打开主窗口填写"
	state := art.TrayOff
	a.breathe = false
	switch {
	case a.operationBlocked.Load():
		label, state = "浏览器清理异常，请重启程序", art.TrayOff
	case a.m.verifying:
		label, state = "登录验证中（不签到）…", art.TrayBusy
	case a.m.authIssue == signin.AuthCredentialsRejected || a.m.authIssue == signin.AuthLocked:
		label, state = "账号认证异常，请打开窗口处理", art.TrayOff
	case a.m.cfg.Holiday:
		label = "假期模式（已停用）"
	case id == "" || pass == "":
		label = "未配置账号"
	case a.running.Load():
		label, state = "签到进行中…", art.TrayBusy
	case a.m.resultOK:
		label, state = "今日已签到 ✓", art.TrayOn
	default:
		label = "监测中 · 下次签到 " + nextSlot(a.m.cfg.Times)
		state = art.TrayOn
		a.breathe = true
	}
	a.menu.ItemByID("status").SetLabel(label)
	a.menu.ItemByID("sign").SetEnabled(!a.running.Load() && !a.operationBlocked.Load() && !a.m.cfg.Holiday)
	a.menu.ItemByID("holiday").SetChecked(a.m.cfg.Holiday)
	a.menu.ItemByID("visible").SetChecked(a.m.cfg.VisibleBrowser)
	a.menu.ItemByID("remember").SetChecked(a.m.cfg.RememberPassword)
	a.menu.ItemByID("resident").SetChecked(a.m.cfg.ResidentBrowser)
	a.menu.ItemByID("resident").SetEnabled(!a.running.Load())
	a.tray.SetToolTip(appTitle + " · 白云校区 · " + label)
	if !a.breathe {
		a.tray.SetIcon(art.TrayIcon(state, mac), mac)
	}
}

// breathingLoop alternates the idle star between bright and dark gold.
func (a *app) breathingLoop() {
	tk := time.NewTicker(1500 * time.Millisecond)
	defer tk.Stop()
	bright := true
	for range tk.C {
		mygo.RunOnMain(func() {
			if a.tray == nil || !a.breathe || a.running.Load() {
				return
			}
			bright = !bright
			s := art.TrayIdle
			if bright {
				s = art.TrayOn
			}
			mac := runtime.GOOS == "darwin"
			a.tray.SetIcon(art.TrayIcon(s, mac), mac)
		})
	}
}

func nextSlot(times []string) string {
	now := time.Now().Format("15:04")
	for _, t := range times {
		if t >= now {
			return t
		}
	}
	return times[0] + "（明天）"
}

func nowHM() string { return time.Now().Format("15:04:05") }

// baseDir is the exe directory (shots and the legacy config live there).
func baseDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

// runSelftest is a read-only check: settings, credentials presence,
// Edge path, captcha templates.
func runSelftest() {
	fmt.Println("== GZIST DormSignin 自检（只读）==")
	base, err := os.UserConfigDir()
	dir := "."
	if err == nil {
		dir = filepath.Join(base, "GZIST DormSignin")
	}
	fmt.Println("数据目录:", dir)
	st := store.New(dir)
	cfg := st.Load()
	fmt.Printf("url: %s\n", cfg.URL)
	fmt.Printf("定位: %.6f, %.6f ±%.0fm (启用=%v 必须通过=%v)\n", cfg.Lat, cfg.Lon, cfg.AccM, cfg.GeoOn, cfg.GeoMust)
	fmt.Printf("考勤窗口: %s  晚归线: %s  触发: %s\n", cfg.AttWindow, cfg.LateLine, strings.Join(cfg.Times, "/"))
	fmt.Printf("假期模式: %v\n", cfg.Holiday)
	id, pass, _ := st.Credentials()
	fmt.Printf("学号: %s  密码: %s\n", present(id), present(pass))
	if _, err := os.Stat(cfg.EdgePath); err != nil {
		fmt.Println("Edge: 未找到", cfg.EdgePath)
	} else {
		fmt.Println("Edge: OK")
	}
	s, err := captcha.New(filepath.Join(dir, "templates-g.cache"))
	if err != nil {
		fmt.Println("验证码模板: 失败,", err)
		return
	}
	fmt.Println("验证码模板: OK,", s.Count(), "条")
	fmt.Println("== 自检完成 ==")
}

func present(s string) string {
	if s == "" {
		return "未设置"
	}
	return "已设置（长度 " + fmt.Sprint(len(s)) + "）"
}

// residentWindowClient deliberately exposes no navigation, lease or launch API.
// A window command must work while sign-in is waiting for user verification.
type residentWindowClient interface {
	SetWindowVisible(context.Context, bool) error
}

type residentWindowRequest struct {
	account string
	cfg     store.Settings
	visible bool
}

// beginResidentWindow runs on the UI thread. Only the last saved identity is
// used; editing either input does not change the target or persist anything.
func (m *model) beginResidentWindow(visible bool) (residentWindowRequest, bool) {
	if m.windowBusy || m.saving {
		m.windowMessage = "账号保存或窗口操作正在进行，请稍后再试。"
		return residentWindowRequest{}, false
	}
	if !m.cfg.ResidentBrowser {
		m.windowMessage = "请先开启常驻浏览器；此按钮不会启动浏览器。"
		return residentWindowRequest{}, false
	}
	if !m.hasCreds || strings.TrimSpace(m.storedID) == "" || strings.TrimSpace(m.cfg.UserData) == "" {
		m.windowMessage = "请先保存账号；此按钮不会保存当前输入。"
		return residentWindowRequest{}, false
	}
	cfg := m.cfg
	cfg.UserData = filepath.Join(cfg.UserData, "accounts-v1", accountKey(m.storedID))
	m.windowBusy = true
	m.windowMessage = "正在控制已保存账号的现有浏览器窗口…"
	return residentWindowRequest{account: m.storedID, cfg: cfg, visible: visible}, true
}

func (m *model) finishResidentWindow(req residentWindowRequest, err error) {
	m.windowBusy = false
	if m.storedID != req.account || !m.cfg.ResidentBrowser {
		m.windowMessage = "账号或浏览器设置已变化，请重新操作。"
		return
	}
	if err != nil {
		// Do not expose state paths, endpoints or authentication data from errors.
		m.windowMessage = "当前账号的常驻浏览器尚未启动、已变化或窗口操作未完成；未启动新浏览器，请稍后重试。"
		return
	}
	if req.visible {
		m.windowMessage = "已显示验证窗口，请手动完成学校验证；完成后可点击「隐藏浏览器」。隐藏不等于绕过二次验证。"
	} else {
		m.windowMessage = "已隐藏浏览器（任务栏与 Alt+Tab 均不显示）；学校二次验证仍需你主动显示窗口完成。"
	}
}

func runResidentWindow(ctx context.Context, req residentWindowRequest, get func(context.Context, store.Settings) (residentWindowClient, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	client, err := get(ctx, req.cfg)
	if err != nil {
		return err
	}
	if client == nil {
		return errors.New("resident host not started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// GetClient and the protocol bind this command to the existing generation.
	return client.SetWindowVisible(ctx, req.visible)
}

func (a *app) controlResidentWindow(visible bool) {
	req, ok := a.m.beginResidentWindow(visible)
	if !ok {
		a.post(func() {})
		return
	}
	hosts := a.hosts
	a.post(func() {})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		err := runResidentWindow(ctx, req, func(ctx context.Context, cfg store.Settings) (residentWindowClient, error) {
			if hosts == nil {
				return nil, errors.New("resident manager not initialized")
			}
			return hosts.GetClient(ctx, cfg)
		})
		a.post(func() { a.m.finishResidentWindow(req, err) })
	}()
}
