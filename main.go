// GZIST DormSignin — 智能查寝自动签到（广州理工学院 · 白云校区专属）
// Go + mygo rewrite of the PowerShell dorm-sign-in tool. Lives in the
// tray, schedules the daily sign-in itself (no Windows scheduled task),
// and drives headless Edge over CDP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/art"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/captcha"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

const appTitle = "GZIST DormSignin"

// Identifies this local repair even before a release tag is created.
const repairBuild = "daily-ledger-20261011-r3"

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
	log    *applog.Log
	store  *store.Store
	m      *model
	solver *captcha.Solver

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
	flag.Parse()
	if *browserTest {
		if err := runBrowserSelftest(); err != nil {
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
		Save:         a.save,
		Sign:         a.signNow,
		SetHoliday:   a.setHoliday,
		SetAutoSign:  a.setAutoSign,
		SetAutostart: a.setAutostart,
		OpenLogs:     func() { mygo.Shell.ShowItemInFolder(a.log.Path()) },
	}
	a.m.logs = a.log.Lines()

	a.makeTray()
	a.syncTray() // set the real state right away: star breathing, not the blank icon
	go a.breathingLoop()
	go a.scheduleLoop()

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
		ticket, err := a.ledger.claim(time.Now(), cfg, accountKey(id), id != "" && pass != "", a.running.Load())
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
	if !a.running.CompareAndSwap(false, true) {
		return signin.Result{Neutral: true, Reason: "签到正在运行，已忽略重复请求"}
	}
	defer func() {
		a.running.Store(false)
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
		// overwrite the current account's notice.
		if a.m.statusAccount == account && a.m.statusDate == date {
			a.m.setResult(res.OK, res.Neutral, res.Reason)
		}
	})
	return res
}

func (a *app) signNow() {
	if a.running.Load() {
		a.m.notice = "签到正在运行…"
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

// save writes credentials and merges UI-visible settings.
func (a *app) save(id, pass string) {
	if id == "" {
		a.m.notice = "学号不能为空"
		return
	}
	if pass == "" && !a.m.hasCreds {
		a.m.notice = "第一次设置请同时填写密码"
		return
	}
	a.m.notice = "保存中…"
	a.post(func() {})
	go func() {
		if pass == "" {
			a.store.DeleteCredentials()
			a.log.Add("账号已清除")
		} else {
			if insecure, err := a.store.SetCredentials(id, pass); err != nil {
				a.post(func() { a.m.notice = "保存失败：" + err.Error() })
				return
			} else if insecure {
				a.log.Add("系统凭据管理器不可用，密码以明文（权限 0600）保存在本机")
			}
			a.log.Printf("账号已保存（学号=%s）", id)
		}
		a.post(func() {
			a.m.studentID, a.m.hasCreds = id, pass != ""
			a.m.notice = "已保存"
			a.syncTray()
		})
	}()
}

func (a *app) importLegacy() string {
	return a.store.ImportLegacy()
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
		mygo.Separator(),
		{ID: "autostart", Label: "开机自启", Type: mygo.MenuItemCheckbox, Checked: a.m.autostart,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setAutostart(it.Checked) }},
		{ID: "holiday", Label: "假期模式（停用签到）", Type: mygo.MenuItemCheckbox, Checked: a.m.cfg.Holiday,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setHoliday(it.Checked) }},
		mygo.Separator(),
		{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
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
	a.menu.ItemByID("sign").SetEnabled(!a.running.Load() && !a.m.cfg.Holiday)
	a.menu.ItemByID("holiday").SetChecked(a.m.cfg.Holiday)
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
