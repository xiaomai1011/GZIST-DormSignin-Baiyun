package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// processMode is what this process is going to do. The GUI (and with it the
// scheduler) is only reachable when no probe flag was passed at all, so an
// isolated -session-probe-profile can never start a real sign-in by accident.
type processMode int

const (
	modeGUI processMode = iota
	modeProbe
	modeProbeDryRun
)

// resolveProcessMode decides between GUI, probe and dry run. A profile flag on
// its own is an error rather than a no-op: presence is checked by the caller, so
// an empty value cannot slip through either.
func resolveProcessMode(probe, dryRun, profileFlagSet bool) (processMode, error) {
	if profileFlagSet && !probe && !dryRun {
		return modeGUI, fmt.Errorf("-session-probe-profile 必须与 -session-probe 或 -session-probe-dry-run 一起使用；" +
			"单独传入时它不会生效，那就会启动界面与调度并可能真实签到，本轮已直接退出")
	}
	switch {
	case dryRun:
		return modeProbeDryRun, nil
	case probe:
		return modeProbe, nil
	default:
		return modeGUI, nil
	}
}

// Session recovery probe — CLI only.
//
// It is deliberately not wired into the tray, the scheduler or the sign-in flow:
// it runs only when someone passes -session-probe (or -session-probe-dry-run), it
// does one navigation, and it exits. It shares the account profile (and therefore
// the profile lock) with sign-in and verification, so it can never touch the same
// profile concurrently. A lock conflict is reported as-is and nothing steals the
// lock, deletes files or ends another browser.
//
// Exit codes: 0 recovered, 2 needs login, 3 needs second factor, 4 unknown, 1 error.
// -session-probe-dry-run stops after resolving and checking the profile: no
// browser, no lock, no request, nothing created.
func runSessionProbe(profileFlag string, dryRun bool) int {
	base, err := os.UserConfigDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir := filepath.Join(base, appTitle)
	st := store.New(dir)
	env := probeEnv{
		dataDir: dir,
		out:     os.Stdout,
		launch:  edge.LaunchContext,
		creds:   st.Credentials,
	}
	return runProbe(env, profileFlag, dryRun)
}

// probeEnv is what the probe needs from the outside world: where the app keeps
// its settings, where to print, how to start a browser, and where the account
// comes from. Tests replace the launcher to prove it is never called.
type probeEnv struct {
	dataDir string
	out     io.Writer
	launch  func(context.Context, store.Settings) (*edge.Session, error)
	creds   func() (string, string, error)
	// probe is the observation itself: nil means the real CDP probe. It exists so
	// tests can pin the verdict and prove the exit code and the cleanup without a
	// browser or a school page.
	probe func(caller, browser context.Context, entry string) signin.ProbeResult
	// close releases the browser tree. It is a field so tests can prove that
	// cleanup runs on every exit path and that an unconfirmed cleanup is never
	// reported as success; nil means edge.Session.Close.
	close func(*edge.Session) error
}

// probeProfile is the resolved answer to "which profile does this run use".
// Base is exactly what the program is handed as the userData base path, the
// account segment is appended once, and AccountDir is the single final path used
// for printing, checking and launching.
type probeProfile struct {
	Base       string
	BaseAbs    string
	Segment    string
	AccountDir string
	Source     string
}

func runProbe(env probeEnv, profileFlag string, dryRun bool) (code int) {
	out := env.out
	if out == nil {
		out = io.Discard
	}
	st := store.New(env.dataDir)
	cfg := st.Load()

	id, pass, credErr := env.creds()
	if credErr != nil {
		fmt.Fprintln(out, "探测未开始: 无法读取账号凭据")
		return 1
	}
	if id == "" || pass == "" {
		fmt.Fprintln(out, "探测未开始: 请先填写学号和密码")
		return 1
	}

	cfgProfile, p, err := resolveProbeProfile(profileFlag, cfg, id)
	if err != nil {
		fmt.Fprintln(out, "探测未开始: "+err.Error())
		return 1
	}
	fmt.Fprint(out, describeProbeProfile(p))

	if err := checkProbeProfile(p); err != nil {
		fmt.Fprintln(out, "探测未开始: "+err.Error())
		return 1
	}
	if dryRun {
		fmt.Fprintln(out, "dry-run：只解析与检查，未启动浏览器、未取目录锁、未创建任何目录。")
		return 0
	}

	entry, err := signin.SessionProbeEntry(cfg.URL)
	if err != nil {
		fmt.Fprintln(out, "探测未开始: "+err.Error())
		return 1
	}

	log := applog.NewNamed(filepath.Join(env.dataDir, "logs"), "session-probe.log")
	defer log.Close()
	log.Add("======== 会话恢复探测开始（只导航、不填表单、不签到、不重试）========")
	log.Add(buildIdentity())
	if exe, err := os.Executable(); err == nil {
		log.Add("探测运行文件: " + exe)
	}
	log.Add("探测 profile: 来源=" + p.Source + " base=" + p.Base + " account=" + p.Segment + " final=" + p.AccountDir)
	log.Add("探测入口: 学校统一认证的固定登录路由（service 为已配置的业务地址，不记录带票据的地址）")
	// The two paths are not the same test, and a result here must not be read as
	// one about the other: the probe asks the SSO (ids) whether it still resumes a
	// session, while a normal run opens the business site (xsfw) directly and
	// depends on that site's own session cookie.
	log.Add("探测限制: 本探测验证的是统一认证会话，正式签到直接打开业务站地址；两者不是同一条恢复路径")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	sess, err := env.launch(ctx, cfgProfile)
	if err != nil {
		log.Add("探测未开始: " + err.Error())
		fmt.Fprintln(out, "探测未开始: "+err.Error())
		return 1
	}
	if sess == nil {
		// A launcher that claims success without a session would be dereferenced
		// below; never treat that as a started browser.
		log.Add("探测未开始: 启动器没有返回浏览器会话")
		fmt.Fprintln(out, "探测未开始: 启动器没有返回浏览器会话")
		return 1
	}
	// Every exit after this point closes the browser tree, including an early
	// return and a panic. An unconfirmed cleanup is never reported as success:
	// Session.Close keeps the profile lock in that case, and the exit code turns
	// into an error so a half-cleaned run cannot look like a valid verdict.
	defer func() {
		closeSession := env.close
		if closeSession == nil {
			closeSession = func(s *edge.Session) error { return s.Close() }
		}
		if closeErr := closeSession(sess); closeErr != nil {
			log.Add("探测后浏览器清理未确认: " + closeErr.Error())
			fmt.Fprintln(out, "探测后浏览器清理未确认: "+closeErr.Error())
			code = 1
			return
		}
		log.Add("探测结束：浏览器进程树已关闭")
	}()
	// The path that was printed, checked and handed to the launcher must be the
	// one the browser actually got; anything else means the profile moved.
	if sess.UserData != p.AccountDir {
		log.Add("探测未开始: 实际使用的浏览器目录与核对结果不一致（核对=" + p.AccountDir + " 实际=" + sess.UserData + "）")
		fmt.Fprintln(out, "探测未开始: 实际使用的浏览器目录与核对结果不一致（核对="+p.AccountDir+" 实际="+sess.UserData+"）")
		return 1
	}
	log.Printf("探测浏览器: pid=%d（与签到共用账号目录与目录锁）", sess.PID)
	// sess.Ctx carries the CDP target; ctx only carries the person's stop. Both
	// are needed: page operations need the former, and a merge of the two cannot
	// tell "the user stopped" from "the browser went away".
	observe := env.probe
	if observe == nil {
		observe = signin.RunSessionProbe
	}
	res := observe(ctx, sess.Ctx, entry)
	log.Add(signin.SessionProbeDiagLine(res))
	log.Add(signin.SessionProbeSummary(res))
	fmt.Fprintln(out, signin.SessionProbeDiagLine(res))
	switch res.Class {
	case signin.ProbeRecovered:
		return 0
	case signin.ProbeNeedsLogin:
		return 2
	case signin.ProbeNeedsSecondFactor:
		return 3
	default:
		return 4
	}
}

// resolveProbeProfile picks the userData base path and appends the account
// segment exactly once. An explicit flag must be absolute; the account segment is
// never added twice, so passing the account directory itself is an error rather
// than a silently doubled path.
func resolveProbeProfile(profileFlag string, cfg store.Settings, id string) (store.Settings, probeProfile, error) {
	var p probeProfile
	base := cfg.UserData
	p.Source = "配置"
	if strings.TrimSpace(profileFlag) != "" {
		base = profileFlag
		p.Source = "显式指定"
	}
	if strings.TrimSpace(base) == "" {
		return cfg, p, fmt.Errorf("Edge 用户目录不能为空")
	}
	if profileFlag != "" && !filepath.IsAbs(profileFlag) {
		return cfg, p, fmt.Errorf("--session-probe-profile 只接受绝对路径（收到 %q）：相对路径会按程序所在目录解析，容易测到另一个空 profile", profileFlag)
	}
	if hasAccountSegment(base) {
		return cfg, p, fmt.Errorf("传入的 profile 里已经含有 accounts-v1\\<账号目录>（%q）：请去掉完整的 accounts-v1\\<账号目录> 段，改传它的父目录", base)
	}
	if p.Source == "配置" && strings.EqualFold(base, store.Defaults().UserData) {
		p.Source = "默认"
	}
	p.Base = base
	baseAbs, err := edge.ProfilePath(store.Settings{UserData: base})
	if err != nil {
		return cfg, p, err
	}
	p.BaseAbs = baseAbs
	p.Segment = filepath.Join("accounts-v1", accountKey(id))
	p.AccountDir = filepath.Join(baseAbs, p.Segment)

	// The account segment is appended exactly once, here, from the resolved base
	// path. The launcher gets that same final absolute path — the very one that
	// was printed and checked — so the base is never resolved a second time.
	cfgProfile := cfg
	cfgProfile.UserData = p.AccountDir
	return cfgProfile, p, nil
}

func hasAccountSegment(path string) bool {
	for _, part := range strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' }) {
		if strings.EqualFold(part, "accounts-v1") {
			return true
		}
	}
	return false
}

func describeProbeProfile(p probeProfile) string {
	exist := "否"
	if st, err := os.Stat(p.AccountDir); err == nil {
		if st.IsDir() {
			exist = "是"
		} else {
			exist = "否（同名文件）"
		}
	}
	def := "否"
	if _, err := os.Stat(filepath.Join(p.AccountDir, "Default")); err == nil {
		def = "是"
	}
	lock := "不存在"
	if _, err := os.Stat(filepath.Join(p.AccountDir, ".dormsign.lock")); err == nil {
		// Only a hint: a lock file may exist without anyone holding the lock.
		lock = "文件存在（仅供参考，是否被占用由取锁结果判定）"
	}
	var b strings.Builder
	b.WriteString("探测 profile: 来源=" + p.Source + "\n")
	b.WriteString("  base    = " + p.Base + "\n")
	b.WriteString("  base_abs= " + p.BaseAbs + "\n")
	b.WriteString("  account = " + p.Segment + "\n")
	b.WriteString("  final   = " + p.AccountDir + "\n")
	b.WriteString("  存在=" + exist + "  Default 目录=" + def + "  .dormsign.lock=" + lock + "\n")
	return b.String()
}

// checkProbeProfile refuses to invent a profile: the account directory has to
// exist already. Nothing here creates it, and there is no fallback to the
// program directory.
func checkProbeProfile(p probeProfile) error {
	st, err := os.Stat(p.AccountDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("探测 profile 不存在：%s（不会新建，也不会回退到默认目录；请确认参数或先正常签到一次生成账号目录）", p.AccountDir)
		}
		return fmt.Errorf("无法检查探测 profile：%v", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("探测 profile 不是目录：%s", p.AccountDir)
	}
	return nil
}
