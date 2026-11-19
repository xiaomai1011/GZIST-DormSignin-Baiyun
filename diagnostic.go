package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Uses the installed profile, but only about:blank. No credentials, site requests,
// scheduling or button clicks. Logs work even in the GUI-subsystem executable.
func runBrowserSelftest() (result error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(base, appTitle)
	log := applog.New(filepath.Join(dir, "logs"))
	defer log.Close()
	log.Add("======== 浏览器自检开始（仅本地空白页，不签到）========")
	log.Add(buildIdentity())
	if exe, err := os.Executable(); err == nil {
		log.Add("自检运行文件: " + exe)
	}
	defer func() {
		if result != nil {
			log.Add("浏览器自检失败: " + result.Error())
		} else {
			log.Add("======== 浏览器自检通过：连续三轮启动/CDP/关闭 ========")
		}
	}()
	cfg := store.New(dir).Load()
	for i := 1; i <= 3; i++ {
		session, err := edge.Launch(cfg)
		if err != nil {
			return err
		}
		log.Printf("浏览器自检 %d/3: pid=%d, profile=%s", i, session.PID, session.UserData)
		ctx, cancel := context.WithTimeout(session.Ctx, 5*time.Second)
		var value int
		err = chromedp.Run(ctx, chromedp.Evaluate("1+1", &value))
		cancel()
		if closeErr := session.Close(); closeErr != nil {
			return fmt.Errorf("浏览器进程树清理失败: %w", closeErr)
		}
		if err != nil {
			return err
		}
		if value != 2 {
			return fmt.Errorf("unexpected CDP result %d", value)
		}
		log.Printf("浏览器自检 %d/3: CDP 正常，进程树已关闭", i)
	}
	return nil
}

// Resident selftest exercises the resident path the tray application uses:
// the manager starts one host, two attaches must land on the same browser
// process, and the exit path must close it. It uses a throwaway profile and
// only about:blank; no credentials, no school requests, no scheduling.
func runResidentSelftest() (result error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(base, appTitle)
	log := applog.New(filepath.Join(dir, "logs"))
	defer log.Close()
	log.Add("======== 常驻自检开始（临时 profile，仅本地空白页）========")
	log.Add(buildIdentity())
	if exe, err := os.Executable(); err == nil {
		log.Add("自检运行文件: " + exe)
	}
	defer func() {
		if result != nil {
			log.Add("常驻自检失败: " + result.Error())
		} else {
			log.Add("======== 常驻自检通过：两次附加复用同一浏览器，退出已关闭 ========")
		}
	}()

	cfg := store.New(dir).Load()
	tmp, err := os.MkdirTemp("", "dormsign-resident-selftest-")
	if err != nil {
		return err
	}
	cfg.UserData = filepath.Join(tmp, "account")
	if err := os.MkdirAll(cfg.UserData, 0o700); err != nil {
		return err
	}

	// cleanupProfile=false: the selftest owns this temporary directory and
	// removes it; the host must not delete a directory it did not create, and
	// the client's account check compares against exactly this profile.
	m := browserhost.NewManager(false)
	// The temporary profile is removed only after CloseAll confirms the host is
	// gone. A cleanup that cannot be confirmed keeps the directory and reports
	// the cleanup error; an unconditional defer would hide exactly the failure
	// the caller needs to see.
	defer func() {
		if err := finishSelftestProfile(m, tmp); err != nil {
			result = errors.Join(result, err)
			log.Add("常驻自检收尾失败: " + err.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	first, err := m.Ensure(ctx, cfg)
	if err != nil {
		return err
	}
	before, err := first.Status()
	if err != nil {
		return err
	}
	session1, release1, err := first.Attach(ctx, 10*time.Minute)
	if err != nil {
		return err
	}
	pid1 := session1.PID
	release1()
	log.Printf("常驻自检 1/2: 宿主 pid=%d launches=%d 附加 pid=%d", before.PID, before.Launches, pid1)

	second, err := m.Ensure(ctx, cfg)
	if err != nil {
		return err
	}
	after, err := second.Status()
	if err != nil {
		return err
	}
	if after.PID != before.PID || after.Launches != 1 {
		return fmt.Errorf("两次任务未复用同一浏览器：first pid=%d launches=%d，second pid=%d launches=%d",
			before.PID, before.Launches, after.PID, after.Launches)
	}
	session2, release2, err := second.Attach(ctx, 10*time.Minute)
	if err != nil {
		return err
	}
	if session2.PID != pid1 {
		return fmt.Errorf("第二次附加得到另一浏览器：first=%d second=%d", pid1, session2.PID)
	}
	release2()
	log.Printf("常驻自检 2/2: 复用 pid=%d，任务结束宿主仍在（%d 个）", after.PID, m.Hosts())

	if err := m.CloseAll(); err != nil {
		return fmt.Errorf("退出时关闭常驻浏览器失败: %w", err)
	}
	return nil
}

// finishSelftestProfile closes the resident host and only then removes the
// throwaway profile. Both failures are reported instead of being folded into a
// silent RemoveAll: a host that may still be running must keep its directory.
func finishSelftestProfile(closer interface{ CloseAll() error }, dir string) error {
	if err := closer.CloseAll(); err != nil {
		return fmt.Errorf("关闭常驻浏览器失败，临时 profile 保留 %s: %w", dir, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("删除临时 profile 失败 %s: %w", dir, err)
	}
	return nil
}
