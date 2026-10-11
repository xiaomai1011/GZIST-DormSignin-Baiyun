package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/applog"
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
