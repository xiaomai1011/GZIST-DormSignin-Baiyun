package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/updatecheck"
)

type updateController struct{ updateChecker *updatecheck.Checker }
type updateUIState struct {
	updateBusy    bool
	updateMessage string
	updateRelease *updatecheck.Release
}

// initUpdates is called on the UI thread. Checks never install, restart, change
// the sign-in lifecycle, or open a browser. Only an explicit click opens a page.
func (a *app) initUpdates(dataDir string) {
	cachePath := ""
	if dataDir != "" {
		cachePath = filepath.Join(dataDir, "update-check.json")
	}
	a.updateChecker = updatecheck.New(cachePath)
	a.m.act.CheckUpdate = func() { a.checkProgramUpdate(true) }
	a.m.act.OpenRelease = a.openProgramRelease
	a.m.updateMessage = "仅检查正式发布版；下载安装由你确认，不自动安装或重启。"
	a.checkProgramUpdate(false)
	go func() {
		timer := time.NewTicker(updatecheck.CacheTTL)
		defer timer.Stop()
		for range timer.C {
			a.post(func() { a.checkProgramUpdate(false) })
		}
	}()
}
func (a *app) checkProgramUpdate(manual bool) {
	if a.updateChecker == nil || a.m.updateBusy {
		return
	}
	a.m.updateBusy = true
	a.m.updateMessage = "正在检查正式发布版…"
	current := a.m.version
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		result, err := a.updateChecker.Check(ctx, current, manual)
		a.post(func() {
			a.m.updateBusy = false
			if err != nil {
				a.m.updateMessage = "更新检查暂未完成，可稍后重试。"
				a.log.Printf("程序更新检查失败: %v", err)
				return
			}
			a.m.updateRelease = result.Release
			if result.Release == nil {
				a.m.updateMessage = "未发现更高版本的正式发布版。"
				return
			}
			a.m.updateMessage = "发现新版本 " + result.Release.Version + "；打开官方发布页后选择安装包下载。"
			if !result.Cached {
				a.notify("程序有新版本 "+result.Release.Version, "打开主窗口查看官方下载入口；不会自动安装或重启。")
			}
		})
	}()
}
func (a *app) openProgramRelease() {
	r := a.m.updateRelease
	if r == nil || !updatecheck.ValidateRelease(*r) {
		return
	}
	if err := mygo.Shell.OpenExternal(r.URL); err != nil {
		a.m.updateMessage = "打开发布页失败，可稍后重试。"
		a.log.Printf("打开官方发布页失败: %v", err)
	}
}
func (m *model) updateCard(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "程序更新").Bold().Grow(1)
			if ui.Button(c, "检查更新").Disabled(m.updateBusy).Clicked() && m.act.CheckUpdate != nil {
				m.act.CheckUpdate()
			}
		})
		if m.updateMessage != "" {
			ui.Text(c, m.updateMessage).Wrap().FontSize(12)
		}
		ui.Text(c, "仅检查与通知 · 不自动安装或重启 · 签到和人工验证照常运行").Wrap().FontSize(11).TextColor(t.TextMuted)
		if m.updateRelease != nil {
			if ui.PrimaryButton(c, "打开官方发布页下载安装包").Clicked() && m.act.OpenRelease != nil {
				m.act.OpenRelease()
			}
		}
	})
}
