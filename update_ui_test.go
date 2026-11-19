package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/updatecheck"
	"testing"
)

func TestUpdateCardExplicitActionsOnly(t *testing.T) {
	m := &model{}
	m.phase = "签到中"
	m.verifying = true
	m.updateRelease = &updatecheck.Release{Version: "v2.0.20", URL: updatecheck.ReleasesURL + "/tag/v2.0.20"}
	checks, opens := 0, 0
	m.act.CheckUpdate = func() { checks++ }
	m.act.OpenRelease = func() { opens++ }
	tt := ui.NewTester(func(c *ui.Context) { m.updateCard(c, applyTheme(c)) }, 500, 320)
	tt.Frame()
	if checks != 0 || opens != 0 {
		t.Fatal("render triggered update operation")
	}
	for _, label := range []string{"检查更新", "打开官方发布页下载安装包"} {
		if e := tt.Click(label); e != nil {
			t.Fatal(e)
		}
		tt.Frame()
	}
	if checks != 1 || opens != 1 {
		t.Fatalf("checks=%d opens=%d", checks, opens)
	}
	if m.phase != "签到中" || !m.verifying {
		t.Fatal("update UI disturbed active task")
	}
	m.updateBusy = true
	tt.Frame()
	if e := tt.Click("检查更新"); e != nil {
		t.Fatal(e)
	}
	tt.Frame()
	if checks != 1 {
		t.Fatal("duplicate check")
	}
}
func TestUpdateCardDoesNotOfferDownloadWithoutRelease(t *testing.T) {
	m := &model{}
	tt := ui.NewTester(func(c *ui.Context) { m.updateCard(c, applyTheme(c)) }, 500, 320)
	tt.Frame()
	if e := tt.Click("打开官方发布页下载安装包"); e == nil {
		t.Fatal("download offered without release")
	}
}
func TestUpdateInvalidSelectionDoesNotOpenBrowser(t *testing.T) {
	a := &app{m: &model{}}
	a.m.updateRelease = &updatecheck.Release{Version: "v2.0.20", URL: "https://example.invalid"}
	// Invalid selection returns before using OS shell/log or touching operation state.
	a.running.Store(true)
	a.m.verifying = true
	a.openProgramRelease()
	if !a.running.Load() || !a.m.verifying {
		t.Fatal("task interrupted")
	}
}
