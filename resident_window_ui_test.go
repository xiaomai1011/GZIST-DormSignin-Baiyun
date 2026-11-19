package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

type fakeResidentWindow struct {
	calls []bool
	err   error
}

func (f *fakeResidentWindow) SetWindowVisible(ctx context.Context, on bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.calls = append(f.calls, on)
	return f.err
}
func windowTestModel() *model {
	return &model{cfg: store.Settings{ResidentBrowser: true, UserData: "fake-base"}, storedID: "saved-A", hasCreds: true, id: "unsaved-B", pass: "unsaved-secret", phase: "签到中"}
}
func TestResidentWindowUsesOnlySavedAccountDuringTask(t *testing.T) {
	m := windowTestModel()
	f := &fakeResidentWindow{}
	for _, visible := range []bool{true, false} {
		req, ok := m.beginResidentWindow(visible)
		if !ok {
			t.Fatal(m.windowMessage)
		}
		err := runResidentWindow(context.Background(), req, func(_ context.Context, cfg store.Settings) (residentWindowClient, error) {
			want := filepath.Join("fake-base", "accounts-v1", accountKey("saved-A"))
			if cfg.UserData != want {
				t.Fatalf("wrong account profile: %s", cfg.UserData)
			}
			return f, nil
		})
		m.finishResidentWindow(req, err)
		if err != nil || m.windowBusy {
			t.Fatal(err)
		}
	}
	if len(f.calls) != 2 || !f.calls[0] || f.calls[1] {
		t.Fatal(f.calls)
	}
	if m.id != "unsaved-B" || m.pass != "unsaved-secret" || m.storedID != "saved-A" || m.storedPass != "" {
		t.Fatal("input or saved credentials changed")
	}
}
func TestResidentWindowMissingAndChangedHost(t *testing.T) {
	for _, err := range []error{errors.New("not started"), errors.New("generation changed")} {
		m := windowTestModel()
		req, _ := m.beginResidentWindow(true)
		got := runResidentWindow(context.Background(), req, func(context.Context, store.Settings) (residentWindowClient, error) { return nil, err })
		m.finishResidentWindow(req, got)
		if m.windowBusy || !strings.Contains(m.windowMessage, "未启动新浏览器") {
			t.Fatal(m.windowMessage)
		}
	}
	m := windowTestModel()
	req, _ := m.beginResidentWindow(true)
	m.storedID = "saved-C"
	m.finishResidentWindow(req, nil)
	if strings.Contains(m.windowMessage, "已显示") {
		t.Fatal("stale completion accepted")
	}
}
func TestResidentWindowGuardsAndCancellation(t *testing.T) {
	for _, change := range []func(*model){func(m *model) { m.saving = true }, func(m *model) { m.windowBusy = true }, func(m *model) { m.cfg.ResidentBrowser = false }, func(m *model) { m.hasCreds = false }, func(m *model) { m.storedID = "" }} {
		m := windowTestModel()
		change(m)
		if _, ok := m.beginResidentWindow(true); ok {
			t.Fatal("guard missed")
		}
	}
	m := windowTestModel()
	req, _ := m.beginResidentWindow(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runResidentWindow(ctx, req, func(context.Context, store.Settings) (residentWindowClient, error) {
		t.Fatal("called lookup after cancel")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f := &fakeResidentWindow{err: errors.New("native failure")}
	err = runResidentWindow(context.Background(), req, func(context.Context, store.Settings) (residentWindowClient, error) { return f, nil })
	m.finishResidentWindow(req, err)
	if strings.Contains(m.windowMessage, "已显示") {
		t.Fatal("failure reported as success")
	}
}
func TestResidentWindowBlocksSaveWithoutReadingStore(t *testing.T) {
	m := windowTestModel()
	m.windowBusy = true
	a := &app{m: m}
	a.running.Store(true)
	a.save("other", "secret") // nil store/log would panic if it tried to persist.
	a.setResident(false)
	if !m.cfg.ResidentBrowser || !a.running.Load() {
		t.Fatal("window control altered task/mode")
	}
}
func TestResidentWindowRenderHasNoImplicitActions(t *testing.T) {
	m := windowTestModel()
	m.act.ShowBrowser = func() { t.Fatal("render showed real window") }
	m.act.HideBrowser = func() { t.Fatal("render hid real window") }
	m.act.Save = func(string, string) { t.Fatal("render saved input") }
	if img := ui.Render(m.view, 440, 1400, 1); img == nil {
		t.Fatal("empty render")
	}
}

// These are synthetic input events in mygo's offscreen tester, never OS clicks.
func TestResidentWindowExplicitButtonEvents(t *testing.T) {
	m := windowTestModel()
	f := &fakeResidentWindow{}
	command := func(visible bool) {
		req, ok := m.beginResidentWindow(visible)
		if !ok {
			t.Fatal(m.windowMessage)
		}
		err := runResidentWindow(context.Background(), req, func(context.Context, store.Settings) (residentWindowClient, error) { return f, nil })
		m.finishResidentWindow(req, err)
	}
	m.act.ShowBrowser = func() { command(true) }
	m.act.HideBrowser = func() { command(false) }
	tt := ui.NewTester(func(c *ui.Context) { m.switches(c, applyTheme(c)) }, 440, 600)
	tt.Frame()
	if len(f.calls) != 0 {
		t.Fatal("implicit command")
	}
	for _, label := range []string{"显示验证窗口", "隐藏浏览器"} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
		tt.Frame()
	}
	if len(f.calls) != 2 || !f.calls[0] || f.calls[1] {
		t.Fatal(f.calls)
	}
	m.windowBusy = true
	tt.Frame()
	if err := tt.Click("显示验证窗口"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if len(f.calls) != 2 {
		t.Fatal("duplicate window command")
	}
}
