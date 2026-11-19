//go:build windows

package browserhost

import (
	"context"
	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
	"os"
	"testing"
	"time"
)

// Explicit opt-in, newHarness uses only a throwaway profile and loopback pages.
// Exact run: DORMSIGN_EDGE_TEST=1 BROWSERHOST_WINDOW_TEST=1 go test ./internal/browserhost -run '^TestResidentWindowRoundTripEdge$' -count=1 -v
func TestResidentWindowRoundTripEdge(t *testing.T) {
	if os.Getenv("BROWSERHOST_WINDOW_TEST") != "1" {
		t.Skip("requires BROWSERHOST_WINDOW_TEST=1")
	}
	d, c, _ := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d.mu.Lock()
	control, ok := d.window.(*controlledWindow)
	sess := d.session
	gen := d.sessionGen
	d.mu.Unlock()
	if !ok {
		t.Fatal("native window not bound")
	}
	before, err := chromedp.Targets(sess.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(sess.Ctx, chromedp.Evaluate(`window.__windowFixture="retained"`, nil)); err != nil {
		t.Fatal(err)
	}
	c.windowGeneration.Store(gen)
	for _, visible := range []bool{false, true, false, true, false} {
		if err := c.SetWindowVisible(ctx, visible); err != nil {
			t.Fatal(err)
		}
		control.mu.Lock()
		w, err := control.candidate()
		control.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if w.visible != visible {
			t.Fatalf("visible=%t want=%t", w.visible, visible)
		}
	}
	var retained string
	if err := chromedp.Run(sess.Ctx, chromedp.Evaluate(`window.__windowFixture`, &retained)); err != nil {
		t.Fatal(err)
	}
	if retained != "retained" {
		t.Fatal("document variable lost")
	}
	after, err := chromedp.Targets(sess.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("window operation changed targets")
	}
	for i := range before {
		if before[i].TargetID != after[i].TargetID {
			t.Fatal("target identity changed")
		}
	}
	if d.session != sess || d.sessionGen != gen {
		t.Fatal("session changed")
	}
}

func TestResidentWindowCandidatesEdge(t *testing.T) {
	if os.Getenv("BROWSERHOST_WINDOW_TEST") != "1" {
		t.Skip("requires BROWSERHOST_WINDOW_TEST=1")
	}
	cfg := store.Settings{EdgePath: edgeExe(t), UserData: t.TempDir(), VisibleBrowser: true, ViewW: 430, ViewH: 900}
	s, err := edge.LaunchContext(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	backend := &nativeWindowBackend{pid: uint32(s.PID)}
	ws, err := backend.Windows()
	if err != nil {
		t.Fatal(err)
	}
	getLong := windowUser32.NewProc("GetWindowLongW")
	for _, w := range ws {
		style, _, _ := getLong.Call(w.handle, ^uintptr(15))
		exstyle, _, _ := getLong.Call(w.handle, ^uintptr(19))
		t.Logf("fixture pid=%d hwnd=%d class=%s owner=%d width=%d height=%d visible=%t minimized=%t style=%08x exstyle=%08x", w.pid, w.handle, w.class, w.owner, w.width, w.height, w.visible, w.minimized, uint32(style), uint32(exstyle))
	}
}
