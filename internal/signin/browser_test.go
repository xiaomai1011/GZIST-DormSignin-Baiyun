package signin

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// Opt-in local integration test: only about:blank and a disposable profile.
// No school URL, login, navigation, or sign-in click is performed.
func TestPageReadersWithEdgeExecutor(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for local about:blank reader test")
	}
	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	sess, err := edge.Launch(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sess.Close(); err != nil {
			t.Errorf("browser cleanup: %v", err)
		}
	}()
	// Derive only a deadline: do not inject an executor here. The reader
	// helpers must resolve it themselves from the real session context.
	ctx, cancel := context.WithTimeout(sess.Ctx, 5*time.Second)
	defer cancel()
	// Granting permission is a browser-level CDP command; the target executor
	// alone is not sufficient. This does not navigate to the permitted origin.
	if err := emulationSetGeo(ctx, cfg.Lat, cfg.Lon, cfg.AccM); err != nil {
		t.Fatalf("geolocation override and permission: %v", err)
	}
	var location string
	if err := chromedp.Run(ctx, chromedp.Evaluate("location.href", &location)); err != nil {
		t.Fatal(err)
	}
	if location != "about:blank" {
		t.Fatalf("refusing to modify unexpected page: %q", location)
	}
	const text = "查寝时间段 点击签到 测试文字（仅本地）"
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.body.innerText = '查寝时间段 点击签到 测试文字（仅本地）'`, nil)); err != nil {
		t.Fatal(err)
	}
	if got := pageText(ctx); got != text {
		t.Fatalf("pageText from browser context: got %q, want %q", got, text)
	}
	state, err := probePage(ctx)
	if err != nil {
		t.Fatalf("probePage from browser context: %v", err)
	}
	if state.URL != "about:blank" || state.Text != text {
		t.Fatalf("probePage: got %#v", state)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.title='xsfw.gzist.edu.cn'`, nil)); err != nil {
		t.Fatal(err)
	}
	if reason := clickSafety(ctx, text); reason == "" {
		t.Fatal("a forged title on about:blank must not pass the live hostname guard")
	}
	t.Logf("PID=%d: page readers and live-host safety guard verified on local about:blank", sess.PID)
}
