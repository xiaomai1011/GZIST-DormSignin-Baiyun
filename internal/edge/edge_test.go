package edge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

func TestEndpointReader(t *testing.T) {
	var out tailOutput
	ch := make(chan string, 1)
	scanEndpoint(strings.NewReader("diagnostic\nDevTools listening on ws://127.0.0.1:123/devtools/browser/test\nmore\n"), ch, &out)
	if got := <-ch; got != "ws://127.0.0.1:123/devtools/browser/test" {
		t.Fatal(got)
	}
	if !strings.Contains(out.String(), "more") {
		t.Fatal("output not drained")
	}
	out.Write([]byte(strings.Repeat("x", 10000)))
	if len(out.String()) != 8192 {
		t.Fatal("output not bounded")
	}
}
func TestProfileLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".dormsign.lock")
	release, err := lockProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := lockProfile(p); err == nil {
		other()
		release()
		t.Fatal("duplicate profile allowed")
	}
	release()
	release, err = lockProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
func TestLaunchCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := LaunchContext(ctx, store.Defaults()); err == nil {
		s.Close()
		t.Fatal("cancelled launch succeeded")
	}
}

// The Go test executable rejects Edge flags and exits immediately. Exercise the
// real startup-error path and prove it releases its process/profile ownership.
func TestLaunchEarlyExitReleasesProfile(t *testing.T) {
	cfg := store.Defaults()
	cfg.EdgePath = os.Args[0]
	cfg.UserData = t.TempDir()
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, err := LaunchContext(ctx, cfg)
		cancel()
		if err == nil {
			s.Close()
			t.Fatal("invalid browser unexpectedly started")
		}
		if !strings.Contains(err.Error(), "调试连接建立前退出") {
			t.Fatalf("unexpected failure: %v", err)
		}
	}
	release, err := lockProfile(filepath.Join(cfg.UserData, ".dormsign.lock"))
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestBrowserArgs(t *testing.T) {
	args := strings.Join(browserArgs(store.Defaults(), "C:/profile with spaces"), "\n")
	for _, want := range []string{"--edge-skip-compat-layer-relaunch", "--user-data-dir=C:/profile with spaces", "--remote-debugging-address=127.0.0.1", "about:blank"} {
		if !strings.Contains(args, want) {
			t.Fatal(want)
		}
	}
}

// Opt-in: local about:blank only, never logs in or clicks a sign-in button.
func TestEdgeLifecycle(t *testing.T) {
	if os.Getenv("DORMSIGN_EDGE_TEST") != "1" {
		t.Skip("set DORMSIGN_EDGE_TEST=1 for local Edge smoke test")
	}
	cfg := store.Defaults()
	cfg.UserData = t.TempDir()
	for i := 0; i < 3; i++ {
		s, err := Launch(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(s.Ctx, 5*time.Second)
		var result int
		err = chromedp.Run(ctx, chromedp.Evaluate("1+1", &result))
		cancel()
		if err != nil || result != 2 {
			s.Close()
			t.Fatalf("CDP: %d %v", result, err)
		}
		if duplicate, err := Launch(cfg); err == nil {
			duplicate.Close()
			s.Close()
			t.Fatal("concurrent profile not rejected")
		}
		t.Logf("cycle=%d pid=%d CDP=ok", i+1, s.PID)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Closing and restarting with the same profile verifies lock release.
	ctx, cancel := context.WithCancel(context.Background())
	s, err := LaunchContext(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
