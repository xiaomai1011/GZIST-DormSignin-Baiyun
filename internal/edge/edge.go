// Package edge owns a dedicated browser process tree and connects chromedp to it.
package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

const pcUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0"

// Session owns Edge's complete process tree (a kill-on-close Job on Windows).
type Session struct {
	Ctx         context.Context
	PID         int
	UserData    string
	once        sync.Once
	kill        func() error
	closeErr    error
	unlock      func()
	done        chan error
	outputDone  chan struct{}
	pipe        io.Closer
	ctxCancel   context.CancelFunc
	allocCancel context.CancelFunc
}

func ProfilePath(cfg store.Settings) (string, error) {
	if strings.TrimSpace(cfg.UserData) == "" {
		return "", fmt.Errorf("浏览器数据目录不能为空")
	}
	p := cfg.UserData
	if !filepath.IsAbs(p) {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		p = filepath.Join(filepath.Dir(exe), p)
	}
	return filepath.Abs(p)
}

func browserArgs(cfg store.Settings, profile string) []string {
	return []string{
		"--headless", "--hide-scrollbars", "--mute-audio", "--no-first-run", "--no-default-browser-check",
		// Edge may otherwise relaunch through its compatibility shim and disconnect
		// stdout from the actual browser. Keep the managed process as the real root.
		"--edge-skip-compat-layer-relaunch",
		"--disable-background-networking", "--enable-features=NetworkService,NetworkServiceInProcess",
		"--disable-background-timer-throttling", "--disable-backgrounding-occluded-windows",
		"--disable-breakpad", "--disable-client-side-phishing-detection", "--disable-default-apps",
		"--disable-dev-shm-usage", "--disable-extensions", "--disable-features=Translate",
		"--disable-hang-monitor", "--disable-ipc-flooding-protection", "--disable-popup-blocking",
		"--disable-prompt-on-repost", "--disable-renderer-backgrounding", "--disable-sync",
		"--force-color-profile=srgb", "--metrics-recording-only", "--safebrowsing-disable-auto-update",
		"--enable-automation", "--password-store=basic", "--use-mock-keychain",
		"--disable-http2", "--no-proxy-server", "--force-device-scale-factor=1",
		"--user-data-dir=" + profile, "--user-agent=" + pcUA,
		fmt.Sprintf("--window-size=%d,%d", cfg.ViewW, cfg.ViewH),
		"--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "about:blank",
	}
}

func Launch(cfg store.Settings) (*Session, error) { return LaunchContext(context.Background(), cfg) }

// LaunchContext respects cancellation without giving the browser's lifetime a
// startup deadline. The 45s startup guard is external to its chromedp context.
func LaunchContext(parent context.Context, cfg store.Settings) (*Session, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(cfg.EdgePath); err != nil {
		return nil, fmt.Errorf("找不到 Edge: %s: %w", cfg.EdgePath, err)
	}
	profile, err := ProfilePath(cfg)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(profile, 0700); err != nil {
		return nil, err
	}
	unlock, err := lockProfile(filepath.Join(profile, ".dormsign.lock"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(cfg.EdgePath, browserArgs(cfg, profile)...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		unlock()
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	kill, err := startOwnedProcess(cmd)
	if err != nil {
		pipe.Close()
		unlock()
		return nil, fmt.Errorf("启动 Edge 失败（profile=%s）: %w", profile, err)
	}
	s := &Session{PID: cmd.Process.Pid, UserData: profile, kill: kill, unlock: unlock, done: make(chan error, 1), outputDone: make(chan struct{}), pipe: pipe}
	// Wait only after the reader sees EOF; exec.Wait must not close StdoutPipe
	// underneath an active reader. Close kills the whole job to force EOF.
	endpoint := make(chan string, 1)
	var output tailOutput
	go func() { defer close(s.outputDone); scanEndpoint(pipe, endpoint, &output) }()
	go func() { <-s.outputDone; s.done <- waitOwnedProcess(cmd) }()
	fail := func(e error) (*Session, error) {
		e = errors.Join(e, s.Close())
		return nil, fmt.Errorf("启动 Edge 失败（pid=%d, profile=%s）: %w; 输出: %s", s.PID, profile, e, output.String())
	}
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	var ws string
	select {
	case ws = <-endpoint:
	case err = <-s.done:
		// Preserve the completion token for Close.
		s.done <- err
		return fail(fmt.Errorf("浏览器在调试连接建立前退出: %v", err))
	case <-parent.Done():
		return fail(parent.Err())
	case <-timer.C:
		return fail(fmt.Errorf("45 秒内未就绪"))
	}
	allocCtx, allocCancel := chromedp.NewRemoteAllocator(parent, ws, chromedp.NoModifyURL)
	ctx, ctxCancel := chromedp.NewContext(allocCtx)
	s.Ctx = ctx
	s.ctxCancel = ctxCancel
	s.allocCancel = allocCancel
	started := make(chan error, 1)
	go func() { started <- chromedp.Run(ctx) }()
	select {
	case err = <-started:
		if err != nil {
			return fail(err)
		}
	case <-parent.Done():
		return fail(parent.Err())
	case <-timer.C:
		return fail(fmt.Errorf("45 秒内未建立 CDP 会话"))
	}
	return s, nil
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		// On Windows kill also waits for every Job member to exit, not just the
		// browser root. Never unlock a profile still owned by surviving children.
		if s.kill != nil {
			s.closeErr = s.kill()
		}
		if s.pipe != nil {
			s.pipe.Close()
		}
		if s.ctxCancel != nil {
			s.ctxCancel()
		}
		if s.allocCancel != nil {
			s.allocCancel()
		}
		if s.done != nil {
			select {
			case <-s.done: // Forced termination has an expected nonzero exit code.
			case <-time.After(5 * time.Second):
				s.closeErr = errors.Join(s.closeErr, fmt.Errorf("等待 Edge 根进程退出超时"))
			}
		}
		if s.unlock != nil && s.closeErr == nil {
			s.unlock()
		}
		// If cleanup could not be proven complete, keep our OS profile lock
		// until this application exits rather than allowing another unsafe run.
	})
	return s.closeErr
}

// Keep draining stderr after DevTools appears; bounded storage prevents log growth.
type tailOutput struct {
	mu   sync.Mutex
	text string
}

func (b *tailOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.text += string(p)
	if len(b.text) > 8192 {
		b.text = b.text[len(b.text)-8192:]
	}
	return len(p), nil
}
func (b *tailOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.text)
}
func scanEndpoint(r io.Reader, endpoints chan<- string, out *tailOutput) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		out.Write([]byte(line + "\n"))
		if !found && strings.HasPrefix(line, "DevTools listening on ") {
			ws := strings.TrimSpace(strings.TrimPrefix(line, "DevTools listening on "))
			if strings.HasPrefix(ws, "ws://127.0.0.1:") || strings.HasPrefix(ws, "ws://localhost:") || strings.HasPrefix(ws, "ws://[::1]:") {
				endpoints <- ws
				found = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		out.Write([]byte(err.Error()))
	}
}

// DataURLScreenshotJS extracts a captcha image without changing the page.
const DataURLScreenshotJS = `(function(sel){
  var img = sel ? document.querySelector(sel) : null;
  if (!img) { [].some.call(document.querySelectorAll('img'), function(el){
      var s = el.src||''; if (s.indexOf('data:image')===0) { img = el; return true; } return false; }); }
  if (!img) return null;
  if (!img.naturalWidth) return 'WAIT';
  var c=document.createElement('canvas'); var s=4;
  c.width=img.naturalWidth*s; c.height=img.naturalHeight*s;
  var ctx=c.getContext('2d'); ctx.imageSmoothingEnabled=false;
  ctx.drawImage(img,0,0,c.width,c.height);
  try { return c.toDataURL('image/png'); } catch(e) { return 'ERR:'+e.message; }
})(%q)`
