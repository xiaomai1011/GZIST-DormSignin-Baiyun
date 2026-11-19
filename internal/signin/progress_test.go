package signin

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The business-page wait used to be silent: a run inside it could only be
// described from the line before it started. These tests pin down that the
// wait now reports what it sees, that the reports never extend the budget, and
// that a report carries no URL the log must not keep.

func TestWaitBusinessPageReportsProgressAndKeepsTheBudget(t *testing.T) {
	var elapsedSeen []time.Duration
	var snapshots []pageState
	opts := waitOptions{
		budget:        60 * time.Millisecond,
		poll:          time.Millisecond,
		progressEvery: 10 * time.Millisecond,
		progress: func(elapsed time.Duration, s pageState, repaired bool, readErr error) {
			elapsedSeen = append(elapsedSeen, elapsed)
			snapshots = append(snapshots, s)
		},
	}
	notReady := pageState{URL: "http://xsfw.gzist.edu.cn/#/xscq/grcq", Text: "正在加载"}

	start := time.Now()
	_, elapsed, err := waitBusinessPageWith(context.Background(), opts,
		func(context.Context) (pageState, error) { return notReady, nil },
		func(context.Context) error { return nil })
	wall := time.Since(start)

	if err == nil {
		t.Fatal("a page that never becomes ready must still end as a timeout failure")
	}
	// The budget is the only thing that ends this wait: progress reporting may
	// not stretch it.
	if wall > 10*opts.budget {
		t.Fatalf("wait took %v for a %v budget: reporting must not extend it", wall, opts.budget)
	}
	if elapsed > 10*opts.budget {
		t.Fatalf("reported elapsed = %v for a %v budget", elapsed, opts.budget)
	}
	if len(elapsedSeen) < 2 {
		t.Fatalf("progress reports = %d, want at least 2 while the page stays unready", len(elapsedSeen))
	}
	for i := 1; i < len(elapsedSeen); i++ {
		if elapsedSeen[i] < elapsedSeen[i-1] {
			t.Fatalf("progress elapsed went backwards: %v then %v", elapsedSeen[i-1], elapsedSeen[i])
		}
	}
	for _, s := range snapshots {
		if s.Text != notReady.Text {
			t.Fatalf("progress snapshot text = %q, want the page's own text", s.Text)
		}
	}
}

func TestWaitBusinessPageProgressSurfacesReadErrors(t *testing.T) {
	var readErrs []error
	opts := waitOptions{
		budget:        30 * time.Millisecond,
		poll:          time.Millisecond,
		progressEvery: 5 * time.Millisecond,
		progress: func(_ time.Duration, _ pageState, _ bool, readErr error) {
			readErrs = append(readErrs, readErr)
		},
	}
	broken := errors.New("cdp: connection closed")
	if _, _, err := waitBusinessPageWith(context.Background(), opts,
		func(context.Context) (pageState, error) { return pageState{}, broken },
		func(context.Context) error { return nil },
	); err == nil {
		t.Fatal("a failing probe must still end the wait as a failure")
	}
	if len(readErrs) == 0 {
		t.Fatal("no progress report while the page could not be read")
	}
	for _, e := range readErrs {
		if e == nil || !strings.Contains(e.Error(), "connection closed") {
			t.Fatalf("progress read error = %v, want the probe's own error", e)
		}
	}
}

func TestStep6ProgressLineCarriesNoQueryOrTicket(t *testing.T) {
	var lines []string
	r := &Runner{Log: func(s string) { lines = append(lines, s) }}
	s := pageState{
		URL:  "https://xsfw.gzist.edu.cn/index.do?ticket=ST-123456-abcdef#/xscq/grcq",
		Text: strings.Repeat("x", 42) + "查寝时间段",
	}
	r.step6Progress(32*time.Second, s, false, nil)
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(lines))
	}
	line := lines[0]
	for _, bad := range []string{"ticket", "ST-", "123456", "index.do?"} {
		if strings.Contains(line, bad) {
			t.Fatalf("progress line leaks %q: %s", bad, line)
		}
	}
	wants := []string{"已等待 32s", "页面=business", "文本长度=" + strconv.Itoa(len(s.Text)), "查寝文本=true", "点击签到=false"}
	for _, want := range wants {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line missing %q: %s", want, line)
		}
	}
}

func TestStep6ProgressLineReportsReadError(t *testing.T) {
	var lines []string
	r := &Runner{Log: func(s string) { lines = append(lines, s) }}
	r.step6Progress(time.Second, pageState{}, false, errors.New("cdp: target closed"))
	// Read errors are classified, not echoed: the log keeps a fixed token so no
	// page or transport detail (and nothing a URL could carry) reaches the file.
	if len(lines) != 1 || !strings.Contains(lines[0], "最近读取错误=operation-failed") {
		t.Fatalf("progress line = %v, want the classified read error", lines)
	}
	if strings.Contains(lines[0], "target closed") {
		t.Fatalf("progress line echoes the raw error: %s", lines[0])
	}
}
