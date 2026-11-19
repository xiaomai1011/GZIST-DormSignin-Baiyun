package applog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewNamedWritesItsOwnFileAndLeavesTheAppLogAlone(t *testing.T) {
	dir := t.TempDir()
	app := New(dir)
	app.Add("签到日志")
	app.Close()

	probe := NewNamed(dir, "session-probe.log")
	probe.Add("探测日志")
	path := probe.Path()
	probe.Close()

	if want := filepath.Join(dir, "session-probe.log"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read probe log: %v", err)
	}
	if !strings.Contains(string(body), "探测日志") {
		t.Fatalf("probe log does not hold its own line: %q", string(body))
	}
	if strings.Contains(string(body), "签到日志") {
		t.Fatalf("probe log must not receive application lines: %q", string(body))
	}

	appBody, err := os.ReadFile(filepath.Join(dir, "dormsign.log"))
	if err != nil {
		t.Fatalf("read app log: %v", err)
	}
	if strings.Contains(string(appBody), "探测日志") {
		t.Fatalf("the application log must not receive probe lines: %q", string(appBody))
	}
}

func TestNewNamedWithEmptyDirStaysInMemory(t *testing.T) {
	l := NewNamed("", "session-probe.log")
	l.Add("内存里")
	if l.Path() != "" {
		t.Fatalf("path = %q, want empty for memory-only logging", l.Path())
	}
}
