// Package applog keeps the last lines in memory for the window and writes
// everything to a size-rotated file.
package applog

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Keep is how many lines stay in memory.
const Keep = 200

// MaxSize is the file size that triggers rotation to <name>.1.
const MaxSize = 1 << 20

// Log is safe for concurrent use.
type Log struct {
	mu       sync.Mutex
	lines    []string
	path     string
	f        *os.File
	size     int64
	now      func() time.Time
	onChange func()
}

// New opens (or creates) dir/dormsign.log. An empty dir keeps logs in
// memory only.
func New(dir string) *Log {
	l := &Log{now: time.Now}
	if dir != "" {
		os.MkdirAll(dir, 0o700)
		l.path = filepath.Join(dir, "dormsign.log")
		l.open()
	}
	return l
}

func (l *Log) open() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	l.f = f
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
}

// Path is the log file, or "" when logging to memory only.
func (l *Log) Path() string { return l.path }

// OnChange registers a callback run (on the logging goroutine) after each
// line.
func (l *Log) OnChange(fn func()) {
	l.mu.Lock()
	l.onChange = fn
	l.mu.Unlock()
}

// Printf adds a line.
func (l *Log) Printf(format string, args ...any) { l.Add(fmt.Sprintf(format, args...)) }

// Add appends one line.
func (l *Log) Add(msg string) {
	t := l.now()
	l.mu.Lock()
	l.lines = append(l.lines, t.Format("15:04:05")+"  "+msg)
	if len(l.lines) > Keep {
		l.lines = append(l.lines[:0:0], l.lines[len(l.lines)-Keep:]...)
	}
	if l.f != nil {
		n, _ := fmt.Fprintf(l.f, "%s  %s\n", t.Format("2006-01-02 15:04:05"), msg)
		l.size += int64(n)
		if l.size > MaxSize {
			l.f.Close()
			os.Rename(l.path, l.path+".1")
			l.size = 0
			l.open()
		}
	}
	fn := l.onChange
	l.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// Lines returns a copy of the recent lines.
func (l *Log) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Close closes the log file; later lines stay in memory only.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
