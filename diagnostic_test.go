package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCloser struct{ err error }

func (f fakeCloser) CloseAll() error { return f.err }

// A cleanup that cannot be confirmed must keep the directory: deleting it would
// destroy the only evidence while the browser may still be running.
func TestSelftestKeepsTheProfileWhenTheCloseFails(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "account")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}

	err := finishSelftestProfile(fakeCloser{err: errors.New("拒绝退出")}, victim)
	if err == nil || !strings.Contains(err.Error(), "拒绝退出") || !strings.Contains(err.Error(), "保留") {
		t.Fatalf("应报告关闭失败并说明保留目录，实得 %v", err)
	}
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Fatalf("清理未确认时目录应保留: %v", statErr)
	}
}

func TestSelftestRemovesTheProfileAfterACleanClose(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "account")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := finishSelftestProfile(fakeCloser{}, victim); err != nil {
		t.Fatalf("干净关闭后应删除目录: %v", err)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatalf("目录应已删除，实得 %v", err)
	}
}
