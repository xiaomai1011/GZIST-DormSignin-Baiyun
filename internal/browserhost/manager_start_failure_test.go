package browserhost

import (
	"path/filepath"
	"testing"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

func TestProductionStartFailureHasNoTypedNilHost(t *testing.T) {
	dir := t.TempDir()
	cfg := store.Settings{EdgePath: filepath.Join(dir, "missing-edge.exe"), UserData: filepath.Join(dir, "profile")}
	m := NewManager(false)
	host, err := m.start(cfg, filepath.Join(dir, "state.json"))
	if err == nil || host != nil {
		t.Fatalf("startup failure must return nil Host: host=%T err=%v", host, err)
	}
	// Exercise the actual late-start branch with production failure, not a fake
	// returning an untyped nil. It must signal completion without calling a nil Daemon.
	m.closing = true
	entry := &managedHost{profile: cfg.UserData, statePath: filepath.Join(dir, "state.json"), starting: true, ready: make(chan struct{})}
	m.runStart(entry, cfg)
	select {
	case <-entry.ready:
	default:
		t.Fatal("failed late start did not complete")
	}
	if entry.startErr == nil || entry.host != nil || entry.broken != nil || m.closeErr != nil {
		t.Fatalf("unexpected late failure state: start=%v broken=%v close=%v", entry.startErr, entry.broken, m.closeErr)
	}
}
