package edge

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// These cover the shutdown contract without a browser: the session asks the
// browser to close itself first, stays inside one budget, and always ends with
// the Job reaper proving the tree is gone before the profile lock is released.

func fakeSession(done chan error, kill func() error, unlock func()) *Session {
	return &Session{
		Ctx:    context.Background(),
		done:   done,
		kill:   kill,
		unlock: unlock,
	}
}

func withGracefulBudget(t *testing.T, budget time.Duration) {
	t.Helper()
	old := gracefulCloseBudget
	gracefulCloseBudget = budget
	t.Cleanup(func() { gracefulCloseBudget = old })
}

func withGracefulHook(t *testing.T, hook func(context.Context) error) *int32 {
	t.Helper()
	var calls int32
	old := gracefulCloseHook
	gracefulCloseHook = func(ctx context.Context) error {
		atomic.AddInt32(&calls, 1)
		return hook(ctx)
	}
	t.Cleanup(func() { gracefulCloseHook = old })
	return &calls
}

func TestCloseAsksTheBrowserToCloseBeforeReaping(t *testing.T) {
	done := make(chan error, 1)
	var kills, unlocks int32
	calls := withGracefulHook(t, func(ctx context.Context) error {
		done <- nil // the browser really exited
		return errors.New("websocket: close 1001 (going away)")
	})
	s := fakeSession(done, func() error { atomic.AddInt32(&kills, 1); return nil }, func() { atomic.AddInt32(&unlocks, 1) })

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Fatalf("browser-level close calls = %d, want 1", n)
	}
	if n := atomic.LoadInt32(&kills); n != 1 {
		t.Fatalf("reaper calls = %d, want 1 (it proves the tree is gone)", n)
	}
	if n := atomic.LoadInt32(&unlocks); n != 1 {
		t.Fatalf("unlock calls = %d, want 1", n)
	}
}

func TestCloseFallsBackToTheReaperWhenTheBrowserIgnoresIt(t *testing.T) {
	withGracefulBudget(t, 60*time.Millisecond)
	done := make(chan error, 1)
	var unlocks int32
	blocked := make(chan struct{})
	defer close(blocked)
	withGracefulHook(t, func(ctx context.Context) error {
		// Ignores the browser's fate, but still ends with the budget so the
		// goroutine cannot outlive the test.
		select {
		case <-blocked:
		case <-ctx.Done():
		}
		return nil
	})
	s := fakeSession(done, func() error {
		done <- nil // the reaper killed the tree
		return nil
	}, func() { atomic.AddInt32(&unlocks, 1) })

	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("close waited %s; the graceful attempt must stay inside its budget", elapsed)
	}
	if n := atomic.LoadInt32(&unlocks); n != 1 {
		t.Fatalf("unlock calls = %d, want 1 after the reaper confirmed the exit", n)
	}
}

func TestCloseKeepsTheLockWhenTheReaperCannotConfirmTheExit(t *testing.T) {
	done := make(chan error, 1)
	var unlocks int32
	withGracefulHook(t, func(ctx context.Context) error { done <- nil; return nil })
	s := fakeSession(done, func() error { return errors.New("Edge job exit barrier timed out") }, func() { atomic.AddInt32(&unlocks, 1) })

	err := s.Close()
	if err == nil {
		t.Fatal("close must report that cleanup could not be proven")
	}
	if n := atomic.LoadInt32(&unlocks); n != 0 {
		t.Fatalf("unlock calls = %d, want 0: an unproven cleanup must keep the profile lock", n)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	done := make(chan error, 1)
	var kills, unlocks int32
	calls := withGracefulHook(t, func(ctx context.Context) error { done <- nil; return nil })
	s := fakeSession(done, func() error { atomic.AddInt32(&kills, 1); return errors.New("reaper failed") }, func() { atomic.AddInt32(&unlocks, 1) })

	first := s.Close()
	second := s.Close()
	if first == nil || second == nil {
		t.Fatal("both calls must report the same cleanup failure")
	}
	if first.Error() != second.Error() {
		t.Fatalf("second close = %q, want the same error as %q", second, first)
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Fatalf("browser-level close calls = %d, want 1", n)
	}
	if n := atomic.LoadInt32(&kills); n != 1 {
		t.Fatalf("reaper calls = %d, want 1", n)
	}
	if n := atomic.LoadInt32(&unlocks); n != 0 {
		t.Fatalf("unlock calls = %d, want 0", n)
	}
}

func TestCloseWithoutACDPSessionSkipsTheGracefulStep(t *testing.T) {
	done := make(chan error, 1)
	calls := withGracefulHook(t, func(ctx context.Context) error { return nil })
	s := &Session{done: done, kill: func() error { done <- nil; return nil }, unlock: func() {}}

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("browser-level close calls = %d, want 0 when no CDP session exists", n)
	}
}
