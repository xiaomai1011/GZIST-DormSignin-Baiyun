package edge

import (
	"errors"
	"reflect"
	"testing"
)

func TestCloseBarrierAndIdempotence(t *testing.T) {
	var events []string
	done := make(chan error, 1)
	done <- nil
	s := &Session{
		kill:      func() error { events = append(events, "tree-exited"); return nil },
		ctxCancel: func() { events = append(events, "context-canceled") },
		done:      done,
		unlock:    func() { events = append(events, "profile-unlocked") },
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{"tree-exited", "context-canceled", "profile-unlocked"}
	if !reflect.DeepEqual(events, want) {
		t.Fatal(events)
	}
}

func TestCloseFailureRetainsProfileLock(t *testing.T) {
	failure := errors.New("job cleanup failed")
	unlocked := false
	done := make(chan error, 1)
	done <- nil
	s := &Session{kill: func() error { return failure }, done: done, unlock: func() { unlocked = true }}
	if !errors.Is(s.Close(), failure) || !errors.Is(s.Close(), failure) {
		t.Fatal("cleanup error lost")
	}
	if unlocked {
		t.Fatal("profile unlocked without confirmed process-tree exit")
	}
}
