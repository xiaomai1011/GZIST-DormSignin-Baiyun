package store

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// Individual fake key operations deliberately yield; only Store can keep pairs together.
type concurrentPairKeyring struct {
	mu     sync.Mutex
	values map[string]string
}

func (k *concurrentPairKeyring) Set(_, user, value string) error {
	k.mu.Lock()
	k.values[user] = value
	k.mu.Unlock()
	runtime.Gosched()
	return nil
}
func (k *concurrentPairKeyring) Get(_, user string) (string, error) {
	k.mu.Lock()
	v, ok := k.values[user]
	k.mu.Unlock()
	runtime.Gosched()
	if !ok {
		return "", errors.New("fake credential absent")
	}
	return v, nil
}
func (k *concurrentPairKeyring) Delete(_, user string) error {
	k.mu.Lock()
	delete(k.values, user)
	k.mu.Unlock()
	runtime.Gosched()
	return nil
}
func TestCredentialPairsConcurrentReadWriteDelete(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Keyring: &concurrentPairKeyring{values: make(map[string]string)}}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		workers.Add(1)
		go func(writer int) {
			defer workers.Done()
			<-start
			for n := 0; n < 128; n++ {
				id := fmt.Sprintf("fake-%d-%d", writer, n)
				if insecure, err := s.SetCredentials(id, "password:"+id); err != nil || insecure {
					t.Errorf("fake save insecure=%v err=%v", insecure, err)
					return
				}
			}
		}(writer)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for n := 0; n < 128; n++ {
			s.DeleteCredentials()
		}
	}()
	for reader := 0; reader < 4; reader++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for n := 0; n < 512; n++ {
				id, pass, err := s.Credentials()
				if err != nil {
					t.Error(err)
					return
				}
				if id == "" && pass == "" {
					continue
				}
				if id == "" || pass != "password:"+id {
					t.Errorf("mixed synthetic pair id=%q pass=%q", id, pass)
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	if insecure, err := s.SetCredentials("fake-final", "password:fake-final"); err != nil || insecure {
		t.Fatalf("final save: %v %v", insecure, err)
	}
	if id, pass, err := s.Credentials(); err != nil || id != "fake-final" || pass != "password:fake-final" {
		t.Fatalf("final read: %q %q %v", id, pass, err)
	}
	s.DeleteCredentials()
	if id, pass, err := s.Credentials(); err != nil || id != "" || pass != "" {
		t.Fatalf("deleted pair: %q %q %v", id, pass, err)
	}
}
