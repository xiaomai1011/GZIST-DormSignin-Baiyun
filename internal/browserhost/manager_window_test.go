package browserhost

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

type windowLookupHost struct {
	status Status
	closes int
}

func (h *windowLookupHost) Status() Status { return h.status }
func (h *windowLookupHost) Alive() bool    { return h.status.Alive }
func (h *windowLookupHost) Close() error   { h.closes++; return nil }

func TestWindowLookupNeverStartsOrRetires(t *testing.T) {
	for _, mode := range []string{"absent", "starting", "broken", "closed", "dial-error", "generation-change", "cancel-dial", "ok"} {
		t.Run(mode, func(t *testing.T) {
			cfg := store.Settings{UserData: filepath.Join(t.TempDir(), "profile")}
			h := &windowLookupHost{status: Status{Alive: true, Generation: 7}}
			e := &managedHost{profile: cfg.UserData, statePath: "unused", host: h}
			m := &Manager{entries: map[string]*managedHost{cfg.UserData: e}}
			starts, dials := 0, 0
			m.start = func(store.Settings, string) (Host, error) { starts++; return nil, errors.New("must not start") }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &Client{}
			m.dial = func(string, string) (*Client, error) {
				dials++
				if mode == "dial-error" {
					return nil, errors.New("discovery failure")
				}
				if mode == "generation-change" {
					h.status.Generation++
				}
				if mode == "cancel-dial" {
					cancel()
				}
				return c, nil
			}
			switch mode {
			case "absent":
				delete(m.entries, cfg.UserData)
			case "starting":
				e.starting = true
			case "broken":
				e.broken = ErrBroken
			case "closed":
				m.closed = true
			}
			got, err := m.GetClient(ctx, cfg)
			if mode == "ok" {
				if err != nil || got != c || c.windowGeneration.Load() != 7 {
					t.Fatalf("lookup failed: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("invalid host accepted")
			}
			if starts != 0 || h.closes != 0 {
				t.Fatalf("lookup has lifecycle effects: starts=%d closes=%d", starts, h.closes)
			}
			if mode == "absent" || mode == "starting" || mode == "broken" || mode == "closed" {
				if dials != 0 {
					t.Fatal("invalid entry reached discovery")
				}
			}
		})
	}
}
