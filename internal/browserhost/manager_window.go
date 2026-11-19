package browserhost

import (
	"context"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// GetClient addresses only an already running host. Unlike Ensure/dialEntry it
// never starts, retires or replaces a browser, even when discovery fails.
func (m *Manager) GetClient(ctx context.Context, cfg store.Settings) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := edge.ProfilePath(cfg)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing || m.closed {
		return nil, ErrManagerClosed
	}
	e := m.entries[profile]
	if e == nil || e.host == nil {
		return nil, ErrNoDaemon
	}
	if e.starting {
		return nil, ErrNotReady
	}
	if e.broken != nil {
		return nil, e.broken
	}
	st := e.host.Status()
	if !st.Alive || st.Closing || st.Revoking || st.Generation == 0 {
		return nil, ErrNotReady
	}
	if st.Broken != "" {
		return nil, ErrBroken
	}
	// Dial reads discovery metadata only, not the browser or credentials.
	c, err := m.dial(e.statePath, profile)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	after := e.host.Status()
	if !after.Alive || after.Closing || after.Revoking || after.Generation != st.Generation || after.Broken != "" {
		return nil, ErrRevoked
	}
	c.windowGeneration.Store(st.Generation)
	return c, nil
}
