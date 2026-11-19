package browserhost

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// ErrSwitchBusy is returned when the application asks to move the resident
// browser to another account while a task still holds a lease. The switch is
// refused rather than queued: a running task must never find itself driving a
// browser that now belongs to a different account.
var ErrSwitchBusy = errors.New("常驻浏览器仍有任务在运行，暂不能切换账号")

// ErrManagerClosed is returned once CloseAll has begun: no new host may be
// started while the application is leaving, because a browser started after the
// sweep would be outside anyone's accounting.
var ErrManagerClosed = errors.New("常驻浏览器管理器正在关闭或已关闭")

// managerStartWait bounds how long CloseAll waits for a start that is already
// in flight. Exiting must be bounded even if a browser refuses to come up.
const managerStartWait = 30 * time.Second

// Host is the part of the daemon the manager needs. It exists so the lifecycle
// can be tested without Edge, while production always uses *Daemon.
type Host interface {
	Alive() bool
	Status() Status
	Close() error
}

// Manager owns the resident hosts of the running application: one host per
// account profile, started on demand, kept between tasks, and closed when the
// application exits or the account changes. It never falls back to a private
// browser; callers treat an Ensure error as "this run does not happen".
//
// A host that fails to close is never replaced: the record stays with the
// failure so a later run reports it instead of quietly starting a second
// browser next to the one that may still be running.
type Manager struct {
	mu      sync.Mutex
	entries map[string]*managedHost
	start   func(cfg store.Settings, statePath string) (Host, error)
	dial    func(statePath, profile string) (*Client, error)

	closing  bool
	closed   bool
	closeCh  chan struct{}
	closeErr error

	// startWait bounds how long CloseAll waits for an in-flight start. It is a
	// field so tests can use a short budget instead of sleeping for 30s.
	startWait time.Duration
}

type managedHost struct {
	host      Host
	statePath string
	profile   string

	// starting is true while a start or a close is in flight. ready is closed
	// when that operation finishes; startErr carries a failed start.
	starting bool
	ready    chan struct{}
	startErr error

	// broken keeps a close failure. While it is set the entry must neither be
	// replaced nor forgotten.
	broken error
}

// NewManager returns a manager whose hosts own their profile directory and
// delete it on close (the profile is created per account by the application).
func NewManager(cleanupProfile bool) *Manager {
	m := &Manager{entries: make(map[string]*managedHost), dial: Dial, startWait: managerStartWait}
	m.start = func(cfg store.Settings, statePath string) (Host, error) {
		d, err := Start(context.Background(), cfg, statePath, cleanupProfile)
		// A nil *Daemon converted directly to Host is a non-nil interface.
		// In-flight startup failure during CloseAll must not call Close on it.
		if d == nil {
			return nil, err
		}
		return d, err
	}
	return m
}

// NewManagerWithHooks builds a manager with injected start and dial functions.
// The application tests use it to exercise the real account and mode
// transitions without launching Edge or opening a CDP connection.
func NewManagerWithHooks(start func(cfg store.Settings, statePath string) (Host, error), dial func(statePath, profile string) (*Client, error)) *Manager {
	m := NewManager(false)
	if start != nil {
		m.start = start
	}
	if dial != nil {
		m.dial = dial
	}
	return m
}

// Ensure returns a client for cfg's account, starting its host if none is
// alive. The caller's context bounds the wait: a cancelled task stops waiting
// for a slow start. The browser itself is owned by the manager, so a start that
// was already in flight still completes and stays accounted for.
func (m *Manager) Ensure(ctx context.Context, cfg store.Settings) (*Client, error) {
	profile, err := edge.ProfilePath(cfg)
	if err != nil {
		return nil, err
	}
	statePath := filepath.Join(profile, StateFileName)

	for {
		m.mu.Lock()
		if m.closing || m.closed {
			m.mu.Unlock()
			return nil, ErrManagerClosed
		}
		entry := m.entries[profile]
		if entry == nil {
			entry = &managedHost{statePath: statePath, profile: profile, starting: true, ready: make(chan struct{})}
			m.entries[profile] = entry
			m.mu.Unlock()
			go m.runStart(entry, cfg)
			return m.awaitStart(ctx, entry)
		}
		if entry.broken != nil {
			broken := entry.broken
			m.mu.Unlock()
			return nil, fmt.Errorf("常驻宿主上次清理失败，已停止替换: %w", broken)
		}
		if entry.starting {
			ready := entry.ready
			m.mu.Unlock()
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if !entry.host.Alive() {
			// The dead host must close cleanly before a replacement starts; a
			// close failure keeps the record and stops the run.
			entry.starting = true
			entry.ready = make(chan struct{})
			m.mu.Unlock()
			if err := m.retire(profile, entry); err != nil {
				return nil, fmt.Errorf("常驻宿主无法关闭，已保留记录并停止替换: %w", err)
			}
			continue
		}
		m.mu.Unlock()
		return m.dialEntry(profile, entry)
	}
}

// runStart performs the start outside the manager lock so CloseAll and other
// accounts are not blocked by a slow browser launch.
func (m *Manager) runStart(entry *managedHost, cfg store.Settings) {
	host, err := m.start(cfg, entry.statePath)

	m.mu.Lock()
	if m.closing || m.closed {
		// CloseAll swept the map while this start was in flight and may have
		// stopped waiting for it. A host that appears now must never become
		// usable or keep running unaccounted: close it here, and join a close
		// failure into the sticky close result so repeated closes keep
		// reporting it.
		entry.startErr = err
		m.mu.Unlock()

		// The ready channel is the completion barrier for "this start is done":
		// whoever waits on it (CloseAll, Ensure) may delete a profile as soon as
		// it fires. Closing the host first and only then signalling means a slow
		// or failing close is still inside the barrier instead of arriving after
		// the caller already reported success.
		var closeErr error
		if host != nil {
			closeErr = host.Close()
		}

		m.mu.Lock()
		entry.host = nil
		entry.starting = false
		if closeErr != nil {
			entry.broken = closeErr
			m.closeErr = errors.Join(m.closeErr, fmt.Errorf("迟到的常驻宿主关闭失败（%s）: %w", entry.profile, closeErr))
		}
		close(entry.ready)
		m.mu.Unlock()
		return
	}
	entry.host = host
	entry.startErr = err
	entry.starting = false
	if err != nil && m.entries[entry.profile] == entry {
		delete(m.entries, entry.profile)
	}
	close(entry.ready)
	m.mu.Unlock()
}

// awaitStart waits for a start this call initiated, honouring cancellation.
func (m *Manager) awaitStart(ctx context.Context, entry *managedHost) (*Client, error) {
	select {
	case <-entry.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if entry.startErr != nil {
		return nil, entry.startErr
	}
	m.mu.Lock()
	closed := m.closing || m.closed
	m.mu.Unlock()
	if closed {
		// CloseAll swept the entries while this start was in flight; the sweep
		// waited for it, so reporting the close keeps the caller from driving a
		// browser nobody owns.
		return nil, ErrManagerClosed
	}
	return m.dialEntry(entry.profile, entry)
}

// dialEntry builds the client for a live host. A dial failure retires the host;
// if that close also fails, both errors are returned and the record stays.
func (m *Manager) dialEntry(profile string, entry *managedHost) (*Client, error) {
	client, err := m.dial(entry.statePath, profile)
	if err == nil {
		return client, nil
	}

	m.mu.Lock()
	if m.entries[profile] != entry || entry.starting {
		m.mu.Unlock()
		return nil, err
	}
	entry.starting = true
	entry.ready = make(chan struct{})
	m.mu.Unlock()

	if closeErr := m.retire(profile, entry); closeErr != nil {
		return nil, errors.Join(err, fmt.Errorf("关闭无法连接的常驻宿主失败，记录保留: %w", closeErr))
	}
	return nil, err
}

// retire closes an entry whose start/close was already announced by setting
// starting=true and a fresh ready channel. On failure the entry is kept with
// broken set; on success it is removed.
func (m *Manager) retire(profile string, entry *managedHost) error {
	var err error
	if entry.host != nil {
		err = entry.host.Close()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	entry.host = nil
	entry.starting = false
	if err != nil {
		entry.broken = err
	} else if m.entries[profile] == entry {
		delete(m.entries, profile)
	}
	close(entry.ready)
	return err
}

// Switch moves the resident browser to cfg's account. It refuses while any
// host still has a task, and it refuses once the manager is closing.
func (m *Manager) Switch(cfg store.Settings) error {
	profile, err := edge.ProfilePath(cfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.closing || m.closed {
		m.mu.Unlock()
		return ErrManagerClosed
	}
	var keys []string
	var entries []*managedHost
	for key, entry := range m.entries {
		if key == profile {
			continue
		}
		if entry.broken != nil {
			broken := entry.broken
			m.mu.Unlock()
			return fmt.Errorf("旧账号常驻宿主清理失败，不能切换: %w", broken)
		}
		if entry.starting {
			m.mu.Unlock()
			return fmt.Errorf("%w: 宿主正在启动", ErrSwitchBusy)
		}
		if entry.host != nil && entry.host.Status().Leased {
			m.mu.Unlock()
			return fmt.Errorf("%w: %s", ErrSwitchBusy, strings.TrimSpace(entry.profile))
		}
		keys = append(keys, key)
		entries = append(entries, entry)
	}
	// Only after every host passed the checks above do we mark them busy: a
	// refusal must leave the other accounts exactly as they were.
	for _, entry := range entries {
		entry.starting = true
		entry.ready = make(chan struct{})
	}
	m.mu.Unlock()

	var errs []error
	for i, entry := range entries {
		if err := m.retire(keys[i], entry); err != nil {
			errs = append(errs, fmt.Errorf("关闭旧账号常驻浏览器失败：%w", err))
		}
	}
	return errors.Join(errs...)
}

// CloseAll closes every host and joins the errors. It is safe to call twice and
// concurrently: every caller shares the same completion and the same result.
// Once it starts, Ensure and Switch are refused, so no host can appear after the
// sweep.
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	if m.closed {
		ch, err := m.closeCh, m.closeErr
		m.mu.Unlock()
		<-ch
		return err
	}
	if m.closing {
		ch := m.closeCh
		m.mu.Unlock()
		<-ch
		m.mu.Lock()
		err := m.closeErr
		m.mu.Unlock()
		return err
	}
	m.closing = true
	m.closeCh = make(chan struct{})
	wait := m.startWait
	if wait <= 0 {
		wait = managerStartWait
	}
	entries := m.entries
	m.entries = make(map[string]*managedHost)
	m.mu.Unlock()

	var errs []error
	for _, entry := range entries {
		// Take the entry's state under the lock: a start may be publishing its
		// host right now, and reading entry.host outside the lock would race
		// with that write (and could miss the host entirely).
		m.mu.Lock()
		if entry.starting {
			ready := entry.ready
			m.mu.Unlock()
			select {
			case <-ready:
			case <-time.After(wait):
				errs = append(errs, fmt.Errorf("等待常驻宿主启动结束超时: %s", entry.profile))
				continue
			}
			m.mu.Lock()
		}
		broken := entry.broken
		host := entry.host
		entry.host = nil
		entry.starting = false
		profile := entry.profile
		m.mu.Unlock()

		if broken != nil {
			// A previous retire already failed: the browser may still be
			// running and was never confirmed closed. Reporting success here
			// would let the caller delete a profile that is still in use.
			errs = append(errs, fmt.Errorf("%s: 上次清理失败仍未确认: %w", profile, broken))
			continue
		}
		if host == nil {
			continue
		}
		if err := host.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", profile, err))
		}
	}
	err := errors.Join(errs...)

	m.mu.Lock()
	// A late start may have recorded its own close failure while the sweep was
	// running; join it instead of overwriting it with this sweep's result.
	err = errors.Join(err, m.closeErr)
	m.closeErr = err
	m.closed = true
	m.closing = false
	close(m.closeCh)
	m.mu.Unlock()
	return err
}

// Hosts returns how many hosts are currently registered; used by tests and
// diagnostics only.
func (m *Manager) Hosts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
