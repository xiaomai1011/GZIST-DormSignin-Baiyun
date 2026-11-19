// Package browserhost implements an offline prototype of a resident browser:
// one small daemon process owns Edge for the whole desktop session, and short
// lived sign-in tasks rent it over loopback instead of starting a browser each
// time. It is deliberately not wired into main: nothing here runs in
// production, and the only pages the tests touch are served from 127.0.0.1.
package browserhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

var (
	// ErrNoDaemon means the state file is missing or unusable.
	ErrNoDaemon = errors.New("没有正在运行的长驻浏览器")
	// ErrBusy means another task held the browser for the whole wait.
	ErrBusy = errors.New("浏览器正被其它任务占用")
	// ErrClosed means the daemon is shutting down.
	ErrClosed = errors.New("长驻浏览器已关闭")
	// ErrBroken means the daemon could not prove that the previous task lost
	// access, so it refuses to hand the browser to anybody else.
	ErrBroken = errors.New("长驻浏览器状态不可信，已停止派发")
	// ErrRevoked means the start a caller waited for was revoked before the
	// lease could be handed out.
	ErrRevoked = errors.New("启动已被撤销")
	// ErrStaleLease means the id belongs to an older or already finished lease.
	ErrStaleLease = errors.New("租约已失效或不属于该编号")
	// ErrBadLeaseToken means the confirmation credential does not match.
	ErrBadLeaseToken = errors.New("租约凭据不匹配")
	// ErrConfirmExpired means the reservation was not confirmed inside its
	// activation window and has been reclaimed.
	ErrConfirmExpired = errors.New("确认窗口已过，预约已回收")
	// ErrLeaseExpired means the lease's own deadline has passed, whether or not
	// the TTL timer already ran. A timer is an optimisation, never the rule.
	ErrLeaseExpired = errors.New("租约已到期")
	// ErrNotReady means the browser is still starting; no reservation is
	// announced in this state.
	ErrNotReady = errors.New("浏览器尚未就绪")
	// ErrWrongProfile means the discovered host belongs to a different account
	// profile than the one this run is configured for.
	ErrWrongProfile = errors.New("宿主不属于本账号")
)

// leasePhase is the reservation state machine: a reservation nobody confirmed
// must never be able to look like an issued lease.
type leasePhase int

const (
	leaseNone     leasePhase = iota
	leaseReserved            // slot taken, browser starting, no credentials sent
	leaseAwaiting            // credentials handed out, waiting for confirmation
	leaseActive              // confirmed: the endpoint is or may be in use
)

// Task is one unit of browser work; the context is a tab inside the daemon's
// browser, not a new browser process.
type Task func(ctx context.Context) error

// StateFileName is the discovery file name; the host writes it inside the
// account's own profile directory.
const StateFileName = ".browserhost-state.json"

// State is what the daemon publishes for clients. It deliberately carries no
// CDP endpoint: the address is only handed out by a successful confirmation, so
// a client that merely read the discovery file cannot drive the browser.
type State struct {
	PID      int    `json:"pid"`
	UserData string `json:"userData"`
	LeaseURL string `json:"leaseUrl"`
	Token    string `json:"token"`
}

// Status is the daemon's own view, used by tests and diagnostics.
type Status struct {
	Generation uint64 `json:"generation"`
	PID        int    `json:"pid"`
	UserData   string `json:"userData"`
	Launches   int    `json:"launches"`
	Tasks      int    `json:"tasks"`
	Alive      bool   `json:"alive"`
	Control    bool   `json:"control"` // the host's own CDP session is still usable
	Leased     bool   `json:"leased"`
	Revoking   bool   `json:"revoking"`
	Closing    bool   `json:"closing"`
	Broken     string `json:"broken,omitempty"`
}

// Daemon owns the browser and the lease API.
type Daemon struct {
	cfg            store.Settings
	statePath      string
	cleanupProfile bool
	ownedProfile   string // set only when this daemon created the directory

	srv *http.Server
	ln  net.Listener

	hostCtx    context.Context // lifetime of the browser's CDP control session
	hostCancel context.CancelFunc

	mu      sync.Mutex
	session *edge.Session
	window  hostWindow // bound to session; guarded by mu
	// sessionGen identifies the browser instance a lease was handed against.
	// A confirmation only succeeds while the generation it was announced under
	// is still installed, so a revocation plus relaunch cannot let an old
	// confirmation reach the new browser.
	sessionGen uint64
	launches   int
	tasks      int
	revoking   bool
	broken     string
	closing    bool
	closed     bool
	closeErr   error

	sem chan struct{} // capacity 1: the exclusive browser lease

	launchMu sync.Mutex // guards inflight; lock order: launchMu → mu
	inflight *launchOp

	// stopMu serializes teardowns so a TTL revocation and a Close can never
	// both take the resident session and mistake "nil" for "cleaned up".
	// cleanupErr keeps the first teardown failure for the life of the daemon:
	// a failed exit must not be forgotten when d.inflight is cleared, or a
	// later Close would report success and delete a profile still in use.
	stopMu     sync.Mutex
	cleanupErr error

	leaseMu    sync.Mutex // guards the lease identity, deadline and timer
	leaseSeq   uint64
	leaseID    uint64
	leaseToken string
	leasePhase leasePhase
	leaseUntil time.Time
	leaseGen   uint64 // browser generation this lease was announced against
	leaseTimer *time.Timer
	// confirm* cover only the activation handshake. The window starts when the
	// reservation is announced, never when the browser starts, so a slow launch
	// cannot eat the time the client has to confirm.
	confirmUntil  time.Time
	confirmTimer  *time.Timer
	confirmWindow time.Duration
	expiring      bool

	done       chan struct{} // closed when shutdown starts
	doneOnce   sync.Once
	refuse     chan struct{} // closed when the daemon fails closed
	refuseOnce sync.Once
	once       sync.Once
	token      string
}

// Start launches the browser and serves the lease API on loopback. When
// cleanupProfile is true the daemon creates its own throwaway profile under the
// OS temp directory and is the only party allowed to delete it; a caller
// supplied directory is never deleted.
func Start(ctx context.Context, cfg store.Settings, statePath string, cleanupProfile bool) (*Daemon, error) {
	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	hostCtx, hostCancel := context.WithCancel(context.Background())
	d := &Daemon{
		cfg:            cfg,
		statePath:      statePath,
		cleanupProfile: cleanupProfile,
		sem:            make(chan struct{}, 1),
		done:           make(chan struct{}),
		refuse:         make(chan struct{}),
		token:          tok,
		hostCtx:        hostCtx,
		hostCancel:     hostCancel,
	}
	if cleanupProfile {
		dir, err := os.MkdirTemp("", "dormsign-browserhost-")
		if err != nil {
			return nil, d.failStart(err)
		}
		d.ownedProfile = dir
		d.cfg.UserData = dir
	}
	if err := d.ensureAlive(ctx); err != nil {
		return nil, d.failStart(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, d.failStart(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/lease", d.handleLease)
	mux.HandleFunc("/release", d.handleRelease)
	mux.HandleFunc("/lease/confirm", d.handleConfirm)
	mux.HandleFunc("/lease/abort", d.handleAbort)
	mux.HandleFunc("/status", d.handleStatus)
	mux.HandleFunc("/window", d.handleWindow)
	mux.HandleFunc("/shutdown", d.handleShutdown)
	d.ln = ln
	d.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = d.srv.Serve(ln) }()
	if err := d.writeState(); err != nil {
		return nil, d.failStart(err)
	}
	return d, nil
}

// failStart funnels every initialization failure through the same bounded
// teardown as a normal close: the in-flight start is discarded and awaited, the
// throwaway profile is only removed once the exit is confirmed, and a cleanup
// failure is returned next to the initialization error instead of being
// swallowed. Start therefore never hands back a nil daemon with a browser or a
// profile still unaccounted for.
func (d *Daemon) failStart(startErr error) error {
	if startErr == nil {
		return nil
	}
	if cerr := d.shutdown(context.Background()); cerr != nil {
		return errors.Join(startErr, cerr)
	}
	return startErr
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (d *Daemon) writeState() error {
	st := d.State()
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.statePath), 0o700); err != nil {
		return err
	}
	// The secret must never exist in a file with inherited permissions: the
	// platform writer creates it with the restrictive descriptor already in
	// place (Windows) or with 0600 from the first byte (Unix).
	return writeStateFile(d.statePath, b)
}

// State returns the current client-facing state.
func (d *Daemon) State() State {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := State{Token: d.token}
	if d.ln != nil {
		st.LeaseURL = "http://" + d.ln.Addr().String()
	}
	if d.session != nil {
		st.PID = d.session.PID
		st.UserData = d.session.UserData
	}
	return st
}

// Status reports liveness without touching the browser.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	s := Status{Generation: d.sessionGen, Launches: d.launches, Tasks: d.tasks, Revoking: d.revoking, Closing: d.closing, Broken: d.broken}
	if d.session != nil {
		s.PID = d.session.PID
		s.UserData = d.session.UserData
		s.Alive = !sessionExited(d.session)
		s.Control = d.session.Ctx != nil && d.session.Ctx.Err() == nil
	}
	d.mu.Unlock()
	d.leaseMu.Lock()
	s.Leased = d.leaseID != 0 && !d.expiring
	d.leaseMu.Unlock()
	return s
}

// Alive reports whether this host still owns a running browser and has not
// begun shutting down. The manager uses it to decide between reusing a host and
// starting a new one; it never starts a browser itself.
func (d *Daemon) Alive() bool {
	d.mu.Lock()
	alive := !d.closing && d.session != nil && !sessionExited(d.session)
	d.mu.Unlock()
	return alive
}

// launchOp is one in-flight browser start. It is registered in d.inflight so
// that cancellation, TTL revocation and shutdown can see it, wait for it and
// make sure a late session is cleaned up instead of being adopted silently.
type launchOp struct {
	discarded  bool // set by revoke/shutdown: the result must not be adopted
	sess       *edge.Session
	err        error
	cleanupErr error
	done       chan struct{}
}

// ensureAlive returns a live browser, waiting for (or starting) one. ctx only
// bounds this caller's wait; the start itself belongs to the daemon and keeps
// going (and is cleaned up) even if the caller goes away.
func (d *Daemon) ensureAlive(ctx context.Context) error {
	for {
		d.launchMu.Lock()
		d.mu.Lock()
		broken, closing := d.broken, d.closing
		alive := d.session != nil && !sessionExited(d.session)
		d.mu.Unlock()
		switch {
		case broken != "":
			d.launchMu.Unlock()
			return ErrBroken
		case closing:
			d.launchMu.Unlock()
			return ErrClosed
		case alive:
			d.launchMu.Unlock()
			return nil
		}
		op := d.inflight
		if op == nil {
			op = &launchOp{done: make(chan struct{})}
			d.inflight = op
			d.launchMu.Unlock()
			go d.runLaunch(op)
		} else {
			d.launchMu.Unlock()
		}
		select {
		case <-op.done:
			if err := ctx.Err(); err != nil {
				return err
			}
			if op.discarded {
				// The start this caller was waiting for was revoked; handing
				// out a lease now would mean silently starting a second
				// browser behind the revocation's back.
				return ErrRevoked
			}
			if op.err != nil {
				return errors.Join(op.err, op.cleanupErr)
			}
			if op.cleanupErr != nil {
				return op.cleanupErr
			}
			// Adopted or discarded: look at the daemon state again.
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// runLaunch performs one start and either adopts the result or cleans it up.
// Everything that might wait for it observes close(op.done) only after any
// cleanup has finished, so "done" always means the process is accounted for.
func (d *Daemon) runLaunch(op *launchOp) {
	// A resident browser that died on its own keeps the profile directory (and
	// its singleton lock) until every helper process is gone. Reusing the same
	// profile while that lock is still held makes the new Edge exit during
	// startup, so the old process tree is reaped first.
	d.mu.Lock()
	old := d.session
	dead := old != nil && sessionExited(old)
	if dead {
		d.session = nil
		d.sessionGen++
	}
	d.mu.Unlock()
	if dead {
		// A dead root process is not a clean process tree: helper processes can
		// still hold the profile's singleton lock. Reaping has to succeed, or
		// the new start would fail in a way that looks like a launch problem.
		if cerr := revokeBrowser(old); cerr != nil {
			op.err = fmt.Errorf("上一浏览器未能清理: %w", cerr)
			d.recordCleanupFailure(cerr)
			d.finishLaunch(op)
			return
		}
		if !waitExit(old, 5*time.Second) {
			err := errors.New("上一浏览器退出后进程未能及时结束")
			op.err = err
			d.recordCleanupFailure(err)
			d.finishLaunch(op)
			return
		}
	}

	// Only the production launcher fills this result. Fake launchers never touch native windows.
	windowResult := &windowLaunchResult{}
	s, err := launchSession(context.WithValue(d.hostCtx, windowLaunchKey{}, windowResult), d.cfg)

	d.launchMu.Lock()
	adopt := err == nil && !op.discarded
	if adopt {
		d.mu.Lock()
		if d.closing || d.broken != "" || (d.session != nil && !sessionExited(d.session)) {
			adopt = false
		} else {
			d.session = s
			d.window = windowResult.window
			d.sessionGen++
			d.launches++
		}
		d.mu.Unlock()
	}
	d.launchMu.Unlock()

	op.sess, op.err = s, err
	if s != nil && !adopt {
		cerr := revokeBrowser(s)
		if cerr == nil && !waitExit(s, 10*time.Second) {
			cerr = errors.New("启动中的浏览器未能确认退出")
		}
		op.cleanupErr = cerr
		if cerr != nil {
			d.recordCleanupFailure(cerr)
		}
	}

	d.finishLaunch(op)
}

// finishLaunch publishes the outcome and only then clears the slot, so anyone
// waiting on op.done observes either an adopted session or a finished cleanup.
func (d *Daemon) finishLaunch(op *launchOp) {
	d.launchMu.Lock()
	if d.inflight == op {
		d.inflight = nil
	}
	d.launchMu.Unlock()
	close(op.done)
}

func (d *Daemon) markBroken(reason string) {
	d.mu.Lock()
	if d.broken == "" {
		d.broken = reason
	}
	d.mu.Unlock()
	d.refuseOnce.Do(func() { close(d.refuse) })
}

// revokeAll discards any in-flight start, waits for it, then terminates and
// confirms the exit of every browser the daemon owns. Teardowns are serialized
// and failures are sticky: an exit that could not be confirmed is remembered,
// so a later Close can neither report success nor delete the profile.
func (d *Daemon) revokeAll(timeout time.Duration) error {
	d.stopMu.Lock()
	defer d.stopMu.Unlock()

	deadline := time.Now().Add(timeout)
	var first error
	d.launchMu.Lock()
	op := d.inflight
	if op != nil {
		op.discarded = true
	}
	d.launchMu.Unlock()

	if op != nil {
		select {
		case <-op.done:
			if op.cleanupErr != nil {
				first = op.cleanupErr
			}
		case <-time.After(time.Until(deadline)):
			first = errors.New("启动操作未在期限内结束")
		}
	}

	// Taking the session happens under the same serialization as the teardown,
	// so a concurrent caller waits for this result instead of seeing nil.
	d.mu.Lock()
	s := d.session
	d.session = nil
	d.sessionGen++
	d.mu.Unlock()
	if s != nil {
		if err := revokeBrowser(s); err != nil {
			if first == nil {
				first = err
			}
		} else if !waitExit(s, time.Until(deadline)) {
			if first == nil {
				first = errors.New("浏览器未能确认退出")
			}
		}
	}

	if first != nil {
		d.recordCleanupFailure(first)
		return first
	}
	d.mu.Lock()
	sticky := d.cleanupErr
	d.mu.Unlock()
	return sticky
}

// recordCleanupFailure keeps the first unresolved teardown failure and fails
// the daemon closed. Without it a failed exit would vanish with the launch
// record, and a later Close would delete a profile a live process may hold.
func (d *Daemon) recordCleanupFailure(err error) {
	d.mu.Lock()
	if d.cleanupErr == nil {
		d.cleanupErr = err
	}
	d.mu.Unlock()
	d.markBroken("清理浏览器失败: " + err.Error())
}

func (d *Daemon) acquire(ctx context.Context, ttl time.Duration) (uint64, time.Time, string, error) {
	select {
	case d.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, time.Time{}, "", ErrBusy
	case <-d.done:
		return 0, time.Time{}, "", ErrClosed
	case <-d.refuse:
		return 0, time.Time{}, "", ErrBroken
	}
	d.mu.Lock()
	closing, broken := d.closing, d.broken
	d.mu.Unlock()
	if closing || broken != "" {
		<-d.sem
		if broken != "" {
			return 0, time.Time{}, "", ErrBroken
		}
		return 0, time.Time{}, "", ErrClosed
	}
	tok, err := newToken()
	if err != nil {
		<-d.sem
		return 0, time.Time{}, "", err
	}
	deadline := time.Now().Add(ttl)
	d.leaseMu.Lock()
	d.leaseSeq++
	id := d.leaseSeq
	d.leaseID = id
	d.leaseToken = tok
	d.leasePhase = leaseReserved
	d.leaseUntil = deadline
	d.confirmUntil = time.Time{}
	d.expiring = false
	d.leaseTimer = time.AfterFunc(ttl, func() { d.expireLease(id) })
	d.leaseMu.Unlock()
	return id, deadline, tok, nil
}

// announce turns a reservation into an offer: the caller gets the lease id and
// its confirmation credential, but never an endpoint. The confirmation window
// starts here, after the browser is ready, so a slow launch cannot spend it.
func (d *Daemon) announce(id uint64) (time.Time, error) {
	d.leaseMu.Lock()
	defer d.leaseMu.Unlock()
	if d.leaseID != id || d.leasePhase != leaseReserved || d.expiring {
		return time.Time{}, ErrStaleLease
	}
	if !time.Now().Before(d.leaseUntil) {
		return time.Time{}, ErrBusy
	}
	d.mu.Lock()
	closing, broken := d.closing, d.broken
	sess := d.session
	gen := d.sessionGen
	d.mu.Unlock()
	if closing {
		return time.Time{}, ErrClosed
	}
	if broken != "" {
		return time.Time{}, ErrBroken
	}
	if sess == nil || sessionExited(sess) {
		return time.Time{}, ErrNoDaemon
	}
	// Bind the offer to this browser instance: a confirmation must not reach a
	// later browser that replaced it in the meantime.
	d.leaseGen = gen
	window := d.confirmWindow
	if window <= 0 {
		window = defaultConfirmWindow
	}
	d.leasePhase = leaseAwaiting
	d.confirmUntil = time.Now().Add(window)
	d.confirmTimer = time.AfterFunc(window, func() { d.expireConfirm(id) })
	return d.confirmUntil, nil
}

// confirm activates the reservation and only then hands out the endpoint. It is
// idempotent: a repeated confirmation returns the same endpoint and never
// resets the lease deadline. A stale id or a foreign credential is rejected
// without touching the current lease.
//
// Everything that decides "may this caller drive a browser" is checked in one
// critical section that spans both locks: the lease identity, both deadlines
// (activation window and lease TTL), the daemon state and the browser
// generation. A TTL timer that has not fired yet is irrelevant: the deadline
// itself is authoritative.
// confirm preserves the endpoint-only internal API for existing callers.
func (d *Daemon) confirm(id uint64, token string) (string, bool, error) {
	grant, first, err := d.confirmTarget(id, token)
	return grant.Endpoint, first, err
}

func (d *Daemon) confirmTarget(id uint64, token string) (TargetGrant, bool, error) {
	d.leaseMu.Lock()
	if d.leaseID != id || d.leasePhase == leaseNone {
		d.leaseMu.Unlock()
		return TargetGrant{}, false, ErrStaleLease
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(d.leaseToken)) != 1 {
		d.leaseMu.Unlock()
		return TargetGrant{}, false, ErrBadLeaseToken
	}
	if d.expiring {
		d.leaseMu.Unlock()
		return TargetGrant{}, false, ErrBusy
	}
	now := time.Now()
	if !now.Before(d.leaseUntil) {
		d.leaseMu.Unlock()
		d.releaseLease(id)
		return TargetGrant{}, false, ErrLeaseExpired
	}
	first := false
	switch d.leasePhase {
	case leaseActive:
		// A repeat confirmation: the browser is still this lease's browser.
	case leaseAwaiting:
		if !now.Before(d.confirmUntil) {
			d.leaseMu.Unlock()
			d.releaseLease(id)
			return TargetGrant{}, false, ErrConfirmExpired
		}
		d.leasePhase = leaseActive
		if d.confirmTimer != nil {
			d.confirmTimer.Stop()
			d.confirmTimer = nil
		}
		first = true
	default:
		d.leaseMu.Unlock()
		return TargetGrant{}, false, ErrNotReady
	}
	gen := d.leaseGen
	d.mu.Lock()
	closing, broken, sess, genNow := d.closing, d.broken, d.session, d.sessionGen
	defer d.mu.Unlock()
	defer d.leaseMu.Unlock()

	if closing {
		return TargetGrant{}, false, ErrClosed
	}
	if broken != "" {
		return TargetGrant{}, false, ErrBroken
	}
	if sess == nil || sessionExited(sess) {
		return TargetGrant{}, false, ErrNoDaemon
	}
	if genNow != gen {
		// The browser this lease was announced against is gone; returning the
		// current endpoint would hand over a browser nobody leased.
		return TargetGrant{}, false, ErrStaleLease
	}
	if sess.Endpoint == "" || sess.TargetID == "" {
		return TargetGrant{}, false, ErrNotReady
	}
	return TargetGrant{ID: id, Endpoint: sess.Endpoint, TargetID: sess.TargetID, Generation: genNow}, first, nil
}

// releaseLease ends lease id and frees the slot. A stale id (already released,
// expired, or a timer that fired after a later lease began) never touches the
// current lease.
func (d *Daemon) releaseLease(id uint64) bool {
	d.leaseMu.Lock()
	if d.expiring || d.leaseID != id {
		d.leaseMu.Unlock()
		return false
	}
	d.clearLeaseLocked()
	d.leaseMu.Unlock()
	<-d.sem
	return true
}

func (d *Daemon) clearLeaseLocked() {
	d.leaseID = 0
	d.leaseToken = ""
	d.leasePhase = leaseNone
	d.confirmUntil = time.Time{}
	if d.leaseTimer != nil {
		d.leaseTimer.Stop()
		d.leaseTimer = nil
	}
	if d.confirmTimer != nil {
		d.confirmTimer.Stop()
		d.confirmTimer = nil
	}
}

// expireConfirm reclaims a reservation nobody confirmed. The endpoint was never
// handed out, so there is nothing to revoke; the browser stays resident for the
// next caller and the slot is returned.
func (d *Daemon) expireConfirm(id uint64) {
	d.leaseMu.Lock()
	if d.leaseID != id || d.leasePhase != leaseAwaiting {
		d.leaseMu.Unlock()
		return
	}
	d.clearLeaseLocked()
	d.leaseMu.Unlock()
	<-d.sem
}

// finishExpiry completes a revocation started by expireLease or abortLease.
func (d *Daemon) finishExpiry(id uint64) {
	d.leaseMu.Lock()
	d.expiring = false
	if d.leaseID == id {
		d.clearLeaseLocked()
		d.leaseMu.Unlock()
		<-d.sem
		return
	}
	d.leaseMu.Unlock()
}

// abortLease revokes a lease whose fate is unknown (the client may have
// received an endpoint, or its confirmation reply was lost). Releasing the slot
// would let a second task drive a browser this client might still be using, so
// the browser is torn down and only a confirmed exit reopens the daemon.
func (d *Daemon) abortLease(id uint64) error {
	d.leaseMu.Lock()
	if d.leaseID != id || d.expiring {
		d.leaseMu.Unlock()
		return ErrStaleLease
	}
	d.expiring = true
	d.leaseMu.Unlock()

	d.mu.Lock()
	d.revoking = true
	d.mu.Unlock()

	if err := d.revokeAll(15 * time.Second); err != nil {
		d.mu.Lock()
		d.revoking = false
		d.mu.Unlock()
		d.markBroken("撤销旧任务失败: " + err.Error())
		// The slot must go back even when the host broke, but every waiter has
		// to fail: markBroken has closed refuse, so nobody can win a new lease.
		d.finishExpiry(id)
		return err
	}

	d.mu.Lock()
	d.revoking = false
	d.mu.Unlock()
	d.finishExpiry(id)
	return nil
}

// expireLease runs when a client disappeared without releasing. Loosening the
// lock alone would let a second task drive the same browser, so the browser is
// torn down first and only a confirmed exit reopens the lease.
func (d *Daemon) expireLease(id uint64) {
	d.leaseMu.Lock()
	if d.leaseID != id || d.expiring {
		d.leaseMu.Unlock()
		return
	}
	d.expiring = true
	d.leaseMu.Unlock()

	d.mu.Lock()
	d.revoking = true
	d.mu.Unlock()

	if err := d.revokeAll(15 * time.Second); err != nil {
		d.mu.Lock()
		d.revoking = false
		d.mu.Unlock()
		d.markBroken("撤销旧任务失败: " + err.Error())
		// Even a broken host must give the lease slot back: otherwise every
		// later caller waits for this (already expired) lease forever.
		d.finishExpiry(id)
		return
	}

	d.mu.Lock()
	d.revoking = false
	d.mu.Unlock()
	d.finishExpiry(id)
}

// waitExit is a variable so unit tests can decide whether a fake browser
// actually exited.
var waitExit = waitExited

func waitExited(s *edge.Session, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if s.Exited() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Close stops the lease API, closes the browser and removes the throwaway
// profile it created. It is safe to call twice and keeps the first error.
func (d *Daemon) Close() error { return d.shutdown(context.Background()) }

func (d *Daemon) shutdown(ctx context.Context) error {
	d.once.Do(func() {
		d.mu.Lock()
		d.closing = true
		d.mu.Unlock()
		d.doneOnce.Do(func() { close(d.done) })

		// A lease timer that outlived the daemon would later try to revoke a
		// browser that is already gone (and, in tests, the next daemon's).
		d.leaseMu.Lock()
		if d.leaseTimer != nil {
			d.leaseTimer.Stop()
			d.leaseTimer = nil
		}
		d.leaseID = 0
		d.leaseMu.Unlock()

		_ = os.Remove(d.statePath)

		// Bounded drain: a client stuck in a long task must not block exit.
		if d.srv != nil {
			d.srv.SetKeepAlivesEnabled(false)
			drain, cancel := context.WithTimeout(ctx, time.Second)
			if err := d.srv.Shutdown(drain); err != nil {
				// A connection that never sent a request can hold Shutdown
				// open; force it shut once the grace ends.
				_ = d.srv.Close()
			}
			cancel()
		}
		if d.ln != nil {
			_ = d.ln.Close()
		}

		// Wait (bounded) for any start that is still running, discard its
		// result and confirm every browser really exited.
		err := d.revokeAll(15 * time.Second)
		// The CDP control session is owned by the daemon; release it only now.
		d.hostCancel()
		// Only a confirmed exit allows the throwaway profile to be removed.
		if err == nil && d.cleanupProfile && d.ownedProfile != "" {
			if rmErr := os.RemoveAll(d.ownedProfile); rmErr != nil {
				err = fmt.Errorf("清理临时 profile 失败: %w", rmErr)
			}
		}

		d.mu.Lock()
		d.closed = true
		d.closeErr = err
		d.mu.Unlock()
	})
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closeErr
}

// sessionExited is a variable so tests can decide that a fake browser has died.
var sessionExited = func(s *edge.Session) bool { return s != nil && s.Exited() }

// revokeBrowser is a variable so tests can simulate a browser that refuses to
// die; production always uses edge.Session.Close.
var revokeBrowser = func(s *edge.Session) error {
	if s == nil {
		return nil
	}
	return s.Close()
}

// launchSession is a variable so unit tests can run without a real browser.
var launchSession = func(ctx context.Context, cfg store.Settings) (*edge.Session, error) {
	cfg.VisibleBrowser = true // resident host must have one restorable native window
	s, err := edge.LaunchContext(ctx, cfg)
	if err != nil {
		return s, err
	}
	window, err := newHostWindow(s.PID)
	if err != nil {
		log.Printf("browserhost window startup category=%s", windowErrorCategory(err))
		return s, fmt.Errorf("resident default hide: %w", err)
	}
	if result, ok := ctx.Value(windowLaunchKey{}).(*windowLaunchResult); ok {
		result.window = window
	}
	return s, nil
}

type leaseRequest struct {
	TTLMs int64 `json:"ttlMs"`
}

// TargetGrant is a single host-authoritative snapshot, issued only on confirm.
// The client cannot nominate a target; targetId is never accepted in a request.
type TargetGrant struct {
	ID         uint64 `json:"id"`
	Endpoint   string `json:"endpoint"`
	TargetID   string `json:"targetId"`
	Generation uint64 `json:"generation"`
}
type leaseResponse = TargetGrant

type releaseRequest struct {
	ID uint64 `json:"id"`
}

const (
	minLeaseTTL = time.Second
	maxLeaseTTL = 10 * time.Minute
	// defaultConfirmWindow is the first guess for the activation handshake; it is a
	// daemon field so tests inject a window instead of sleeping two real seconds.
	defaultConfirmWindow = 2 * time.Second
)

func (d *Daemon) guard(w http.ResponseWriter, r *http.Request, method string) bool {
	// A browser cannot reach us without an Origin; anything that carries one is
	// not this program.
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "来源不被接受", http.StatusForbidden)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return false
	}
	got := r.Header.Get("X-Control-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(d.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

type leaseOffer struct {
	ID              uint64 `json:"id"`
	Token           string `json:"token"`
	ConfirmWindowMs int64  `json:"confirmWindowMs"`
}

type confirmRequest struct {
	ID    uint64 `json:"id"`
	Token string `json:"token"`
}

func (d *Daemon) handleLease(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	var req leaseRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "请求体无效", http.StatusBadRequest)
		return
	}
	// Validate the raw integer before multiplying: no overflow, no zero, no
	// negative value that would silently mean "no timer".
	if req.TTLMs < int64(minLeaseTTL/time.Millisecond) || req.TTLMs > int64(maxLeaseTTL/time.Millisecond) {
		http.Error(w, "ttlMs 超出范围", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLMs) * time.Millisecond

	id, deadline, tok, err := d.acquire(r.Context(), ttl)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrClosed) || errors.Is(err, ErrBroken) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}

	// The wait for a browser must never outlive the lease it is acquiring for,
	// otherwise a slow start could hand back a lease that is already expiring.
	waitCtx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	if err := d.ensureAlive(waitCtx); err != nil {
		d.releaseLease(id)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// A client that gave up while the browser was starting must not leave a
	// reservation behind: nobody would confirm it and the next caller would wait
	// for the whole TTL.
	if r.Context().Err() != nil {
		d.releaseLease(id)
		return
	}

	until, err := d.announce(id)
	if err != nil {
		d.releaseLease(id)
		status := http.StatusConflict
		if errors.Is(err, ErrClosed) || errors.Is(err, ErrBroken) || errors.Is(err, ErrNoDaemon) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	if r.Context().Err() != nil {
		d.releaseLease(id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(leaseOffer{
		ID:              id,
		Token:           tok,
		ConfirmWindowMs: time.Until(until).Milliseconds(),
	})
}

// handleConfirm is where a reservation becomes a lease. Until this succeeds the
// client has no endpoint at all, so a lost first reply can only leave a
// reservation that expires on its own.
func (d *Daemon) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	var req confirmRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.ID == 0 || req.Token == "" {
		http.Error(w, "缺少租约标识或凭据", http.StatusBadRequest)
		return
	}
	// A confirmation that arrives after the client gave up must not spend the
	// host's revocation machinery: the browser it might have touched is still
	// leased until the client aborts or the TTL fires.
	if r.Context().Err() != nil {
		return
	}
	grant, first, err := d.confirmTarget(req.ID, req.Token)
	if err != nil {
		status := http.StatusConflict
		switch {
		case errors.Is(err, ErrBadLeaseToken):
			status = http.StatusForbidden
		case errors.Is(err, ErrClosed), errors.Is(err, ErrBroken), errors.Is(err, ErrNoDaemon), errors.Is(err, ErrBusy):
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	if first {
		d.mu.Lock()
		d.tasks++
		d.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(grant)
}

// handleAbort revokes a lease whose fate is unknown: the client may have seen an
// endpoint, or its confirmation reply may have been lost. The slot only reopens
// after a confirmed browser exit.
func (d *Daemon) handleAbort(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	var req confirmRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.ID == 0 || req.Token == "" {
		http.Error(w, "缺少租约标识或凭据", http.StatusBadRequest)
		return
	}
	if !d.tokenMatches(req.ID, req.Token) {
		http.Error(w, ErrStaleLease.Error(), http.StatusConflict)
		return
	}
	if err := d.abortLease(req.ID); err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrBroken) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tokenMatches reports whether id names the current lease and token is its
// credential. Used by abort, which must reject a caller that never held it.
func (d *Daemon) tokenMatches(id uint64, token string) bool {
	d.leaseMu.Lock()
	defer d.leaseMu.Unlock()
	if d.leaseID != id || d.leasePhase == leaseNone {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(d.leaseToken)) == 1
}

func (d *Daemon) handleRelease(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	var req releaseRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.ID == 0 {
		http.Error(w, "缺少租约标识", http.StatusBadRequest)
		return
	}
	if !d.releaseLease(req.ID) {
		http.Error(w, "租约不是当前持有者", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodGet) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(d.Status())
}

// handleWindow changes only the bound root window; it never attaches CDP or touches targets.
func (d *Daemon) handleWindow(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Visible    *bool  `json:"visible"`
		Generation uint64 `json:"generation"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Visible == nil {
		http.Error(w, "invalid_window_request", http.StatusBadRequest)
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "invalid_window_request", http.StatusBadRequest)
		return
	}
	// Holding mu prevents replacement/revocation while the bounded native operation runs.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session == nil {
		http.Error(w, "window_no_session", http.StatusConflict)
		return
	}
	if req.Generation == 0 || req.Generation != d.sessionGen {
		http.Error(w, "window_generation_changed", http.StatusConflict)
		return
	}
	if d.closing || d.revoking || d.broken != "" {
		http.Error(w, "window_session_unavailable", http.StatusConflict)
		return
	}
	if err := setHostWindow(r.Context(), d.window, *req.Visible); err != nil {
		category := windowErrorCategory(err)
		log.Printf("browserhost window request category=%s", category)
		http.Error(w, category, http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Daemon) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !d.guard(w, r, http.MethodPost) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
	go func() { _ = d.Close() }()
}

// Client talks to a running daemon.
type Client struct {
	windowGeneration atomic.Uint64 // binds visibility changes to the acquired session
	state            State
	expected         string // profile this client is allowed to drive, from the account
	http             *http.Client
}

// Attach leases the resident browser for ttl and returns a CDP session bound to
// it. Closing the session only drops the connection; the browser keeps running.
// release must be called when the run ends and is safe to call more than once.
func (c *Client) Attach(ctx context.Context, ttl time.Duration) (*edge.Session, func(), error) {
	sess, finish, err := c.AttachForTask(ctx, ttl, nil)
	if err != nil {
		return nil, nil, err
	}
	return sess, func() { _ = finish() }, nil
}

// AttachForTask restores task-scoped page settings before disconnecting and
// releasing the lease. Failed restoration revokes the lease, never reuses it.
func (c *Client) AttachForTask(ctx context.Context, ttl time.Duration, cleanup func(context.Context, *edge.Session) error) (*edge.Session, func() error, error) {
	if err := c.checkProfile(); err != nil {
		return nil, nil, err
	}
	res, err := c.Reserve(ctx, ttl)
	if err != nil {
		return nil, nil, err
	}
	grant, err := c.ConfirmTarget(ctx, res)
	if err != nil {
		// The reply may have been lost after activation: whether the endpoint
		// reached us or not, the lease must be revoked, and a failed revocation
		// is part of the error rather than being dropped.
		return nil, nil, errors.Join(err, c.abortBounded(res, "确认失败后撤销租约"))
	}
	sess, err := attachSession(ctx, grant.Endpoint, c.state.PID, c.state.UserData, grant.TargetID)
	if err != nil {
		// The lease is active and the attach outcome is unknown. Releasing the
		// slot would let the next task drive a browser this one may still be
		// using; the host must prove the exit first.
		return nil, nil, errors.Join(err, c.abortBounded(res, "附加失败后撤销租约"))
	}
	c.windowGeneration.Store(grant.Generation)
	finish := taskLeaseFinisher(sess.Ctx, func(cleanCtx context.Context) error {
		if cleanup == nil {
			return nil
		}
		return cleanup(cleanCtx, sess)
	}, sess.Close, func() error { return c.releaseTask(res.ID) }, func() error {
		return c.abortBounded(res, "任务清理失败后撤销租约")
	})
	return sess, finish, nil
}

// SetWindowVisible returns success only after native visibility verification.
func (c *Client) SetWindowVisible(ctx context.Context, visible bool) error {
	body, _ := json.Marshal(map[string]any{"visible": visible, "generation": c.windowGeneration.Load()})
	resp, err := c.do(ctx, http.MethodPost, "/window", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("常驻浏览器窗口操作失败: %s", bytes.TrimSpace(msg))
	}
	return nil
}

func (c *Client) abortBounded(r Reservation, what string) error {
	actx, acancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer acancel()
	if err := c.Abort(actx, r); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// checkProfile refuses to attach when the running host belongs to another
// account. The state file is per account, but a stale or copied file must not
// be able to point this account's run at somebody else's signed-in browser.
func (c *Client) checkProfile() error {
	if c.expected == "" {
		return nil
	}
	st, err := c.Status()
	if err != nil {
		return fmt.Errorf("无法确认宿主所属账号: %w", err)
	}
	if !samePath(st.UserData, c.expected) {
		return fmt.Errorf("%w: 宿主 profile=%s，本次账号 profile=%s", ErrWrongProfile, st.UserData, c.expected)
	}
	// The discovery file was written at startup; the browser may have been
	// replaced since. Use the live PID for diagnostics, not the stale one.
	c.state.PID = st.PID
	return nil
}

// samePath compares two profile paths the way Windows resolves them: case
// insensitive and cleaned, so a differently spelled path is not mistaken for
// another account.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// attachSession is a seam: tests attach to fake browsers, production uses CDP.
var attachSession = edge.Attach

// leaseHTTP has no fixed timeout: a lease request waits for the running task
// and is bounded only by the caller's context.
var leaseHTTP = &http.Client{}

// Dial reads the daemon state file. expectedProfile is the profile this process
// is allowed to drive (the account's own directory); when it does not match the
// host's profile the client is refused before any lease is taken, so account A
// can never be attached to account B's signed-in browser.
func Dial(statePath, expectedProfile string) (*Client, error) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%w: 状态文件损坏: %v", ErrNoDaemon, err)
	}
	if st.LeaseURL == "" || st.Token == "" || st.UserData == "" {
		return nil, ErrNoDaemon
	}
	if expectedProfile != "" && !samePath(st.UserData, expectedProfile) {
		return nil, fmt.Errorf("%w: 状态文件指向 %s，本次账号 profile=%s", ErrWrongProfile, st.UserData, expectedProfile)
	}
	return &Client{state: st, expected: expectedProfile, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

// RunOptions bounds how long a client waits for the lease and how long the
// daemon keeps it if the client disappears.
type RunOptions struct {
	Wait     time.Duration
	LeaseTTL time.Duration
}

func (o RunOptions) normalized() RunOptions {
	if o.Wait <= 0 {
		o.Wait = 60 * time.Second
	}
	if o.LeaseTTL < minLeaseTTL {
		o.LeaseTTL = o.Wait + 2*time.Minute
	}
	return o
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.state.LeaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Control-Token", c.state.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// Reservation is the answer to the first call: an id and a one-time credential,
// never an endpoint. The client holds it from the very first response so it can
// always release or abort by id, even when a later reply is lost.
type Reservation struct {
	ID     uint64
	Token  string
	Window time.Duration
}

// Reserve asks for the browser without receiving it.
func (c *Client) Reserve(ctx context.Context, ttl time.Duration) (Reservation, error) {
	body, _ := json.Marshal(leaseRequest{TTLMs: int64(ttl / time.Millisecond)})
	// The reserve call may legitimately block while another task runs, so it
	// must not inherit the short client timeout: ctx bounds the wait.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.state.LeaseURL+"/lease", bytes.NewReader(body))
	if err != nil {
		return Reservation{}, err
	}
	req.Header.Set("X-Control-Token", c.state.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := leaseHTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return Reservation{}, ErrBusy
		}
		return Reservation{}, fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		return Reservation{}, ErrBusy
	case http.StatusServiceUnavailable:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return Reservation{}, fmt.Errorf("%w: %s", ErrClosed, bytes.TrimSpace(msg))
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return Reservation{}, fmt.Errorf("租用失败: %s", bytes.TrimSpace(msg))
	}
	var offer leaseOffer
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return Reservation{}, err
	}
	if offer.ID == 0 || offer.Token == "" {
		return Reservation{}, errors.New("宿主返回的预约缺少编号或凭据")
	}
	return Reservation{ID: offer.ID, Token: offer.Token, Window: time.Duration(offer.ConfirmWindowMs) * time.Millisecond}, nil
}

// Confirm activates the reservation and returns the endpoint. A lost reply is
// ambiguous: the caller must Abort instead of assuming the browser was unused.
func (c *Client) Confirm(ctx context.Context, r Reservation) (string, error) {
	grant, err := c.ConfirmTarget(ctx, r)
	return grant.Endpoint, err
}

// ConfirmTarget returns the endpoint, owned target and generation atomically.
func (c *Client) ConfirmTarget(ctx context.Context, r Reservation) (TargetGrant, error) {
	body, _ := json.Marshal(confirmRequest{ID: r.ID, Token: r.Token})
	resp, err := c.do(ctx, http.MethodPost, "/lease/confirm", body)
	if err != nil {
		return TargetGrant{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return TargetGrant{}, fmt.Errorf("确认租约失败: %s", bytes.TrimSpace(msg))
	}
	var out leaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return TargetGrant{}, err
	}
	if out.ID != r.ID || out.Endpoint == "" || out.TargetID == "" || out.Generation == 0 {
		return TargetGrant{}, errors.New("确认成功但宿主目标凭据不完整或编号不匹配")
	}
	return out, nil
}

// Abort asks the host to revoke and clean up a lease whose fate is unknown.
// It is bounded: the host only honours it while it can still prove the exit.
func (c *Client) Abort(ctx context.Context, r Reservation) error {
	body, _ := json.Marshal(confirmRequest{ID: r.ID, Token: r.Token})
	resp, err := c.do(ctx, http.MethodPost, "/lease/abort", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("撤销租约失败: %s", bytes.TrimSpace(msg))
	}
	return nil
}
func (c *Client) release(id uint64) {
	body, _ := json.Marshal(releaseRequest{ID: id})
	resp, err := c.do(context.Background(), http.MethodPost, "/release", body)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Status asks the daemon.
func (c *Client) Status() (Status, error) {
	resp, err := c.do(context.Background(), http.MethodGet, "/status", nil)
	if err != nil {
		return Status{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("状态查询失败: %s", resp.Status)
	}
	var st Status
	err = json.NewDecoder(resp.Body).Decode(&st)
	return st, err
}

// Shutdown asks the daemon to close the browser and exit.
func (c *Client) Shutdown() error {
	resp, err := c.do(context.Background(), http.MethodPost, "/shutdown", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Run leases the browser, attaches a tab, runs task and detaches. The browser
// stays alive; a tab left behind by a crashed task is closed by the daemon's
// next launch, not by this call.
func (c *Client) Run(ctx context.Context, task Task, opts RunOptions) error {
	opts = opts.normalized()
	if err := c.checkProfile(); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, opts.Wait)
	defer cancel()
	res, err := c.Reserve(waitCtx, opts.LeaseTTL)
	if err != nil {
		return err
	}
	grant, err := c.ConfirmTarget(waitCtx, res)
	if err != nil {
		// The reply may have been lost after activation, so the browser might
		// be in use by nobody. Only a confirmed abort reopens the host.
		return errors.Join(err, c.abortBounded(res, "确认失败后撤销租约"))
	}
	sess, err := attachSession(ctx, grant.Endpoint, c.state.PID, c.state.UserData, grant.TargetID)
	if err != nil {
		return errors.Join(err, c.abortBounded(res, "附加失败后撤销租约"))
	}
	defer c.release(res.ID)
	defer sess.Close()
	return task(sess.Ctx)
}
