package browserhost

import (
	"bytes"
	"context"
	"errors"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeWindowBackend struct {
	windows     []windowInfo
	commands    []int
	identity    error
	changeAfter int
}

func (b *fakeWindowBackend) Identity() error                { return b.identity }
func (b *fakeWindowBackend) Windows() ([]windowInfo, error) { return b.windows, nil }
func (b *fakeWindowBackend) Command(h uintptr, n int) error {
	b.commands = append(b.commands, n)
	for i := range b.windows {
		if b.windows[i].handle == h {
			switch n {
			case 6:
				b.windows[i].minimized = true
			case 0:
				b.windows[i].visible = false
			case 9:
				b.windows[i].visible = true
				b.windows[i].minimized = false
			}
		}
	}
	if b.changeAfter > 0 && len(b.commands) == b.changeAfter {
		b.identity = ErrWindowIdentity
	}
	return nil
}
func fakeMainWindow() windowInfo {
	return windowInfo{handle: 77, pid: 4242, class: "Chrome_WidgetWin_1", width: 516, height: 900, visible: true}
}
func TestWindowMinimizeHideRestoreSingleMain(t *testing.T) {
	helper := fakeMainWindow()
	helper.handle = 88
	helper.class = "Chrome_WidgetWin_0"
	b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow(), helper}}
	c := &controlledWindow{backend: b}
	for _, visible := range []bool{false, true, false} {
		if err := c.SetVisible(context.Background(), visible); err != nil {
			t.Fatal(err)
		}
	}
	want := []int{6, 0, 9, 6, 0}
	if len(b.commands) != len(want) {
		t.Fatal(b.commands)
	}
	for i, n := range want {
		if b.commands[i] != n {
			t.Fatal(b.commands)
		}
	}
	if !b.windows[1].visible {
		t.Fatal("helper touched")
	}
}
func TestWindowFailClosed(t *testing.T) {
	for _, kind := range []string{"ambiguous", "identity", "owner", "class", "size", "changed during hide"} {
		t.Run(kind, func(t *testing.T) {
			b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}
			switch kind {
			case "ambiguous":
				b.windows = append(b.windows, fakeMainWindow())
			case "identity":
				b.identity = ErrWindowIdentity
			case "owner":
				b.windows[0].owner = 1
			case "class":
				b.windows[0].class = "Chrome_WidgetWin_10"
			case "size":
				b.windows[0].width = 1
			case "changed during hide":
				b.changeAfter = 1
			}
			c := &controlledWindow{backend: b}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if kind == "changed during hide" {
				ctx = context.Background()
			}
			if err := c.SetVisible(ctx, false); err == nil {
				t.Fatal("expected error")
			}
			max := 0
			if kind == "changed during hide" {
				max = 1
			}
			if len(b.commands) > max {
				t.Fatal(b.commands)
			}
		})
	}
}
func TestWindowBoundHandleNeverReplaced(t *testing.T) {
	b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}
	c := &controlledWindow{backend: b}
	if err := c.SetVisible(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	b.windows[0].handle++
	if err := c.SetVisible(context.Background(), true); !errors.Is(err, ErrWindowIdentity) {
		t.Fatal(err)
	}
	if len(b.commands) != 2 {
		t.Fatal(b.commands)
	}
}
func TestWindowEndpointHasNoSessionSideEffects(t *testing.T) {
	b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}
	sess := &edge.Session{PID: 4242, TargetID: "retain"}
	d := &Daemon{token: "tok", session: sess, window: &controlledWindow{backend: b}, sessionGen: 7, launches: 1, tasks: 3, leaseID: 9, leasePhase: leaseActive}
	for _, visible := range []string{"false", "true"} {
		r := httptest.NewRequest(http.MethodPost, "/window", bytes.NewBufferString(`{"visible":`+visible+`,"generation":7}`))
		r.Header.Set("X-Control-Token", "tok")
		w := httptest.NewRecorder()
		d.handleWindow(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatal(w.Code, w.Body.String())
		}
		if d.session != sess || sess.TargetID != "retain" || d.sessionGen != 7 || d.launches != 1 || d.tasks != 3 || d.leaseID != 9 || d.leasePhase != leaseActive {
			t.Fatal("session/target changed")
		}
	}
}
func TestWindowEndpointValidationAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, method, token, body string
		session                   bool
		status                    int
	}{
		{"wrong token", "POST", "bad", `{"visible":true}`, true, 401}, {"wrong method", "GET", "tok", `{"visible":true}`, true, 405},
		{"invalid JSON", "POST", "tok", "{", true, 400}, {"invalid type", "POST", "tok", `{"visible":"true"}`, true, 400},
		{"missing visible", "POST", "tok", `{}`, true, 400}, {"extra value", "POST", "tok", `{"visible":true}{}`, true, 400},
		{"unknown field", "POST", "tok", `{"visible":true,"url":"secret"}`, true, 400},
		{"no session", "POST", "tok", `{"visible":true}`, false, 409}, {"unbound fake", "POST", "tok", `{"visible":true}`, true, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Daemon{token: "tok"}
			if tc.session {
				d.session = &edge.Session{PID: 4242}
			}
			r := httptest.NewRequest(tc.method, "/window", bytes.NewBufferString(tc.body))
			r.Header.Set("X-Control-Token", tc.token)
			w := httptest.NewRecorder()
			d.handleWindow(w, r)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
func TestWindowClientRetainsProtocolAndPropagatesFailure(t *testing.T) {
	b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}
	d := &Daemon{token: "tok", session: &edge.Session{PID: 4242}, sessionGen: 7, window: &controlledWindow{backend: b}}
	srv := httptest.NewServer(http.HandlerFunc(d.handleWindow))
	defer srv.Close()
	c := &Client{state: State{LeaseURL: srv.URL, Token: "tok"}, http: srv.Client()}
	c.windowGeneration.Store(7)
	for _, v := range []bool{false, true} {
		if err := c.SetWindowVisible(context.Background(), v); err != nil {
			t.Fatal(err)
		}
	}
	b.identity = ErrWindowIdentity
	if err := c.SetWindowVisible(context.Background(), false); err == nil {
		t.Fatal("expected client error")
	}
}

func TestWindowGenerationMismatchNeverMutates(t *testing.T) {
	b := &fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}
	d := &Daemon{token: "tok", session: &edge.Session{PID: 4242}, sessionGen: 8, window: &controlledWindow{backend: b}}
	for _, body := range []string{`{"visible":true}`, `{"visible":true,"generation":7}`} {
		r := httptest.NewRequest("POST", "/window", bytes.NewBufferString(body))
		r.Header.Set("X-Control-Token", "tok")
		w := httptest.NewRecorder()
		d.handleWindow(w, r)
		if w.Code != 409 || w.Body.String() != "window_generation_changed\n" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if len(b.commands) != 0 {
		t.Fatal(b.commands)
	}
}

type stalledWindowBackend struct{ fakeWindowBackend }

func (b *stalledWindowBackend) Command(h uintptr, n int) error {
	b.commands = append(b.commands, n)
	return nil
}
func TestWindowAsyncVerificationIsBounded(t *testing.T) {
	b := &stalledWindowBackend{fakeWindowBackend: fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}}
	c := &controlledWindow{backend: b}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.SetVisible(ctx, false)
	if !errors.Is(err, ErrWindowVerify) || time.Since(start) > time.Second {
		t.Fatal(err, time.Since(start))
	}
	if len(b.commands) != 1 || b.commands[0] != 6 {
		t.Fatal("hide must wait for minimize verification", b.commands)
	}
}
func TestWindowStartupFailurePreservesCleanupError(t *testing.T) {
	oldLaunch, oldRevoke := launchSession, revokeBrowser
	defer func() { launchSession = oldLaunch; revokeBrowser = oldRevoke }()
	cleanupErr := errors.New("fixture_cleanup_failed")
	sess := &edge.Session{PID: 4242}
	launchSession = func(context.Context, store.Settings) (*edge.Session, error) { return sess, ErrWindowVerify }
	revoked := false
	revokeBrowser = func(s *edge.Session) error { revoked = s == sess; return cleanupErr }
	d := &Daemon{hostCtx: context.Background(), refuse: make(chan struct{})}
	err := d.ensureAlive(context.Background())
	if !errors.Is(err, ErrWindowVerify) || !errors.Is(err, cleanupErr) || !revoked {
		t.Fatal(err, revoked)
	}
	if d.session != nil || d.launches != 0 || d.cleanupErr != cleanupErr || d.broken == "" {
		t.Fatal("failed start adopted or cleanup failure lost")
	}
}

func TestWindowInitiallyHiddenIdenticalHelperNeverPromoted(t *testing.T) {
	main := fakeMainWindow()
	helper := main
	helper.handle = 88
	helper.visible = false
	b := &fakeWindowBackend{windows: []windowInfo{helper, main}}
	c := &controlledWindow{backend: b}
	for _, v := range []bool{false, true, false, true, false} {
		if err := c.SetVisible(context.Background(), v); err != nil {
			t.Fatal(err)
		}
		if c.handle != main.handle || b.windows[0].visible {
			t.Fatal("hidden identical helper promoted")
		}
	}
	b.windows[0].visible = true
	count := len(b.commands)
	if err := c.SetVisible(context.Background(), true); !errors.Is(err, ErrWindowAmbiguous) {
		t.Fatal(err)
	}
	if len(b.commands) != count {
		t.Fatal("ambiguous request mutated a window")
	}
}

type transitionalWindowBackend struct {
	fakeWindowBackend
	transient  int
	persistent bool
}

func (b *transitionalWindowBackend) Command(h uintptr, n int) error {
	err := b.fakeWindowBackend.Command(h, n)
	if n == 9 {
		b.transient = 1
	}
	return err
}
func (b *transitionalWindowBackend) Windows() ([]windowInfo, error) {
	ws := append([]windowInfo(nil), b.windows...)
	if b.transient > 0 {
		ws[0].width = 160
		ws[0].height = 28
		ws[0].visible = false
		if !b.persistent {
			b.transient--
		}
	}
	return ws, nil
}
func TestWindowRestoreGeometryTransitionOnlyPolls(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		b := &transitionalWindowBackend{fakeWindowBackend: fakeWindowBackend{windows: []windowInfo{fakeMainWindow()}}, persistent: persistent}
		c := &controlledWindow{backend: b}
		if err := c.SetVisible(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		err := c.SetVisible(ctx, true)
		cancel()
		if persistent {
			if !errors.Is(err, ErrWindowVerify) {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if len(b.commands) != 3 || b.commands[2] != 9 {
			t.Fatal("geometry polling reissued native commands", b.commands)
		}
	}
}
