package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/signin"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// errUnconfirmedCleanup stands in for a browser tree that could not be proven
// gone (edge.Session.Close reports exactly this kind of failure).
var errUnconfirmedCleanup = errors.New("等待 Edge 根进程退出超时")

// closeSpy records how the probe released the browser tree, so a test can prove
// cleanup happened (or that it was reported as unconfirmed) without a browser.
type closeSpy struct {
	calls int
	err   error
}

// stubProbeEnv returns an env whose browser starts without Edge and whose
// observation returns verdict. The account directory the probe resolves already
// exists, so the run reaches the launch step.
func stubProbeEnv(t *testing.T, out *bytes.Buffer, verdict signin.ProbeResult) (probeEnv, *closeSpy, string, string) {
	t.Helper()
	base := t.TempDir()
	accountDir := filepath.Join(base, "accounts-v1", accountKey("20230001"))
	if err := os.MkdirAll(accountDir, 0o755); err != nil {
		t.Fatal(err)
	}
	spy := &closeSpy{}
	env := probeEnv{
		dataDir: t.TempDir(),
		out:     out,
		launch: func(context.Context, store.Settings) (*edge.Session, error) {
			return &edge.Session{PID: 4242, UserData: accountDir, Ctx: context.Background()}, nil
		},
		creds: func() (string, string, error) { return "20230001", "pw", nil },
		probe: func(context.Context, context.Context, string) signin.ProbeResult { return verdict },
		close: func(*edge.Session) error {
			spy.calls++
			return spy.err
		},
	}
	return env, spy, accountDir, base
}

func TestEveryVerdictReleasesTheBrowserExactlyOnce(t *testing.T) {
	cases := []struct {
		name    string
		verdict signin.ProbeResult
		want    int
	}{
		{"recovered", signin.ProbeResult{Class: signin.ProbeRecovered, Stop: signin.ProbeStopVerdict, Page: "business"}, 0},
		{"needs login", signin.ProbeResult{Class: signin.ProbeNeedsLogin, Stop: signin.ProbeStopVerdict, Page: "cas-login"}, 2},
		{"needs second factor", signin.ProbeResult{Class: signin.ProbeNeedsSecondFactor, Stop: signin.ProbeStopVerdict, Page: "cas-twoverify"}, 3},
		{"unknown", signin.ProbeResult{Class: signin.ProbeUnknown, Stop: signin.ProbeStopBudget, Page: "cas-login"}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			env, spy, _, base := stubProbeEnv(t, &out, c.verdict)
			if got := runProbe(env, base, false); got != c.want {
				t.Fatalf("exit = %d, want %d (output: %s)", got, c.want, out.String())
			}
			if spy.calls != 1 {
				t.Fatalf("browser closed %d times, want exactly 1", spy.calls)
			}
		})
	}
}

func TestUnconfirmedCleanupIsNeverReportedAsSuccess(t *testing.T) {
	var out bytes.Buffer
	env, spy, _, base := stubProbeEnv(t, &out, signin.ProbeResult{Class: signin.ProbeRecovered, Stop: signin.ProbeStopVerdict, Page: "business"})
	spy.err = errUnconfirmedCleanup
	if got := runProbe(env, base, false); got != 1 {
		t.Fatalf("exit = %d, want 1 when cleanup cannot be confirmed (output: %s)", got, out.String())
	}
	if spy.calls != 1 {
		t.Fatalf("browser closed %d times, want exactly 1", spy.calls)
	}
	if !strings.Contains(out.String(), "清理未确认") {
		t.Fatalf("output must report the unconfirmed cleanup: %s", out.String())
	}
}

func TestProfileMismatchStillClosesTheBrowserAndFails(t *testing.T) {
	var out bytes.Buffer
	env, spy, accountDir, base := stubProbeEnv(t, &out, signin.ProbeResult{Class: signin.ProbeRecovered})
	env.launch = func(context.Context, store.Settings) (*edge.Session, error) {
		return &edge.Session{PID: 4242, UserData: accountDir + `\另一个目录`, Ctx: context.Background()}, nil
	}
	env.probe = func(context.Context, context.Context, string) signin.ProbeResult {
		t.Fatal("the probe must not observe a profile that is not the checked one")
		return signin.ProbeResult{}
	}
	if got := runProbe(env, base, false); got != 1 {
		t.Fatalf("exit = %d, want 1 on a profile mismatch", got)
	}
	if spy.calls != 1 {
		t.Fatalf("a mismatched browser must still be closed: closed %d times, want 1", spy.calls)
	}
	if !strings.Contains(out.String(), "不一致") {
		t.Fatalf("output must report the mismatch: %s", out.String())
	}
}

func TestLauncherWithoutASessionIsAnErrorNotACrash(t *testing.T) {
	var out bytes.Buffer
	env, spy, _, base := stubProbeEnv(t, &out, signin.ProbeResult{Class: signin.ProbeRecovered})
	env.launch = func(context.Context, store.Settings) (*edge.Session, error) { return nil, nil }
	if got := runProbe(env, base, false); got != 1 {
		t.Fatalf("exit = %d, want 1 when the launcher returns no session", got)
	}
	if spy.calls != 0 {
		t.Fatalf("there is no browser to close, but close ran %d times", spy.calls)
	}
	if !strings.Contains(out.String(), "没有返回浏览器会话") {
		t.Fatalf("output must say no session was returned: %s", out.String())
	}
}

func TestLauncherGetsTheFinalAbsolutePathNotABaseToResolveAgain(t *testing.T) {
	var out bytes.Buffer
	env, _, accountDir, base := stubProbeEnv(t, &out, signin.ProbeResult{Class: signin.ProbeRecovered})
	var got string
	env.launch = func(_ context.Context, cfg store.Settings) (*edge.Session, error) {
		got = cfg.UserData
		return &edge.Session{PID: 4242, UserData: cfg.UserData, Ctx: context.Background()}, nil
	}
	if code := runProbe(env, base, false); code != 0 {
		t.Fatalf("exit = %d, want 0 (output: %s)", code, out.String())
	}
	if got != accountDir {
		t.Fatalf("launcher userData = %q, want the checked final path %q", got, accountDir)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("launcher userData must already be absolute: %q", got)
	}
}

func probeTestEnv(t *testing.T, out *bytes.Buffer) probeEnv {
	t.Helper()
	return probeEnv{
		dataDir: t.TempDir(),
		out:     out,
		launch: func(context.Context, store.Settings) (*edge.Session, error) {
			t.Fatal("the browser must not be launched here")
			return nil, nil
		},
		creds: func() (string, string, error) { return "20230001", "pw", nil },
	}
}

func TestProbeProfileRejectsRelativeExplicitPath(t *testing.T) {
	cfg := store.Defaults()
	if _, _, err := resolveProbeProfile(`edge-userdata\其他目录`, cfg, "20230001"); err == nil {
		t.Fatal("a relative -session-probe-profile must be rejected")
	} else if !strings.Contains(err.Error(), "绝对路径") {
		t.Fatalf("error should ask for an absolute path: %v", err)
	}
}

func TestProbeProfileRejectsTheAccountDirectory(t *testing.T) {
	cfg := store.Defaults()
	base := t.TempDir()
	accountDir := filepath.Join(base, "accounts-v1", accountKey("20230001"))

	_, p, err := resolveProbeProfile(accountDir, cfg, "20230001")
	if err == nil {
		t.Fatal("passing the account directory itself must be refused")
	}
	// The hint has to name the whole segment, not just "go up one level".
	if !strings.Contains(err.Error(), `accounts-v1\<账号目录>`) || !strings.Contains(err.Error(), "父目录") {
		t.Fatalf("error should explain removing the whole account segment: %v", err)
	}
	if p.AccountDir != "" {
		t.Fatalf("no path may be produced on rejection: %q", p.AccountDir)
	}
}

func TestProbeProfileAppendsTheAccountSegmentExactlyOnce(t *testing.T) {
	cfg := store.Defaults()
	base := t.TempDir()

	cfgProfile, p, err := resolveProbeProfile(base, cfg, "20230001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(base, "accounts-v1", accountKey("20230001"))
	if p.AccountDir != want {
		t.Fatalf("account dir = %q, want %q", p.AccountDir, want)
	}
	if n := strings.Count(p.AccountDir, "accounts-v1"); n != 1 {
		t.Fatalf("account segment appears %d times in %q, want exactly 1", n, p.AccountDir)
	}
	// The path printed, checked and given to the launcher must be the same one.
	resolved, err := edge.ProfilePath(cfgProfile)
	if err != nil {
		t.Fatalf("ProfilePath: %v", err)
	}
	if resolved != p.AccountDir {
		t.Fatalf("launcher profile = %q, checked profile = %q", resolved, p.AccountDir)
	}
}

func TestProbeProfileReportsWhereThePathCameFrom(t *testing.T) {
	base := t.TempDir()

	// Explicit flag.
	cfg := store.Defaults()
	if _, p, err := resolveProbeProfile(base, cfg, "20230001"); err != nil || p.Source != "显式指定" {
		t.Fatalf("explicit source = %q, err = %v", p.Source, err)
	}

	// Configured userData.
	cfg.UserData = base
	if _, p, err := resolveProbeProfile("", cfg, "20230001"); err != nil || p.Source != "配置" {
		t.Fatalf("configured source = %q, err = %v", p.Source, err)
	}

	// Nothing configured: the program default.
	cfg.UserData = store.Defaults().UserData
	_, p, err := resolveProbeProfile("", cfg, "20230001")
	if err != nil {
		t.Fatalf("default source failed: %v", err)
	}
	if p.Source != "默认" {
		t.Fatalf("default source = %q, want 默认", p.Source)
	}
	if !filepath.IsAbs(p.BaseAbs) || !strings.HasSuffix(strings.ToLower(p.BaseAbs), strings.ToLower(store.Defaults().UserData)) {
		t.Fatalf("default base must be resolved against the program directory, got %q", p.BaseAbs)
	}
}

func TestProbeProfileRefusesToInventADirectory(t *testing.T) {
	base := t.TempDir()
	_, p, err := resolveProbeProfile(base, store.Defaults(), "20230001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := checkProbeProfile(p); err == nil {
		t.Fatal("a missing account directory must be an error, not a silent creation")
	} else if !strings.Contains(err.Error(), "不会新建") {
		t.Fatalf("error should say nothing is created: %v", err)
	}

	if err := os.MkdirAll(p.AccountDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkProbeProfile(p); err != nil {
		t.Fatalf("an existing account directory must pass: %v", err)
	}

	fileAsDir := filepath.Join(base, "accounts-v1", accountKey("20230002"))
	if err := os.MkdirAll(filepath.Dir(fileAsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, p2, err := resolveProbeProfile(base, store.Defaults(), "20230002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := checkProbeProfile(p2); err == nil {
		t.Fatal("a file in place of the account directory must be an error")
	} else if !strings.Contains(err.Error(), "不是目录") {
		t.Fatalf("error should say it is not a directory: %v", err)
	}
}

func TestDryRunChecksTheProfileWithoutLaunchingAnything(t *testing.T) {
	var out bytes.Buffer
	env := probeTestEnv(t, &out)
	base := t.TempDir()
	// exists already: the dry run only checks.
	result := runProbe(env, base, true)
	if result != 1 {
		// The account directory does not exist yet, so the check must fail.
		t.Fatalf("dry run on a missing profile returned %d, want 1", result)
	}
	if !strings.Contains(out.String(), filepath.Join("accounts-v1", accountKey("20230001"))) {
		t.Fatalf("dry run must print the final path: %s", out.String())
	}

	// Now with the directory present: still no launch, no lock, nothing created.
	accountDir := filepath.Join(base, "accounts-v1", accountKey("20230001"))
	if err := os.MkdirAll(accountDir, 0o755); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, base)
	launches := 0
	env.launch = func(context.Context, store.Settings) (*edge.Session, error) {
		launches++
		return nil, nil
	}
	out.Reset()
	if result := runProbe(env, base, true); result != 0 {
		t.Fatalf("dry run on an existing profile = %d, want 0 (output: %s)", result, out.String())
	}
	if launches != 0 {
		t.Fatalf("the browser launcher was called %d times, want 0", launches)
	}
	if !strings.Contains(out.String(), "dry-run") {
		t.Fatalf("dry run should say it is a dry run: %s", out.String())
	}
	if after := listDir(t, base); after != before {
		t.Fatalf("dry run changed the profile tree: before=%q after=%q", before, after)
	}
}

func TestLaunchReceivesThePathThatWasChecked(t *testing.T) {
	var out bytes.Buffer
	env := probeTestEnv(t, &out)
	base := t.TempDir()
	accountDir := filepath.Join(base, "accounts-v1", accountKey("20230001"))
	if err := os.MkdirAll(accountDir, 0o755); err != nil {
		t.Fatal(err)
	}

	var got string
	env.launch = func(_ context.Context, cfg store.Settings) (*edge.Session, error) {
		resolved, err := edge.ProfilePath(cfg)
		if err != nil {
			t.Fatalf("ProfilePath: %v", err)
		}
		got = resolved
		return nil, os.ErrInvalid
	}
	if result := runProbe(env, base, false); result != 1 {
		t.Fatalf("a launcher error must exit 1, got %d", result)
	}
	if got != accountDir {
		t.Fatalf("launcher profile = %q, want %q", got, accountDir)
	}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}

func TestProfileFlagAloneIsAFlagErrorNotTheGUI(t *testing.T) {
	cases := []struct {
		name             string
		probe, dryRun    bool
		profileFlagGiven bool
		wantMode         processMode
		wantErr          bool
	}{
		{name: "profile only", profileFlagGiven: true, wantErr: true},
		{name: "profile only, probe explicitly off", probe: false, dryRun: false, profileFlagGiven: true, wantErr: true},
		{name: "profile with probe", probe: true, profileFlagGiven: true, wantMode: modeProbe},
		{name: "profile with dry run", dryRun: true, profileFlagGiven: true, wantMode: modeProbeDryRun},
		{name: "profile with both probe and dry run", probe: true, dryRun: true, profileFlagGiven: true, wantMode: modeProbeDryRun},
		{name: "no probe flags at all: the GUI, unchanged", wantMode: modeGUI},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode, err := resolveProcessMode(c.probe, c.dryRun, c.profileFlagGiven)
			if c.wantErr {
				if err == nil {
					t.Fatal("a profile flag without a probe mode must be an error")
				}
				// Whatever the mode value is, the caller exits on the error, so no
				// launch mode may be selected here.
				if mode == modeProbe || mode == modeProbeDryRun {
					t.Fatalf("mode = %v, want no launch mode on error", mode)
				}
				if !strings.Contains(err.Error(), "session-probe") {
					t.Fatalf("error should name the flags that were missing: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != c.wantMode {
				t.Fatalf("mode = %v, want %v", mode, c.wantMode)
			}
		})
	}
}

func TestProfileFlagPresenceIncludesAnEmptyValue(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	profile := fs.String("session-probe-profile", "", "")
	if err := fs.Parse([]string{"-session-probe-profile="}); err != nil {
		t.Fatal(err)
	}
	if *profile != "" {
		t.Fatalf("value = %q, want empty", *profile)
	}
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "session-probe-profile" {
			given = true
		}
	})
	if !given {
		t.Fatal("an explicitly passed empty value must still count as given")
	}
	if _, err := resolveProcessMode(false, false, given); err == nil {
		t.Fatal("an empty but explicit profile value must not fall through to the GUI")
	}
}
