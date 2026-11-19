package signin

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestResidentEntryPolicy(t *testing.T) {
	now := time.Date(2026, 11, 4, 22, 0, 0, 0, time.UTC)
	stable := "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq"
	for _, tc := range []struct {
		name, current, target  string
		resident, owned, fresh bool
		want                   entryDecision
		calls                  []string
		fail                   bool
	}{
		{"private unchanged", "https://evil.invalid", "https://private.invalid", false, false, true, entryPrivate, []string{"navigate"}, false},
		{"missing ownership", stable, stable, true, false, true, entryStopped, nil, true},
		{"previous task CAS", "https://ids.gzist.edu.cn/lyuapServer/login?service=PRIVATE", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"previous task authserver CAS", "https://ids.gzist.edu.cn/authserver/login", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"previous task twoVerify", "https://ids.gzist.edu.cn/loginAgain", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"old twoVerify rejects unstable configured target", "https://ids.gzist.edu.cn/loginAgain", "https://ids.gzist.edu.cn/loginAgain", true, true, true, entryStopped, []string{"probe"}, true},
		{"yesterday success document", stable, stable, true, true, false, entryReload, []string{"probe", "navigate", "reload"}, false},
		{"hash only change", "https://xsfw.gzist.edu.cn/index.do#/old", stable, true, true, false, entryReload, []string{"probe", "navigate", "reload"}, false},
		{"callback ticket never reloaded", "https://xsfw.gzist.edu.cn/index.do?ticket=PRIVATE#/xscq/grcq", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"unknown host fixed entry only", "https://evil.invalid/login", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"lookalike CAS fixed entry only", "https://ids.gzist.edu.cn.evil.invalid/loginAgain", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"twoVerify query is unknown", "https://ids.gzist.edu.cn/loginAgain?ticket=PRIVATE", stable, true, true, true, entryFresh, []string{"probe", "navigate"}, false},
		{"unstable config closed", stable, "https://xsfw.gzist.edu.cn/index.do?ticket=PRIVATE#/xscq/grcq", true, true, false, entryStopped, []string{"probe"}, true},
		{"foreign config closed", stable, "https://evil.invalid", true, true, false, entryStopped, []string{"probe"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			ops := entryOps{
				now:   func() time.Time { return now },
				probe: func(context.Context) (string, error) { calls = append(calls, "probe"); return tc.current, nil },
				navigate: func(_ context.Context, u string) (bool, error) {
					calls = append(calls, "navigate")
					if u != tc.target {
						t.Fatal("navigated outside configured entry")
					}
					return tc.fresh, nil
				},
				reload: func(_ context.Context, u string) error {
					calls = append(calls, "reload")
					if u != stable {
						t.Fatal("reloaded nonstable callback")
					}
					return nil
				},
			}
			got, err := prepareEntry(context.Background(), tc.resident, tc.owned, tc.target, now.Add(time.Hour), ops)
			if got != tc.want || (err != nil) != tc.fail || !reflect.DeepEqual(calls, tc.calls) {
				t.Fatalf("decision=%s err=%v calls=%v want=%s %v", got, err, calls, tc.want, tc.calls)
			}
		})
	}
}

func TestResidentEntryStopsAtEveryEffect(t *testing.T) {
	for _, stop := range []string{"before", "probe", "navigate", "reload"} {
		for _, late := range []bool{false, true} {
			t.Run(stop+map[bool]string{true: " late", false: " cancel"}[late], func(t *testing.T) {
				now := time.Date(2026, 11, 4, 22, 0, 0, 0, time.UTC)
				deadline := now.Add(time.Hour)
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				var calls []string
				end := func(at string) {
					if at == stop {
						if late {
							now = deadline
						} else {
							cancel(context.Canceled)
						}
					}
				}
				end("before")
				ops := entryOps{
					now: func() time.Time { return now },
					probe: func(context.Context) (string, error) {
						calls = append(calls, "probe")
						end("probe")
						return "https://xsfw.gzist.edu.cn/index.do", nil
					},
					navigate: func(context.Context, string) (bool, error) {
						calls = append(calls, "navigate")
						end("navigate")
						return false, nil
					},
					reload: func(context.Context, string) error { calls = append(calls, "reload"); end("reload"); return nil },
				}
				got, err := prepareEntry(ctx, true, true, "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq", deadline, ops)
				expected := context.Canceled
				if late {
					expected = errLateLine
				}
				if got != entryStopped || !errors.Is(err, expected) {
					t.Fatalf("%s %v", got, err)
				}
				want := map[string]int{"before": 0, "probe": 1, "navigate": 2, "reload": 3}[stop]
				if len(calls) != want {
					t.Fatalf("effects after stop: %v", calls)
				}
			})
		}
	}
}

func TestResidentEntryEffectFailuresFailClosed(t *testing.T) {
	for _, failure := range []string{"probe", "navigate", "reload"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now()
			var calls []string
			fail := func(at string) error {
				calls = append(calls, at)
				if at == failure {
					return errors.New("PRIVATE ticket URL")
				}
				return nil
			}
			ops := entryOps{
				now:      func() time.Time { return now },
				probe:    func(context.Context) (string, error) { return "https://xsfw.gzist.edu.cn/index.do", fail("probe") },
				navigate: func(context.Context, string) (bool, error) { return false, fail("navigate") },
				reload:   func(context.Context, string) error { return fail("reload") },
			}
			decision, err := prepareEntry(context.Background(), true, true, "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq", now.Add(time.Hour), ops)
			if decision != entryStopped || err != errResidentEntry {
				t.Fatalf("not redacted and closed: %s %v", decision, err)
			}
			if len(calls) != map[string]int{"probe": 1, "navigate": 2, "reload": 3}[failure] {
				t.Fatal(calls)
			}
		})
	}
}

// A fake document preserves yesterday's success until a full document refresh.
// The entry result must not expose that old success, including hash-only navigate.
func TestResidentEntryInvalidatesYesterdaySuccess(t *testing.T) {
	for _, newDocument := range []bool{false, true} {
		oldSuccess := true
		now := time.Now()
		_, err := prepareEntry(context.Background(), true, true, "https://xsfw.gzist.edu.cn/index.do#/xscq/grcq", now.Add(time.Hour), entryOps{
			now:   func() time.Time { return now },
			probe: func(context.Context) (string, error) { return "https://xsfw.gzist.edu.cn/index.do#/old", nil },
			navigate: func(context.Context, string) (bool, error) {
				if newDocument {
					oldSuccess = false
				}
				return newDocument, nil
			},
			reload: func(context.Context, string) error { oldSuccess = false; return nil },
		})
		if err != nil || oldSuccess {
			t.Fatalf("yesterday's DOM survived: newDocument=%v err=%v", newDocument, err)
		}
	}
}
