package browserhost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestTaskLeaseCleanupOrderAndFailures(t *testing.T) {
	cleanErr := errors.New("focus restore failed")
	closeErr := errors.New("disconnect failed")
	releaseErr := errors.New("release failed")
	abortErr := errors.New("revoke failed")
	for _, tc := range []struct {
		name                         string
		clean, close, release, abort error
		canceled                     bool
		want                         []string
	}{
		{name: "success", want: []string{"cleanup", "close", "release"}},
		{name: "canceled but transport alive", canceled: true, want: []string{"cleanup", "close", "release"}},
		{name: "canceled transport gone", canceled: true, clean: cleanErr, want: []string{"cleanup", "close", "abort"}},
		{name: "restore failed", clean: cleanErr, want: []string{"cleanup", "close", "abort"}},
		{name: "disconnect failed", close: closeErr, want: []string{"cleanup", "close", "abort"}},
		{name: "release failed", release: releaseErr, want: []string{"cleanup", "close", "release", "abort"}},
		{name: "errors joined", clean: cleanErr, close: closeErr, abort: abortErr, want: []string{"cleanup", "close", "abort"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			var order []string
			finish := taskLeaseFinisher(ctx, func(cleanCtx context.Context) error {
				order = append(order, "cleanup")
				if cleanCtx.Err() != nil {
					t.Fatalf("cleanup inherited cancellation: %v", cleanCtx.Err())
				}
				deadline, ok := cleanCtx.Deadline()
				if !ok || time.Until(deadline) > 3*time.Second {
					t.Fatal("missing independent cleanup budget")
				}
				return tc.clean
			}, func() error { order = append(order, "close"); return tc.close }, func() error { order = append(order, "release"); return tc.release }, func() error { order = append(order, "abort"); return tc.abort })
			err := finish()
			again := finish()
			if !reflect.DeepEqual(order, tc.want) {
				t.Fatalf("order=%v want=%v", order, tc.want)
			}
			if (err == nil) != (tc.clean == nil && tc.close == nil && tc.release == nil) {
				t.Fatalf("error=%v", err)
			}
			if err != again {
				t.Fatal("finish not idempotent")
			}
			for _, want := range []error{tc.clean, tc.close, tc.release, tc.abort} {
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("lost error %v in %v", want, err)
				}
			}
		})
	}
}
