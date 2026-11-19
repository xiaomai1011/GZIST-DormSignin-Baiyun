package signin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRevealManualWindow(t *testing.T) {
	t.Run("resident shows once with deadline", func(t *testing.T) {
		n := 0
		err := revealManualWindow(context.Background(), true, func(c context.Context) error {
			n++
			d, ok := c.Deadline()
			if !ok || time.Until(d) > 5*time.Second {
				t.Fatal("missing bounded deadline")
			}
			return nil
		})
		if err != nil || n != 1 {
			t.Fatalf("err=%v calls=%d", err, n)
		}
	})
	t.Run("ordinary visible no native action", func(t *testing.T) {
		if err := revealManualWindow(context.Background(), false, func(context.Context) error { t.Fatal("unexpected show"); return nil }); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing and failed controller stop", func(t *testing.T) {
		if !errors.Is(revealManualWindow(context.Background(), true, nil), errManualWindow) {
			t.Fatal("missing accepted")
		}
		if !errors.Is(revealManualWindow(context.Background(), true, func(context.Context) error { return errors.New("private detail") }), errManualWindow) {
			t.Fatal("failure accepted")
		}
	})
	t.Run("cancel before show", func(t *testing.T) {
		c, cancel := context.WithCancel(context.Background())
		cancel()
		if !errors.Is(revealManualWindow(c, true, func(context.Context) error { t.Fatal("show after cancel"); return nil }), context.Canceled) {
			t.Fatal("cancel lost")
		}
	})
	t.Run("cancel during successful show", func(t *testing.T) {
		c, cancel := context.WithCancel(context.Background())
		defer cancel()
		if !errors.Is(revealManualWindow(c, true, func(context.Context) error { cancel(); return nil }), context.Canceled) {
			t.Fatal("late success accepted")
		}
	})
}
