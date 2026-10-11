package signin

import (
	"context"
	"errors"
	"time"
)

var errLateLine = errors.New("已到晚归线，停止本轮操作，避免晚归记录")

func beforeLateLine(ctx context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadlineCause(ctx, deadline, errLateLine)
}

type formVisibility struct{ since time.Time }

// The PS grace period starts when the form appears, not when probing starts.
func (f *formVisibility) stable(now time.Time, visible bool) bool {
	if !visible {
		f.since = time.Time{}
		return false
	}
	if f.since.IsZero() {
		f.since = now
	}
	return now.Sub(f.since) >= 4*time.Second
}
