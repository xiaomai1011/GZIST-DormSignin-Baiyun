package signin

import (
	"context"
	"strings"
	"time"
)

// Observe one submission. A slow response must never trigger a second sign-in
// click; delayed captcha dialogs are handled inside this bounded observation.
func waitSignResult(ctx context.Context, budget, poll time.Duration,
	read func(context.Context) string, handle func(context.Context, int),
) (hit, last string, err error) {
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	tries := 0
	for {
		if err := sleepCtx(waitCtx, poll); err != nil {
			return "", last, context.Cause(waitCtx)
		}
		last = read(waitCtx)
		if waitCtx.Err() != nil {
			return "", last, context.Cause(waitCtx)
		}
		if hit = hitKeyword(last); hit != "" {
			return hit, last, nil
		}
		if strings.Contains(last, "验证码") && tries < 3 {
			tries++ // A failed recognition consumes an attempt too, as in the PS original.
			handle(waitCtx, tries)
		}
	}
}
