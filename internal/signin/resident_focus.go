package signin

import (
	"context"
	"github.com/chromedp/cdproto/emulation"
)

// Emulation changes renderer focus/visibility, not native window visibility.
// Scope it to the resident sign-in lease; read-only attachment is unchanged.
var residentFocus = func(ctx context.Context, enabled bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return emulation.SetFocusEmulationEnabled(enabled).Do(exec(ctx))
}
