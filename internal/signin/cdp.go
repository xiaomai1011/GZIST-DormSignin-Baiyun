// CDP primitives shared by the sign-in flow: trusted mouse clicks and
// the geolocation override. These replace the raw WebSocket calls of
// the PowerShell original (Send-Cdp / Invoke-CdpMouseAt).
package signin

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// exec wraps the browser-level chromedp ctx with the page target as the
// action executor. chromedp v0.13 split the API: actions need an executor,
// and a plain browser-level ctx is not one — calling .Do(ctx) directly
// fails with "invalid context".
func exec(ctx context.Context) context.Context {
	c := chromedp.FromContext(ctx)
	if c == nil {
		return ctx // let the action fail with its own error
	}
	return cdp.WithExecutor(ctx, c.Target)
}

// dispatchMouseClick sends moved→pressed→released, a trusted gesture.
func dispatchMouseClick(ctx context.Context, x, y float64) {
	if x < 0 || y < 0 {
		return
	}
	_ = input.DispatchMouseEvent(input.MouseMoved, x, y).Do(exec(ctx))
	time.Sleep(90 * time.Millisecond)
	_ = input.DispatchMouseEvent(input.MousePressed, x, y).
		WithButton(input.Left).WithClickCount(1).Do(exec(ctx))
	time.Sleep(90 * time.Millisecond)
	_ = input.DispatchMouseEvent(input.MouseReleased, x, y).
		WithButton(input.Left).WithClickCount(1).Do(exec(ctx))
}

// dispatchTouchAt sends touchStart/touchEnd — some buttons under the
// iPhone UA respond to touch rather than mouse (the original's ladder).
func dispatchTouchAt(ctx context.Context, x, y float64) {
	if x < 0 || y < 0 {
		return
	}
	_ = emulation.SetTouchEmulationEnabled(true).Do(exec(ctx))
	time.Sleep(80 * time.Millisecond)
	_ = input.DispatchTouchEvent(input.TouchStart, []*input.TouchPoint{{X: x, Y: y}}).Do(exec(ctx))
	time.Sleep(70 * time.Millisecond)
	_ = input.DispatchTouchEvent(input.TouchEnd, []*input.TouchPoint{}).Do(exec(ctx))
	time.Sleep(80 * time.Millisecond)
}

// emulationSetGeo overrides the browser geolocation (the fix for Windows
// location services timing out or drifting to the ISP's IP position).
func emulationSetGeo(ctx context.Context, lat, lon, accM float64) error {
	if err := emulation.SetGeolocationOverride().
		WithLatitude(lat).WithLongitude(lon).WithAccuracy(accM).Do(exec(ctx)); err != nil {
		return err
	}
	c := chromedp.FromContext(ctx)
	if c == nil || c.Browser == nil {
		return fmt.Errorf("定位授权缺少浏览器上下文")
	}
	// An override supplies coordinates, but does not grant the page permission
	// to read them. This browser-scoped call was present in the PS original.
	return browser.GrantPermissions([]browser.PermissionType{browser.PermissionTypeGeolocation}).
		WithOrigin("https://xsfw.gzist.edu.cn").Do(cdp.WithExecutor(ctx, c.Browser))
}

// evalStr runs a JS expression and returns its string result ("" on error).
func evalStr(ctx context.Context, expr string) string {
	var s string
	chromedp.Evaluate(expr, &s).Do(exec(ctx))
	return s
}

// reloadIgnoreCache is Page.reload(ignoreCache=true) — the original's
// recovery for a stalled Baidu-map SDK and for cached geo verdicts.
func reloadIgnoreCache(ctx context.Context) {
	_ = page.Reload().WithIgnoreCache(true).Do(exec(ctx))
}

// CredsFunc supplies the student credentials; tests and main wire it to
// the store.
type CredsFunc func() (string, string, error)

var _ = store.Settings{}
