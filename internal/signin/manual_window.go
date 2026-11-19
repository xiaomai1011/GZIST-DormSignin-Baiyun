package signin

import (
	"context"
	"errors"
	"time"
)

var errManualWindow = errors.New("自动显示验证窗口失败；本轮停止，请在设置中检查浏览器窗口")

// revealManualWindow never navigates or submits anything. Its callback controls
// only the generation-bound browser window already owned by this task.
func revealManualWindow(ctx context.Context, resident bool, show func(context.Context) error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if !resident {
		return nil
	}
	if show == nil {
		return errManualWindow
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := show(c)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	if c.Err() != nil || err != nil {
		return errManualWindow
	}
	return nil
}

func (r *Runner) revealVerificationWindow(ctx context.Context) error {
	var show func(context.Context) error
	if r.hostClient != nil {
		show = func(c context.Context) error { return r.hostClient.SetWindowVisible(c, true) }
	}
	return revealManualWindow(ctx, r.Cfg.ResidentBrowser, show)
}
