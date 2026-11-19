package signin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/browserhost"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/edge"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// launchEdge is a seam so tests can prove that the resident mode never falls
// back to a private browser.
var launchEdge = edge.LaunchContext

// residentLeaseTTL must outlive the longest run: the manual two-factor wait and
// the business-page budget can together exceed six minutes, and a lease that
// expires mid-run would have the host revoke the browser underneath the flow.
const residentLeaseTTL = 10 * time.Minute

// openBrowser returns the browser a run may drive. In resident mode there is
// exactly one path: take a lease from the host. A busy host, an unclear
// confirmation or a failed attach ends the run; switching to a private browser
// would mean signing in from an unaccounted process, which the safety rules
// forbid. Only the explicit non-resident mode starts its own Edge.
func (r *Runner) openBrowser(ctx context.Context) (*edge.Session, func() error, error) {
	if !r.Cfg.ResidentBrowser {
		s, err := launchEdge(ctx, r.Cfg)
		return s, nil, err
	}
	path, err := residentStatePath(r.Cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("常驻模式无法定位宿主状态文件: %w", err)
	}
	profile, err := edge.ProfilePath(r.Cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("常驻模式无法定位账号 profile: %w", err)
	}
	var client *browserhost.Client
	if r.Hosts != nil {
		// The application owns the host: start it on demand, reuse it between
		// runs, and never fall back to a private browser when it cannot serve.
		client, err = r.Hosts.Ensure(ctx, r.Cfg)
	} else {
		client, err = browserhost.Dial(path, profile)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("常驻宿主不可用，本次不执行（不会改用独立浏览器）: %w", err)
	}
	sess, release, err := client.AttachForTask(ctx, residentLeaseTTL, func(cleanCtx context.Context, _ *edge.Session) error {
		return residentFocus(cleanCtx, false)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("常驻浏览器租约失败，本次不执行（不会改用独立浏览器）: %w", err)
	}
	if err := residentFocus(sess.Ctx, true); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("常驻页面焦点模拟开启未确认: %w", err), release())
	}
	r.hostClient = client
	r.log("  常驻浏览器租约已激活（默认隐藏；需人工验证时请主动显示窗口）")
	return sess, func() error {
		// A canceled task still hides only its own host generation before
		// returning the lease. Never reopen a window automatically.
		hideCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.SetWindowVisible(hideCtx, false); err != nil {
			r.log("!! 本轮结束时未确认浏览器已隐藏，请使用设置中的隐藏按钮")
		}
		return release()
	}, nil
}

// residentStatePath is where the host writes its control address and token. It
// lives inside the account's browser profile, so two accounts can never share a
// discovery file and one account's task can never find the other's browser.
func residentStatePath(cfg store.Settings) (string, error) {
	profile, err := edge.ProfilePath(cfg)
	if err != nil {
		return "", err
	}
	return filepath.Join(profile, browserhost.StateFileName), nil
}
