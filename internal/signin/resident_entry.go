package signin

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Entry decisions are fixed enums: URLs, tickets and page text never enter logs.
type entryDecision string

const (
	entryPrivate entryDecision = "private_navigate"
	entryFresh   entryDecision = "fresh_navigation"
	entryReload  entryDecision = "stable_reload"
	entryStopped entryDecision = "stopped"
)

var errResidentEntry = errors.New("常驻入口检查失败，停止本轮")

// probe reads only the attached target URL. navigate waits for navigation and
// reports whether it created a document; a hash-only navigation is not freshness.
// reload must atomically check the exact stable URL before reloading, and wait
// for the new document. No enumeration, tab switching or form effects exist here.
type entryOps struct {
	probe    func(context.Context) (string, error)
	navigate func(context.Context, string) (bool, error)
	reload   func(context.Context, string) error
	now      func() time.Time
}

func prepareEntry(ctx context.Context, resident, owned bool, target string, deadline time.Time, ops entryOps) (entryDecision, error) {
	check := func() error {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if !ops.now().Before(deadline) {
			return errLateLine
		}
		return nil
	}
	if err := check(); err != nil {
		return entryStopped, err
	}
	if !resident {
		_, err := ops.navigate(ctx, target)
		if stop := check(); stop != nil {
			return entryStopped, stop
		}
		return entryPrivate, err
	}
	if !owned {
		return entryStopped, errResidentEntry
	}
	_, err := ops.probe(ctx)
	if stop := check(); stop != nil {
		return entryStopped, stop
	}
	if err != nil {
		return entryStopped, errResidentEntry
	}
	// This is called once at the start of a NEW task, never from the manual
	// verification wait. A retained CAS/2FA URL is not proof that its previous
	// authentication transaction is still valid. Start from the stable business
	// entry, allowing valid server sessions to redirect normally. Do not reload
	// a stale verification page or a callback carrying an old ticket.
	// In-task verification continues on its existing page without navigation.
	if !stableRecoveryURL(target) {
		return entryStopped, errResidentEntry
	}
	fresh, err := ops.navigate(ctx, target)
	if stop := check(); stop != nil {
		return entryStopped, stop
	}
	if err != nil {
		return entryStopped, errResidentEntry
	}
	if fresh {
		return entryFresh, nil
	}
	// Navigate may only change the hash (or leave the existing document intact).
	// The guarded reload never reloads a callback URL carrying an old CAS ticket.
	if err := ops.reload(ctx, target); err != nil {
		if stop := check(); stop != nil {
			return entryStopped, stop
		}
		return entryStopped, errResidentEntry
	}
	if stop := check(); stop != nil {
		return entryStopped, stop
	}
	return entryReload, nil
}

func (r *Runner) prepareRunEntry(ctx context.Context, deadline time.Time, ownedTargetID string) error {
	c := chromedp.FromContext(ctx)
	owned := r.hostClient != nil && ownedTargetID != "" && c != nil && c.Target != nil && string(c.Target.TargetID) == ownedTargetID
	decision, err := prepareEntry(ctx, r.Cfg.ResidentBrowser, owned, r.Cfg.URL, deadline, entryOps{
		now: time.Now,
		probe: func(c context.Context) (string, error) {
			var u string
			err := chromedp.Location(&u).Do(exec(c))
			return u, err
		},
		navigate: func(c context.Context, u string) (bool, error) {
			// Keep private browser navigation unchanged.
			if !r.Cfg.ResidentBrowser {
				return true, chromedp.Navigate(u).Do(exec(c))
			}
			fresh := false
			response, err := chromedp.RunResponse(c, chromedp.ActionFunc(func(c context.Context) error {
				_, loader, message, err := page.Navigate(u).Do(c)
				if err != nil {
					return err
				}
				if message != "" {
					return errResidentEntry
				}
				fresh = loader != ""
				return nil
			}))
			if err == nil && fresh && response == nil {
				return false, errResidentEntry
			}
			return fresh, err
		},
		reload: reloadStableEntry,
	})
	r.log("  常驻入口策略: " + string(decision))
	return err
}

func reloadStableEntry(ctx context.Context, target string) error {
	if !stableRecoveryURL(target) {
		return errResidentEntry
	}
	encoded, _ := json.Marshal(target)
	// The comparison and reload share one renderer task: redirects between a
	// Go-side URL probe and Page.reload must never replay a consumed ticket.
	script := `(() => { if (location.href !== new URL(` + string(encoded) + `).href) throw new Error('entry_changed'); location.reload(); })()`
	response, err := chromedp.RunResponse(ctx, chromedp.Evaluate(script, nil))
	if err == nil && response == nil {
		// RunResponse also finishes on a fragment event. A concurrent SPA hash
		// change is not proof that reload created and loaded a new document.
		return errResidentEntry
	}
	return err
}
