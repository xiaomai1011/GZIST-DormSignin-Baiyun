package edge

import (
	"context"
	"sync"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// connectionAllocator owns only a CDP transport, never a browser or a page.
// Do not replace it with RemoteAllocator: in chromedp v0.13.6 a remote
// NewContext has first=false and cancellation sends Target.closeTarget even
// with WithTargetID. A root NewContext with this allocator has first=true:
// ordinary context cancellation skips target cleanup, and NewBrowser closes
// the websocket, which detaches this connection's sessions on the server.
// Unlike RemoteAllocator, this allocator never calls chromedp.Cancel (which
// would send Browser.close for a root context). No chromedp internals mutate.
// The pinned dependency contract is exercised against an offline CDP fixture.
type connectionAllocator struct {
	endpoint string
	mu       sync.Mutex
	browser  *chromedp.Browser
}

func (a *connectionAllocator) Allocate(ctx context.Context, opts ...chromedp.BrowserOption) (*chromedp.Browser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := chromedp.NewBrowser(ctx, a.endpoint, opts...)
	if err == nil {
		a.browser = b
	}
	return b, err
}

func (a *connectionAllocator) Wait() {
	a.mu.Lock()
	b := a.browser
	a.mu.Unlock()
	if b != nil {
		<-b.LostConnection
	}
}

// newAttachedContext intentionally starts a fresh root rather than inheriting
// any chromedp Context from parent. Parent cancellation is forwarded without
// granting parent or chromedp ownership of the resident target. Call close to
// wait until this client's websocket has disconnected; never chromedp.Cancel.
func newAttachedContext(parent context.Context, endpoint, targetID string) (context.Context, context.CancelFunc) {
	root, cancelRoot := context.WithCancel(context.Background())
	stop := context.AfterFunc(parent, cancelRoot)
	a := &connectionAllocator{endpoint: endpoint}
	ctx, cancelContext := chromedp.NewContext(root,
		chromedp.WithTargetID(target.ID(targetID)),
		func(c *chromedp.Context) { c.Allocator = a },
	)
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			stop()
			cancelRoot()
			cancelContext()
			a.Wait()
		})
	}
}
