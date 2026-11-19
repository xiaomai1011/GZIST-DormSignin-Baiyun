package browserhost

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// Opt-in only. Uses newHarness's temporary profile and loopback HTTP server;
// never loads account settings, real profiles or school URLs. Run only with
// DORMSIGN_EDGE_TEST=1 BROWSERHOST_TARGET_REUSE_TEST=1 and this exact test name.
func TestOwnedTargetRetainsDocumentAcrossLeasesEdge(t *testing.T) {
	if os.Getenv("BROWSERHOST_TARGET_REUSE_TEST") != "1" {
		t.Skip("requires BROWSERHOST_TARGET_REUSE_TEST=1")
	}
	d, c, server := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	first, release, err := c.Attach(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := chromedp.Run(first.Ctx, chromedp.Navigate(server.URL+"/read"), chromedp.Evaluate(`window.__residentFixture="same-document"; sessionStorage.setItem("resident-fixture", "same-session");`, nil)); err != nil {
		t.Fatal(err)
	}
	id := first.TargetID
	before, err := chromedp.Targets(d.session.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	release()
	second, release2, err := c.Attach(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	defer second.Close()
	var value string
	if err := chromedp.Run(second.Ctx, chromedp.Evaluate(`window.__residentFixture+":"+sessionStorage.getItem("resident-fixture")`, &value)); err != nil {
		t.Fatal(err)
	}
	after, err := chromedp.Targets(d.session.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.TargetID != id || value != "same-document:same-session" || len(before) != len(after) {
		t.Fatalf("target/document not retained: sameID=%t value=%q targets=%d/%d", second.TargetID == id, value, len(before), len(after))
	}
}
