package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
type cancelReader struct { io.Reader; cancel context.CancelFunc }
func (r cancelReader) Read(b []byte) (int, error) { n, err := r.Reader.Read(b); r.cancel(); return n, err }

func TestCanceledResponseNeverPublishesOrCaches(t *testing.T) {
 for _, tc := range []struct{name string; status int; duringBody bool}{
  {"response200",200,false}, {"response404",404,false}, {"body200",200,true},
 } { t.Run(tc.name,func(t *testing.T){
  ctx,cancel:=context.WithCancel(context.Background());defer cancel()
  path:=filepath.Join(t.TempDir(),"update-check.json")
  c:=New(path)
  c.client.Transport=roundTripFunc(func(r *http.Request)(*http.Response,error){
   var reader io.Reader = strings.NewReader(releaseJSON("v2.0.20",ReleasesURL+"/tag/v2.0.20"))
   if tc.duringBody { reader=cancelReader{Reader:reader,cancel:cancel} } else { cancel() }
   return &http.Response{StatusCode:tc.status,Header:make(http.Header),Body:io.NopCloser(reader),Request:r},nil
  })
  result,err:=c.Check(ctx,"2.0.19",true)
  if !errors.Is(err,context.Canceled) || result.Release!=nil { t.Fatalf("canceled result=%+v err=%v",result,err) }
  if !c.saved.CheckedAt.IsZero() { t.Fatal("canceled response cached in memory") }
  if _,err:=os.Stat(path);!errors.Is(err,os.ErrNotExist) { t.Fatal("canceled response persisted",err) }
 }) }
}

func TestStableVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		candidate, current string
		want, fail         bool
	}{
		{"v2.0.20", "2.0.19", true, false}, {"v2.0.19", "2.0.19", false, false}, {"2.0.9", "2.0.19", false, false}, {"2.10.0", "2.9.9", true, false},
		{"2.0.19", "2.0.19-rc.1", true, false}, {"2.0.19+build.2", "2.0.19+build.1", false, false}, {"2.0.20-beta", "2.0.19", false, true},
		{"2.01.0", "2.0.19", false, true}, {"2.0", "2.0.19", false, true}, {"2.0.20", "dev", false, true}, {"2.0.20", "2.0.19-01", false, true},
	} {
		got, e := newer(tc.candidate, tc.current)
		if got != tc.want || (e != nil) != tc.fail {
			t.Errorf("newer(%q,%q)=%v,%v", tc.candidate, tc.current, got, e)
		}
	}
}
func fixture(t *testing.T, handler http.HandlerFunc) *Checker {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New("")
	c.endpoint = srv.URL
	return c
}
func releaseJSON(tag, url string) string {
	b, _ := json.Marshal(map[string]any{"tag_name": tag, "html_url": url, "draft": false, "prerelease": false})
	return string(b)
}
func TestReleaseValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body  string
		newer, fail bool
	}{
		{"new", releaseJSON("v2.0.20", ReleasesURL+"/tag/v2.0.20"), true, false},
		{"same", releaseJSON("v2.0.19", ReleasesURL+"/tag/v2.0.19"), false, false},
		{"draft", `{"draft":true}`, false, false}, {"prerelease", `{"prerelease":true}`, false, false},
		{"prerelease tag", releaseJSON("v2.0.20-rc.1", ReleasesURL+"/tag/v2.0.20-rc.1"), false, false},
		{"invalid version", releaseJSON("latest", ReleasesURL+"/tag/latest"), false, true},
		{"external", releaseJSON("v2.0.20", "https://evil.example/release"), false, true},
		{"http", releaseJSON("v2.0.20", strings.Replace(ReleasesURL, "https:", "http:", 1)+"/tag/v2.0.20"), false, true},
		{"other repo", releaseJSON("v2.0.20", "https://github.com/other/repo/releases/tag/v2.0.20"), false, true},
		{"query", releaseJSON("v2.0.20", ReleasesURL+"/tag/v2.0.20?redirect=elsewhere"), false, true},
		{"malformed", `{"tag_name":`, false, true}, {"oversized", strings.Repeat(" ", maxResponse+1), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) })
			got, e := c.Check(context.Background(), "2.0.19", true)
			if (got.Release != nil) != tc.newer || (e != nil) != tc.fail {
				t.Fatalf("result=%+v error=%v", got, e)
			}
		})
	}
}
func TestCacheExpiryManualAndPersistence(t *testing.T) {
	calls := 0
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(releaseJSON("v2.0.20", ReleasesURL+"/tag/v2.0.20")))
	})
	c.cachePath = filepath.Join(t.TempDir(), "update-check.json")
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	for _, force := range []bool{false, false, true} {
		if _, e := c.Check(context.Background(), "2.0.19", force); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
	other := New(c.cachePath)
	other.now = c.now
	other.endpoint = "http://127.0.0.1:1/never"
	got, e := other.Check(context.Background(), "2.0.19", false)
	if e != nil || !got.Cached || got.Release == nil {
		t.Fatalf("disk cache=%+v %v", got, e)
	}
	got, e = other.Check(context.Background(), "2.0.20", false)
	if e != nil || got.Release != nil {
		t.Fatalf("cache after upgrade=%+v %v", got, e)
	}
	now = now.Add(CacheTTL)
	if _, e := c.Check(context.Background(), "2.0.19", false); e != nil {
		t.Fatal(e)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
func TestHTTPFailureCancellationRedirect(t *testing.T) {
	for _, status := range []int{403, 429, 500} {
		c := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		if _, e := c.Check(context.Background(), "2.0.19", false); e == nil {
			t.Fatal(status)
		}
		if !c.saved.CheckedAt.IsZero() {
			t.Fatal("failure cached")
		}
	}
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://example.invalid", 302) })
	if _, e := c.Check(context.Background(), "2.0.19", true); e == nil {
		t.Fatal("redirect accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Check(ctx, "2.0.19", true); e == nil {
		t.Fatal("cancellation ignored")
	}
	c = fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if got, e := c.Check(context.Background(), "2.0.19", true); e != nil || got.Release != nil {
		t.Fatalf("no releases=%+v %v", got, e)
	}
}
func TestInvalidCacheNotUsed(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	c.cachePath = filepath.Join(t.TempDir(), "update-check.json")
	b, _ := json.Marshal(cache{CheckedAt: time.Now(), Release: &Release{Version: "v9.0.0", URL: "https://example.invalid"}})
	if e := os.WriteFile(c.cachePath, b, 0600); e != nil {
		t.Fatal(e)
	}
	got, e := c.Check(context.Background(), "2.0.19", false)
	if e != nil || got.Cached || got.Release != nil {
		t.Fatalf("bad cache accepted: %+v %v", got, e)
	}
}
func TestRequestDeadline(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := c.Check(ctx, "2.0.19", true); e == nil {
		t.Fatal("deadline ignored")
	}
}
