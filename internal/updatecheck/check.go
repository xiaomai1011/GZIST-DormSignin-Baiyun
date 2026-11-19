// Package updatecheck discovers official releases. It never downloads or executes code.
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Repository  = "xiaomai1011/GZIST-DormSignin-Baiyun"
	ReleasesURL = "https://github.com/" + Repository + "/releases"
	latestAPI   = "https://api.github.com/repos/" + Repository + "/releases/latest"
	CacheTTL    = 24 * time.Hour
	maxResponse = 1 << 20
)

type Release struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}
type Result struct {
	Release *Release
	Cached  bool
}
type cache struct {
	CheckedAt time.Time `json:"checkedAt"`
	Release   *Release  `json:"release,omitempty"`
}

// Checker serializes requests and keeps only public release metadata on disk.
// cachePath may be empty to disable disk persistence.
type Checker struct {
	mu        sync.Mutex
	client    *http.Client
	endpoint  string
	cachePath string
	now       func() time.Time
	saved     cache
	loaded    bool
}

func New(cachePath string) *Checker {
	return &Checker{client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("release API redirect rejected") }}, endpoint: latestAPI, cachePath: cachePath, now: time.Now}
}

var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

func parseVersion(v string) ([]string, error) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil || len(v) > 128 {
		return nil, errors.New("invalid semantic version")
	}
	for _, id := range strings.Split(m[4], ".") {
		if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
			return nil, errors.New("invalid prerelease version")
		}
	}
	return m, nil
}
func newer(candidate, current string) (bool, error) {
	a, e := parseVersion(candidate)
	if e != nil || (a != nil && a[4] != "") {
		return false, errors.New("release is not a stable semantic version")
	}
	b, e := parseVersion(current)
	if e != nil {
		return false, errors.New("current build has no valid semantic version")
	}
	for i := 1; i <= 3; i++ {
		if len(a[i]) != len(b[i]) {
			return len(a[i]) > len(b[i]), nil
		}
		if a[i] != b[i] {
			return a[i] > b[i], nil
		}
	}
	return b[4] != "", nil
}
func validRelease(r *Release) bool {
	if r == nil {
		return true
	}
	m, e := parseVersion(r.Version)
	return e == nil && m[4] == "" && r.URL == ReleasesURL+"/tag/"+r.Version
}
func (c *Checker) load() {
	if c.loaded {
		return
	}
	c.loaded = true
	if c.cachePath == "" {
		return
	}
	f, e := os.Open(c.cachePath)
	if e != nil {
		return
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxResponse+1))
	if e != nil || len(b) > maxResponse {
		return
	}
	var saved cache
	if json.Unmarshal(b, &saved) == nil && validRelease(saved.Release) {
		c.saved = saved
	}
}
func (c *Checker) save(v cache) {
	c.saved = v
	if c.cachePath == "" {
		return
	}
	b, e := json.Marshal(v)
	if e != nil {
		return
	}
	// Best-effort cache: a write failure must not hide a checked release.
	f, e := os.CreateTemp(filepath.Dir(c.cachePath), ".update-check-*")
	if e != nil {
		return
	}
	name := f.Name()
	defer os.Remove(name)
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return
	}
	// Windows rename does not replace existing files. Only this dedicated cache is removed.
	_ = os.Remove(c.cachePath)
	_ = os.Rename(name, c.cachePath)
}
func resultFor(r *Release, current string, cached bool) (Result, error) {
	result := Result{Cached: cached}
	if r == nil {
		return result, nil
	}
	yes, e := newer(r.Version, current)
	if e != nil {
		return result, e
	}
	if yes {
		copied := *r
		result.Release = &copied
	}
	return result, nil
}

// Check checks at most daily unless force is true. Only the fixed repository's
// latest stable release is accepted. Cancellation and HTTP failures are not cached.
func (c *Checker) Check(ctx context.Context, current string, force bool) (Result, error) {
	if _, e := parseVersion(current); e != nil {
		return Result{}, errors.New("current build has no valid semantic version")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	c.load()
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	now := c.now()
	age := now.Sub(c.saved.CheckedAt)
	if !force && !c.saved.CheckedAt.IsZero() && age >= 0 && age < CacheTTL {
		return resultFor(c.saved.Release, current, true)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if e != nil {
		return Result{}, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "GZIST-DormSignin-UpdateCheck")
	resp, e := c.client.Do(req)
	if e != nil {
		return Result{}, fmt.Errorf("release check request: %w", e)
	}
	defer resp.Body.Close()
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	if resp.StatusCode == http.StatusNotFound {
		return c.accept(ctx, cache{CheckedAt: now}, current)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("release API HTTP %d", resp.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Result{}, ctxErr
	}
	if e != nil {
		return Result{}, e
	}
	if len(b) > maxResponse {
		return Result{}, errors.New("release response exceeds limit")
	}
	var payload struct {
		Tag        string `json:"tag_name"`
		URL        string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if e = json.Unmarshal(b, &payload); e != nil {
		return Result{}, errors.New("invalid release response")
	}
	if payload.Draft || payload.Prerelease {
		return c.accept(ctx, cache{CheckedAt: now}, current)
	}
	m, e := parseVersion(payload.Tag)
	if e != nil {
		return Result{}, errors.New("release tag is not a semantic version")
	}
	if m[4] != "" {
		return c.accept(ctx, cache{CheckedAt: now}, current)
	}
	r := &Release{Version: payload.Tag, URL: payload.URL}
	if !validRelease(r) {
		return Result{}, errors.New("release page is not the official repository tag URL")
	}
	return c.accept(ctx, cache{CheckedAt: now, Release: r}, current)
}

// accept is the final cancellation gate before publishing/cache persistence.
func (c *Checker) accept(ctx context.Context, saved cache, current string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	c.save(saved)
	return resultFor(saved.Release, current, false)
}

// ValidateRelease checks a saved UI selection before opening its URL.
func ValidateRelease(r Release) bool { return validRelease(&r) }
