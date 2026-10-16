package signin

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// safePageURL is a log-only host category, never a navigation target.
// No paths, ports, queries, fragments, userinfo or unknown hosts are retained.
func safePageURL(raw string) string {
	const known = "host=xsfw.gzist.edu.cn"
	if raw == known {
		return known
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "[redacted-url]"
	}
	if strings.EqualFold(u.Hostname(), "xsfw.gzist.edu.cn") {
		return known
	}
	return "[redacted-url]"
}

// Error messages may contain URLs, JS exception text or private page content.
func safeDiagnosticError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline-exceeded"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "operation-failed"
	}
}
