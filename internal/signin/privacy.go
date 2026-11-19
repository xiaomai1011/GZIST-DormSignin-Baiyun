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

// safePageCategory classifies the current document for diagnostics only and
// never leaves the process as anything but one of these literals. It exists
// because safePageURL collapses "still on the CAS login host" and "some unknown
// host" into the same "[redacted-url]", which is what made the 2026-10-21 log
// unable to distinguish "the login page is still there" from "we are somewhere
// else". No path, port, query or fragment is retained.
func safePageCategory(raw string) string {
	switch {
	case raw == "":
		return "none"
	case schoolURL(raw, "xsfw.gzist.edu.cn"):
		return "business"
	case twoVerifyURL(raw):
		// Diagnostic label only: the same literal name is what the log shows for
		// the school's two-factor route. The decision to stop is taken from
		// twoVerifyURL itself, never from this string comparison.
		return "cas-twoverify"
	case casLoginURL(raw):
		return "cas-login"
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "none"
	}
	if strings.EqualFold(u.Hostname(), "ids.gzist.edu.cn") {
		return "cas-other"
	}
	return "other"
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
