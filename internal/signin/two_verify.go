package signin

import (
	"net/url"
	"strings"
)

// twoVerifyPath is the school SSO's two-factor route. It is a client-side route
// on the CAS page: the login POST answers {"code":"TWOVERIFY"} and the front end
// pushes this path (see docs/分析-loginAgain二次验证.md; the frontend route table
// and the single push("/loginAgain") site are the evidence).
const twoVerifyPath = "/loginAgain"

// twoVerifyURL reports whether raw is exactly the school's two-factor route.
//
// This is a business fact, not a log category: it decides that the run must stop
// and that a human has to finish the phone/security-question step. It is checked
// strictly and independently of safePageCategory, which stays diagnostics:
//   - https only;
//   - host exactly ids.gzist.edu.cn (the school's own CAS host);
//   - default port or the explicit :443, never another port;
//   - no URL userinfo (user:pass@host cannot select a host);
//   - path exactly /loginAgain — no prefix, suffix or case-insensitive match;
//   - no query and no fragment: a parameter must never widen this trust, and the
//     verified route as served carries neither.
func twoVerifyURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	if !strings.EqualFold(u.Hostname(), "ids.gzist.edu.cn") {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	if u.Path != twoVerifyPath {
		return false
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false
	}
	return true
}
