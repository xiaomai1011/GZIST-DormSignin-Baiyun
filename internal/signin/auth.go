package signin

import (
	"context"
	"errors"
	"github.com/chromedp/chromedp"
	"strings"
)

// AuthIssue is a safe classification, never server text or a credential.
type AuthIssue string

const (
	AuthNone                AuthIssue = ""
	AuthCredentialsRejected AuthIssue = "credentials_rejected"
	AuthLocked              AuthIssue = "locked"
	AuthCaptcha             AuthIssue = "captcha"
	AuthActionRequired      AuthIssue = "action_required"
	AuthBusinessOther       AuthIssue = "business_other"
	AuthNetwork             AuthIssue = "network"
	AuthCanceled            AuthIssue = "canceled"
	AuthUnknown             AuthIssue = "unknown"
)

type VerificationResult struct {
	CleanupFailed bool
	OK            bool
	Issue         AuthIssue
	Reason        string
	// ReasonCode is the fixed internal explanation of a non-success result. It is
	// for diagnostics only and is never shown as user text.
	ReasonCode VerifyReason
}

// ClassifyAuthMessage accepts only a dedicated error element's entire text.
// In particular, help text mentioning passwords and generic login failure are not evidence.
func ClassifyAuthMessage(text string) AuthIssue {
	t := strings.Trim(strings.TrimSpace(text), "。.!！")
	switch t {
	case "密码错误", "用户名或密码错误", "用户名或密码不正确", "用户名或密码有误", "账号或密码错误", "账户或密码错误":
		return AuthCredentialsRejected
	case "账户已锁定", "账号被锁定", "账号锁定", "账号已锁定", "账号被停用，请联系相关管理员处理":
		return AuthLocked
	case "验证码错误", "验证码不正确", "验证码已过期":
		return AuthCaptcha
	}
	if strings.HasPrefix(t, "账号锁定至:") && strings.HasSuffix(t, "，请稍后重新登录或联系管理员处理") {
		return AuthLocked
	}
	return AuthNone
}
func authReason(issue AuthIssue) string {
	switch issue {
	case AuthCredentialsRejected:
		return "账号或密码错误，请检查后重新验证"
	case AuthLocked:
		return "账号已锁定，请稍后重试或联系学校管理员"
	case AuthCaptcha:
		return "验证码未通过，无法确定账号密码是否正确"
	case AuthActionRequired:
		return "学校要求完成二次验证或补充资料后才能登录，未涉及密码判定"
	case AuthBusinessOther:
		return "学校返回了其他业务状态（如未注册／未授权），未涉及密码判定"
	case AuthNetwork:
		return "网络或浏览器连接失败，无法确定账号密码是否正确"
	case AuthCanceled:
		return "已取消验证"
	default:
		return "验证结果不确定，未取得可信认证成功证据"
	}
}

// unknownReasonText gives the "no reliable answer" family a fixed text per
// internal reason, instead of collapsing every such outcome into one sentence.
//
// Rules it encodes:
//   - the text is a compile-time constant: server text, business code values,
//     their hashes, tickets and URLs never appear in it;
//   - only a credential rejection may tell the user the password is wrong, so
//     nothing here says "账号或密码错误";
//   - a reason that already carries a more specific text at its call site is not
//     overridden here — this is the fallback for reasons that have none.
//
// The default keeps the previous wording so unclassified outcomes do not change.
func unknownReasonText(code VerifyReason) string {
	switch code {
	case ReasonUnknownBusinessCode:
		return "认证服务返回了暂未识别的结果，暂时无法判断账号密码是否正确，请勿连续重试。"
	case ReasonPageGenericRejection:
		// The login page itself said the attempt did not pass, and said nothing
		// more specific. That is a generic rejection: it must not be phrased as a
		// password verdict, and no page or server text is interpolated.
		return "学校页面提示本次登录未通过，但没有可核实的账号密码判定；请检查账号状态，或直接在学校官方登录页确认。"
	case ReasonLaunchFailed:
		return "验证浏览器未能启动，无法判断账号密码是否正确。"
	case ReasonCASFormTimeout:
		return "统一认证登录页未能在限定时间内加载完成，未取得认证结果。"
	case ReasonCASPageNotTrusted, ReasonCASFormMissing:
		return "登录页结构未按预期出现，未取得认证结果。"
	case ReasonLoginButtonMissing, ReasonLoginButtonNotVisible,
		ReasonLoginButtonNotClicked, ReasonLoginClickFailed:
		return "未能点击登录按钮完成提交，未取得认证结果，请勿连续重试。"
	case ReasonTicketRequestNotSeen:
		return "提交后未观测到认证请求，无法判断账号密码是否正确，请勿连续重试。"
	case ReasonHTTPStatusUnexpected:
		return "认证服务返回了异常状态，无法判断账号密码是否正确。"
	case ReasonResponseNotReceived:
		return "未观测到认证服务的响应，无法判断账号密码是否正确，请勿连续重试。"
	case ReasonResponseBodyUnavail, ReasonBodyEmpty:
		return "已提交账号密码，但认证响应正文为空或无法读取，无法判断账号密码是否正确，请勿连续重试。"
	case ReasonBodyReadFailed, ReasonBodyResourceGone:
		return "已提交账号密码，但认证响应正文读取失败（页面可能已跳转），无法判断账号密码是否正确，请勿连续重试。"
	case ReasonBodyReadTimeout, ReasonVerificationTimeout:
		return "已提交账号密码，但等待认证响应超时，无法判断账号密码是否正确，请勿连续重试。"
	case ReasonResponseBodyTooLarge:
		return "认证响应超出可读体积上限，无法判断账号密码是否正确。"
	case ReasonResponseSchemaUnknown:
		return "认证响应格式与预期不符，无法判断账号密码是否正确。"
	case ReasonResponseEvidenceMissing:
		return "认证响应缺少可核验的来源证据，未采用该结果，无法判断账号密码是否正确。"
	}
	return "未取得明确认证结果，请勿连续重试。"
}

// UserText returns the fixed user-facing text for one internal reason. It is
// exported so the UI layer and its offscreen demos show exactly the text the
// verification flow attaches, instead of a copy that could drift.
func UserText(code VerifyReason) string {
	return unknownReasonText(code)
}

// IssueText returns the fixed, issue-level user-facing text. It is the sentence
// the flow attaches when no reason-specific constant overrides it (see
// verificationText), so the network family — which is reported with this
// text — reads in the UI exactly as the flow wrote it. Exported for the same
// reason as UserText: one source, no copy that could drift.
func IssueText(issue AuthIssue) string {
	return authReason(issue)
}

// businessIssue maps a CAS business code to a safe category.
//
// Only codes the public CAS client actually emits are listed. Anything else stays
// unknown on purpose: a new or unrecognised server code must never be reported
// as a wrong password. Codes that mean "the school still wants something from
// you" are kept apart from credential rejection for the same reason.
//
// Matching is an exact, case- and whitespace-sensitive comparison, exactly like
// the client's own `==` chain: no substring probing and no normalisation, so a
// similar-looking code ("NOUSER2", "nouser", " NOUSER") stays unknown instead of
// inheriting a meaning it was never shown to have.
func businessIssue(code string) (AuthIssue, bool) {
	switch code {
	case "NOUSER":
		return AuthCredentialsRejected, true
	case "CODEFALSE":
		return AuthCaptcha, true
	case "USERLOCK", "USERDISABLED":
		return AuthLocked, true
	case "TWOVERIFY", "ISPHONEOREMAILORANSWER", "PEOPLEMOREACCOUNT",
		"NETWORKCOMMITMENT", "ISMODIFYPASS", "ISBINDWX":
		return AuthActionRequired, true
	case "NOAUTHORIZATION", "NOREGISTER", "USERNOTONLY":
		return AuthBusinessOther, true
	}
	return AuthNone, false
}
func authResult(issue AuthIssue) Result {
	return Result{AuthIssue: issue, Reason: authReason(issue), Exit: 3}
}

type authIssueError struct{ issue AuthIssue }

func (e *authIssueError) Error() string { return authReason(e.issue) }

func loginDOMIssue(ctx context.Context) AuthIssue {
	var texts []string
	// The error regions are shared with the bounded page-prompt look, so both
	// readers can never drift apart. Ant Design's error modal is what the public
	// CAS client renders. Never scan body/help text.
	_ = chromedp.Evaluate(`(function(){`+casPageGuardJS+`
 return `+casErrorRegionsJS+`;
 })()`, &texts).Do(exec(ctx))
	for _, text := range texts {
		if issue := ClassifyAuthMessage(text); issue != AuthNone {
			return issue
		}
	}
	return AuthNone
}
func loginRejected(text string) bool {
	i := ClassifyAuthMessage(text)
	return i == AuthCredentialsRejected || i == AuthLocked
}
func terminalDOMAuth(ctx context.Context) AuthIssue {
	i := loginDOMIssue(ctx)
	if i == AuthCredentialsRejected || i == AuthLocked {
		return i
	}
	return AuthNone
}

// resultForRecovery preserves authentication evidence through the page-wait layer.
func resultForRecovery(err error) (Result, bool) {
	var a *authIssueError
	if errors.As(err, &a) {
		return authResult(a.issue), true
	}
	return Result{}, false
}
