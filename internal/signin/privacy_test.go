package signin

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSafePageURL(t *testing.T) {
	const known = "host=xsfw.gzist.edu.cn"
	cases := []struct{ raw, want string }{
		{"https://user-secret:pass-secret@xsfw.gzist.edu.cn/token/path-secret?ticket=query-secret#fragment-secret", known},
		{"https://XSFW.GZIST.EDU.CN:443/index.do?token=secret", known},
		{"https://xsfw.gzist.edu.cn/%74%6f%6b%65%6e/secret#ticket=secret", known}, {known, known},
		{"https://xsfw.gzist.edu.cn.evil.example/ticket", "[redacted-url]"}, {"https://xsfw.gzist.edu.cn@evil.example/ticket", "[redacted-url]"},
		{"https://token-secret.example/private", "[redacted-url]"}, {"//xsfw.gzist.edu.cn/index.do?ticket=secret", "[redacted-url]"}, {"/token/secret?ticket=secret", "[redacted-url]"},
		{"https://xsfw.gzist.edu.cn/%zz?ticket=secret", "[redacted-url]"}, {"https://xsfw.gzist.edu.cn:bad/?ticket=secret", "[redacted-url]"},
		{"javascript:ticket-secret", "[redacted-url]"}, {"data:text/plain,token-secret", "[redacted-url]"}, {"about:blank", "[redacted-url]"}, {"\nhttps://xsfw.gzist.edu.cn/?token=secret", "[redacted-url]"}, {"", "[redacted-url]"}, {"[redacted-url]", "[redacted-url]"},
	}
	for _, tc := range cases {
		if got := safePageURL(tc.raw); got != tc.want {
			t.Errorf("got %q want fixed category %q", got, tc.want)
		}
	}
}
func TestSafeDiagnosticError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{{nil, "none"}, {context.Canceled, "canceled"}, {fmt.Errorf("https://private.invalid/token?ticket=secret: %w", context.DeadlineExceeded), "deadline-exceeded"}, {errors.New("https://private.invalid/token?ticket=secret#fragment"), "operation-failed"}} {
		if got := safeDiagnosticError(tc.err); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
func FuzzSafePageURLFixedCategories(f *testing.F) {
	f.Add("https://xsfw.gzist.edu.cn/token?ticket=secret#fragment")
	f.Add("%zz")
	f.Fuzz(func(t *testing.T, raw string) {
		got := safePageURL(raw)
		if got != "host=xsfw.gzist.edu.cn" && got != "[redacted-url]" {
			t.Fatalf("unsafe category %q", got)
		}
		if safePageURL(got) != got {
			t.Fatal("not idempotent")
		}
	})
}
