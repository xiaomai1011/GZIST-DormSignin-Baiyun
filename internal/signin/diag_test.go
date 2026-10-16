package signin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutopsyLinesRecordedResourcesCannotEstablishPending(t *testing.T) {
	for _, a := range []pageAutopsy{{ReadyState: "interactive", Resources: 3, SlowestResources: []resourceAutopsy{{Entry: 1, DurationMS: 0, Status: 0}}}, {ReadyState: "complete", Resources: 0}} {
		got := strings.Join(autopsyLines(a), "\n")
		for _, want := range []string{"仅已记录资源", "不能证明无 pending", "不能排除网络卡住", "duration=0 不代表 pending"} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q: %s", want, got)
			}
		}
		for _, bad := range []string{"不是卡在加载", "未完成资源", "校方", "渲染/接口后置"} {
			if strings.Contains(got, bad) {
				t.Fatalf("unjustified diagnosis %q", bad)
			}
		}
		if len(a.SlowestResources) > 0 && !strings.Contains(got, "entry=1 duration=0ms status=0") {
			t.Fatal("zero timing lost")
		}
	}
}
func TestWriteAutopsyJSONSanitizesEveryTextBoundary(t *testing.T) {
	dir := t.TempDir()
	in := pageAutopsy{ReadyState: "ready-secret", URL: "https://user-secret:pass-secret@xsfw.gzist.edu.cn/token/path-secret?ticket=query-secret#fragment-secret", Nodes: 11, ResourceScope: "scope-secret", PendingState: "pending-secret", SlowestResources: []resourceAutopsy{{Entry: 1}}, Navigation: &navigationAutopsy{ResponseStartMS: 88}}
	p, err := writeAutopsyJSON(dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "-step6-timeout.json") || filepath.Dir(p) != dir {
		t.Fatal("wrong output path")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	all := string(b) + strings.Join(autopsyLines(in), "\n")
	for _, bad := range []string{"ready-secret", "user-secret", "pass-secret", "path-secret", "ticket", "token", "query-secret", "fragment-secret", "scope-secret", "pending-secret", "https://", "pendingResources"} {
		if strings.Contains(all, bad) {
			t.Fatalf("leaked %q", bad)
		}
	}
	var out pageAutopsy
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.URL != "host=xsfw.gzist.edu.cn" || out.ReadyState != "unknown" || out.Nodes != 11 || out.ResourceScope != "recorded-only" || out.PendingState != "unknown" {
		t.Fatalf("bad sanitized result: %+v", out)
	}
	if len(out.SlowestResources) != 1 || out.SlowestResources[0].DurationMS != 0 || out.Navigation == nil || out.Navigation.ResponseStartMS != 88 {
		t.Fatal("timing changed")
	}
}
func TestAutopsyResourcesAreBounded(t *testing.T) {
	if len(sanitizeAutopsy(pageAutopsy{SlowestResources: make([]resourceAutopsy, 20)}).SlowestResources) != 8 {
		t.Fatal("resource bound lost")
	}
}
func TestWriteAutopsyJSONNeedsDir(t *testing.T) {
	if _, err := writeAutopsyJSON("", pageAutopsy{}); err == nil {
		t.Fatal("empty dir accepted")
	}
}
func TestAutopsyJSMakesNoStateChangesOrCollectsRawURLs(t *testing.T) {
	for _, bad := range []string{"location.href", "location.assign", "location.replace", "location.reload", "location.hash", ".click(", "dispatchEvent", "fetch(", "XMLHttpRequest", "localStorage", "document.cookie", "submit(", "r.name", "pendingResources", "r.d === 0", "r.duration === 0"} {
		if strings.Contains(autopsyJS, bad) {
			t.Fatalf("forbidden JS %q", bad)
		}
	}
	for _, want := range []string{"performance.getEntriesByType('resource')", "readyState", "querySelectorAll", "recorded-only", "pendingState:'unknown'", ".slice(0,8)"} {
		if !strings.Contains(autopsyJS, want) {
			t.Fatalf("missing JS %q", want)
		}
	}
}
