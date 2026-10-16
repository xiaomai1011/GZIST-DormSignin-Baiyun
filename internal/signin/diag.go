// Bounded read-only page evidence. Resource Timing lists recorded entries,
// not requests in flight; zero duration does not establish pending state.
package signin

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/chromedp/chromedp"
	"os"
	"path/filepath"
	"time"
)

type resourceAutopsy struct {
	Entry      int `json:"entry"`
	DurationMS int `json:"durationMs"`
	Status     int `json:"status"`
}
type navigationAutopsy struct {
	ResponseStartMS  int `json:"responseStartMs"`
	DOMInteractiveMS int `json:"domInteractiveMs"`
	LoadEventEndMS   int `json:"loadEventEndMs"`
}
type pageAutopsy struct {
	ReadyState       string             `json:"readyState"`
	URL              string             `json:"url"`
	HTMLLen          int                `json:"htmlLen"`
	BodyTextLen      int                `json:"bodyTextLen"`
	Nodes            int                `json:"nodes"`
	Scripts          int                `json:"scripts"`
	Resources        int                `json:"recordedResourceCount"`
	ResourceScope    string             `json:"resourceScope"`
	PendingState     string             `json:"pendingState"`
	SlowestResources []resourceAutopsy  `json:"slowestRecordedResources"`
	Navigation       *navigationAutopsy `json:"navigation"`
}

// Resource names may contain secrets even in path segments: never collect them.
const autopsyJS = `(function(){
 var rs = [];
 try { rs = performance.getEntriesByType('resource').map(function(r,i){
  return {entry:i+1,durationMs:Math.round(r.duration),status:(r.responseStatus===undefined?0:r.responseStatus)};
 }); } catch(e) {}
 var nav = null;
 try { var list=performance.getEntriesByType('navigation'); if(list&&list.length){
  var n=list[0]; nav={responseStartMs:Math.round(n.responseStart),domInteractiveMs:Math.round(n.domInteractive),loadEventEndMs:Math.round(n.loadEventEnd)};
 } } catch(e) {}
 var state=document.readyState;
 return {
  readyState:(state==='loading'||state==='interactive'||state==='complete')?state:'unknown',
  url:location.hostname==='xsfw.gzist.edu.cn'?'host=xsfw.gzist.edu.cn':'[redacted-url]',
  htmlLen:document.documentElement?document.documentElement.outerHTML.length:-1,
  bodyTextLen:document.body?(document.body.innerText||'').length:-1,
  nodes:document.querySelectorAll('*').length,scripts:document.querySelectorAll('script').length,
  recordedResourceCount:rs.length,resourceScope:'recorded-only',pendingState:'unknown',
  slowestRecordedResources:rs.slice().sort(function(a,b){return b.durationMs-a.durationMs}).slice(0,8),navigation:nav
 };
})()`

func sanitizeAutopsy(a pageAutopsy) pageAutopsy {
	a.URL = safePageURL(a.URL)
	switch a.ReadyState {
	case "loading", "interactive", "complete":
	default:
		a.ReadyState = "unknown"
	}
	a.ResourceScope = "recorded-only"
	a.PendingState = "unknown"
	if len(a.SlowestResources) > 8 {
		a.SlowestResources = a.SlowestResources[:8]
	}
	return a
}
func collectPageAutopsy(ctx context.Context) (pageAutopsy, error) {
	var a pageAutopsy
	if err := chromedp.Evaluate(autopsyJS, &a).Do(exec(ctx)); err != nil {
		return pageAutopsy{}, err
	}
	return sanitizeAutopsy(a), nil
}
func autopsyLines(a pageAutopsy) []string {
	a = sanitizeAutopsy(a)
	out := []string{
		fmt.Sprintf("  !! 只读诊断: readyState=%s 节点=%d 脚本=%d 正文长度=%d HTML长度=%d", a.ReadyState, a.Nodes, a.Scripts, a.BodyTextLen, a.HTMLLen),
		fmt.Sprintf("  !! 只读诊断: Resource Timing 仅已记录资源 %d 个；不能证明无 pending（未完成请求），也不能排除网络卡住；duration=0 不代表 pending", a.Resources),
	}
	if a.Navigation != nil {
		out = append(out, fmt.Sprintf("  !! 只读诊断: 导航 responseStart=%dms domInteractive=%dms loadEnd=%dms", a.Navigation.ResponseStartMS, a.Navigation.DOMInteractiveMS, a.Navigation.LoadEventEndMS))
	}
	for _, r := range a.SlowestResources {
		out = append(out, fmt.Sprintf("  !! 只读诊断: 最慢已记录资源 entry=%d duration=%dms status=%d（0不代表失败或pending）", r.Entry, r.DurationMS, r.Status))
	}
	return out
}
func writeAutopsyJSON(dir string, a pageAutopsy) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("未配置存证目录")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(sanitizeAutopsy(a), "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, time.Now().Format("20060102-150405")+"-step6-timeout.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
func (r *Runner) reportDeadPage(ctx context.Context) {
	actx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	a, err := collectPageAutopsy(actx)
	if err != nil {
		r.log("  !! 只读诊断不可用: " + safeDiagnosticError(err))
		return
	}
	for _, line := range autopsyLines(a) {
		r.log(line)
	}
	if p, err := writeAutopsyJSON(r.ShotDir, a); err != nil {
		r.log("  !! 诊断记录写入失败: " + safeDiagnosticError(err))
	} else {
		r.log("  已存证: " + filepath.Base(p))
	}
}
