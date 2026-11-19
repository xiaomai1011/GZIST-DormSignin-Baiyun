package signin

import (
	"context"
	"fmt"
	"github.com/chromedp/cdproto/input"
	"math"
	"time"

	"github.com/chromedp/chromedp"
)

// Login checks and mutations run in one renderer task. Business mouse gestures
// use these checks again before each CDP event (see clickSignWith below).
const actionTargetJS = `
function actionable(e){
 if(!e||!e.isConnected||e.disabled||e.readOnly||e.matches(':disabled')||e.closest('[inert],[aria-disabled="true"]'))return false;
 var r=e.getBoundingClientRect();
 if(!(r.width>0&&r.height>0))return false;
 for(var p=e;p;p=p.parentElement){var s=getComputedStyle(p);if(s.display==='none'||s.visibility==='hidden'||s.visibility==='collapse'||Number(s.opacity)===0||s.pointerEvents==='none')return false;}
 var x=r.left+r.width/2,y=r.top+r.height/2;
 if(x<0||y<0||x>=innerWidth||y>=innerHeight)return false;
 var hit=document.elementFromPoint(x,y);
 return !!hit&&(hit===e||e.contains(hit));
}
`

const signTargetJS = `(function(){
var u=new URL(location.href);
if(u.protocol!=='https:'||u.hostname!=='xsfw.gzist.edu.cn'||u.username||u.password||(u.port!==''&&u.port!=='443'))return 0;
` + actionTargetJS + `
var text=(document.body?document.body.innerText:'').replace(/\s+/g,'');
if(text.indexOf('查寝时间段')<0||/不在考勤范围|非考勤时段|无需重复签到|您已签到成功|签到成功/.test(text))return 0;
var candidates=[].filter.call(document.querySelectorAll('.erweima-bksy,a,button,[role="button"]'),function(e){return (e.innerText||'').replace(/\s+/g,'')==='点击签到'&&actionable(e);});
// Nested label wrappers are not separate controls; ambiguous controls stop.
candidates=candidates.filter(function(e){return !candidates.some(function(p){return p!==e&&p.contains(e);});});
if(candidates.length!==1)return 0;
var r=candidates[0].getBoundingClientRect();return [r.left+r.width/2,r.top+r.height/2];
})()`

type actionEvaluator func(context.Context, string, any) error

func evaluateAction(ctx context.Context, expr string, out any) error {
	return chromedp.Evaluate(expr, out).Do(exec(ctx))
}

func checkedAction(ctx context.Context, name, expr string, evaluate actionEvaluator) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var code int
	err := evaluate(ctx, expr, &code)
	if stopped := ctx.Err(); stopped != nil {
		return stopped
	}
	if err != nil {
		return fmt.Errorf("%s action evaluation: %w", name, err)
	}
	if code != 1 {
		return fmt.Errorf("%s action target not available", name)
	}
	return nil
}

func setReactValueChecked(ctx context.Context, sel, val string) error {
	// Only the known CAS inputs are writable through this helper.
	switch sel {
	case "#userName", "#password", "#captcha":
	default:
		return fmt.Errorf("unsupported login input")
	}
	expr := fmt.Sprintf(`(function(){`+casPageGuardJS+`
var u=new URL(location.href);if(u.username||u.password)return 0;
`+actionTargetJS+`
var e=document.querySelector(%q);if(!(e instanceof HTMLInputElement)||!actionable(e))return 0;
var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
setter.call(e,%q);e.dispatchEvent(new Event('input',{bubbles:true}));return e.value===%q?1:0;
})()`, sel, val, val)
	return checkedAction(ctx, "login input", expr, evaluateAction)
}

func clickLoginButton(ctx context.Context) error {
	return checkedAction(ctx, "login click", clickLoginButtonJS, evaluateAction)
}

const clickLoginButtonJS = `(function(){` + casPageGuardJS + casVisibleFormJS + `
var u=new URL(location.href);if(u.username||u.password)return 0;
` + actionTargetJS + `
var buttons=[].filter.call(document.querySelectorAll('button'),function(b){return (b.innerText||'').replace(/\s+/g,'')==='登录'&&actionable(b);});
if(buttons.length!==1)return 0;buttons[0].click();return 1;
})()`

// Each event rechecks the live business target. CDP and renderer operations are
// not atomic across navigation; any interrupted/uncertain gesture stops the run.
func clickSignWith(ctx context.Context, evaluate actionEvaluator, send mouseSender, sleep actionSleeper) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var pt []float64
	if err := evaluate(ctx, signTargetJS, &pt); err != nil {
		return fmt.Errorf("sign target evaluation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(pt) != 2 {
		return fmt.Errorf("sign target not available")
	}
	guard := func(ctx context.Context) error {
		var current []float64
		if err := evaluate(ctx, signTargetJS, &current); err != nil {
			return fmt.Errorf("sign target recheck: %w", err)
		}
		if len(current) != 2 || current[0] != pt[0] || current[1] != pt[1] {
			return fmt.Errorf("sign target changed")
		}
		return nil
	}
	return mouseClickWith(ctx, pt[0], pt[1], guard, send, sleep)
}

type mouseSender func(context.Context, input.MouseType, float64, float64) error
type actionSleeper func(context.Context, time.Duration) error

func mouseClickWith(ctx context.Context, x, y float64, guard func(context.Context) error, send mouseSender, sleep actionSleeper) error {
	if x < 0 || y < 0 || math.IsNaN(x) || math.IsNaN(y) || math.IsInf(x, 0) || math.IsInf(y, 0) {
		return fmt.Errorf("invalid mouse coordinates")
	}
	for i, kind := range []input.MouseType{input.MouseMoved, input.MousePressed, input.MouseReleased} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			if err := sleep(ctx, 90*time.Millisecond); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if guard != nil {
			if err := guard(ctx); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		sendErr := send(ctx, kind, x, y)
		if err := ctx.Err(); err != nil {
			return err
		}
		if sendErr != nil {
			return fmt.Errorf("mouse %s: %w", kind, sendErr)
		}
	}
	return nil
}

func (d loginDriver) writeInput(ctx context.Context, sel, val string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.fillChecked != nil {
		return d.fillChecked(ctx, sel, val)
	}
	if d.fill != nil && d.fill(ctx, sel, val) {
		return nil
	}
	return fmt.Errorf("login input not confirmed")
}
func (d loginDriver) submit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.submitChecked != nil {
		return d.submitChecked(ctx)
	}
	if d.click == nil {
		return fmt.Errorf("login click unavailable")
	}
	d.click(ctx)
	return ctx.Err()
}
