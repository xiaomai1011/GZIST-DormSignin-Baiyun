// The look follows MyGO!!!!! with 长崎爽世's gold as the app identity:
// gold tray star, gold accents — the third color after the blue
// NetKeeper star and the green Hotspot star. 白云校区专属.
package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/art"
	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/store"
)

// gold identity colors.
var (
	colSoyo    = ui.Hex("#FFDD88")
	colGold    = ui.Hex("#D9A62E")
	colGoldDk  = ui.Hex("#B8860B")
	colMembers = []ui.Color{ui.Hex("#77BBDD"), ui.Hex("#FF8899"), ui.Hex("#77DD77"), colSoyo, ui.Hex("#7777AA")}
)

type actions struct {
	Save         func(id, pass string)
	Sign         func()
	SetHoliday   func(on bool)
	SetAutoSign  func(on bool)
	SetAutostart func(on bool)
	OpenLogs     func()
}

type model struct {
	cfg                  store.Settings
	studentID            string
	id, pass             string // echoed from the store at startup
	storedID, storedPass string // what is on disk; dirty = diff
	showPass             bool   // the eye toggle: true = plain text
	hasCreds             bool
	autostart            bool
	version              string

	phase         string // tray line text mirror
	resultOK      bool   // confirmed success for the current account/day, not last attempt
	statusAccount string
	statusDate    string
	notice        string
	neutral       bool // the notice is an expected idle state, not an error
	logs          []string
	logScroll     ui.ScrollState
	act           actions
}

func (m *model) setPhase(title, _ string) { m.phase = title }

// Called only on the UI thread. Account/day rollover discards stale notices too.
func (m *model) syncSuccess(account string, now time.Time, success bool) {
	date := now.Format("2006-01-02")
	if m.statusAccount != account || m.statusDate != date {
		m.notice, m.neutral = "", false
	}
	m.statusAccount, m.statusDate, m.resultOK = account, date, success
}
func (m *model) setResult(ok, neutral bool, reason string) {
	// The ledger owns resultOK: a later failed attempt cannot revoke success.
	m.notice = reason
	if !ok {
		m.notice = "最近一次尝试：" + reason
	}
	m.neutral = neutral
}

// statusLine is the big headline in the status card. Neutral notices
// (off-hours manual tests, past the late line) keep the calm "monitoring"
// headline — they are expected states, not errors.
func (m *model) statusLine() (title, line string, col ui.Color, tray art.TrayState) {
	if m.cfg.Holiday {
		return "自动签到已停用", "假期模式开着 —— 回校后打开上面的开关", colGoldDk, art.TrayOff
	}
	if m.resultOK {
		return "今日已签到", "今晚不用管了，睡觉吧", colSoyo, art.TrayOn
	}
	if m.notice != "" && !m.neutral {
		return "需要处理", m.notice, colGoldDk, art.TrayError
	}
	if m.notice != "" && m.neutral {
		return "监测中", m.notice, colGold, art.TrayOff
	}
	return "监测中", "自动签到运行中 · 今天 " + strings.Join(m.cfg.Times, " / "), colGold, art.TrayOff
}

func applyTheme(c *ui.Context) *ui.Theme {
	t := *c.Theme()
	if t.Dark {
		t.Background = ui.Hex("#171409")
		t.Surface, t.SurfaceHover, t.SurfacePressed = ui.Hex("#241F10"), ui.Hex("#2C2615"), ui.Hex("#352E1A")
		t.Border = ui.Hex("#3A331C")
		t.Text, t.TextMuted = ui.Hex("#F2ECD9"), ui.Hex("#9A9070")
		t.Accent, t.AccentHover, t.AccentPressed = ui.Hex("#D9A62E"), ui.Hex("#E8B84A"), ui.Hex("#B8860B")
		t.Selection, t.Focus = colSoyo.Alpha(0.30), colSoyo.Alpha(0.45)
	} else {
		t.Background = ui.Hex("#FAF6E8")
		t.Surface, t.SurfaceHover, t.SurfacePressed = ui.Hex("#FFFDF2"), ui.Hex("#F7F0D8"), ui.Hex("#EFE6C4")
		t.Border = ui.Hex("#E4DBBA")
		t.Text, t.TextMuted = ui.Hex("#2E2A18"), ui.Hex("#8A8163")
		t.Accent, t.AccentHover, t.AccentPressed = ui.Hex("#C9952F"), ui.Hex("#D9A62E"), ui.Hex("#A87A1F")
		t.Selection, t.Focus = colSoyo.Alpha(0.35), colSoyo.Alpha(0.55)
	}
	t.AccentText = ui.Hex("#FFFFFF")
	t.Radius = 8
	c.SetTheme(&t)
	return &t
}

func cardBG(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.Hex("#1E1910")
	}
	return ui.Hex("#FFFFFF")
}

func card(c *ui.Context, t *ui.Theme) ui.Element {
	e := ui.Column(c).Padding(14).Gap(10).Radius(14).Background(cardBG(t)).Border(1, t.Border)
	if !t.Dark {
		e.Shadow(0, 2, 10, 0, ui.RGBA(120, 90, 20, 0.08))
	}
	return e
}

func starPath(r ui.Rect, inner float64, rot float64) *ui.Path {
	cx, cy := float64(r.X+r.W/2), float64(r.Y+r.H/2)+float64(r.H)*0.03
	pts := art.StarPoints(cx, cy, float64(min(r.W, r.H))/2, inner, rot)
	var p ui.Path
	p.MoveTo(float32(pts[0][0]), float32(pts[0][1]))
	for _, q := range pts[1:] {
		p.LineTo(float32(q[0]), float32(q[1]))
	}
	p.Close()
	return &p
}

func (m *model) view(c *ui.Context) {
	t := applyTheme(c)
	title, line, col, _ := m.statusLine()
	ui.Column(c).Fill().Children(func() {
		m.header(c, t)
		ui.Scroll(c).Grow(1).Children(func() {
			ui.Column(c).Padding(14).Gap(12).Children(func() {
				m.statusCard(c, t, title, line, col)
				m.accountCard(c, t)
				m.switches(c, t)
				m.logCard(c, t)
				m.footer(c, t)
			})
		})
	})
}

func (m *model) header(c *ui.Context, t *ui.Theme) {
	ui.Column(c).FillWidth().Children(func() {
		hc1, hc2 := colSoyo, ui.Hex("#E8B84A")
		if t.Dark {
			hc1, hc2 = ui.Hex("#8A6A18"), ui.Hex("#C9952F")
		}
		ui.Row(c).FillWidth().Padding(16, 18, 14, 18).Gap(12).AlignItems(ui.Center).
			Gradient(hc1, hc2, 120).
			Children(func() {
				ui.Box(c).Size(34, 34).Draw(func(p *ui.Painter, r ui.Rect) {
					p.FillPath(starPath(r, 0.48, -8), ui.Hex("#FFFFFF"))
				})
				ui.Column(c).Gap(2).Grow(1).Children(func() {
					ui.Text(c, "GZIST DormSignin").FontSize(19).Bold().TextColor(ui.Hex("#FFFFFF"))
					ui.Text(c, "やり直せますよね？ · 白云校区专属").FontSize(11.5).TextColor(ui.RGBA(255, 255, 255, 0.88))
				})
			})
		ui.Row(c).FillWidth().Height(4).Children(func() {
			for _, col := range colMembers {
				ui.Box(c).Grow(1).Height(4).Background(col)
			}
		})
	})
}

func (m *model) statusCard(c *ui.Context, t *ui.Theme, title, line string, col ui.Color) {
	card(c, t).Border(1.5, col.Alpha(0.75)).Gradient(cardBG(t).Mix(col, 0.16), cardBG(t), 180).Children(func() {
		// auto-sign state pill + switch: "running / stopped" at a glance
		autoOn := !m.cfg.Holiday
		dotCol := colGold
		if !autoOn {
			dotCol = ui.Hex("#8A8163")
		}
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).
			Padding(6, 10).Radius(8).Background(cardBG(t).Mix(colGold, 0.10)).Children(func() {
			ui.Box(c).Size(8, 8).Radius(4).Background(dotCol)
			ui.Column(c).Gap(0).Grow(1).Children(func() {
				ui.Text(c, map[bool]string{true: "自动签到：运行中", false: "自动签到：已停用"}[autoOn]).FontSize(12.5).Bold()
				ui.Text(c, "关掉 = 假期模式（离校防伪造在场）").FontSize(10.5).TextColor(t.TextMuted)
			})
			if ui.Switch(c, &autoOn).Label("自动签到").Changed() {
				m.act.SetAutoSign(autoOn)
			}
		})
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			star := ui.Box(c).Size(40, 40)
			busy := m.phase == "签到中" || strings.Contains(m.phase, "运行")
			if busy {
				star.Rotate(star.Loop("spin", 2400*time.Millisecond, ui.Linear) * 72)
			}
			on := m.resultOK
			star.Draw(func(p *ui.Painter, r ui.Rect) {
				if on || busy {
					p.FillPath(starPath(r, 0.48, 0), col)
				} else {
					p.StrokePath(starPath(ui.Rect{X: r.X + 2, Y: r.Y + 2, W: r.W - 4, H: r.H - 4}, 0.48, 0), 2.5, col)
				}
			})
			ui.Column(c).Gap(3).Grow(1).Children(func() {
				ui.Text(c, title).FontSize(20).Bold()
				ui.Text(c, line).FontSize(12).TextColor(t.TextMuted).Wrap()
			})
		})
		if m.notice != "" && !m.neutral {
			ui.Text(c, m.notice).
				FontSize(12).Wrap().Padding(8, 10).Radius(8).Background(colSoyo.Alpha(0.22))
		}
		if m.notice != "" && m.neutral {
			ui.Text(c, m.notice).
				FontSize(12).Wrap().Padding(8, 10).Radius(8).Background(t.Surface).Border(1, t.Border)
		}
		m.kvGrid(c, t, [][2]string{
			{"学号", dash(m.studentID)},
			{"定位坐标", fmt.Sprintf("%.6f, %.6f ±%.0fm", m.cfg.Lat, m.cfg.Lon, m.cfg.AccM)},
			{"考勤窗口", m.cfg.AttWindow + "（晚归线 " + m.cfg.LateLine + "）"},
			{"自动签到", strings.Join(m.cfg.Times, " / ")},
			{"定位注入", onOff(m.cfg.GeoOn) + mustMark(m.cfg.GeoMust)},
		})
		ui.Row(c).Gap(8).Children(func() {
			busy := m.phase == "签到中"
			if ui.PrimaryButton(c, "立即签到").Grow(1).Disabled(busy).Clicked() {
				m.act.Sign()
			}
			if ui.Button(c, "刷新").Grow(1).Disabled(busy).Clicked() {
				m.notice = ""
			}
		})
	})
}

func (m *model) kvGrid(c *ui.Context, t *ui.Theme, kvs [][2]string) {
	ui.Grid(c).ColumnTracks(ui.Fixed(72), ui.Fr(1)).GapX(12).GapY(4).Children(func() {
		for _, kv := range kvs {
			ui.Text(c, kv[0]).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, kv[1]).FontSize(12).Selectable().Wrap()
		}
	})
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "开启"
	}
	return "关闭"
}

func mustMark(must bool) string {
	if must {
		return "（必须通过）"
	}
	return ""
}

func (m *model) accountCard(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		sectionTitle(c, t, "账号", colGold)
		ui.TextInput(c, &m.id).Label("学号").Placeholder("学号").FillWidth()
		placeholder := "学工系统密码"
		if m.hasCreds {
			placeholder = "清空后保存 = 删除密码"
		}
		var submitted bool
		if m.showPass {
			pw := ui.TextInput(c, &m.pass).Label("密码").FillWidth()
			pw.Placeholder(placeholder)
			submitted = pw.Submitted()
		} else {
			pw := ui.TextInput(c, &m.pass).Label("密码").Password().FillWidth()
			pw.Placeholder(placeholder)
			submitted = pw.Submitted()
		}
		eye := "👁 显示"
		if m.showPass {
			eye = "🙈 隐藏"
		}
		ui.Row(c).Gap(8).AlignItems(ui.Center).FillWidth().Children(func() {
			if ui.Button(c, eye).FontSize(12).Clicked() {
				m.showPass = !m.showPass
			}
		})
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, m.notice).FontSize(12).TextColor(t.TextMuted).Grow(1).Wrap()
			dirty := m.id != m.storedID || m.pass != m.storedPass
			if (ui.PrimaryButton(c, "保存").Disabled(!dirty || m.id == "").Clicked() || (submitted && dirty)) && m.id != "" {
				m.act.Save(m.id, m.pass)
			}
		})
	})
}

func (m *model) switches(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		sectionTitle(c, t, "设置", colGoldDk)
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(1).Children(func() {
				ui.Text(c, "开机自启")
				ui.Text(c, "登录系统后在托盘待命，到点自动签").FontSize(11.5).TextColor(t.TextMuted)
			})
			if ui.Switch(c, &m.autostart).Label("开机自启").Changed() {
				m.act.SetAutostart(m.autostart)
			}
		})
	})
}

const logLine = 19

func (m *model) logCard(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(8, 8).Radius(4).Background(colGold)
			ui.Text(c, "爽世的记事本").FontSize(13).Bold().Grow(1)
			if ui.Button(c, "日志文件").FontSize(12).Clicked() {
				m.act.OpenLogs()
			}
		})
		bg, rule := ui.Hex("#FFFEF5"), ui.RGBA(217, 166, 46, 0.13)
		if t.Dark {
			bg, rule = ui.Hex("#241F10"), ui.RGBA(255, 221, 136, 0.10)
		}
		sc := ui.Scroll(c).Height(200).TrackScroll(&m.logScroll).Radius(8).Background(bg).Border(1, t.Border)
		if m.logScroll.Y >= m.logScroll.MaxY-1 {
			m.logScroll.Y = math.MaxFloat32
		}
		sc.Children(func() {
			ui.Column(c).FillWidth().MinHeight(200).Padding(4, 10, 4, 22).
				Draw(func(p *ui.Painter, r ui.Rect) {
					for y := r.Y + 4 + logLine; y < r.Y+r.H; y += logLine {
						p.Line(r.X, y, r.X+r.W, y, 1, rule)
					}
					p.Line(r.X+14, r.Y, r.X+14, r.Y+r.H, 1, colGold.Alpha(0.45))
				}).
				Children(func() {
					if len(m.logs) == 0 {
						ui.Text(c, "这里会记下每一次签到……").FontSize(12).FixedLineHeight(logLine).TextColor(t.TextMuted)
					}
					for i, l := range m.logs {
						ui.Text(c, l).Key(i).FontSize(11.5).FixedLineHeight(logLine).Selectable().Wrap()
					}
				})
		})
	})
}

func sectionTitle(c *ui.Context, t *ui.Theme, title string, col ui.Color) {
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Box(c).Size(8, 8).Radius(4).Background(col)
		ui.Text(c, title).FontSize(13).Bold()
	})
}

func (m *model) footer(c *ui.Context, t *ui.Theme) {
	ui.Row(c).Center().Gap(6).Padding(2, 0, 6, 0).Children(func() {
		for _, col := range colMembers {
			ui.Box(c).Size(6, 6).Radius(3).Background(col)
		}
		ui.Text(c, "it's MyGO!!!!!  ·  白云校区专属  ·  v"+m.version).FontSize(11).TextColor(t.TextMuted)
	})
}
