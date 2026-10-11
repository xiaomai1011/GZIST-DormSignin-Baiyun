// Package captcha recognizes the arithmetic captcha ("5+7=") shown by
// the CAS login page and the sign-in dialog. It is a faithful Go port of
// captcha-solve.ps1 v2: connected-component segmentation, multi-font
// template matching on 40x40 normalized bitmaps with popcount Jaccard,
// and a hole-count tiebreak for look-alike digits. Recognition failures
// are reported honestly — the caller refreshes and retries, never guesses.
package captcha

import (
	"fmt"
	"image"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/freetype"
	"github.com/golang/freetype/truetype"
)

const (
	algoVer  = "g1-20261009"
	boxW     = 40
	boxH     = 40
	boxBytes = boxW * boxH / 8 // 200
)

var charset = []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '+', '-', '='}

// fonts pairs the PowerShell font list with Windows font files, in a
// fixed order (stable template cache). Missing files are skipped, same
// try/catch semantics as the original.
type fontRef struct{ name, file string }

var fonts = []fontRef{
	{"Arial", "arial.ttf"},
	{"Arial Bold", "arialbd.ttf"},
	{"Times New Roman", "times.ttf"},
	{"Times New Roman Bold", "timesbd.ttf"},
	{"Courier New", "cour.ttf"},
	{"Courier New Bold", "courbd.ttf"},
	{"Verdana", "verdana.ttf"},
	{"Tahoma", "tahoma.ttf"},
	{"Georgia", "georgia.ttf"},
	{"Trebuchet MS", "trebuc.ttf"},
	{"Calibri", "calibri.ttf"},
	{"Cambria", "cambria.ttc"},
	{"Segoe UI", "segoeui.ttf"},
	{"Microsoft Sans Serif", "micross.ttf"},
	{"Comic Sans MS", "comic.ttf"},
	{"Impact", "impact.ttf"},
	{"Arial Narrow", "arialn.ttf"},
	{"Book Antiqua", "BKANT.TTF"},
	{"Century Gothic", "GOTHIC.TTF"},
	{"Garamond", "gara.ttf"},
	{"Rockwell", "rock.ttf"},
	{"Sylfaen", "sylfaen.ttf"},
}

var fontSizes = []float64{22, 34, 44}

// holeExpect is the hole-count tiebreak (4 has open/closed forms; skip).
var holeExpect = map[byte]int{'0': 1, '6': 1, '8': 2, '9': 1}

// ---------- bitmaps ----------

// glyph is a normalized 40x40 bitmap: packed bits + ink pixel count.
type glyph struct {
	ch   byte
	bits []byte
	pop  int
}

type mask struct {
	w, h int
	bits []bool
	pop  int
}

func (m *mask) set(x, y int) {
	i := y*m.w + x
	if !m.bits[i] {
		m.bits[i] = true
		m.pop++
	}
}

func (m *mask) boxed() *mask { return scaleToBox(m) }

func lumBytes(img image.Image) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	lum := make([]byte, w*h)
	i := 0
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			lum[i] = byte((299*(r>>8) + 587*(g>>8) + 114*(bl>>8)) / 1000)
			i++
		}
	}
	return lum
}

// adaptiveThreshold: thr = min + (255-min)/2 — the "50% edge" semantics
// shared by glyphs and templates.
func adaptiveThreshold(lum []byte, off, w, h, stride int) int {
	min := 255
	for y := 0; y < h; y++ {
		row := off + y*stride
		for x := 0; x < w; x++ {
			if int(lum[row+x]) < min {
				min = int(lum[row+x])
			}
		}
	}
	return min + (255-min)/2
}

func maskFromLum(lum []byte, off, w, h, stride, thr int) *mask {
	m := &mask{w: w, h: h, bits: make([]bool, w*h)}
	for y := 0; y < h; y++ {
		row := off + y*stride
		for x := 0; x < w; x++ {
			if int(lum[row+x]) < thr {
				m.set(x, y)
			}
		}
	}
	return m
}

// scaleToBox fits the mask into boxW x boxH keeping the aspect ratio,
// centered, with a 90% margin — identical to Convert-MaskToBox.
func scaleToBox(m *mask) *mask {
	out := &mask{w: boxW, h: boxH, bits: make([]bool, boxW*boxH)}
	if m.pop == 0 {
		return out
	}
	minX, minY, maxX, maxY := m.w, m.h, -1, -1
	for y := 0; y < m.h; y++ {
		for x := 0; x < m.w; x++ {
			if m.bits[y*m.w+x] {
				if x < minX {
					minX = x
				}
				if x > maxX {
					maxX = x
				}
				if y < minY {
					minY = y
				}
				if y > maxY {
					maxY = y
				}
			}
		}
	}
	cw, ch := maxX-minX+1, maxY-minY+1
	scale := math.Min(float64(boxW)*0.9/float64(cw), float64(boxH)*0.9/float64(ch))
	dw := max(1, int(math.Round(float64(cw)*scale)))
	dh := max(1, int(math.Round(float64(ch)*scale)))
	ox, oy := (boxW-dw)/2, (boxH-dh)/2
	for y := 0; y < dh; y++ {
		sy := min(ch-1, int(float64(y)/scale))
		for x := 0; x < dw; x++ {
			sx := min(cw-1, int(float64(x)/scale))
			if m.bits[(minY+sy)*m.w+(minX+sx)] {
				out.set(ox+x, oy+y)
			}
		}
	}
	return out
}

func pack(m *mask) glyph {
	g := glyph{bits: make([]byte, boxBytes)}
	for y := 0; y < boxH; y++ {
		for x := 0; x < boxW; x++ {
			if m.bits[y*boxW+x] {
				bi := y*boxW + x
				g.bits[bi/8] |= 1 << (bi % 8)
			}
		}
	}
	for _, b := range g.bits {
		g.pop += int(popTab[b])
	}
	return g
}

var popTab = func() [256]byte {
	var t [256]byte
	for i := 0; i < 256; i++ {
		for v := i; v > 0; v &= v - 1 {
			t[i]++
		}
	}
	return t
}()

func jaccard(a, b *glyph) float64 {
	hi, lo := a.pop, b.pop
	if hi < lo {
		hi, lo = lo, hi
	}
	if hi == 0 || float64(lo)/float64(hi) < 0.5 {
		return 0 // fast reject = Jaccard upper bound below 0.5
	}
	inter := 0
	for i := 0; i < boxBytes; i++ {
		if x := a.bits[i] & b.bits[i]; x != 0 {
			inter += int(popTab[x])
		}
	}
	uni := a.pop + b.pop - inter
	if uni == 0 {
		return 0
	}
	return float64(inter) / float64(uni)
}

// holeCount floods the background from the mask border; unreached
// background regions are holes (area-filtered). Mirrors Get-HoleCount.
func holeCount(m *mask) int {
	if m.pop == 0 {
		return 0
	}
	w, h := m.w, m.h
	seen := make([]bool, w*h)
	var visit func(start int) int
	stack := make([]int, 0, 64)
	push := func(i int) {
		if !seen[i] && !m.bits[i] {
			seen[i] = true
			stack = append(stack, i)
		}
	}
	visit = func(start int) int {
		area := 0
		seen[start] = true
		stack = append(stack, start)
		for len(stack) > 0 {
			i := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			area++
			cx := i % w
			for _, j := range []int{i - 1, i + 1, i - w, i + w} {
				if j < 0 || j >= w*h {
					continue
				}
				if (j == i-1 && cx == 0) || (j == i+1 && cx == w-1) {
					continue
				}
				push(j)
			}
		}
		return area
	}
	for x := 0; x < w; x++ {
		visit(x)
		visit((h-1)*w + x)
	}
	for y := 0; y < h; y++ {
		visit(y * w)
		visit(y*w + w - 1)
	}
	holes, minArea := 0, max(6, m.pop*6/100)
	for start := 0; start < w*h; start++ {
		if seen[start] || m.bits[start] {
			continue
		}
		if visit(start) >= minArea {
			holes++
		}
	}
	return holes
}

// glyphBoxes segments the image into character boxes: connected
// components (4-neighborhood, ink = lum < coarseThr), merged by X
// overlap then by gap — mirroring Get-GlyphsFromLum.
func glyphBoxes(lum []byte, w, h, coarseThr int) []*mask {
	visited := make([]bool, w*h)
	type comp struct{ minX, minY, maxX, maxY int }
	var comps []comp
	for start := 0; start < w*h; start++ {
		if int(lum[start]) >= coarseThr || visited[start] {
			continue
		}
		visited[start] = true
		stack := []int{start}
		pix := 0
		c := comp{minX: w, minY: h, maxX: -1, maxY: -1}
		for len(stack) > 0 {
			i := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			pix++
			cx, cy := i%w, i/w
			if cx < c.minX {
				c.minX = cx
			}
			if cx > c.maxX {
				c.maxX = cx
			}
			if cy < c.minY {
				c.minY = cy
			}
			if cy > c.maxY {
				c.maxY = cy
			}
			for _, j := range []int{i - 1, i + 1, i - w, i + w} {
				if j < 0 || j >= w*h {
					continue
				}
				if (j == i-1 && cx == 0) || (j == i+1 && cx == w-1) {
					continue
				}
				if visited[j] || int(lum[j]) >= coarseThr {
					continue
				}
				visited[j] = true
				stack = append(stack, j)
			}
		}
		if pix >= 6 {
			comps = append(comps, c)
		}
	}
	if len(comps) == 0 {
		return nil
	}
	// sort by minX (insertion sort — comps is small)
	for i := 1; i < len(comps); i++ {
		for j := i; j > 0 && comps[j].minX < comps[j-1].minX; j-- {
			comps[j], comps[j-1] = comps[j-1], comps[j]
		}
	}
	var glyphs []comp
	var cur *comp
	for _, c := range comps {
		if cur == nil {
			cur = new(comp)
			*cur = c
			continue
		}
		if c.minX <= cur.maxX-1 {
			if c.maxX > cur.maxX {
				cur.maxX = c.maxX
			}
			if c.minY < cur.minY {
				cur.minY = c.minY
			}
			if c.maxY > cur.maxY {
				cur.maxY = c.maxY
			}
		} else {
			glyphs = append(glyphs, *cur)
			cur = new(comp)
			*cur = c
		}
	}
	if cur != nil {
		glyphs = append(glyphs, *cur)
	}
	gapThr := max(6, w*25/1000)
	var merged []comp
	for _, g := range glyphs {
		if n := len(merged); n > 0 && g.minX-merged[n-1].maxX <= gapThr {
			if g.maxX > merged[n-1].maxX {
				merged[n-1].maxX = g.maxX
			}
			if g.minY < merged[n-1].minY {
				merged[n-1].minY = g.minY
			}
			if g.maxY > merged[n-1].maxY {
				merged[n-1].maxY = g.maxY
			}
			continue
		}
		merged = append(merged, g)
	}
	out := make([]*mask, 0, len(merged))
	for _, gl := range merged {
		gw, gh := gl.maxX-gl.minX+1, gl.maxY-gl.minY+1
		off := gl.minY*w + gl.minX
		thr := adaptiveThreshold(lum, off, gw, gh, w)
		out = append(out, maskFromLum(lum, off, gw, gh, w, thr))
	}
	return out
}

// ---------- templates ----------

type templateSet struct {
	byChar map[byte][]glyph
	n      int
}

// buildTemplates renders every charset char in every font/size with
// freetype and normalizes each to the 40x40 box.
func buildTemplates() (*templateSet, error) {
	ts := &templateSet{byChar: map[byte][]glyph{}}
	fontDir := filepath.Join(os.Getenv("WINDIR"), "Fonts")
	for _, ch := range charset {
		for _, fr := range fonts {
			data, err := os.ReadFile(filepath.Join(fontDir, fr.file))
			if err != nil {
				continue
			}
			f, err := truetype.Parse(data)
			if err != nil {
				continue
			}
			for _, pt := range fontSizes {
				m, err := renderGlyph(f, pt, rune(ch))
				if err != nil || m.pop == 0 {
					continue
				}
				g := pack(scaleToBox(m))
				g.ch = ch
				ts.byChar[ch] = append(ts.byChar[ch], g)
				ts.n++
			}
		}
	}
	if ts.n == 0 {
		return nil, fmt.Errorf("no font template could be rendered (check %s)", fontDir)
	}
	return ts, nil
}

// renderGlyph draws ch at the given point size and binarizes with the
// adaptive mid threshold (same semantics as the GDI originals).
func renderGlyph(f *truetype.Font, pt float64, ch rune) (*mask, error) {
	const pad = 8
	w, h := int(pt*3)+pad*2, int(pt*2)+pad*2
	img := image.NewGray(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	c := freetype.NewContext()
	c.SetDPI(96)
	c.SetFont(f)
	c.SetFontSize(pt)
	c.SetClip(img.Bounds())
	c.SetDst(img)
	c.SetSrc(image.Black)
	if _, err := c.DrawString(string(ch), freetype.Pt(pad, int(pt*1.5))); err != nil {
		return nil, err
	}
	lum := make([]byte, w*h)
	for i, v := range img.Pix {
		lum[i] = v
	}
	thr := adaptiveThreshold(lum, 0, w, h, w)
	return maskFromLum(lum, 0, w, h, w, thr), nil
}

// ---------- template cache (Go format "GDST1") ----------

func cacheVersion() int32 {
	var names []string
	for _, fr := range fonts {
		names = append(names, fr.name)
	}
	s := algoVer + "|" + strings.Join(names, ",") + "|22,34,44|40x40"
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return int32(h)
}

func loadCache(path string) *templateSet {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 13 || string(b[:5]) != "GDST1" {
		return nil
	}
	off := 5
	i32 := func() int32 {
		v := int32(b[off]) | int32(b[off+1])<<8 | int32(b[off+2])<<16 | int32(b[off+3])<<24
		off += 4
		return v
	}
	if i32() != cacheVersion() {
		return nil
	}
	n := int(i32())
	if n <= 0 || n > 100000 {
		return nil
	}
	ts := &templateSet{byChar: map[byte][]glyph{}}
	for i := 0; i < n; i++ {
		if off+1+boxBytes+4 > len(b) {
			return nil
		}
		ch := b[off]
		off++
		g := glyph{ch: ch, bits: append([]byte(nil), b[off:off+boxBytes]...)}
		off += boxBytes
		g.pop = int(i32())
		if g.pop <= 0 {
			return nil
		}
		ts.byChar[ch] = append(ts.byChar[ch], g)
		ts.n++
	}
	if ts.n == 0 {
		return nil
	}
	return ts
}

func saveCache(path string, ts *templateSet) error {
	out := []byte("GDST1")
	i32 := func(v int32) { out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	i32(cacheVersion())
	i32(int32(ts.n))
	for _, ch := range charset {
		for _, g := range ts.byChar[ch] {
			out = append(out, ch)
			out = append(out, g.bits...)
			i32(int32(g.pop))
		}
	}
	return os.WriteFile(path, out, 0o600)
}

// ---------- entry ----------

type Solver struct {
	cachePath string
	ts        *templateSet
}

// New returns a solver. Templates load from cachePath, or rebuild from
// the system fonts on first use.
func New(cachePath string) (*Solver, error) {
	s := &Solver{cachePath: cachePath}
	if ts := loadCache(cachePath); ts != nil {
		s.ts = ts
		return s, nil
	}
	ts, err := buildTemplates()
	if err != nil {
		return nil, err
	}
	s.ts = ts
	_ = saveCache(cachePath, ts)
	return s, nil
}

type charRes struct {
	ch     byte
	score  float64
	margin float64
}

// Count reports the number of loaded templates.
func (s *Solver) Count() int { return s.ts.n }

// Solve recognizes an arithmetic captcha image. Mirrors Invoke-CaptchaSolve:
// honest failures — refresh and retry, never guess.
func (s *Solver) Solve(img image.Image) Result {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	if w <= 0 || h <= 0 {
		return Result{Reason: "空图"}
	}
	lum := lumBytes(img)
	boxes := glyphBoxes(lum, w, h, 245)
	if len(boxes) < 3 || len(boxes) > 6 {
		return Result{Reason: fmt.Sprintf("字符数异常(%d)", len(boxes))}
	}
	var chars []charRes
	expr := ""
	for _, m := range boxes {
		g := pack(scaleToBox(m))
		// score every charset char, keep the ranked top pair
		type pair struct {
			ch byte
			s  float64
		}
		var ranked []pair
		for _, ch := range charset {
			bs := 0.0
			for _, t := range s.ts.byChar[ch] {
				if sc := jaccard(&g, &t); sc > bs {
					bs = sc
				}
			}
			ranked = append(ranked, pair{ch, bs})
		}
		for i := 1; i < len(ranked); i++ {
			for j := i; j > 0 && ranked[j].s > ranked[j-1].s; j-- {
				ranked[j], ranked[j-1] = ranked[j-1], ranked[j]
			}
		}
		bestCh, bestS := ranked[0].ch, ranked[0].s
		secondS := 0.0
		if len(ranked) > 1 {
			secondS = ranked[1].s
		}
		// hole-count tiebreak: both top candidates are look-alike digits
		// with a small margin → decide by topology
		if len(ranked) > 1 && bestS-secondS < 0.06 {
			e1, ok1 := holeExpect[bestCh]
			e2, ok2 := holeExpect[ranked[1].ch]
			if ok1 && ok2 {
				holes := holeCount(scaleToBox(m))
				if e1 != holes && e2 == holes {
					bestCh, bestS = ranked[1].ch, ranked[1].s
				}
			}
		}
		chars = append(chars, charRes{ch: bestCh, score: bestS, margin: bestS - secondS})
		expr += string(bestCh)
	}
	// structure: digit op digit, optional trailing '='
	var a, b int
	var op byte
	var digits []charRes
	switch len(chars) {
	case 3:
		digits = chars
	case 4:
		if chars[3].ch != '=' {
			return Result{Reason: "结构不匹配", Expr: expr, Detail: charsDetail(chars)}
		}
		digits = chars[:3]
	default:
		return Result{Reason: "结构不匹配", Expr: expr, Detail: charsDetail(chars)}
	}
	if !isDigit(digits[0].ch) || !isOp(digits[1].ch) || !isDigit(digits[2].ch) {
		return Result{Reason: "结构不匹配", Expr: expr, Detail: charsDetail(chars)}
	}
	a, op, b = int(digits[0].ch-'0'), digits[1].ch, int(digits[2].ch-'0')
	minScore, minMargin := 1.0, 1.0
	for _, c := range digits {
		minScore = min(minScore, c.score)
		minMargin = min(minMargin, c.margin)
	}
	ans := 0
	switch op {
	case '+':
		ans = a + b
	case '-':
		ans = a - b
	case '*':
		ans = a * b
	}
	return Result{
		OK:        true,
		Expr:      fmt.Sprintf("%d%c%d", a, op, b),
		Ans:       fmt.Sprint(ans),
		MinScore:  math.Round(minScore*1000) / 1000,
		MinMargin: math.Round(minMargin*1000) / 1000,
		Glyphs:    expr,
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isOp(b byte) bool    { return b == '+' || b == '-' || b == '*' }

func charsDetail(chars []charRes) string {
	var parts []string
	for _, c := range chars {
		parts = append(parts, fmt.Sprintf("%c:%.2f", c.ch, c.score))
	}
	return strings.Join(parts, " ")
}

// Result is the outcome of one recognition attempt. OK=false means the
// caller should refresh the image and retry — never guess.
type Result struct {
	OK        bool
	Reason    string
	Expr      string
	Ans       string
	MinScore  float64
	MinMargin float64
	Glyphs    string
	Detail    string
}
