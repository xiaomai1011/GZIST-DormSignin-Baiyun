// Package art draws the app's pictures: the "迷星" star with Wi-Fi waves,
// the tray and the app icon, in the colors of MyGO!!!!!.
package art

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"

	"golang.org/x/image/vector"
)

// Colors of the band and its five members.
var (
	Band    = color.RGBA{0x33, 0x88, 0xBB, 0xff} // MyGO!!!!!
	Tomori  = color.RGBA{0x77, 0xBB, 0xDD, 0xff} // 高松灯
	Anon    = color.RGBA{0xFF, 0x88, 0x99, 0xff} // 千早爱音
	Rana    = color.RGBA{0x77, 0xDD, 0x77, 0xff} // 要乐奈
	Soyo    = color.RGBA{0xFF, 0xDD, 0x88, 0xff} // 长崎爽世
	Taki    = color.RGBA{0x77, 0x77, 0xAA, 0xff} // 椎名立希
	Members = []color.RGBA{Tomori, Anon, Rana, Soyo, Taki}
)

// StarPoints returns the ten corners of a five-pointed star centred at
// (cx, cy) with outer radius r, turned by rot degrees.
func StarPoints(cx, cy, r, inner, rot float64) [][2]float64 {
	pts := make([][2]float64, 10)
	for i := range pts {
		rr := r
		if i%2 == 1 {
			rr = r * inner
		}
		a := (rot - 90 + float64(i)*36) * math.Pi / 180
		pts[i] = [2]float64{cx + rr*math.Cos(a), cy + rr*math.Sin(a)}
	}
	return pts
}

type raster struct {
	img *image.RGBA
	w   int
}

func newRaster(w int) *raster {
	return &raster{img: image.NewRGBA(image.Rect(0, 0, w, w)), w: w}
}

func (r *raster) fill(path func(z *vector.Rasterizer), src image.Image) {
	z := vector.NewRasterizer(r.w, r.w)
	z.DrawOp = draw.Over
	path(z)
	z.Draw(r.img, r.img.Bounds(), src, image.Point{})
}

func poly(pts [][2]float64) func(z *vector.Rasterizer) {
	return func(z *vector.Rasterizer) {
		z.MoveTo(float32(pts[0][0]), float32(pts[0][1]))
		for _, p := range pts[1:] {
			z.LineTo(float32(p[0]), float32(p[1]))
		}
		z.ClosePath()
	}
}

// ring is the outline of a star: outer star minus a smaller one drawn the
// other way round.
func ring(outer, inner [][2]float64) func(z *vector.Rasterizer) {
	return func(z *vector.Rasterizer) {
		poly(outer)(z)
		z.MoveTo(float32(inner[0][0]), float32(inner[0][1]))
		for i := len(inner) - 1; i >= 1; i-- {
			z.LineTo(float32(inner[i][0]), float32(inner[i][1]))
		}
		z.ClosePath()
	}
}

func circle(cx, cy, r float64) func(z *vector.Rasterizer) {
	return func(z *vector.Rasterizer) {
		const k = 0.5522847498
		x, y, R := float32(cx), float32(cy), float32(r)
		K := float32(k) * R
		z.MoveTo(x+R, y)
		z.CubeTo(x+R, y+K, x+K, y+R, x, y+R)
		z.CubeTo(x-K, y+R, x-R, y+K, x-R, y)
		z.CubeTo(x-R, y-K, x-K, y-R, x, y-R)
		z.CubeTo(x+K, y-R, x+R, y-K, x+R, y)
		z.ClosePath()
	}
}

func roundRect(x, y, w, h, r float64) func(z *vector.Rasterizer) {
	return func(z *vector.Rasterizer) {
		const k = 0.5522847498
		K := r * k
		f := func(v float64) float32 { return float32(v) }
		z.MoveTo(f(x+r), f(y))
		z.LineTo(f(x+w-r), f(y))
		z.CubeTo(f(x+w-r+K), f(y), f(x+w), f(y+r-K), f(x+w), f(y+r))
		z.LineTo(f(x+w), f(y+h-r))
		z.CubeTo(f(x+w), f(y+h-r+K), f(x+w-r+K), f(y+h), f(x+w-r), f(y+h))
		z.LineTo(f(x+r), f(y+h))
		z.CubeTo(f(x+r-K), f(y+h), f(x), f(y+h-r+K), f(x), f(y+h-r))
		z.LineTo(f(x), f(y+r))
		z.CubeTo(f(x), f(y+r-K), f(x+r-K), f(y), f(x+r), f(y))
		z.ClosePath()
	}
}

// wifiWaves draws two Wi-Fi arcs centred at (cx, cy), opening upwards,
// with the given outer radii and stroke width.
func wifiWaves(r *raster, cx, cy, r1, r2, width float64, src image.Image) {
	// Each wave is a stroked arc; approximate it as the region between
	// two concentric arcs (outer minus inner, drawn the other way round).
	wave := func(radius float64) {
		z := vector.NewRasterizer(r.w, r.w)
		const steps = 64
		a0, a1 := -math.Pi*0.78, -math.Pi*0.22 // up-opening 135° arc
		for i := 0; i <= steps; i++ {
			a := a0 + (a1-a0)*float64(i)/steps
			x, y := cx+(radius+width/2)*math.Cos(a), cy+(radius+width/2)*math.Sin(a)
			if i == 0 {
				z.MoveTo(float32(x), float32(y))
			} else {
				z.LineTo(float32(x), float32(y))
			}
		}
		for i := steps; i >= 0; i-- {
			a := a0 + (a1-a0)*float64(i)/steps
			x, y := cx+(radius-width/2)*math.Cos(a), cy+(radius-width/2)*math.Sin(a)
			z.LineTo(float32(x), float32(y))
		}
		z.ClosePath()
		r.fillRaw(z, src)
	}
	wave(r1)
	wave(r2)
	// the dot
	r.fill(circle(cx, cy, width*0.9), src)
}

func (r *raster) fillRaw(z *vector.Rasterizer, src image.Image) {
	z.DrawOp = draw.Over
	z.Draw(r.img, r.img.Bounds(), src, image.Point{})
}

// gradient is a diagonal two-color gradient image.
type gradient struct {
	from, to color.RGBA
	w        int
}

func (g gradient) ColorModel() color.Model { return color.RGBAModel }
func (g gradient) Bounds() image.Rectangle { return image.Rect(0, 0, g.w, g.w) }
func (g gradient) At(x, y int) color.Color {
	t := float64(x+y) / float64(2*g.w)
	m := func(a, b uint8) uint8 { return uint8(float64(a) + (float64(b)-float64(a))*t) }
	return color.RGBA{m(g.from.R, g.to.R), m(g.from.G, g.to.G), m(g.from.B, g.to.B), 0xff}
}

func encode(img image.Image) []byte {
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// AppIcon draws the 1024² application icon: a white 迷星 with Wi-Fi waves
// over gold (Soyo's color, matching the tray), with the five members'
// colors beneath it. Green so the app reads apart from the blue-star app.
func AppIcon() []byte {
	const W = 1024
	r := newRaster(W)
	// macOS-style icon grid: 824² body with a little room around it.
	r.fill(roundRect(100, 100, 824, 824, 185),
		gradient{color.RGBA{0xFF, 0xC9, 0x4D, 0xff}, color.RGBA{0xB8, 0x86, 0x0B, 0xff}, W})
	// faint sparkles
	white := image.NewUniform(color.NRGBA{255, 255, 255, 0x66})
	for _, s := range [][3]float64{{250, 260, 34}, {790, 230, 26}, {800, 640, 20}, {230, 600, 18}} {
		r.fill(poly(StarPoints(s[0], s[1], s[2], 0.42, 0)), white)
	}
	// soft shadow, then the star
	r.fill(poly(StarPoints(512, 470, 255, 0.48, -8)), image.NewUniform(color.NRGBA{0x5a, 0x40, 0x10, 0x48}))
	r.fill(poly(StarPoints(512, 452, 255, 0.48, -8)), image.NewUniform(color.RGBA{255, 255, 255, 255}))
	// Wi-Fi waves above the star
	waves := image.NewUniform(color.NRGBA{255, 255, 255, 0xe6})
	wifiWaves(r, 512, 330, 150, 100, 30, waves)
	// five members
	for i, c := range Members {
		x := 512 + float64(i-2)*92
		y := 790 - 22*math.Cos(float64(i-2)*0.6)
		r.fill(circle(x, y+4, 34), image.NewUniform(color.NRGBA{0x5a, 0x40, 0x10, 0x48}))
		r.fill(circle(x, y, 34), image.NewUniform(color.RGBA{255, 255, 255, 255}))
		r.fill(circle(x, y, 26), image.NewUniform(c))
	}
	return encode(r.img)
}

// TrayState picks the tray picture.
type TrayState int

const (
	TrayOff TrayState = iota
	TrayOn
	TrayIdle // solid dark gold: monitoring, breathing between TrayOn/TrayIdle
	TrayBusy
	TrayError
)

// TrayIcon draws a 32×32 star (16 points at 2×). A template icon is black
// on transparent for the macOS menu bar, which tints it itself; otherwise
// it is colored. TrayOn adds small Wi-Fi waves over the filled star.
func TrayIcon(s TrayState, template bool) []byte {
	const W = 32
	r := newRaster(W)
	outer := StarPoints(16, 17, 15, 0.46, 0)
	col := map[TrayState]color.RGBA{
		// Soyo's gold, so the tray star reads apart from the blue
		// (NetKeeper) and green (Hotspot) stars of the other apps.
		TrayOff:   {0x8a, 0x8f, 0x98, 0xff}, // grey: holiday / not configured
		TrayOn:    Soyo,                     // bright gold: monitoring
		TrayIdle:  {0xB0, 0x8A, 0x28, 0xff}, // dark gold: the breathing "dim" phase
		TrayBusy:  Anon,
		TrayError: {0xE0, 0x9A, 0x1E, 0xff},
	}[s]
	if template {
		col = color.RGBA{0, 0, 0, 0xff}
	}
	src := image.NewUniform(col)
	switch s {
	case TrayOff:
		r.fill(ring(outer, StarPoints(16, 17, 10.2, 0.46, 0)), src)
	case TrayBusy:
		r.fill(ring(outer, StarPoints(16, 17, 10.2, 0.46, 0)), src)
		r.fill(circle(16, 17.5, 3.2), src)
	case TrayError:
		r.fill(ring(outer, StarPoints(16, 17, 10.2, 0.46, 0)), src)
		r.fill(roundRect(14.6, 10, 2.8, 6.5, 1.2), src)
		r.fill(circle(16, 20.4, 1.7), src)
	default:
		// A plain filled star, like the other app's tray icon — the
		// color alone tells the two apart.
		r.fill(poly(outer), src)
	}
	return encode(r.img)
}
