package captcha

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"

	"github.com/golang/freetype/truetype"
	"path/filepath"
)

func TestBuildTemplatesRealFonts(t *testing.T) {
	ts, err := buildTemplates()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("templates built: %d (%d chars)", ts.n, len(ts.byChar))
	if ts.n < 400 {
		t.Fatalf("too few templates: %d — font files missing?", ts.n)
	}
	// self-consistency: render "5+7=" as an image, solve it back
	img := renderExpr("5+7=")
	r := (&Solver{ts: ts}).Solve(img)
	if !r.OK || r.Expr != "5+7" || r.Ans != "12" {
		t.Fatalf("self-test: %+v", r)
	}
	t.Logf("self-test OK: %s=%s score=%.3f margin=%.3f", r.Expr, r.Ans, r.MinScore, r.MinMargin)
}

// renderExpr composes a synthetic captcha image from the same renderer.
func renderExpr(expr string) image.Image {
	var imgs []image.Image
	for _, ch := range expr {
		f := loadFontAny(ch)
		m, err := renderGlyph(f, 34, ch)
		if err != nil {
			panic(err)
		}
		imgs = append(imgs, maskToImg(m))
	}
	W := 0
	H := 0
	for _, im := range imgs {
		W += im.Bounds().Dx() + 6
		if im.Bounds().Dy() > H {
			H = im.Bounds().Dy()
		}
	}
	canvas := image.NewGray(image.Rect(0, 0, W+20, H+20))
	for i := range canvas.Pix {
		canvas.Pix[i] = 255
	}
	x := 10
	for _, im := range imgs {
		b := im.Bounds()
		for yy := 0; yy < b.Dy(); yy++ {
			for xx := 0; xx < b.Dx(); xx++ {
				c := color.GrayModel.Convert(im.At(b.Min.X+xx, b.Min.Y+yy)).(color.Gray)
				if c.Y < 255 {
					canvas.SetGray(x+xx, 10+yy, c)
				}
			}
		}
		x += b.Dx() + 6
	}
	return canvas
}

func maskToImg(m *mask) image.Image {
	img := image.NewGray(image.Rect(0, 0, m.w, m.h))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	for y := 0; y < m.h; y++ {
		for x := 0; x < m.w; x++ {
			if m.bits[y*m.w+x] {
				img.SetGray(x, y, color.Gray{Y: 0})
			}
		}
	}
	return img
}

func TestCacheRoundTrip(t *testing.T) {
	ts, err := buildTemplates()
	if err != nil {
		t.Fatal(err)
	}
	p := "test-templates-g.cache"
	defer os.Remove(p)
	if err := saveCache(p, ts); err != nil {
		t.Fatal(err)
	}
	loaded := loadCache(p)
	if loaded == nil || loaded.n != ts.n {
		t.Fatalf("cache round trip failed: got n=%v want %d", loaded, ts.n)
	}
	_ = png.Encode
}

func loadFontAny(ch rune) *truetype.Font {
	data, err := os.ReadFile(filepath.Join(os.Getenv("WINDIR"), "Fonts", "arial.ttf"))
	if err != nil {
		panic(err)
	}
	f, err := truetype.Parse(data)
	if err != nil {
		panic(err)
	}
	return f
}
