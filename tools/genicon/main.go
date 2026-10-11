// Command genicon writes resources/icon.png from the art package.
// Run it from the repository root: go run ./tools/genicon
package main

import (
	"os"
	"path/filepath"

	"github.com/xiaomai1011/GZIST-DormSignin-Baiyun/internal/art"
)

func main() {
	dir := "resources"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	p := filepath.Join(dir, "icon.png")
	if err := os.WriteFile(p, art.AppIcon(), 0o644); err != nil {
		panic(err)
	}
	println("wrote", p)
}
