//go:build !wails

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprint(os.Stderr, `denyout-desktop: build with Wails + CGO

  # Linux (Ubuntu 24.04+):
  sudo apt-get install -y libgtk-3-dev libwebkit2gtk-4.1-dev
  cd cmd/denyout-desktop/frontend && npm ci && npm run build && cd ../../..
  CGO_ENABLED=1 go build -tags 'wails,production,webkit2_41' -o denyout-desktop ./cmd/denyout-desktop

  # Or from repo root: wails build -tags webkit2_41
  # (wails build adds production; plain go build must include production)

CLI/proxy remains: denyout (static, CGO_ENABLED=0).
`)
	os.Exit(2)
}
