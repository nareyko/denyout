package hostguard_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
)

func TestResolveCLIExe_DesktopUsesSibling(t *testing.T) {
	dir := t.TempDir()
	cliName := "denyout"
	deskName := "denyout-desktop"
	if runtime.GOOS == "windows" {
		cliName += ".exe"
		deskName += ".exe"
	}
	cli := filepath.Join(dir, cliName)
	desk := filepath.Join(dir, deskName)
	if err := os.WriteFile(cli, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(desk, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := hostguard.ResolveCLIExe(desk)
	if err != nil {
		t.Fatal(err)
	}
	if got != cli {
		t.Fatalf("got %q want %q", got, cli)
	}
}

func TestResolveCLIExe_PlainDenyout(t *testing.T) {
	p := "/usr/bin/denyout"
	got, err := hostguard.ResolveCLIExe(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got %q", got)
	}
}
