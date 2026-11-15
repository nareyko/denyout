package hostguard_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nareyko/denyout/internal/hostguard"
)

func TestResolveCLIExe_GUIUsesSiblingCLI(t *testing.T) {
	dir := t.TempDir()
	cliName := "denyout-cli"
	guiName := "denyout"
	if runtime.GOOS == "windows" {
		cliName += ".exe"
		guiName += ".exe"
	}
	cli := filepath.Join(dir, cliName)
	gui := filepath.Join(dir, guiName)
	if err := os.WriteFile(cli, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gui, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := hostguard.ResolveCLIExe(gui)
	if err != nil {
		t.Fatal(err)
	}
	if got != cli {
		t.Fatalf("got %q want %q", got, cli)
	}
}

func TestResolveCLIExe_PlainCLI(t *testing.T) {
	p := "/usr/bin/denyout-cli"
	got, err := hostguard.ResolveCLIExe(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("got %q", got)
	}
}
