package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUninstallDataDirsRespectXDG(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	dirs := uninstallDataDirs()
	want := []string{
		filepath.Join(tmp, "cfg", "denyout"),
		filepath.Join(tmp, "state", "denyout"),
		filepath.Join(tmp, "data", "denyout"),
		filepath.Join(tmp, "cache", "denyout"),
	}
	if len(dirs) != len(want) {
		t.Fatalf("got %v want %v", dirs, want)
	}
	for i := range want {
		if dirs[i] != want[i] {
			t.Fatalf("dirs[%d]=%q want %q", i, dirs[i], want[i])
		}
	}
}

func TestUninstallKeepConfigLeavesDirs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("DENYOUT_INSTALL_DIR", filepath.Join(tmp, "bin"))
	cfg := filepath.Join(tmp, "cfg", "denyout")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "desktop.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "denyout")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// KeepConfig: should not remove cfg; ElevateTeardown may warn without admin.
	if err := Uninstall(UninstallOptions{KeepConfig: true, Yes: true, SkipElevate: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg, "desktop.json")); err != nil {
		t.Fatalf("config should remain: %v", err)
	}
	if _, err := os.Stat(bin); !os.IsNotExist(err) {
		t.Fatalf("binary should be removed, err=%v", err)
	}
}

func TestUninstallRemovesConfigDirs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(tmp, "data"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
	t.Setenv("DENYOUT_INSTALL_DIR", filepath.Join(tmp, "bin"))
	cfg := filepath.Join(tmp, "cfg", "denyout")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "desktop.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(UninstallOptions{Yes: true, SkipElevate: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("config dir should be gone, err=%v", err)
	}
}
