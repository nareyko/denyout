package desktop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsDenyoutDesktopOrProxyd(t *testing.T) {
	cases := []struct {
		args string
		want bool
	}{
		{"/home/u/.local/bin/denyout desktop", true},
		{"denyout desktop", true},
		{"denyout desktop --install", true},
		{"/home/u/.local/bin/denyout-desktop", true},
		{"denyout-desktop", true},
		{"/opt/DenyOut/denyout-desktop --flag", true},
		{"/home/u/.local/bin/denyout hostctl proxyd --port 1", true},
		{"denyout hostctl proxyd", true},
		{"/home/u/.local/bin/denyout install", false},
		{"/home/u/.local/bin/denyout version", false},
		{"/usr/bin/something else desktop", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isDenyoutDesktopOrProxyd(tc.args); got != tc.want {
			t.Errorf("isDenyoutDesktopOrProxyd(%q)=%v want %v", tc.args, got, tc.want)
		}
	}
}

func TestMatchDenyoutPIDsSkipsSelf(t *testing.T) {
	ps := "  1 /sbin/init\n  42 /home/u/.local/bin/denyout-desktop\n  99 /home/u/.local/bin/denyout desktop\n"
	got := matchDenyoutPIDs(ps, 42)
	if len(got) != 1 || got[0] != 99 {
		t.Fatalf("matchDenyoutPIDs=%v want [99]", got)
	}
}

func TestWarnStaleBinariesOnPATH(t *testing.T) {
	tmp := t.TempDir()
	install := filepath.Join(tmp, "install")
	other := filepath.Join(tmp, "other")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(other, "denyout")
	if err := os.WriteFile(stale, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(install, "denyout")
	if err := os.WriteFile(fresh, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", other+string(os.PathListSeparator)+install)
	// Should not panic; prints to stderr.
	WarnStaleBinariesOnPATH(install)
}

func TestDefaultInstallDirEnv(t *testing.T) {
	t.Setenv("DENYOUT_INSTALL_DIR", "/tmp/denyout-install-qa")
	if got := DefaultInstallDir(); got != "/tmp/denyout-install-qa" {
		t.Fatalf("got %q", got)
	}
}

func TestQuitUnloadClearsLeaveOnWithoutElevate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	st := DefaultState()
	st.Scope = ScopeSession
	st.ProtectionOn = true
	st.ComputerEnabled = false
	a := &App{state: st, status: "Session"}
	a.quitUnload()
	if a.state.ProtectionOn || a.state.ComputerEnabled {
		t.Fatalf("leave-on not cleared: protection=%v computer=%v", a.state.ProtectionOn, a.state.ComputerEnabled)
	}
	if a.status != "Off" {
		t.Fatalf("status=%q", a.status)
	}
}

func FuzzIsDenyoutDesktopOrProxyd(f *testing.F) {
	for _, s := range []string{
		"",
		"denyout desktop",
		"denyout desktop --install",
		"denyout-desktop",
		"/usr/local/bin/denyout hostctl proxyd",
		"denyout version",
		"not-denyout desktop",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		_ = isDenyoutDesktopOrProxyd(args)
	})
}

func BenchmarkIsDenyoutDesktopOrProxyd(b *testing.B) {
	args := "/home/u/.local/bin/denyout desktop --install"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isDenyoutDesktopOrProxyd(args) {
			b.Fatal("expected match")
		}
	}
}
