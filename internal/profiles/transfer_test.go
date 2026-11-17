package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nareyko/denyout/internal/appdata"
)

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodProfile = `id: from-file-ignored
name: Imported
command: [claude, --flag]
preset: agent
extra_allow: [api.example.com, "*.cursor.sh"]
ask_mode: true
learning: {enabled: false}
`

func TestExportImportRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, err := ImportProfile("mine", writeTmp(t, goodProfile), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "mine" {
		t.Errorf("file id must be ignored, got %q", p.ID)
	}
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := ExportProfile("mine", out); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
		t.Errorf("export perms %v", fi.Mode())
	}
	q, err := ImportProfile("copy", out, false)
	if err != nil || q.ID != "copy" || len(q.ExtraAllow) != 2 {
		t.Fatalf("re-import: %v %+v", err, q)
	}
	if _, err := ImportProfile("copy", out, false); err == nil {
		t.Error("existing profile must not be replaced without force")
	}
	if _, err := ImportProfile("copy", out, true); err != nil {
		t.Errorf("force: %v", err)
	}
}

func TestImportIDCannotEscape(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := writeTmp(t, goodProfile)
	for _, id := range []string{"../evil", "a/b", "..", "", "x\x00y", strings.Repeat("a", 65)} {
		if _, err := ImportProfile(id, f, true); err == nil {
			t.Errorf("id %q accepted", id)
		}
		if err := ExportProfile(id, filepath.Join(t.TempDir(), "o")); err == nil {
			t.Errorf("export id %q accepted", id)
		}
	}
	ents, _ := os.ReadDir(appdata.ProfilesDir())
	if len(ents) != 0 {
		t.Errorf("nothing should have been written: %v", ents)
	}
}

func TestImportRejectsScannerWeakening(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	bad := map[string]string{
		"passthrough": "name: x\ncommand: [a]\ntls_mode: passthrough\n",
		"preset none": "name: x\ncommand: [a]\npreset: none\n",
		"sandbox":     "name: x\ncommand: [a]\nsandbox: custom\n",
		"wildcard":    "name: x\ncommand: [a]\nextra_allow: ['*']\n",
		"tld wild":    "name: x\ncommand: [a]\nextra_allow: ['*.com']\n",
		"ip":          "name: x\ncommand: [a]\nextra_allow: ['10.0.0.1']\n",
		"url":         "name: x\ncommand: [a]\nextra_allow: ['https://a.example.com/x']\n",
		"no command":  "name: x\n",
		"unknown key": "name: x\ncommand: [a]\nscanners_off: true\n",
		"pack host":   "name: x\ncommand: [a]\napplied_packs: [{id: p, version: 1, hosts: ['*']}]\n",
	}
	for name, body := range bad {
		if _, err := ImportProfile("t", writeTmp(t, body), true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(profilePath("t")); err == nil {
		t.Error("rejected import left a file behind")
	}
}

func TestImportRejectsHugeAndNonRegular(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	big := writeTmp(t, "name: x\ncommand: [a]\n#"+strings.Repeat("x", MaxImportBytes))
	if _, err := ImportProfile("big", big, true); err == nil {
		t.Error("oversized import accepted")
	}
	if _, err := ImportProfile("dir", t.TempDir(), true); err == nil {
		t.Error("directory accepted")
	}
}
