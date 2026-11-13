package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/policy"
)

func TestLoadExampleEnforceModels(t *testing.T) {
	root := findRepoRoot(t)
	path := filepath.Join(root, "examples", "policies", "denyout.enforce.models.yaml")
	cfg, err := policy.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Mode != "enforce" {
		t.Fatalf("mode=%s", cfg.Mode)
	}
	if cfg.Preset != "models" {
		t.Fatalf("preset=%s", cfg.Preset)
	}
	if len(cfg.Allow) == 0 {
		t.Fatal("expected preset hosts merged into allow")
	}
}

func TestLoadRejectsBadAPIVersion(t *testing.T) {
	_, err := policy.LoadBytes([]byte(`
apiVersion: denyout/v0
kind: Config
mode: enforce
`))
	if err == nil {
		t.Fatal("expected schema error")
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 6; i++ {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}
