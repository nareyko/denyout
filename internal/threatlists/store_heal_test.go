package threatlists

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSelfHealsCorruptStatus(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil || s == nil {
		t.Fatalf("Open must survive corrupt status.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "status.json.corrupt")); err != nil {
		t.Error("corrupt status should be quarantined")
	}
}
