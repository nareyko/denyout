package lab_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/lab"
)

func TestSeedJSONLAndMetrics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.jsonl")
	body := `{"id":"c1","suite":"t","url":"https://api.anthropic.com/x?api_key=sk-denyouttest000000000000000","mode":"enforce","preset":"models","expect_verdict":"deny"}
{"id":"c2","suite":"t","url":"https://api.anthropic.com/","mode":"enforce","preset":"models","expect_verdict":"allow"}
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := lab.Open(filepath.Join(dir, "lab.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	n, err := lab.SeedJSONL(db, path)
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	rep, err := lab.RunDB(db, lab.RunOptions{Suite: "t"})
	if err != nil {
		t.Fatal(err)
	}
	m := lab.MetricsFromResults(rep.Results)
	if m.TP < 1 || m.TN < 1 {
		t.Fatalf("metrics=%+v results=%+v", m, rep.Results)
	}
}
