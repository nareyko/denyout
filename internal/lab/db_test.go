package lab_test

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/lab"
	"github.com/nareyko/denyout/internal/policy"
)

func TestSeedCanaryAndCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denyout-lab.sqlite")
	db, err := lab.OpenSeeded(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	url, err := lab.ActiveCanaryURL(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.DefaultEnforceModels()
	if err != nil {
		t.Fatal(err)
	}
	res, err := check.URL(cfg, url)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != check.VerdictDeny {
		t.Fatalf("expected deny, got %s (%v)", res.Verdict, res.Reasons)
	}
}
