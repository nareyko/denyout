package lab_test

import (
	"path/filepath"
	"testing"

	"github.com/nareyko/denyout/internal/lab"
)

func TestSeedAtLeast20R20AndFullRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab.sqlite")
	db, err := lab.OpenSeeded(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	n, err := lab.CountActive(db, "r20_url")
	if err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("r20_url active=%d want >=20", n)
	}

	rep, err := lab.RunDB(db, lab.RunOptions{Suite: "r20_url", Label: "m1"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed != 0 {
		for _, r := range rep.Results {
			if !r.Passed {
				t.Logf("FAIL %s verdict=%s reasons=%v detail=%s", r.CaseID, r.Verdict, r.Reasons, r.Detail)
			}
		}
		t.Fatalf("r20_url failed=%d/%d", rep.Failed, rep.Total)
	}
	if rep.Passed < 20 {
		t.Fatalf("passed=%d", rep.Passed)
	}
}

func TestFullLabRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab.sqlite")
	db, err := lab.OpenSeeded(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rep, err := lab.RunDB(db, lab.RunOptions{Label: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed != 0 {
		for _, r := range rep.Results {
			if !r.Passed {
				t.Errorf("%s: %s", r.CaseID, r.Detail)
			}
		}
	}
}
