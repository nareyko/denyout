package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/nareyko/denyout/internal/lab"
)

const (
	labDefaultDB       = "examples/fixtures/denyout-lab.sqlite"
	labDefaultCorpusDB = "examples/fixtures/denyout-lab-corpus.sqlite"
)

const labTestUsage = `Usage: denyout-cli test [--db path] [--suite name] [--corpus-jsonl path]... [--quiet] [--metrics]
  Seeds the lab DB if needed, runs active fixtures (no network dial).
  --corpus-jsonl  import external JSONL cases (Prowl / egress-bench) before run
  --quiet         print summary only (needed for large corpora)
  --metrics       print TP/FP/TN/FN precision/recall (deny = positive class)`

type labTestOpts struct {
	dbPath  string
	suite   string
	quiet   bool
	metrics bool
	corpus  []string
}

// parseLabTestArgs parses `test` flags (pure).
func parseLabTestArgs(args []string) (labTestOpts, *cliExit) {
	o := labTestOpts{dbPath: labDefaultDB}
	fs := flagSet{
		cmd:  "test",
		help: labTestUsage,
		values: []flagSpec{
			{names: []string{"--db"}, eq: true, set: setStr(&o.dbPath), missing: "--db requires a path"},
			{names: []string{"--suite"}, eq: true, set: setStr(&o.suite), missing: "--suite requires a name"},
			{names: []string{"--corpus-jsonl"}, eq: true, missing: "--corpus-jsonl requires a path", set: func(v string) string {
				o.corpus = append(o.corpus, v)
				return ""
			}},
		},
		bools: map[string]func(){
			"--quiet":   func() { o.quiet = true },
			"--metrics": func() { o.metrics = true },
		},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	if len(o.corpus) > 0 && o.dbPath == labDefaultDB {
		o.dbPath = labDefaultCorpusDB
	}
	return o, nil
}

// openLabDB opens the lab DB, importing any external corpora first.
func openLabDB(o labTestOpts) (*sql.DB, *cliExit) {
	if len(o.corpus) == 0 {
		db, err := lab.OpenSeeded(o.dbPath)
		if err != nil {
			return nil, failExit("denyout-cli test: %v", err)
		}
		return db, nil
	}
	db, err := lab.Open(o.dbPath)
	if err != nil {
		return nil, failExit("denyout-cli test: %v", err)
	}
	for _, p := range o.corpus {
		n, err := lab.SeedJSONL(db, p)
		if err != nil {
			_ = db.Close()
			return nil, failExit("denyout-cli test: import %s: %v", p, err)
		}
		fmt.Fprintf(os.Stderr, "denyout-cli test: imported %d cases from %s\n", n, p)
	}
	return db, nil
}

// checkLabSuite enforces the M1 minimum for the r20_url suite.
func checkLabSuite(db *sql.DB, suite string) *cliExit {
	if suite != "r20_url" {
		return nil
	}
	n, err := lab.CountActive(db, "r20_url")
	if err != nil {
		return failExit("denyout-cli test: %v", err)
	}
	if n < 20 {
		return failExit("denyout-cli test: r20_url active=%d want >=20 (M1)", n)
	}
	return nil
}

// formatLabReport renders per-case lines (unless quiet), the summary and the
// optional metrics line.
func formatLabReport(o labTestOpts, rep *lab.RunReport) string {
	var b strings.Builder
	if !o.quiet {
		for _, r := range rep.Results {
			status := "PASS"
			if !r.Passed {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "%s %s suite=%s verdict=%s reasons=%v %s\n", status, r.CaseID, r.Suite, r.Verdict, r.Reasons, r.Detail)
		}
	}
	fmt.Fprintf(&b, "summary run_id=%s passed=%d failed=%d total=%d db=%s\n", rep.RunID, rep.Passed, rep.Failed, rep.Total, o.dbPath)
	if o.metrics || len(o.corpus) > 0 {
		m := lab.MetricsFromResults(rep.Results)
		fmt.Fprintf(&b, "metrics tp=%d fp=%d tn=%d fn=%d precision=%.4f recall=%.4f specificity=%.4f\n",
			m.TP, m.FP, m.TN, m.FN, m.Precision(), m.Recall(), m.Specificity())
	}
	return b.String()
}

// labExitCode: large external corpora are yardsticks (metrics), not hard CI
// gates; otherwise any failed case fails the run.
func labExitCode(o labTestOpts, failed int) int {
	if len(o.corpus) > 0 || failed == 0 {
		return 0
	}
	return 1
}

func runLabTest(o labTestOpts) *cliExit {
	db, ex := openLabDB(o)
	if ex != nil {
		return ex
	}
	defer db.Close()
	if ex := checkLabSuite(db, o.suite); ex != nil {
		return ex
	}
	rep, err := lab.RunDB(db, lab.RunOptions{Suite: o.suite, Label: "cli"})
	if err != nil {
		return failExit("denyout-cli test: %v", err)
	}
	return &cliExit{code: labExitCode(o, rep.Failed), out: formatLabReport(o, rep)}
}

func cmdTest(args []string) int {
	o, ex := parseLabTestArgs(args)
	if ex != nil {
		return ex.emit()
	}
	return runLabTest(o).emit()
}
