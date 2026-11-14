package lab

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nareyko/denyout/internal/policy"
	"github.com/nareyko/denyout/internal/secrets"
)

// RunOptions configures a lab run.
type RunOptions struct {
	Suite string // empty = all active
	Label string
}

// CaseResult is one evaluated fixture.
type CaseResult struct {
	CaseID    string
	Suite     string
	URL       string
	Verdict   string
	Reasons   []string
	Expect    string
	Passed    bool
	Detail    string
	WouldDeny bool
}

// RunReport summarizes a lab execution.
type RunReport struct {
	RunID   string
	Passed  int
	Failed  int
	Total   int
	Results []CaseResult
}

type caseRow struct {
	id, suite, rawURL, mode, preset, expectVerdict, expectReasonsJSON string
}

// RunDB evaluates active cases with the policy engine (no network dial).
func RunDB(db *sql.DB, opts RunOptions) (*RunReport, error) {
	_, _ = db.Exec(`PRAGMA busy_timeout = 5000`)

	q := `SELECT id, suite, url, mode, preset, expect_verdict, expect_reasons FROM cases WHERE active = 1`
	args := []any{}
	if opts.Suite != "" {
		q += ` AND suite = ?`
		args = append(args, opts.Suite)
	}
	q += ` ORDER BY suite, id`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	var cases []caseRow
	for rows.Next() {
		var c caseRow
		if err := rows.Scan(&c.id, &c.suite, &c.rawURL, &c.mode, &c.preset, &c.expectVerdict, &c.expectReasonsJSON); err != nil {
			_ = rows.Close()
			return nil, err
		}
		cases = append(cases, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	runID := uuid.NewString()
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO runs (id, started_at, label, ok) VALUES (?, ?, ?, NULL)`, runID, started, opts.Label); err != nil {
		return nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rep := &RunReport{RunID: runID}
	cfgCache := map[string]*policy.Config{}
	for _, c := range cases {
		var expectReasons []string
		if c.expectReasonsJSON != "" && c.expectReasonsJSON != "null" {
			_ = json.Unmarshal([]byte(c.expectReasonsJSON), &expectReasons)
		}

		ckey := c.mode + "|" + c.preset
		cfg, ok := cfgCache[ckey]
		if !ok {
			var err error
			cfg, err = configFor(c.mode, c.preset)
			if err != nil {
				cr := CaseResult{CaseID: c.id, Suite: c.suite, URL: secrets.RedactURL(c.rawURL), Passed: false, Detail: err.Error(), Expect: c.expectVerdict}
				rep.Results = append(rep.Results, cr)
				rep.Failed++
				rep.Total++
				_ = insertResultTx(tx, runID, cr)
				continue
			}
			cfgCache[ckey] = cfg
		}

		d, err := policy.EvaluateURL(cfg, c.rawURL)
		if err != nil {
			cr := CaseResult{CaseID: c.id, Suite: c.suite, URL: secrets.RedactURL(c.rawURL), Passed: false, Detail: err.Error(), Expect: c.expectVerdict}
			rep.Results = append(rep.Results, cr)
			rep.Failed++
			rep.Total++
			_ = insertResultTx(tx, runID, cr)
			continue
		}

		cr := CaseResult{
			CaseID:    c.id,
			Suite:     c.suite,
			URL:       secrets.RedactURL(c.rawURL),
			Verdict:   d.Verdict,
			Reasons:   d.Reasons,
			Expect:    c.expectVerdict,
			WouldDeny: d.WouldDeny,
		}
		cr.Passed, cr.Detail = matchExpectation(c.expectVerdict, expectReasons, d)
		rep.Results = append(rep.Results, cr)
		rep.Total++
		if cr.Passed {
			rep.Passed++
		} else {
			rep.Failed++
		}
		_ = insertResultTx(tx, runID, cr)
	}

	okFlag := 0
	if rep.Failed == 0 {
		okFlag = 1
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`UPDATE runs SET finished_at = ?, ok = ? WHERE id = ?`, finished, okFlag, runID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return rep, nil
}

func matchExpectation(expectVerdict string, expectReasons []string, d policy.Decision) (bool, string) {
	if d.Verdict != expectVerdict {
		// AT-06 style: audit allow with would_deny still records host_not_allowed in reasons.
		if expectVerdict == "allow" && d.Verdict == "allow" && d.WouldDeny && containsAny(d.Reasons, expectReasons) {
			return true, "allow+would_deny"
		}
		return false, fmt.Sprintf("verdict got=%s want=%s reasons=%v", d.Verdict, expectVerdict, d.Reasons)
	}
	if len(expectReasons) == 0 {
		return true, "ok"
	}
	if containsAny(d.Reasons, expectReasons) {
		return true, "ok"
	}
	// Audit allow cases may only carry would-deny reasons when ExpectVerdict is allow.
	if expectVerdict == "allow" && d.WouldDeny && containsAny(d.Reasons, expectReasons) {
		return true, "allow+would_deny"
	}
	return false, fmt.Sprintf("reasons %v none of %v", d.Reasons, expectReasons)
}

func containsAny(have, want []string) bool {
	set := map[string]struct{}{}
	for _, h := range have {
		set[h] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; ok {
			return true
		}
	}
	return false
}

func insertResult(db *sql.DB, runID string, cr CaseResult) error {
	return insertResultTx(db, runID, cr)
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertResultTx(db execer, runID string, cr CaseResult) error {
	reasons, _ := json.Marshal(cr.Reasons)
	passed := 0
	if cr.Passed {
		passed = 1
	}
	_, err := db.Exec(`INSERT INTO results (run_id, case_id, verdict, reasons, passed, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		runID, cr.CaseID, cr.Verdict, string(reasons), passed, cr.Detail)
	return err
}

func configFor(mode, preset string) (*policy.Config, error) {
	if mode == "" {
		mode = "enforce"
	}
	if preset == "" {
		preset = "models"
	}
	denyBlock := "deny: []"
	if mode == "blocklist" {
		// Explicit deny hosts matter only when the web is otherwise allowed.
		denyBlock = "deny:\n  - host: pastebin.com"
	}
	yaml := fmt.Sprintf(`
apiVersion: denyout/v1
kind: Config
mode: %s
preset: %s
allow_private: false
allow_ip_literals: false
allowed_ports: [443, 80]
%s
scanners:
  hard_secrets_in_audit_mode: true
  min_value_len: 6
  named_query:
    enabled: true
  high_entropy:
    enabled: false
  canaries:
    - "DENYOUT_CANARY_"
    - "ARVISER_CANARY_"
    - "SECRET_MARKER_"
`, mode, preset, denyBlock)
	return policy.LoadBytes([]byte(strings.TrimSpace(yaml) + "\n"))
}
