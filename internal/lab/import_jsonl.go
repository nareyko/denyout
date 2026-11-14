package lab

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// JSONLCase is one external corpus fixture line.
type JSONLCase struct {
	ID             string   `json:"id"`
	Suite          string   `json:"suite"`
	URL            string   `json:"url"`
	Mode           string   `json:"mode"`
	Preset         string   `json:"preset"`
	ExpectVerdict  string   `json:"expect_verdict"`
	ExpectReasons  []string `json:"expect_reasons"`
	Note           string   `json:"note"`
}

// SeedJSONL upserts cases from a JSONL file. Returns number of rows processed.
func SeedJSONL(db *sql.DB, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
INSERT INTO cases (id, suite, url, mode, preset, expect_verdict, expect_reasons, active, note)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
ON CONFLICT(id) DO UPDATE SET
  suite=excluded.suite,
  url=excluded.url,
  mode=excluded.mode,
  preset=excluded.preset,
  expect_verdict=excluded.expect_verdict,
  expect_reasons=excluded.expect_reasons,
  active=1,
  note=excluded.note
`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	sc := bufio.NewScanner(f)
	// large probe URLs
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 4*1024*1024)

	n := 0
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var c JSONLCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return n, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if c.ID == "" || c.URL == "" || c.ExpectVerdict == "" {
			return n, fmt.Errorf("%s:%d: id/url/expect_verdict required", path, lineNo)
		}
		if c.Suite == "" {
			c.Suite = "external"
		}
		if c.Mode == "" {
			c.Mode = "enforce"
		}
		if c.Preset == "" {
			c.Preset = "models"
		}
		reasons, err := json.Marshal(c.ExpectReasons)
		if err != nil {
			return n, err
		}
		if _, err := stmt.Exec(c.ID, c.Suite, c.URL, c.Mode, c.Preset, c.ExpectVerdict, string(reasons), c.Note); err != nil {
			return n, fmt.Errorf("%s:%d id=%s: %w", path, lineNo, c.ID, err)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	if err := tx.Commit(); err != nil {
		return n, err
	}
	return n, nil
}

// ClassificationMetrics is a confusion matrix for allow/deny expectations.
type ClassificationMetrics struct {
	TP, FP, TN, FN int
}

func (m ClassificationMetrics) Precision() float64 {
	d := m.TP + m.FP
	if d == 0 {
		return 0
	}
	return float64(m.TP) / float64(d)
}

func (m ClassificationMetrics) Recall() float64 {
	d := m.TP + m.FN
	if d == 0 {
		return 0
	}
	return float64(m.TP) / float64(d)
}

func (m ClassificationMetrics) Specificity() float64 {
	d := m.TN + m.FP
	if d == 0 {
		return 0
	}
	return float64(m.TN) / float64(d)
}

// MetricsFromResults builds TP/FP/TN/FN treating expect deny as positive class.
func MetricsFromResults(results []CaseResult) ClassificationMetrics {
	var m ClassificationMetrics
	for _, r := range results {
		wantDeny := r.Expect == "deny"
		gotDeny := r.Verdict == "deny"
		switch {
		case wantDeny && gotDeny:
			m.TP++
		case !wantDeny && gotDeny:
			m.FP++
		case !wantDeny && !gotDeny:
			m.TN++
		case wantDeny && !gotDeny:
			m.FN++
		}
	}
	return m
}
