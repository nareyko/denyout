package lab

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

func schemaSQL() (string, error) {
	b, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Open opens (or creates) a SQLite lab DB and applies schema.
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	sqlText, err := schemaSQL()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(sqlText); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return db, nil
}

// SeedCanary inserts the minimum active canary case (idempotent).
func SeedCanary(db *sql.DB) error {
	_, err := db.Exec(`
INSERT INTO cases (id, suite, url, mode, preset, expect_verdict, expect_reasons, active, note)
VALUES (
  'canary-r20-lab',
  'r20_url',
  'https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB',
  'enforce',
  'models',
  'deny',
  '["canary_detected","secret_in_url","host_not_allowed"]',
  1,
  'W3 seed — R-20 style secret URL canary'
)
ON CONFLICT(id) DO UPDATE SET
  url=excluded.url,
  expect_verdict=excluded.expect_verdict,
  expect_reasons=excluded.expect_reasons,
  active=1
`)
	return err
}

// OpenSeeded opens path and ensures the canary seed exists.
func OpenSeeded(path string) (*sql.DB, error) {
	db, err := Open(path)
	if err != nil {
		return nil, err
	}
	if err := SeedCanary(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// ActiveCanaryURL returns the seed canary URL or error if missing.
func ActiveCanaryURL(db *sql.DB) (string, error) {
	var u string
	err := db.QueryRow(`SELECT url FROM cases WHERE id = ? AND active = 1`, "canary-r20-lab").Scan(&u)
	if err != nil {
		return "", err
	}
	return u, nil
}
