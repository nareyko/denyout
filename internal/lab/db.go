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

// SeedCanary keeps the original single-canary helper for older tests.
func SeedCanary(db *sql.DB) error {
	return SeedAll(db)
}

// ActiveCanaryURL returns the primary R-20 canary URL.
func ActiveCanaryURL(db *sql.DB) (string, error) {
	var u string
	err := db.QueryRow(`SELECT url FROM cases WHERE id = ? AND active = 1`, "r20-01-canary-query").Scan(&u)
	if err != nil {
		return "", err
	}
	return u, nil
}
