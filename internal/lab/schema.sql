-- DenyOut lab fixture schema (MVP stub).
-- cases: normative URL / SSRF / allow scenarios
-- runs: one execution of a suite
-- results: per-case outcome for a run

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    id            TEXT PRIMARY KEY,
    suite         TEXT NOT NULL,
    url           TEXT NOT NULL,
    mode          TEXT NOT NULL DEFAULT 'enforce',
    preset        TEXT NOT NULL DEFAULT 'models',
    expect_verdict TEXT NOT NULL,
    expect_reasons TEXT, -- JSON array of acceptable reason codes (any match)
    active        INTEGER NOT NULL DEFAULT 1,
    note          TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id         TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    label      TEXT,
    git_sha    TEXT,
    ok         INTEGER
);

CREATE TABLE IF NOT EXISTS results (
    run_id     TEXT NOT NULL REFERENCES runs(id),
    case_id    TEXT NOT NULL REFERENCES cases(id),
    verdict    TEXT NOT NULL,
    reasons    TEXT, -- JSON array
    passed     INTEGER NOT NULL,
    detail     TEXT,
    PRIMARY KEY (run_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_cases_suite_active ON cases(suite, active);
