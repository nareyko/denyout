#!/usr/bin/env bash
# Anti-AI / symbol hygiene for product copy: docs + desktop UI + notify strings.
# Site gates live in sibling denyout-web (scripts/check-site.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PH="${PROSE_HYGIENE:-$HOME/projects/prose-hygiene/bin/prose-hygiene.mjs}"
if [[ ! -f "$PH" ]]; then
  if [[ -n "${CI:-}" ]]; then
    git clone --depth 1 https://github.com/nareyko/prose-hygiene.git /tmp/prose-hygiene
    PH=/tmp/prose-hygiene/bin/prose-hygiene.mjs
  else
    echo "prose-hygiene missing at $PH (clone ~/projects/prose-hygiene)" >&2
    exit 1
  fi
fi

echo "== typography: docs =="
node "$PH" typography --check --strict --ext=.md docs README.md SECURITY.md CHANGELOG.md

echo "== typography: desktop Go UI =="
node "$PH" typography --check --strict --ext=.go internal/desktop internal/notify

echo "== typography: Wails frontend + static =="
node "$PH" typography --check --strict --ext=.tsx,.ts,.html \
  cmd/denyout-desktop/frontend/src \
  cmd/denyout-desktop/frontend/index.html \
  internal/desktop/static

echo "== prose-hygiene patterns (docs blockers) =="
node "$PH" check --fail-on=blocker --ext=.md docs README.md SECURITY.md

if command -v uvx >/dev/null 2>&1; then
  echo "== lexaudit (docs; detection) =="
  uvx lexaudit audit --path docs --locale en --check || true
else
  echo "uvx not found; skip lexaudit"
fi

echo "OK: product copy gates passed"
