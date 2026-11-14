#!/usr/bin/env bash
# Anti-AI / symbol hygiene for product copy: docs + desktop UI + notify strings.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PH="${PROSE_HYGIENE:-$HOME/projects/prose-hygiene/bin/prose-hygiene.mjs}"
if [[ ! -f "$PH" ]]; then
  if [[ -n "${CI:-}" ]]; then
    # Optional CI clone of prose-hygiene; soft-skip if unavailable.
    clone_url="https://github.com/nareyko/prose-hygiene.git"
    if [[ -n "${PROSE_HYGIENE_TOKEN:-}" ]]; then
      clone_url="https://x-access-token:${PROSE_HYGIENE_TOKEN}@github.com/nareyko/prose-hygiene.git"
    fi
    if ! git clone --depth 1 "$clone_url" /tmp/prose-hygiene 2>/tmp/ph-clone.err; then
      echo "WARN: prose-hygiene clone failed. Skip copy-hygiene in CI." >&2
      cat /tmp/ph-clone.err >&2 || true
      echo "Set secret PROSE_HYGIENE_TOKEN (read access) if the tool is not public." >&2
      exit 0
    fi
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

echo "== semicolon scan (docs + README; report) =="
set +e
SEMI=$(node "$PH" check --ext=.md docs README.md SECURITY.md CHANGELOG.md 2>&1 | grep -c 'semicolon-density' || true)
set -e
echo "semicolon-density hits: ${SEMI:-0} (fix stacked ';' in English to periods)"

if command -v uvx >/dev/null 2>&1; then
  echo "== lexaudit (docs, detection) =="
  uvx lexaudit audit --path docs --locale en --check || true
else
  echo "uvx not found; skip lexaudit"
fi

echo "OK: product copy gates passed"
