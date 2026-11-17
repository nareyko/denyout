#!/usr/bin/env bash
# Discover every Fuzz* target under internal/ and cmd/ and run each for a bounded time.
# Usage: scripts/fuzz-all.sh [fuzztime]   (default 60s; FUZZ_LIST=1 only lists targets)
# Crashers stay in <pkg>/testdata/fuzz/<Target>/ (go test writes them there).
# Host-safe: fuzz targets are pure functions; run in CI or Docker, never needs root.
set -uo pipefail
FUZZTIME="${1:-60s}"
cd "$(dirname "$0")/.."
targets=$(grep -rn --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]+\(f \*testing\.F\)' internal cmd |
  sed -E 's#^([^:]+)/[^/:]+:[0-9]+:func (Fuzz[A-Za-z0-9_]+)\(.*#\1 \2#' | sort -u)
if [ -z "$targets" ]; then echo "no fuzz targets found" >&2; exit 2; fi
if [ "${FUZZ_LIST:-}" = 1 ]; then echo "$targets"; exit 0; fi
fail=0
while read -r dir name; do
  echo "== ./$dir $name ($FUZZTIME)"
  if ! go test "./$dir" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME"; then
    echo "FAIL: $dir $name" >&2
    fail=1
  fi
done <<<"$targets"
exit $fail
