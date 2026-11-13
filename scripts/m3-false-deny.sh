#!/usr/bin/env bash
# M3: model-only false-deny ≤ 1/10 scripted runs need an allowlist edit.
# Uses denyout check (no dial). A false-deny is verdict=deny with host_not_allowed
# (or any deny on these clean model URLs — they should never need allowlist edits).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DENYOUT_BIN:-$ROOT/bin/denyout}"
URLS="${M3_URLS:-$ROOT/examples/m3/urls.txt}"
MAX_FALSE="${M3_MAX_FALSE:-1}"
CONFIG="${DENYOUT_CONFIG:-}"

if [[ ! -x "$BIN" ]]; then
  echo "m3: building denyout → $BIN" >&2
  (cd "$ROOT" && go build -ldflags "-X main.version=dev" -o "$BIN" ./cmd/denyout)
fi

if [[ ! -f "$URLS" ]]; then
  echo "m3: missing URL list: $URLS" >&2
  exit 2
fi

mapfile -t LINES < <(grep -vE '^\s*(#|$)' "$URLS" || true)
if ((${#LINES[@]} != 10)); then
  echo "m3: want exactly 10 URLs, got ${#LINES[@]} in $URLS" >&2
  exit 2
fi

false_deny=0
pass=0
i=0
declare -a FAILS=()

for url in "${LINES[@]}"; do
  i=$((i + 1))
  check_args=(check)
  if [[ -n "$CONFIG" ]]; then
    check_args+=(--config "$CONFIG")
  fi
  check_args+=(--json "$url")

  out="$("$BIN" "${check_args[@]}" 2>/dev/null || true)"
  verdict="$(printf '%s' "$out" | sed -n 's/.*"verdict"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  reasons="$(printf '%s' "$out" | sed -n 's/.*"reasons"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | head -1)"

  if [[ "$verdict" == "allow" ]]; then
    pass=$((pass + 1))
    printf 'PASS %02d allow %s\n' "$i" "$url"
  else
    # Clean model-host URLs must allow; any deny means allowlist (or policy) edit needed.
    false_deny=$((false_deny + 1))
    FAILS+=("$i|$verdict|$reasons|$url")
    printf 'FAIL %02d verdict=%s reasons=[%s] %s\n' "$i" "${verdict:-?}" "${reasons:-}" "$url"
  fi
done

echo "summary m3 false_deny=${false_deny}/10 pass=${pass}/10 max_allowed=${MAX_FALSE}"
if ((false_deny > MAX_FALSE)); then
  echo "m3: FAIL — false-deny ${false_deny}/10 exceeds ${MAX_FALSE}/10 (M3)" >&2
  for f in "${FAILS[@]}"; do
    echo "  $f" >&2
  done
  exit 1
fi
echo "m3: OK — within M3 budget (≤${MAX_FALSE}/10 need allowlist edit)"
exit 0
