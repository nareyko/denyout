#!/usr/bin/env bash
# M3 on a REAL agent CLI: ten runs through `denyout-cli run`; at most one may need an
# allowlist edit (a false deny of a model host), and none may hang.
# scripts/m3-false-deny.sh only calls `denyout check` (no sockets); this one sends real
# traffic through the proxy, the way a user's agent does.
#
#   M3_AGENT='claude -p' scripts/m3-live-agent.sh
#   M3_AGENT='codex exec' M3_TIMEOUT=180 scripts/m3-live-agent.sh
#
# Self-test without an agent (each "prompt" is a URL, the "agent" is curl):
#   M3_AGENT='curl -sS -m 20 -o /dev/null' M3_PROMPTS=examples/m3/urls.txt scripts/m3-live-agent.sh
#
# Env: M3_AGENT (required; prompt is appended as the last argument), M3_PROMPTS (file, default
# examples/m3/live-prompts.txt, exactly 10 lines), M3_TIMEOUT (seconds per run, default 120),
# M3_MAX_FALSE (default 1), DENYOUT_BIN (default: denyout-cli on PATH), M3_UPLOAD=0 to skip the
# >1 MiB upload check, M3_OUT (result markdown file, default ./m3-live-result.md).
# The agent needs its own credentials (its usual env/login); the audit log is kept in a
# throw-away XDG_STATE_HOME, so only these runs are counted.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DENYOUT_BIN:-denyout-cli}"
AGENT="${M3_AGENT:-}"
PROMPTS="${M3_PROMPTS:-$ROOT/examples/m3/live-prompts.txt}"
TMO="${M3_TIMEOUT:-120}"
MAX_FALSE="${M3_MAX_FALSE:-1}"
OUT="${M3_OUT:-./m3-live-result.md}"

[ -n "$AGENT" ] || { echo "m3-live: set M3_AGENT, e.g. M3_AGENT='claude -p'" >&2; exit 2; }
command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || { echo "m3-live: $BIN not found (install denyout-cli or set DENYOUT_BIN)" >&2; exit 2; }
[ -f "$PROMPTS" ] || { echo "m3-live: missing prompts file $PROMPTS" >&2; exit 2; }
mapfile -t LINES < <(grep -vE '^\s*(#|$)' "$PROMPTS" || true)
[ "${#LINES[@]}" -eq 10 ] || { echo "m3-live: want exactly 10 prompts, got ${#LINES[@]} in $PROMPTS" >&2; exit 2; }

TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_CMD="gtimeout"; fi
[ -n "$TIMEOUT_CMD" ] || echo "m3-live: warning: no timeout/gtimeout, a hung run will block (brew install coreutils)" >&2

STATE="$(mktemp -d)"
export XDG_STATE_HOME="$STATE"
AUDIT="$STATE/denyout/audit.jsonl"
trap 'rm -rf "$STATE"' EXIT

# deny events since line $1 of the audit file, as "host reason" pairs.
new_denies() {
  [ -f "$AUDIT" ] || return 0
  tail -n +"$(( $1 + 1 ))" "$AUDIT" | grep -E '"verdict":"(deny|would_deny)"' | while IFS= read -r l; do
    host=$(printf '%s' "$l" | sed -n 's/.*"dest_host":"\([^"]*\)".*/\1/p' | head -1)
    why=$(printf '%s' "$l" | sed -n 's/.*"reasons":\[\([^]]*\)\].*/\1/p' | head -1 | tr -d '"')
    printf '%s(%s)\n' "$host" "$why"
  done
}
audit_lines() { [ -f "$AUDIT" ] && wc -l < "$AUDIT" || echo 0; }

false_runs=0; hangs=0; errs=0; ok=0
rows=""
echo "m3-live: agent=[$AGENT] timeout=${TMO}s prompts=$PROMPTS"
i=0
for p in "${LINES[@]}"; do
  i=$((i + 1))
  before=$(audit_lines)
  t0=$(date +%s)
  # shellcheck disable=SC2086
  if [ -n "$TIMEOUT_CMD" ]; then
    $TIMEOUT_CMD "$TMO" "$BIN" run -- $AGENT "$p" >/tmp/m3-live.$$.out 2>&1; rc=$?
  else
    "$BIN" run -- $AGENT "$p" >/tmp/m3-live.$$.out 2>&1; rc=$?
  fi
  el=$(( $(date +%s) - t0 ))
  denies=$(new_denies "$before" | sort -u | paste -sd, -)
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    status="HANG"; hangs=$((hangs + 1))
  elif [ -n "$denies" ]; then
    status="FALSE-DENY"; false_runs=$((false_runs + 1))
  elif [ "$rc" -ne 0 ]; then
    status="AGENT-ERROR"; errs=$((errs + 1))
  else
    status="OK"; ok=$((ok + 1))
  fi
  printf '%02d %-11s rc=%-3s %3ss denies=[%s] %s\n' "$i" "$status" "$rc" "$el" "$denies" "${p:0:50}"
  [ "$status" = "AGENT-ERROR" ] && sed 's/^/     | /' /tmp/m3-live.$$.out | tail -3
  rows="${rows}| $i | $status | $rc | ${el}s | ${denies:--} | ${p:0:60} |
"
done
rm -f /tmp/m3-live.$$.out

# Upload larger than 1 MiB: curl sends Expect: 100-continue and used to hang through the proxy.
up_status="skipped"
if [ "${M3_UPLOAD:-1}" != 0 ] && command -v curl >/dev/null 2>&1; then
  big="$STATE/big.bin"; head -c $((2 * 1024 * 1024)) /dev/zero | tr '\0' 'x' > "$big"
  t0=$(date +%s)
  if [ -n "$TIMEOUT_CMD" ]; then
    $TIMEOUT_CMD 60 "$BIN" run -- curl -sS -m 45 -o /dev/null -w '%{http_code}' -X POST --data-binary "@$big" https://api.anthropic.com/v1/messages >"$STATE/up.out" 2>&1; urc=$?
  else
    "$BIN" run -- curl -sS -m 45 -o /dev/null -w '%{http_code}' -X POST --data-binary "@$big" https://api.anthropic.com/v1/messages >"$STATE/up.out" 2>&1; urc=$?
  fi
  uel=$(( $(date +%s) - t0 ))
  # Any HTTP answer (401 without a key is fine) within the budget is a pass; a hang or reset is not.
  if [ "$urc" -eq 0 ] && [ "$uel" -le 20 ]; then up_status="PASS (${uel}s, HTTP $(tail -c 3 "$STATE/up.out"))"; else up_status="FAIL (rc=$urc, ${uel}s)"; hangs=$((hangs + 1)); fi
  echo "upload >1 MiB through the proxy: $up_status"
fi

verdict="PASS"
{ [ "$false_runs" -gt "$MAX_FALSE" ] || [ "$hangs" -gt 0 ]; } && verdict="FAIL"
{
  echo "# M3 live result"
  echo
  echo "- Date: $(date -u +%Y-%m-%dT%H:%MZ)  Host: $(uname -srm)"
  echo "- denyout-cli: $("$BIN" version 2>&1 | head -1)"
  echo "- Agent: \`$AGENT\`"
  echo "- Runs: $ok ok, $false_runs false-deny, $hangs hang/slow, $errs agent-error (limit: false-deny <= $MAX_FALSE, hangs = 0)"
  echo "- Upload > 1 MiB: $up_status"
  echo "- **Verdict: $verdict**"
  echo
  echo "| # | Status | rc | Time | Denies (host(reason)) | Prompt |"
  echo "| --- | --- | --- | --- | --- | --- |"
  printf '%s' "$rows"
  echo
  echo "A FALSE-DENY needing an allowlist edit counts against M3. AGENT-ERROR (agent failed, no deny) does not count against DenyOut but must be explained (login, quota)."
} > "$OUT"
echo "m3-live: $ok ok, $false_runs false-deny, $hangs hang, $errs agent-error -> $verdict (written to $OUT)"
[ "$verdict" = PASS ]
