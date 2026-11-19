#!/usr/bin/env bash
# M4 smoke: with denyout-cli already on PATH, run the checks a first-time user runs
# after install and print a markdown table. Exit 1 if any check fails or the total
# elapsed time (since M4_START, epoch seconds) exceeds M4_BUDGET_SECS (default 300).
#
# Used by .github/workflows/m4-smoke.yml; runnable by hand on a clean machine:
#   M4_START=$(date +%s) scripts/m4-smoke.sh
set -u

BIN="${DENYOUT_BIN:-denyout-cli}"
BUDGET="${M4_BUDGET_SECS:-300}"
START="${M4_START:-$(date +%s)}"
CURL="${M4_CURL:-curl}"
# Default kept in its own single-quoted variable: inside ${VAR:-...} the "}" of
# %{http_code} would end the expansion and append a stray "}" to the flags.
DEFAULT_CURL_FLAGS='-sS -o /dev/null -m 30 -w %{http_code}'
CURL_FLAGS="${M4_CURL_FLAGS:-$DEFAULT_CURL_FLAGS}"
# M4_CACERT=1: pass the session CA to curl explicitly (--cacert). Needed on Windows,
# where curl.exe (Schannel) ignores CURL_CA_BUNDLE.
export M4_CACERT="${M4_CACERT:-}"
CANARY_URL='https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB'

fail=0
rows=""

row() { # name expected actual ok(0|1)
  local mark="PASS"
  [ "$4" -eq 0 ] || { mark="FAIL"; fail=1; }
  rows="${rows}| $1 | $2 | $3 | ${mark} |
"
}

# run_curl URL: run curl under `denyout-cli run`. bash -c keeps $CURL_CA_BUNDLE
# (set by run for the child) expandable inside the child.
run_curl() {
  # shellcheck disable=SC2086
  "$BIN" run -- bash -c 'c=$1; shift; if [ -n "$M4_CACERT" ]; then set -- --cacert "$CURL_CA_BUNDLE" "$@"; fi; exec "$c" "$@"' _ "$CURL" $CURL_FLAGS "$1"
}

# 1. version
ver_out=$("$BIN" version 2>&1); rc=$?
[ $rc -eq 0 ] && row "version" "exit 0" "${ver_out}" 0 || row "version" "exit 0" "exit ${rc}: ${ver_out}" 1

# 2. canary check must deny (exit 1, verdict=deny, secret not echoed)
out=$("$BIN" check "$CANARY_URL" 2>&1); rc=$?
if [ $rc -eq 1 ] && echo "$out" | grep -q 'verdict=deny' && ! echo "$out" | grep -q 'DENYOUT_CANARY_LAB'; then
  row "check canary URL" "deny, secret redacted" "deny" 0
else
  row "check canary URL" "deny, secret redacted" "exit ${rc}: ${out}" 1
fi

# 3. run + HTTPS to a model host must be allowed by DenyOut (upstream 401/404 is fine)
# shellcheck disable=SC2086
out=$(run_curl https://api.anthropic.com 2>&1); rc=$?
code=$(printf '%s' "$out" | grep -Eo '[0-9]{3}$' | tail -1)
if [ $rc -eq 0 ] && [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" != "403" ]; then
  row "run: HTTPS to api.anthropic.com" "allowed (HTTP ${code} from upstream)" "HTTP ${code}" 0
else
  row "run: HTTPS to api.anthropic.com" "allowed through TLS intercept" "exit ${rc}: ${out}" 1
fi

# 4. run + HTTPS to a non-model host must be denied by DenyOut
out=$(run_curl https://example.com 2>&1); rc=$?
# Must be a DenyOut deny of this host AND a failed client; the startup banner also
# contains the word "deny", so match the event line, not the bare word.
if [ $rc -ne 0 ] && echo "$out" | grep -q 'DENY host=example.com'; then
  row "run: HTTPS to example.com" "denied by DenyOut" "denied" 0
else
  row "run: HTTPS to example.com" "denied" "exit ${rc}: ${out}" 1
fi

elapsed=$(( $(date +%s) - START ))
if [ "$elapsed" -le "$BUDGET" ]; then
  row "elapsed (install to last check)" "<= ${BUDGET}s" "${elapsed}s" 0
else
  row "elapsed (install to last check)" "<= ${BUDGET}s" "${elapsed}s" 1
fi

report="### M4 smoke: ${M4_LABEL:-$(uname -s)}

| Check | Expected | Actual | Result |
| --- | --- | --- | --- |
${rows}"
printf '%s\n' "$report"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$report" >> "$GITHUB_STEP_SUMMARY"
exit $fail
