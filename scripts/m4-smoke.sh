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
CURL_FLAGS="${M4_CURL_FLAGS:--sS -o /dev/null -m 30 -w %{http_code}}"
CANARY_URL='https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB'

fail=0
rows=""

row() { # name expected actual ok(0|1)
  local mark="PASS"
  [ "$4" -eq 0 ] || { mark="FAIL"; fail=1; }
  rows="${rows}| $1 | $2 | $3 | ${mark} |
"
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
out=$("$BIN" run -- $CURL $CURL_FLAGS https://api.anthropic.com 2>&1); rc=$?
code=$(printf '%s' "$out" | grep -Eo '[0-9]{3}$' | tail -1)
if [ $rc -eq 0 ] && [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" != "403" ]; then
  row "run: HTTPS to api.anthropic.com" "allowed (HTTP ${code} from upstream)" "HTTP ${code}" 0
else
  row "run: HTTPS to api.anthropic.com" "allowed through TLS intercept" "exit ${rc}: ${out}" 1
fi

# 4. run + HTTPS to a non-model host must be denied by DenyOut
# shellcheck disable=SC2086
out=$("$BIN" run -- $CURL $CURL_FLAGS https://example.com 2>&1); rc=$?
if echo "$out" | grep -qiE 'DENY|403|Forbidden|CONNECT'; then
  row "run: HTTPS to example.com" "denied" "denied" 0
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
