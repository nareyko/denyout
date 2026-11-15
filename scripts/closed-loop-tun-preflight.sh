#!/bin/sh
# Closed-loop TUN T1 preflight (no /dev/net/tun, no elevate, no ~/.local install).
# Fails if stubs claim enabled=true or if DENYOUT_TUN_E2E leaks into default checks.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CLI="${DENYOUT_BIN:-}"
if [ -z "$CLI" ]; then
  mkdir -p "$ROOT/bin"
  CLI="$ROOT/bin/denyout-cli"
  if [ ! -x "$CLI" ]; then
    (cd "$ROOT" && go build -o "$CLI" ./cmd/denyout-cli)
  fi
fi
if [ ! -x "$CLI" ]; then
  echo "closed-loop-tun-preflight: CLI not executable: $CLI" >&2
  exit 2
fi

# Ensure default gate is off for this process tree.
unset DENYOUT_TUN_E2E || true

echo "== preflight version =="
"$CLI" version

echo "== gate: E2E must be unset =="
if [ -n "${DENYOUT_TUN_E2E:-}" ]; then
  echo "DENYOUT_TUN_E2E is set; refuse default preflight" >&2
  exit 1
fi

echo "== tun stubs disabled =="
for verb in tun-stats tun-start tun-stop; do
  out=$("$CLI" hostctl "$verb")
  echo "$out"
  echo "$out" | grep -q 'enabled=false\|present=false'
  if echo "$out" | grep -q 'enabled=true'; then
    echo "stub must never claim enabled=true: $out" >&2
    exit 1
  fi
  if echo "$out" | grep -q 'reason='; then
    echo "$out" | grep -E 'reason=(flag_off|stub_no_device)' >/dev/null
  fi
done

echo "== render --tun preview =="
rend=$("$CLI" hostctl render --port 18080 --uid 1000 --tun)
echo "$rend" | grep -q 'denyout-block-quic'
echo "$rend" | grep -q 'denyout-tun-quic'
echo "$rend" | grep -q 'T1 TUN'

echo "== tun-rollback-plan =="
plan=$("$CLI" hostctl tun-rollback-plan)
echo "$plan" | grep -q 'tun-stop'
echo "$plan" | grep -q 'denyout0'
echo "$plan" | grep -q 'hostctl apply'

echo "== unit: gate + denylist + rollback (no kernel) =="
(cd "$ROOT" && go test ./internal/tun/ -count=1 -run 'TestWantDeviceDefaultOff|TestShouldSkipIface|TestRollbackPlan|TestHelperReplyStartStopDisabled|TestEngineBatchQUICDrops')

echo "== live path note =="
if [ -x "${HOME}/.local/bin/denyout-cli" ]; then
  echo "LIVE=$(${HOME}/.local/bin/denyout-cli version 2>/dev/null | head -n 1 || true)"
fi

echo "closed-loop-tun-preflight OK (VM dogfood still required for real denyout0)"
echo "See docs/tun-vm-dogfood.md"
