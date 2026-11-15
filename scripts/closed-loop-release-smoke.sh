#!/bin/sh
# Verify a DenyOut release tree in a closed loop (no ~/.local, no Protect elevate).
# Usage:
#   scripts/closed-loop-release-smoke.sh /tmp/denyout-v048-XXXX
#   scripts/closed-loop-release-smoke.sh   # builds ./bin/denyout-cli from this repo
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DIR="${1:-}"
if [ -n "$DIR" ]; then
  CLI=$(find "$DIR" -type f -name denyout-cli | head -n 1)
  if [ -z "$CLI" ] || [ ! -x "$CLI" ]; then
    echo "closed-loop-release-smoke: no denyout-cli under $DIR" >&2
    exit 2
  fi
else
  mkdir -p "$ROOT/bin"
  CLI="$ROOT/bin/denyout-cli"
  (cd "$ROOT" && go build -o "$CLI" ./cmd/denyout-cli)
fi

echo "== version =="
"$CLI" version

echo "== tun stubs (must stay disabled) =="
"$CLI" hostctl tun-stats | grep -E 'present=false|source=tun'
"$CLI" hostctl tun-start | grep 'enabled=false'
"$CLI" hostctl tun-stop | grep 'enabled=false'

echo "== render --tun (T0 + T1 preview, not applied) =="
"$CLI" hostctl render --port 18080 --uid 1000 --tun | grep -E 'denyout-block-quic|denyout-tun-quic|T1 TUN'

POLICY="$ROOT/examples/policies/denyout.whole_device_browse.yaml"
if [ -f "$POLICY" ]; then
  echo "== AIza FP (google allow / evil deny) =="
  AIZA="AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "$CLI" check --config "$POLICY" "https://chat.google.com/x?key=${AIZA}" | grep 'verdict=allow'
  "$CLI" check --config "$POLICY" "https://evil.example/x?key=${AIZA}" | grep 'verdict=deny'
fi

LIVE="${HOME}/.local/bin/denyout-cli"
if [ -x "$LIVE" ]; then
  echo "== live path untouched check =="
  echo "LIVE=$("$LIVE" version 2>/dev/null | head -n 1 || true)"
fi

echo "closed-loop-release-smoke OK cli=$CLI"
