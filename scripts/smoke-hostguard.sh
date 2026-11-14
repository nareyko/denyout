#!/bin/sh
# CI-friendly hostguard dry-run (no root).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="${DENYOUT_BIN:-$ROOT/bin/denyout}"
if [ ! -x "$BIN" ]; then
  (cd "$ROOT" && go build -o "$BIN" ./cmd/denyout)
fi
echo "== hostctl render =="
"$BIN" hostctl render --port 18443 --uid 1000
echo "== policy whole_device =="
"$BIN" check --config "$ROOT/examples/policies/denyout.whole_device.yaml" 'https://example.com/' | head -5
"$BIN" check --config "$ROOT/examples/policies/denyout.whole_device.yaml" 'https://example.com/?api_key=sk-ant-testvalue999' | head -5
echo "smoke-hostguard OK"
