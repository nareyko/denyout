#!/bin/sh
# Linux Protect this computer end-to-end (needs interactive pkexec/polkit once).
# Usage: ./scripts/smoke-linux-protect-e2e.sh
# Env: DENYOUT_E2E_SKIP_ELEVATE=1 — only transparent proxy smoke (no nft).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="${DENYOUT_BIN:-$ROOT/bin/denyout}"
cd "$ROOT"
go build -o "$BIN" ./cmd/denyout

UID_N=$(id -u)
CA_DIR=$(mktemp -d)
STATE_DIR=$(mktemp -d)
export XDG_CONFIG_HOME="$STATE_DIR/config"
export XDG_STATE_HOME="$STATE_DIR/state"
mkdir -p "$XDG_CONFIG_HOME/denyout/ca" "$XDG_STATE_HOME/denyout"

echo "== 1) hostctl render =="
"$BIN" hostctl render --port 18443 --uid "$UID_N" | tee /tmp/denyout-nft-render.txt
grep -q "table inet denyout" /tmp/denyout-nft-render.txt
grep -q "ip6 daddr" /tmp/denyout-nft-render.txt

echo "== 2) transparent proxy + whole_device (no elevate) =="
# Use a tiny Go helper via denyout check for policy; proxy path covered by unit tests.
"$BIN" check --config examples/policies/denyout.whole_device.yaml 'https://example.com/' | grep -q 'verdict=allow'
"$BIN" check --config examples/policies/denyout.whole_device.yaml 'https://example.com/?api_key=sk-ant-e2e-secret99' | grep -q 'verdict=deny'

if [ "${DENYOUT_E2E_SKIP_ELEVATE:-}" = "1" ]; then
  echo "SKIP elevate (DENYOUT_E2E_SKIP_ELEVATE=1)"
  echo "smoke-linux-protect-e2e: partial OK"
  exit 0
fi

echo "== 3) start desktop API + Protect On (pkexec dialog) =="
LISTEN="127.0.0.1:18781"
"$BIN" desktop --no-tray --no-open --listen "$LISTEN" &
DPID=$!
cleanup() {
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
  "$BIN" hostctl remove --port 0 --uid "$UID_N" --no-elevate 2>/dev/null || true
  # Best-effort nft cleanup if table left behind
  if command -v nft >/dev/null 2>&1; then
    pkexec nft delete table inet denyout 2>/dev/null || true
    pkexec nft delete table ip denyout 2>/dev/null || true
  fi
  rm -rf "$CA_DIR" "$STATE_DIR"
}
trap cleanup EXIT INT HUP

i=0
while [ "$i" -lt 50 ]; do
  if curl -fsS "http://$LISTEN/api/status" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.1
done
curl -fsS -X POST "http://$LISTEN/api/setup" -H 'Content-Type: application/json' \
  -d '{"notify":true,"ask_mode":false}' >/dev/null

echo "Approve the polkit/pkexec dialog if prompted…"
set +e
RESP=$(curl -fsS -X POST "http://$LISTEN/api/computer" -H 'Content-Type: application/json' \
  -d '{"enabled":true}' 2>&1)
RC=$?
set -e
echo "$RESP"
STATUS=$(curl -fsS "http://$LISTEN/api/status")
echo "$STATUS"
echo "$STATUS" | grep -q 'Protecting computer\|computer_enabled.:true' || {
  echo "Protect On failed (admin denied or hostguard error). Status above."
  exit 1
}

echo "== 4) traffic without HTTP_PROXY should hit DenyOut (secret URL) =="
# Force IPv4 + HTTP/1.1 TCP (avoid QUIC/UDP bypass). Expect 403 from DenyOut MITM.
set +e
CODE=$(curl -4 --http1.1 -sS -o /tmp/denyout-e2e-body.txt -w '%{http_code}' --max-time 15 \
  'https://example.com/?api_key=sk-ant-e2e-secret99' 2>/dev/null)
CURL_RC=$?
set -e
echo "curl_rc=$CURL_RC http_code=$CODE"
echo "body=$(head -c 200 /tmp/denyout-e2e-body.txt 2>/dev/null || true)"
case "$CODE" in
  403) echo "deny path OK" ;;
  200) echo "FAIL: HTTP 200 — redirect not active"; exit 1 ;;
  000)
    echo "FAIL: connect timeout/error — likely redirect loop or proxy stuck (rc=$CURL_RC)"; exit 1
    ;;
  *)
    grep -qiE 'deny|forbid|secret' /tmp/denyout-e2e-body.txt || exit 1
    echo "deny path OK (body match, code=$CODE)"
    ;;
esac

echo "== 5) Turn Off =="
curl -fsS -X POST "http://$LISTEN/api/computer" -H 'Content-Type: application/json' \
  -d '{"enabled":false}' >/dev/null

echo "smoke-linux-protect-e2e OK"
