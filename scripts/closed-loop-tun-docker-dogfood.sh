#!/bin/sh
# Limited TUN dogfood inside Docker (NET_ADMIN + /dev/net/tun).
# Proves helper-held denyout0 create/stats/stop. Not a full Chrome/Cursor matrix.
# Usage:
#   ./scripts/closed-loop-tun-docker-dogfood.sh
#   DENYOUT_BIN=/path/to/denyout-cli ./scripts/closed-loop-tun-docker-dogfood.sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
IMAGE="${DENYOUT_DOGFOOD_IMAGE:-debian:bookworm-slim}"
BIN="${DENYOUT_BIN:-}"

if [ ! -e /dev/net/tun ]; then
  echo "closed-loop-tun-docker-dogfood: /dev/net/tun missing on host" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "closed-loop-tun-docker-dogfood: docker required" >&2
  exit 2
fi

if [ -z "$BIN" ]; then
  BIN=/tmp/denyout-cli-dogfood
  echo "== build host binary → $BIN =="
  (cd "$ROOT" && go build -buildvcs=false -o "$BIN" ./cmd/denyout-cli)
fi
if [ ! -x "$BIN" ]; then
  echo "closed-loop-tun-docker-dogfood: DENYOUT_BIN not executable: $BIN" >&2
  exit 2
fi

echo "== docker dogfood image=$IMAGE bin=$BIN =="
docker run --rm --privileged \
  --device=/dev/net/tun \
  -v "$BIN:/usr/local/bin/denyout-cli:ro" \
  -e DENYOUT_TUN_E2E=1 \
  -e DEBIAN_FRONTEND=noninteractive \
  "$IMAGE" bash -ec '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq iproute2 nftables >/dev/null
    echo "== helper-serve =="
    denyout-cli hostctl helper-serve &
    hp=$!
    trap "kill $hp 2>/dev/null || true" EXIT
    for i in 1 2 3 4 5 6 7 8 9 10; do
      [ -S /run/denyout-hostguard.sock ] && break
      sleep 0.2
    done
    test -S /run/denyout-hostguard.sock
    echo "== tun-start --real =="
    denyout-cli hostctl tun-start --real --uid 1000
    ip link show denyout0
    denyout-cli hostctl tun-stats --real --uid 1000
    echo "== tun-stop --real =="
    denyout-cli hostctl tun-stop --real --uid 1000
    if ip link show denyout0 >/dev/null 2>&1; then
      echo "denyout0 still present after stop" >&2
      exit 1
    fi
    echo "rollback ok"
  '

echo "closed-loop-tun-docker-dogfood OK (full browser matrix still needs a real VM)"
