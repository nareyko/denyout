#!/bin/sh
# Limited TUN dogfood inside Docker (NET_ADMIN + /dev/net/tun).
# Not a full Chrome/Cursor VM matrix — proves denyout0 create/steer/rollback.
# Usage: ./scripts/closed-loop-tun-docker-dogfood.sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
IMAGE="${DENYOUT_DOGFOOD_IMAGE:-golang:1.27.4}"

if [ ! -e /dev/net/tun ]; then
  echo "closed-loop-tun-docker-dogfood: /dev/net/tun missing on host" >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "closed-loop-tun-docker-dogfood: docker required" >&2
  exit 2
fi

echo "== docker dogfood image=$IMAGE =="
docker run --rm --privileged \
  --device=/dev/net/tun \
  -v "$ROOT:/src:ro" \
  -w /src \
  -e DENYOUT_TUN_E2E=1 \
  "$IMAGE" bash -ec '
    set -euo pipefail
    go build -buildvcs=false -o /tmp/denyout-cli ./cmd/denyout-cli
    echo "== tun-start --real (root in container) =="
    /tmp/denyout-cli hostctl tun-start --real --uid 1000
    ip link show denyout0
    /tmp/denyout-cli hostctl tun-stats
    /tmp/denyout-cli hostctl tun-stop --real --uid 1000
    if ip link show denyout0 >/dev/null 2>&1; then
      echo "denyout0 still present after stop" >&2
      exit 1
    fi
    echo "rollback ok"
  '

echo "closed-loop-tun-docker-dogfood OK (full browser matrix still needs a real VM)"
