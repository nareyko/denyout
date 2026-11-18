#!/bin/sh
# Docker-only regression for the root hostguard helper (never touches the host network).
# Replays the review's exploits (shell injection via VPN iface, foreign-uid access,
# arbitrary-file read via CA path, uid-0 redirect, missing owner_uid) and fails if any succeeds.
#   ./scripts/security-helper-regression-docker.sh            # test the current tree
#   DENYOUT_BIN=/path/to/denyout-cli ./scripts/...            # test a given binary
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="${DENYOUT_BIN:-/tmp/denyout-cli-secreg}"
command -v docker >/dev/null 2>&1 || { echo "docker required" >&2; exit 2; }
if [ -z "${DENYOUT_BIN:-}" ]; then
  (cd "$ROOT" && go build -buildvcs=false -o "$BIN" ./cmd/denyout-cli)
fi
out=$(docker run --rm --cap-add NET_ADMIN --cap-add SYS_PTRACE --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  -v "$BIN:/usr/local/bin/denyout-cli:ro" \
  -v "$ROOT/scripts/docker/helper-exploits.sh:/exploit.sh:ro" \
  debian:bookworm-slim bash /exploit.sh /usr/local/bin/denyout-cli 2>&1)
echo "$out" | grep -E "RESULT|rules:|^audit:"
if echo "$out" | grep -q "EXPLOITED"; then
  echo "security-helper-regression: FAIL (exploit succeeded)" >&2
  exit 1
fi
echo "security-helper-regression: OK"
