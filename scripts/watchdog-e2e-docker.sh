#!/bin/sh
# Docker-only e2e: helper watchdog (degrade on dead proxy, recover, no resurrection after
# Protect Off) and the IPv6 ::1 listener. Needs Docker; never touches host networking.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="${DENYOUT_BIN:-/tmp/denyout-cli-wd}"
[ -n "${DENYOUT_BIN:-}" ] || (cd "$ROOT" && go build -buildvcs=false -o "$BIN" ./cmd/denyout-cli)
exec docker run --rm --cap-add NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  -v "$BIN:/usr/local/bin/denyout-cli:ro" -v "$ROOT/scripts/docker/watchdog-e2e.sh:/t.sh:ro" \
  debian:bookworm-slim bash /t.sh /usr/local/bin/denyout-cli
