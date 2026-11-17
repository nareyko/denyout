#!/bin/sh
# Docker-only soak/stress test: concurrent connections + repeated proxy/helper restarts.
# Asserts bounded goroutine/fd growth, state back to protected, no orphan redirect.
# Never touches host networking (NET_ADMIN is scoped to the container).
#
#   SOAK_SECONDS=60 (default)  chaos+load duration
#   SOAK_CONC=24               concurrent client workers
#   DENYOUT_BIN=path           skip the (Docker) build and use this linux binary
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SOAK_SECONDS="${SOAK_SECONDS:-60}"
SOAK_CONC="${SOAK_CONC:-24}"
OUT="${SOAK_OUT:-$ROOT/.soak-bin}"
BIN="${DENYOUT_BIN:-$OUT/denyout-cli}"
if [ -z "${DENYOUT_BIN:-}" ]; then
  mkdir -p "$OUT"
  docker run --rm -v "$ROOT:/src" -w /src \
    -v denyout-gocache:/go/pkg/mod -v denyout-gobuild:/root/.cache/go-build \
    -e CGO_ENABLED=0 golang:1.27.4 \
    sh -c 'go build -buildvcs=false -o /src/.soak-bin/denyout-cli ./cmd/denyout-cli; chown -R '"$(id -u):$(id -g)"' /src/.soak-bin /src'
fi
exec docker run --rm --cap-add NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  -e SOAK_SECONDS="$SOAK_SECONDS" -e SOAK_CONC="$SOAK_CONC" \
  -v "$BIN:/usr/local/bin/denyout-cli:ro" -v "$ROOT/scripts/docker/soak.sh:/t.sh:ro" \
  debian:bookworm-slim bash /t.sh /usr/local/bin/denyout-cli
