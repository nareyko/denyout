#!/bin/sh
# Docker test of Protect this computer On/Off on Ubuntu against a PUBLISHED release binary
# (not a fresh `go build`): nft redirect, TLS intercept, deny, Off removes enforcement.
# Runs in a throw-away container with NET_ADMIN; never touches the host network.
# Needs Docker and outbound internet (example.com).
#   sh scripts/desktop-protect-docker-test.sh v0.4.14-rc2
#   PROTECT_TEST_BIN=./bin/denyout-cli sh scripts/desktop-protect-docker-test.sh v0.4.14-rc2   # a local build replaces the installed binary after install (to test a fix)
# Plan: denyout-hq docs/qa/ubuntu-desktop-docker-test-plan.md (D4, D5, D6).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
IMAGE="${DESKTOP_TEST_IMAGE:-ubuntu:24.04}"
TAG="${1:-${DENYOUT_VERSION:-}}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }
exec docker run --rm --cap-add NET_ADMIN --cap-add SYS_PTRACE \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  -e DENYOUT_VERSION="$TAG" \
  ${PROTECT_TEST_BIN:+-v "$PROTECT_TEST_BIN:/local-bin:ro"} \
  -v "$ROOT/install.sh:/install.sh:ro" \
  -v "$ROOT/scripts/docker/protect-test.sh:/t.sh:ro" \
  "$IMAGE" bash /t.sh
