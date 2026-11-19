#!/bin/sh
# Docker test of the Ubuntu desktop install (GUI archive, runtime libs, headless start,
# `desktop --install` side effects, uninstall). Never touches the host: everything runs in
# throw-away containers. Needs Docker and outbound internet (installs a real release).
#
#   sh scripts/desktop-docker-test.sh [tag]        # default: latest prerelease-or-release tag
#   DENYOUT_DOCKER_IMAGE=ubuntu:24.04 sh scripts/desktop-docker-test.sh v0.4.14-rc2
#
# Plan: denyout-hq docs/qa/ubuntu-desktop-docker-test-plan.md (D1, D1b, D2, D3, D7).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
IMAGE="${DENYOUT_DOCKER_IMAGE:-ubuntu:24.04}"
TAG="${1:-${DENYOUT_VERSION:-}}"
[ -n "$TAG" ] || { echo "usage: $0 <tag, e.g. v0.4.14-rc2>" >&2; exit 2; }
FAIL=0
run_case() { # name script-arg
  echo "##### $1"
  docker run --rm -e DENYOUT_VERSION="$TAG" \
    -v "$ROOT/install.sh:/install.sh:ro" \
    -v "$ROOT/scripts/docker/desktop-test.sh:/t.sh:ro" \
    "$IMAGE" bash /t.sh "$2" || FAIL=1
}
run_case "with GUI runtime libs (D1, D2, D3, D7)" full
run_case "without GUI runtime libs (D1b)" nolibs
if [ "$FAIL" -eq 0 ]; then echo "desktop-docker-test: OK ($TAG, $IMAGE)"; else echo "desktop-docker-test: FAILED"; exit 1; fi
