#!/bin/sh
# D8: upgrade from an old published release to a new one while Protect is ON, in a throw-away
# NET_ADMIN container (never touches the host network). Needs Docker and outbound internet.
#   sh scripts/upgrade-docker-test.sh v0.4.13 v0.4.14-rc3
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
OLD="${1:-}"; NEW="${2:-}"
[ -n "$OLD" ] && [ -n "$NEW" ] || { echo "usage: $0 <old-tag> <new-tag>" >&2; exit 2; }
IMAGE="${DESKTOP_TEST_IMAGE:-ubuntu:24.04}"
exec docker run --rm --cap-add NET_ADMIN --cap-add SYS_PTRACE \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
  -e OLD_TAG="$OLD" -e NEW_TAG="$NEW" \
  -v "$ROOT/install.sh:/install.sh:ro" \
  -v "$ROOT/scripts/docker/upgrade-test.sh:/t.sh:ro" \
  "$IMAGE" bash /t.sh
