#!/bin/sh
# Tamper / helper-exploit regression against a PUBLISHED release binary (not a fresh build):
# downloads denyout-cli for <tag> from GitHub, verifies it against SHA256SUMS, then runs
# scripts/security-helper-regression-docker.sh on it (shell injection via VPN iface, foreign
# uid, arbitrary-file read via CA path, uid-0 redirect, audit trail T8, missing owner_uid).
#   sh scripts/release-security-docker-test.sh v0.4.14-rc3
# Linux amd64/arm64 hosts only (the container runs the host architecture).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TAG="${1:-}"
[ -n "$TAG" ] || { echo "usage: $0 <tag>" >&2; exit 2; }
case "$(uname -m)" in x86_64|amd64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) echo "unsupported arch $(uname -m)" >&2; exit 2 ;; esac
VER="${TAG#v}"
ARCHIVE="denyout-cli_${VER}_linux_${A}.tar.gz"
BASE="https://github.com/nareyko/denyout/releases/download/${TAG}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
curl -fsSL -o "$W/$ARCHIVE" "$BASE/$ARCHIVE"
curl -fsSL -o "$W/SHA256SUMS" "$BASE/SHA256SUMS"
want=$(grep " ${ARCHIVE}\$" "$W/SHA256SUMS" | awk '{print $1}')
got=$(sha256sum "$W/$ARCHIVE" | awk '{print $1}')
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "release-security: checksum mismatch for $ARCHIVE" >&2; exit 1; }
tar -xzf "$W/$ARCHIVE" -C "$W" denyout-cli
echo "release-security: testing $ARCHIVE ($got)"
DENYOUT_BIN="$W/denyout-cli" sh "$ROOT/scripts/security-helper-regression-docker.sh"
