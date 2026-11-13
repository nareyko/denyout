#!/bin/sh
# DenyOut installer (Linux / macOS) — installs to ~/.local/bin/denyout
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nareyko/denyout/main/install.sh | sh
#   DENYOUT_VERSION=v0.1.0 sh install.sh
# Env:
#   DENYOUT_VERSION      — tag (default: latest GitHub release)
#   DENYOUT_INSTALL_DIR  — default ~/.local/bin
#   DENYOUT_REPO         — default nareyko/denyout
#   DENYOUT_BASE_URL     — override asset base (tests / mirrors)
#   DENYOUT_INSTALL_MODE — desktop | server (skip prompt; for CI / scripts)
#   DENYOUT_NO_DESKTOP=1 — same as server mode (compat)
set -eu

REPO="${DENYOUT_REPO:-nareyko/denyout}"
INSTALL_DIR="${DENYOUT_INSTALL_DIR:-${HOME}/.local/bin}"
BASE_URL="${DENYOUT_BASE_URL:-}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
  linux|darwin) ;;
  *)
    echo "denyout install: unsupported OS '$os' (use docs/install-windows.md on Windows)" >&2
    exit 1
    ;;
esac
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)
    echo "denyout install: unsupported arch '$arch'" >&2
    exit 1
    ;;
esac

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "denyout install: need '$1' on PATH" >&2
    exit 1
  }
}
need_cmd curl
need_cmd tar
need_cmd mktemp

# sha256: sha256sum (Linux) or shasum -a 256 (macOS)
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "denyout install: need sha256sum or shasum" >&2
    exit 1
  fi
}

resolve_version() {
  if [ -n "${DENYOUT_VERSION:-}" ]; then
    echo "$DENYOUT_VERSION"
    return
  fi
  # Latest release tag via GitHub API
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  if [ -z "$tag" ]; then
    echo "denyout install: could not resolve latest release for ${REPO}" >&2
    echo "hint: set DENYOUT_VERSION=vX.Y.Z once a GitHub Release exists" >&2
    exit 1
  fi
  echo "$tag"
}

VERSION=$(resolve_version)
# Strip leading v for archive name conventions if needed — goreleaser uses tag in name.
TAG="$VERSION"
case "$TAG" in
  v*) VER_NUM=${TAG#v} ;;
  *) VER_NUM=$TAG ;;
esac

ARCHIVE="denyout_${VER_NUM}_${os}_${arch}.tar.gz"
SUMS="SHA256SUMS"
if [ -n "$BASE_URL" ]; then
  ASSET_BASE="$BASE_URL"
else
  ASSET_BASE="https://github.com/${REPO}/releases/download/${TAG}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT HUP

echo "denyout install: version=${TAG} os=${os} arch=${arch}"
echo "denyout install: fetching ${ASSET_BASE}/${ARCHIVE}"

fetch() {
  # $1 dest $2 url-or-path
  src=$2
  dest=$1
  case "$src" in
    http://*|https://*|file://*)
      curl -fsSL -o "$dest" "$src"
      ;;
    *)
      # Local directory / path (snapshot testing)
      if [ -f "$src" ]; then
        cp "$src" "$dest"
      else
        echo "denyout install: missing asset $src" >&2
        exit 1
      fi
      ;;
  esac
}

fetch "${TMP}/${ARCHIVE}" "${ASSET_BASE}/${ARCHIVE}"
fetch "${TMP}/${SUMS}" "${ASSET_BASE}/${SUMS}"

# Verify checksum for this archive line in SHA256SUMS
expected=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "./"f {print $1; exit}' "${TMP}/${SUMS}")
if [ -z "$expected" ]; then
  # Some generators put only the basename; try matching end of field
  expected=$(awk -v f="$ARCHIVE" 'index($2, f) {print $1; exit}' "${TMP}/${SUMS}")
fi
if [ -z "$expected" ]; then
  echo "denyout install: ${ARCHIVE} not listed in ${SUMS}" >&2
  exit 1
fi
actual=$(sha256_file "${TMP}/${ARCHIVE}")
if [ "$actual" != "$expected" ]; then
  echo "denyout install: SHA256 mismatch for ${ARCHIVE}" >&2
  echo "  expected: ${expected}" >&2
  echo "  actual:   ${actual}" >&2
  exit 1
fi
echo "denyout install: checksum ok"

tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"
BIN=""
for cand in "${TMP}/denyout" "${TMP}/bin/denyout" "${TMP}/denyout_${VER_NUM}_${os}_${arch}/denyout"; do
  if [ -f "$cand" ]; then
    BIN=$cand
    break
  fi
done
if [ -z "$BIN" ]; then
  BIN=$(find "$TMP" -type f -name denyout | head -n1 || true)
fi
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  echo "denyout install: denyout binary not found in archive" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"
install -m 0755 "$BIN" "${INSTALL_DIR}/denyout"
echo "denyout install: installed ${INSTALL_DIR}/denyout"

case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "denyout install: note — add ${INSTALL_DIR} to PATH if 'denyout' is not found" >&2
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" >&2
    ;;
esac

"${INSTALL_DIR}/denyout" version || true

echo "denyout install: done"
echo ""

# --- Install mode: Desktop (native tray UI) vs Server (CLI only, no web) ---
# Always try /dev/tty so `curl | sh` can still prompt interactively.
MODE="${DENYOUT_INSTALL_MODE:-}"
if [ -n "${DENYOUT_NO_DESKTOP:-}" ] && [ -z "$MODE" ]; then
  MODE=server
fi

ask_mode() {
  # Prefer controlling TTY (works under curl|sh). Fall back to stdin if interactive.
  tty_dev=""
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    tty_dev=/dev/tty
  elif [ -t 0 ] && [ -t 1 ]; then
    tty_dev=""
  else
    return 1
  fi

  echo "Choose install type:" >&2
  echo "  1) Desktop — native tray + Protect this computer (no browser UI)" >&2
  echo "  2) Server  — CLI only (denyout init / run / serve); no tray, no web services" >&2
  if [ -n "$tty_dev" ]; then
    printf "Install type [1=Desktop / 2=Server] (default 1): " >/dev/tty
    IFS= read -r ans </dev/tty || ans=1
  else
    printf "Install type [1=Desktop / 2=Server] (default 1): "
    IFS= read -r ans || ans=1
  fi
  case "$ans" in
    ""|1|d|D|desktop|Desktop|DESKTOP) echo desktop ;;
    2|s|S|server|Server|SERVER) echo server ;;
    *)
      echo "denyout install: unknown choice '$ans' — using desktop" >&2
      echo desktop
      ;;
  esac
  return 0
}

if [ -z "$MODE" ]; then
  if MODE=$(ask_mode); then
    :
  else
    echo "denyout install: no TTY — defaulting to server (CLI only)." >&2
    echo "  Re-run with DENYOUT_INSTALL_MODE=desktop to launch the native UI," >&2
    echo "  or later: denyout desktop" >&2
    MODE=server
  fi
fi

case "$MODE" in
  desktop|Desktop|DESKTOP)
    MODE=desktop
    ;;
  server|Server|SERVER)
    MODE=server
    ;;
  *)
    echo "denyout install: DENYOUT_INSTALL_MODE must be desktop or server (got '$MODE')" >&2
    exit 1
    ;;
esac

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
mkdir -p "${CONFIG_HOME}/denyout"
echo "$MODE" >"${CONFIG_HOME}/denyout/install-mode"
echo "denyout install: mode=${MODE}"

if [ "$MODE" = "server" ]; then
  echo ""
  echo "Server install — no tray, no localhost web UI."
  echo "  denyout init"
  echo "  denyout run -- <your-agent>"
  echo "  denyout serve --config ~/.config/denyout/config.yaml   # optional long-running"
  echo ""
  exit 0
fi

echo ""
echo "Desktop install — native UI (tray + dialogs). No browser wizard."
echo "  Later: denyout desktop"
echo "  Advanced/tests only: denyout desktop --web-ui"
echo ""

# Launch native first-run setup + tray (not a web server).
exec "${INSTALL_DIR}/denyout" desktop --setup
