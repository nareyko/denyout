#!/bin/sh
# DenyOut installer (Linux / macOS) — installs to ~/.local/bin/denyout
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/nareyko/denyout/main/install.sh | sh
#   curl ... | sh -s -- --desktop          # force desktop
#   curl ... | sh -s -- --server           # force server
#   DENYOUT_VERSION=v0.1.0 sh install.sh
# Env / flags (force wins over auto-detect):
#   DENYOUT_VERSION        — tag (default: latest GitHub release)
#   DENYOUT_INSTALL_DIR    — default ~/.local/bin
#   DENYOUT_REPO           — default nareyko/denyout
#   DENYOUT_BASE_URL       — override asset base (tests / mirrors)
#   DENYOUT_INSTALL_MODE   — desktop | server (force; same as --desktop / --server)
#   DENYOUT_NO_DESKTOP=1   — force server (compat)
#   DENYOUT_INSTALL_PROMPT=1 — ask interactively instead of auto-detect (rare)
# Desktop path is silent: autostart + try whole-computer once + detach tray.
set -eu

REPO="${DENYOUT_REPO:-nareyko/denyout}"
INSTALL_DIR="${DENYOUT_INSTALL_DIR:-${HOME}/.local/bin}"
BASE_URL="${DENYOUT_BASE_URL:-}"
FORCE_MODE=""
WANT_PROMPT="${DENYOUT_INSTALL_PROMPT:-}"

# Parse force flags early (supports: curl … | sh -s -- --desktop)
for arg in "$@"; do
  case "$arg" in
    --desktop|-d) FORCE_MODE=desktop ;;
    --server|-s) FORCE_MODE=server ;;
    --prompt) WANT_PROMPT=1 ;;
    --help|-h)
      echo "Usage: install.sh [--desktop|--server] [--prompt]"
      echo "  Auto-detects Desktop vs Server; flags/env force the mode."
      echo "  DENYOUT_INSTALL_MODE=desktop|server  DENYOUT_NO_DESKTOP=1"
      exit 0
      ;;
  esac
done

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

# --- Install mode: auto-detect Desktop vs Server; flags/env force ---
# Priority: --desktop/--server > DENYOUT_INSTALL_MODE > DENYOUT_NO_DESKTOP > prompt > auto-detect

normalize_mode() {
  case "$1" in
    desktop|Desktop|DESKTOP|d|D|1) echo desktop ;;
    server|Server|SERVER|s|S|2) echo server ;;
    *) return 1 ;;
  esac
}

detect_desktop() {
  # Graphical session → desktop install (native tray).
  # Headless / SSH without display → server (CLI only).
  case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
    darwin)
      # macOS laptop/desktop is the common case; treat as desktop unless forced.
      # Headless CI often has no Aqua session — still ok; --server / MODE=server overrides.
      if [ -n "${SSH_CONNECTION:-}${SSH_TTY:-}" ] && [ -z "${DISPLAY:-}" ]; then
        # Rare: SSH into Mac without GUI forwarding → prefer server.
        return 1
      fi
      return 0
      ;;
  esac

  if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
    return 0
  fi
  if [ -n "${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:-}${GNOME_DESKTOP_SESSION_ID:-}${KDE_FULL_SESSION:-}" ]; then
    return 0
  fi
  # systemd user session type (best-effort)
  if command -v loginctl >/dev/null 2>&1; then
    sid=$(loginctl 2>/dev/null | awk -v u="$(id -un)" '$3==u {print $1; exit}')
    if [ -n "$sid" ]; then
      st=$(loginctl show-session "$sid" -p Type --value 2>/dev/null || true)
      case "$st" in
        x11|wayland|mir) return 0 ;;
      esac
    fi
  fi
  return 1
}

ask_mode() {
  # Prefer controlling TTY (works under curl|sh).
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    echo "Choose install type:" >/dev/tty
    echo "  1) Desktop — native tray + Protect this computer (no browser UI)" >/dev/tty
    echo "  2) Server  — CLI only; no tray, no web services" >/dev/tty
    printf "Install type [1=Desktop / 2=Server]: " >/dev/tty
    IFS= read -r ans </dev/tty || ans=
  elif [ -t 0 ] && [ -t 1 ]; then
    echo "Choose install type:" >&2
    echo "  1) Desktop — native tray + Protect this computer (no browser UI)" >&2
    echo "  2) Server  — CLI only; no tray, no web services" >&2
    printf "Install type [1=Desktop / 2=Server]: "
    IFS= read -r ans || ans=
  else
    return 1
  fi
  normalize_mode "${ans:-}" || {
    echo "denyout install: unknown choice — using auto-detect" >&2
    return 1
  }
}

MODE=""
MODE_SRC=""

if [ -n "$FORCE_MODE" ]; then
  MODE=$(normalize_mode "$FORCE_MODE") || true
  MODE_SRC="flag"
elif [ -n "${DENYOUT_INSTALL_MODE:-}" ]; then
  MODE=$(normalize_mode "$DENYOUT_INSTALL_MODE") || {
    echo "denyout install: DENYOUT_INSTALL_MODE must be desktop or server (got '$DENYOUT_INSTALL_MODE')" >&2
    exit 1
  }
  MODE_SRC="env"
elif [ -n "${DENYOUT_NO_DESKTOP:-}" ]; then
  MODE=server
  MODE_SRC="DENYOUT_NO_DESKTOP"
elif [ -n "$WANT_PROMPT" ]; then
  if MODE=$(ask_mode); then
    MODE_SRC="prompt"
  else
    echo "denyout install: no TTY for --prompt; falling back to auto-detect" >&2
  fi
fi

if [ -z "$MODE" ]; then
  if detect_desktop; then
    MODE=desktop
  else
    MODE=server
  fi
  MODE_SRC="auto-detect"
fi

echo "denyout install: mode=${MODE} (${MODE_SRC})"
if [ "$MODE_SRC" = "auto-detect" ]; then
  echo "denyout install: force with --desktop / --server or DENYOUT_INSTALL_MODE=…" >&2
fi

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
mkdir -p "${CONFIG_HOME}/denyout"
echo "$MODE" >"${CONFIG_HOME}/denyout/install-mode"

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
echo "Desktop install — silent: autostart, try whole computer, fallback session, tray in background."
echo ""

# Silent register + start (does not replace this shell with tray).
"${INSTALL_DIR}/denyout" desktop --install
exit $?
