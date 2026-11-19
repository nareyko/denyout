#!/bin/sh
# DenyOut installer (Linux / macOS) — installs denyout-cli (+ denyout GUI when published) to ~/.local/bin
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
#   DENYOUT_FETCH_RETRIES  — curl attempts (default 10)
#   DENYOUT_FETCH_RETRY_SECS — base delay between retries, doubles up to 30s (default 2)
# Desktop path is silent: autostart + try whole-computer once + detach tray.
set -eu

REPO="${DENYOUT_REPO:-nareyko/denyout}"
INSTALL_DIR="${DENYOUT_INSTALL_DIR:-${HOME}/.local/bin}"
BASE_URL="${DENYOUT_BASE_URL:-}"
FORCE_MODE=""
WANT_PROMPT="${DENYOUT_INSTALL_PROMPT:-}"
FETCH_RETRIES="${DENYOUT_FETCH_RETRIES:-10}"
FETCH_RETRY_SECS="${DENYOUT_FETCH_RETRY_SECS:-2}"

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

# curl_fetch dest url [optional] — retries on network / HTTP failures until success or give up.
# Prints wait lines so a flaky GitHub is visible instead of a silent fail.
# With a third argument "optional" the asset may legitimately not exist (the GUI archive and
# signatures are not published for every OS/arch): a missing file (HTTP 404, or no such
# file:// path) returns 1 at once and quietly instead of waiting through every retry.
curl_fetch() {
  dest=$1
  url=$2
  optional=${3:-}
  attempt=1
  delay=$FETCH_RETRY_SECS
  while [ "$attempt" -le "$FETCH_RETRIES" ]; do
    if [ "$optional" = optional ]; then
      code=$(curl -fsSL --connect-timeout 15 --retry 0 -o "$dest" -w '%{http_code}' "$url" 2>/dev/null) && rc=0 || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      rm -f "$dest" 2>/dev/null || true
      # 22 = HTTP error (404 prints 404), 37 = file:// path missing
      if [ "$rc" -eq 37 ] || { [ "$rc" -eq 22 ] && [ "$code" = 404 ]; }; then
        return 1
      fi
    elif curl -fsSL --connect-timeout 15 --retry 0 -o "$dest" "$url"; then
      return 0
    fi
    rm -f "$dest" 2>/dev/null || true
    if [ "$attempt" -ge "$FETCH_RETRIES" ]; then
      break
    fi
    echo "denyout install: download failed (${attempt}/${FETCH_RETRIES}), waiting ${delay}s — ${url}" >&2
    sleep "$delay" || true
    # Exponential backoff, cap 30s.
    next=$((delay * 2))
    if [ "$next" -gt 30 ]; then
      next=30
    fi
    delay=$next
    attempt=$((attempt + 1))
  done
  return 1
}

# Release tags are interpolated into download URLs: accept only plain versions.
check_tag() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*|*..*|-*)
      echo "denyout install: invalid version/tag: $1" >&2; exit 1 ;;
  esac
}

resolve_version() {
  if [ -n "${DENYOUT_VERSION:-}" ]; then
    check_tag "$DENYOUT_VERSION"
    echo "$DENYOUT_VERSION"
    return
  fi
  # Latest release tag: the github.com /releases/latest redirect first (not subject to the
  # unauthenticated API rate limit that shared or corporate IPs hit), the API as fallback.
  final=$(curl -fsSLI --connect-timeout 15 --retry 0 -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)
  case "$final" in
    */releases/tag/*)
      tag=${final##*/releases/tag/}
      case "$tag" in ''|*[!A-Za-z0-9._-]*|*..*|-*) ;; *) echo "$tag"; return ;; esac
      ;;
  esac
  api="https://api.github.com/repos/${REPO}/releases/latest"
  body=$(mktemp)
  if ! curl_fetch "$body" "$api"; then
    rm -f "$body"
    echo "denyout install: could not resolve latest release for ${REPO}" >&2
    echo "hint: set DENYOUT_VERSION=vX.Y.Z once a GitHub Release exists" >&2
    exit 1
  fi
  tag=$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$body" | head -n1)
  rm -f "$body"
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

ARCHIVE="denyout-cli_${VER_NUM}_${os}_${arch}.tar.gz"
SUMS="SHA256SUMS"
if [ -n "$BASE_URL" ]; then
  case "$BASE_URL" in
    https://*|file://*) ASSET_BASE="$BASE_URL" ;;
    *) echo "denyout install: BASE_URL must be https:// (or file:// for local tests)" >&2; exit 1 ;;
  esac
else
  ASSET_BASE="https://github.com/${REPO}/releases/download/${TAG}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT HUP

echo "denyout install: version=${TAG} os=${os} arch=${arch}"
echo "denyout install: fetching ${ASSET_BASE}/${ARCHIVE}"

fetch() {
  # $1 dest $2 url-or-path — required (exit on failure after retries)
  src=$2
  dest=$1
  case "$src" in
    http://*|https://*|file://*)
      if ! curl_fetch "$dest" "$src"; then
        echo "denyout install: failed to download after ${FETCH_RETRIES} tries: $src" >&2
        exit 1
      fi
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

# Verify the Sigstore (cosign keyless) signature of SHA256SUMS when possible.
#   DENYOUT_VERIFY_SIG=auto (default)  verify if cosign + signature are available, else warn
#   DENYOUT_VERIFY_SIG=require         fail unless the signature verifies
#   DENYOUT_VERIFY_SIG=skip            checksum only (corruption check, NOT authenticity)
verify_signature() {
  mode="${DENYOUT_VERIFY_SIG:-auto}"
  case "$mode" in auto|require|skip) ;; *) echo "denyout install: DENYOUT_VERIFY_SIG must be auto|require|skip" >&2; exit 1 ;; esac
  [ "$mode" = skip ] && { echo "denyout install: WARNING signature check skipped (checksum only)" >&2; return 0; }
  sig_ok=0
  if command -v cosign >/dev/null 2>&1 \
     && curl_fetch "${TMP}/${SUMS}.sig" "${ASSET_BASE}/${SUMS}.sig" optional \
     && curl_fetch "${TMP}/${SUMS}.pem" "${ASSET_BASE}/${SUMS}.pem" optional; then
    if cosign verify-blob \
        --certificate "${TMP}/${SUMS}.pem" --signature "${TMP}/${SUMS}.sig" \
        --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${TMP}/${SUMS}" >/dev/null 2>&1; then
      echo "denyout install: signature ok (cosign, GitHub Actions identity)"
      sig_ok=1
    else
      echo "denyout install: SIGNATURE VERIFICATION FAILED for ${SUMS}" >&2
      exit 1
    fi
  fi
  if [ "$sig_ok" -ne 1 ]; then
    if [ "$mode" = require ]; then
      echo "denyout install: signature required but cosign/signature unavailable (install cosign: https://docs.sigstore.dev)" >&2
      exit 1
    fi
    echo "denyout install: note: signature not verified (cosign or ${SUMS}.sig missing). Checksum only protects against corruption." >&2
  fi
}
verify_signature

# Verify checksum for this archive line in SHA256SUMS
expected=$(awk -v f="$ARCHIVE" '$2 == f || $2 == "./"f {print $1; exit}' "${TMP}/${SUMS}")
# Exact file-name match only (no substring match against other archives).
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
for cand in "${TMP}/denyout-cli" "${TMP}/bin/denyout-cli" "${TMP}/denyout-cli_${VER_NUM}_${os}_${arch}/denyout-cli"; do
  if [ -f "$cand" ]; then
    BIN=$cand
    break
  fi
done
if [ -z "$BIN" ]; then
  BIN=$(find "$TMP" -type f -name denyout-cli | head -n1 || true)
fi
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  echo "denyout install: denyout-cli binary not found in archive" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"

# Stop old tray/proxyd/desktop before overwriting binaries (ETXTBSY / duplicate trays).
# Hostguard rules are left for the new process to Apply once (no Remove+Apply).
if command -v pkill >/dev/null 2>&1; then
  pkill -x denyout 2>/dev/null || true
  pkill -f '[d]enyout-cli[[:space:]]+desktop' 2>/dev/null || true
  pkill -f '[d]enyout-cli[[:space:]]+hostctl[[:space:]]+proxyd' 2>/dev/null || true
  sleep 0.4 || true
fi

install -m 0755 "$BIN" "${INSTALL_DIR}/denyout-cli"
echo "denyout install: installed ${INSTALL_DIR}/denyout-cli"

# Optional second artifact: denyout (Wails GUI). Best-effort; CLI tray still works without it.
# Archives may contain denyout or denyout_<tag>_<os>_<arch>[.exe].
GUI_ARCHIVE="denyout_${TAG}_${os}_${arch}.tar.gz"
GUI_DEST="${INSTALL_DIR}/denyout"
if [ "$os" = "windows" ]; then
  GUI_DEST="${INSTALL_DIR}/denyout.exe"
fi
# verify_gui_archive: cosign signature (release-desktop.yml identity) over the archive.
# Returns 0 = ok/allowed, 1 = must not install.
verify_gui_archive() {
  mode="${DENYOUT_VERIFY_SIG:-auto}"
  [ "$mode" = skip ] && return 0
  if command -v cosign >/dev/null 2>&1 \
     && curl_fetch "${TMP}/${GUI_ARCHIVE}.sig" "${ASSET_BASE}/${GUI_ARCHIVE}.sig" optional \
     && curl_fetch "${TMP}/${GUI_ARCHIVE}.pem" "${ASSET_BASE}/${GUI_ARCHIVE}.pem" optional; then
    if cosign verify-blob \
        --certificate "${TMP}/${GUI_ARCHIVE}.pem" --signature "${TMP}/${GUI_ARCHIVE}.sig" \
        --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release-desktop\.yml@refs/tags/v" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${TMP}/${GUI_ARCHIVE}" >/dev/null 2>&1; then
      echo "denyout install: GUI signature ok (cosign, GitHub Actions identity)"
      return 0
    fi
    echo "denyout install: SIGNATURE VERIFICATION FAILED for ${GUI_ARCHIVE} - GUI not installed" >&2
    return 1
  fi
  if [ "$mode" = require ]; then
    echo "denyout install: signature required but cosign/signature unavailable for ${GUI_ARCHIVE} - GUI not installed" >&2
    return 1
  fi
  echo "denyout install: note: ${GUI_ARCHIVE} signature not verified (cosign or .sig missing)" >&2
  return 0
}

if curl_fetch "${TMP}/${GUI_ARCHIVE}" "${ASSET_BASE}/${GUI_ARCHIVE}" optional && ! verify_gui_archive; then
  echo "denyout install: note - skipping GUI (CLI tray still available)" >&2
elif [ -f "${TMP}/${GUI_ARCHIVE}" ]; then
  tar -xzf "${TMP}/${GUI_ARCHIVE}" -C "$TMP"
  DBIN=$(find "$TMP" -type f \( -name 'denyout' -o -name 'denyout.exe' \) ! -name 'denyout-cli*' | head -n1 || true)
  if [ -z "$DBIN" ]; then
    DBIN=$(find "$TMP" -type f \( -name "denyout_${TAG}_${os}_${arch}" -o -name "denyout_${TAG}_${os}_${arch}.exe" \) | head -n1 || true)
  fi
  if [ -n "$DBIN" ] && [ -f "$DBIN" ]; then
    if command -v pkill >/dev/null 2>&1; then
      pkill -x denyout 2>/dev/null || true
      sleep 0.2 || true
    fi
    install -m 0755 "$DBIN" "$GUI_DEST"
    echo "denyout install: installed ${GUI_DEST}"
  else
    echo "denyout install: note - ${GUI_ARCHIVE} has no denyout binary (CLI tray still available)" >&2
  fi
else
  echo "denyout install: note - denyout GUI still unreachable after ${FETCH_RETRIES} tries (CLI tray still available)" >&2
fi

# Warn about other denyout binaries on PATH (do not delete system copies).
warn_stale_on_path() {
  name=$1
  IFS=':'
  for d in $PATH; do
    [ -n "$d" ] || continue
    case "$d" in
      "$INSTALL_DIR") continue ;;
    esac
    if [ -x "${d}/${name}" ] && [ ! -d "${d}/${name}" ]; then
      echo "denyout install: warning - stale ${name} on PATH: ${d}/${name} (install dir is ${INSTALL_DIR})" >&2
      echo "  remove or rename it so upgrades use ${INSTALL_DIR}/${name}" >&2
    fi
  done
  unset IFS
}
warn_stale_on_path denyout
warn_stale_on_path denyout-cli

case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "denyout install: note - add ${INSTALL_DIR} to PATH if 'denyout' / 'denyout-cli' is not found" >&2
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" >&2
    ;;
esac

"${INSTALL_DIR}/denyout-cli" version || true
if [ -x "${INSTALL_DIR}/denyout" ]; then
  "${INSTALL_DIR}/denyout" --version || true
fi

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
  echo "  denyout-cli init"
  echo "  denyout-cli run -- <your-agent>"
  echo "  denyout-cli serve --config ~/.config/denyout/config.yaml   # optional long-running"
  echo ""
  exit 0
fi

echo ""
echo "Desktop install — no password yet. Opening DenyOut to choose protection…"
echo ""

# Install() detaches sibling Wails `denyout` when present; else CLI tray fallback.
"${INSTALL_DIR}/denyout-cli" desktop --install
exit $?
