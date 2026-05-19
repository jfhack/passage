#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help|help)
      cat <<EOF
usage: $0

Builds the passage binary from source and installs it. Asks to
confirm the install prefix (default /usr/local/bin) before copying.
EOF
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "usage: $0" >&2
      exit 2
      ;;
  esac
fi

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "this installer must run as root (try: sudo $0)" >&2
    exit 1
  fi
}

ask() {
  local prompt="$1" default="${2:-}" var
  if [[ -n "${default}" ]]; then
    read -r -p "${prompt} [${default}] " var
    echo "${var:-${default}}"
  else
    read -r -p "${prompt} " var
    echo "${var}"
  fi
}

ask_yes_no() {
  local prompt="$1" default="${2:-N}" ans label
  case "${default}" in
    y|Y|yes|Yes) label="[Y/n]" ;;
    *)           label="[y/N]" ;;
  esac
  read -r -p "${prompt} ${label} " ans
  case "${ans:-${default}}" in
    y|Y|yes|Yes) return 0 ;;
    *)           return 1 ;;
  esac
}

require_root

PREFIX="$(ask "install prefix?" "/usr/local/bin")"
if ! ask_yes_no "install passage binary to ${PREFIX}/passage?" "Y"; then
  echo "aborted by user."
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_SCRIPT="${ROOT_DIR}/scripts/build.sh"
DIST_BIN="${ROOT_DIR}/dist/passage"

if [[ ! -x "${BUILD_SCRIPT}" ]]; then
  echo "build script not found at ${BUILD_SCRIPT}" >&2
  exit 1
fi

echo "==> building binary"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  # Build as the invoking user so their Go toolchain (typically under
  # ~/go/bin or /usr/local/go/bin) is on PATH; building as root often
  # fails because root's PATH doesn't include go.
  sudo -u "${SUDO_USER}" -i bash -c "cd '${ROOT_DIR}' && '${BUILD_SCRIPT}'"
else
  ( cd "${ROOT_DIR}" && "${BUILD_SCRIPT}" )
fi

if [[ ! -x "${DIST_BIN}" ]]; then
  echo "build did not produce ${DIST_BIN}" >&2
  exit 1
fi

mkdir -p "${PREFIX}"
DEST="${PREFIX}/passage"
echo "==> installing binary to ${DEST}"
install -m 0755 "${DIST_BIN}" "${DEST}"

echo
echo "==> done. binary installed at ${DEST}"
echo "  - run 'passage help' to see subcommands"
