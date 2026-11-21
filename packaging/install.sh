#!/bin/sh

# `local` is undefined by POSIX, yet dash/ash/bash/zsh/busybox all
# implement it, and the alternative (all-global variables) breeds
# cross-function mix-ups. Deliberately deviated only here
# shellcheck disable=SC3043

set -eu

REPO="maruhiapp/maruhi"
RELEASES_URL="https://github.com/${REPO}/releases"

SUPPORTED_TARGETS="linux-x64 linux-arm64 darwin-x64 darwin-arm64"

VERSION=""
INSTALL_DIR=""
BASE_URL=""
EXPECTED_VERSION=""
INSTALLED_VERSION=""
TARGET=""
ARCHIVE=""
BINARY=""
SHA_TOOL=""
MH_LINKED="0"
TMP_DIR=""
PARTIAL_FILE=""

log() { printf '%s\n' "$*"; }
warn() { printf 'maruhi: warning: %s\n' "$*" >&2; }
die() {
  printf 'maruhi: error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${TMP_DIR}" ]; then rm -rf "${TMP_DIR}"; fi
  if [ -n "${PARTIAL_FILE}" ]; then rm -f "${PARTIAL_FILE}"; fi
}

usage() {
  cat <<EOF
maruhi install script (Unix)

Usage:
  sh install.sh [--version <tag>] [--dir <path>]
  curl -fsSL <URL of this script> | sh -s -- --version <tag>

Options:
  --version <tag>   Version to install (example: v0.1.0-rc.1). If omitted, the
                    latest stable release is resolved from
                    ${RELEASES_URL}/latest.
                    During the pre-release period latest does not exist, so a
                    tag is required
  --dir <path>      Install directory (default: ~/.local/bin). Does not invoke sudo
  -h, --help        Show this help

Environment variables:
  MARUHI_VERSION      Same as --version (--version wins)
  MARUHI_INSTALL_DIR  Same as --dir (--dir wins)
  MARUHI_BASE_URL     Override the asset download directory (internal mirrors
                      and local verification; example: file:///path/to/dist).
                      When set, GitHub tag resolution is skipped and a version
                      flag is used only as the expected value for the startup check

Supported targets: ${SUPPORTED_TARGETS}
Windows is not supported (see the manual steps in the README).
This script does not talk to anything other than github.com.
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version)
        shift
        [ $# -gt 0 ] || die "--version requires a tag (example: --version v0.1.0-rc.1)"
        VERSION="$1"
        ;;
      --version=*) VERSION="${1#--version=}" ;;
      --dir)
        shift
        [ $# -gt 0 ] || die "--dir requires a path"
        INSTALL_DIR="$1"
        ;;
      --dir=*) INSTALL_DIR="${1#--dir=}" ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
  done
}

require_tools() {
  local cmd
  for cmd in curl tar grep mktemp uname; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      die "${cmd} is required"
    fi
  done
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_TOOL="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    SHA_TOOL="shasum"
  else
    die "neither sha256sum nor shasum was found. Will not install without checksum verification"
  fi
}

sha_check() {
  case "${SHA_TOOL}" in
    sha256sum) sha256sum -c "$1" ;;
    shasum) shasum -a 256 -c "$1" ;;
    *) die "internal error: unknown checksum tool ${SHA_TOOL}" ;;
  esac
}

detect_target() {
  local os arch musl
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}" in
    Linux)
      for musl in /lib/ld-musl-*.so.1; do
        if [ -e "${musl}" ]; then
          die "no binary is published for musl libc (Alpine and similar). Use a glibc environment, or install via Bun (bun install -g maruhi)"
        fi
      done
      case "${arch}" in
        x86_64 | amd64) TARGET="linux-x64" ;;
        aarch64 | arm64) TARGET="linux-arm64" ;;
        *) die "unsupported CPU architecture: ${arch} (supported: ${SUPPORTED_TARGETS})" ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        arm64) TARGET="darwin-arm64" ;;
        x86_64)
          if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')" = "1" ]; then
            TARGET="darwin-arm64"
          else
            TARGET="darwin-x64"
          fi
          ;;
        *) die "unsupported CPU architecture: ${arch} (supported: ${SUPPORTED_TARGETS})" ;;
      esac
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      die "Windows is not supported by this script. See the README for the manual tar steps: https://github.com/${REPO}"
      ;;
    *) die "unsupported OS: ${os} (supported: ${SUPPORTED_TARGETS})" ;;
  esac
}

normalize_version() {
  case "${VERSION}" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
  esac
  case "${VERSION}" in
    v[0-9]*) ;;
    *) die "specify the version as v0.1.0 or 0.1.0: ${VERSION}" ;;
  esac
  case "${VERSION}" in
    *[!A-Za-z0-9.-]*) die "version contains characters that are not allowed: ${VERSION}" ;;
  esac
}

resolve_version() {
  local resolved
  if [ -n "${VERSION}" ]; then
    normalize_version
  elif [ -n "${BASE_URL}" ]; then
    return 0
  else
    resolved="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${RELEASES_URL}/latest" 2>/dev/null)" || resolved=""
    case "${resolved}" in
      */releases/tag/?*) VERSION="${resolved##*/releases/tag/}" ;;
      *)
        die "could not resolve the latest stable release. During the pre-release period, releases/latest does not exist — pass a tag such as --version v0.1.0-rc.1 (list: ${RELEASES_URL})"
        ;;
    esac
    normalize_version
  fi
  EXPECTED_VERSION="${VERSION#v}"
}

resolve_base_url() {
  if [ -n "${BASE_URL}" ]; then
    BASE_URL="${BASE_URL%/}"
  else
    BASE_URL="${RELEASES_URL}/download/${VERSION}"
  fi
}

fetch() {
  if ! curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"; then
    die "download failed: $1"
  fi
}

download_and_verify() {
  local pattern matches
  ARCHIVE="maruhi-${TARGET}.tar.gz"
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/maruhi-install.XXXXXX")" || die "could not create a working directory"
  trap cleanup EXIT INT TERM

  fetch "${BASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt"
  fetch "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"

  pattern="^[0-9a-f]{64}  maruhi-${TARGET}\.tar\.gz\$"
  matches="$(grep -E -c "${pattern}" "${TMP_DIR}/checksums.txt" || true)"
  if [ "${matches}" != "1" ]; then
    die "checksums.txt does not contain exactly one line for ${ARCHIVE} (${matches:-0} lines). Check the source: ${BASE_URL}/checksums.txt"
  fi
  grep -E "${pattern}" "${TMP_DIR}/checksums.txt" >"${TMP_DIR}/checksums.filtered"

  if ! (cd "${TMP_DIR}" && sha_check checksums.filtered); then
    die "SHA-256 mismatch (${ARCHIVE}). Check the source and the network path. Nothing was installed"
  fi
}

extract_and_check() {
  local got
  mkdir -p "${TMP_DIR}/extract"
  tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}/extract" || die "could not extract the archive (${ARCHIVE})"
  BINARY="${TMP_DIR}/extract/maruhi"
  [ -f "${BINARY}" ] || die "archive contents are not what was expected (maruhi is missing)"
  chmod 755 "${BINARY}"

  got="$("${BINARY}" --version)" || die "could not run the downloaded binary (target: ${TARGET})"
  if [ -n "${EXPECTED_VERSION}" ] && [ "${got}" != "${EXPECTED_VERSION}" ]; then
    die "version mismatch (expected ${EXPECTED_VERSION} / got ${got}). The assets may have been mixed up"
  fi
  INSTALLED_VERSION="${got}"
}

install_binary() {
  mkdir -p "${INSTALL_DIR}" || die "could not create the install directory: ${INSTALL_DIR}"
  INSTALL_DIR="$(cd "${INSTALL_DIR}" && pwd)"
  [ -w "${INSTALL_DIR}" ] || die "cannot write to ${INSTALL_DIR} (change it with --dir. This script does not invoke sudo)"

  if [ -e "${INSTALL_DIR}/maruhi" ] && [ ! -f "${INSTALL_DIR}/maruhi" ]; then
    die "${INSTALL_DIR}/maruhi is not a regular file. Move it aside and retry, or pick another location with --dir"
  fi

  PARTIAL_FILE="$(mktemp "${INSTALL_DIR}/.maruhi.install.XXXXXX")" ||
    die "could not create a staging file in the install directory: ${INSTALL_DIR}"
  cp "${BINARY}" "${PARTIAL_FILE}" || die "could not copy to the install directory: ${INSTALL_DIR}"
  chmod 755 "${PARTIAL_FILE}"
  mv -f "${PARTIAL_FILE}" "${INSTALL_DIR}/maruhi" || die "failed to install: ${INSTALL_DIR}/maruhi"
  PARTIAL_FILE=""
}

link_alias() {
  local link current
  link="${INSTALL_DIR}/mh"
  if [ -L "${link}" ]; then
    current="$(readlink "${link}" 2>/dev/null || printf '')"
    case "${current}" in
      maruhi | "${INSTALL_DIR}/maruhi") ln -sf maruhi "${link}" ;;
      *)
        warn "${link} is a symlink that does not point to maruhi; leaving it alone (currently: ${current})"
        return 0
        ;;
    esac
  elif [ -e "${link}" ]; then
    warn "${link} already exists (not a symlink). Will not create the mh alias"
    return 0
  else
    ln -s maruhi "${link}" || die "could not create the mh symlink: ${link}"
  fi
  MH_LINKED="1"
}

report() {
  local rc_hint path_line
  log "installed maruhi ${INSTALLED_VERSION} to ${INSTALL_DIR}/maruhi (${TARGET})"
  if [ "${MH_LINKED}" = "1" ]; then
    log "alias: ${INSTALL_DIR}/mh -> maruhi"
  fi
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      # rc_hint is guidance text shown on screen, not a path this
      # script opens
      # (which is why an unexpanded `~` is fine)
      # shellcheck disable=SC2088
      case "$(basename "${SHELL:-sh}")" in
        fish)
          rc_hint="~/.config/fish/config.fish"
          path_line="fish_add_path ${INSTALL_DIR}"
          ;;
        zsh)
          rc_hint="~/.zshrc"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
        bash)
          rc_hint="~/.bashrc"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
        *)
          rc_hint="your shell config file"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
      esac
      log ""
      log "${INSTALL_DIR} is not on PATH. Add the following line to ${rc_hint}:"
      log "  ${path_line}"
      log "(this script does not modify your config files)"
      ;;
  esac
  log ""
  log "next: maruhi --help"
}

main() {
  parse_args "$@"
  VERSION="${VERSION:-${MARUHI_VERSION:-}}"
  INSTALL_DIR="${INSTALL_DIR:-${MARUHI_INSTALL_DIR:-}}"
  BASE_URL="${MARUHI_BASE_URL:-}"

  if [ -z "${INSTALL_DIR}" ]; then
    [ -n "${HOME:-}" ] || die "HOME is unset. Pass an install directory with --dir"
    INSTALL_DIR="${HOME}/.local/bin"
  fi

  require_tools
  detect_target
  resolve_version
  resolve_base_url
  download_and_verify
  extract_and_check
  install_binary
  link_alias
  report
}

main "$@"
