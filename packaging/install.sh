#!/bin/sh
# maruhi install script(Unix: linux-x64 / linux-arm64 / darwin-x64 / darwin-arm64)
#
#   curl -fsSL https://raw.githubusercontent.com/maruhiapp/maruhi/<tag>/packaging/install.sh -o install.sh
#   less install.sh          # the right path is to read it first, then run it
#   sh install.sh --version <tag>
#
# Design (docs/adr/0015-cli-distribution.md / README.md):
# - The only external access is fetching from github.com. No telemetry
#   or outbound traffic (CLAUDE.md's "does not say")
# - SHA-256 verification against checksums.txt is mandatory; nothing
#   is written to the install destination until verification passes.
#   On a mid-way failure it exits non-zero leaving no partial files
# - Never says "signature verification": checksums.txt is unsigned at
#   this point and the completeness guarantee rests solely on TLS to
#   github.com. It does not pretend to verify what is not there
#   (signature support is on the ROADMAP)
# - `mh` is created as a relative symlink to maruhi (ADR-0015
#   rulings 6/7)
# - Shell config files (~/.zshrc etc.) are never rewritten. The
#   PATH-adding line is only displayed
# - Never invokes sudo. The default install destination is
#   ~/.local/bin
#
# The whole body is wrapped in main() and called on the last line.
# This blocks a `curl | sh` truncated mid-transfer from running
# half-way.

# `local` is undefined by POSIX, yet dash/ash/bash/zsh/busybox all
# implement it, and the alternative (all-global variables) breeds
# cross-function mix-ups. Deliberately deviated only here
# shellcheck disable=SC3043

set -eu

REPO="maruhiapp/maruhi"
RELEASES_URL="https://github.com/${REPO}/releases"

# The supported targets. apps/cli/test/installer.test.ts checks that
# this matches the 4 entries of apps/cli/scripts/shared.ts's TARGETS
# minus windows-x64 (the target table is not duplicated and left to
# drift).
SUPPORTED_TARGETS="linux-x64 linux-arm64 darwin-x64 darwin-arm64"

# Every variable referenced under set -u is initialized here
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

# No "intermediate state" is left on a failure path either. TMP_DIR
# is the whole work set; PARTIAL_FILE is the temporary file just
# before being renamed into the install destination
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
  # Linux uses coreutils' sha256sum, macOS uses shasum. With neither
  # present it does not install (no install without verification)
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
      # The shipped binaries link glibc (no musl target is
      # published). If not stopped here, it fails at run time with an
      # "not found" that looks unrelated
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
          # uname -m seen from sh under Rosetta is x86_64. Install
          # the native build
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
  # A value that ends up on a URL. Unexpected characters are
  # rejected here. `+` (build metadata) is excluded by the
  # producer-side SEMVER_PATTERN (scripts/shared.ts) too = the
  # convention is that it is never used in a tag, so the fetch
  # side's acceptance range aligns with that
  case "${VERSION}" in
    *[!A-Za-z0-9.-]*) die "version contains characters that are not allowed: ${VERSION}" ;;
  esac
}

resolve_version() {
  local resolved
  if [ -n "${VERSION}" ]; then
    normalize_version
  elif [ -n "${BASE_URL}" ]; then
    # Mirror given + no version: neither tag resolution nor version
    # collation is done
    return 0
  else
    # Does not depend on the GitHub API (60 req/h unauthenticated +
    # JSON parsing); reads the releases/latest redirect's target tag
    # instead. A pre-release never becomes latest, so during the rc
    # period it cannot resolve here = an explicit error, never a
    # guess.
    #
    # The success branch cannot be exercised in CI until a stable
    # release exists (the harness sets MARUHI_BASE_URL = the path
    # that skips resolution). The failure side is an explicit error
    # asking for a tag — it never falls to the dangerous side.
    # Verify once by hand after the first stable tag
    # (docs/RELEASING.md)
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
  # -f: HTTP errors to non-zero / -L: follow redirects (Release
  # assets 302 to objects.githubusercontent.com) / --retry: only
  # transient failures
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

  # checksums.txt is sha256sum -c compatible (64 hex digits + 2
  # spaces + filename).
  # Only our own target's line is extracted and verified (the other
  # targets' archives are not present, so it does not rely on the
  # implementation-divergent --ignore-missing). A count other than 1
  # line or a wrong format is dangerous whether it is tampering or a
  # generation accident, so it is refused
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

  # Confirm it starts before touching the install destination. Only
  # this ordering lets a wrong target or a libc mismatch be treated
  # as a "failure that left nothing"
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

  # If the replacement destination is not a regular file (e.g. a
  # directory), mv would slip inside it — a state of "thought it
  # installed, but it didn't". Stop early
  if [ -e "${INSTALL_DIR}/maruhi" ] && [ ! -f "${INSTALL_DIR}/maruhi" ]; then
    die "${INSTALL_DIR}/maruhi is not a regular file. Move it aside and retry, or pick another location with --dir"
  fi

  # Place it inside the same directory, then rename: never shows a
  # half-written executable and also avoids overwriting a running
  # binary (ETXTBSY)
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
    # Make it a relative symlink (survives the whole directory
    # moving)
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
