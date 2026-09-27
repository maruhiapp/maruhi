#!/usr/bin/env bash
# A live-run test of packaging/install.sh (positive cases + tampered
# negative cases).
#
#   bun run --filter @maruhi/cli build:binaries   # build the artifacts first
#   packaging/install-test.sh --dist apps/cli/dist --target linux-x64 --version 0.1.0-rc.1
#
# It does not depend on a real release: it uses install.sh's
# MARUHI_BASE_URL to install the local artifacts (build:binaries'
# output) from both http://127.0.0.1 and file://.
# CI (.github/workflows/installer.yml) runs this on the same real
# runners for the unix 4 targets as release.yml's smoke.
#
# The negative cases are 5: "one character of checksums.txt tampered",
# "one byte of the archive tampered", "asset missing", "replacement
# destination not a regular file", and "version mismatch". Each must
# exit non-zero, and the test checks all the way down to no partial
# files left at the install destination (never building a shape whose
# bypassing verification would go unnoticed).
set -euo pipefail

DIST=""
TARGET=""
VERSION=""
PORT=""
SERVER_PID=""
WORK=""
FAILURES=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="${SCRIPT_DIR}/install.sh"

usage() {
  cat <<EOF
Usage: install-test.sh --dist <dir> --target <name> --version <x.y.z>

  --dist     The directory holding maruhi-<target>.tar.gz and checksums.txt
  --target   The target under test (example: linux-x64). Must match
             the target install.sh detects on this runner
  --version  The expected \`maruhi --version\` output (no v prefix)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n ${DIST} && -n ${TARGET} && -n ${VERSION} ]] || {
  usage >&2
  exit 2
}

DIST="$(cd "${DIST}" && pwd)"
ARCHIVE="maruhi-${TARGET}.tar.gz"
[[ -f "${DIST}/${ARCHIVE}" ]] || {
  echo "artifact missing: ${DIST}/${ARCHIVE}" >&2
  exit 2
}
[[ -f "${DIST}/checksums.txt" ]] || {
  echo "artifact missing: ${DIST}/checksums.txt" >&2
  exit 2
}
# For the local http fixture (install.sh itself requires only curl /
# tar / sha256-family tools)
command -v python3 >/dev/null || {
  echo "python3 is required (to bring up the local http fixture)" >&2
  exit 2
}

cleanup() {
  if [[ -n ${SERVER_PID} ]]; then kill "${SERVER_PID}" 2>/dev/null || true; fi
  if [[ -n ${WORK} ]]; then rm -rf "${WORK}"; fi
}
trap cleanup EXIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/maruhi-install-test.XXXXXX")"
mkdir -p "${WORK}/serve"

# The pristine artifacts (the positive case). Every later case
# duplicates and tampers these
new_case() {
  local name="$1"
  local dir="${WORK}/serve/${name}"
  mkdir -p "${dir}"
  cp "${DIST}/${ARCHIVE}" "${DIST}/checksums.txt" "${dir}/"
  printf '%s' "${dir}"
}

start_server() {
  local log="${WORK}/server.log"
  # port 0 = an OS-assigned free port (no collisions under parallel
  # runs).
  # `python3 -m http.server`'s startup message is not parsed — stdout
  # aimed at a file is block-buffered, and the wording varies by
  # version (actually hit on CI).
  # Take the port ourselves and print it flushed
  python3 -u -c '
import functools, http.server, socketserver, sys

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
    print(httpd.server_address[1], flush=True)
    httpd.serve_forever()
' "${WORK}/serve" >"${log}" 2>&1 &
  SERVER_PID=$!
  # The cleanup kill makes bash emit an asynchronous "Terminated"
  # notice and the whole python program flows into the log tail
  # (confirmed on real runners). Disown it from the job table to
  # silence it
  disown "${SERVER_PID}" 2>/dev/null || true
  local i
  for ((i = 0; i < 100; i++)); do
    PORT="$(head -n 1 "${log}" 2>/dev/null || true)"
    if [[ ${PORT} =~ ^[0-9]+$ ]]; then return; fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then break; fi
    sleep 0.1
  done
  PORT=""
  cat "${log}" >&2
  echo "could not start the http server" >&2
  exit 2
}

pass() { echo "  ok: $1"; }
fail() {
  echo "  NG: $1" >&2
  FAILURES=$((FAILURES + 1))
}

# check <label> <command...>: count ok / NG by the command's exit
# status.
# The `A && pass || fail` shape is not used — a failing pass would
# still run fail even when A is true
check() {
  local label="$1"
  shift
  if "$@"; then pass "${label}"; else fail "${label}"; fi
}

# That nothing remains at the install destination (no partial files,
# no non-empty contents)
assert_clean_dest() {
  local dest="$1" label="$2"
  if [[ ! -e ${dest} ]]; then
    pass "${label}: never created the install destination"
    return
  fi
  local leftovers
  leftovers="$(ls -A "${dest}")"
  if [[ -z ${leftovers} ]]; then
    pass "${label}: install destination stayed empty"
  else
    fail "${label}: intermediate state left behind: ${leftovers}"
  fi
}

run_install() {
  local base="$1" dest="$2"
  shift 2
  MARUHI_BASE_URL="${base}" sh "${INSTALL_SH}" --dir "${dest}" "$@" 2>&1
}

# ---- Positive case 1: installs over http; mh points at the same binary --
case_http_ok() {
  local dest out
  new_case http-ok >/dev/null
  dest="${WORK}/dest/http-ok"
  if ! out="$(run_install "http://127.0.0.1:${PORT}/http-ok" "${dest}" --version "${VERSION}")"; then
    fail "http positive: failed"
    echo "${out}" >&2
    return
  fi
  check "http positive: installed maruhi" test -x "${dest}/maruhi"
  check "http positive: --version is ${VERSION}" test "$("${dest}/maruhi" --version)" = "${VERSION}"
  check "http positive: mh is a relative symlink to maruhi" test "$(readlink "${dest}/mh")" = "maruhi"
  check "http positive: mh starts too" test "$("${dest}/mh" --version)" = "${VERSION}"
}

# ---- Positive case 2: via file:// (the internal-mirror / local-artifact path) --
case_file_ok() {
  local dir dest out
  dir="$(new_case file-ok)"
  dest="${WORK}/dest/file-ok"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "file positive: failed"
    echo "${out}" >&2
    return
  fi
  check "file positive: installed maruhi" test -x "${dest}/maruhi"
  check "file positive: mh is created too" test "$(readlink "${dest}/mh")" = "maruhi"
}

# ---- Positive case 3: reinstall (idempotent) + does not crush someone else's mh --
case_reinstall_and_foreign_mh() {
  local dir dest out
  dir="$(new_case reinstall)"
  dest="${WORK}/dest/reinstall"
  mkdir -p "${dest}"
  # Leave another tool's mh in place (a real file, not a symlink)
  printf '#!/bin/sh\necho other\n' >"${dest}/mh"
  chmod 755 "${dest}/mh"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "reinstall: failed"
    echo "${out}" >&2
    return
  fi
  check "reinstall: kept the foreign mh" test "$("${dest}/mh")" = "other"
  check "reinstall: warned about mh" grep -q "already exists (not a symlink)" <<<"${out}"
  # Second run (overwrites the existing maruhi)
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "reinstall: second run failed"
    echo "${out}" >&2
    return
  fi
  check "reinstall: overwrites" test "$("${dest}/maruhi" --version)" = "${VERSION}"
}

# ---- Positive case 4: an existing mh that is "a symlink to
# something else" is not relinked ------------------------------------------------
# The only branch of link_alias that can reach `ln -sf`. A different
# path than the regular-file branch (positive case 3), so it is
# exercised separately
case_foreign_mh_symlink() {
  local dir dest out
  dir="$(new_case foreign-mh-symlink)"
  dest="${WORK}/dest/foreign-mh-symlink"
  mkdir -p "${dest}"
  printf '#!/bin/sh\necho other\n' >"${dest}/other-tool"
  chmod 755 "${dest}/other-tool"
  ln -s other-tool "${dest}/mh"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "foreign mh symlink: failed"
    echo "${out}" >&2
    return
  fi
  check "foreign mh symlink: not relinked" test "$(readlink "${dest}/mh")" = "other-tool"
  check "foreign mh symlink: warned" grep -q "does not point to maruhi" <<<"${out}"
  check "foreign mh symlink: maruhi itself installs" test -x "${dest}/maruhi"
}

# ---- Negative case 1: one character of checksums.txt tampered (the body of the mutation verification) --
case_tampered_checksums() {
  local dir dest out
  dir="$(new_case tampered-checksums)"
  # Replace only the first hex character of our own target's line
  # with a different hex digit. The format (64 digits + 2 spaces) is
  # kept = exercises the SHA-256 comparison itself, not the format
  # check
  awk -v target="${ARCHIVE}" '
    $2 == target {
      first = substr($1, 1, 1)
      newfirst = (first == "0" ? "1" : "0")
      printf "%s%s  %s\n", newfirst, substr($1, 2), $2
      next
    }
    { print }
  ' "${DIST}/checksums.txt" >"${dir}/checksums.txt"
  if diff -q "${DIST}/checksums.txt" "${dir}/checksums.txt" >/dev/null; then
    fail "tampered checksums: could not tamper (a defect in the test itself)"
    return
  fi
  if ! grep -qE "^[0-9a-f]{64}  ${ARCHIVE}\$" "${dir}/checksums.txt"; then
    fail "tampered checksums: the format broke (the test no longer exercises the SHA comparison)"
    return
  fi
  dest="${WORK}/dest/tampered-checksums"
  if out="$(run_install "http://127.0.0.1:${PORT}/tampered-checksums" "${dest}" --version "${VERSION}")"; then
    fail "tampered checksums: the install succeeded"
    echo "${out}" >&2
    return
  fi
  pass "tampered checksums: exited non-zero"
  check "tampered checksums: reported as a verification failure" grep -q "SHA-256" <<<"${out}"
  assert_clean_dest "${dest}" "tampered checksums"
}

# ---- Negative case 2: one byte of the archive tampered ------------------------
case_tampered_archive() {
  local dest out
  local dir
  dir="$(new_case tampered-archive)"
  # Tamper deterministically with a conditional like negative case 1.
  # Overwriting with a fixed character would flake on "could not
  # tamper" (1/256) when the original byte at that position happens
  # to be the same character
  local orig repl
  orig="$(dd if="${dir}/${ARCHIVE}" bs=1 skip=1024 count=1 2>/dev/null || true)"
  repl="$([ "${orig}" = "X" ] && echo "Y" || echo "X")"
  printf '%s' "${repl}" | dd of="${dir}/${ARCHIVE}" bs=1 seek=1024 conv=notrunc 2>/dev/null
  if cmp -s "${DIST}/${ARCHIVE}" "${dir}/${ARCHIVE}"; then
    fail "tampered archive: could not tamper (a defect in the test itself)"
    return
  fi
  dest="${WORK}/dest/tampered-archive"
  if out="$(run_install "http://127.0.0.1:${PORT}/tampered-archive" "${dest}" --version "${VERSION}")"; then
    fail "tampered archive: the install succeeded"
    echo "${out}" >&2
    return
  fi
  pass "tampered archive: exited non-zero"
  check "tampered archive: reported as a verification failure" grep -q "SHA-256" <<<"${out}"
  assert_clean_dest "${dest}" "tampered archive"
}

# ---- Negative case 3: asset missing (404) -------------------------------------
case_missing_asset() {
  local dir dest out
  dir="$(new_case missing-asset)"
  rm -f "${dir}/${ARCHIVE}"
  dest="${WORK}/dest/missing-asset"
  if out="$(run_install "http://127.0.0.1:${PORT}/missing-asset" "${dest}" --version "${VERSION}")"; then
    fail "asset missing: the install succeeded"
    echo "${out}" >&2
    return
  fi
  pass "asset missing: exited non-zero"
  check "asset missing: reported as a fetch failure" grep -q "download failed" <<<"${out}"
  assert_clean_dest "${dest}" "asset missing"
}

# ---- Negative case 4: the replacement destination is not a regular file
# (blocks the shape where mv slips inside it) ---------------------------------
case_dest_not_a_file() {
  local dir dest out
  dir="$(new_case dest-not-a-file)"
  dest="${WORK}/dest/dest-not-a-file"
  mkdir -p "${dest}/maruhi"
  if out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "destination not a file: the install succeeded"
    echo "${out}" >&2
    return
  fi
  pass "destination not a file: exited non-zero"
  check "destination not a file: reported the reason" grep -q "is not a regular file" <<<"${out}"
  check "destination not a file: did not slip inside" test -z "$(ls -A "${dest}/maruhi")"
}

# ---- Negative case 5: version mismatch (detects mixed-up assets) --------------
case_version_mismatch() {
  local dir dest out
  dir="$(new_case version-mismatch)"
  dest="${WORK}/dest/version-mismatch"
  if out="$(run_install "file://${dir}" "${dest}" --version "99.99.99")"; then
    fail "version mismatch: the install succeeded"
    echo "${out}" >&2
    return
  fi
  pass "version mismatch: exited non-zero"
  check "version mismatch: reported as a version mismatch" grep -q "version mismatch" <<<"${out}"
  assert_clean_dest "${dest}" "version mismatch"
}

echo "install.sh live-run test (target=${TARGET} version=${VERSION})"
start_server
echo "http fixture: http://127.0.0.1:${PORT}/"

case_http_ok
case_file_ok
case_reinstall_and_foreign_mh
case_foreign_mh_symlink
case_tampered_checksums
case_tampered_archive
case_missing_asset
case_dest_not_a_file
case_version_mismatch

if [[ ${FAILURES} -gt 0 ]]; then
  echo "failures: ${FAILURES}" >&2
  exit 1
fi
echo "all passed"
