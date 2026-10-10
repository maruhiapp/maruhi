#!/usr/bin/env bash
# install-headless-shell.sh — installs the Chrome Headless Shell that the
# pinned Playwright expects into ~/.cache/chrome-headless-shell, and prints the
# path of its executable (the value for PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH)
# as its only line on stdout. The single browser installer for every
# environment this repository sets up that downloads one: CI (ci.yml, before
# the Playwright steps) and the Cursor Cloud startup install script. Claude
# Code on the web downloads none: its SessionStart hook points the tests at
# that environment's preinstalled build. It does not edit shell profiles:
# each caller sets PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH its own way
# (GITHUB_ENV, ~/.bashrc).
#
# The archive is checked against the SHA-256 pinned below before it is
# unpacked. Do not go back to `playwright install`: it downloads, unpacks and
# runs `ldd` on the binaries in one process with no digest check, so a
# tampered CDN object would execute. The tests take the binary through
# PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, and Playwright's own browser directory
# stays empty, so a test that ignores the variable fails instead of running
# an unverified browser.
#
# The archive comes from the Chrome for Testing bucket, where
# cdn.playwright.dev redirects Playwright's own download (the same bytes:
# measured identical SHA-256 through both URLs). Google publishes no digest
# or signature for it, so the pin is trust on first use at bump time. On a
# Playwright bump: take browserVersion of chromium-headless-shell from
# playwright-core's browsers.json (apps/cli/test/workflows-supply-chain.test.ts
# prints it), download
# https://cdn.playwright.dev/builds/cft/<version>/linux64/chrome-headless-shell-linux64.zip
# and the storage.googleapis.com URL below, check that both give the same
# SHA-256 and that it matches the bucket's `x-goog-hash: md5=` header, then
# pin both values here. `bun run check` fails until the version is the one
# the new Playwright expects; a stale SHA-256 fails this script.
#
# Only linux64 is supported (CI runners, Cursor Cloud). Another platform is
# refused rather than guessed: pin its archive the same way if one is ever
# needed.
#
# Usage: scripts/install-headless-shell.sh
set -euo pipefail

CHROME_HEADLESS_SHELL_VERSION="156.0.8078.4"
CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256="c3e50596aef52c58f8fda3c6b3411c33d34c88b177b3ed1c2243359fd3b8ba20"

die() {
  # A workflow command, so the reason is annotated on the GitHub Actions run
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error::install-headless-shell: $*" >&2
  else
    echo "install-headless-shell: $*" >&2
  fi
  exit 1
}

if [ "$#" -ne 0 ]; then
  die "takes no arguments (usage: scripts/install-headless-shell.sh)"
fi

platform="$(uname -s)/$(uname -m)"
if [ "${platform}" != "Linux/x86_64" ]; then
  die "the pinned headless shell is linux64 only (got ${platform})"
fi

install_root="${HOME}/.cache/chrome-headless-shell"
tree="chrome-headless-shell-linux64"
mkdir -p "${install_root}"
# Next to the install, so the verified tree is moved in by a rename
work="$(mktemp -d "${install_root}/.partial.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
zip="${work}/${tree}.zip"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --retry 3 --retry-all-errors --output "${zip}" \
  "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_HEADLESS_SHELL_VERSION}/linux64/${tree}.zip" ||
  die "downloading ${tree}.zip failed"
# stdout carries only the executable's path, so the check reports on stderr
if ! echo "${CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256}  ${zip}" | sha256sum --check --strict >&2; then
  die "${tree}.zip does not match the pinned SHA-256; nothing was installed"
fi
unzip -q "${zip}" -d "${work}/new" || die "unpacking ${tree}.zip failed"
rm -f "${zip}"
if [ ! -x "${work}/new/${tree}/chrome-headless-shell" ]; then
  die "${tree}.zip has no ${tree}/chrome-headless-shell; nothing was installed"
fi

# Replace an older install only with a complete new one (the trap removes it)
if [ -e "${install_root}/${tree}" ]; then
  mv "${install_root}/${tree}" "${work}/old"
fi
mv "${work}/new/${tree}" "${install_root}/${tree}"
echo "${install_root}/${tree}/chrome-headless-shell"
