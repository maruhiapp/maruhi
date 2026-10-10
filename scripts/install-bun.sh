#!/usr/bin/env bash
# install-bun.sh — installs the Bun that `.bun-version` pins into ~/.bun/bin.
# The single Bun installer for every environment this repository sets up: CI
# (through .github/actions/install-bun), the Claude Code on the web
# SessionStart hook (.claude/hooks/session-start.sh), and the Cursor Cloud
# startup install script. It does not edit shell profiles: each caller puts
# ~/.bun/bin on PATH its own way (GITHUB_PATH, CLAUDE_ENV_FILE, ~/.bashrc).
#
# The official release zip is verified against the SHA-256 pinned below
# before anything in it runs. Do not go back to `curl bun.sh/install | bash`
# (it runs an unverified script that fetches an unverified zip) or to
# oven-sh/setup-bun (see .github/actions/install-bun).
#
# Bumping Bun changes `.bun-version`, the three values below, and the release
# runtimes in apps/cli/scripts/bun-runtimes.ts together (the script fails
# closed on a mismatch, and apps/cli/test/dev-setup.test.ts and
# workflows-supply-chain.test.ts fail first in `bun run check`). The SHA-256
# lines come from the release's clearsigned SHASUMS256.txt.asc, signed by the
# Robobun key F3DCC08A8572C0749B3E18888EAB4D40A7B22B59. Check it with gpgv
# against a keyring holding that key only, and require that fingerprint in
# VALIDSIG:
#   curl -fsSL https://keys.openpgp.org/vks/v1/by-fingerprint/F3DCC08A8572C0749B3E18888EAB4D40A7B22B59 |
#     gpg --dearmor > robobun.gpg
#   rm -f shasums.txt
#   gpgv --status-fd 1 --keyring ./robobun.gpg --output shasums.txt SHASUMS256.txt.asc |
#     grep -q '^\[GNUPG:\] VALIDSIG .* F3DCC08A8572C0749B3E18888EAB4D40A7B22B59$' &&
#     grep -E ' bun-linux-x64(-baseline)?\.zip$' shasums.txt
# Not `gpg --decrypt … | grep`: it still prints the text after a BAD
# signature, and a plain gpg accepts a good signature from any key in the
# user's keyring.
#
# Only linux-x64 is supported (CI runners, Claude Code on the web, Cursor
# Cloud). A CPU without AVX2 gets the baseline build unless `--require-avx2`
# is passed (CI passes it, so every job runs the build the linux-x64 release
# runtime pin names). Another
# platform is refused rather than guessed: add its line from the verified
# SHASUMS256.txt if one is ever needed.
#
# Usage: scripts/install-bun.sh [--require-avx2]
set -euo pipefail

BUN_VERSION="1.4.2"
BUN_LINUX_X64_ZIP_SHA256="36368faef7527875d5ffa52e53cd48021741f2a83eb6208a8dd64068d422a913"
BUN_LINUX_X64_BASELINE_ZIP_SHA256="c678040f14fe0440eb839d37cbd0ce4c051a32da72806ac97de6a6aab6bf728f"

die() {
  # A workflow command, so the reason is annotated on the GitHub Actions run
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error::install-bun: $*" >&2
  else
    echo "install-bun: $*" >&2
  fi
  exit 1
}

require_avx2=false
for arg in "$@"; do
  case "${arg}" in
    --require-avx2) require_avx2=true ;;
    *) die "unknown argument: ${arg} (usage: scripts/install-bun.sh [--require-avx2])" ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wanted="$(cat "${repo_root}/.bun-version")"
if [ "${wanted}" != "${BUN_VERSION}" ]; then
  die ".bun-version is ${wanted} but scripts/install-bun.sh pins ${BUN_VERSION} (update the version and SHA-256s together)"
fi

platform="$(uname -s)/$(uname -m)"
if [ "${platform}" != "Linux/x86_64" ]; then
  die "only linux-x64 is supported (got ${platform})"
fi
if grep -qw avx2 /proc/cpuinfo; then
  target="linux-x64"
  sha256="${BUN_LINUX_X64_ZIP_SHA256}"
elif [ "${require_avx2}" = "true" ]; then
  die "this CPU has no AVX2, and --require-avx2 refuses the baseline build"
else
  target="linux-x64-baseline"
  sha256="${BUN_LINUX_X64_BASELINE_ZIP_SHA256}"
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
zip="${work}/bun-${target}.zip"
curl --fail --silent --show-error --location --proto '=https' --retry 3 --retry-all-errors \
  --output "${zip}" \
  "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-${target}.zip" ||
  die "downloading bun-${target}.zip failed"
if ! echo "${sha256}  ${zip}" | sha256sum --check --strict; then
  die "bun-${target}.zip does not match the pinned SHA-256; nothing was installed"
fi
unzip -q -j "${zip}" "bun-${target}/bun" -d "${work}" || die "unpacking bun-${target}.zip failed"

bin_dir="${HOME}/.bun/bin"
mkdir -p "${bin_dir}"
# Copy next to the target, then rename: replacing an older bun is atomic
cp "${work}/bun" "${bin_dir}/.bun.partial"
mv -f "${bin_dir}/.bun.partial" "${bin_dir}/bun"
ln -sf bun "${bin_dir}/bunx"
"${bin_dir}/bun" --revision
