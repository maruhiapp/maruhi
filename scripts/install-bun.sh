#!/usr/bin/env bash
set -euo pipefail

BUN_VERSION="1.4.4"
BUN_LINUX_X64_ZIP_SHA256="bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c"
BUN_LINUX_X64_BASELINE_ZIP_SHA256="e0446eb55995772eb9894bebae9a6be368d985a8b9271ee124486f9946eedd76"

die() {
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
cp "${work}/bun" "${bin_dir}/.bun.partial"
mv -f "${bin_dir}/.bun.partial" "${bin_dir}/bun"
ln -sf bun "${bin_dir}/bunx"
"${bin_dir}/bun" --revision
