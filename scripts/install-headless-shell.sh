#!/usr/bin/env bash
set -euo pipefail

CHROME_HEADLESS_SHELL_VERSION="158.0.8127.18"
CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256="18352d22cb0cdf520cbff2ad8c41391f0e02a72886cb53b0fde4bdfc4bd075d6"

die() {
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
exec 9>"${install_root}/.lock"
flock 9 || die "could not lock ${install_root}/.lock"
work="$(mktemp -d "${install_root}/.partial.XXXXXX")"
trap 'rm -rf "${work}"' EXIT
zip="${work}/${tree}.zip"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --retry 3 --retry-all-errors --output "${zip}" \
  "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_HEADLESS_SHELL_VERSION}/linux64/${tree}.zip" ||
  die "downloading ${tree}.zip failed"
if ! echo "${CHROME_HEADLESS_SHELL_LINUX64_ZIP_SHA256}  ${zip}" | sha256sum --check --strict >&2; then
  die "${tree}.zip does not match the pinned SHA-256; nothing was installed"
fi
unzip -q "${zip}" -d "${work}/new" || die "unpacking ${tree}.zip failed"
rm -f "${zip}"
if [ ! -x "${work}/new/${tree}/chrome-headless-shell" ]; then
  die "${tree}.zip has no ${tree}/chrome-headless-shell; nothing was installed"
fi

if [ -e "${install_root}/${tree}" ]; then
  mv -T "${install_root}/${tree}" "${work}/old"
fi
mv -T "${work}/new/${tree}" "${install_root}/${tree}"
echo "${install_root}/${tree}/chrome-headless-shell"
