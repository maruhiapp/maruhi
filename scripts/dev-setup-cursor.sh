#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

die() {
  echo "dev-setup-cursor: $*" >&2
  exit 1
}

bashrc_line() {
  touch "${HOME}/.bashrc"
  grep -qxF "$1" "${HOME}/.bashrc" || echo "$1" >>"${HOME}/.bashrc"
}

bash scripts/install-bun.sh
bashrc_line 'export PATH="$HOME/.bun/bin:$PATH"'
export PATH="${HOME}/.bun/bin:${PATH}"
bashrc_line 'export PLAYWRIGHT_DOWNLOAD_HOST="https://playwright-download.invalid"'

bun install --frozen-lockfile

rm -rf "${HOME}/.cache/ms-playwright"
executable="$(bash scripts/install-headless-shell.sh)"
if [ "${executable}" != "${HOME}/.cache/chrome-headless-shell/chrome-headless-shell-linux64/chrome-headless-shell" ]; then
  die "install-headless-shell.sh installed ${executable}, not the path the ~/.bashrc line names"
fi
bashrc_line 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$HOME/.cache/chrome-headless-shell/chrome-headless-shell-linux64/chrome-headless-shell"'
