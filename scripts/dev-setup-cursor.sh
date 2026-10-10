#!/usr/bin/env bash
# dev-setup-cursor.sh — the whole Cursor Cloud environment install. The
# environment's install command is only `bash scripts/dev-setup-cursor.sh`,
# so a change to the setup ships in a reviewed pull request. It runs on the
# environment's build pod (from the default branch) and may run again on a
# previously prepared disk, so every step is idempotent.
#
# Not for a local machine: it appends to ~/.bashrc and deletes Playwright's
# own browser directory (~/.cache/ms-playwright).
#
# - Bun comes only from scripts/install-bun.sh, and the tests' browser only
#   from scripts/install-headless-shell.sh: both check a SHA-256 pinned in
#   this repository before anything they fetch runs.
# - Agent shells get Bun's PATH, the browser's path, and a
#   PLAYWRIGHT_DOWNLOAD_HOST that makes any `playwright install` fail (as in
#   ci.yml) through ~/.bashrc lines, since neither installer edits a profile.
# - ~/.cache/ms-playwright is removed: older environments fetched unverified
#   browsers into it, and a shell that never reads ~/.bashrc (a plain
#   `bash -c`) would launch them silently. Without it, such a shell fails like
#   CI does instead.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

die() {
  echo "dev-setup-cursor: $*" >&2
  exit 1
}

# Appends a line to ~/.bashrc unless it is already there, verbatim
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
# The ~/.bashrc line names the path with a literal $HOME, so it must be the
# one the installer reports
if [ "${executable}" != "${HOME}/.cache/chrome-headless-shell/chrome-headless-shell-linux64/chrome-headless-shell" ]; then
  die "install-headless-shell.sh installed ${executable}, not the path the ~/.bashrc line names"
fi
bashrc_line 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$HOME/.cache/chrome-headless-shell/chrome-headless-shell-linux64/chrome-headless-shell"'
