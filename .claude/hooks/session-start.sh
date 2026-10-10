#!/bin/bash
# SessionStart hook for Claude Code on the web.
# Syncs Bun to .bun-version (strict pin) and installs workspace dependencies.
# Bun comes from scripts/install-bun.sh, which checks the release zip against
# the SHA-256 pinned there (the same pin CI uses) before running it. Does not
# download Playwright's Chromium — uses the environment's preinstalled build
# (the apps/web / apps/site e2e suites and the packages/crypto browser tests
# read PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH).
set -euo pipefail

# No-op outside the remote environment (Claude Code on the web)
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

BUN_VERSION="$(cat .bun-version)"
if [ "$("$HOME/.bun/bin/bun" --version 2>/dev/null)" != "$BUN_VERSION" ]; then
  bash scripts/install-bun.sh
fi
export PATH="$HOME/.bun/bin:$PATH"

# The session's PATH and the Playwright path are this hook's core job. Write
# them before `bun install` and the optional deepsec install, so a later
# failure cannot keep the session off Bun or e2e off the preinstalled
# Chromium. install-bun.sh edits no shell profile, so the session gets
# ~/.bun/bin from here.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export PATH="$HOME/.bun/bin:$PATH"' >>"$CLAUDE_ENV_FILE"
  if [ -x /opt/pw-browsers/chromium ]; then
    echo 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium' >>"$CLAUDE_ENV_FILE"
  fi
fi

bun install

# `.deepsec/` is isolated from the root bun install. A failure here must not
# fail the whole hook. (`/deepsec` repairs itself the same way when missing;
# init is never re-run.) pnpm is never fetched unverified: corepack checks the
# sha512 pinned in .deepsec/package.json's packageManager whenever it downloads
# pnpm (a pnpm already in corepack's cache is not re-checked). Without
# corepack, a preinstalled pnpm runs as is, with its switch to the
# packageManager version turned off (here and in .deepsec/pnpm-workspace.yaml):
# that switch downloads without checking the hash. A corepack failure does not
# fall back to that pnpm.
if [ -f .deepsec/package.json ]; then
  deepsec_install_status=0
  if command -v corepack >/dev/null 2>&1; then
    (cd .deepsec && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm install --frozen-lockfile) ||
      deepsec_install_status=$?
  elif command -v pnpm >/dev/null 2>&1; then
    (cd .deepsec && pnpm install --frozen-lockfile --config.manage-package-manager-versions=false) ||
      deepsec_install_status=$?
  else
    deepsec_install_status=1
  fi
  if [ "$deepsec_install_status" -ne 0 ]; then
    echo "session-start: .deepsec install failed; /deepsec needs: cd .deepsec && corepack pnpm install --frozen-lockfile (without corepack: pnpm install --frozen-lockfile --config.manage-package-manager-versions=false)" >&2
  fi
fi
