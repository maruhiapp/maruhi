#!/bin/bash
# SessionStart hook for Claude Code on the web.
# Syncs Bun to .bun-version (strict pin) and installs workspace dependencies.
# Does not download Playwright's Chromium — uses the environment's
# preinstalled build (the apps/web / apps/site e2e suites and the
# packages/crypto browser tests read PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH).
set -euo pipefail

# No-op outside the remote environment (Claude Code on the web)
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "$CLAUDE_PROJECT_DIR"

BUN_VERSION="$(cat .bun-version)"
if [ "$("$HOME/.bun/bin/bun" --version 2>/dev/null)" != "$BUN_VERSION" ]; then
  curl -fsSL https://bun.sh/install | bash -s "bun-v$BUN_VERSION"
fi
export PATH="$HOME/.bun/bin:$PATH"

bun install

# The Playwright path is this hook's core job. Write it before the optional
# deepsec install so a later failure cannot keep e2e off the preinstalled
# Chromium.
if [ -n "${CLAUDE_ENV_FILE:-}" ] && [ -x /opt/pw-browsers/chromium ]; then
  echo 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium' >>"$CLAUDE_ENV_FILE"
fi

# `.deepsec/` is isolated from the root bun install. A failure here must not
# fail the whole hook. (`/deepsec` repairs itself via pnpm install when
# missing; init is never re-run.)
if [ -f .deepsec/package.json ]; then
  deepsec_install_status=0
  if command -v pnpm >/dev/null 2>&1; then
    (cd .deepsec && pnpm install --frozen-lockfile) || deepsec_install_status=$?
  else
    (cd .deepsec && bunx pnpm install --frozen-lockfile) || deepsec_install_status=$?
  fi
  if [ "$deepsec_install_status" -ne 0 ]; then
    echo "session-start: .deepsec install failed; /deepsec needs: cd .deepsec && pnpm install --frozen-lockfile" >&2
  fi
fi
