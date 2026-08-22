#!/bin/bash
# Claude Code on the web 用 SessionStart フック。
# Bun を .bun-version(厳密ピン)に同期し、ワークスペースの依存をインストールする。
# Playwright の Chromium はダウンロードせず、環境プリインストール版を使う
# (apps/web/test/e2e.test.ts が PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH を参照)。
set -euo pipefail

# リモート環境(Claude Code on the web)以外では何もしない
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

# Playwright パスはフックの本業。任意の deepsec install より先に書き、
# 後続が落ちても e2e がプリインストール Chromium を使えるようにする。
if [ -n "${CLAUDE_ENV_FILE:-}" ] && [ -x /opt/pw-browsers/chromium ]; then
  echo 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium' >>"$CLAUDE_ENV_FILE"
fi

# `.deepsec/` はルート bun とは別隔離。失敗してもフック全体は落とさない。
# (`/deepsec` は欠落時に pnpm install で直す。init 再開はしない。)
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
