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

# deepsec スキル(`.agents/skills/deepsec`)の公式 runbook は
# `.deepsec/node_modules/deepsec` が無いと init 再開に入る。
# ワークスペース依存はルート bun とは別隔離なので、ここだけ pnpm で入れる。
if [ -f .deepsec/package.json ]; then
  if command -v pnpm >/dev/null 2>&1; then
    (cd .deepsec && pnpm install --frozen-lockfile)
  else
    (cd .deepsec && bunx pnpm install --frozen-lockfile)
  fi
fi

# プリインストール Chromium(PLAYWRIGHT_BROWSERS_PATH 配下)は Playwright の
# ピン版が要求する revision と一致しないことがあるため、実行パスを直接渡す
if [ -n "${CLAUDE_ENV_FILE:-}" ] && [ -x /opt/pw-browsers/chromium ]; then
  echo 'export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium' >>"$CLAUDE_ENV_FILE"
fi
