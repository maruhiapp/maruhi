# AGENTS

リポジトリ全体の開発ガイドは `CLAUDE.md` を参照(絶対規則・技術スタック・品質ゲート)。

## Claude Code on the web specific instructions

- セットアップは SessionStart フック(`.claude/hooks/session-start.sh`)が行う: Bun の `.bun-version` 同期と `bun install`。Playwright の Chromium は**ダウンロードせず**、環境プリインストール版(`/opt/pw-browsers/chromium`)を使う
- フックが `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` をセッション環境変数に書き出し、`apps/web/test/e2e.test.ts` がそれを `chromium.launch({ executablePath })` に渡す(未設定なら従来どおり Playwright 管理のブラウザを使うため、Cursor / CI には影響しない)
- `bunx playwright install` は実行しない(プリインストール版と競合し、ディスク割当も消費する)
- 上記以外(品質ゲート・e2e の実行手順・dev サーバーの注意点など)は下の Cursor Cloud の節と共通

## Cursor Cloud specific instructions

- Bun は `.bun-version`(厳密ピン)に従い `~/.bun/bin` にインストール済み(PATH は `~/.bashrc` 経由)。起動時のインストールスクリプトがバージョン同期・`bun install`・Playwright Chromium 取得を行う
- 品質ゲートは `bun run check`(ルート `package.json` 参照)。CI(`.github/workflows/ci.yml`)と同一順序
- ルートの `bun run test` に `apps/web` の e2e は含まれない(意図的)。web e2e は `cd apps/web && bun run build && bunx vitest run --config vitest.config.ts` で実行する。事前 build 必須で、テストが自前で `wrangler dev`(port 8791)を spawn する
- web dev サーバー(`bun run --filter @maruhi/web dev`、port 5173)は `Accept: text/html` ヘッダーがないリクエストに 404 を返す。curl での疎通確認は `-H "Accept: text/html"` を付ける(ブラウザでは問題なし)
- `apps/server` はスタブ(dev スクリプトなし)。必要なら `cd apps/server && bunx wrangler dev`。DB・シークレット・外部サービスは現状一切不要
- `.agents/skills` の一部エントリは node_modules へのシンボリックリンクのため、`bun install` 前は壊れて見える
- deepsec スキル(`/deepsec`、`.agents/skills/deepsec`)を使う場合は `cd .deepsec && pnpm install --frozen-lockfile`。無いと公式 runbook が `npx deepsec init` 再開に入る
