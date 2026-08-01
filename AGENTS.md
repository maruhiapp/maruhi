# AGENTS

リポジトリ全体の開発ガイドは `CLAUDE.md` を参照(絶対規則・技術スタック・品質ゲート)。

## Cursor Cloud specific instructions

- Bun は `.bun-version`(厳密ピン)に従い `~/.bun/bin` にインストール済み(PATH は `~/.bashrc` 経由)。起動時のインストールスクリプトがバージョン同期・`bun install`・Playwright Chromium 取得を行う
- 品質ゲートは `bun run check`(ルート `package.json` 参照)。CI(`.github/workflows/ci.yml`)と同一順序
- ルートの `bun run test` に `apps/web` の e2e は含まれない(意図的)。web e2e は `cd apps/web && bun run build && bunx vitest run --config vitest.config.ts` で実行する。事前 build 必須で、テストが自前で `wrangler dev`(port 8791)を spawn する
- web dev サーバー(`bun run --filter @maruhi/web dev`、port 5173)は `Accept: text/html` ヘッダーがないリクエストに 404 を返す。curl での疎通確認は `-H "Accept: text/html"` を付ける(ブラウザでは問題なし)
- `spikes/*` はルートワークスペース外(使い捨て検証コード)。各ディレクトリで個別に `bun install` が必要。spike-b の `bunx alchemy plan` は実 Cloudflare 認証情報が必要なので実行しない
- `apps/server` はスタブ(dev スクリプトなし)。必要なら `cd apps/server && bunx wrangler dev`。DB・シークレット・外部サービスは現状一切不要
- `.agents/skills` の一部エントリは node_modules へのシンボリックリンクのため、`bun install` 前は壊れて見える
