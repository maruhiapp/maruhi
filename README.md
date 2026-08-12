# maruhi ㊙

Cloudflare を実行基盤とする、汎用のディスクレス secrets 管理ツール。

- **セルフホスト可能** — 自分の Cloudflare アカウントに `wrangler deploy` 一発で立つサーバーレス構成(Workers + Durable Objects + D1)
- **E2EE(ゼロ知識)がデフォルト** — 暗号化・復号はすべてクライアントで行われ、平文のシークレットはサーバーに到達しない
- **ディスクレス CLI** — `maruhi run -- <cmd>` は子プロセスの環境変数へのメモリ注入のみで値を渡し、平文をディスクに書かない

> **Status**: 開発中(pre-release)。API・仕様は予告なく変わります。

## ドキュメント

- [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) — 暗号仕様(唯一の正)
- [docs/AUTH_SPEC.md](docs/AUTH_SPEC.md) — 認証・アイデンティティ仕様
- [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) — セルフホスト手順
- [docs/adr/](docs/adr/) — 設計判断の記録(ADR)

## ライセンス

本リポジトリは部位ごとにライセンスが異なります([ADR-0003](docs/adr/0003-license-fsl-mit.md))。

| 対象 | ライセンス |
|---|---|
| `apps/server`・`apps/web` を含むリポジトリ既定 | [FSL-1.1-MIT](LICENSE.md) |
| `apps/cli`・`packages/crypto`・`packages/core`・`packages/api-schema` | MIT(各ディレクトリの `LICENSE`) |

FSL-1.1-MIT(Functional Source License)は、競合するホスト型サービスとしての提供のみを制限するライセンスです。セルフホスト・社内利用・改変・再配布は自由で、公開から 2 年後に自動的に MIT へ変換されます。OSI 定義の「オープンソース」ではなく source-available / Fair Source です。

## 貢献

[CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。すべてのコミットに DCO の `Signed-off-by` が必要です。
