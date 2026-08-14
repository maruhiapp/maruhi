# maruhi ㊙

Cloudflare を実行基盤とする、汎用のディスクレス secrets 管理ツール。

- **セルフホスト可能** — 自分の Cloudflare アカウントに `wrangler deploy` 一発で立つサーバーレス構成(Workers + Durable Objects + D1)
- **E2EE(ゼロ知識)がデフォルト** — 暗号化・復号はすべてクライアントで行われ、平文のシークレットはサーバーに到達しない
- **ディスクレス CLI** — `maruhi run -- <cmd>` は子プロセスの環境変数へのメモリ注入のみで値を渡し、平文をディスクに書かない

> **Status**: 開発中(pre-release)。API・仕様は予告なく変わります。

## インストール(CLI)

配布形態の設計は [ADR-0015](docs/adr/0015-cli-distribution.md)。install script と
brew tap は後続 PR で提供予定です。

### コンパイル済みバイナリ(推奨。Bun 不要)

[GitHub Releases](https://github.com/maruhiapp/maruhi/releases) からプラットフォーム別の
`maruhi-<os>-<arch>.tar.gz` を取得し、チェックサムを検証して展開します:

```sh
# 例: Apple Silicon mac(linux-x64 / linux-arm64 / darwin-x64 / windows-x64 も同様)。
# V は Releases ページの最新タグに置き換える(プレリリース期間中は
# releases/latest が存在しないため、タグ URL を使う)
V=v0.1.0-rc.1
curl -fsSLO "https://github.com/maruhiapp/maruhi/releases/download/${V}/maruhi-darwin-arm64.tar.gz"
curl -fsSLO "https://github.com/maruhiapp/maruhi/releases/download/${V}/checksums.txt"
shasum -a 256 --ignore-missing -c checksums.txt   # Linux では sha256sum --ignore-missing -c
tar -xzf maruhi-darwin-arm64.tar.gz
./maruhi --version
```

`mh` エイリアスが必要なら並べてリンクを張ってください: `ln -s maruhi mh`

- **windows-x64 は experimental** です(Credential Manager 経路が未検証。キーチェーンに
  問題がある場合も平文フォールバックせず型付きエラーで止まります)
- macOS バイナリは未公証のため、**ブラウザで**ダウンロードすると Gatekeeper に隔離されます
  (上記のように curl で取得すれば隔離属性は付きません)。公証は公開準備の段階で対応します

### npm(Bun ランタイム必須)

CLI は OS キーチェーン(`Bun.secrets`)等の Bun 固有 API に依存するため、npm 版の実行には
[Bun](https://bun.sh) が必要です(最低バージョンはリポジトリの [`.bun-version`](.bun-version) と同じ。
公開パッケージの `engines.bun` も同ファイルから導出されます)。Bun が無い環境では、
Node.js で起動した場合は案内を出して終了し、Unix で直接 `maruhi` を叩いた場合は shebang 解決の段階で
`env: 'bun': No such file or directory` になります(いずれも Bun の導入で解消):

```sh
# プレリリース期間中(v0.1.0 まで)は dist-tag `next` を指定する。
# 素の `maruhi` は現状プレースホルダ(0.0.1)を指すため注意
bun install -g maruhi@next
maruhi --version             # mh --version も同じ
```

安定版(`v0.1.0`)以降は `bun install -g maruhi` で入ります。

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
