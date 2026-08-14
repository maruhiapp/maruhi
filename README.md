# maruhi ㊙

Cloudflare を実行基盤とする、汎用のディスクレス secrets 管理ツール。

- **セルフホスト可能** — 自分の Cloudflare アカウントに `wrangler deploy` 一発で立つサーバーレス構成(Workers + Durable Objects + D1)
- **E2EE(ゼロ知識)がデフォルト** — 暗号化・復号はすべてクライアントで行われ、平文のシークレットはサーバーに到達しない
- **ディスクレス CLI** — `maruhi run -- <cmd>` は子プロセスの環境変数へのメモリ注入のみで値を渡し、平文をディスクに書かない

> **Status**: 開発中(pre-release)。API・仕様は予告なく変わります。

## インストール(CLI)

配布形態の設計は [ADR-0015](docs/adr/0015-cli-distribution.md)。

### install script(Linux / macOS。推奨。Bun 不要)

```sh
# V は Releases ページ(https://github.com/maruhiapp/maruhi/releases)の最新タグ。
# プレリリース期間中(v0.1.0 まで)は releases/latest が存在しないため、
# タグの明示が必要です(まだタグが無い時期は raw URL も 404 になります)
V=v0.1.0-rc.1
curl -fsSL "https://raw.githubusercontent.com/maruhiapp/maruhi/${V}/packaging/install.sh" -o maruhi-install.sh
less maruhi-install.sh          # 中身を読んでから実行してください(下の信頼モデル参照)
sh maruhi-install.sh --version "${V}"
```

`~/.local/bin` に `maruhi` と `mh`(`maruhi` への symlink)を置きます。sudo は使いません。
安定版 `v0.1.0` 以降は `--version` を省略でき、最新の安定版が入ります。

- 主なオプション: `--dir <path>`(既定 `~/.local/bin`)/ `--version <tag>`。
  環境変数 `MARUHI_INSTALL_DIR` / `MARUHI_VERSION` も同じ。一覧は `sh maruhi-install.sh --help`
- 一行で済ませる形(`curl | sh`)も動きます —
  `curl -fsSL ".../${V}/packaging/install.sh" | sh -s -- --version "${V}"`。
  ただし下記の信頼モデルを読んでから選んでください
- 対応対象は linux-x64 / linux-arm64 / darwin-x64 / darwin-arm64。**Windows は対象外**です
  (下の手動手順へ)

<details>
<summary><b>install script の信頼モデル</b>(secrets 管理ツールなので明示します)</summary>

- 通信先は **github.com だけ**です。テレメトリ・外部送信は一切ありません(「言わざる」)。
  例外は利用者自身が `MARUHI_BASE_URL` を指定した場合だけ(内部ミラー・検証用の口。既定では使いません)
- tar.gz は `checksums.txt` の SHA-256 で**検証してから**展開します。検証に失敗した場合は
  インストール先に部分ファイルを残さず、非 0 で終了します
- ただし `checksums.txt` 自体は**まだ署名していません**。完全性の根拠は github.com への
  TLS だけです(署名の導入は今後の課題)。無いものを「署名検証しています」とは書きません。
  だからこそ `curl | sh` を既定にせず、**落として読んでから実行**する形を先に案内しています
- シェルの設定ファイル(`~/.zshrc` 等)は書き換えません。PATH に足す行を表示するだけです
- macOS バイナリは未公証ですが、**curl 取得なら Gatekeeper の隔離属性は付きません**
  (ブラウザでダウンロードした場合は隔離されます)。公証は公開準備の段階で対応します

</details>

### Homebrew(macOS / Linuxbrew)

> **準備中** — tap(`maruhiapp/homebrew-maruhi`)はまだ公開していません。formula は安定版
> `v0.1.0` から提供します(プレリリースは tap に載せません)。それまでは上の install script を
> お使いください。

```sh
# Homebrew 6.0.0 以降、サードパーティ tap はコードが評価される前に明示的な信頼が必要です
# (それ以前の brew に `brew trust` は無いので、この行は不要)
brew trust --tap maruhiapp/maruhi
brew install maruhiapp/maruhi/maruhi
```

`brew trust` は maruhi 側の都合ではなく、tap の Ruby コードを走らせる前に利用者の同意を求める
Homebrew の仕組みです(未信頼 tap の自動 tap は行われません)。

<details>
<summary><b>手動でコンパイル済みバイナリを入れる</b>(Windows はこちら)</summary>

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
  問題がある場合も平文フォールバックせず型付きエラーで止まります)。scoop / winget は将来対応
- macOS バイナリは未公証のため、**ブラウザで**ダウンロードすると Gatekeeper に隔離されます
  (上記のように curl で取得すれば隔離属性は付きません)

</details>

### npm(Bun ランタイム必須)

CLI は OS キーチェーン(`Bun.secrets`)等の Bun 固有 API に依存するため、npm 版の実行には
[Bun](https://bun.sh) が必要です(最低バージョンはリポジトリの [`.bun-version`](.bun-version) と同じ。
公開パッケージの `engines.bun` も同ファイルから導出されます)。Bun が無い環境では、
Node.js で起動した場合は案内を出して終了し、Unix で直接 `maruhi` を叩いた場合は shebang 解決の段階で
`env: bun: No such file or directory` の形のエラーになります(表記は OS の env 実装で多少異なる。
いずれも Bun の導入で解消):

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
