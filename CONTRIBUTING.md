# maruhi への貢献

maruhi への貢献に興味を持っていただきありがとうございます。Issue・Pull Request を歓迎します。

## 開発セットアップ

- ランタイムは Bun です。版は `.bun-version` で厳密ピン(現行 1.3.14)。ADR-0004 の 1.4 系は未到達です
- `bun install` で依存をインストールします
- コミット前に品質ゲートをすべて通してください: `bun run check`(oxfmt → oxlint → tsc → ImportLint → fallow → React Doctor → テスト)

開発ルールの詳細は [CLAUDE.md](CLAUDE.md) と [docs/adr/](docs/adr/) を参照してください。特に:

- 暗号仕様は [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) が唯一の正です。`packages/crypto` への変更は必ず人間レビューとテストベクター(`test-vectors/`)による検証を経ます
- 平文のシークレットがサーバー API・ディスク・ログを通らないこと(ディスクレス不変条件)を破る変更は受け付けられません

## ライセンス構成と貢献の取り扱い

本リポジトリは部位ごとにライセンスが異なります([ADR-0003](docs/adr/0003-license-fsl-mit.md)):

- リポジトリ既定(`apps/server`・`apps/web` を含む): [FSL-1.1-MIT](LICENSE.md)
- `apps/cli`・`packages/crypto`・`packages/core`・`packages/api-schema`: MIT(各ディレクトリの `LICENSE`)

Pull Request を送ることで、あなたの貢献が変更対象ディレクトリに適用されるライセンスの下で提供されることに同意したものとみなします。

## DCO(Developer Certificate of Origin)

すべてのコミットに、[DCO 1.1](https://developercertificate.org/) への同意を示す `Signed-off-by` トレーラーが必要です。`-s` フラグで自動付与できます:

```sh
git commit -s
```

トレーラーは次の形式で、実名またはあなたを特定できる一貫した名義と有効なメールアドレスを使ってください:

```
Signed-off-by: Your Name <your@example.com>
```

<details>
<summary>Developer Certificate of Origin 1.1(全文)</summary>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

</details>

## セキュリティ

脆弱性を発見した場合は、公開 issue に詳細を書かず、GitHub の Private Vulnerability Reporting(Security タブ → Report a vulnerability)から報告してください。
