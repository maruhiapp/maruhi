# セッション 01 引き継ぎメモ(開発基盤の整備)

日付: 2026-07-31。スコープは開発基盤のみ。製品ロジック・暗号コードは未実装。

## このセッションでやったこと

1. 5 文書(CLAUDE.md / ROADMAP.md / CRYPTO_SPEC.md / AUTH_SPEC.md / ADR.md)の矛盾チェック(結果は下記)
2. `docs/ADR.md` を `docs/adr/NNNN-slug.md` × 12 + 索引 `README.md` に分割(本文は原文一致を検証済み。見出しレベル `##`→`#` のみ調整)
3. Bun workspaces モノレポ骨格: `packages/{crypto,core,api-schema}` + `apps/{server,cli,web,docs}`
4. 品質ゲート 7 ステップを `bun run check` と GitHub Actions(`.github/workflows/ci.yml`)に配線
5. Vitest 4 + `@cloudflare/vitest-pool-workers`(server は workerd 実環境)。ダミーテスト 5 ファイル 6 件通過
6. エージェントスキル 18 個を `.agents/skills/`(正)+ `.claude/skills/`(symlink)に導入

## 文書の矛盾・綻び(未修正。人間の判断待ち)

1. ADR 前文「Status: すべて Accepted」と ADR-0003 の「【仮決定】」が矛盾。0003 に個別 Status を持たせるべき
2. CLAUDE.md 技術スタック表の docs 行「別リポジトリ or apps/docs」が未決の書き方のまま。モノレポ構成では apps/docs 確定
3. 「実装開始前に要決定」の件数: ROADMAP は 2 件(環境モデル、認可モデル)だが、AUTH_SPEC §9-1「プロジェクトと組織の関係」も要決定マーク付きで実質 3 件
4. ADR-0010 の CI 順序に第 7 ステップ(テスト)がない。CLAUDE.md の品質ゲートと不一致
5. CRYPTO_SPEC §8 リカバリーラップの AES-256-GCM に AAD の規定がない(設計原則 3「すべての暗号文は AAD / info により束縛」と不整合)。仕様改訂が必要
6. CRYPTO_SPEC §8 の HKDF に salt の規定がない。テストベクター定義時に必ず問題になる
7. 分割後の `docs/adr/README.md` 前文に「各 ADR は将来分割する」の一文が残っている(原文不変更の指示に従い温存。次の文書改訂で削除可)
8. 誤字レベル: ADR-0005「平文がAPI」、ADR-0009「でありGitHub」等のスペース欠落

## 環境・バージョンの実態(文書との差分)

- **Bun 1.4 は未リリース**(2026-07-31 時点の最新は 1.3.14)。`.bun-version` + `engines` で 1.3.14 をピン留め。ROADMAP の「Bun 1.4 リリース待ち」と整合。1.4 が出たら独立 PR で更新
- 主要バージョン(すべて厳密ピン): typescript 7.0.2 / vitest 4.1.10 / @cloudflare/vitest-pool-workers 0.20.1 / oxlint 1.76.0 / oxfmt 0.61.0 / @import-lint/cli 0.1.6 / fallow 3.10.0 / react-doctor 0.9.2 / @cloudflare/workers-types 5.20260731.1
- vitest-pool-workers は v0.13 で API が変わった。旧 `defineWorkersConfig` は削除済みで、現行は `cloudflareTest()` Vite プラグイン(`apps/server/vitest.config.ts` 参照)。古い記事の設定例は使えない

## 品質ゲートの運用

- `bun run check` = oxfmt --check → oxlint → tsc → ImportLint → fallow audit → React Doctor → vitest run。CI も同一順序
- **fallow**: baseline を `fallow-baselines/` にコミット済み。既存問題を意図的に受け入れ直すときだけ `bun run fallow:baseline` で更新する
- **ImportLint**: `*.package` ディレクトリ命名が境界(`defaultImportability: "package"`)。Drizzle 隔離(ADR-0006)や crypto 内部の API 境界は、実装時に該当ディレクトリを `foo.package` に命名して有効化する
- **React Doctor**: apps/web に React がまだ無いため「rules gated off」で素通りしている。スパイク A で React が入ると自動的に実検査になる。テレメトリ(Sentry)があるため **常に `--no-telemetry` を付ける**こと(scripts に設定済み)
- **oxfmt**: Markdown は整形対象外(決定済み 2026-07-31: 文書の整形は行わない)
- web / docs の vitest プロジェクトは未定義。スパイク A / Blume 導入時にルート `vitest.config.ts` の projects に追加する

## エージェントスキル

- 正: `.agents/skills/`(Cursor 等が読む)。`.claude/skills/` は symlink
- fallow / react-doctor / improve-react は **node_modules への symlink**(バージョン連動)。`bun install` 前はリンク切れ表示になるが正常
- drizzle 系 8 スキルは drizzle-kit@rc(1.0.0-beta 系)からの**コピー**。Phase 1 で drizzle-kit を依存に追加したら `drizzle-kit skills` で再同期する
- 導入元: heroui-react / import-lint / funstack-{router,static}-knowledge / blume / blume-update-docs は `npx skills add` (GitHub 配布)

## 次セッション(ROADMAP スパイク A)への引き継ぎ

スパイク A: funstack-static + funstack-router + HeroUI v3 + Tailwind v4 → Workers Static Assets。`"use client"` 境界と Navigation API 非対応ブラウザの劣化挙動の確認。

- 作業場所は `apps/web`(骨格のみ。React 依存なし)。使い捨てスパイクなら別ディレクトリでも可
- スキル `funstack-static-knowledge` / `funstack-router-knowledge` / `heroui-react` を導入済み。HeroUI v3 は beta で `@beta` タグ必須、Tailwind v4 必須、Provider 不要・compound components、という v2 との差分がスキルに詳述されている
- HeroUI Pro のライセンスは所有者が保有しており、クラウド環境(Cloud Agents > Secrets)に登録予定。ライセンスキーをリポジトリ・`.dev.vars` に書かないこと(CLAUDE.md のダミー値規則)
- 依存追加は `bun add -E`(bunfig.toml の exact=true で強制)。理由をコミットメッセージに書く(CLAUDE.md)
- web は Trusted Computing Base: CSP(`script-src 'self'`)、サードパーティスクリプト禁止を静的シェル段階から確認する
- funstack-static は `@vitejs/plugin-rsc` ベース。RSC は静的シェルのみ(ADR-0007)の制約をスパイクの検証項目に含めること
