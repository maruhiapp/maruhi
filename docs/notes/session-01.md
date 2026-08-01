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
5. CRYPTO_SPEC §8 リカバリーラップの AES-256-GCM に AAD の規定がない(設計原則 3「すべての暗号文は AAD / info により束縛」と不整合)。→ 2026-07-31 改訂案を §8 に反映済み(AAD = "maruhi/v1/recovery-wrap" || user_id)。承認待ち
6. CRYPTO_SPEC §8 の HKDF に salt の規定がない。→ 2026-07-31 改訂案を §8 に反映済み(salt = 空。RFC 5869 §3.1 の一様ランダム IKM 条項)。承認待ち
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

## Astryx 採用決定(2026-08-01、ADR-0013)と styling 運用規律

- 所有者決定により web の UI は Astryx(Tailwind v4 は不採用)。ADR-0013 参照。heroui-react スキルは削除済み
- Astryx の styling 経路は 4 つ: defineTheme(トークン・variant)/ xstyle(stylex.create + typed tokens)/ className(外部 CSS interop 用)/ style(インライン)。swizzle はソース取り込み(**要 StyleX コンパイラ。無いと無警告で無スタイル描画**という罠あり)
- **運用規律は B2 で決定(2026-08-01)**: defineTheme を基本とし、局所調整のみ xstyle(typed tokens 縛り)。className / インライン style / アプリコードでの stylex.props は oxlint(oxlint-plugin-eslint の no-restricted-syntax、apps/web スコープ)で機械禁止、`ui.package/` 内のみ解除。同じ上書きの再発はテーマ variant か ui.package へ昇格(逆流禁止)。CLAUDE.md に明文化済み・ダミー違反ファイルで発火と免除を検証済み
- **swizzle は全面禁止で確定(2026-08-01、所有者決定)**: 手段を問わず Astryx 内部実装のリポジトリへの取り込みを禁止(実質基準。手動コピーも同罪)。上流バグは厳密ピン留め運用の「アップグレード PR 差し戻し」で対処するため、ホットフィックス用の例外は不要と判断。表現できない UI は UX 再設計 / 合成 / 公開 API での自作 / upstream issue・PR で解く
- **訂正(重要)**: StyleX コンパイラは swizzle ではなく **`stylex.create` を書いた時点(xstyle 使用開始時点)で必要**(公式 docs 確認済み)。「未設定だと無警告で無スタイル描画」も authored StyleX 全般に適用。スパイク A で FunStack(Vite)+ StyleX コンパイラの組み合わせを必ず検証すること
- スパイク A に残した実装: `astryx init --features agents`(AGENTS.md 生成)、`astryx doctor` の品質ゲート追加、`@stylexjs/eslint-plugin` の上乗せ検討(xstyle 値の妥当性検査)
- 強制手段(確認済み): oxlint native の no-restricted-imports(paths/patterns + overrides)、no-restricted-syntax は oxlint-plugin-eslint(jsPlugins)経由、astryx doctor(CI-friendly exit code)、ImportLint の *.package 境界
- Astryx は SKILL.md 配布・MCP npm パッケージなし(確認済み)。エージェント対応は CLI(--json / capability manifest / --lang dense)と astryx init --features agents による AGENTS.md / CLAUDE.md 生成。導入はスパイク A で実施
- バージョン規律: stable のみ(canary 禁止)、厳密ピン、更新は astryx upgrade コードモッド + 独立 PR

## 次セッション(ROADMAP スパイク A)への引き継ぎ

スパイク A(ADR-0013 により更新): funstack-static + funstack-router + **Astryx** → Workers Static Assets。`"use client"` 境界、Navigation API 非対応ブラウザの劣化挙動、Astryx プリビルド CSS の静的配信、厳格 CSP との整合を確認。`astryx init --features agents` でエージェントドキュメントを生成し、`astryx doctor` を品質ゲートに追加する。

- 作業場所は `apps/web`(骨格のみ。React 依存なし)。使い捨てスパイクなら別ディレクトリでも可
- スキル `funstack-static-knowledge` / `funstack-router-knowledge` を導入済み(heroui-react は ADR-0013 により削除済み)
- ~~HeroUI Pro のライセンスをクラウド環境(Cloud Agents > Secrets)に登録予定~~ → **不要になった(ADR-0013)**。本リポジトリでは HeroUI を使わない。Pro を使うなら将来の非公開マーケティングサイト用リポジトリで
- **HeroUI Pro のライセンス制約(2026-07-31 調査。経緯の記録)**: Pro は私有ライセンス(`@heroui-pro/react`、トークン必須)で、コンポーネント・ソースの共有/公開/再配布を禁止。トークンの公開環境への露出も禁止。したがって OSS 配布物には Pro を入れられない。→ この制約が UI ライブラリ再選定の起点となり、**ADR-0013(Astryx 採用)で解決済み**
- **HeroUI 乗り換え候補の調査(2026-08-01、実測込みで更新)**: 候補は Astryx(Meta、MIT、StyleX ベース、公開 2026-06、内部 8 年・13,000 アプリ)と React Aria Components(Adobe、v1.20、monopackage 化済み・公式エージェントスキル + MCP + llms.txt あり)。実測では依存はどちらも 16 パッケージ / 約 72MB で同等。ただし Astryx はプリビルド CSS 方式のため Tailwind ツールチェーン自体が不要になる。壊れにくさは RAC が優位(公開 8 年の互換実績・コードモッド文化。ただし次期 major が nightly 進行中)、Astryx は 0.x semver・外部コミュニティ対応が未証明。**所有者は Astryx の新規リスク許容 + Tailwind 廃止も可と表明済み**。推奨: スパイク A を「Astryx × FunStack」検証に差し替え、退避経路 = RAC(+ Tailwind v4)として ADR-0007 を改訂(人間の最終決定待ち)。採用決定時は .agents/skills の heroui-react を外し Astryx の CLI/MCP(`astryx init` が AGENTS.md / CLAUDE.md を生成)に入れ替え、oxfmt の sortTailwindcss 設定も除去する
- **CRYPTO_SPEC §8 改訂案の裏取り(2026-07-31)**: Shelve / Keyway はサーバー側暗号化でリカバリーラップの概念自体がなく参考外。E2EE の Infisical はリカバリーキット(乱数鍵)で秘密鍵の複製を直接復号し、salt 保存は低エントロピーなパスワード経路(Argon2id)のみ。→「salt = 空」は Infisical のリカバリー経路と同型、「AAD 束縛」は 3 製品のどれもやっていない上乗せの強化、として決定を維持
- 依存追加は `bun add -E`(bunfig.toml の exact=true で強制)。理由をコミットメッセージに書く(CLAUDE.md)
- web は Trusted Computing Base: CSP(`script-src 'self'`)、サードパーティスクリプト禁止を静的シェル段階から確認する
- funstack-static は `@vitejs/plugin-rsc` ベース。RSC は静的シェルのみ(ADR-0007)の制約をスパイクの検証項目に含めること
