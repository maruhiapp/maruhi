# maruhi Architecture Decision Records

各 ADR は将来 `docs/adr/NNNN-slug.md` に分割する。Status: すべて Accepted(2026-07 時点)。
これらの決定を覆す実装をエージェントが行うことは禁止。変更提案は ADR の改訂案として人間に提示すること。

---

## ADR-0001: 実行基盤に Cloudflare を採用

**Context**: セルフホスト可能かつサーバーレスの secrets 管理。候補は Cloudflare / Deno Deploy / Prisma Compute。
**Decision**: Cloudflare(Workers + Durable Objects + D1 + Static Assets)。
**Rationale**: (1) 基盤の存続性・成熟度が突出(Deno Deploy は Classic 廃止の移行実績、Prisma Compute はベータ + canary ランタイム)。(2) DO の「テナント = 一貫性ドメイン」がプロジェクト単位の DEK・監査ログ設計と例外的に適合。(3) ターゲット層の CF アカウント保有率が高く「自分のアカウントに一発で立つ」体験が成立する。
**Consequences**: 動的シークレット等の長時間処理は将来 Cloudflare Containers 等へ逃がす。

## ADR-0002: 暗号アーキテクチャは選択的開示 E2EE

**Context**: サーバー側暗号化(Shelve 型)、純粋 E2EE、Git-native、しきい値暗号、BYOK、TEE を比較検討。
**Decision**: E2EE を基盤とし、サーバーを「招待制のメンバー N+1」として扱う選択的開示モデル。+ 署名付きメンバーシップログ、ヘッドゴシップ、HPKE の文脈束縛、エポック制、暗号アジリティ。詳細は CRYPTO_SPEC.md。
**Rationale**: 純粋 E2EE の厳密な上位互換(誰も招待しなければ同一)であり、個人開発への信頼問題を暗号で解決しつつ、サーバー主導機能(GitHub 同期等)をプロジェクト単位のオプトインで実現できる。
**Consequences**: 実装は 3 方式中最も複雑。MVP は純粋 E2EE のみ実装し、サーバー鍵は GitHub 同期実装時に追加。

## ADR-0003: ライセンスは FSL-1.1-MIT(サーバー)+ MIT(CLI/SDK/crypto)【仮決定・公開前に最終確認】

**Context**: 第三者による競合クラウドサービス化を禁じたい。AGPL では提供自体は禁止できない。
**Decision**: サーバー = FSL-1.1-MIT(競合利用のみ禁止、2 年後に MIT へ自動変換)。CLI / SDK / crypto = MIT。
**Rationale**: セルフホスト・自己利用は許可しつつ競合 SaaS を禁止できる唯一の要件適合。2 年後 MIT 変換は「作者が消えても資産は残る」という信頼の物語になる。
**Consequences**: OSI の「オープンソース」を名乗らない(source-available / Fair Source と表現)。公開時に DCO + CONTRIBUTING.md のライセンス条項が必須。公開まではクローズド開発。

## ADR-0004: ランタイムと実行環境の分離

**Decision**: 開発ツールチェーン・CLI = Bun 1.4 系。サーバー実行 = workerd(Workers)。サーバーコードは Web 標準 + Workers API のみで Bun API 禁止。テストは Vitest に統一(サーバー / DO は @cloudflare/vitest-pool-workers、他は通常環境)。`bun:test` 不使用。
**Rationale**: Bun はサーバー上で動かない(動かす必要がない)。暗号コアはブラウザ / Bun / workerd の 3 環境で動く WebCrypto 縛りとし、移植性を CI で担保。

## ADR-0005: HTTP 層は @effect/platform HttpApi(Hono 不使用)

**Context**: Workers のデファクトは Hono。Effect v4 全面採用と Alchemy v2 Effect スタイルを決定済み。
**Decision**: HttpApi によるスキーマファースト API。Hono は採用しない。
**Rationale**: (1) Alchemy v2 Effect スタイルは @effect/platform の HTTP 抽象を既に使用しており、Hono を重ねると抽象が二重になる。(2) スキーマ定義から型付きクライアント(CLI 用)と OpenAPI が自動導出される。(3) `EncryptedPayload` 型を API 境界で強制でき、平文がAPI を通らない不変条件をコンパイル時に守れる。
**Consequences**: 退避経路: HttpApi が実運用に耐えない場合は Hono + ハンドラ内 Effect へ差し替え(ドメインコア・API Schema は無傷)。

## ADR-0006: DB 層は Drizzle v1(Effect サービス境界内に隔離)

**Context**: 当初は @effect/sql-d1 で Effect 一貫の予定。Drizzle v1 が Effect v4 ネイティブ対応を発表。
**Decision**: Drizzle v1 + drizzle-kit。リポジトリ層を Effect サービスとして 1 枚に閉じ、Drizzle の型を外に出さない(ImportLint で強制)。D1 は drizzle-kit migrations、DO SQLite は DO 内自己マイグレーション(drizzle-orm/durable-sqlite)。
**Rationale**: スキーマ差分からのマイグレーション自動生成と DO 対応は自作代替不能な生産性。Effect 一貫の目的(型付きエラー・Layer・テスト容易性)はサービス境界で保たれる。
**Consequences**: D1 / DO SQLite 向け Effect ネイティブドライバの有無を開発開始時に確認(なければ tryPromise の薄いアダプタ)。

## ADR-0007: フロントエンドは FunStack(funstack-static + funstack-router)

**Context**: 候補は Vite SPA + TanStack Router、Next.js 等のメタフレームワーク、FunStack。
**Decision**: funstack-static(ビルド時 RSC、静的デプロイ)+ funstack-router(Navigation API)。HeroUI v3 / Pro + Tailwind v4。
**Rationale**: E2EE アプリはリクエスト時 SSR の利益がゼロ(サーバーは暗号文しか持たない)。ビルド時 RSC はこの制約と完全に整合し、静的シェルのバンドル削減と SEO ページの同居を実現、成果物は Workers Static Assets にそのまま載る。「No server runs = No RCE」は secrets 製品の攻撃面削減思想と一致。
**Consequences**: 本番実績の少なさはリスク。緩和: RSC 境界を静的シェルに限定し、Vite SPA への退避を安価に保つ。シークレットを扱うコードは必ず client 側。

## ADR-0008: docs は Blume、ランディングは FunStack

**Decision**: ドキュメントサイトは Blume(Astro ベース、MCP / llms.txt / 検索 / OpenAPI 内蔵)。
**Rationale**: docs の資産はコンテンツ(Markdown)でありフレームワークではないため移行コストが低く、「後から変えやすい決定」。ゼロコンフィグで AI-ready な現時点最速を採る。Fumadocs は未採用のメタフレームワークを持ち込むため不採用。自作は非差別化労働のため不採用。

## ADR-0009: 認証は GitHub OAuth 直接実装、WorkOS は不採用(再判断ポイント付き)

**Context**: 将来のエンタープライズと無料ユーザー増を見据え WorkOS 採用を検討した。
**Decision**: コア認証は GitHub OAuth(web + device flow)の直接実装。Better Auth 等のフレームワークも不使用。ただし AUTH_SPEC の 6 項目(内部 user_id 主キー、メール検証 + 自動リンク禁止、org のファーストクラス化、DB バックセッション、maruhi 発行トークン、冪等 get-or-create)により将来の IdP 追加を無停止で可能に保つ。
**Rationale**: セルフホスト版は外部依存なしが製品価値でありGitHub 直実装が必須。同一コードベース戦略のため WorkOS は削減ではなく純増になる。自前実装の範囲は OAuth クライアント + セッション + トークンの数百行で、危険物(パスワード等)を含まない。Better Auth はスキーマ所有がE2EE 主導のユーザーモデル設計と衝突。
**Consequences**: 再判断ポイント: ホステッド版の着工日。メンバーシップチェーンにプロバイダ情報を書かないことが最重要の不可逆制約(CRYPTO_SPEC §6.1)。

## ADR-0010: 品質ツールチェーン

**Decision**: oxlint + oxfmt(Prettier 不使用)、ImportLint(@public カプセル化)、fallow(コードベース健全性、baseline 運用)、React Doctor(web、diff モード)。CI 順: format → lint → tsc → ImportLint → fallow → React Doctor。
**Rationale**: oxc ファミリーで統一(速度・Tailwind クラスソート内蔵)。ImportLint は暗号コアの API 境界強制というセキュリティ設計を機械化する。全ツールがエージェントスキルを配布しており、エージェント併用開発のガードレールとして機能する。

## ADR-0011: 未安定依存のリスク管理原則

**Decision**: 影響半径が小さい場所ほど新しい技術を許容し(docs = Blume、fmt = oxfmt)、退避可能な場所は退避経路つきで採用し(FunStack → SPA、Alchemy → wrangler、HttpApi → Hono)、暗号コアは退屈な標準(WebCrypto、HPKE)のみとする。全依存はバージョン厳密ピン留め、更新は独立 PR で意図的に行う。

## ADR-0012: IaC は Alchemy v2 Effect スタイル + セルフホストは wrangler 両対応

**Context**: 自分が運用するデプロイ(クラウド版・開発環境)と、ユーザーがセルフホストする配布物では要件が異なる。
**Decision**: 運用側は Alchemy v2 の Effect スタイル(インフラとランタイムの型付き結線)。セルフホスト配布物は素の wrangler 設定 / Deploy to Cloudflare ボタンで立つ経路を必ず維持し、ユーザーに Alchemy 依存を強要しない。
**Rationale**: 「ワンクリックで自分のアカウントに立つ」が製品価値の核であり、配布物の依存は最小でなければならない。デプロイ定義の二重管理は参入障壁を下げる対価として許容する。
**Consequences**: 退避経路: Alchemy の async スタイル、または wrangler への完全退避。CI でセルフホスト経路(wrangler のみ)のデプロイ検証を行う。
