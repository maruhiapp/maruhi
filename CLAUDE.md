# CLAUDE.md — maruhi

maruhi (㊙) は、Cloudflare を実行基盤とする汎用のディスクレス secrets 管理ツール。
セルフホスト可能(ユーザー自身の CF アカウントに `wrangler deploy` 一発で立つ)かつサーバーレス。
E2EE(ゼロ知識)がデフォルト。ブランド表記は常に小文字の `maruhi`。

## 絶対規則(違反禁止)

### 暗号・セキュリティ
- 暗号プリミティブは WebCrypto と選定済み HPKE ライブラリのみ。**独自プロトコル・独自プリミティブの発明は禁止**
- 暗号仕様は `docs/CRYPTO_SPEC.md` が唯一の正。仕様にない暗号操作を実装しない。仕様変更はまず仕様書を更新し、人間の承認を得てから実装する
- `packages/crypto` への変更は必ず人間レビューを経る。テストベクターを先に書き、実装がそれを通ることを確認する
- 平文のシークレットは絶対にサーバー API を通らない。API 境界の型は `EncryptedPayload` 系のみ(Schema で強制)
- メンバーシップログと監査ログのアクターは**内部 user_id と鍵フィンガープリントのみ**。GitHub ID 等のプロバイダ情報を append-only 構造に書き込まない
- リポジトリ・テスト・`.dev.vars` に本物のシークレットを置かない。すべてダミー値を使う
- テレメトリ・外部送信を一切実装しない(「言わざる」)

### CLI のディスクレス不変条件
- シークレットの平文をディスクに書かない。`maruhi run -- <cmd>` は子プロセスの環境変数へのメモリ注入のみで値を渡す
- `.env` 系ファイルの生成・出力機能を作らない(エクスポートは将来の SOPS 互換のみ、明示操作)
- CLI が永続化してよいのは: maruhi API トークン(OS キーチェーン)、master 秘密鍵(OS キーチェーン)、非機密の設定のみ
- `gunshi/agent` による AI エージェント環境検出時、値を表示する系のコマンド(例: 値の cat / export)は拒否しメッセージを出す
- 平文値・鍵素材をログ・エラーメッセージ・クラッシュレポートに出力しない

### Web ダッシュボードは Trusted Computing Base である
E2EE では復号がクライアントで起きるため、Web フロントの XSS = 全シークレットの漏洩である。よって:
- 厳格な CSP を必須とする(`script-src 'self'` 基調。inline script・eval 禁止)。唯一の例外: 自ビルドが生成する起動スクリプトを、ビルド時に計算した SHA-256 ハッシュで個別許可すること(2026-08-01 所有者承認。`apps/web/scripts/write-headers.ts` 参照)。`'unsafe-inline'` はいかなる場合も禁止
- サードパーティのスクリプト・CDN・アナリティクスを一切読み込まない。全アセットは自己配信(Workers Static Assets)
- `dangerouslySetInnerHTML` と同等の生 HTML 挿入は禁止(React Doctor / レビューで検査)
- 依存パッケージの追加は最小限とし、フロントの供給網を小さく保つ

### Web UI(Astryx)の styling 規律(ADR-0013)
- 見た目の変更はまず `apps/web/theme/` の defineTheme(トークン・variant)。ブランド定義はここが唯一の置き場所
- 個別調整は Astryx コンポーネントの `xstyle` のみ。値は `stylex.create` + typed tokens(`@astryxdesign/core/theme/tokens.stylex`)で書き、生の hex 値・マジックナンバーを書かない
- `className` とインライン `style` は禁止(oxlint が error にする)。外部 CSS を持ち込まない
- 生 DOM への `stylex.props` と新規の視覚パターンは `apps/web/src/ui.package/` のみ
- カスタマイズは必ずこの順で検討する: ① defineTheme(variant 追加を含む)→ ② xstyle → ③ ui.package での合成ラッパー → ④ ui.package での新規自作(Astryx の hooks / tokens 等の公開 API のみ使用)→ ⑤ upstream(facebook/astryx)への issue / PR。UX の再設計はどの段階でも選択肢に含める
- **`astryx swizzle` は禁止**。コマンドに限らず、Astryx 内部実装のソースを手段を問わずリポジトリへ取り込むこと全般を禁止する(内部ソースの閲覧は学習目的のみ可、コピーは不可)。上流バグは厳密ピン留めにより「アップグレード PR の差し戻し」で対処し、swizzle をホットフィックスに使わない
- 自作の StyleX(`stylex.create`。xstyle 用を含む)はビルドに StyleX コンパイラを要求し、未設定だと無警告で無スタイル描画になる。プリビルド CSS の消費と defineTheme のみならコンパイラ不要
- 同じ xstyle 上書きが 2〜3 回現れたら、defineTheme の variant 化か ui.package への昇格を人間に提案する(逆流させない)
- Astryx コンポーネントの API は推測せず `astryx component <名前> --json` で確認する。バージョンは stable のみ(canary 禁止)・厳密ピン、更新は `astryx upgrade` コードモッドを使う独立 PR で行う

### アーキテクチャ
- 認証は `docs/AUTH_SPEC.md` に従う。メールによる自動アカウントリンク禁止。セッションは DB バック(stateless JWT のみのセッション禁止)
- Drizzle の型(テーブル型・select 結果型)をリポジトリサービスの外に出さない。公開 API はドメイン型と Effect 型のみ
- RSC(server components)は静的シェルのみ。シークレットを扱うロジック・復号処理は必ず client components / クライアントコード
- サーバーコードに Bun 固有 API(`bun:*`)を使わない。Worker 側は Web 標準 + Workers API のみ
- 過去の設計判断は `docs/adr/` を参照。ADR にある決定を蒸し返す実装をしない(変更提案は ADR の改訂として人間に提示する)

## 技術スタック

| 層 | 技術 |
|---|---|
| ランタイム(dev/CLI) | Bun 1.4 系(バージョンピン留め) |
| サーバー実行環境 | Cloudflare Workers (workerd) + Durable Objects + D1 |
| サーバー HTTP 層 | Effect v4 `@effect/platform` HttpApi(Hono 不使用) |
| アプリ基盤 | Effect v4 系(ピン留め) |
| DB | Drizzle v1(`drizzle-kit` migrations、Effect サービス境界内に隔離)。D1 + DO SQLite |
| フロント | React + FunStack(funstack-static + funstack-router)+ Astryx(StyleX ベース。ADR-0013) |
| CLI | Gunshi(引数パース)+ Effect(実装)+ HttpApi 導出型付きクライアント |
| IaC | Alchemy v2 Effect スタイル(運用側)。セルフホスト配布物は素の wrangler 両対応を維持 |
| docs | Blume(`apps/docs`) |
| Lint/Format | oxlint + oxfmt + ImportLint + fallow + React Doctor |

## モノレポ構成(予定)

```
packages/
  crypto/        # E2EE コア。WebCrypto + HPKE。全環境(ブラウザ/Bun/workerd)で動く。人間レビュー必須
  core/          # ドメイン型、Effect Schema、共有ロジック
  api-schema/    # HttpApi 定義(サーバー実装とクライアント導出の共有源)
apps/
  server/        # Workers + DO + D1。Effect HttpApi
  cli/           # Gunshi + Effect。`maruhi` / `mh` バイナリ
  web/           # FunStack ダッシュボード + ランディング
  docs/          # Blume
```

## 品質ゲート(コミット前に必ず通す)

1. `oxfmt` → 2. `oxlint` → 3. `tsc --noEmit` → 4. ImportLint → 5. fallow(baseline)→ 6. React Doctor(web のみ、diff モード)→ 7. **テスト**(Vitest: crypto/core/CLI は通常環境、サーバー/DO は vitest-pool-workers)

- ImportLint の `@public` によるディレクトリカプセル化を尊重する。内部モジュールへの直 import が必要に感じたら、それは公開 API の設計不足なので人間に相談する
- テスト: サーバー/DO は `@cloudflare/vitest-pool-workers`(workerd 実環境)、crypto/core/CLI は Vitest。`bun:test` は使わない
- `packages/crypto` はテストベクター(`test-vectors/`)による検証を必須とする

## コーディング規約

- エラーは Effect の型付きエラーで表現し、握り潰さない。`catch` で無言に飲むコード禁止
- 新規依存の追加は最小限。追加時は理由をコミットメッセージに書く
- コメント・ドキュメントは日本語可、公開 API の JSDoc は英語
- 未安定依存(Bun 1.4 / Effect v4 / Alchemy v2 / FunStack)のバージョンは厳密にピン留め。更新は独立した PR で意図的に行う

## 参照ドキュメント

- `docs/CRYPTO_SPEC.md` — 暗号仕様(唯一の正)
- `docs/AUTH_SPEC.md` — 認証・アイデンティティ仕様
- `docs/adr/` — 設計判断の記録
- ライセンス: サーバー = FSL-1.1-MIT、CLI/SDK/crypto = MIT(公開前に最終確認。公開までクローズド)
