# maruhi ロードマップ

## Phase 0: 開発開始前(Bun 1.4 リリース + 数週間の待機期間)

- [ ] 仕様の最終レビュー: CRYPTO_SPEC / AUTH_SPEC の未決事項のうち「実装開始前に要決定」3 件(環境モデル、認可モデル、プロジェクトと組織の関係 = AUTH_SPEC §9-1)を決定
- [ ] 監査ログのスキーマ設計(記録イベント一覧、actor = 内部 user_id + 鍵フィンガープリント、DO 内 append-only 形式。「要ローテーション検出」の算出要件を満たすこと)
- [ ] 暗号テストベクターの定義(実装より先にコミット)
- [ ] 検証スパイク(使い捨て):
  - スパイク A: funstack-static + funstack-router + Astryx(ADR-0013)→ Workers Static Assets。`"use client"` 境界、Navigation API 非対応ブラウザの劣化挙動、プリビルド CSS の静的配信 + 厳格 CSP、StyleX コンパイラ(xstyle 用)と Vite の組み合わせを確認
  - スパイク B: Effect v4 HttpApi + Durable Objects(ManagedRuntime パターン)+ vitest-pool-workers + Alchemy v2 デプロイ
  - スパイク C: E2EE ラウンドトリップをブラウザ / Bun / workerd の 3 環境で。HPKE ライブラリ選定(未決事項 #1 を解消)
- [ ] npm `maruhi` プレースホルダ publish + org `maruhi`(@maruhi スコープ)作成
- [ ] ウォッチ: Bun 1.4 安定化、Drizzle v1 正式版(D1 / DO SQLite の Effect ドライバ有無)、Effect v4 安定版化

## Phase 1: MVP(クローズド開発)

**完了条件: 自分の全プロジェクトから .env を消せた**

- E2EE コア(純粋 E2EE。サーバー鍵 = 選択的開示は実装しない、データ構造のみ確保)
- メンバーシップログ(genesis + 単独ユーザー分。検証ロジック込み)
- CLI: `maruhi run`(メモリ注入)、`push` / `pull`、device flow ログイン、OS キーチェーン
- サーバー: プロジェクト DO、D1、HttpApi、監査ログ(append-only)
- リカバリーコード
- セルフホスト初回セットアップウィザード(GitHub OAuth App の作成案内 + client_id/secret 登録。AUTH_SPEC §3 参照)
- Deploy to Cloudflare / wrangler 一発デプロイの検証
- 数週間のドッグフーディング

## Phase 2: 公開

**完了条件: SECURITY.md + 脅威モデル文書とセットで public 化**

- 公開前チェックリスト: ライセンス最終確認(FSL-1.1-MIT + MIT 分割)、DCO + CONTRIBUTING.md、テレメトリゼロの明文化、maruhi.dev 取得、商標出願(9 類・42 類)
- 脅威モデル文書(CRYPTO_SPEC を基に「何から守り、何からは守らないか」を明文化)
- チーム共有(add_member / remove_member、エポックローテーション、要ローテーション検出)
- ヘッドゴシップ検証
- GitHub Actions 同期(ここで選択的開示 = grant_server を実装)
- 環境間パリティチェック(環境モデル決定が前提)
- 監査ログ UI、Web ダッシュボード
- CLI 配布: npm / brew tap / インストールスクリプト、macOS 公証(Apple Developer Program は公開 2〜3 週前に登録)、npm provenance、チェックサム公開
- docs サイト(Blume)

## Phase 3: エージェント

- MCP サーバー同居(スコープ付き・短命・監査付きの読み取り)
- DO ベースのリース(「このエージェントセッションに、この変数だけ、30 分」)
- エージェント向け credential brokering の土台

## 将来(未スケジュール)

- パスキー PRF によるデバイス鍵、SOPS 互換エクスポート、チェーンヘッド外部チェックポイント、`maruhi/v2` ハイブリッド PQ、ホステッドクラウド版(着工日 = WorkOS 再判断ポイント、ADR-0009)
