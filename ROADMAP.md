# maruhi ロードマップ

## Phase 0: 開発開始前(Bun 1.4 リリース + 数週間の待機期間)

- [x] 仕様の最終レビュー: 「実装開始前に要決定」3 件を決定(2026-08-01 所有者裁定): 環境モデル = プロジェクト × 環境 × エポック(CRYPTO_SPEC §3〜§5)、認可モデル = チェーン上の 4 role(CRYPTO_SPEC §6.2)、プロジェクトと組織の関係 = パーソナル org 自動作成(AUTH_SPEC §9-1)
- [x] 監査ログのスキーマ設計(記録イベント一覧、actor = 内部 user_id + 鍵フィンガープリント、DO 内 append-only 形式。「要ローテーション検出」の算出要件を満たすこと)(2026-08-02 完了。AUDIT_SPEC = セッション 06 起草、PR #18 のマージをもって所有者承認済み。チェックの付け忘れを 2026-08-03 に修正)
- [x] 暗号テストベクターの定義(実装より先にコミット)(2026-08-01 PR #11。2026-08-02 PR #12 で grant_server / revoke_server / change_role・認可系 negative・expected_head_states を補完)
- [x] 検証スパイク(使い捨て)3 本完了(2026-08-01。結果は docs/notes/spike-{a,b,c}.md):
  - スパイク A: funstack-static + funstack-router + Astryx(ADR-0013)→ Workers Static Assets。`"use client"` 境界、Navigation API 非対応ブラウザの劣化挙動、プリビルド CSS の静的配信 + 厳格 CSP、StyleX コンパイラ(xstyle 用)と Vite の組み合わせを確認
  - スパイク B: Effect v4 HttpApi + Durable Objects(ManagedRuntime パターン)+ vitest-pool-workers + Alchemy v2 / wrangler 両対応。実デプロイ検証は wrangler 経路成立(Alchemy 経路はユーザー API トークン切り替え待ち。docs/notes/session-03.md)
  - スパイク C: E2EE ラウンドトリップをブラウザ / Bun / workerd の 3 環境で確認。HPKE ライブラリ選定(未決事項 #1)= `hpke`(panva)で決定
- [x] npm `maruhi` プレースホルダ publish + org `maruhi`(@maruhi スコープ)作成(2026-08-01 完了。`maruhi@0.0.1`)
- [ ] ウォッチ: Bun 1.4 安定化、Drizzle v1 正式版(D1 / DO SQLite の Effect ドライバ有無)、Effect v4 安定版化

## Phase 1: MVP(クローズド開発)

**完了条件: 自分の全プロジェクトから .env を消せた**

- [x] E2EE コア(純粋 E2EE。サーバー鍵 = 選択的開示は実装しない、データ構造のみ確保)(2026-08-02 完了。PR #12 = packages/crypto: §2.1 エンコーダ / §3 鍵 / §4 変数暗号化 / §5 DEK ラップ / §6 チェーン検証・状態導出 / §8 リカバリーラップ、テストベクター全通過・4 実行環境 CI。§6.3 の DEK ラップ先一致検査・ヘッドゴシップは同期ロジックとして後続)
- [ ] メンバーシップログ(genesis + 単独ユーザー分。検証ロジック込み)※チェーンの暗号・検証層は PR #12、サーバー保存(プロジェクト DO)・追記 API(§6.4 検証 / CAS / 受理ポリシー)は PR #14 で完了(2026-08-02)。クライアント同期のうち §6.3 の DEK ラップ先一致検査は PR #25 で完了(2026-08-03)。残りはヘッドゴシップ(Phase 2)
- [x] CLI: `maruhi run`(メモリ注入)、`push` / `pull`、device flow ログイン、OS キーチェーン(2026-08-03 完了。PR #25 = apps/cli: login〔device flow〕/ logout / key / project init|verify / env create / pull [--show] / push / run / config、OS キーチェーン = Bun.secrets、§5.1 配布時検証・§6.3 同期検査のクライアント実装込み。§6.3 ローカル床(巻き戻し・欠落・前進注入〔値〕の永続検出)は PR #33 = セッション 16 / 真正性シリーズ実装 PR-4 で完了(2026-08-04)。CLI 配布・Windows 対応は Phase 2、初回セットアップウィザード・リカバリーは別項目のまま)
- [x] サーバー: プロジェクト DO、D1、HttpApi、監査ログ(append-only)※ DO・D1(Drizzle v1)・HttpApi に加え、認証・アイデンティティ基盤(AUTH_SPEC 本実装: GitHub OAuth web / device 交換、DB バックセッション、maruhi 発行トークン、パーソナル org、チェーン API の認証・認可 = AUTH_SPEC §11)は PR #16 で完了(2026-08-02)。変数値・環境・DEK API(AUTH_SPEC §12)と監査ログ(project DO 側: AUDIT_SPEC §3.3 / §3.4 / §5.1。同 PR のマージをもって AUDIT_SPEC は所有者承認済み)は PR #18 で完了(2026-08-02)。セッション 07 レビュー裁定 3 件の実装(3-D = ラップの suite 保存、F 先行分 = DEK ラップ行数上限、2-D = 修復経路〔ラップ削除 → 再登録〕+ dek 監査イベント)は PR #20 で完了(2026-08-02)。DEK ラップ登録署名(裁定 2-E = CRYPTO_SPEC §5.1。同 PR のマージをもって §5.1 は所有者承認済み)は PR #21 で完了(2026-08-03)。値・DEK・メタデータの真正性(CRYPTO_SPEC 0.4 改訂 = セッション 12。PR #27 マージで承認)の実装は PR #28(DEK コミットメント / create_environment・rotate_epoch の複合受理)・PR #30(値署名 / 認可時点の二重判定 / prev 連鎖・fork 証拠化)・PR #31(メタデータステートメント / 認証済み名前解決)で完了(2026-08-04。crypto / api-schema / server / CLI 横断)。残りは監査ログの D1 側(認証・org 系 = AUDIT_SPEC §3.1〜§3.2)と読み取り API(Phase 2 の監査ログ UI と同時に設計)
- [ ] リカバリーコード
- [ ] セルフホスト初回セットアップウィザード(GitHub OAuth App の作成案内 + client_id/secret 登録。AUTH_SPEC §3 参照)
- [ ] Deploy to Cloudflare / wrangler 一発デプロイの検証
- [ ] 数週間のドッグフーディング

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
