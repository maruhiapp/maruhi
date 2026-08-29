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
- [ ] ウォッチ: Drizzle v1 正式版(D1 / DO SQLite の Effect ドライバ有無)、Effect v4 安定版化(Bun 1.4 は 2026-08-24 の 1.4.0 到達で完了 — PR #91)

## Phase 1: MVP(クローズド開発)

**完了条件: 自分の全プロジェクトから .env を消せた**

- [x] E2EE コア(純粋 E2EE。サーバー鍵 = 選択的開示は実装しない、データ構造のみ確保)(2026-08-02 完了。PR #12 = packages/crypto: §2.1 エンコーダ / §3 鍵 / §4 変数暗号化 / §5 DEK ラップ / §6 チェーン検証・状態導出 / §8 リカバリーラップ、テストベクター全通過・4 実行環境 CI。§6.3 の DEK ラップ先一致検査・ヘッドゴシップは同期ロジックとして後続)
- [ ] メンバーシップログ(genesis + 単独ユーザー分。検証ロジック込み)※チェーンの暗号・検証層は PR #12、サーバー保存(プロジェクト DO)・追記 API(§6.4 検証 / CAS / 受理ポリシー)は PR #14 で完了(2026-08-02)。クライアント同期のうち §6.3 の DEK ラップ先一致検査は PR #25 で完了(2026-08-03)。残りはヘッドゴシップ(Phase 2)
- [x] CLI: `maruhi run`(メモリ注入)、`push` / `pull`、device flow ログイン、OS キーチェーン(2026-08-03 完了。PR #25 = apps/cli: login〔device flow〕/ logout / key / project init|verify / env create / pull [--show] / push / run / config、OS キーチェーン = Bun.secrets、§5.1 配布時検証・§6.3 同期検査のクライアント実装込み。§6.3 ローカル床(巻き戻し・欠落・前進注入〔値〕の永続検出)は PR #33 = セッション 16 / 真正性シリーズ実装 PR-4 で完了(2026-08-04)。CLI 配布・Windows 対応は Phase 2、初回セットアップウィザード・リカバリーは別項目のまま)
- [x] サーバー: プロジェクト DO、D1、HttpApi、監査ログ(append-only)※ DO・D1(Drizzle v1)・HttpApi に加え、認証・アイデンティティ基盤(AUTH_SPEC 本実装: GitHub OAuth web / device 交換、DB バックセッション、maruhi 発行トークン、パーソナル org、チェーン API の認証・認可 = AUTH_SPEC §11)は PR #16 で完了(2026-08-02)。変数値・環境・DEK API(AUTH_SPEC §12)と監査ログ(project DO 側: AUDIT_SPEC §3.3 / §3.4 / §5.1。同 PR のマージをもって AUDIT_SPEC は所有者承認済み)は PR #18 で完了(2026-08-02)。セッション 07 レビュー裁定 3 件の実装(3-D = ラップの suite 保存、F 先行分 = DEK ラップ行数上限、2-D = 修復経路〔ラップ削除 → 再登録〕+ dek 監査イベント)は PR #20 で完了(2026-08-02)。DEK ラップ登録署名(裁定 2-E = CRYPTO_SPEC §5.1。同 PR のマージをもって §5.1 は所有者承認済み)は PR #21 で完了(2026-08-03)。値・DEK・メタデータの真正性(CRYPTO_SPEC 0.4 改訂 = セッション 12。PR #27 マージで承認)の実装は PR #28(DEK コミットメント / create_environment・rotate_epoch の複合受理)・PR #30(値署名 / 認可時点の二重判定 / prev 連鎖・fork 証拠化)・PR #31(メタデータステートメント / 認証済み名前解決)で完了(2026-08-04。crypto / api-schema / server / CLI 横断)。監査ログの D1 側(認証・org 系 = AUDIT_SPEC §3.1〜§3.2 / §5.2 案 A = user_audit_events / org_audit_events、auth.recovery_* の記録 = AUTH_SPEC §13-5 申し送り解消込み)は PR #42 = セッション 21 で完了(2026-08-10)。残りは読み取り API(Phase 2 の監査ログ UI と同時に設計)。pull のメタデータのみモード(AUTH_SPEC §12-7 改訂 = var.read を記録しない意味論の明文化 + CLI push の名前解決切り替え・DEK 二重取得解消)は PR #41 = セッション 20 で完了(2026-08-10。session-11 §5 の裁定済み後続 PR 3 本はこれで全完了)
- [x] リカバリーコード(保存確認・印刷 / 保管リマインダ等の紛失対策 UX 込み — ADR-0014)(2026-08-09 セッション 18 で完了。CRYPTO_SPEC §8 のサーバー保存・配布面 = AUTH_SPEC §13 起草(登録・再発行 = 置換 upsert / 取得レート制限 = 1 時間 5 回 / status)、D1 `recovery_wraps` + ハンドラ、CLI = `key generate` への発行組み込み(Base32 13 グループ表示・最終グループ再入力の保存確認・エージェント環境スキップ)+ `key recovery`(再発行)+ `key recover`(復元)+ `key show` / login の保管リマインダ。auth.recovery_* の監査記録は D1 側監査基盤(下記残項目)と同時に実装する申し送り)
- [x] セルフホスト初回セットアップウィザード(GitHub OAuth App の作成案内 + client_id/secret 登録。AUTH_SPEC §3 参照)(2026-08-10 セッション 19 で完了。形 = `docs/SELF_HOSTING.md` の検証済み runbook(ADR-0014「セルフホストは上級者経路」)+ 公開設定エンドポイント `GET /auth/config`(セッション 11 裁定 B の実装 — login の client_id 自動解決、CLI 設定は server 1 項目で足りる)+ 未設定検出(プレースホルダ → 503 SetupIncomplete で fail-closed)。ランタイムの client_id/secret 登録 API は先着者乗っ取り経路のため不採用 — AUTH_SPEC §3)
- [x] Deploy to Cloudflare / wrangler 一発デプロイの検証(2026-08-10 セッション 19 で完了。素の wrangler のみで実デプロイ成立: d1 create → migrations apply --remote(drizzle フォルダ形式 = migrations_pattern)→ secret put → deploy → 疎通・cron 確認。起動 35 ms。検証デプロイは残置 = ドッグフーディングの土台(docs/notes/session-19.md §1)。Deploy to Cloudflare ボタンは公開リポジトリ前提のため Phase 2 公開時に検証)
- [ ] 数週間のドッグフーディング

## Phase 2: 公開

**完了条件: SECURITY.md + 脅威モデル文書とセットで public 化**

- 公開前チェックリスト: ライセンス最終確認(FSL-1.1-MIT + MIT 分割)・DCO + CONTRIBUTING.md(いずれも 2026-08-12 完了 — ADR-0003 確定、LICENSE 一式 + README 導入)、テレメトリゼロの明文化、maruhi.dev 取得、商標出願(9 類・42 類)、Deploy to Cloudflare ボタンの実検証(公開リポジトリが前提。モノレポサブディレクトリ指定と D1 自動プロビジョニング — セッション 19 申し送り)、**SELF_HOSTING.md の "Updates" 節へ環境マニフェスト移行の項目を追加**(PR-M1 導入前に作成された環境の `maruhi env rotate --init-manifest` 初期化と「環境の移行 → CI の更新」の順序要件。旧サーバー × 新 CLI ではこの案内自体が通らないため、サーバー更新を先に行うことも明記 — 2026-08-18 PR #81 pullfrog レビュー。公開前の内部移行手順自体は docs/notes/session-28.md §2-2)**(2026-08-19 PR-F1 で完了 — strict 受理〔AUTH_SPEC §12-10〕後の失敗方向の説明込み。順序は後続 PR-F3b〔境界 checkpoint 同梱〕で「サーバー → CI/CLI → 移行 rotate」へ再改訂される前提を本文に注記済み — docs/notes/session-32.md §4-2)**
- 脅威モデル文書(CRYPTO_SPEC を基に「何から守り、何からは守らないか」を明文化)
- チーム共有(add_member / remove_member、エポックローテーション、要ローテーション検出。ゼロ知識運用の UX 設計込み: 未登録ユーザー招待 = CRYPTO_SPEC 未決 #9、鍵フィンガープリント確認、退職時ローテ推奨 — ADR-0014)
- ヘッドゴシップ検証(環境マニフェスト・定期チェックポイントの設計と同時 — CRYPTO_SPEC **旧**未決 #12)**設計・仕様起草済み(2026-08-18 — Wave 3 D。PR #80、docs/notes/session-27.md、CRYPTO_SPEC 0.6-draft §4.3 / §6.2 `checkpoint` / §6.6、AUTH_SPEC §16、AUDIT_SPEC 旧未決 #2 統合。仕様 PR #80 のマージ = 所有者承認)。実装は承認後の後続 PR(PR-M1 マニフェスト → M2 チェックポイント〔受理時スナップショット保存を含む〕→ M3 値スナップショット配布・検証、M4 ゴシップは並走可 — session-27 §14)。**PR-M1(環境マニフェスト)は実装済み(2026-08-18 — テストベクター → crypto → api-schema → server → CLI の全層 + 床のマニフェスト拡張 + `--init-manifest` 移行経路。実装判断は docs/notes/session-28.md)**
- GitHub Actions 同期(ここで選択的開示 = grant_server を実装)**完了(2026-08-17 — Wave 2 全完了)**: A1 = サーバー鍵基盤 + grant/revoke CLI(PR #63)、A2 = OIDC 検証 + lease エンドポイント + 監査(PR #65)+ リプレイ先着束縛(PR #67)、A3 = CLI の CI モード(`maruhi ci run` — OIDC リース + CRYPTO_SPEC §9.1 の全検証義務 + メモリ注入。リポジトリアンカーの生成 = `maruhi project anchor`)+ リポジトリ内 setup-maruhi action(`actions/setup-maruhi` — マーケットプレイス公開は public 化と同時。設計判断は docs/notes/session-25.md)
- 環境間パリティチェック(環境モデル決定が前提)
- 監査ログ UI、Web ダッシュボード(**信頼境界は ADR-0018 — 2026-08-18 裁定**: Web は鍵・平文を持たない管理画面。値・鍵操作は各人の CLI、画面は TUI → 値なし `maruhi ui` → 値ありは独立 ADR の段階導入。W0 は「誰がこの画面を見るか」から)**W0(画面設計)完了(2026-08-28 — ADR-0018 改訂 2: Web は「静的案内 + 読み取り + 失効系のみ」、トークン・招待の発行と生値は端末限定、SECURITY_REVIEW L-2 は AUTH_SPEC §6 の既定 TTL で同時解消。画面目録・gap 分析・実装分割 W1〜W3b は docs/notes/web-dashboard-design.md、裁定は docs/notes/session-39.md)**
- CLI 配布: npm / brew tap / インストールスクリプト、macOS 公証(Apple Developer Program は公開 2〜3 週前に登録)、npm provenance、チェックサム公開
- 運用側デプロイを Alchemy v2 へ載せる(ADR-0012。現状は素の wrangler 経路のみが実在 — セルフホスト配布物はこのまま維持する)。spike-b / セッション 03 の申し送り: ① state store が常設 worker + secret を張る設計を運用として受け入れるか `state:` を差し替えるか ② worker 名が Alchemy の命名規則(`<stack>-<resource>-<stage>-<hash>`)になるので stage / 命名の明示設定 ③ ソースを Alchemy 非依存に保つため **Async Worker 形式に固定**(Effect ネイティブな Worker/DO 記述を使うと wrangler 経路が壊れる)
- ユーザーに見える文言を英語へ統一(ADR-0017)。**CLI 分は完了**(ADR-0016 第 3 段階 — コマンド単位の移行 PR + 最終コミットの共有モジュール一括英語化で、`pull` / `run` / `env create` の先行 3 コマンド分も解消済み)。**web / README / インストーラ / 配布物ドキュメント分は完了**(web = `Root.tsx` の `lang="en"`。README / CONTRIBUTING / SELF_HOSTING / install.sh のユーザー可視メッセージ)。docs サイト(Blume)は実体が未着工(`apps/docs` はプレースホルダのみ)なので、サイト構築時に英語で書く
- docs サイト(Blume)

## Phase 3: エージェント(方針は ADR-0014。優先度順)

- 値なしスキーマ(名前・型・説明・必須のみをエージェントへ開示。`maruhi schema` / MCP。`.env.schema` ファイルは正にしない)
- MCP サーバー同居(スコープ付き・短命・監査付きの読み取り。値なしスキーマの配信機構を兼ねる)
- エージェント向け credential brokering(`maruhi proxy run`: プレースホルダのみ渡し、通信境界で実値に差し替え。「サーバーもエージェントも平文を持たない」)
- DO ベースのリース(「このエージェントセッションに、この変数だけ、30 分」)
- no-reveal 方針化(人間向けの値表示を例外操作に格上げ。エージェント検出時の表示拒否は既定のまま)
- リーク検知・ログ redact(付帯機能。本線を汚さない範囲で)

## 将来(未スケジュール)

- パスキー PRF によるデバイス鍵(封印バックエンド抽象の検討メモ: docs/notes/device-key-sealing.md)、SOPS 互換エクスポート、`maruhi/v2` ハイブリッド PQ、ホステッドクラウド版(着工日 = WorkOS 再判断ポイント、ADR-0009)
- リカバリーの封印バックアップ(ユーザー所有ストレージへ、パスフレーズ / パスキーで暗号化。運営が読める預かりは禁止 — ADR-0014)
- 四眼・承認付き reveal(prod reveal / エクスポート / 危険操作の break-glass。企業向け)、上流 credential の自動ローテーション(コネクタ次第。「要ローテーション検出」= Phase 2 の後続)、remove / 降格から全環境 rotate 完了までの窓の機構化(CRYPTO_SPEC §14.3-5 (ii)。候補はセッション 12 ノート §10-7)
