# セッション 21 メモ(D1 側監査ログ基盤 — AUDIT_SPEC §3.1〜§3.2 / §5.2 案 A)

日付: 2026-08-10。前提: PR #41(セッション 20)マージ済みの main から開始。
スコープ: ROADMAP Phase 1 サーバー項目に唯一残っていた「監査ログの D1 側
(認証・org 系)」+ セッション 18 の申し送り(auth.recovery_* の記録 =
AUTH_SPEC §13-5)の解消。保存先は AUDIT_SPEC §5.2 で裁定済みの案 A(D1)。

## 1. 仕様(実装に伴う細則の明文化 — マージをもって承認)

- **AUDIT_SPEC 0.6**: §5.2 に実装注記(テーブル = `user_audit_events` /
  `org_audit_events`、DO 専用列は持たず org_id / project_id を列昇格、users への
  FK なし、同一トランザクション追記は各リポジトリの batch 同梱)。§3.1 に記録
  細則 4 点: login_succeeded がセッション id(保存 id と同じハッシュ)を payload
  に写す / session_revoked は明示失効のみ(期限切れ掃除は記録しない)/
  login_failed の actor は user_id なしの type=user / 同名ローテーションは
  token_created 1 行(旧行削除を独立の token_revoked にしない)。§3.2 に
  パーソナル org の org.created + org.member_added と「org 名スナップショットを
  写さない」(providerLogin 由来 = §1-2 の禁止情報)
- **AUTH_SPEC §13-5**: 申し送りを解消。取得の記録は**配布した応答(200)のみ**
  (レート制限拒否・未登録 404 は記録しない — §13-3 の計数対象と同じ線引き)

## 2. 設計判断

- **同一トランザクション追記の形**: 監査挿入文(userAuditInsert / orgAuditInsert)
  を各リポジトリが自分の D1 batch へ同梱する。DO 側 audit-store の appendSync
  (同期ブロック原子性)の D1 対応物。単独追記サービス(D1AuditRepo)は
  主データ書き込みを伴わないイベント(login_failed / device flow の
  login_succeeded)専用
- **イベントと書き込み経路の対応**:
  - createUserBatch: user_created + identity_linked(provider 種別名のみ)+
    org.created(personal)+ org.member_added(owner 本人)を既存 batch に同梱
  - sessions.insert: login_succeeded(§3.1 の 1:1 規定に基づきリポジトリ内で固定)
  - sessions.revokeByHash(新設): 明示失効専用。先に行を引いて actor(所有者・
    auth_method)を写し、削除と同一 batch で session_revoked。期限切れ掃除の
    deleteByHash / deleteExpired は従来どおりイベントなし
  - tokens.replaceForUserAndName: token_created(tokenId / name / scopes)。
    tokens.revokeById(deleteById を置換): token_revoked(actor のトークン id =
    失効対象 id — v1 は自トークン失効のみ)
  - recovery.upsert / recordFetch: actor(principal 由来)を引数で受け、
    reissued / blob_fetched を各 batch に同梱
  - projects.insertIfAbsent: org.project_created は**行が実際に挿入されたとき
    のみ**記録(PR レビュー = Cursor Bugbot 指摘対応、修正実装は Bugbot Autofix
    案を採用: onConflictDoNothing をやめ素の挿入 + 監査行の 2 文 batch とし、
    PK 競合時は batch ごと原子的に巻き戻して no-op(isUniqueConflict 判別)。
    偽イベントの混入も監査行だけの欠落も起きない)
- **device flow のログイン成功**: セッションを作らないため sessions.insert に
  相乗りできない。getOrCreateUser 直後にハンドラで単独追記(トークン発行が
  上限で失敗しても GitHub 検証は成功している、の順序に整合)
- **login_failed は未認証経路からの D1 書き込み**になる(仕様が記録を要求)。
  PR レビュー(Cursor Security Agent, MEDIUM)の指摘を受け、固定窓の全体上限
  (1 時間 100 行、超過は不記録のベストエフォート — AUDIT_SPEC §3.1 に明文化)
  で書き込み増幅を有界にした。窓の実測・上限値の調整は §5.3 のドッグフー
  ディング実測と同時に見直す

## 3. 実装

- db.package: schema に 2 テーブル + 索引(actor / target / event、org は org_id
  も)、audit.ts(挿入文ビルダ + D1AuditRepo + principalAuditActor)、repos の
  各所へ batch 同梱。drizzle マイグレーション 1 本
- auth.package: session.revokeSession → revokeByHash、token.revokePresentedToken
  → revokeById
- handlers-auth: login_failed(state-mismatch / code-exchange-failed /
  github-token-invalid × web・device)、device flow の login_succeeded、recovery
  への actor 受け渡し。handlers-membership: init へ principal を通し
  org.project_created

## 4. テスト・品質

- server +15(audit-d1.test.ts): サインアップ一括イベント列 / 再ログインの差分 /
  login_failed の固定窓上限(上限で抑制・窓経過で再開)/ 冪等挿入の空振りが
  org.project_created を増やさない /
  login_failed 3 種の理由と匿名 actor / device flow の token_created(id・name・
  scopes 突合)/ ローテーション 2 行 / session_revoked の id 突合と再ログアウト
  無記録 / **期限切れ掃除が session_revoked を出さない** / token_revoked の
  actor = 対象 / recovery の配布時のみ記録(404・429 は無記録)/
  org.project_created の座標と actor / 禁止情報スキャン(provider 数値 ID・
  login・@ が全行に現れない — DO 側 §1-2 テストの D1 版)
- 既存テストの追随は test/support/auth.ts の reset テーブル追加のみ(API 変更が
  サーバー内部に閉じた)
- `bun run check` green(940 テスト)

## 5. スコープ外(申し送り)

- 監査ログの読み取り API と閲覧権限の詳細は Phase 2 の監査ログ UI と同時
  (AUDIT_SPEC §6〜§7 / 未決 #1)
- org の改名・削除・メンバー管理 API は未実装のため、対応する §3.2 イベントの
  記録は API 導入時に開始する(AUDIT_SPEC §5.2 実装注記に明文化)
- login_failed の書き込み量・var.read の集約方針はドッグフーディングの実測後
  (AUDIT_SPEC §5.3 / 未決 #4)
- ドッグフーディング開始時の人間タスク(GitHub OAuth App 作成 + 検証デプロイ
  への登録 — session-19 §6)は未着手のまま有効
- チェーン追記系コマンド・crypto test/checks の整理候補(session-17 §4)は
  未着手のまま有効
