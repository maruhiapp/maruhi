# maruhi 認証・アイデンティティ仕様書 (AUTH_SPEC)

Version: 0.13-draft
Status: 所有者承認済み(§11 は 2026-08-02 のセッション 06 裁定、§12 は 2026-08-02 のセッション 07 提案を反映。§12-2 の suite / §12-6 の修復経路 / §12-8 の DEK ラップ行数上限はセッション 07 の所有者裁定をセッション 08 で反映。§12-2 / §12-6 の DEK ラップ登録署名は CRYPTO_SPEC §5.1 として PR #21、§12-6 のメンバー鍵一意性は CRYPTO_SPEC §6.2 として PR #22 で承認済み。§12-1〜§12-8 の値・メタデータ署名 / DEK コミットメント / 環境作成のチェーン op 化に伴う改訂は 2026-08-04 の PR #27 マージで承認。§12-8 の metaVersion 行数上限と §12-4 の環境削除カスケード対象への変数メタステートメント明記は、2026-08-04 のセッション 15 所有者裁定 — PR #31 マージで承認 — をセッション 15.5 で反映。§13 リカバリーブロブ API は 2026-08-09 セッション 18 起草 — PR #38 マージで承認。§3 のセットアップウィザードの形と §4 の公開設定エンドポイント `GET /auth/config`(セッション 11 裁定 B の実装)は 2026-08-10 セッション 19 起草 — 実装 PR のマージをもって所有者承認とする。§3-2 の client_id 登録方法の Workers Secret への統一(Deploy to Cloudflare ボタン対応の前提工事)は 2026-08-11 起草 — 実装 PR のマージをもって所有者承認とする。0.9-draft = Phase 2 機能裁定の起草 — 2026-08-12 セッション 22: §4 サーバー鍵 FP の公開 / §12-4・§12-6 のサーバー鍵宛ラップ〔旧 v1 線引きの解消〕/ §14 ワークロードリース API / §15 招待 API — **本改訂 PR のマージをもって所有者承認とする**。§4 の `serverEncPubHex` は A1〔PR #63〕の実装挙動に追いつかせた記述改訂、§14-1 の `crit` 拒否と JWKS の猶予窓、§14-3 のレート制限の位置と 503 の 2 理由〔`oidc-jwks-unavailable` / `server-key-unconfigured`〕は 2026-08-15 の Wave 2 A2 起草 — **本改訂 PR のマージをもって所有者承認とする**。§14-1 の先着束縛と §14-3 の判定順への追加〔401 `token-replayed`〕は 2026-08-15 の所有者裁定 — 設計比較は docs/notes/session-24.md — の反映。§15-2 受諾行のトークン条件の明文化〔B1a 実装済み挙動の追認 — PR #68 申し送り ①〕と §15-3 の `r` パラメータ追加〔§15-1 の受諾前 role 表示の運搬経路 — 同申し送り ②〕は 2026-08-15 の B1b 所有者裁定 — **本改訂を含む実装 PR のマージをもって所有者承認とする**。0.10-draft = 2026-08-15 の Wave 2 B2 所有者裁定〔PR #69 申し送りの解消 + AUDIT_SPEC §4.1 実装の受理面〕: §12-5 の再暗号化マーカー / §12-6 の 409 応答への占有ラップ受信者 enc 公開鍵の同梱と再追加受理時の旧鍵宛ラップ掃除 — **本改訂を含む実装 PR のマージをもって所有者承認とする**(PR #70 マージ済み = 承認済み)。0.11-draft = Wave 3 D の起草(2026-08-18 セッション 27 — 設計探索は docs/notes/session-27.md): §12-2 / §12-4 / §12-5 / §12-7 / §12-8 の環境マニフェスト(CRYPTO_SPEC §4.3)の受理・配布面 / §14-2 のリース応答への同梱 / §16 ヘッド申告・チェックポイント支援 API — **本改訂 PR のマージをもって所有者承認とする**(PR #80 マージ済み = 承認済み)。§12-5 (6) の manifestVersion CAS 初期値の明確化(保存済みマニフェストなし = 最新 0 → manifestVersion 1 受理 — 移行経路)は 2026-08-18 の PR-M1 実装起草 — 本改訂を含む実装 PR のマージをもって所有者承認とする(PR #81 マージ済み = 承認済み)。0.12-draft = PR-M1 マージ後監査(docs/notes/session-31.md)の裁定 1〜3 の起草(2026-08-19 セッション 32 — 設計比較・棄却案は session-31 §7 と docs/notes/session-32.md §2・§4〜§5。裁定 2 = 案 2-G′・裁定 3 = 3-D + 3-E + 3-E′ + 3-F の選択は 2026-08-19 所有者裁定済みで、本 PR は仕様文言の承認): 裁定 1 = §12-10 security-critical 受理スキーマの厳格性(未知フィールド拒否)・wire 非互換変更の設計規範・mutation 成功の定義(CRYPTO_SPEC §1 原則 6 と対)。裁定 2 = §12-4 の環境作成・ローテーション複合への境界 `checkpoint` エントリの必須同梱(チェーン 2 エントリ + データ登録の単一トランザクション受理)と複合内整合検査の拡張(checkpoint タプル ↔ 同梱マニフェストの束縛一致)— **本改訂 PR のマージをもって所有者承認とする**)。0.13-draft = W0(Web ダッシュボード画面設計 — ADR-0018 改訂 2)の裁定の起草(2026-08-28 セッション 39 — 画面設計は docs/notes/web-dashboard-design.md、裁定の経緯は docs/notes/session-39.md): §5 のセッション主体の能力制限(肯定列挙 — 裁定 AT。PR #103 pullfrog レビュー指摘の反映)とその §13-2 / §15-2 への追随 / §6 のトークン管理の線引き更新(追加発行 API は作らない・一覧 / 指定失効 API の設計〔対象 = 本人のみ・非該当 404〕・既定 TTL = SECURITY_REVIEW 2026-08-14 L-2 の解消)/ §15-3 の招待リンク着地点の静的案内ページ化(フラグメント非解釈)— **本改訂 PR のマージをもって所有者承認とする**

認証は GitHub OAuth の直接実装で行う(認証フレームワーク・外部 IdP サービスは使用しない)。
ただしデータモデルは将来のエンタープライズ IdP(WorkOS 等)追加を無停止で行える形に固定する。
この設計判断の経緯は ADR-0009 を参照。

---

## 1. 原則

1. **GitHub は認証手段であり、アイデンティティの主ではない**。システム内の主体は常に内部 user_id
2. **メールによる自動アカウントリンクは行わない**(アカウントリンク攻撃対策)。リンクは常にログイン済みセッションからの明示操作
3. **セッションは DB バックで失効可能**。stateless JWT のみのセッションは禁止
4. **CLI / API トークンは maruhi 自身が発行する**。GitHub のトークンを保存・流用しない
5. ユーザー作成は単一の冪等な入口(get-or-create)で行い、認証フローと密結合させない

## 2. データモデル

```sql
users (
  id            TEXT PRIMARY KEY,   -- ULID。内部 user_id。全システムの主体識別子
  email         TEXT,               -- 表示・通知用。識別子として使用禁止
  email_verified INTEGER NOT NULL DEFAULT 0,
  created_at, updated_at
)

linked_identities (
  user_id          TEXT NOT NULL REFERENCES users(id),
  provider         TEXT NOT NULL,   -- 'github'(将来: 'workos' 等)
  provider_user_id TEXT NOT NULL,   -- GitHub の数値 ID(login 名ではない。login は変更可能)
  provider_login   TEXT,            -- 表示用スナップショット
  linked_at,
  PRIMARY KEY (provider, provider_user_id)
)

organizations (
  id, slug, name, created_at
  -- 将来カラム(今は作らない): sso_connection_id, allowed_domains, enforce_sso
)

memberships (
  org_id, user_id, role,            -- role: 'owner' | 'admin' | 'member'
  PRIMARY KEY (org_id, user_id)
)

sessions (
  id            TEXT PRIMARY KEY,   -- ランダム 256-bit の SHA-256 ハッシュを保存(生値は保存しない)
  user_id       TEXT NOT NULL,
  auth_method   TEXT NOT NULL,      -- 'github_oauth'(将来: 'sso' 等)。SSO 強制ポリシーに必要
  created_at, expires_at, last_used_at
)

api_tokens (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL,
  name          TEXT NOT NULL,
  token_hash    TEXT NOT NULL,      -- SHA-256。生トークンは発行時に一度だけ表示
  token_prefix  TEXT NOT NULL,      -- 表示用(例: maruhi_pat_Ab12…)
  scopes        TEXT NOT NULL,      -- JSON 配列
  expires_at, created_at, last_used_at
)
```

規則:
- プロジェクト・監査ログ・メンバーシップチェーン等、他のあらゆるテーブル / 構造からの参照は `users.id` のみ。`provider_user_id` を外部キーとして使用禁止
- ルックアップは `(provider, provider_user_id)` でのみ行う。メールでのユーザー検索・照合をコードパスとして作らない
- **memberships.role(org ロール)はプロジェクトアクセスに関与しない**。プロジェクトのデータアクセス・操作権限の唯一の真実源は CRYPTO_SPEC §6 のメンバーシップチェーンである(§9-2 の決定)

## 3. Web ログイン(GitHub OAuth Authorization Code Flow)

**セルフホストの前提**: GitHub OAuth(web / device とも)には OAuth App の client_id / client_secret が必要であり、これは maruhi が中央で配布できない(コールバック URL がデプロイごとに異なるため)。**セルフホストする各ユーザーが自分の GitHub OAuth App を作成する必要がある**。

**初回セットアップウィザードの形(2026-08-10 セッション 19 設計。実装 PR のマージをもって所有者承認)**:

1. **導入手順の正は `docs/SELF_HOSTING.md`**(実デプロイで検証済みの wrangler コマンド列 + OAuth App 作成案内)。セットアップの全手順が Cloudflare 資格情報を要する wrangler 操作であり、maruhi CLI にもサーバーにも CF 資格情報を持たせない。対話的な CLI ウィザードは作らない — セルフホストは上級者経路(ADR-0014 裁定 5)であり、コピー&ペースト可能な検証済み手順書が最小かつ十分
2. **client_id / client_secret はともに Workers Secret として登録する(`wrangler secret put` ×2)。ランタイムの登録 API・「初回アクセス時の Web 登録フォーム」は作らない**: client_id は公開情報(§4)であり秘匿目的ではない — 登録経路を secret に統一するのは、`wrangler.jsonc` の編集(フォークへのコミット)を不要にし、`secret put` の即時反映により再デプロイなしで設定を完了させるため(Deploy to Cloudflare ボタン経由のデプロイでは複製リポジトリの編集を挟まない導線が前提。2026-08-11 改訂 — 旧仕様は client_id を wrangler vars で配布していた)。Web 登録フォームを作らない理由: 未認証の初回登録面は「デプロイ直後に先にアクセスした者が自分の OAuth App を登録してインスタンスを乗っ取る」経路になり、防ぐには別のブートストラップシークレットの配布が要る(複雑さの追加に見合わない。設定はデプロイ時に固定するのが最小)
3. **未設定サーバーの自己診断**: OAuth App 設定が未完(client_id がプレースホルダ `replace-with-your-github-oauth-app-client-id`(client_id を wrangler vars で配布していた旧テンプレートのフォークへの後方互換防御)/ 空 / 欠落、**または client_secret が未登録 / 空**)のサーバーは、`GET /auth/config`(§4)・`GET /auth/github/start`・`POST /auth/device/exchange` が 503 `SetupIncomplete`(reason: `github-oauth-unconfigured`)を返し、セットアップガイドへ誘導する(GitHub のエラーページや不透明なトークン交換失敗 = `AuthFlow` 400 へ落として原因を分からなくしない)。secret も条件に含めるため、`/auth/config` の 200 は「client_id / client_secret とも登録済み」の確認として使える(`SELF_HOSTING.md` の "6. Smoke-check")
4. CLI 側の client_id 自動解決は §4 の公開設定エンドポイントで行う(セルフホスト利用者の CLI 設定は `server` 1 項目で足りる)

1. `GET /auth/github/start`: `state`(128-bit 乱数)を発行し、HttpOnly クッキーに保存して GitHub へリダイレクト。scope は最小(`read:user user:email`)
2. `GET /auth/github/callback`: `state` 検証(不一致は即拒否)→ code 交換 → GitHub API でユーザー情報取得
3. `getOrCreateUser(provider='github', provider_user_id, profile)`:
   - linked_identities に存在 → 該当 user を返す
   - 不在 → users + linked_identities を作成(email は GitHub 側で verified なもののみ `email_verified=1` で保存)
4. セッション発行(§5)

- GitHub のアクセストークンは即時破棄する(保存しない)
- 既ログイン状態からの別プロバイダ連携は「明示リンク」フロー(ログイン済みセッション + 新規 OAuth 完了)でのみ許可

## 4. CLI ログイン(GitHub Device Flow, RFC 8628)

1. CLI が GitHub の device flow を開始し、user_code と検証 URL を表示
2. ユーザーがブラウザで承認 → CLI が GitHub トークンを取得
3. CLI はそのトークンで maruhi サーバーの `/auth/device/exchange` を呼ぶ
4. サーバーは GitHub API でトークンを検証し、getOrCreateUser → **maruhi 発行の API トークン**を返す
   - **audience 検証(2026-08-02 追加)**: 持ち込まれたトークンの検証は check-token API(`POST /applications/{client_id}/token`、Basic 認証 = client_id:client_secret)で行い、**自分の OAuth App に対して発行されたトークンであること**まで確認する。`GET /user` による有効性確認だけでは、他のアプリ向けに発行された(漏洩・流用)トークンで他人のアカウントに解決できてしまう(confused-deputy)
   - **形式事前検査(2026-08-15 追記 — セキュリティレビュー L-3)**: `/auth/device/exchange` は未認証で到達でき、リクエストごとに check-token API へのアウトバウンド呼び出しを伴う。この API の呼び出し枠は OAuth App 単位でレート制限されるため、無制限に中継するとゴミトークンの洪水でデプロイメントの枠が枯渇し、正規ユーザーのログインが失敗する。GitHub のトークン形式(`gh<種別 1 文字>_` プレフィックス + Base62/`_` 本体)を満たさない入力はワイヤ Schema で 400 とし、GitHub へ問い合わせない(形式を満たす入力の検証・失敗記録は従来どおり)。**この検査が遮断するのは無差別・形式不明の洪水までである**: 形式適合のトークンを流す標的型の洪水への送信元単位の対策は 2 層とする(2026-08-24 deepsec M3/B11 対応): (a) 既定デプロイの `wrangler.jsonc` が持つ Workers Rate Limiting binding(発信元 IP 単位 10 回/分。per-colo の best-effort。超過は 429 `AuthRateLimited`。判定はハンドラ最初 = GitHub へのアウトバウンドより前。binding 不在の旧設定デプロイは従来挙動)、(b) より強いグローバル計数が要る場合の運用側 Cloudflare WAF ルール(`docs/SELF_HOSTING.md` の "Recommended hardening")。web OAuth の `/auth/github/callback` も同種の未認証アウトバウンド(code 交換 + `/user`)を持つため、クエリに同様のサイズ上限を課し、同じく運用側レート制限の対象とする
5. GitHub トークンは両側で即時破棄。CLI は maruhi トークンのみを OS キーチェーンに保存する

- **公開設定エンドポイント `GET /auth/config`(2026-08-03 セッション 11 裁定 B。2026-08-10 セッション 19 で実装)**: 未認証で `{ githubClientId }` を返す。client_id は公開情報(authorize URL のクエリに平文で現れる)であり、未認証面の増加は許容する(裁定 (ii))。サーバーが未設定(§3 の自己診断条件 — client_secret の未登録を含む)の場合は 503 `SetupIncomplete` を返す。**サーバー鍵 FP の公開(2026-08-12 起草。実装は 2026-08-13 の PR #63 でマージ済み)**: デプロイメント keypair(CRYPTO_SPEC §9)が設定済みの場合、応答に `serverKeyFingerprintHex` と `serverEncPubHex`(32 バイト hex)を加える — 前者は grant_server 実行時の照合対象(同 §9 のサーバー鍵確認)、後者は同 §9 の「サーバーが配布する enc 公開鍵」の配布チャネル(grant_server payload に載せる公開鍵そのもの)。どちらも公開情報であり、未設定のデプロイメントでは両フィールドとも省略する
- **CLI の client_id 解決順**: `--github-client-id` フラグ → config の `githubClientId` → `GET /auth/config`。導入後も config の `githubClientId` は上書き手段として残す(GHES・テスト用 — 裁定 (iii))

## 5. セッション

- 生成: 256-bit 乱数。クライアントには生値、DB にはハッシュのみ
- クッキー: `__Host-maruhi_session` / `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/`
- 有効期限: 30 日(スライディング更新)。サーバー側削除で即時失効可能
- CSRF: SameSite=Lax + 書き込み系は custom header 要求(HttpApi ミドルウェアで一括)。状態を持つ GET はミドルウェア外でハンドラが追加要求する(§11-4 の明示規定一覧)
- **セッション主体の能力制限(2026-08-28 W0 裁定 — ADR-0018 改訂 2・1 項。実装は Wave 3 W2b — セッションを持つ Web 画面の初出〔W2〕より前)**: セッションクッキーは XSS に最も晒される資格情報であり(同一オリジンの XSS は CSRF ヘッダーも自分で付けられる)、Web の境界原則(読み取り + 失効系のみ)は UI・バンドルの省略では強制にならない。セッション主体が呼べる API を**肯定列挙**で制限する — 許可: **認証・自己情報系**(§3 のフロー・ログアウト・`GET /auth/me`・`GET /auth/recovery/status`)、**読み取り**(チェーン取得〔§11〕・環境一覧・メタデータのみ pull〔§12-7〕・監査読み取り〔AUDIT_SPEC §7〕・要ローテーションフラグビュー・招待一覧〔§15-2〕・トークン一覧〔§6〕・**プロジェクト一覧〔W2a で設計 — 返すのは本人の membership のみ。設計文書 S4〕**)、**失効系**(招待の失効〔§15-2〕・トークンの指定失効〔§6〕)。**列挙外はセッション主体に対して拒否する**(fail-closed — 新設エンドポイントの既定は「セッション不可」であり、セッションに開く場合は本列挙への追加を同じ改訂で行う。拒否の位置は §11-2 の存在秘匿・§12-3 の判定順と整合させ、実装 PR は受理経路の固定テストで実効性を保証する。実装形は §12-10 (1) と同じ型を推奨: エンドポイント契約への宣言焼き込み = 単一実装点とし、ハンドラごとの手動検査を持たない)。とくに次はセッションからの正当な導線が存在せず明示的に拒否する: 値付き一括 pull(§12-7 — セッション経由の監査証跡汚染 = SECURITY_REVIEW L-1 の発生面自体を消す)、DEK の取得・登録・削除(§12-6 — 削除は署名を伴わない唯一の破壊系)、チェーン追記・init(§11)、環境・変数の全 mutation(§12-4 / §12-5)、招待の発行・受諾(§15-2)、rotation dismiss(AUDIT_SPEC §7)、リカバリーブロブの登録・取得(§13-2)。署名を要する操作は鍵を持たない XSS には元々成立しないが、明示拒否に含めて防御を署名検証の実装詳細に依存させない。CLI・`maruhi ui` はトークン主体であり影響を受けない

## 6. API トークン

- 形式: `maruhi_pat_` + Base62 乱数(256-bit 相当)。プレフィックスで種別判別・secret scanning 対応
- スコープ: プロジェクト単位 × 権限(read / write / admin)。実効権限は min(トークンスコープ, 所有者のチェーン role)(§9-2)。将来: 環境単位のスコープ(Phase 2、CRYPTO_SPEC 未決事項 #11 と連動)、エージェント用の短命リーストークン(Phase 3、CRYPTO_SPEC と連動)
- 検証: 提示トークンの SHA-256 を DB と照合。タイミング安全比較
- **スコープ表現(2026-08-02 決定)**: スコープは `{ project: <project_id> | "*", permission: "read" | "write" | "admin" }` の配列。`"*"` は「所有者の全プロジェクト」を指すワイルドカード(CLI の作業用トークンに使う。実効権限は常に min(スコープ, チェーン role) でチェーン role に束縛されるため、ワイルドカードでも本人のチェーン権限を超えない)。device flow 交換時に要求スコープを指定し、省略時は `[{ project: "*", permission: "admin" }]`
- **操作が要求する権限水準(2026-08-02 決定。2026-08-03 改訂)**: チェーン取得 = read。チェーン追記はエントリの op で決まる(`checkpoint` だけは payload の audit_head_hash の空 / 非空も含めて決まる)— `create_environment` / `rotate_epoch` = write(**ただしこの 2 op は §12-4 の複合リクエスト経由でのみ受理し、汎用チェーン追記 API では型付きエラーで拒否する** — チェーンエントリと付随データの原子性を汎用経路が迂回できないようにするため)、`checkpoint` = **audit_head_hash が空なら write、非空なら admin**(汎用追記経由 — §16-2。2026-08-18)、`add_member` / `remove_member` / `change_role` / `grant_server` / `revoke_server` = admin。プロジェクト作成(genesis init)= admin。op ごとの認可(誰がその op を実行できるか)の真実源は引き続きチェーン role(CRYPTO_SPEC §6.2)であり、この表はトークンスコープ側の必要条件である。データプレーン(変数・環境・DEK)の op 別水準は §12-3 の表に規定する
- **v1 の線引き(2026-08-02 決定。2026-08-28 W0 裁定で更新 — ADR-0018 改訂 2・3 項)**: トークンの発行経路は device flow(§4)のみ — **追加発行の UI / API は作らない**(生値がワイヤ・画面に現れる場所を「発行時の端末表示 1 箇所」に固定する。生値は Web にも `maruhi ui` の DOM にも出さない)。管理系 API は「自分自身のトークンの失効」(提示トークン自身の失効・トークン主体限定 — CLI logout 用)に加え、Web ダッシュボードのトークン管理(**一覧・失効まで** — 同改訂 1 項)向けに次の 2 面を設計する(実装は Wave 3 W3a — docs/notes/web-dashboard-design.md §7): (1) **一覧 `GET /auth/tokens`** — 自分のトークンの id / name / token_prefix / scopes / created_at / last_used_at / expires_at を返す。**生値・token_hash は返さない**。(2) **指定失効**(token id 指定)— 認可はセッション主体、または `*` × admin スコープを含むトークンのみ(§13-2 の鍵素材条件と同水準: スコープ限定トークンの窃取で他のトークンを失効させる可用性攻撃を遮断する)。**対象は本人(認証主体)のトークンのみ**: 他ユーザーの・存在しない token id の指定は一様に **404** で拒否する(黙って成功させない規律 — §12-6 の削除系と同じ。一様応答により他人のトークン id の存在有無を漏らさない)。名前変更 API は作らない(同名再発行 = ローテーションで足り、書き込み面を増やさない)
- **既定 TTL(2026-08-28 起草 — SECURITY_REVIEW 2026-08-14 L-2 の解消。ADR-0018 改訂 2・3 項)**: device flow で発行するトークンは既定の有効期限を持つ(起草値: 発行から **90 日**。expires_at へ発行時に固定 — セッション §5 のスライディング更新とは意図的に非対称: トークンには定期再認証を強制する)。期限切れトークンは検証時に 401 で拒否する(失効と同じ扱い)。更新は再ログイン = 同名ローテーション(上記)。既存(無期限)トークンへの遡及の要否・移行規則は実装 PR で定める。セルフホストでの値の調整は受理ポリシーの引き上げと同様に許す(合意規則ではない)。**リース対応の範囲に注意(2026-08-28 PR #103 レビュー反映)**: ワークロードリース(§14)でトークン不要になるのは対応 issuer のワークロード(v1 = GitHub Actions のみ — §14-1)であり、**リース非対応の実行環境(GitLab CI / k8s / cron 等)で PAT を無人利用している場合、本 TTL は 90 日ごとの再ログイン(人間の介在)を要求する**。この形の扱い(発行時の明示 TTL 指定〔上限つき〕を許すか、対応 issuer の拡張で解くか)は実装 PR(W3a)の裁定に申し送る — 無期限の既定へ戻す選択肢は採らない(L-2 の再導入)
- **同名トークンはローテーション(2026-08-02 追加)**: 同一 (user, name) への発行は既存トークンの失効を伴う再発行とする(再ログイン = ローテーション)。失効と挿入は原子的に行い、並行発行でも同名トークンは 1 本(DB の一意制約で保証)
- **発行の上限(2026-08-02 追加、2026-08-27 deepsec S7 原子化)**: 別名トークンはユーザーあたり 100 本まで(超過は 429。同名ローテーションは上限に達していても可能)。上限判定と新規 insert は同じ `INSERT … SELECT … WHERE` で原子的に行い、異なる token 名の並行発行が同じ under-limit を観測して上限を超える形を許さない。同名ローテーションは既存行の検出・旧 id を載せた `auth.token_created`・置換を D1 batch で直列化する。トークン名は 128 文字以下、スコープは 100 エントリ以下、スコープの project はプロジェクト ID 形式または `"*"` のみ(認証済み主体による api_tokens の肥大 DoS の遮断)

## 7. 将来の IdP 追加(WorkOS 挿入ポイント)

ホステッド版でエンタープライズ SSO を提供すると決めた場合の変更点は以下に限られる(それ以外の変更が必要になったら本仕様の設計ミスとして扱う):

1. `AuthProvider` Effect サービスに WorkOS 実装を追加(OIDC コールバック → getOrCreateUser(provider='workos', …))
2. organizations に SSO 関連カラムを追加(sso_connection_id, allowed_domains, enforce_sso)
3. sessions.auth_method による「SSO 必須」ポリシーの実施
4. SCIM deprovision: users の無効化 + 該当セッション削除 + org からの除去(メンバーシップチェーンの remove_member はチーム管理者のクライアント操作として通知)

## 8. Effect サービス構成

- `AuthProvider` — プロバイダとの認証ダンス(GitHub web / device)。プロバイダ検証済みアイデンティティを返す
- `IdentityService` — getOrCreateUser、明示リンク、users / linked_identities の管理
- `SessionService` — セッションの発行・検証・失効
- `TokenService` — API トークンの発行・検証・失効・スコープ判定

## 9. 旧未決事項(2026-08-01 決定済み)

1. ~~プロジェクトと組織の関係~~ **決定: パーソナル org 自動作成を採用**
   - サインアップ(getOrCreateUser での user 新規作成)時に、本人が owner のパーソナル org を自動作成する。`projects.org_id` は NOT NULL(「org なしプロジェクト」は存在しない)
   - パーソナル org は通常の org と同一モデル。特別扱いは「自動作成される」ことのみで、名前変更・メンバー招待が可能なままチームに成長できる(移行処理なし)
   - 単独利用時の UI / CLI は org の存在を表示しなくてよい(概念の簡素化は表示層で行い、データモデルは単一に保つ)
   - 一般規則: org の最後の owner は削除・脱退・降格できない
2. ~~認可モデル~~ **決定: org ロールとプロジェクトロールの完全分離**
   - org role(owner / admin / member)が認可するのは org 管理のみ: プロジェクト作成 = member 以上、org メンバーの招待・削除 = admin 以上、org の改名・削除 = owner
   - プロジェクトのデータアクセス・チェーン操作は CRYPTO_SPEC §6.2 のチェーン role(owner / admin / member / reader)のみが決める。**org 加入はいかなるプロジェクトアクセスも自動付与しない**(E2EE の明示的な鍵ラップと整合)
   - API トークン(§6)のスコープは project × (read / write / admin) とし、実効権限は min(トークンスコープ, トークン所有者のチェーン role)。トークンで本人のチェーン role を超えることはできない

## 10. 禁止事項

- メール一致による自動リンク・自動マージ
- GitHub login 名(変更可能)を識別子として使うこと
- GitHub トークンの永続化
- セッション / トークン生値の DB 保存・ログ出力
- パスワード認証の追加(本仕様の全面改訂なしに導入禁止)

## 11. チェーン API との接続(2026-08-02 所有者裁定)

AUTH_SPEC(リクエスト認証)と CRYPTO_SPEC §6(チェーン認可)の接続部の規定。

### 11-1. 認証主体とチェーン actor の対応

- チェーン操作 API(init / get / append)はすべて**認証必須**
- 追記系(init / append)は「**認証済み主体の内部 user_id と entry.actor.user_id の厳密一致**」を受理条件とする。不一致は拒否する
- この一致要求は **API 受理ポリシー**であり、チェーン有効性の合意規則(CRYPTO_SPEC §6.1)ではない。チェーン形式は user_id の形式(ULID か否か)に依存せず検証可能であり続ける — ID 形式を有効性規則へ持ち込むことは、暗号学的利得なしにプロバイダ独立性を毀損するため行わない。本番のチェーンには結果として内部 ULID が載る。crypto のテストベクター(任意形式の bounded string)は無変更のまま正であり、サーバー統合テストは users にベクター ID の行をシードして整合させる
- `add_member` 等の対象(target_user_id)の存在検証はチェーン受理では行わない(合意規則を認証 DB に依存させない)。相手の実在・鍵の真正性は招待機構(§15、CRYPTO_SPEC §6.5 — 2026-08-12 起草)が担う

### 11-2. 非メンバーへの応答は一律 404

- 認証済みでもチェーン導出メンバー(または有効スコープのトークン)でない主体には、get / append とも **404(ProjectNotFound)** を返し、プロジェクト ID の存在を秘匿する。未初期化プロジェクトと区別できない応答とする(ID は genesis ハッシュであり実質ケーパビリティ)

### 11-3. プロジェクト作成(init)と org の整合

- init リクエストは **org_id を必須**とし、作成権限は対象 org の **member 以上**(§9-1)。`projects.org_id` は NOT NULL
- 順序: org 権限確認(D1)→ DO genesis 受理 → D1 `projects` 行挿入。**DO(チェーン)が確定点**であり、projects 行は org 帰属の従属メタデータ(プロジェクト内権限の真実源ではない — CRYPTO_SPEC §6.4)
- 部分失敗の修復(冪等): DO 受理後・行挿入前に失敗した場合、同一 genesis の再 init は DO から already-initialized が返る。このとき「projects 行が欠損 + 認証主体 = genesis actor」であれば行を挿入して成功として返す。それ以外の already-initialized は 409

### 11-4. エンドポイントの配置

- 認証エンドポイントは **OAuth リダイレクト系(§3 start / callback)を含めすべて api-schema の HttpApi 定義**に置く(サーバー実装とクライアント導出の共有源を単一に保つ)
- 401 / 403 の型付きエラー(Unauthorized / Forbidden)を api-schema に共有定義し、認証必須エンドポイントの宣言に載せる
- CSRF(§5)の custom header は `x-maruhi-csrf: 1` とする。セッションクッキーで認証された書き込み系リクエストに要求する(Authorization ヘッダーによるトークン認証はクロスサイトから発行できないため対象外)。**状態を持つ GET** は各章の明示規定によりセッション主体へ追加要求する(一括 pull〔値付き〕 = §12-7、リカバリーブロブ取得 = §13-2)。ここでの「状態」は監査行・計数への書き込みを指す。**意図的に対象外とするもの**: (1) DO の実体化などインフラ面のコスト(対策は未認証プローブの要求レート上限と同じ申し送りの設計判断に属する)、(2) セッションのスライディング失効更新(§5 — セッション認証の全リクエストで発火しうる持続書き込みだが、被害者自身のセッションを延ばすだけでクロスサイトから得られるものがなく、1 時間単位の間引きも入っている)

## 12. 変数値・環境・DEK API との接続(2026-08-02 セッション 07 裁定)

CRYPTO_SPEC §3〜§5・§7(鍵階層・変数暗号化・値署名・メタデータステートメント・DEK ラップ・コミットメント・エポック)のデータプレーンの API 面の規定。§11 と同じ規律に従う: 全エンドポイント認証必須、非メンバー・スコープ外への応答は一律 404(§11-2)、実効権限 = min(トークンスコープ, チェーン role)(§9-2)。本章の規則は原則**サーバーの API 受理ポリシー**である。ただし 2026-08-03(セッション 12)以降、暗号仕様側に規範を持つ検証(値・メタデータ署名 = CRYPTO_SPEC §4.1 / §4.2、DEK コミットメント = 同 §5.2、環境ライフサイクル = 同 §6.2)については、本章はそのワイヤ・受理面の**具体化**であり、規範の変更は CRYPTO_SPEC の改訂を要する。

### 12-1. リソースモデルと識別子

- 環境・変数の集合・表示名は project DO 内の**平文メタデータ**(CRYPTO_SPEC §4。暗号化されるのは値のみ)。**名前 ↔ ID の対応と active / deleted 状態の真正性は署名付きメタデータステートメント(CRYPTO_SPEC §4.2)が担う**(2026-08-03): 変数の作成・改名・削除、環境の改名・削除はステートメントを伴い、サーバーは保存・配布時にステートメントと署名を併置する
- `environment_id` / `variable_id` は**クライアント採番の安定識別子**(CRYPTO_SPEC §3 の「環境作成時に採番」の採番主体はクライアント)。AAD / HPKE info(§4 / §5)に入る値をクライアントが暗号化・ラップの前に確定できるようにするため — サーバー採番では「ID 取得 → ラップ → 登録」の 2 往復に分かれ、「環境はあるが DEK ラップが存在しない」中間状態が生まれる
- 形式(受理ポリシー): `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`。environment_id はプロジェクト内で一意、variable_id は環境内で一意
- **ID の再利用禁止**: 削除済み変数の ID は再利用できない(tombstone による拒否 + CRYPTO_SPEC §4.2 の「deleted 後の再 active 化禁止」)。**環境 ID の再利用禁止は、環境作成のチェーン op 化(CRYPTO_SPEC §6.2 `create_environment`。2026-08-03)によりチェーン合意規則へ昇格した**(履歴全体で一意 — サーバー tombstone は導出キャッシュに退化する)。epoch と version が AAD に入るため、同一 AAD 座標の暗号文が世代をまたいで二重に存在しうる状態を構造的に作らない
- 表示名(name)は改名可能な平文メタデータ。**NFC 正規化の実施主体はクライアント(署名前)であり、サーバーは正規化しない**(受理ポリシー): サーバーは受理時に name が NFC 正規形であることを検査し、非正規形は 422 で拒否する — 署名済みバイト列を受理後に変更する経路を持たない(CRYPTO_SPEC §4.2 の byte-exact 検証との両立)。大文字小文字は区別する(POSIX 環境変数名の意味論に一致)。名前の一意性(環境名はプロジェクト内、変数名は環境内。byte-exact 完全一致で判定 — 全受理名が NFC 正規形なので NFC 一致と同値。削除済みは対象外)はサーバーが強制し、クライアントも配布された active ステートメント集合に対して検証する(環境間パリティチェックは変数名で行う — CRYPTO_SPEC §4)。**名前 → variable_id の解決・CLI の実行制御系変数名 denylist(セッション 11)も同じ比較規則(byte-exact、大文字小文字区別)を検証済みステートメントの name に適用する**。クライアントは解決のルックアップキーを NFC 正規化してから照合し、配布されたステートメントに非 NFC 正規形の name を検出したら警告する(SHOULD — NFC 検査はサーバー受理ポリシーであり、悪意サーバーは非 NFC 名の署名済みステートメントを配布しうる。byte-exact 照合は誤解決を生まないが、視覚的同名の並存を不可視にしない)

### 12-2. ワイヤ表現(CRYPTO_SPEC §10 の具体化)

変数値は `EncryptedPayload` としてのみ API 境界を通る:

```
EncryptedPayload = {
  suite: "maruhi/v1",
  aad: { projectId, environmentId, epoch, variableId, version },  // 申告 AAD 構成要素
  nonceHex,                    // 96-bit ランダム nonce(hex 小文字 24 文字)
  ciphertextHex,               // AES-256-GCM の ct || tag(hex 小文字、タグ込み 16 バイト以上)
  // 値の書き込み署名(CRYPTO_SPEC §4.1。2026-08-03 セッション 12):
  prevValueSigHashHex,         // 直前 version の value_signed_bytes の SHA-256(version 1 は空文字列)
  chainHeadHashHex,            // writer が最後に検証したチェーンヘッドの entry_hash(64 文字)
  chainHeadSeq,                // 同ヘッドの seq
  signatureHex                 // Ed25519、64 バイト。writer_user_id は push では呼び出し主体(12-5)、配布では writerUserId
}

VariableMetaStatement = {     // 変数の作成・改名・削除(CRYPTO_SPEC §4.2)
  suite: "maruhi/v1",
  environmentId, variableId,
  name,                        // NFC 正規化済み表示名(12-1)
  status,                      // "active" | "deleted"
  metaVersion,                 // 1 始まりの連番
  prevMetaSigHashHex,          // 直前ステートメントの signed_bytes の SHA-256(metaVersion 1 は空文字列)
  chainHeadHashHex, chainHeadSeq,
  signatureHex
}

EnvironmentMetaStatement = {  // 環境の作成(12-4 の複合)・改名・削除(CRYPTO_SPEC §4.2)
  suite: "maruhi/v1",
  environmentId, name, status, metaVersion, prevMetaSigHashHex,
  chainHeadHashHex, chainHeadSeq,
  signatureHex
}

EnvironmentManifest = {      // 環境マニフェスト(CRYPTO_SPEC §4.3。2026-08-18)
  suite: "maruhi/v1",
  environmentId,
  epoch,                     // 発行時点(宣言ヘッド時点)の現エポック — メタ層の鮮度アンカー
  manifestVersion,           // 1 始まりの連番(環境作成 = 1)
  variablesDigestHex,        // 全変数ステートメント(tombstone 含む)の正規ダイジェスト(同 §4.3)
  envMetaVersion, envMetaSigHashHex,
  prevManifestSigHashHex,    // 直前マニフェストの signed_bytes の SHA-256(manifestVersion 1 は空文字列)
  chainHeadHashHex, chainHeadSeq,
  signatureHex
}

WrappedDek = {
  suite: "maruhi/v1",          // スイート識別子(CRYPTO_SPEC §2 設計原則 4)
  epoch,
  recipientUserId,             // 受信者の同定は user_id + enc 公開鍵の両方(12-6)
  recipientEncPubHex,          // 32 バイト
  encHex,                      // HPKE encapsulated key(32 バイト)
  ciphertextHex,               // ラップ済み DEK(48 バイト = 32 + GCM タグ 16)
  signatureHex                 // 登録署名(Ed25519、64 バイト — CRYPTO_SPEC §5.1)
}
```

- バイナリ列の表現はチェーン(§6.1)と同じ **hex 小文字**に統一する
- **配布(pull / 取得)応答は署名の検証材料を運ぶ(2026-08-03)**: 値には `writerUserId` + `writerKeyFingerprintHex`、メタステートメントには `authorUserId` + `authorKeyFingerprintHex`、環境マニフェストには `issuerUserId` + `issuerKeyFingerprintHex`(2026-08-18)を付す(RecipientDek の signerUserId + signerKeyFingerprintHex と同型 — 受信者はチェーン履歴と照合して CRYPTO_SPEC §6.3 のクライアント検証を行う)。**名前を返すすべての応答(一括 pull・環境一覧等)は、名前の裸のスナップショットでなく検証可能なステートメント(+ author 情報)を運ぶ**(クライアントはステートメント検証を経ない名前を信用してはならない)。push・メタ操作リクエストではこれらは載せない(呼び出し主体 = 署名者が契約 — §5.1 / §12-5 と同じ規則)。DEK コミットメント(CRYPTO_SPEC §5.2)はチェーンエントリ内で配布されるため、データプレーン応答に独立のフィールドを持たない
- **DEK 配布応答(RecipientDek)は署名・署名者情報を運ぶ(2026-08-02 裁定 2-E のセッション 09 反映)**: 保存されたラップの `signatureHex` に加え、`signerUserId` と `signerKeyFingerprintHex`(登録受理時のチェーン導出メンバーの鍵 FP)を返す。受信者はこれらとチェーン履歴から配布時のクライアント検証(CRYPTO_SPEC §5.1)を行える
- **suite は永続データ構造の全域に持たせる(2026-08-02 セッション 07 レビュー裁定)**: WrappedDek のワイヤに suite を持ち、サーバーの保存行(変数バージョン・DEK ラップ)も suite 列を持つ。DEK 配布応答(RecipientDek)・pull 応答(EncryptedPayload)も保存された suite を返す。CRYPTO_SPEC §2 設計原則 4「すべての永続データ構造はスイート識別子を持つ」との整合であり、暗号仕様側の変更は伴わない(HPKE info は従来どおり CRYPTO_SPEC §5)。API スキーマ上は Literal `"maruhi/v1"` にピン留めしたまま(`maruhi/v2` 導入時の suite とエポックの結合判断は v2 設計まで保留する — 先取りしない)
- **サーバーは AAD を暗号学的に検証できない**(E2EE。復号鍵を持たない)。サーバーが行うのは (1a) 申告 AAD 構成要素と **URL 座標**(project / environment / variable)の一致検査 — リクエスト内容のみから計算できる自己整合検査で、不一致は 422(12-3 の認可先行例外の対象はこれのみ)、(1b) 申告 version・epoch と**プロジェクト状態**(期待 version、現エポック)の一致検査 — 認可判定の**後**に行い、不一致は 409 で現在値を返す(12-5 の CAS / エポック応答。状態依存の検査を認可に先行させると §11-2 の存在秘匿が破れる)、(2) 構造検査(hex 形式・nonce 長・ciphertext 最小長・サイズ上限)、(3) **値・メタデータ署名の検証(12-5。2026-08-03 — §12-6 の登録署名と同じく、復号を要しない署名検証としてサーバーにも可能な検査)**。文脈束縛の実際の強制は復号失敗(CRYPTO_SPEC §4)であり、その検証は crypto 層のテストベクターが担う

### 12-3. 認可(op 別必要権限。§6 の表のデータプレーン拡張)

| op | トークンスコープ | チェーン role |
|---|---|---|
| 一括 pull(メタデータのみモード含む — §12-7)・環境一覧・自分宛 DEK 取得 | read | reader 以上 |
| 変数の作成・push・改名・削除、環境の作成・改名、DEK ラップ登録 | write | member 以上 |
| 環境の削除、DEK ラップの削除(§12-6 の修復経路) | admin | admin 以上 |

- 判定順は §11 の先例と同一: 認証(401)→ 書き込み系はサイズ先行検査(413。資源保護は意味論的判定に優先)→ トークンスコープ(スコープ外 = 404、水準不足 = 403)→ チェーン導出メンバーシップ(非メンバー = 404)→ チェーン role(不足 = 403)→ 意味論的検査
- 例外として、**申告 AAD の URL 座標一致検査(§12-2 の 1a)はサイズ検査と同様に認可判定へ先行してよい**: 応答(422)がリクエスト内容のみから計算できる自己整合検査であり、プロジェクトの存在・状態情報を一切運ばないため、§11-2 の存在秘匿と両立する(スコープ外の主体が AAD 不整合なリクエストを送った場合は 404 でなく 422 が返る)。**状態依存の一致検査(§12-2 の 1b — version・エポック)と署名検証(同 3)はこの例外の対象外**であり、認可判定の後に行う(2026-08-03 明確化)
- 環境・変数の存在に関する 404(EnvironmentNotFound / VariableNotFound)が返るのは**チェーン導出メンバーに対してのみ**(プロジェクト自体の存在秘匿 §11-2 が常に先行する)
- reader は取得可・push 不可(CRYPTO_SPEC §6.2)。チェーン role の真実源は引き続きチェーンであり、この表はトークンスコープ側の必要条件 + サーバーが強制する role 下限である
- **認可時点の二重判定(2026-08-03)**: 署名を伴う操作(push・メタ操作)は、従来の「受理時点の現メンバー role」に加えて「**宣言ヘッド時点の role**」(CRYPTO_SPEC §6.3 の 3)も満たさなければならない。表の role 水準は両時点に同じ値を適用する(値 push・変数の作成/改名/削除・環境の作成/改名 = member、環境の削除 = admin)

### 12-4. 環境管理(2026-08-03 セッション 12 改訂 — 環境作成のチェーン op 化に追随)

- **作成は複合リクエストとして原子的**: リクエストに (1) `create_environment` チェーンエントリ(environment_id + エポック 1 の dek_commitment_hex — CRYPTO_SPEC §6.2。親ヘッドの CAS を含む通常のチェーン追記として検証する)、(2) `EnvironmentMetaStatement`(metaVersion 1、status active — 表示名を運ぶ)、(3) **エポック 1 の DEK ラップ完全集合**(現メンバー全員 + 有効な grant_server のサーバー鍵宛〔開示スコープ内の場合 — 2026-08-12〕。12-6 の検証を通ること)、(4) **`EnvironmentManifest`(manifestVersion 1、epoch 1、変数空集合のダイジェスト — CRYPTO_SPEC §4.3。2026-08-18)**、(5) **境界 `checkpoint` チェーンエントリ(2026-08-19 セッション 32 — CRYPTO_SPEC §6.3 の必須同梱)**: 当該環境 1 タプルのみ(epoch 1・manifestVersion 1・同梱マニフェストの signed_bytes ハッシュ・変数空集合の values_digest。audit_head_hash の扱いは §6.2 / §16-2 の既存規則どおり)を同梱し、プロジェクト DO が**チェーン 2 エントリの追記(create = H+1、checkpoint = H+2。CAS 親は宣言ヘッド H)とデータ登録を単一トランザクションで原子的に**受理する(CRYPTO_SPEC §6.4 の複合受理)。「環境はあるが誰も DEK を持てない」「コミットメントはあるがラップがない」「環境はあるがマニフェストがない」中間状態を作らない(新規環境にマニフェスト未初期化状態が構造的に存在しないことの根拠 — CRYPTO_SPEC §6.3)。チェーンエントリ(create と checkpoint の両方)の actor・ステートメントの author・ラップの署名者・マニフェストの issuer は、いずれも呼び出し主体と厳密一致でなければならない。ヘッド CAS 失敗(409)後の再試行では両エントリ・ステートメント・マニフェストのすべてを再署名する
- **複合内の宣言ヘッド(2026-08-03 明確化)**: 同梱ステートメントの `chainHeadHashHex` / `chainHeadSeq` は**追記前の現ヘッド(= 同梱チェーンエントリの prev と同一)**とし、サーバーのヘッド実在検査(12-5 の 2)は**追記前のチェーン**に対して行う(同梱エントリ自身をヘッドに宣言する形は受理しない — 実装間で検査対象チェーンが割れる曖昧さを排除する)。ヘッド CAS 失敗(409)後の再試行では、チェーンエントリ(prev_hash 変更)と同梱ステートメント(宣言ヘッド変更)の**両方を再署名**する。ラップ集合は再試行の間に現メンバー集合が変わった場合のみ作り直す。なお env メタステートメント(metaVersion 1)の宣言ヘッド時点に環境は未存在だが、メタステートメントの検証は環境の存在を検査しない(値署名のエポック整合 — CRYPTO_SPEC §6.3 の 4 — とは非対称であることを明示しておく)
- 作成の受理条件: `create_environment` の合意規則(environment_id はチェーン履歴全体で一意 — CRYPTO_SPEC §6.2)が従来の「現存しない・tombstone でない・rotate 観測済みでない」検査を包含する(tombstone・環境行はチェーン導出のキャッシュに退化し、独立の真実源にしない)。作成時点の現エポックは常に初期値 1(CRYPTO_SPEC §3)
- **ローテーションも複合リクエスト**: `rotate_epoch` チェーンエントリ(新エポックの dek_commitment_hex 込み)+ **新エポックのラップ完全集合** + **新エポックを焼き込んだ `EnvironmentManifest`(manifestVersion + 1。メタ集合は不変でもエポック前進を反映する — CRYPTO_SPEC §4.3。2026-08-18)**+ **境界 `checkpoint` チェーンエントリ(2026-08-19 セッション 32 — 当該環境 1 タプル: new_epoch・同梱マニフェストの manifestVersion + signed_bytes ハッシュ・受理時点の現在値〔未再暗号化 = 旧エポック — 12-7 の正当な状態〕から構成した values_digest)**を、チェーン 2 エントリ(rotate = H+1、checkpoint = H+2)+ データ登録の単一トランザクションで原子的に受理する(従来の「チェーン追記 → ラップ初回登録」の 2 リクエスト分離を廃止 — 分離は「新エポックはあるが誰も DEK を持てない」中間状態を常態化させるため)。values_digest の内容突合(CRYPTO_SPEC §6.4 — 複合の適用後基準)が受理時点の保存状態と一致しない場合(宣言ヘッド確定後の並行 push)は 422 で拒否し、クライアントは再 pull(再暗号化に必要な読み取りと同一 — 取りこぼしの防止を兼ねる)の上で有界再試行する。現在値の再暗号化(CRYPTO_SPEC §7)は後続の通常 push(12-5)であり、複合には含めない(値の量に依存する巨大リクエストを避ける。未再暗号化の間、旧エポックの最新値が配布されることは 12-7 のとおり)。**削除済み(tombstone)環境への rotate 複合は 404(EnvironmentNotFound)で拒否する**(CRYPTO_SPEC §7 の「全環境」は削除済みを含まない — 仕様適合クライアントが満たせない義務を作らない)。ラップ完全集合の対象は**現メンバー集合 + 有効な grant_server のサーバー鍵(当該環境が開示スコープに含まれる場合)**とする(2026-08-12 改訂 — 旧「v1 = 現メンバーのみ」線引きの解消。CRYPTO_SPEC §7 のサーバー鍵再ラップ義務の受理面)。完全一致・欠落拒否の判定は受信者クラスを跨いで同一に適用する
- **複合内の整合検査(2026-08-03 明確化。2026-08-18 マニフェスト追加。2026-08-19 チェックポイント追加)**: サーバーは同梱サブペイロード間の座標一致を受理条件とする — 作成: チェーンエントリ payload の environment_id = ステートメントの environmentId = 全ラップの環境座標 = マニフェストの environmentId = **checkpoint タプルの environment_id**、かつ全ラップの epoch = 1 = マニフェストの epoch = **checkpoint タプルの epoch**。ローテーション: エントリ payload の environment_id = 全ラップの環境座標 = マニフェストの environmentId = **checkpoint タプルの environment_id**、かつ全ラップの epoch = エントリの new_epoch = マニフェストの epoch = **checkpoint タプルの epoch**。**checkpoint タプルの (manifest_version, manifest_sig_hash) は同梱マニフェストの (manifestVersion, signed_bytes ハッシュ) と一致すること(境界束縛そのもの — CRYPTO_SPEC §4.3 検証規則 (2) の受理面)**。**同梱 checkpoint の受理にあたりサーバーは、再構成した値スナップショット列挙 + 対応 checkpoint seq / hash を当該環境の最新包含 checkpoint として複合と同一トランザクションで upsert する(§16-2 の保存規律と経路によらず同一 — 12-7 / §14-2 の配布義務の供給源。作成では空列挙)**。**各部分の独立検証だけで不整合な組(別環境のステートメント・別エポックのラップ等)を受理してはならない**。12-6 の「登録できるエポックは 1〜現エポック」の複合同梱ラップへの適用は**同梱エントリ適用後のチェーン状態**に対して行う(上記の epoch 一致検査と同値。追記前の状態で判定すると、新エポック宛ラップを同梱する正当なローテーション複合が「未来のエポック宛」として全拒否になる)
- **add_member 後のバックフィルは複合化しない(意図的な非対称)**: 「メンバーはいるがラップがない」中間状態は残る。全環境 × 全エポックのラップは 12-8 のリクエスト上限を超えうる(環境 100 × エポック多数 × 対象メンバー)ため 1 リクエストの原子性で覆えず、また不足は §6.3 のラップ先一致検査と 12-6 の追記経路で収束可能なため、複合の対象にしない
- ~~チェーン受理は環境メタデータと突合しない~~(2026-08-03 廃止): `rotate_epoch` は当該 environment_id の `create_environment` の先行を要する(CRYPTO_SPEC §6.2 の合意規則)。環境の存在がチェーン導出値になったため、可変のサーバーローカル状態への依存という旧規則の懸念は解消されている(旧規則の「存在しない ID への rotate はデータ層に効果を持たず ID を焼却する」挙動は廃止)
- 改名は表示名のみ(暗号文脈は改名の影響を受けない environment_id — CRYPTO_SPEC §3)。改名・削除は `EnvironmentMetaStatement`(metaVersion + 1)を伴い、**受理は 12-5 のメタステートメント規則に従う**(署名検証 1〜3 + prev 連鎖 + metaVersion CAS + 座標のサーバー側再構成。削除は宣言ヘッド時点 admin — 12-3)。**環境の改名は `EnvironmentManifest`(manifestVersion + 1 — 新しい envMetaSigHashHex を写す)も同梱する。環境の削除はマニフェストを再発行しない**(配下メタのカスケード削除で配布チャネルが消える — CRYPTO_SPEC §4.3。環境自身の deleted ステートメントが終端の検出材料)
- 削除は admin 以上。環境行は tombstone として残し、配下の変数・バージョン(暗号文)・ラップ済み DEK・**変数メタステートメント(tombstone 含む)**・**環境マニフェストとチェックポイント時点の値スナップショット列挙(2026-08-18 — 配下メタと同じ論法: 削除済み環境には配布チャネルが存在せず、配布されないサーバー保存物に検出材料としての残存価値がない。§12-8 の「削除で解放される」原則の対象)**は即時削除する。配下の変数メタステートメントを残さない根拠(2026-08-04 セッション 15 所有者裁定 — PR #31): 環境 ID はチェーン合意規則で再利用不能(CRYPTO_SPEC §6.2)であり、削除済み環境の配下ステートメントには配布チャネルが存在しない(pull は 404、環境一覧は環境自身の tombstone ステートメントのみ)— 配布されないサーバー保存物はクライアントが検証できず、変数側 tombstone に検出材料としての残存価値がない(環境自身の deleted ステートメントが検出材料)。削除の `EnvironmentMetaStatement`(status deleted)は保存・配布し続ける(CRYPTO_SPEC §4.2 — 削除の否認・無断復活の検出材料)。監査ログには変数ごとの var.deleted と env.deleted を記録する(AUDIT_SPEC §3.3)

### 12-5. 変数とバージョニング

- version は 1 始まりの連番で AAD の一部(CRYPTO_SPEC §4)。**サーバーは version を採番できない**(採番すると申告 AAD とずれる)ため、push は CAS で受理する: 申告 version == 現在の最新 version + 1 のみ受理し、不一致は 409 で現在の最新 version(番号のみ)を返す
- **409 後の再試行手順(2026-08-03 — CRYPTO_SPEC §4.1 の連鎖と CAS の接続)**: クライアントは勝った最新 version を取得し(12-7)、**§6.3 の全検証を通過させた上で**その signed_bytes ハッシュを自ら再計算して `prevValueSigHashHex` に用い、新 version で再暗号化・再署名して再試行する。**409 応答に勝者の signed_bytes ハッシュは含めない**(含めるとクライアントが未検証のサーバー申告値へ自分の署名で連鎖することになり、悪意サーバーが偽 prev への連鎖署名を作らせられる — 証拠連鎖の汚染)。metaVersion CAS(下記)の再試行は**同型の手順をステートメントに適用する**: 勝った最新ステートメントを取得 → §6.3 の全検証 → その signed_bytes ハッシュを自ら再計算して `prevMetaSigHashHex` に用い、metaVersion + 1 の新ステートメントを再署名して再試行する(値を伴わないため再暗号化は発生しない。409 応答に勝者のハッシュを含めない規律も同一)
- **push が参照できるエポックは現エポックのみ**(チェーン導出 ChainState.environmentEpochs の値、`create_environment` 直後は初期値 1)。旧エポックの push は 409 で現エポックを返す。ローテーション直後の競合はこの応答によりクライアントが新 DEK を取得・再暗号化して再試行する。**保存済みの過去バージョンは当時のエポックのまま保持される**(CRYPTO_SPEC §7)— 本規則は新規受理だけを現エポックに束縛する
- **値署名の検証(2026-08-03 — CRYPTO_SPEC §4.1 / §6.4)**: push の受理条件に以下を加える。検証失敗は 422(`signature-invalid` / `chain-head-unknown` / `chain-head-state-mismatch`)で拒否する:
  1. 署名は**呼び出し主体の受理時点チェーン導出 sig 鍵**で検証し、署名対象の writer_user_id にも呼び出し主体の user_id を用いる(12-6 の登録署名と同じ「呼び出し主体 = 署名者」規則。他人が署名した値の持ち込みは拒否)
  2. `chainHeadHashHex` は自チェーンの seq = `chainHeadSeq` のエントリハッシュと一致すること
  3. **認可時点(共通)**: 宣言ヘッド時点のチェーン導出状態で、呼び出し主体が当該操作の必要 role(12-3 の二重判定の表)を持ち、**かつ宣言ヘッド時点でその user_id に束縛されていた sig 鍵が、検証に用いた受理時点の鍵と一致すること**(2026-08-03 明確化: remove → 別鍵で re-add された主体が旧在籍区間のヘッドを宣言する形を拒否する。クライアント検証 — CRYPTO_SPEC §6.3 の 1 のヘッド時点鍵束縛 — が全拒否するデータをサーバーが保存しないための整合)
  4. **エポック整合(値のみ — CRYPTO_SPEC §6.3 の 4 と同じ書き分け)**: 宣言ヘッド時点の当該環境の現エポックが、申告 AAD の epoch と一致すること(受理時点の現エポック検査 — 上記 — とは別の検査であることに注意: 宣言ヘッドから受理までの間にローテーションが挟まれば受理時点検査が 409 で落とす)。**宣言ヘッド seq が当該環境の `create_environment` の seq より前である値署名は無効**(§6.3 の 4 の後段と同一 — エポックが未定義の宣言ヘッドを既定値で補う実装を禁止する)。メタステートメントは AAD・epoch フィールドを持たない(CRYPTO_SPEC §4.2)ため本検査の対象外
  5. `prevValueSigHashHex` が保存済みの直前 version の signed_bytes ハッシュと一致すること(version 1 は空文字列)。サーバーは各バージョンの signed_bytes ハッシュを保存行に持つ
- **エポック単調性(CRYPTO_SPEC §4.1)の独立検査はサーバーに置かない(2026-08-03 明確化)**: 「受理は現エポックのみ」(上記)と現エポックの時間単調性(rotate_epoch は +1 のみ — CRYPTO_SPEC §6.3)により、受理される新 version の epoch は保存済み全バージョンの epoch 以上であることが**構造的に**保証される。独立の比較検査は冗長であり追加しない(この含意は本規則群の帰結であるため、「受理は現エポックのみ」を緩める将来改訂はエポック単調性の担保方法の再検討を伴う)
- **署名対象の座標はサーバー側の値から再構成する(2026-08-03)**: signed_bytes の検証に用いる project_id は DO 自身のチェーン(genesis ハッシュ)から、environment / variable 座標は URL・保存先から取る。クライアント申告値(申告 AAD)から組まない(CRYPTO_SPEC §5.1 実装の「project_id は DO 自身のチェーンから取る」— セッション 09 §3 — と同じ不変条件。申告 AAD との一致検査 — 12-2 — に暗黙依存させない)。**この規則は値署名とメタステートメント署名の両方に適用する**: 署名対象の座標フィールド — `var_meta_signed_bytes` は project_id / environment_id / variable_id、`env_meta_signed_bytes` は project_id / environment_id(CRYPTO_SPEC §4.2 の各 LP に存在するフィールドのみ。env メタに variable_id は存在しない)— も URL・保存先座標から再構成し、ワイヤの `environmentId` / `variableId` 申告値から組まない(別座標への有効署名を要求パスの座標で保存する取り違えを構造的に排除する)
- サーバーの保存行は値ごとに署名・writer(user_id + 鍵 FP)・宣言ヘッド(hash + seq)・prev ハッシュを持ち、配布(12-7)でそのまま返す。監査イベント `var.version_pushed` は writer の鍵 FP を写す(AUDIT_SPEC §3.3)
- **再暗号化マーカー(2026-08-15 セッション 25 所有者裁定 — Wave 2 B2)**: push リクエストは省略可の boolean `reencryption` を運んでよい(既定 false)。意味論は「このバージョンは直前バージョンと同一平文の、新エポックへの再暗号化(CRYPTO_SPEC §7 の義務ローテーションに伴う再 push)である」という **writer の自己申告**であり、サーバーは平文を見られない(E2EE)ため真偽を検証しない・できない。サーバーはこの申告を `var.version_pushed` の監査 payload に写すだけで、受理判定・値署名(CRYPTO_SPEC §4.1 — 署名対象にマーカーは含まれない)には一切影響させない。用途は要ローテーション検出の解消導出(AUDIT_SPEC §4.1 手順 5 — マーカー付き push は解消と見なさない)のみ。虚偽申告の影響は助言フラグの精度に閉じ、失敗方向は安全側(true の誤申告 = フラグが残る。省略・false の誤申告 = 追補以前の文字通り挙動と同一)。CRYPTO_SPEC §7 の再暗号化 push を行う準拠クライアントはマーカーを付ける(SHOULD)
- **環境マニフェストの複合受理(2026-08-18 — CRYPTO_SPEC §4.3)**: メタ状態を変えるすべての操作 — 変数の作成・改名・削除、環境の改名(12-4)、環境の作成・ローテーション(12-4 の複合)— は、操作後のメタ状態を反映した `EnvironmentManifest`(manifestVersion = 最新 + 1)を同梱し、サーバーはステートメントとマニフェストを**原子的に**受理する。マニフェストの受理条件: (1) 呼び出し主体 = issuer の厳密一致(署名は受理時点のチェーン導出 sig 鍵で検証 — 値・メタと同じ規則)、(2) 宣言ヘッドの実在(上記 2)、(3) 認可時点(上記 3 — role 水準は同梱される操作自体と同じ)、(4) **エポック整合**: マニフェストの epoch が宣言ヘッド時点の当該環境の現エポックと一致すること(値の上記 4 のマニフェスト版。rotate 複合の同梱分は同梱エントリ適用後の状態 = new_epoch — 12-4 の判定基準と同じ)、(5) prev 連鎖(`prevManifestSigHashHex` = 保存済み直前 manifestVersion の signed_bytes ハッシュ。manifestVersion 1 は空文字列)、(6) manifestVersion の CAS(申告 == 最新 + 1。**保存済みマニフェストが存在しない環境 — マニフェスト導入前に作成された環境の移行 — では最新 = 0 とみなし、manifestVersion 1〔prev 空文字列〕を受理する(2026-08-18 明確化 — PR-M1 移行経路。移行完了後は通常の CAS に合流し、専用の初期化エンドポイントは設けない — 受理経路はメタ操作への同梱のみ)**。**非複合のメタ操作での v1 受理は、宣言ヘッド = 受理時点の現ヘッドを要求する(2026-08-18 — PR #81 レビュー対応)**: v1 は最新 0 からの受理であり、宣言ヘッド後にローテーションが挟まっても本 CAS が 409 で落とせない — 下記「受理時点の現エポックとの独立検査は置かない」の論証が v1 に限って成立しないため、複合経路の宣言ヘッドピン留め(12-4)と同型の要求でエポック整合の担保を代替する(stale エポックを焼き込んだブートストラップの遮断。不一致は 422 `payload-mismatch`〔field: manifestChainHead〕)。同梱される metaVersion CAS と同一トランザクションで判定し、409 の再試行ではステートメントとマニフェストの**両方**を再署名する)、(7) **ダイジェストの再計算一致**: サーバーは受理後のメタ状態(同梱ステートメント適用後の全変数ステートメント — tombstone 含む — と環境メタステートメント)から variablesDigestHex / envMetaVersion / envMetaSigHashHex を再計算し、マニフェストの申告値と一致しなければ 422 で拒否する(メタは平文でありサーバーが完全検証できる — E2EE の制約がない。CRYPTO_SPEC §4.3)。座標(project / environment)のサーバー側再構成は上記の規則と同一。**値の push はマニフェストに触れない**(発行契機の限定 — CRYPTO_SPEC §4.3)。**サーバーの保持は環境ごとに最新マニフェスト 1 通のみで足りる(2026-08-18 pullfrog レビュー対応 — 過去行を要する検証経路が存在しない)**: prev 検査(5)は最新の signed_bytes ハッシュ、配布(12-7)は最新、チェックポイント受理検証(CRYPTO_SPEC §6.4)は受理時点の最新との一致であり、いずれも履歴を参照しない。メタステートメント(全 metaVersion 保持)との非対称は意図的である — ステートメント履歴は tombstone の配布・prev 連鎖の再試行材料として配布されるが、マニフェストの検証は最新 1 通で成立する(CRYPTO_SPEC §4.3)。equivocation の証拠はクライアント側の床・受信記録が担う(サーバーは被疑者であり、サーバー保持は証拠源にならない)。**並行メタ操作の直列化への注意(実装 PR 向け)**: 従来の metaVersion CAS は変数単位で独立だったが、マニフェスト CAS の追加により同一環境内の全メタ操作が環境単位の manifestVersion で直列化される — 変数の一括投入(CI からのバッチ作成等)は 409 再試行の増幅を避けるため逐次実行する。検証失敗のエラー区分は既存を共有する: 署名・ダイジェスト不一致・エポック不整合 = 422(`signature-invalid` / `manifest-digest-mismatch` / `manifest-epoch-mismatch`)、manifestVersion 競合 = 409(最新 manifestVersion のみを返す — 勝者のハッシュを載せない規律も 12-5 と同一)。**受理時点の現エポックとの独立検査は置かない(2026-08-18 明確化)**: `rotate_epoch` 複合がマニフェストを必ず再発行する(12-4)ため、宣言ヘッド後にローテーションが挟まれていれば manifestVersion CAS(6)が 409 で落とす — この含意は「rotate はマニフェストを再発行する」に依存するため、発行契機を緩める将来改訂はエポック整合の担保方法の再検討を伴う(12-5 のエポック単調性の注記と同じ構図)
- 変数の作成は最初の値(version 1)と `VariableMetaStatement`(metaVersion 1)を同梱する(値のない変数は存在しない)。**同梱する version 1 の値は通常 push と同一の検証(上記 1〜5)を受ける**(作成経由で値署名の検証を迂回できない)。改名・削除のステートメントは metaVersion の CAS(申告 == 最新 + 1)で受理し、409 は最新 metaVersion を返す。ステートメントの署名検証は**上記 1〜3(署名者一致・ヘッド実在・宣言ヘッド時点の role)+ prev 連鎖(`prevMetaSigHashHex` の metaVersion 連鎖 — 上記 5 と同型)**。エポック整合(上記 4)は値専用でありメタステートメントには適用しない。**このメタステートメント受理規則は `VariableMetaStatement` と `EnvironmentMetaStatement` に共通**(環境の改名・削除 — 12-4 — と複合作成の同梱ステートメントにも適用する。複合固有の宣言ヘッド規則は 12-4、削除の role 水準 admin は 12-3)。**サーバーは変数・環境ごとに各 metaVersion のステートメント(signed_bytes ハッシュ・署名・author 情報込み)を保存する**(prev 検査は保存済み直前 metaVersion のハッシュに対して行い、409 再試行・12-7 の配布材料もこの保存行が担う — 値の保存行規定と同型)
- 削除は変数 tombstone + 全バージョンの暗号文削除。削除の `VariableMetaStatement`(status deleted)は保存・配布し続ける。監査上の存在区間は var.created / var.deleted イベントが保持する(要ローテーション検出は削除済み変数も対象 — AUDIT_SPEC §4.1)

### 12-6. DEK ラップの保存・配布(CRYPTO_SPEC §6.3 ゴーストメンバー対策のサーバー側)

- 受信者の同定は **user_id と enc 公開鍵の両方**とし、チェーン導出の現メンバーと両方が厳密一致しなければ受理しない。user_id だけでは「チェーン上の鍵と異なる鍵へのラップ」(実質ゴーストメンバー)を検出できず、公開鍵だけでは HPKE info の recipient_user_id(CRYPTO_SPEC §5)と照合できない
- **登録署名の検証(2026-08-02 セッション 07 所有者裁定 2-E。CRYPTO_SPEC §5.1)**: ラップ挿入の**全経路**(DEK 登録 API と環境作成の同梱ラップの両方。修復経路の削除後の再登録も追記経路として同一)で、各ラップの `signatureHex` を検証する。受理条件は (1) **API 呼び出し主体 = 署名者の厳密一致**(署名は呼び出し主体のチェーン導出 sig 公開鍵で検証し、署名対象の signer_user_id にも呼び出し主体の user_id を用いる — 他人が署名したラップの持ち込みは拒否される。同一公開鍵を持つ別メンバーは CRYPTO_SPEC §6.2 のメンバー鍵の一意性 — 2026-08-03 — によりそもそも成立しないが、signer_user_id の束縛は独立の防衛層であり、仮に鍵重複メンバーが存在しても署名者不一致として拒否される)、(2) 署名対象(CRYPTO_SPEC §5.1 の signed_bytes。URL の project / environment 座標とワイヤの epoch・受信者・enc・ct、および署名者 user_id を束縛)との一致。検証失敗は 422(`signature-invalid`)で拒否する。この検証はチェーン外のデータに対する最初のクライアント署名検証(2026-08-02 当時は唯一。2026-08-03 に値・メタデータ署名 — 12-5 — が加わった)であり、毒ラップの帰属をサーバー不信で成立させる(監査イベントの署名者 FP — AUDIT_SPEC §3.3 — と突合できる)
- (環境, エポック) のラップ集合の**初回登録**(環境作成時のエポック 1、ローテーション後の新エポックの一括登録)は、**現メンバー集合 + 有効な grant_server のサーバー鍵(当該環境が開示スコープに含まれる場合)**との**完全一致**を要求する(§12-4 のラップ完全集合と同一の対象 — 2026-08-12 改訂。判定は受信者クラスを跨いで同一に適用する): 欠落・対象集合外宛・鍵不一致・重複はすべて 422 で拒否する
- 以後は**不足分の追記のみ**許可する(add_member 後に招待者が新メンバー宛へ全エポックの DEK をラップして登録する経路 — CRYPTO_SPEC §7)。**既存 (環境, エポック, 受信者) の上書きは禁止**(409)。ラップの中身はサーバーに検証不能であり、上書きを許すと有効なラップを復号不能なブロブで置換する可用性攻撃が成立するため。**登録の列挙は 1 件以上**とする(空の `deks: []` は Schema 検証の 400。2026-08-03 に 204 no-op から変更 — 呼び出し形として意味のあるユースケースがなく、silent no-op はクライアントバグ〔空配列の送信を登録完了と誤認する〕を隠すため、削除側の空列挙 400 と同じ「黙って成功させない」規律に統一した。環境作成の同梱 `deks` は対象外: 空集合は完全一致要件の 422 recipient-missing が既に拒否する)
- **上書き禁止 409 の応答内容(2026-08-15 セッション 25 所有者裁定 — Wave 2 B2、PR #69 申し送りの解消)**: `DekWrapExists`(409)応答は `{epoch, recipientUserId}` に加えて、占有しているラップの**保存済み受信者 enc 公開鍵**を `storedRecipientEncPubHex` として載せる(SHOULD。フィールドは省略可 — 本追補以前のサーバーは載せない = 後方互換の追加のみ)。公開鍵は非機密であり(全歴史鍵はチェーンで全メンバーへ配布済み)、開示先は登録経路の認可水準(member 以上)に限られる。用途: 再追加メンバーへのバックフィルの 409 で、占有スロットが旧鍵ラップ(修復経路の削除 → 再登録の対象)か現行鍵ラップ(登録済み = 冪等)かを、クライアントが**鍵履歴からの推定でなく保存行との厳密比較**で判定する — ラップの復号可能性は受信者 enc 鍵の一致と同値(HPKE)であり、これが判定の完全な材料である。クライアントは応答にフィールドがあればそれを優先し、無い場合(版ズレのセルフホストサーバー)に限り従来の推定ヒューリスティックへフォールバックしてよい
- **再追加受理時の旧鍵宛ラップ掃除(2026-08-15 セッション 25 所有者裁定 — Wave 2 B2)**: `add_member` の受理時、サーバーは対象 user_id 宛(受信者クラス member)の保存済みラップのうち、**受信者 enc 公開鍵が追加された鍵と一致しないもの**を同一受理タスク内で削除する。これはチェーン導出真実へのストレージ収束(§6.3 の「ラップ先は現メンバーの鍵と厳密一致」不変条件の強制)であり、削除対象は現行チェーンの下で定義上復号不能なゴーストラップのみ — 正当な現行鍵ラップは対象にならず、上書き禁止(可用性攻撃の遮断)は不変のまま維持される。対象の履歴アクセスは追加後のバックフィル(全エポックの新鍵宛ラップ — CRYPTO_SPEC §7)が担う。削除は `dek.deleted`(actor = system、payload に原因と対応 chain seq — AUDIT_SPEC §3.3)として受信者ごとに記録する。受信者クラス server はこの掃除の対象外(鍵の変わる再 grant はサーバー鍵 FP = スロット識別子自体が変わるため stale スロットが発生しない)。remove_member 時は削除しない(同一鍵での再追加時に既存ラップがそのまま有効に復帰する — 掃除は「鍵が変わった」ことが確定する再追加時のみ)
- 登録できるエポックは 1〜現エポック(未来のエポック宛は拒否)。判定の基準状態は経路で異なる(2026-08-03 明確化): 独立登録 API(バックフィル・修復再登録)は**受理時点のチェーン状態**、複合リクエスト(12-4)の同梱ラップは**同梱エントリ適用後の状態**(同梱ラップの epoch は同梱エントリが確立するエポック — 作成 = 1、rotate = new_epoch — との一致を 12-4 が要求するため、実質同値)
- **修復経路: ラップ削除 → 不足分再登録(2026-08-02 セッション 07 レビュー所有者裁定)**: 上書き禁止を維持したまま、復号不能な毒ラップ(登録者のバグ・不正)の唯一の修復手段として、**(環境, エポック, 受信者) 単位の明示的なラップ削除**を提供する。削除後は上記の「不足分の追記」経路で正しいラップを再登録する(あるエポックの全ラップが削除された場合、その再登録は初回登録として完全一致を要求される)。**再登録にも登録署名が必須**(追記経路は登録署名の検証を常に伴う — 再登録者が自らラップし自ら署名する)。必要権限は**環境削除と同水準(トークンスコープ admin × チェーン role admin 以上 — §12-3)**: 削除は他メンバーの復号可能性を奪う操作であり、member 水準に置くと上書き禁止が防いだ可用性攻撃が削除経由で復活するため。存在しないタプルの削除は 404 で拒否し、**削除対象の列挙は 1 件以上**とする(空列挙は Schema 検証の 400。監査痕跡を一切残さない破壊系 API の呼び出し形を許さない — 404 と同じ「黙って成功させない」規律)。削除は監査イベント(`dek.deleted` — AUDIT_SPEC §3.3)として受信者ごとに記録する
- 配布は本人宛のみ: 認証主体は自分が受信者であるラップだけを取得できる(reader を含む全メンバー — CRYPTO_SPEC §6.2)
- **DEK コミットメントとの関係(2026-08-03 — CRYPTO_SPEC §5.2)**: サーバーはラップの中身とコミットメントの一致を検証**できない**(E2EE)。照合は受信者が開封後に行い、不一致のラップは毒ラップとして本節の修復経路(削除 → 再登録)の対象になる。コミットメント導入後も本節の受理条件(受信者一致・完全一致・上書き禁止・登録署名)は不変であり、修復経路の意義は「復号不能な毒」から「復号不能またはコミットメント不一致の毒」へ広がるだけである
- **サーバー鍵宛ラップ(2026-08-12 改訂 — 旧 Phase 2 線引きの解消)**: 受信者クラス server のラップは、受信者の同定を**サーバー鍵 FP + enc 公開鍵の両方**(チェーン導出の有効 grant_server の payload と厳密一致)で行う(user_id を持たないため、member クラスの「user_id + enc 公開鍵」に対応する規則)。HPKE info の recipient_user_id 位置にはサーバー鍵 FP を用いる(CRYPTO_SPEC §9)。登録署名(同 §5.1)・上書き禁止・修復経路(削除 → 再登録。削除権限 = admin)は member 宛と同一規則。開示スコープ外の環境へのサーバー宛ラップは 422 で拒否する
- **エポック 1 とローテーションのラップ登録は 12-4 の複合リクエストに移った**ため、本節の独立登録 API が残る経路は「add_member 後の新メンバー宛バックフィル」「**grant_server 受理直後の、grant 実行者(owner)による開示スコープ内全環境 × 全エポックのサーバー宛バックフィル**(2026-08-12 — add_member 後のバックフィルと同型。CRYPTO_SPEC §7 のラップ実行者規則)」「修復経路の再登録」の 3 つである(受理規則は全経路共通のまま)

### 12-7. 一括 pull(CLI `maruhi run` / Web の取得経路)

- 環境単位の 1 リクエストで、全アクティブ変数の最新バージョン(EncryptedPayload。申告 AAD 込みで自己記述的)+ 現エポック + **呼び出し主体宛の全エポックのラップ済み DEK** を返す
- **検証材料の同梱(2026-08-03。2026-08-18 マニフェスト・チェックポイント材料を追加)**: 各値には署名ブロックと writer 情報(12-2)、各変数・環境には最新の `VariableMetaStatement` / `EnvironmentMetaStatement` と author 情報、**環境には最新の `EnvironmentManifest` と issuer 情報、および削除済み変数の deleted ステートメント(ダイジェスト再計算の材料 — 値付き・メタのみ両モード共通)**を同梱する。**当該環境のエントリを含む最新の `checkpoint`(CRYPTO_SPEC §6.3 の環境ごとの基準)が存在する場合、値付き応答には「そのチェックポイント時点の値スナップショット列挙」(variable_id / version / value_signed_bytes ハッシュの列 — チェックポイント受理時にサーバーが保存したもの)も同梱する**(クライアントのチェックポイント整合検証 — CRYPTO_SPEC §6.3 — の材料。メタのみモードは値を運ばないため対象外)。クライアントは CRYPTO_SPEC §6.3 の検証(署名・ヘッド束縛・認可時点・エポック整合・座標整合・マニフェストのダイジェスト再計算・チェックポイント整合)と §5.2 のコミットメント照合を通過したものだけを使用する。名前 → variable_id の解決は検証済みステートメント経由で行う
- 最新バージョンのエポックは変数ごとに異なりうる(ローテーション後の再暗号化が完了するまで、CRYPTO_SPEC §7)。このため全エポックのラップを同梱する
- 監査: var.read を**変数ごとに 1 行**記録する(AUDIT_SPEC §3.3)
- **一括 pull(値付き)の CSRF ヘッダー(セッション主体のみ — 2026-08-15 追記)**: 一括 pull は GET だが var.read 監査の記録という状態を持ち、`SameSite=Lax` のセッションクッキーはクロスサイトのトップレベル遷移でも同送されるため、セッション主体には書き込み系(§5)と同じ `x-maruhi-csrf: 1` を要求する(欠落は 403)。第三者サイトが被害者のセッションで偽の `var.read` を刻む監査証跡の汚染(要ローテーション検出 — AUDIT_SPEC §4.1 — への混入を含む)の遮断であり、§13-2 のブロブ取得と同じ規律(あちらの状態は §13-3 の取得計数)。Bearer トークンはクロスサイトで付与できないため対象外。メタデータのみモードは監査を記録しないため対象外。**なお §5 の能力制限(2026-08-28 — W2b 実装以降)はセッション主体の値付き一括 pull 自体を拒否する**: 本段の CSRF 要求はそれ以前の防御と、制限を緩める将来改訂への保険として維持する(撤去しない — ADR-0018 の「実装済みの防御は撤去せず維持する」と同じ規律)
- **メタデータのみモード(2026-08-10 セッション 20 — session-11 裁定 3)**: 同じ環境単位で、**値(暗号文)と DEK を返さない**取得経路を提供する(独立エンドポイント)。応答 = 環境の最新ステートメント + 現エポック + 全アクティブ変数の最新 `VariableMetaStatement`(author 情報込み)+ 削除済み変数の deleted ステートメント + **最新の `EnvironmentManifest`(issuer 情報込み — 2026-08-18。メタ検証の完全性はこのモードでも同水準)**。検証材料の同梱・クライアント検証の義務(CRYPTO_SPEC §6.3 のメタ検証・マニフェスト検証・検証済みステートメント経由の名前解決)は一括 pull と同一で、認可も同水準(トークンスコープ read × チェーン role reader — §12-3 の同一行)。用途は名前 → variable_id の解決(CLI push の解決経路)など、値を必要としない読み取り
- **メタデータのみモードは `var.read` を記録しない(「読んでいないものを読んだと記録しない」)**: `var.read` の記録条件は暗号文の配布である(AUDIT_SPEC §3.3)。メタデータのみの応答を記録すると、要ローテーション検出(AUDIT_SPEC §4)の「確実に取得した」ランクに値を読んでいない操作が混入し、検出の意味論を壊す。逆方向の規律(読んだものは必ず記録する)は一括 pull 側の「返した変数ごとに 1 行」が担う

### 12-8. 受理ポリシー(サイズ・数量。CRYPTO_SPEC §6.4 と同じ性格 = 合意規則ではない)

| 対象 | 上限 |
|---|---|
| 値の暗号文(ct \|\| tag) | 64 KiB |
| 表示名(環境・変数) | 256 文字 |
| 環境数 / プロジェクト | アクティブ 100(tombstone 込み 1,000) |
| 変数数 / 環境 | アクティブ 1,000(tombstone 込み 5,000) |
| バージョン数 / 変数 | 1,000 |
| metaVersion 行数 / 変数(環境) | 1,000(status = deleted のステートメントは対象外) |
| プロジェクト累積暗号文バイト | 1 GiB |
| DEK ラップ数 / リクエスト | 10,000 |
| DEK ラップ行数 / プロジェクト | 1,000,000 |

- 累積暗号文バイトは「現在保存中の量」であり削除で解放される(DO SQLite 10 GB に対する資源保護)
- **マニフェストは行数上限を持たない(2026-08-18 セッション 27。pullfrog レビュー対応 — 当初起草の「manifestVersion 行数 / 環境」上限は、変数側 metaVersion 予算の合流により削除操作まで恒久遮断する形になり、PR #31 裁定〔下記 metaVersion 上限の deleted 除外〕と矛盾したため撤回)**: サーバーの保持が最新 1 通のみ(§12-5)で行が蓄積しないため、資源保護の対象自体が存在しない。manifestVersion 番号は §6.1 の数値表現の範囲で単調に進むだけであり、番号の消費は資源を消費しない
- **metaVersion 行数 / 変数(環境)(2026-08-04 セッション 15 所有者裁定 — PR #31)**: 改名・削除のメタステートメント行(§12-5)は本表の他のどの上限にも束縛されず、改名の反復で無制限に積み上がるため、「バージョン数 / 変数」と同値の上限を置く。**status = deleted のステートメントは対象外とする**: tombstone は prev 連鎖の終端で追加行は高々 1 行であり、削除まで遮断すると上限到達リソースがどの role でも恒久的に削除不能になる(本節の「削除で解放される」原則と衝突し、削除エンドポイントの wire 契約 — 上限超過エラー未宣言 — にも違反する)。判定は保存済み状態(最新 metaVersion + 1 が上限を超えるか)を基準とし、stale な申告 metaVersion を上限超過と誤報しない
- **DEK ラップ行数 / プロジェクト(2026-08-02 セッション 07 レビュー所有者裁定)**: dek_wraps はエポックごとに全メンバー分の行が積み上がり、リクエスト単位の上限だけでは反復リクエストによる累積が有界にならないため、プロジェクト累積の行数上限を置く。値は現実的利用(メンバー数 × 環境数 × エポック数。数百〜数千行)の 3 桁上。「現在保存中の行数」であり環境削除・ラップ削除(§12-6)で解放される。検査は**ラップ挿入の全経路 — 12-6 の登録 API(バックフィル・修復再登録)と 12-4 の複合リクエスト(環境作成・ローテーション)のすべて — で行う**(2026-08-03: エポック 1・新エポックの一括挿入が複合へ移った — 12-4 — 後も、経路の別なく本上限が適用される。「DEK ラップ数 / リクエスト」の表の上限も同様に複合リクエストの同梱集合へ適用される)
- **Phase 2 予告(DO ストレージ総量ガード)**: 上記の個別上限に加え、DO ストレージ実測量(`databaseSize`)の閾値超過を型付きエラーで拒否する運用ガードを Phase 2 で導入する。監査ログ(audit_events)の無期限保持(AUDIT_SPEC §5.3)を覆う唯一の防衛線となるため、監査ログの集約方針(同 §3.3)の実測判断と同時に設計する
- DEK ラップ数 / リクエストの上限は、チェーン受理ポリシー(10,000 エントリ)が束縛するメンバー数上限以上に取る(初回登録の完全一致要件 12-6 と両立し、登録不能なプロジェクトが生じない)。**登録署名(§12-6)の検証コストもこの上限が束縛する**: 最悪 10,000 件 × Ed25519 検証は、チェーン追記受理時の全チェーン再検証(CRYPTO_SPEC §6.4。最大 10,000 エントリ × Ed25519 検証)と同じオーダーであり、既に受理済みの資源消費水準を超えない(引き下げは完全一致要件との両立を壊すため行わない)。受信者 user_id の受理上限はチェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1 の 1024 バイト)に揃える — これより狭くするとチェーン上の正当なメンバー宛ラップが登録不能になる。理論極値(上限長の user_id × 上限数のラップ)では HTTP 生ボディ上限(実装詳細)が先に束縛しうるが、内部 user_id は ULID(26 文字)であり実運用では到達しない
- 超過は型付きエラー(413 / 422)で拒否する。ただし**表示名の長さ超過のみ Schema 検証の 400** で拒否される(値と違い専用の検証層を持たないため。表の値 256 文字は同じ)。セルフホストでの引き上げは合意規則を破らない
- **値・メタデータ署名の検証コスト(2026-08-03)**: push・メタ操作は 1 リクエスト 1 署名(+1 Ed25519 検証)であり、12-6 の登録署名(最悪 10,000 件)より 4 桁小さい。宣言ヘッド時点の状態参照(role・エポック)はチェーン全再検証を要しない(チェーン更新時に導出済みの区間索引 — メンバー在籍区間・エポック開始 seq — を引く実装を想定。CRYPTO_SPEC §6.3 のエポック有効区間)。保存行の増分は値・ステートメントあたり約 350 バイト(署名 128 + ヘッドハッシュ 64 + prev ハッシュ 64 + FP 32 + seq)で、既存の行数上限(バージョン数 / 変数・変数数 / 環境)が総量を束縛する。配布応答の増分も同オーダーであり 12-7 の一括 pull を有意に肥大させない

### 12-9. 監査イベント

本章の各操作と、チェーン追記の受理(§11)は、AUDIT_SPEC §3.3 / §3.4 のイベントを project DO 内に記録する(同 §5.1 スキーマ)。監査イベントの追記 API は公開しない(AUDIT_SPEC §7)。

### 12-10. security-critical 受理スキーマの厳格性と mutation 成功の定義(2026-08-19 セッション 32 起草 — session-31 裁定 1)

PR-M1 の監査(docs/notes/session-31.md §3 M1-A2)で、新 CLI が送った `manifest` フィールドを旧サーバーが**黙って除去して受理する**(受理スキーマの既定が未知フィールドの除去である)fail-open 経路が確認された。セルフホストではサーバーと CLI が独立に更新されるため、運用手順(更新順序の文書化)は恒久策にならない。本節はこれを構造的に閉じる(設計比較・棄却案は session-31 §7 裁定 1)。

1. **未知フィールドの拒否(strict 受理)**: security-critical mutation payload の受理スキーマは、**未知フィールドを Schema 検証エラー(400)で拒否しなければならない**(既定の「黙って除去」を禁止する)。対象は**署名済み構造・暗号文・鍵材料を運ぶすべての mutation** であり、**本仕様が規定するエンドポイント**では次の全てを指す(実装の有無を問わない — 承認済み・未実装の面も実装時に本基準の対象。新設・改訂時も本基準で判定し、本列挙を更新する): チェーン追記(§11-4。genesis エントリを運ぶプロジェクト作成 = init を含む)、環境作成・ローテーション複合(§12-4)、値 push・メタ操作(§12-5)、DEK ラップ登録(§12-6)、リカバリーブロブ登録(§13-2)、リース請求(§14)、招待の作成・受諾(§15-2 — 受諾署名 = 公開鍵を user_id に束縛する鍵宣言クラス)、ヘッド申告の提出(§16-1 — 2026-08-19 時点で未実装。実装時に本基準の対象)。チェーン層の合意規則「未知 op = チェーン無効」(CRYPTO_SPEC §6.2)と対になる API 受理層の原則であり、公開前のため後方互換条項を持たない。これにより「旧実装へ新フィールドを送る」形の失敗方向が、黙殺して受理(fail-open)から構造的拒否(fail-closed)へ固定される。複合リクエストは 1 リクエスト = 1 decode なので、受理時拒否は原子的であり部分受理は構造的に起きない。実装は受理スキーマ自身への焼き込み(Effect v4 の AST 注釈 `parseOptions` — 呼び出し側の ParseOptions より優先され、ネストと Union を越えて伝播することを実証済み — docs/notes/session-32.md)で行い、ハンドラごとの手動検査を持たない(単一実装点)。注釈は check 合成との適用順に依存して無警告で失効しうる(session-32 §2-3)ため、実装 PR は strict の実効性を受理経路の固定テストで保証しなければならない
2. **wire 非互換変更の設計規範**: 以後の security-critical な wire 変更は「**旧実装が構造的に拒否する形**」でのみ行う。フィールドの追加・削除は (1) の strict 受理が自動的に捕捉する。フィールド構成が変わらない意味論の変更は、CRYPTO_SPEC §1 原則 6(意味論は署名バイト列の中に置く)により、旧実装では署名検証の不一致として捕捉される — 別途の互換フラグ・バージョンネゴシエーションを設けない
3. **mutation 成功の定義**: security-critical mutation の成功は「2xx 応答の受信」ではなく「**検証可能な配布物で効果を確認した**」ことと定義する(2xx は輸送層の事実でしかない — サーバーを信頼しない原則の mutation 側への適用であり、旧サーバーの黙殺だけでなく悪意・バグのある新サーバーの虚偽 2xx にも同じ防御が効く)。確認材料は mutation 種別ごとに定める: チェーン追記・複合(環境作成・ローテーション)は**チェーン同期**(検証済みチェーン上の自エントリの確認)、メタ操作(ステートメント・マニフェスト)は **metadata-only pull**(§12-7 — `var.read` を記録しない経路)。**値 push は本定義の適用外**: 効果確認に使える配布物が値 pull しかなく、書き込み経路へ `var.read` 監査を持ち込むため(監査を汚さない経路が存在しない)。値 push の成功は従来どおりサーバーの CAS + 値署名検証とローカル床への自己記録が担い、値の巻き戻し検出はチェックポイント(CRYPTO_SPEC §6.2 / §6.3)の領分。**ローカル床への記録(CRYPTO_SPEC §6.3)とユーザーへの成功報告は、本確認を通過した効果のみが行う**

## 13. リカバリーブロブ API との接続(2026-08-09 セッション 18 起草)

CRYPTO_SPEC §8(リカバリーコード)のサーバー保存・配布面の規定。ラップ済み master 秘密鍵ブロブは**サーバーから見て不透明な暗号文**であり、リカバリーコード(KEK の素材)はいかなる API ペイロードにも含まれない — サーバーはブロブを復号・解釈できない(ゼロ知識の維持)。他ユーザーのブロブへの移植は AAD の user_id 束縛により復号失敗となる(CRYPTO_SPEC §8。サーバー側の追加検査を要しない)。

### 13-1. リソースモデル

- ブロブは **user 単位で高々 1 つ**(D1 `recovery_wraps`、user_id 主キー)。プロジェクト・org・チェーンと無関係であり、認可にトークンスコープ表(§12-3)・チェーン role は関与しない
- 再発行(CRYPTO_SPEC §8「新コード生成 → 再ラップ → 旧ラップの削除」)は**置換**として実現する: 登録と同一エンドポイントの upsert であり、旧ラップ行は新ブロブの受理と同時に消える(削除だけを行う独立エンドポイントは v1 では設けない — ラップなし状態を意図的に作る操作は再発行で十分)

### 13-2. エンドポイントと認可

| op | エンドポイント | 認可 |
|---|---|---|
| 登録・再発行 | `PUT /auth/recovery`(204) | `*` × admin スコープを含むトークンのみ(**セッション主体は拒否** — §5 の能力制限。2026-08-28 W0 裁定。それ以前はセッション可だった — W2b 実装で反転) |
| ブロブ取得 | `GET /auth/recovery`(200 / 未登録 404) | 同上 + レート制限(13-3) |
| 登録状態 | `GET /auth/recovery/status`(200) | 認証済み主体すべて |

- **鍵素材管理操作のトークン条件**: 登録・再発行・ブロブ取得は user 全域の鍵素材に触れる操作であり、プロジェクト限定・低権限トークンに許可しない。トークン主体は `{ project: "*", permission: "admin" }` スコープを含む場合のみ許可(既定の device flow トークンは満たす)、満たさなければ 403(insufficient-permission)。置換 = 再発行を低権限トークンに許すと、窃取されたスコープ限定トークンでラップを復号不能ブロブへ差し替える可用性攻撃(§12-6 の上書き禁止と同型)が成立するため。取得も同条件とする(ブロブ取得は AUDIT_SPEC §3.1 の要監視イベントであり、日常運用のスコープ限定トークンから呼ばれる正当な理由がない)
- 未認証は常に 401(AuthMiddleware)。404(未登録)が返るのは認証済みの本人に対してのみであり、存在秘匿(§11-2)の問題は生じない(自分の登録有無は status で本人に公開される情報)
- **ブロブ取得の CSRF ヘッダー(セッション主体のみ)**: `GET /auth/recovery` は GET だが取得計数(13-3)という状態を持ち、`SameSite=Lax` のセッションクッキーはクロスサイトのトップレベル遷移でも同送されるため、セッション主体には書き込み系(§5)と同じ `x-maruhi-csrf: 1` を要求する(欠落は 403)。第三者サイトが被害者の取得窓を消費する可用性いやがらせの遮断。Bearer トークンはクロスサイトで付与できないため対象外
- `status` はブロブを運ばない(登録有無 + 更新時刻のみ)。CLI の保管リマインダ・デバイス追加案内が認証のたびに呼べるよう、レート制限・スコープ条件の対象外とする

### 13-3. レート制限(CRYPTO_SPEC §8 の取得エンドポイント要件)

- 対象は `GET /auth/recovery`(ブロブ本体)のみ。**固定窓: user あたり 1 時間 5 回**。超過は 429 で、窓の残り秒数(retryAfterSeconds)を返す
- 位置づけは二重防御の補助線(認証 + 高エントロピーコードが本線): セッション・トークン奪取時のオンライン列挙とブロブ持ち出しの試行を遅くし、要監視イベントとしての検出時間を稼ぐ。並行リクエストで計数が僅かに超過しうるベストエフォートの抑制であり、暗号境界ではない
- 計数はブロブ行に併置し(fetch_window_start / fetch_count)、未登録(404)は計数しない

### 13-4. ワイヤ表現と受理ポリシー

```
RecoveryWrap = {
  suite: "maruhi/v1",          // スイート識別子(CRYPTO_SPEC §2 設計原則 4)
  nonceHex,                    // 96-bit ランダム nonce(hex 小文字 24 文字)
  ciphertextHex                // AES-256-GCM の ct || tag(hex 小文字)
}
```

- ciphertext はタグ込み 16 バイト以上・**16 KiB 以下**(受理ポリシー。ブロブの実体は master 鍵レコードの JSON 直列化 — 数百バイト — であり大きな余裕を持つ。上限は D1 への肥大暗号文蓄積の遮断)
- 配布(GET)は保存された suite / nonceHex / ciphertextHex をそのまま返す(updatedAtMs を付す)。ブロブの直列化形式はクライアント(CLI)の契約であり、サーバーは関知しない

### 13-5. 監査イベント

ブロブ取得は `auth.recovery_blob_fetched`、登録・再発行は `auth.recovery_code_reissued`(AUDIT_SPEC §3.1。D1 側)。D1 側監査ログ基盤(同 §5.2 案 A)の導入をもって実装済み(2026-08-10 セッション 21): 取得はブロブを実際に配布した応答(200)のみ計数更新と同一 batch で記録し、レート制限拒否・未登録 404 は記録しない(配布していないものを配布したと記録しない — §13-3 の計数対象と同じ線引き)。登録・再発行は置換 upsert と同一 batch で記録する(初回登録も同じ置換受理のため同一イベント)。

## 14. ワークロードリース API(2026-08-12 セッション 22 起草)

CRYPTO_SPEC §9.1(ワークロードリース)の API 面。長期資格情報を持たないワークロード(v1 = GitHub Actions のジョブ)が、OIDC トークンと一時公開鍵を提示して、grant_server 済みプロジェクトの環境の「チェーン + 暗号文 + ステートメント + リースラップ済み DEK」を 1 リクエストで取得する。**平文値・永続資格情報はどこにも現れない**: GitHub 側に保存する secret はゼロ、サーバーは値を復号せず(DEK の開封と再ラップのみ)、応答は暗号文とラップのみ(§10 / CRYPTO_SPEC §10 の不変条件はリース経路でも不変)。

### 14-1. 認証(OIDC)と認可(チェーン束縛ポリシー)

- 認証はリクエスト同梱の OIDC トークン(JWT)で行う。maruhi トークン・セッションは使わない(§12-3 の表の外)。検証: (1) issuer が**サーバー実装の対応 issuer 一覧**(v1 = GitHub Actions `https://token.actions.githubusercontent.com` のみ)に含まれること(デプロイメント全体で一様な静的設定であり、プロジェクトの存在・状態情報を運ばない)、(2) 署名は issuer の JWKS(OIDC discovery 経由で取得・TTL キャッシュ)で検証し、alg は RS256 / ES256 のみ許可(対称鍵 alg・`none` は拒否)、(2b) **JOSE ヘッダーが `crit`(RFC 7515 §4.1.11)を宣言していたら拒否する(2026-08-15 追記)** — crit は「理解できないなら受理してはならない拡張」の宣言であり、本仕様は拡張を 1 つも定義していないため、いかなる crit 値も理解できない拡張に該当する、(3) `exp` / `iat` の時刻検証(clock skew 許容 ±60 秒)。
- **JWKS の鮮度と可用性(2026-08-15 起草)**: 再取得に失敗した場合、**猶予窓(起草値: 6 時間)内に取得できていた JWKS があればそれで検証を続ける**(stale-while-revalidate)。これは fail-closed と矛盾しない — 署名検証は常に実施し、使える鍵が 1 つも無い場合にだけ拒否する(その応答は §14-3 の 503 `oidc-jwks-unavailable`)。この設計を採る理由は 2 つ: (a) issuer / ネットワークの一過性障害(数分〜数時間)が全プロジェクトの全ワークロードの停止に直結するのを避ける、(b) **未知 `kid` による再取得は署名検証の前に起きる = 未認証の呼び出し元が誘発できる**ため、失敗した取得が既存キャッシュを破棄する設計だと、存在しない kid を投げるだけで正当なトークンを拒否させられる。実装は「最後に成功した JWKS」を保持し、失敗が既存の値を壊さないこと・未知 kid の強制再取得に固定窓のクールダウンを課すことの両方を満たさなければならない。猶予窓は「issuer が鍵を失効させてから受理しなくなるまでの上限」でもあるため、可用性と失効追随のトレードオフとして明示的な設定値に置く。**認証はここまでであり、チェーン導出状態(grant・lease_policy)を一切参照しない** — grant の policy との突合は下の認可に属する(14-3 のとおり、認証失敗のみが 401 になる)
- **先着束縛(リプレイ緩和。2026-08-15 所有者裁定 — 設計比較・却下案・先例は docs/notes/session-24.md)**: サーバーはリース発行時に「**束縛キー → 提示された一時公開鍵**」の束縛をプロジェクト単位で記録し、同一束縛キーによる再要求を、**同一の一時公開鍵なら冪等に許可**し(応答喪失後の正規リトライ。トークンをジョブ開始時に事前発行しランタイム再発行できない issuer — GitLab 等 — を将来足しても再試行が壊れない)、**異なる一時公開鍵なら 401 `token-replayed` で拒否**する。これにより「使用済みトークンのコピー」は無効化され、盗難は攻撃者側の拒否(監査 — §14-4)または正規ジョブ側の `token-replayed` 失敗として可視化される(CRYPTO_SPEC §9.1 の縮小後の非保証も参照)。規則の要点:
  - **束縛キーは JWS signing input(`header.payload`)の SHA-256 とする — 生トークン文字列をハッシュしてはならない(必須。2026-08-15 pullfrog レビュー)**。生トークンの第 3 セグメント(署名)は署名の保護外で可鍛である: base64url 末尾グループの未使用ビット(WHATWG forgiving-base64 decode が捨てる — RS256 の末尾 1 文字は 15 通りの同値)と ES256 の `s`-malleability により、**デコード結果のバイト列・署名検証・`claims_digest` を一切変えずに生トークン文字列だけを変える**ことができる。生トークンをキーにすると、この 1 文字編集で束縛照合を空振りさせられ、先着束縛が丸ごと無効化される。signing input は issuer が実際に署名したバイト列そのもので、妥当性を保つ変異に対して不変であり、この経路を閉じる(実装では column 名も `token_hash` ではなく `binding_key` として取り違えを名前段階で防ぐ)
  - 束縛キーは `jti` claim にも依存しない。`jti` の有無・意味論は issuer 依存であり(Kubernetes は 1.32 GA、CircleCI は未確認)、signing input ハッシュは issuer に何も要求しない
  - **判定・記録は認可(lease_policy 一致・スコープ)より後**に置く(§14-3 の判定順)— 束縛状態の観測に、対応 issuer の有効署名 × lease_policy 一致より弱い資格で到達できる経路を作らない。束縛の**記録は発行と同一の原子的ブロック**で行う(発行なしに束縛だけが残る・発行されたのに束縛が残らない、のどちらの中間状態も作らない)
  - **保持期間の整合(必須)**: 束縛行は「時刻検証(§14-1 の (3))が当該トークンを受理しうる最終時刻」= `exp` + clock skew **以降まで**保持しなければならない。時刻検証の受理窓より先に束縛を失効させると、その差分の間リプレイが通る(PyPI trusted publishing の 2026 年監査が同型の不整合 — JWT 検証 leeway 30 秒 > リプレイキャッシュ余命 5 秒 — を指摘した先例。session-24)
  - 束縛はプロジェクト(DO)単位であり、キーは環境 ID を含まない。クロスプロジェクトの先着は防がない(CRYPTO_SPEC §9.1 の非保証 (2)。束縛の大域化は cross-DO 状態を要し、v1 の複雑性に見合わない)
  - **クライアント(A3)の義務**: リースエンドポイントは環境単位だが束縛はトークン単位でプロジェクト内の全環境を跨ぐため、**1 つの OIDC トークンで複数環境をリースするジョブは、全リクエストで同一の一時鍵を提示しなければならない**(トークンあたり一時鍵は 1 つ・リクエストごとに鍵をローテーションしない)。鍵をローテーションすると 2 本目以降が `token-replayed` で拒否される。これは意図した挙動である(トークンを最初に使った鍵へロックすることが先着束縛の本体であり、環境ごとに別鍵を許すと盗難トークンで未束縛の別環境を引く経路が開く)。ランタイム発行型 issuer(GitHub Actions)なら鍵を統一するか環境ごとに別トークンを発行してもよいが、事前発行型 issuer(GitLab / k8s projected volume)は 1 トークンを鍵固定で使い回すのが唯一の選択肢になる
  - `token-replayed` は同一トークンの再送では解消しない。ランタイム発行型 issuer(GitHub Actions)は**新規トークンを発行して 1 回だけ自動再試行してよい**(SHOULD)。同一トークン + 同一鍵の再試行は常に冪等に通るため、応答喪失からの回復に追加の対応は不要
- 認可は**存在量化**で判定する(2026-08-12 レビュー反映 — 「一致する要素の選択」では複数要素一致時の選定が非決定になる): チェーン導出の有効 grant_server の lease_policy(CRYPTO_SPEC §6.2)に、(1) issuer_url がトークンの issuer と一致し、(2) audience がトークンの `aud` と一致し(audience の推奨値はデプロイメントの origin)、(3) claim_constraints の**すべて**がトークンの claim と**完全一致**する要素が **1 つでも存在すれば**認可する。制約に列挙された claim のみ評価し、列挙外の claim は関与しない。同一 (issuer_url, audience) で claim_constraints の異なる複数要素は**正当な表現**である(例: ブランチ単位の CI 制限を `sub` 制約の値違いの要素として並べる — v1 は完全一致のみのため、複数ブランチの許可はこの形で表現する)。どの要素が一致したかは認可結果・リースラップに影響しない(claims_digest — CRYPTO_SPEC §9.1 — はトークンの issuer / sub / aud から計算され、要素の同定に依存しない)。評価意味論の拡張(prefix 等)は本章の改訂で行い、チェーン形式には影響しない(CRYPTO_SPEC §6.2 の構造 / 意味論の分離)
- **空の claim_constraints は一致しない(fail-closed。2026-08-24 明確化)**: issuer は全 GitHub Actions ワークロードで共有され、audience はトークン要求側が選べるため、制約 0 件を空積の真として扱うと第三者のワークロードまで認可してしまう。ポリシー作成クライアントは各要素に 1 件以上の claim 制約を必須とし、サーバー評価も古いクライアント等が作った空要素を不一致として扱う。この最低件数は評価意味論であり、CRYPTO_SPEC §6.2 のチェーン形状・合意規則は変更しない
- 対象環境が開示スコープ(scope_environments)に含まれること
- **存在秘匿(§11-2 の適用)**: 未知プロジェクト・grant なし・ポリシー不一致(issuer_url / audience / claim 制約のいずれの不一致も)・スコープ外環境は一律 404。OIDC 検証自体の失敗(対応 issuer 一覧外・署名・時刻・形式)と**先着束縛違反(`token-replayed` — 上記)**のみ 401 — いずれも提示された資格情報に帰属する失敗である。後者は認可通過後にのみ到達するため存在秘匿と両立する(404 に畳むと正規ジョブ側の失敗が診断不能になり、先着束縛の可視化の目的を打ち消す)

### 14-2. エンドポイントと応答

- `POST /projects/:projectId/environments/:environmentId/lease`。リクエスト = `{ oidcToken, ephemeralPubHex }`(一時 X25519 公開鍵 32 バイト hex。ワークロードがメモリ内で生成し、ジョブ終了とともに破棄する)
- 応答 = チェーン全体 + 現エポック + 全アクティブ変数の最新バージョン(EncryptedPayload + writer 情報)+ 最新メタステートメント(author 情報込み)+ **最新の `EnvironmentManifest`(issuer 情報込み)+ tombstone ステートメント + チェックポイント時点の値スナップショット列挙(§12-7 と同じ材料 — 2026-08-18)** + **リースラップ済み DEK(応答内の最新値が使用する全エポック分 + 現エポック)**。値付き一括 pull(§12-7)と同じ検証材料の同梱規律に、メンバーでない受信者のための**チェーン同梱**を加えた形(チェーン取得 API は §11-2 により非メンバーへ 404 を返すため、リース応答が唯一の配布経路になる)。**他メンバーのヘッド申告(§16)は同梱しない**(CRYPTO_SPEC §6.6 — 悪意サーバーは古いビューに当時の申告を添えて配れるため検出を足さず、「検証済み」の誤認だけが増える)
- リースラップは CRYPTO_SPEC §9.1(info に claims_digest を束縛)。**保存しない**(dek_wraps に入らない — 同 §9.1)
- 受信ワークロードの検証義務は CRYPTO_SPEC §9.1(チェーン検証・リポジトリアンカー・コミットメント照合・値署名検証・マニフェストとチェックポイント整合の検証 — 2026-08-18)

### 14-3. 判定順とエラー

- OIDC 検証 = 対応 issuer 一覧・署名・時刻・形式(401 — 14-1 の認証)→ lease_policy 一致(issuer_url / audience / claim 制約)+ スコープ(不一致は一律 404)→ **先着束縛(401 `token-replayed` — §14-1。2026-08-15 裁定)**: 認可の直後・環境の存在判定より前に置く — 束縛済みトークン + 別鍵の再要求には、対象環境の実在・削除状態によらず一様に 401 を返し、ポリシー一致済みトークンのコピー保持者に環境の存在情報を与えない(判定は読み取りのみでレート窓を消費しない)→ 環境の存在 → **レート制限(429 — 下記)**→ サーバー鍵宛ラップの存在(欠落 = 503 型付き `LeaseUnavailable`、reason: `server-wraps-missing` — grant 済みだが再ラップ未了の状態〔CRYPTO_SPEC §7〕を不透明な失敗にしない)→ 発行(先着束縛の記録は発行・監査・レート窓消費と同一の原子的ブロック — §14-1)
- **プロジェクト単位のレート制限(固定窓)は認可の後段に置く(2026-08-15 明確化)**: 認可より前に置くと、未認可の呼び出し元にも 429 が返って「そのプロジェクトは実在する」が漏れる(§11-2 の存在秘匿違反)。後段に置くことで 429 はポリシー一致済みのワークロードにしか届かず、窓を消費できる主体も「対応 issuer の有効署名 × チェーン上の lease_policy 一致」を満たすものだけになる(第三者が正当なワークロードの窓を枯らす経路を塞ぐ)
- **これとは別に、発信元 IP 単位の request-level レート制限をハンドラ最初(OIDC 検証・DO 解決より前)に置く(2026-08-24 deepsec M5 対応)**: DO はプロジェクト ID の名前指定で暗黙生成されるため、有効な OIDC トークンさえあれば多数の異なるプロジェクト ID で DO(constructor がテーブルを作成し、回収経路がない)を量産できる。既定デプロイの Workers Rate Limiting binding(60 回/分/IP。per-colo の best-effort。超過は 429 `LeaseRateLimited`)で生成レートを有界にする。判定は IP のみでいかなるプロジェクト状態にも依存しないため、認可前の 429 でも存在情報は漏れない(上記の存在秘匿論拠はプロジェクト状態に結び付いた 429 についてのもの)
- **JWKS 取得不能時の応答(2026-08-15 起草)**: issuer の JWKS を取得できず署名検証を**実行できなかった**場合は、fail-closed(§14-1)を維持したまま 503 `LeaseUnavailable`(reason: `oidc-jwks-unavailable`)を返す。§14-1 が列挙する 401 の対象(対応 issuer 一覧外・署名不一致・時刻・形式)はいずれも提示トークンに帰属する失敗だが、issuer 側・ネットワーク側の一過性障害はそうではない — 401 で返すと CI ジョブが「資格情報が不正」としてリトライ不能に扱うため、再試行可能な区分として分ける。サーバー鍵が未設定(CRYPTO_SPEC §9 の keypair 未設定)のデプロイメントも同じ 503 の reason `server-key-unconfigured` とする(秘密鍵なしでは開封経路が存在せず、これは設定の欠落であってプロジェクトの不在ではない)
- 受理ポリシー(値は起草値 — レビューで調整): リースはプロジェクトあたり**固定窓 1 時間 300 回**(超過 429)。oidcToken は 16 KiB 以下、ephemeralPubHex は 32 バイト hex 厳密

### 14-4. 監査

- 発行: `server.dek_unwrapped` + `server.lease_issued`(環境単位 1 行 — リースは環境単位配布であり変数粒度の選択がない。AUDIT_SPEC §3.5)。**リース応答は var.read を記録しない**(var.read は人間 actor の読み取りの証跡 — AUDIT_SPEC §3.3。ワークロードへの開示は server.* 系が担い、要ローテーション検出には lease_issued が入力される — 同 §4.1)
- 拒否: `server.lease_denied`(**OIDC 署名検証を通過した後の拒否のみ**・固定窓上限つき — AUDIT_SPEC §3.5)
- 監査 payload に外部識別子(リポジトリ名等)は書かない: 一致した policy 要素はチェーン(grant payload)が保持しており、`grant_chain_seq` + `claims_digest` で突合できる(AUDIT_SPEC §1-2 の禁止情報をリース経路でも増やさない)

## 15. 招待 API(2026-08-12 セッション 22 起草 — CRYPTO_SPEC 未決 #9 の解消)

CRYPTO_SPEC §6.5(受諾署名・相互確認)のリソース・API 面。メンバー追加は登録済み・未登録を問わず**招待 → 受諾 → add_member** の単一機構で行う(同意なき追加を構造的に排除する)。グローバル公開鍵ディレクトリは作らない(同 §6.5)。

### 15-1. リソースモデル

```sql
invitations (
  id              TEXT PRIMARY KEY,   -- ULID
  project_id      TEXT NOT NULL,      -- genesis ハッシュ。トークン保持を capability として扱う(§11-2 との整合)
  token_hash      TEXT NOT NULL,      -- 招待トークン(256-bit 乱数)の SHA-256。生値は発行応答で一度だけ返す(§5 と同じ規律)
  role            TEXT NOT NULL,      -- 'reader' | 'member' | 'admin'(招待経由で owner は付与しない)
  inviter_user_id TEXT NOT NULL,
  status          TEXT NOT NULL,      -- 'pending' | 'accepted' | 'completed' | 'revoked'(期限切れは expires_at からの導出)
  expires_at      INTEGER NOT NULL,   -- 発行 + 7 日(起草値)
  -- 受諾ブロック(status が accepted 以降):
  invitee_user_id TEXT, invitee_enc_pub TEXT, invitee_sig_pub TEXT,
  accept_signature TEXT,              -- CRYPTO_SPEC §6.5
  accepted_at     INTEGER,
  created_at      INTEGER NOT NULL
)
```

- 保存先は D1(受諾はプロジェクト非メンバーからの操作であり、トークン → プロジェクトの解決に全体索引を要するため)。監査イベント(invite.*)も同じ D1 に置き、同一 batch で追記する(AUDIT_SPEC §3.2 / §5.2)
- **単回使用**: 受諾は pending → accepted の CAS。受諾済み・失効・期限切れへの受諾は 410
- 招待相手向けの表示名スナップショット等は招待レコードに**持たせない**: 受諾前の相手に見せるのは role と、リンクが運ぶ検証可能な情報(15-3)のみ。サーバー申告の表示名を信頼させる面を作らない

### 15-2. エンドポイントと認可

| op | エンドポイント | 認可 |
|---|---|---|
| 発行 | `POST /projects/:projectId/invites` | トークンスコープ admin × チェーン role admin 以上(**role = admin の招待の発行は owner のみ** — CRYPTO_SPEC §6.2 の add_member 権限表と同水準)。**セッション主体は拒否**(§5 の能力制限 — 2026-08-28 W0 裁定: 発行は生 invite token = bearer capability の生成であり Web に置かない — ADR-0018 改訂 2。W2b 実装で反転) |
| 受諾 | `POST /invites/accept`(body: token, encPubHex, sigPubHex, signatureHex) | **全プロジェクトスコープ(`*`)× admin のトークンのみ**(§13-2 の鍵素材条件と同水準。device flow の既定トークンは満たす。スコープ限定トークンは 403 — 受諾は「自分の公開鍵を自分の user_id に束縛して宣言する」鍵宣言クラスの操作であり、スコープ限定トークンの窃取 + 招待リンクの複合で攻撃者鍵を被害者 user_id に束縛する経路を FP 相互確認の手前で遮断する。2026-08-15 明文化 — B1a 裁定の実装済み挙動の追認。**セッション主体は拒否** — §5 の能力制限〔2026-08-28 W0 裁定。それ以前はセッション可だった — W2b 実装で反転〕: 受諾は CLI のみ〔§15-3〕でセッションの正当な導線がなく、セッション XSS + 招待リンクの複合も同じ手前で塞ぐ)。トークン保持が対象招待への capability |
| 一覧・失効 | `GET / DELETE /projects/:projectId/invites(/:id)` | トークンスコープ admin × チェーン role admin 以上。**セッション主体も可**(チェーン role admin 以上 — §5 の能力制限の許可列挙〔読み取り + 失効系〕に含まれる。Web の招待管理 S8 の消費経路 — ADR-0018 改訂 2) |

- 受諾のサーバー検証: 受諾署名(CRYPTO_SPEC §6.5)を提示された sig 鍵で検証し、**呼び出し主体の内部 user_id = 署名対象の invitee_user_id** を要求する(§12-5 / CRYPTO_SPEC §5.1 と同じ「呼び出し主体 = 署名者」規則)。signed_bytes の project_id / token_hash は**保存行から再構成**する(§12-5 の座標再構成と同じ不変条件 — ワイヤ申告値から組まない)。鍵は形式検査(32 バイト hex)のみ行い、**メンバー鍵一意性(CRYPTO_SPEC §6.2)の事前判定はしない** — 最終判定は add_member のチェーン合意規則であり、二重の真実源を作らない(受諾時の重複検出は招待者クライアントへの警告表示のための情報提供 — SHOULD — に留める)
- **受諾はチェーンに影響しない**: add_member は招待者クライアントの後続操作(§11 の汎用追記 + §12-6 バックフィル)。サーバーは add_member 受理時に target = invitee の accepted 招待を completed へ更新する(導出状態の突合であり、真実源はチェーン)
- 受理ポリシー(起草値): pending 招待はプロジェクトあたり 100 まで、発行は固定窓 1 時間 30 回 / プロジェクト。超過は 429

### 15-3. 招待リンクの形式(クライアント仕様)

```
https://<web-origin>/invite#v=1&t=<token>&p=<project_id>&h=<head_hash_hex>&s=<head_seq>&iu=<inviter_user_id>&if=<inviter_key_fp_hex>&r=<role>
```

- **フラグメント(`#` 以降)はサーバーへ送信されない**: リンクの組み立ては発行者のクライアント、解釈は受諾者のクライアントが行い、サーバーはトークンハッシュ以外を観測できない。`p` / `h` / `s` は招待リンクアンカー(CRYPTO_SPEC §6.3 帯域外アンカー (a))、`iu` / `if` は相互確認(同 §6.5)の照合材料
- **`r` は付与予定 role の表示専用パラメータ(省略可。2026-08-15 追補 — B1b 裁定)**: §15-1 の「受諾前の相手に見せるのは role と、リンクが運ぶ検証可能な情報」のうち role の運搬経路。発行者クライアントの申告であり検証材料ではない — 付与される role の真実源は招待レコード(add_member の role は招待行から組む)。受諾クライアントは受諾応答の role と突合し、不一致は警告する。`r` を欠くリンク(追補前の発行分)も有効として解釈する
- CLI: `maruhi invite create`(リンクを組み立てて表示)/ `maruhi invite accept <link|token>`(相互確認 → 鍵生成〔未生成時〕→ 受諾署名 → 受諾 → アンカーを非機密ローカル状態へピン留め)
- **リンクの着地点(`<web-origin>/invite`)は完全に静的な案内ページとする(2026-08-28 W0 裁定 — ADR-0018 改訂 2・5 項。旧規定「Web の受諾画面は Web ダッシュボード実装時に同じ形式を解釈する」の置換)**: ページは受諾を CLI で行う旨(リンクをそのまま `maruhi invite accept '<リンク>'` へ渡す)と CLI 導入への導線のみを表示し、**フラグメントを解釈しない**。この不変条件は検査可能な形で固定する: **ページはスクリプトを一切持たない**(SPA の外の独立静的アセットとして配信し、per-path の CSP `script-src 'none'` で強制する — 「自前スクリプトが `location` に触れない」を規約でなく構成で真にする。実装は W1)。招待トークンを自前コードの script 文脈に載せず、Web 受諾画面への漂流を構造的に断つ。フラグメント形式と受諾クライアント(CLI)の解釈は不変であり、Web での受諾画面は作らない。招待リンクの**発行**も Web には置かない(帯域外アンカー `h` / `s` / `if` は発行者クライアントの検証済みヘッドと鍵 FP を要し、鍵なし Web はどちらも持たない — 同改訂 2 項。発行 API 自体〔§15-2〕は不変で、CLI / `maruhi ui` が使う)
- **アンカーのピン留めは受諾成功後に行う(2026-08-15 追補 — B1b レビュー反映)**: 受諾前にピン留めすると、失敗する受諾(失効・偽トークン)を含むリンクの投入だけで既存アンカーを上書きでき、機械照合(CRYPTO_SPEC §6.3 (a))を自己 DoS ないし置換できてしまう。機械照合済み(verified)のアンカーは後続の受諾でも上書きしない

### 15-4. 監査イベント

発行 = `invite.created`、受諾 = `invite.accepted`、失効 = `invite.revoked`(AUDIT_SPEC §3.2 — D1 側、レコード操作と同一 batch。期限切れはイベントなし = 状態導出)。add_member 受理による completed への更新は `chain.member_added`(同 §3.4)が証跡であり、独立イベントにしない。

## 16. ヘッド申告・チェックポイント支援 API(2026-08-18 セッション 27 起草)

CRYPTO_SPEC §6.6(ヘッド申告)/ §6.2 `checkpoint` / §6.3(ヘッドゴシップ・チェックポイント整合)の API 面。§11 / §12 と同じ規律に従う: 全エンドポイント認証必須、非メンバー・スコープ外への応答は一律 404(§11-2)。

### 16-1. ヘッド申告の提出と配布

| op | エンドポイント | 認可 |
|---|---|---|
| 申告の提出 | `PUT /projects/:projectId/head-attestation`(204) | トークンスコープ **read** × チェーン role reader 以上 |
| 申告集合の配布 | チェーン取得(§11 の get)応答に `attestations` として同梱 | 同 get の認可(read × reader 以上) |

- **read スコープで提出できる根拠**: 申告は読み取り同期の付随であり(CRYPTO_SPEC §6.3 — 提出契機は同期 + 検証の成功後)、書けるのは「自分の署名済み申告 1 行」のみで秘密・共有状態に触れない。write を要求すると、reader が常在する認可モデル(CRYPTO_SPEC §6.2)で read トークンの同期クライアントがゴシップに参加できなくなり、split view 検出の網羅性(全メンバーの利害 — 同 §6.6)を損なう
- リクエスト = `{ suite, chainHeadHashHex, chainHeadSeq, signatureHex }`(attester は呼び出し主体 — §12-5 の「呼び出し主体 = 署名者」規則と同じ)。受理検証は CRYPTO_SPEC §6.4(署名・ヘッド実在・seq 単調前進)。**後退申告は 409(型付き `AttestationRegression`。保存済み seq を返す)**: 黙って成功させない規律(§12-6 と同じ)— 正直なクライアントの後退は床の破損・並行 CLI の徴候であり、静かに握り潰すとクライアントバグを隠す。同一 seq への再提出は冪等に 204(同一内容の再送 — リトライ安全)
- 配布は**現メンバーの最新申告のみ**(attesterUserId + attesterKeyFingerprintHex を付す — §12-2 の検証材料と同型)。`remove_member` 受理時に対象の申告行を削除する(CRYPTO_SPEC §6.4)。**申告行のサーバー受理時刻は保存してよいが配布しない**(申告が運ぶ行動情報を「チェーン同期の到達点」に限定する — CRYPTO_SPEC §6.6 / AUDIT_SPEC §6)
- 受理ポリシー(起草値 — レビューで調整): メンバーあたり**固定窓 1 時間 60 回**(超過 429)。保存はメンバーごと最新 1 行でありストレージ肥大はない

### 16-2. チェックポイントの発行支援

- **standalone の** `checkpoint` エントリは**汎用チェーン追記 API(§11 の append)で受理する**。クライアント供給の付随データを伴わず(値スナップショットのダイジェスト原像はサーバーが受理時点状態から再構成する)、複合リクエストで原子的に束ねる別の入力がないため汎用経路を使う。**境界チェックポイント(2026-08-19 セッション 32 — 環境作成・ローテーション複合の必須同梱)は §12-4 の複合経路で受理する**。どちらの経路でもサーバーは、再構成した値スナップショット列挙 + 対応 checkpoint seq / hash を、payload に含まれる環境ごとの最新包含 checkpoint としてチェーン追記と同じ project DO トランザクションで upsert する(**保存規律は経路によらず同一**)。payload に含まれない環境の既存スナップショットは変更しない(CRYPTO_SPEC §6.4)。
- **audit_head_hash が非空の場合だけ、実効権限 admin(トークンスコープ admin × チェーン role admin 以上)を要求し、不足は 403 とする**(空文字列のデータ層 checkpoint は write × member 以上。チェーン role admin の条件は CRYPTO_SPEC §6.2 の合意規則でも独立に検証する)。受理検証(合意規則 + 受理時点の保存状態との突合)は CRYPTO_SPEC §6.2 / §6.4。突合失敗は 422(型付き `CheckpointStateMismatch` — 理由: `manifest-mismatch`〔最新マニフェストとの不一致 = 発行者のビューが古い場合を含む〕/ `values-digest-mismatch` / `audit-head-unknown` / `audit-head-stale`〔位置が直前チェックポイントのミラー行未満 — CRYPTO_SPEC §6.4。CAS 競合後に監査ヘッド申告を取り直さなかった発行の拒否〕/ `environment-deleted`〔削除済み環境のエントリ — CRYPTO_SPEC §6.4〕)で拒否する。クライアントはデータ層のビューを再取得・再検証して再署名・再試行し、監査ヘッドを公証する実効権限 admin の発行者だけが申告も取り直す(公証しない発行者は監査ヘッド取得を行わず、403 を踏まない)。
- **監査ヘッドの取得**: `GET /projects/:projectId/audit-head`(200 = `{ auditHeadHashHex }`)。認可は**実効権限 admin(トークンスコープ admin × チェーン role admin 以上 — §9-2 の min。2026-08-18 セキュリティレビュー対応)** — member 水準に開くと、累積ハッシュの**変化のポーリング**が「可視のクラス 1 イベントを伴わない監査行の追記 = クラス 2 の活動窓」を admin 未満へ漏らすタイミングサイドチャネルになる(admin は全行を閲覧できる主体であり、この応答は新しい情報を運ばない)。**応答に監査 seq・行数は含めない**(累積ハッシュは乱数的で序数を運ばない — AUDIT_SPEC §7 の「件数にも漏らさない」規律・C1 裁定との整合。CRYPTO_SPEC §6.2)。監査行ゼロのプロジェクトは空文字列を返す。**checkpoint の発行権限(member 以上)とは独立**: **実効権限が admin でない**発行者(チェーン role admin でもトークンスコープが write 止まりの場合を含む — クライアントはスコープとチェーン導出 role から事前に判定でき、403 を踏んでからフォールバックしない)は audit_head_hash を空文字列(監査ヘッドの公証なし — CRYPTO_SPEC §6.2)として発行する(データ層の公証は監査ヘッドなしで完結する)
- **遅延実体化の有界伸長(2026-08-28 セッション 38 — AUDIT_SPEC §5.1 の追補の API 面)**: 累積ハッシュ列の遅延実体化が 1 呼び出しの伸長上限に達した(= 列が MAX(seq) 未到達の)場合、監査ヘッドを読む全経路 — 本取得エンドポイントと checkpoint 受理(standalone / 境界複合の非空公証)— は **503(型付き `AuditHeadNotReady`)**で拒否する。本文は空とする(残量・監査行数を載せない — AUDIT_SPEC §7 の件数非漏洩)。拒否は認可判定より後にのみ返る(§11-2 の存在秘匿と両立)。retryable であり、伸長の進捗はサーバー側に保存済みで失敗応答を含む各呼び出しが前進するため、クライアントは即時再試行してよい(CLI は有界再試行し、枯渇時は発生条件〔巨大な既存ログの初回実体化〕と再実行での解消を案内する)
- 発行クライアントはマニフェスト参照(manifestVersion / signed_bytes ハッシュ)と values_digest を**自分の検証済みビューから**組み立てる(§12-7 の配布材料から再計算 — サーバー申告値をそのまま署名しない)。**実効権限 admin の発行者は** audit_head_hash のみ本エンドポイントの申告値を「発行時未検証の公証」として写す(それ以外は空文字列 — 上記。CRYPTO_SPEC §6.3 / §6.4 の意味論)

### 16-3. 監査イベント

- `checkpoint` エントリの受理はチェーンミラー `chain.checkpointed`(AUDIT_SPEC §3.4)を記録する
- **ヘッド申告は監査イベント化しない**(AUDIT_SPEC §6 — 高頻度・低情報で要ローテーション検出に不寄与、かつ「いつ同期したか」の恒久記録という行動情報を新設しない。CRYPTO_SPEC §6.6 のプライバシー最小化)
