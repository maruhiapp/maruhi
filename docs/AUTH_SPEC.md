# maruhi 認証・アイデンティティ仕様書 (AUTH_SPEC)

Version: 0.2-draft
Status: レビュー中(§11 は 2026-08-02 のセッション 06 裁定を反映)

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

**セルフホストの前提**: GitHub OAuth(web / device とも)には OAuth App の client_id / client_secret が必要であり、これは maruhi が中央で配布できない(コールバック URL がデプロイごとに異なるため)。**セルフホストする各ユーザーが自分の GitHub OAuth App を作成する必要がある**。これは「ワンクリックで立つ」体験と摩擦するため、初回アクセス時のセットアップウィザード(OAuth App 作成手順の案内 + client_id/secret の登録)を Phase 1 の CLI / サーバーに含める(ROADMAP 参照)。

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
5. GitHub トークンは両側で即時破棄。CLI は maruhi トークンのみを OS キーチェーンに保存する

## 5. セッション

- 生成: 256-bit 乱数。クライアントには生値、DB にはハッシュのみ
- クッキー: `__Host-maruhi_session` / `HttpOnly` / `Secure` / `SameSite=Lax` / `Path=/`
- 有効期限: 30 日(スライディング更新)。サーバー側削除で即時失効可能
- CSRF: SameSite=Lax + 書き込み系は custom header 要求(HttpApi ミドルウェアで一括)

## 6. API トークン

- 形式: `maruhi_pat_` + Base62 乱数(256-bit 相当)。プレフィックスで種別判別・secret scanning 対応
- スコープ: プロジェクト単位 × 権限(read / write / admin)。実効権限は min(トークンスコープ, 所有者のチェーン role)(§9-2)。将来: 環境単位のスコープ(Phase 2、CRYPTO_SPEC 未決事項 #11 と連動)、エージェント用の短命リーストークン(Phase 3、CRYPTO_SPEC と連動)
- 検証: 提示トークンの SHA-256 を DB と照合。タイミング安全比較
- **スコープ表現(2026-08-02 決定)**: スコープは `{ project: <project_id> | "*", permission: "read" | "write" | "admin" }` の配列。`"*"` は「所有者の全プロジェクト」を指すワイルドカード(CLI の作業用トークンに使う。実効権限は常に min(スコープ, チェーン role) でチェーン role に束縛されるため、ワイルドカードでも本人のチェーン権限を超えない)。device flow 交換時に要求スコープを指定し、省略時は `[{ project: "*", permission: "admin" }]`
- **操作が要求する権限水準(2026-08-02 決定)**: チェーン取得 = read。チェーン追記はエントリの op で決まる — `rotate_epoch` = write、`add_member` / `remove_member` / `change_role` / `grant_server` / `revoke_server` = admin。プロジェクト作成(genesis init)= admin。op ごとの認可(誰がその op を実行できるか)の真実源は引き続きチェーン role(CRYPTO_SPEC §6.2)であり、この表はトークンスコープ側の必要条件である
- **v1 の線引き(2026-08-02 決定)**: トークンの発行経路は device flow(§4)のみ。管理系 API は「自分自身のトークンの失効」まで。一覧・名前変更・追加発行の UI / API は Web ダッシュボード実装時に設計する
- **同名トークンはローテーション(2026-08-02 追加)**: 同一 (user, name) への発行は既存トークンの失効を伴う再発行とする(再ログイン = ローテーション)。発行連打による api_tokens の無制限増加を防ぐ(名前を変えれば複数トークンの併存は可能)

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
- `add_member` 等の対象(target_user_id)の存在検証は v1 では行わない(未登録ユーザー招待は CRYPTO_SPEC 未決事項 #9 の設計時に扱う)

### 11-2. 非メンバーへの応答は一律 404

- 認証済みでもチェーン導出メンバー(または有効スコープのトークン)でない主体には、get / append とも **404(ProjectNotFound)** を返し、プロジェクト ID の存在を秘匿する。未初期化プロジェクトと区別できない応答とする(ID は genesis ハッシュであり実質ケーパビリティ)

### 11-3. プロジェクト作成(init)と org の整合

- init リクエストは **org_id を必須**とし、作成権限は対象 org の **member 以上**(§9-1)。`projects.org_id` は NOT NULL
- 順序: org 権限確認(D1)→ DO genesis 受理 → D1 `projects` 行挿入。**DO(チェーン)が確定点**であり、projects 行は org 帰属の従属メタデータ(プロジェクト内権限の真実源ではない — CRYPTO_SPEC §6.4)
- 部分失敗の修復(冪等): DO 受理後・行挿入前に失敗した場合、同一 genesis の再 init は DO から already-initialized が返る。このとき「projects 行が欠損 + 認証主体 = genesis actor」であれば行を挿入して成功として返す。それ以外の already-initialized は 409

### 11-4. エンドポイントの配置

- 認証エンドポイントは **OAuth リダイレクト系(§3 start / callback)を含めすべて api-schema の HttpApi 定義**に置く(サーバー実装とクライアント導出の共有源を単一に保つ)
- 401 / 403 の型付きエラー(Unauthorized / Forbidden)を api-schema に共有定義し、認証必須エンドポイントの宣言に載せる
- CSRF(§5)の custom header は `x-maruhi-csrf: 1` とする。セッションクッキーで認証された書き込み系リクエストにのみ要求する(Authorization ヘッダーによるトークン認証はクロスサイトから発行できないため対象外)
