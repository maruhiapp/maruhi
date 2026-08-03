# maruhi 認証・アイデンティティ仕様書 (AUTH_SPEC)

Version: 0.6-draft
Status: レビュー中(§11 は 2026-08-02 のセッション 06 裁定、§12 は 2026-08-02 のセッション 07 提案を反映。§12-2 の suite / §12-6 の修復経路 / §12-8 の DEK ラップ行数上限は 2026-08-02 のセッション 07 レビュー所有者裁定をセッション 08 で反映。§12-2 / §12-6 の DEK ラップ登録署名は同裁定 2-E — CRYPTO_SPEC §5.1 — をセッション 09 で反映。§12-6 の鍵重複メンバーに関する事実記述は CRYPTO_SPEC §6.2 のメンバー鍵の一意性 — 2026-08-03 — をセッション 10 で反映。§12-1〜§12-8 の値・メタデータ署名 / DEK コミットメント / 環境作成のチェーン op 化に伴う改訂は CRYPTO_SPEC 0.4-draft — 2026-08-03 セッション 12 起草 — の波及であり、確定条件 = 同改訂 PR のマージ)

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
- **操作が要求する権限水準(2026-08-02 決定。2026-08-03 改訂)**: チェーン取得 = read。チェーン追記はエントリの op で決まる — `create_environment` / `rotate_epoch` = write(**ただしこの 2 op は §12-4 の複合リクエスト経由でのみ受理し、汎用チェーン追記 API では型付きエラーで拒否する** — チェーンエントリと付随データの原子性を汎用経路が迂回できないようにするため)、`add_member` / `remove_member` / `change_role` / `grant_server` / `revoke_server` = admin。プロジェクト作成(genesis init)= admin。op ごとの認可(誰がその op を実行できるか)の真実源は引き続きチェーン role(CRYPTO_SPEC §6.2)であり、この表はトークンスコープ側の必要条件である。データプレーン(変数・環境・DEK)の op 別水準は §12-3 の表に規定する
- **v1 の線引き(2026-08-02 決定)**: トークンの発行経路は device flow(§4)のみ。管理系 API は「自分自身のトークンの失効」まで。一覧・名前変更・追加発行の UI / API は Web ダッシュボード実装時に設計する
- **同名トークンはローテーション(2026-08-02 追加)**: 同一 (user, name) への発行は既存トークンの失効を伴う再発行とする(再ログイン = ローテーション)。失効と挿入は原子的に行い、並行発行でも同名トークンは 1 本(DB の一意制約で保証)
- **発行の上限(2026-08-02 追加)**: 別名トークンはユーザーあたり 100 本まで(超過は 429。同名ローテーションは上限に達していても可能)。トークン名は 128 文字以下、スコープは 100 エントリ以下、スコープの project はプロジェクト ID 形式または `"*"` のみ(認証済み主体による api_tokens の肥大 DoS の遮断)

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
- **配布(pull / 取得)応答は署名の検証材料を運ぶ(2026-08-03)**: 値には `writerUserId` + `writerKeyFingerprintHex`、メタステートメントには `authorUserId` + `authorKeyFingerprintHex` を付す(RecipientDek の signerUserId + signerKeyFingerprintHex と同型 — 受信者はチェーン履歴と照合して CRYPTO_SPEC §6.3 のクライアント検証を行う)。**名前を返すすべての応答(一括 pull・環境一覧等)は、名前の裸のスナップショットでなく検証可能なステートメント(+ author 情報)を運ぶ**(クライアントはステートメント検証を経ない名前を信用してはならない)。push・メタ操作リクエストではこれらは載せない(呼び出し主体 = 署名者が契約 — §5.1 / §12-5 と同じ規則)。DEK コミットメント(CRYPTO_SPEC §5.2)はチェーンエントリ内で配布されるため、データプレーン応答に独立のフィールドを持たない
- **DEK 配布応答(RecipientDek)は署名・署名者情報を運ぶ(2026-08-02 裁定 2-E のセッション 09 反映)**: 保存されたラップの `signatureHex` に加え、`signerUserId` と `signerKeyFingerprintHex`(登録受理時のチェーン導出メンバーの鍵 FP)を返す。受信者はこれらとチェーン履歴から配布時のクライアント検証(CRYPTO_SPEC §5.1)を行える
- **suite は永続データ構造の全域に持たせる(2026-08-02 セッション 07 レビュー裁定)**: WrappedDek のワイヤに suite を持ち、サーバーの保存行(変数バージョン・DEK ラップ)も suite 列を持つ。DEK 配布応答(RecipientDek)・pull 応答(EncryptedPayload)も保存された suite を返す。CRYPTO_SPEC §2 設計原則 4「すべての永続データ構造はスイート識別子を持つ」との整合であり、暗号仕様側の変更は伴わない(HPKE info は従来どおり CRYPTO_SPEC §5)。API スキーマ上は Literal `"maruhi/v1"` にピン留めしたまま(`maruhi/v2` 導入時の suite とエポックの結合判断は v2 設計まで保留する — 先取りしない)
- **サーバーは AAD を暗号学的に検証できない**(E2EE。復号鍵を持たない)。サーバーが行うのは (1) 申告 AAD 構成要素と保存先座標(URL の project / environment / variable、期待 version、現エポック)の一致検査、(2) 構造検査(hex 形式・nonce 長・ciphertext 最小長・サイズ上限)、(3) **値・メタデータ署名の検証(12-5。2026-08-03 — §12-6 の登録署名と同じく、復号を要しない署名検証としてサーバーにも可能な検査)**。文脈束縛の実際の強制は復号失敗(CRYPTO_SPEC §4)であり、その検証は crypto 層のテストベクターが担う

### 12-3. 認可(op 別必要権限。§6 の表のデータプレーン拡張)

| op | トークンスコープ | チェーン role |
|---|---|---|
| 一括 pull・環境一覧・自分宛 DEK 取得 | read | reader 以上 |
| 変数の作成・push・改名・削除、環境の作成・改名、DEK ラップ登録 | write | member 以上 |
| 環境の削除、DEK ラップの削除(§12-6 の修復経路) | admin | admin 以上 |

- 判定順は §11 の先例と同一: 認証(401)→ 書き込み系はサイズ先行検査(413。資源保護は意味論的判定に優先)→ トークンスコープ(スコープ外 = 404、水準不足 = 403)→ チェーン導出メンバーシップ(非メンバー = 404)→ チェーン role(不足 = 403)→ 意味論的検査
- 例外として、**申告 AAD の座標一致検査(§12-2)はサイズ検査と同様に認可判定へ先行してよい**: 応答(422)がリクエスト内容のみから計算できる自己整合検査であり、プロジェクトの存在・状態情報を一切運ばないため、§11-2 の存在秘匿と両立する(スコープ外の主体が AAD 不整合なリクエストを送った場合は 404 でなく 422 が返る)
- 環境・変数の存在に関する 404(EnvironmentNotFound / VariableNotFound)が返るのは**チェーン導出メンバーに対してのみ**(プロジェクト自体の存在秘匿 §11-2 が常に先行する)
- reader は取得可・push 不可(CRYPTO_SPEC §6.2)。チェーン role の真実源は引き続きチェーンであり、この表はトークンスコープ側の必要条件 + サーバーが強制する role 下限である
- **認可時点の二重判定(2026-08-03)**: 署名を伴う操作(push・メタ操作)は、従来の「受理時点の現メンバー role」に加えて「**宣言ヘッド時点の role**」(CRYPTO_SPEC §6.3 の 3)も満たさなければならない。表の role 水準は両時点に同じ値を適用する(値 push・変数の作成/改名/削除・環境の作成/改名 = member、環境の削除 = admin)

### 12-4. 環境管理(2026-08-03 セッション 12 改訂 — 環境作成のチェーン op 化に追随)

- **作成は複合リクエストとして原子的**: リクエストに (1) `create_environment` チェーンエントリ(environment_id + エポック 1 の dek_commitment_hex — CRYPTO_SPEC §6.2。親ヘッドの CAS を含む通常のチェーン追記として検証する)、(2) `EnvironmentMetaStatement`(metaVersion 1、status active — 表示名を運ぶ)、(3) **エポック 1 の DEK ラップ完全集合**(現メンバー全員宛。12-6 の検証を通ること)を同梱し、プロジェクト DO がチェーン追記とデータ登録を**原子的に**受理する(CRYPTO_SPEC §6.4 の複合受理)。「環境はあるが誰も DEK を持てない」「コミットメントはあるがラップがない」中間状態を作らない。チェーンエントリの actor・ステートメントの author・ラップの署名者は、いずれも呼び出し主体と厳密一致でなければならない
- **複合内の宣言ヘッド(2026-08-03 明確化)**: 同梱ステートメントの `chainHeadHashHex` / `chainHeadSeq` は**追記前の現ヘッド(= 同梱チェーンエントリの prev と同一)**とし、サーバーのヘッド実在検査(12-5 の 2)は**追記前のチェーン**に対して行う(同梱エントリ自身をヘッドに宣言する形は受理しない — 実装間で検査対象チェーンが割れる曖昧さを排除する)。ヘッド CAS 失敗(409)後の再試行では、チェーンエントリ(prev_hash 変更)と同梱ステートメント(宣言ヘッド変更)の**両方を再署名**する。ラップ集合は再試行の間に現メンバー集合が変わった場合のみ作り直す。なお env メタステートメント(metaVersion 1)の宣言ヘッド時点に環境は未存在だが、メタステートメントの検証は環境の存在を検査しない(値署名のエポック整合 — CRYPTO_SPEC §6.3 の 4 — とは非対称であることを明示しておく)
- 作成の受理条件: `create_environment` の合意規則(environment_id はチェーン履歴全体で一意 — CRYPTO_SPEC §6.2)が従来の「現存しない・tombstone でない・rotate 観測済みでない」検査を包含する(tombstone・環境行はチェーン導出のキャッシュに退化し、独立の真実源にしない)。作成時点の現エポックは常に初期値 1(CRYPTO_SPEC §3)
- **ローテーションも複合リクエスト**: `rotate_epoch` チェーンエントリ(新エポックの dek_commitment_hex 込み)+ **新エポックのラップ完全集合**を原子的に受理する(従来の「チェーン追記 → ラップ初回登録」の 2 リクエスト分離を廃止 — 分離は「新エポックはあるが誰も DEK を持てない」中間状態を常態化させるため)。現在値の再暗号化(CRYPTO_SPEC §7)は後続の通常 push(12-5)であり、複合には含めない(値の量に依存する巨大リクエストを避ける。未再暗号化の間、旧エポックの最新値が配布されることは 12-7 のとおり)。**削除済み(tombstone)環境への rotate 複合は 404(EnvironmentNotFound)で拒否する**(CRYPTO_SPEC §7 の「全環境」は削除済みを含まない — 仕様適合クライアントが満たせない義務を作らない)。v1 のラップ完全集合は**現メンバー集合のみ**を対象とする(有効な grant_server のサーバー鍵宛ラップは Phase 2 で本章を改訂して扱う — CRYPTO_SPEC §9 の MVP 線引き。それまで grant 済みプロジェクトのローテーションは同期機能を停止させたまま受理される — CRYPTO_SPEC §7 の UI 明示義務)
- **複合内の整合検査(2026-08-03 明確化)**: サーバーは同梱サブペイロード間の座標一致を受理条件とする — 作成: チェーンエントリ payload の environment_id = ステートメントの environmentId = 全ラップの環境座標、かつ全ラップの epoch = 1。ローテーション: エントリ payload の environment_id = 全ラップの環境座標、かつ全ラップの epoch = エントリの new_epoch。**各部分の独立検証だけで不整合な組(別環境のステートメント・別エポックのラップ等)を受理してはならない**。12-6 の「登録できるエポックは 1〜現エポック」の複合同梱ラップへの適用は**同梱エントリ適用後のチェーン状態**に対して行う(上記の epoch 一致検査と同値。追記前の状態で判定すると、新エポック宛ラップを同梱する正当なローテーション複合が「未来のエポック宛」として全拒否になる)
- **add_member 後のバックフィルは複合化しない(意図的な非対称)**: 「メンバーはいるがラップがない」中間状態は残る。全環境 × 全エポックのラップは 12-8 のリクエスト上限を超えうる(環境 100 × エポック多数 × 対象メンバー)ため 1 リクエストの原子性で覆えず、また不足は §6.3 のラップ先一致検査と 12-6 の追記経路で収束可能なため、複合の対象にしない
- ~~チェーン受理は環境メタデータと突合しない~~(2026-08-03 廃止): `rotate_epoch` は当該 environment_id の `create_environment` の先行を要する(CRYPTO_SPEC §6.2 の合意規則)。環境の存在がチェーン導出値になったため、可変のサーバーローカル状態への依存という旧規則の懸念は解消されている(旧規則の「存在しない ID への rotate はデータ層に効果を持たず ID を焼却する」挙動は廃止)
- 改名は表示名のみ(暗号文脈は改名の影響を受けない environment_id — CRYPTO_SPEC §3)。改名・削除は `EnvironmentMetaStatement`(metaVersion + 1)を伴い、**受理は 12-5 のメタステートメント規則に従う**(署名検証 1〜3 + prev 連鎖 + metaVersion CAS + 座標のサーバー側再構成。削除は宣言ヘッド時点 admin — 12-3)
- 削除は admin 以上。環境行は tombstone として残し、配下の変数・バージョン(暗号文)・ラップ済み DEK は即時削除する。削除の `EnvironmentMetaStatement`(status deleted)は保存・配布し続ける(CRYPTO_SPEC §4.2 — 削除の否認・無断復活の検出材料)。監査ログには変数ごとの var.deleted と env.deleted を記録する(AUDIT_SPEC §3.3)

### 12-5. 変数とバージョニング

- version は 1 始まりの連番で AAD の一部(CRYPTO_SPEC §4)。**サーバーは version を採番できない**(採番すると申告 AAD とずれる)ため、push は CAS で受理する: 申告 version == 現在の最新 version + 1 のみ受理し、不一致は 409 で現在の最新 version(番号のみ)を返す
- **409 後の再試行手順(2026-08-03 — CRYPTO_SPEC §4.1 の連鎖と CAS の接続)**: クライアントは勝った最新 version を取得し(12-7)、**§6.3 の全検証を通過させた上で**その signed_bytes ハッシュを自ら再計算して `prevValueSigHashHex` に用い、新 version で再暗号化・再署名して再試行する。**409 応答に勝者の signed_bytes ハッシュは含めない**(含めるとクライアントが未検証のサーバー申告値へ自分の署名で連鎖することになり、悪意サーバーが偽 prev への連鎖署名を作らせられる — 証拠連鎖の汚染)。metaVersion CAS(下記)の再試行は**同型の手順をステートメントに適用する**: 勝った最新ステートメントを取得 → §6.3 の全検証 → その signed_bytes ハッシュを自ら再計算して `prevMetaSigHashHex` に用い、metaVersion + 1 の新ステートメントを再署名して再試行する(値を伴わないため再暗号化は発生しない。409 応答に勝者のハッシュを含めない規律も同一)
- **push が参照できるエポックは現エポックのみ**(チェーン導出 ChainState.environmentEpochs の値、`create_environment` 直後は初期値 1)。旧エポックの push は 409 で現エポックを返す。ローテーション直後の競合はこの応答によりクライアントが新 DEK を取得・再暗号化して再試行する。**保存済みの過去バージョンは当時のエポックのまま保持される**(CRYPTO_SPEC §7)— 本規則は新規受理だけを現エポックに束縛する
- **値署名の検証(2026-08-03 — CRYPTO_SPEC §4.1 / §6.4)**: push の受理条件に以下を加える。検証失敗は 422(`signature-invalid` / `chain-head-unknown` / `chain-head-state-mismatch`)で拒否する:
  1. 署名は**呼び出し主体の受理時点チェーン導出 sig 鍵**で検証し、署名対象の writer_user_id にも呼び出し主体の user_id を用いる(12-6 の登録署名と同じ「呼び出し主体 = 署名者」規則。他人が署名した値の持ち込みは拒否)
  2. `chainHeadHashHex` は自チェーンの seq = `chainHeadSeq` のエントリハッシュと一致すること
  3. **認可時点(共通)**: 宣言ヘッド時点のチェーン導出状態で、呼び出し主体が当該操作の必要 role(12-3 の二重判定の表)を持つこと
  4. **エポック整合(値のみ — CRYPTO_SPEC §6.3 の 4 と同じ書き分け)**: 宣言ヘッド時点の当該環境の現エポックが、申告 AAD の epoch と一致すること(受理時点の現エポック検査 — 上記 — とは別の検査であることに注意: 宣言ヘッドから受理までの間にローテーションが挟まれば受理時点検査が 409 で落とす)。**宣言ヘッド seq が当該環境の `create_environment` の seq より前である値署名は無効**(§6.3 の 4 の後段と同一 — エポックが未定義の宣言ヘッドを既定値で補う実装を禁止する)。メタステートメントは AAD・epoch フィールドを持たない(CRYPTO_SPEC §4.2)ため本検査の対象外
  5. `prevValueSigHashHex` が保存済みの直前 version の signed_bytes ハッシュと一致すること(version 1 は空文字列)。サーバーは各バージョンの signed_bytes ハッシュを保存行に持つ
- **エポック単調性(CRYPTO_SPEC §4.1)の独立検査はサーバーに置かない(2026-08-03 明確化)**: 「受理は現エポックのみ」(上記)と現エポックの時間単調性(rotate_epoch は +1 のみ — CRYPTO_SPEC §6.3)により、受理される新 version の epoch は保存済み全バージョンの epoch 以上であることが**構造的に**保証される。独立の比較検査は冗長であり追加しない(この含意は本規則群の帰結であるため、「受理は現エポックのみ」を緩める将来改訂はエポック単調性の担保方法の再検討を伴う)
- **署名対象の座標はサーバー側の値から再構成する(2026-08-03)**: signed_bytes の検証に用いる project_id は DO 自身のチェーン(genesis ハッシュ)から、environment / variable 座標は URL・保存先から取る。クライアント申告値(申告 AAD)から組まない(CRYPTO_SPEC §5.1 実装の「project_id は DO 自身のチェーンから取る」— セッション 09 §3 — と同じ不変条件。申告 AAD との一致検査 — 12-2 — に暗黙依存させない)。**この規則は値署名とメタステートメント署名の両方に適用する**: 署名対象の座標フィールド — `var_meta_signed_bytes` は project_id / environment_id / variable_id、`env_meta_signed_bytes` は project_id / environment_id(CRYPTO_SPEC §4.2 の各 LP に存在するフィールドのみ。env メタに variable_id は存在しない)— も URL・保存先座標から再構成し、ワイヤの `environmentId` / `variableId` 申告値から組まない(別座標への有効署名を要求パスの座標で保存する取り違えを構造的に排除する)
- サーバーの保存行は値ごとに署名・writer(user_id + 鍵 FP)・宣言ヘッド(hash + seq)・prev ハッシュを持ち、配布(12-7)でそのまま返す。監査イベント `var.version_pushed` は writer の鍵 FP を写す(AUDIT_SPEC §3.3)
- 変数の作成は最初の値(version 1)と `VariableMetaStatement`(metaVersion 1)を同梱する(値のない変数は存在しない)。**同梱する version 1 の値は通常 push と同一の検証(上記 1〜5)を受ける**(作成経由で値署名の検証を迂回できない)。改名・削除のステートメントは metaVersion の CAS(申告 == 最新 + 1)で受理し、409 は最新 metaVersion を返す。ステートメントの署名検証は**上記 1〜3(署名者一致・ヘッド実在・宣言ヘッド時点の role)+ prev 連鎖(`prevMetaSigHashHex` の metaVersion 連鎖 — 上記 5 と同型)**。エポック整合(上記 4)は値専用でありメタステートメントには適用しない。**このメタステートメント受理規則は `VariableMetaStatement` と `EnvironmentMetaStatement` に共通**(環境の改名・削除 — 12-4 — と複合作成の同梱ステートメントにも適用する。複合固有の宣言ヘッド規則は 12-4、削除の role 水準 admin は 12-3)。**サーバーは変数・環境ごとに各 metaVersion のステートメント(signed_bytes ハッシュ・署名・author 情報込み)を保存する**(prev 検査は保存済み直前 metaVersion のハッシュに対して行い、409 再試行・12-7 の配布材料もこの保存行が担う — 値の保存行規定と同型)
- 削除は変数 tombstone + 全バージョンの暗号文削除。削除の `VariableMetaStatement`(status deleted)は保存・配布し続ける。監査上の存在区間は var.created / var.deleted イベントが保持する(要ローテーション検出は削除済み変数も対象 — AUDIT_SPEC §4.1)

### 12-6. DEK ラップの保存・配布(CRYPTO_SPEC §6.3 ゴーストメンバー対策のサーバー側)

- 受信者の同定は **user_id と enc 公開鍵の両方**とし、チェーン導出の現メンバーと両方が厳密一致しなければ受理しない。user_id だけでは「チェーン上の鍵と異なる鍵へのラップ」(実質ゴーストメンバー)を検出できず、公開鍵だけでは HPKE info の recipient_user_id(CRYPTO_SPEC §5)と照合できない
- **登録署名の検証(2026-08-02 セッション 07 所有者裁定 2-E。CRYPTO_SPEC §5.1)**: ラップ挿入の**全経路**(DEK 登録 API と環境作成の同梱ラップの両方。修復経路の削除後の再登録も追記経路として同一)で、各ラップの `signatureHex` を検証する。受理条件は (1) **API 呼び出し主体 = 署名者の厳密一致**(署名は呼び出し主体のチェーン導出 sig 公開鍵で検証し、署名対象の signer_user_id にも呼び出し主体の user_id を用いる — 他人が署名したラップの持ち込みは拒否される。同一公開鍵を持つ別メンバーは CRYPTO_SPEC §6.2 のメンバー鍵の一意性 — 2026-08-03 — によりそもそも成立しないが、signer_user_id の束縛は独立の防衛層であり、仮に鍵重複メンバーが存在しても署名者不一致として拒否される)、(2) 署名対象(CRYPTO_SPEC §5.1 の signed_bytes。URL の project / environment 座標とワイヤの epoch・受信者・enc・ct、および署名者 user_id を束縛)との一致。検証失敗は 422(`signature-invalid`)で拒否する。この検証はチェーン外のデータに対する最初のクライアント署名検証(2026-08-02 当時は唯一。2026-08-03 に値・メタデータ署名 — 12-5 — が加わった)であり、毒ラップの帰属をサーバー不信で成立させる(監査イベントの署名者 FP — AUDIT_SPEC §3.3 — と突合できる)
- (環境, エポック) のラップ集合の**初回登録**(環境作成時のエポック 1、ローテーション後の新エポックの一括登録)は、現メンバー集合との**完全一致**を要求する: 欠落・非メンバー宛・鍵不一致・重複はすべて 422 で拒否する
- 以後は**不足分の追記のみ**許可する(add_member 後に招待者が新メンバー宛へ全エポックの DEK をラップして登録する経路 — CRYPTO_SPEC §7)。**既存 (環境, エポック, 受信者) の上書きは禁止**(409)。ラップの中身はサーバーに検証不能であり、上書きを許すと有効なラップを復号不能なブロブで置換する可用性攻撃が成立するため。**登録の列挙は 1 件以上**とする(空の `deks: []` は Schema 検証の 400。2026-08-03 に 204 no-op から変更 — 呼び出し形として意味のあるユースケースがなく、silent no-op はクライアントバグ〔空配列の送信を登録完了と誤認する〕を隠すため、削除側の空列挙 400 と同じ「黙って成功させない」規律に統一した。環境作成の同梱 `deks` は対象外: 空集合は完全一致要件の 422 recipient-missing が既に拒否する)
- 登録できるエポックは 1〜現エポック(未来のエポック宛は拒否)。判定の基準状態は経路で異なる(2026-08-03 明確化): 独立登録 API(バックフィル・修復再登録)は**受理時点のチェーン状態**、複合リクエスト(12-4)の同梱ラップは**同梱エントリ適用後の状態**(同梱ラップの epoch は同梱エントリが確立するエポック — 作成 = 1、rotate = new_epoch — との一致を 12-4 が要求するため、実質同値)
- **修復経路: ラップ削除 → 不足分再登録(2026-08-02 セッション 07 レビュー所有者裁定)**: 上書き禁止を維持したまま、復号不能な毒ラップ(登録者のバグ・不正)の唯一の修復手段として、**(環境, エポック, 受信者) 単位の明示的なラップ削除**を提供する。削除後は上記の「不足分の追記」経路で正しいラップを再登録する(あるエポックの全ラップが削除された場合、その再登録は初回登録として完全一致を要求される)。**再登録にも登録署名が必須**(追記経路は登録署名の検証を常に伴う — 再登録者が自らラップし自ら署名する)。必要権限は**環境削除と同水準(トークンスコープ admin × チェーン role admin 以上 — §12-3)**: 削除は他メンバーの復号可能性を奪う操作であり、member 水準に置くと上書き禁止が防いだ可用性攻撃が削除経由で復活するため。存在しないタプルの削除は 404 で拒否し、**削除対象の列挙は 1 件以上**とする(空列挙は Schema 検証の 400。監査痕跡を一切残さない破壊系 API の呼び出し形を許さない — 404 と同じ「黙って成功させない」規律)。削除は監査イベント(`dek.deleted` — AUDIT_SPEC §3.3)として受信者ごとに記録する
- 配布は本人宛のみ: 認証主体は自分が受信者であるラップだけを取得できる(reader を含む全メンバー — CRYPTO_SPEC §6.2)
- **DEK コミットメントとの関係(2026-08-03 — CRYPTO_SPEC §5.2)**: サーバーはラップの中身とコミットメントの一致を検証**できない**(E2EE)。照合は受信者が開封後に行い、不一致のラップは毒ラップとして本節の修復経路(削除 → 再登録)の対象になる。コミットメント導入後も本節の受理条件(受信者一致・完全一致・上書き禁止・登録署名)は不変であり、修復経路の意義は「復号不能な毒」から「復号不能またはコミットメント不一致の毒」へ広がるだけである
- grant_server 済みプロジェクトのサーバー鍵宛ラップは Phase 2(CRYPTO_SPEC §9 の MVP 線引き)で本章を改訂して扱う。**エポック 1 とローテーションのラップ登録は 12-4 の複合リクエストに移った**ため、本節の独立登録 API が残る経路は「add_member 後の新メンバー宛バックフィル」と「修復経路の再登録」である(受理規則は全経路共通のまま)

### 12-7. 一括 pull(CLI `maruhi run` / Web の取得経路)

- 環境単位の 1 リクエストで、全アクティブ変数の最新バージョン(EncryptedPayload。申告 AAD 込みで自己記述的)+ 現エポック + **呼び出し主体宛の全エポックのラップ済み DEK** を返す
- **検証材料の同梱(2026-08-03)**: 各値には署名ブロックと writer 情報(12-2)、各変数・環境には最新の `VariableMetaStatement` / `EnvironmentMetaStatement` と author 情報を同梱する。クライアントは CRYPTO_SPEC §6.3 の検証(署名・ヘッド束縛・認可時点・エポック整合・座標整合)と §5.2 のコミットメント照合を通過したものだけを使用する。名前 → variable_id の解決は検証済みステートメント経由で行う
- 最新バージョンのエポックは変数ごとに異なりうる(ローテーション後の再暗号化が完了するまで、CRYPTO_SPEC §7)。このため全エポックのラップを同梱する
- 監査: var.read を**変数ごとに 1 行**記録する(AUDIT_SPEC §3.3)

### 12-8. 受理ポリシー(サイズ・数量。CRYPTO_SPEC §6.4 と同じ性格 = 合意規則ではない)

| 対象 | 上限 |
|---|---|
| 値の暗号文(ct \|\| tag) | 64 KiB |
| 表示名(環境・変数) | 256 文字 |
| 環境数 / プロジェクト | アクティブ 100(tombstone 込み 1,000) |
| 変数数 / 環境 | アクティブ 1,000(tombstone 込み 5,000) |
| バージョン数 / 変数 | 1,000 |
| プロジェクト累積暗号文バイト | 1 GiB |
| DEK ラップ数 / リクエスト | 10,000 |
| DEK ラップ行数 / プロジェクト | 1,000,000 |

- 累積暗号文バイトは「現在保存中の量」であり削除で解放される(DO SQLite 10 GB に対する資源保護)
- **DEK ラップ行数 / プロジェクト(2026-08-02 セッション 07 レビュー所有者裁定)**: dek_wraps はエポックごとに全メンバー分の行が積み上がり、リクエスト単位の上限だけでは反復リクエストによる累積が有界にならないため、プロジェクト累積の行数上限を置く。値は現実的利用(メンバー数 × 環境数 × エポック数。数百〜数千行)の 3 桁上。「現在保存中の行数」であり環境削除・ラップ削除(§12-6)で解放される。検査は**ラップ挿入の全経路 — 12-6 の登録 API(バックフィル・修復再登録)と 12-4 の複合リクエスト(環境作成・ローテーション)のすべて — で行う**(2026-08-03: エポック 1・新エポックの一括挿入が複合へ移った — 12-4 — 後も、経路の別なく本上限が適用される。「DEK ラップ数 / リクエスト」の表の上限も同様に複合リクエストの同梱集合へ適用される)
- **Phase 2 予告(DO ストレージ総量ガード)**: 上記の個別上限に加え、DO ストレージ実測量(`databaseSize`)の閾値超過を型付きエラーで拒否する運用ガードを Phase 2 で導入する。監査ログ(audit_events)の無期限保持(AUDIT_SPEC §5.3)を覆う唯一の防衛線となるため、監査ログの集約方針(同 §3.3)の実測判断と同時に設計する
- DEK ラップ数 / リクエストの上限は、チェーン受理ポリシー(10,000 エントリ)が束縛するメンバー数上限以上に取る(初回登録の完全一致要件 12-6 と両立し、登録不能なプロジェクトが生じない)。**登録署名(§12-6)の検証コストもこの上限が束縛する**: 最悪 10,000 件 × Ed25519 検証は、チェーン追記受理時の全チェーン再検証(CRYPTO_SPEC §6.4。最大 10,000 エントリ × Ed25519 検証)と同じオーダーであり、既に受理済みの資源消費水準を超えない(引き下げは完全一致要件との両立を壊すため行わない)。受信者 user_id の受理上限はチェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1 の 1024 バイト)に揃える — これより狭くするとチェーン上の正当なメンバー宛ラップが登録不能になる。理論極値(上限長の user_id × 上限数のラップ)では HTTP 生ボディ上限(実装詳細)が先に束縛しうるが、内部 user_id は ULID(26 文字)であり実運用では到達しない
- 超過は型付きエラー(413 / 422)で拒否する。ただし**表示名の長さ超過のみ Schema 検証の 400** で拒否される(値と違い専用の検証層を持たないため。表の値 256 文字は同じ)。セルフホストでの引き上げは合意規則を破らない
- **値・メタデータ署名の検証コスト(2026-08-03)**: push・メタ操作は 1 リクエスト 1 署名(+1 Ed25519 検証)であり、12-6 の登録署名(最悪 10,000 件)より 4 桁小さい。宣言ヘッド時点の状態参照(role・エポック)はチェーン全再検証を要しない(チェーン更新時に導出済みの区間索引 — メンバー在籍区間・エポック開始 seq — を引く実装を想定。CRYPTO_SPEC §6.3 のエポック有効区間)。保存行の増分は値・ステートメントあたり約 350 バイト(署名 128 + ヘッドハッシュ 64 + prev ハッシュ 64 + FP 32 + seq)で、既存の行数上限(バージョン数 / 変数・変数数 / 環境)が総量を束縛する。配布応答の増分も同オーダーであり 12-7 の一括 pull を有意に肥大させない

### 12-9. 監査イベント

本章の各操作と、チェーン追記の受理(§11)は、AUDIT_SPEC §3.3 / §3.4 のイベントを project DO 内に記録する(同 §5.1 スキーマ)。監査イベントの追記 API は公開しない(AUDIT_SPEC §7)。
