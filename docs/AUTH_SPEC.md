# maruhi 認証・アイデンティティ仕様書 (AUTH_SPEC)

Version: 0.5-draft
Status: レビュー中(§11 は 2026-08-02 のセッション 06 裁定、§12 は 2026-08-02 のセッション 07 提案を反映。§12-2 の suite / §12-6 の修復経路 / §12-8 の DEK ラップ行数上限は 2026-08-02 のセッション 07 レビュー所有者裁定をセッション 08 で反映。§12-2 / §12-6 の DEK ラップ登録署名は同裁定 2-E — CRYPTO_SPEC §5.1 — をセッション 09 で反映)

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
- **操作が要求する権限水準(2026-08-02 決定)**: チェーン取得 = read。チェーン追記はエントリの op で決まる — `rotate_epoch` = write、`add_member` / `remove_member` / `change_role` / `grant_server` / `revoke_server` = admin。プロジェクト作成(genesis init)= admin。op ごとの認可(誰がその op を実行できるか)の真実源は引き続きチェーン role(CRYPTO_SPEC §6.2)であり、この表はトークンスコープ側の必要条件である。データプレーン(変数・環境・DEK)の op 別水準は §12-3 の表に規定する
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

CRYPTO_SPEC §3〜§5・§7(鍵階層・変数暗号化・DEK ラップ・エポック)のデータプレーンの API 面の規定。§11 と同じ規律に従う: 全エンドポイント認証必須、非メンバー・スコープ外への応答は一律 404(§11-2)、実効権限 = min(トークンスコープ, チェーン role)(§9-2)。本章の規則はすべて**サーバーの API 受理ポリシー**であり、チェーン有効性の合意規則(CRYPTO_SPEC §6.1)にも暗号仕様(同 §2〜§5)にも変更を加えない。

### 12-1. リソースモデルと識別子

- 環境・変数の集合・表示名は project DO 内の**平文メタデータ**(CRYPTO_SPEC §4。暗号化されるのは値のみ)
- `environment_id` / `variable_id` は**クライアント採番の安定識別子**(CRYPTO_SPEC §3 の「環境作成時に採番」の採番主体はクライアント)。AAD / HPKE info(§4 / §5)に入る値をクライアントが暗号化・ラップの前に確定できるようにするため — サーバー採番では「ID 取得 → ラップ → 登録」の 2 往復に分かれ、「環境はあるが DEK ラップが存在しない」中間状態が生まれる
- 形式(受理ポリシー): `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`。environment_id はプロジェクト内で一意、variable_id は環境内で一意
- **ID の再利用禁止**: 削除済み環境・変数の ID は再利用できない(tombstone による拒否)。epoch と version が AAD に入るため、同一 AAD 座標の暗号文が世代をまたいで二重に存在しうる状態を構造的に作らない
- 表示名(name)は改名可能な平文メタデータ。名前の一意性(環境名はプロジェクト内、変数名は環境内。削除済みは対象外)はサーバーが強制する(環境間パリティチェックは変数名で行う — CRYPTO_SPEC §4)

### 12-2. ワイヤ表現(CRYPTO_SPEC §10 の具体化)

変数値は `EncryptedPayload` としてのみ API 境界を通る:

```
EncryptedPayload = {
  suite: "maruhi/v1",
  aad: { projectId, environmentId, epoch, variableId, version },  // 申告 AAD 構成要素
  nonceHex,                    // 96-bit ランダム nonce(hex 小文字 24 文字)
  ciphertextHex                // AES-256-GCM の ct || tag(hex 小文字、タグ込み 16 バイト以上)
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
- **DEK 配布応答(RecipientDek)は署名・署名者情報を運ぶ(2026-08-02 裁定 2-E のセッション 09 反映)**: 保存されたラップの `signatureHex` に加え、`signerUserId` と `signerKeyFingerprintHex`(登録受理時のチェーン導出メンバーの鍵 FP)を返す。受信者はこれらとチェーン履歴から配布時のクライアント検証(CRYPTO_SPEC §5.1)を行える
- **suite は永続データ構造の全域に持たせる(2026-08-02 セッション 07 レビュー裁定)**: WrappedDek のワイヤに suite を持ち、サーバーの保存行(変数バージョン・DEK ラップ)も suite 列を持つ。DEK 配布応答(RecipientDek)・pull 応答(EncryptedPayload)も保存された suite を返す。CRYPTO_SPEC §2 設計原則 4「すべての永続データ構造はスイート識別子を持つ」との整合であり、暗号仕様側の変更は伴わない(HPKE info は従来どおり CRYPTO_SPEC §5)。API スキーマ上は Literal `"maruhi/v1"` にピン留めしたまま(`maruhi/v2` 導入時の suite とエポックの結合判断は v2 設計まで保留する — 先取りしない)
- **サーバーは AAD を暗号学的に検証できない**(E2EE。復号鍵を持たない)。サーバーが行うのは (1) 申告 AAD 構成要素と保存先座標(URL の project / environment / variable、期待 version、現エポック)の一致検査、(2) 構造検査(hex 形式・nonce 長・ciphertext 最小長・サイズ上限)のみ。文脈束縛の実際の強制は復号失敗(CRYPTO_SPEC §4)であり、その検証は crypto 層のテストベクターが担う

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

### 12-4. 環境管理

- **作成は原子的**: リクエストに environment_id・表示名・**エポック 1 の DEK ラップ完全集合**(現メンバー全員宛。12-6 の検証を通ること)を同梱する。「環境はあるが誰も DEK を持てない」中間状態を作らない
- 作成の受理条件: environment_id が (1) 現存せず、(2) tombstone でもなく、(3) チェーン上で `rotate_epoch` により観測済みでもない(ChainState.environmentEpochs に不在)こと。(3) により作成時点の現エポックは常に初期値 1 である(CRYPTO_SPEC §3 との整合)
- **チェーン受理は環境メタデータと突合しない**: `rotate_epoch` の environment_id が環境メタデータに存在することをチェーン追記の受理条件にしない。チェーン受理規則(CRYPTO_SPEC §6.4)を可変のサーバーローカル状態に依存させない(クライアントが検証できない受理条件を作らない・環境削除との競合を排除する)ため。メタデータに対応しない rotate_epoch はデータ層に効果を持たず、その ID を上記 (3) により「使用済み」として焼却するだけである
- 改名は表示名のみ(暗号文脈は改名の影響を受けない environment_id — CRYPTO_SPEC §3)
- 削除は admin 以上。環境行は tombstone として残し(ID 再利用禁止の判定に使う)、配下の変数・バージョン(暗号文)・ラップ済み DEK は即時削除する。監査ログには変数ごとの var.deleted と env.deleted を記録する(AUDIT_SPEC §3.3)

### 12-5. 変数とバージョニング

- version は 1 始まりの連番で AAD の一部(CRYPTO_SPEC §4)。**サーバーは version を採番できない**(採番すると申告 AAD とずれる)ため、push は CAS で受理する: 申告 version == 現在の最新 version + 1 のみ受理し、不一致は 409 で現在の最新 version を返す(クライアントは新 version で再暗号化して再試行する)
- **push が参照できるエポックは現エポックのみ**(チェーン導出 ChainState.environmentEpochs の値、未観測なら初期値 1)。旧エポックの push は 409 で現エポックを返す。ローテーション直後の競合はこの応答によりクライアントが新 DEK を取得・再暗号化して再試行する。**保存済みの過去バージョンは当時のエポックのまま保持される**(CRYPTO_SPEC §7)— 本規則は新規受理だけを現エポックに束縛する
- 変数の作成は最初の値(version 1)を同梱する(値のない変数は存在しない)
- 削除は変数 tombstone + 全バージョンの暗号文削除。監査上の存在区間は var.created / var.deleted イベントが保持する(要ローテーション検出は削除済み変数も対象 — AUDIT_SPEC §4.1)

### 12-6. DEK ラップの保存・配布(CRYPTO_SPEC §6.3 ゴーストメンバー対策のサーバー側)

- 受信者の同定は **user_id と enc 公開鍵の両方**とし、チェーン導出の現メンバーと両方が厳密一致しなければ受理しない。user_id だけでは「チェーン上の鍵と異なる鍵へのラップ」(実質ゴーストメンバー)を検出できず、公開鍵だけでは HPKE info の recipient_user_id(CRYPTO_SPEC §5)と照合できない
- **登録署名の検証(2026-08-02 セッション 07 所有者裁定 2-E。CRYPTO_SPEC §5.1)**: ラップ挿入の**全経路**(DEK 登録 API と環境作成の同梱ラップの両方。修復経路の削除後の再登録も追記経路として同一)で、各ラップの `signatureHex` を検証する。受理条件は (1) **API 呼び出し主体 = 署名者の厳密一致**(署名は呼び出し主体のチェーン導出 sig 公開鍵で検証し、署名対象の signer_user_id にも呼び出し主体の user_id を用いる — 他人が署名したラップの持ち込みは、同一公開鍵を持つ別メンバー経由でも拒否される)、(2) 署名対象(CRYPTO_SPEC §5.1 の signed_bytes。URL の project / environment 座標とワイヤの epoch・受信者・enc・ct、および署名者 user_id を束縛)との一致。検証失敗は 422(`signature-invalid`)で拒否する。この検証はチェーン外のデータに対する唯一のクライアント署名検証であり、毒ラップの帰属をサーバー不信で成立させる(監査イベントの署名者 FP — AUDIT_SPEC §3.3 — と突合できる)
- (環境, エポック) のラップ集合の**初回登録**(環境作成時のエポック 1、ローテーション後の新エポックの一括登録)は、現メンバー集合との**完全一致**を要求する: 欠落・非メンバー宛・鍵不一致・重複はすべて 422 で拒否する
- 以後は**不足分の追記のみ**許可する(add_member 後に招待者が新メンバー宛へ全エポックの DEK をラップして登録する経路 — CRYPTO_SPEC §7)。**既存 (環境, エポック, 受信者) の上書きは禁止**(409)。ラップの中身はサーバーに検証不能であり、上書きを許すと有効なラップを復号不能なブロブで置換する可用性攻撃が成立するため
- 登録できるエポックは 1〜現エポック(未来のエポック宛は拒否)
- **修復経路: ラップ削除 → 不足分再登録(2026-08-02 セッション 07 レビュー所有者裁定)**: 上書き禁止を維持したまま、復号不能な毒ラップ(登録者のバグ・不正)の唯一の修復手段として、**(環境, エポック, 受信者) 単位の明示的なラップ削除**を提供する。削除後は上記の「不足分の追記」経路で正しいラップを再登録する(あるエポックの全ラップが削除された場合、その再登録は初回登録として完全一致を要求される)。**再登録にも登録署名が必須**(追記経路は登録署名の検証を常に伴う — 再登録者が自らラップし自ら署名する)。必要権限は**環境削除と同水準(トークンスコープ admin × チェーン role admin 以上 — §12-3)**: 削除は他メンバーの復号可能性を奪う操作であり、member 水準に置くと上書き禁止が防いだ可用性攻撃が削除経由で復活するため。存在しないタプルの削除は 404 で拒否し、**削除対象の列挙は 1 件以上**とする(空列挙は Schema 検証の 400。監査痕跡を一切残さない破壊系 API の呼び出し形を許さない — 404 と同じ「黙って成功させない」規律)。削除は監査イベント(`dek.deleted` — AUDIT_SPEC §3.3)として受信者ごとに記録する
- 配布は本人宛のみ: 認証主体は自分が受信者であるラップだけを取得できる(reader を含む全メンバー — CRYPTO_SPEC §6.2)
- grant_server 済みプロジェクトのサーバー鍵宛ラップは Phase 2(CRYPTO_SPEC §9 の MVP 線引き)で本章を改訂して扱う

### 12-7. 一括 pull(CLI `maruhi run` / Web の取得経路)

- 環境単位の 1 リクエストで、全アクティブ変数の最新バージョン(EncryptedPayload。申告 AAD 込みで自己記述的)+ 現エポック + **呼び出し主体宛の全エポックのラップ済み DEK** を返す
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
- **DEK ラップ行数 / プロジェクト(2026-08-02 セッション 07 レビュー所有者裁定)**: dek_wraps はエポックごとに全メンバー分の行が積み上がり、リクエスト単位の上限だけでは反復リクエストによる累積が有界にならないため、プロジェクト累積の行数上限を置く。値は現実的利用(メンバー数 × 環境数 × エポック数。数百〜数千行)の 3 桁上。「現在保存中の行数」であり環境削除・ラップ削除(§12-6)で解放される。検査は**ラップ挿入の全経路(DEK 登録・環境作成)**で行う
- **Phase 2 予告(DO ストレージ総量ガード)**: 上記の個別上限に加え、DO ストレージ実測量(`databaseSize`)の閾値超過を型付きエラーで拒否する運用ガードを Phase 2 で導入する。監査ログ(audit_events)の無期限保持(AUDIT_SPEC §5.3)を覆う唯一の防衛線となるため、監査ログの集約方針(同 §3.3)の実測判断と同時に設計する
- DEK ラップ数 / リクエストの上限は、チェーン受理ポリシー(10,000 エントリ)が束縛するメンバー数上限以上に取る(初回登録の完全一致要件 12-6 と両立し、登録不能なプロジェクトが生じない)。**登録署名(§12-6)の検証コストもこの上限が束縛する**: 最悪 10,000 件 × Ed25519 検証は、チェーン追記受理時の全チェーン再検証(CRYPTO_SPEC §6.4。最大 10,000 エントリ × Ed25519 検証)と同じオーダーであり、既に受理済みの資源消費水準を超えない(引き下げは完全一致要件との両立を壊すため行わない)。受信者 user_id の受理上限はチェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1 の 1024 バイト)に揃える — これより狭くするとチェーン上の正当なメンバー宛ラップが登録不能になる。理論極値(上限長の user_id × 上限数のラップ)では HTTP 生ボディ上限(実装詳細)が先に束縛しうるが、内部 user_id は ULID(26 文字)であり実運用では到達しない
- 超過は型付きエラー(413 / 422)で拒否する。ただし**表示名の長さ超過のみ Schema 検証の 400** で拒否される(値と違い専用の検証層を持たないため。表の値 256 文字は同じ)。セルフホストでの引き上げは合意規則を破らない

### 12-9. 監査イベント

本章の各操作と、チェーン追記の受理(§11)は、AUDIT_SPEC §3.3 / §3.4 のイベントを project DO 内に記録する(同 §5.1 スキーマ)。監査イベントの追記 API は公開しない(AUDIT_SPEC §7)。
