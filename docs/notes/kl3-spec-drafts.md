# KL3 仕様改訂ドラフト — master 鍵ラップ台帳(2026-09-12 起草・所有者承認待ち)

**位置づけ**: KL3 フェーズ 1(設計セッション)の成果物。設計の全体像・裁定の反復記録・実装分割は docs/notes/integration-options.md §3 補足 19。本ファイルは正本 3 文書(CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC)へ反映した**改訂本文の起草時の写し**である。**2026-09-12 に所有者が設計の 13 項目を承認し、同日 K1 として正本へ反映済み**(CRYPTO_SPEC 0.9-draft §8 / §11 / §13 / §14.3、AUTH_SPEC 0.21-draft §5 / §13、AUDIT_SPEC 1.6-draft §3.1)。以後の正は各正本であり、本ファイルは経緯の記録として残す(差異が生じた場合は正本が勝つ)。

各ドラフトは「差し替え」または「追記」で示す。既存本文のうち変えない部分は引用しない。

---

## A. CRYPTO_SPEC の改訂案

### A-1. §8 の差し替え(見出しごと)

> ## 8. master 鍵ラップ台帳(リカバリーコード・パスキー PRF・保護者・ハンドオフ)
>
> **2026-09-12 改訂(KL3)**: 旧 §8「リカバリーコード」を、同一の master 鍵ブロブに対する**受信者ごとのラップの集合(台帳)**として一般化する。リカバリーコード経路の構造・バイト列・テストベクター(`recovery-wrap.json`)は**不変**であり、本改訂は経路を足すだけである(既存ブロブの再ラップ・移行は無い)。設計録は docs/notes/integration-options.md 補足 19。
>
> ### 8.1 共通規定
>
> - **ラップ対象 B**: user master 秘密鍵(enc / sig)の不透明ブロブ。直列化形式はクライアント(CLI)の契約であり、サーバーは関知しない(現行 = キーチェーンレコードの JSON。復元側は自己検証を通してから保存する)
> - **受信者クラス**: (S) 対称 KEK — `recovery-code` / `passkey-prf`。(G) 保護者グループ — `guardian`。(H) ハンドオフ — 一時受信者(台帳に永続行を持たない。§9.1 リースラップと同じ応答スコープ)
> - **ラップ**(クラス S / G / H の端末移行に共通): AES-256-GCM、96-bit ランダム nonce(暗号文と併置)。AAD は §2.1 のエンコーディングで
>
>   ```
>   master_wrap_aad = LP("maruhi/v1/master-wrap", user_id, kind, wrap_ref, mode)
>   ```
>
>   `kind` ∈ {`passkey-prf`, `guardian`, `device`}。`wrap_ref` = passkey-prf: `wrap_id` / guardian: `group_id` / device: `request_id`(8.4)。`mode` = guardian のみ `any` | `all`、それ以外は空文字列。**例外: `recovery-code` は旧 §8 の AAD `LP("maruhi/v1/recovery-wrap", user_id)` のまま**(バイト互換の維持。新経路には用いない)
> - すべてのラップ・分片はサーバーから見て不透明であり、KEK の素材(リカバリーコード・PRF 出力・分片の平文・一時秘密鍵)はいかなる API ペイロードにも含まれない。他ユーザー・他文脈への移植は AAD / info の束縛により復号失敗となる(設計原則 3)
> - **取得の前提**: いずれのクラスも、ラップ・分片の取得は認証済みの本人(またはハンドオフの承認者)に限る(認証 + 鍵素材の二重防御 — 旧 §8 と同じ)。取得エンドポイントはレート制限を持つ(AUTH_SPEC §13-8)
>
> ### 8.2 対称 KEK 受信者(クラス S)
>
> - **recovery-code**(旧 §8 のまま): サインアップ時に生成する 256-bit ランダム値。表示は Base32 グループ化。`KEK = HKDF-SHA256(recovery_secret, salt = 空, info = "maruhi/v1/recovery")`。salt 空の根拠(RFC 5869 §3.1 — IKM が一様ランダム)・ストレッチング不要・Argon2id 条項(パスフレーズ由来鍵を導入する場合は Argon2id 必須 = 本仕様の改訂を要する)・再発行 = 新コード → 再ラップ → 旧ラップ削除、はすべて不変。**パスフレーズ由来 KEK は KL3 でも導入しない**(補足 12 L4-a)
> - **passkey-prf**(新設): WebAuthn PRF 拡張(CTAP2 hmac-secret)の出力 `prf_out`(32 バイト。認証器の HMAC-SHA-256 出力で一様ランダム)を IKM とする:
>
>   ```
>   prf_out = PRF(credential, eval.first = prf_salt)
>   KEK     = HKDF-SHA256(prf_out, salt = 空(長さ 0), info = "maruhi/v1/passkey-prf")
>   ```
>
>   - `prf_salt` は**登録ごとに生成する 32 バイトの乱数**で、公開パラメータとして台帳行に併置する(credential_id・rpId と同じ扱い)。固定文字列にしない理由: 固定だと KEK が credential の固定関数になり、一度漏れた KEK が再登録後のラップも開く。乱数なら再登録 = 新 KEK となり、recovery-code の「再発行 → 旧ラップ削除」と同じ意味論が成立する
>   - salt 空の根拠は recovery-code と同じ(prf_out は一様ランダム 256-bit)。用途分離は info が担う。ストレッチング不要
>   - PRF は**ブラウザでしか取得できない**。取得は CLI が配布する localhost ページ(`127.0.0.1`、rpId = `localhost`)で行い、PRF 出力はループバックの 1 POST で CLI プロセスへ渡す(ADR-0018: hosted Web は鍵・ラップのコードパスを持たない)。運営配信の Web で PRF を取得してはならない。ページと CLI 間の認証(ワンタイムトークン + Origin 検査)は ADR-0018 決定 2 の要件に従う
>   - 1 ユーザーが複数の passkey-prf ラップ(複数の認証器)を持ってよい。各行は独立(wrap_id で識別)
>
> ### 8.3 保護者グループ(クラス G)
>
> ward(本人)が指名した保護者の公開鍵へ B を包む。「鍵とリカバリーコードを両方失っても、保護者 + 本人のアカウント認証で復元できる」経路。
>
> - **グループ**: `group_id`(乱数 ULID)、`mode` ∈ {`any`(1-of-n: 誰か 1 人で足りる), `all`(n-of-n: 全員が要る)}、グループ KEK = 256-bit 乱数。B は 8.1 の AES-GCM で `kind = "guardian"`, `wrap_ref = group_id`, `mode` を AAD に束縛してラップする
> - **分片**(share_index = 1..n):
>   - `mode = any`: すべての `s_i = KEK`
>   - `mode = all`(n ≥ 2): `s_1 … s_{n-1}` を独立な 32 バイト乱数とし、`s_n = KEK ⊕ s_1 ⊕ … ⊕ s_{n-1}`。復元は全片の XOR。任意の n−1 片は KEK と独立(情報理論的 n-of-n 秘密分散の標準形)。**k-of-n(Shamir 等)は導入しない**(新プリミティブ)。HPKE の入れ子(A で包んだものを B で包む)は逐次依存で承認が並列にできないため採らない
> - **分片の封印**: HPKE Base mode 単発 Seal(§5 と同一プリミティブ)。受信者 = 保護者の master enc 公開鍵(DEK ラップを受ける鍵と同じ)。平文 = `s_i`(32 バイト)。aad は空、info は
>
>   ```
>   guardian_wrap_info = LP("maruhi/v1/guardian-wrap", user_id, group_id, mode, share_index, guardian_user_id)
>   ```
>
>   ドメイン文字列により §5 `dek-wrap` / §9.1 `lease-wrap` / 8.4 `handoff-wrap` と相互に移植できない。`mode` を AAD と info の両方に含めるのは、サーバーによる `any` ↔ `all` の付け替え(要求者に n 片の XOR を求める / 1 片で足りると誤らせる)を復号失敗に落とすため
> - **保護者の鍵の真正性**: 保護者は ward と共有プロジェクトを持つ**チェーン導出の現メンバー**から選び、その enc 公開鍵はチェーン(add_member / genesis の payload)から取る。鍵の確認は §6.5「明示確認の充足形」(読み上げ儀式 / フラグ / 検証済み指紋帳のヒット + yes)に従う。グローバル公開鍵ディレクトリは作らない(§6.5)。台帳は保護者の鍵 FP を併置し、クライアントは保護者の現鍵(チェーン導出)と突合して不一致(保護者の鍵更新)を警告する — `all` では 1 人の不一致でグループが復元不能になる
> - **保護者の同意手続きは v1 で持たない**: 指名は ward の単独操作。復元には保護者の能動的な承認(8.4)が要るため、同意なき指名で保護者に生じる面は「自分の台帳に ward が表示される」だけである。同意の署名(招待型の握手)は将来の改訂候補
> - グループの削除 = ward の単独操作(行の削除。旧分片は消える)。保護者の入れ替えは削除 → 再作成
>
> ### 8.4 ハンドオフ(クラス H — 端末移行と保護者承認の共通機構)
>
> 「B(または分片)を要求者の一時公開鍵へ再封印して渡す」応答スコープの機構。**端末移行**(旧端末が承認)と**保護者リカバリー**(保護者が承認)は同じ要求・同じ承認 payload を使い、要求者の手順は承認者の種別に依らない。
>
> - **一時鍵 E**: 要求者(新端末)がメモリ内で生成する X25519 keypair。永続化しない。要求者プロセスの終了とともに消える
> - **request_id**: `lower_hex(SHA-256(LP("maruhi/v1/handoff-id", E_pub_hex)))`。要求者・承認者が独立に同じ値を計算できる
> - **ハンドオフコード(クライアント仕様)**: `E_pub(32 バイト) ‖ SHA-256(E_pub) の先頭 4 バイト` を Base32(RFC 4648 アルファベット・パディング無し)で符号化した文字列(グループ化表示。表示形はテストベクターで固定)。**コードは人が運ぶ**(同一人物の端末間はコピー&ペースト、保護者へは帯域外)。**サーバーは E.pub を中継せず保存もしない**: 承認者は運ばれたコードから E.pub と request_id を得る。これにより、サーバーによる受信鍵のすり替えが構造的に成立せず、12 語型の照合儀式を要しない(§3 の「短縮コードへの切り詰めは行わない」— 一方の鍵を攻撃者が選べる状況 — が発生しない)。コードは公開情報(公開鍵)であり、鍵素材ではない
> - **承認**: 承認者は 32 バイト値 `v` を E.pub へ HPKE Base mode 単発 Seal する(aad 空、info は下記)。**同一の request_id に対する承認は、承認者・source ごとに 1 つ**
>
>   ```
>   handoff_wrap_info = LP("maruhi/v1/handoff-wrap", user_id, request_id, source, share_index, approver_user_id)
>   ```
>
>   - **保護者の承認**: `v = s_i`(台帳から自分宛の分片を取得 → 自分の master enc 鍵で Open → **その場で** E.pub へ Seal。分片・B を保存しない)。`source = group_id`、`share_index` = 自分の分片番号、`approver_user_id` = 保護者の user_id
>   - **旧端末の承認(端末移行)**: 承認者 = ward 本人(B を保持する端末)。`KEK_h` を 256-bit 乱数として生成し、`v = KEK_h`、`source = "device"`、`share_index = 0`、`approver_user_id = user_id`。同時に B を 8.1 の AES-GCM で `kind = "device"`, `wrap_ref = request_id`, `mode = ""` として `KEK_h` でラップし、承認に同送する
> - **要求者の組み立て**: 届いた承認を `source` で分ける。`device` があれば `KEK = v`、同送されたラップを開く。`group_id` なら当該グループの `mode` に従い(any: 任意の 1 片、all: 全 n 片の XOR)KEK を得て、台帳から取得したグループのラップを開く。得た B は自己検証(鍵の整合)を通してからキーチェーン(または agent メモリ)へ保存する
> - **承認前の本人確認(規範)**: 保護者は承認前に、要求者が ward 本人であることを**帯域外**(通話等)で確かめる。サーバーは承認者へ要求の ward(user_id と表示用スナップショット)を示すが、それは表示であって証明ではない(サーバーが偽った ward を示しても、info の user_id 束縛により正規の要求者以外は開けず、fail-closed)。承認・PRF 取得・復元は儀式であり、AI エージェント環境・非対話端末では拒否する(ADR-0016 決定 7 の既存ゲート)
> - **有効期間**: 要求は起草値 15 分で失効し、承認は要求とともにサーバーから消える(応答スコープ — 永続台帳に入らない)。要求者は成功後に要求を削除してよい
>
> ### 8.5 禁止事項(本節の範囲)
>
> - KEK・分片・一時秘密鍵・B の平文をディスク・ログ・エラーメッセージに出さない
> - パスフレーズ由来の KEK(Argon2id 条項 — 8.2)
> - k-of-n 閾値分散、独自の鍵合意・確認プロトコル(SAS 短縮を含む)
> - ハンドオフの E.pub をサーバー経由で承認者へ配布する実装(コードは人が運ぶ)

### A-2. §11 テストベクターへの追記

> - 0.9-draft(KL3)で追加されるベクター(**所有者承認後の実装 PR〔K2〕で、実装より先にコミットする**): `master-key-wrap.json`(新規 — §8)。正例 = `passkey-prf-basic`(prf_out → KEK → AES-GCM・AAD バイト列)/ `guardian-any-2` / `guardian-all-3`(XOR 分片・固定一時鍵での HPKE Seal・info バイト列)/ `handoff-guardian-share` / `handoff-device`(KEK_h + device 形 AAD)/ `handoff-id` / `handoff-code`(表示形の符号化・復号)。負例 = AAD の kind / wrap_ref / mode 差し替え(`any` ↔ `all` の付け替え)・user_id 移植・guardian-wrap の share_index / guardian_user_id / group_id 移植・handoff-wrap の request_id / approver / source 移植・分片欠落(n−1 片の XOR)・チェックサム不一致のハンドオフコード・prf_salt 差し替え・suite 不一致。**`recovery-wrap.json` は不変**(バイト互換 — README 規約 25 として明記)

### A-3. §13 未決事項への注記

> 2. デバイス鍵分離・パスキー PRF(WebAuthn PRF 拡張)対応(Phase 2 以降)**— 2026-09-12 追記: パスキー PRF は KL3 で「封印バックアップの KEK 素材」として §8.2 に導入した。デバイス鍵分離(端末単位の失効)は本項のまま未決**

### A-4. §14.3 明示的な非保証への追記

> 8. **保護者リカバリーとハンドオフの共謀(2026-09-12 — §8.3 / §8.4)**: `mode = any` の保護者 1 人(`all` なら全員)と、ward のアカウント認証を得た者が共謀すれば、ward の master 鍵を復元できる。保護者は「その相手」として ward が信頼する人物であり、暗号はこれを防がない(保護者を指名しないことも選べる)。ward のアカウント奪取者が保護者へなりすまして承認を得る攻撃は、保護者の帯域外の本人確認だけが防ぐ(サーバーは証明できない)。ハンドオフコードを運ぶ経路が能動的に改竄された場合、承認は攻撃者の一時鍵へ向くが、承認・ラップの取得には ward のアカウント認証が要る(コード改竄 + アカウント奪取の複合が条件)

---

## B. AUTH_SPEC の改訂案

### B-1. §13 見出しと前文の差し替え

> ## 13. master 鍵ラップ台帳 API との接続(2026-08-09 セッション 18 起草。2026-09-12 KL3 改訂 — §13-6 以降を追加)
>
> CRYPTO_SPEC §8(master 鍵ラップ台帳)のサーバー保存・配布面の規定。台帳のすべてのラップ・分片は**サーバーから見て不透明な暗号文**であり、KEK の素材(リカバリーコード・PRF 出力・分片の平文・一時秘密鍵)はいかなる API ペイロードにも含まれない。移植は AAD / info の束縛により復号失敗となる(サーバー側の追加検査を要しない)。**§13-1〜13-5 はリカバリーコード経路(不変)、§13-6 以降が KL3 で追加された経路**。

(§13-1〜13-5 は現行のまま。§13-3 のレート制限は下記 13-8 の合算窓へ読み替える — 対象と上限値は不変)

### B-2. §13-6 台帳のリソースモデル(追記)

> ### 13-6. 台帳のリソースモデル(2026-09-12)
>
> ```sql
> master_key_wraps (                      -- クラス S(passkey-prf)。recovery-code は recovery_wraps のまま
>   id              TEXT PRIMARY KEY,     -- wrap_id(ULID)
>   user_id         TEXT NOT NULL REFERENCES users(id),
>   kind            TEXT NOT NULL,        -- 'passkey-prf'
>   suite           TEXT NOT NULL,
>   params          TEXT NOT NULL,        -- JSON(公開パラメータ: credentialIdHex, prfSaltHex, rpId, label?)。サーバーは解釈しない
>   nonce_hex, ciphertext_hex,            -- AES-256-GCM(AAD = master-wrap 形)
>   created_at, updated_at
> )
> guardian_groups (
>   id              TEXT PRIMARY KEY,     -- group_id(ULID)
>   user_id         TEXT NOT NULL,        -- ward
>   mode            TEXT NOT NULL,        -- 'any' | 'all'
>   suite, nonce_hex, ciphertext_hex,     -- グループ KEK による B のラップ
>   created_at
> )
> guardian_shares (
>   group_id        TEXT NOT NULL REFERENCES guardian_groups(id) ON DELETE CASCADE,
>   share_index     INTEGER NOT NULL,     -- 1..n
>   guardian_user_id TEXT NOT NULL REFERENCES users(id),
>   guardian_enc_pub_hex TEXT NOT NULL,   -- 封印先(ward クライアントが確認済みの鍵)
>   guardian_key_fingerprint_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE(guardian-wrap 形)。ciphertext は 48 バイト
>   PRIMARY KEY (group_id, share_index),
>   UNIQUE (group_id, guardian_user_id)
> )
> key_handoff_requests (
>   id              TEXT PRIMARY KEY,     -- request_id(CRYPTO_SPEC §8.4 — E.pub からの導出値。E.pub 自体は保存しない)
>   user_id         TEXT NOT NULL,        -- ward(要求者)
>   created_at, expires_at                -- 発行 + 15 分
> )
> key_handoff_approvals (
>   request_id      TEXT NOT NULL REFERENCES key_handoff_requests(id) ON DELETE CASCADE,
>   source          TEXT NOT NULL,        -- 'device' | group_id
>   share_index     INTEGER NOT NULL,     -- device = 0
>   approver_user_id TEXT NOT NULL,
>   approver_key_fingerprint_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE(handoff-wrap 形)
>   blob_suite, blob_nonce_hex, blob_ciphertext_hex,  -- source = 'device' のみ(KEK_h による B のラップ)
>   created_at,
>   PRIMARY KEY (request_id, source, share_index)
> )
> key_blob_fetch_counters (               -- 13-8 の合算窓(監査行ではない可変状態 — AUDIT_SPEC §3.1 のカウンタ行と同じ性格)
>   user_id TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
> )
> ```
>
> - すべて D1(user 単位。プロジェクト・org・チェーンと無関係)。認可にトークンスコープ表・チェーン role は関与しない(§13-1 と同じ)
> - `recovery_wraps` の `fetch_window_start / fetch_count` は合算窓のカウンタ行へ読み替える(移行はサーバー実装〔K3〕の裁量。上限値は不変)
> - 承認は要求の失効・削除とともに消える(応答スコープ。永続台帳に入らない — CRYPTO_SPEC §8.4)。失効行の掃除は日和見削除(§4 のフロー行と同じ)

### B-3. §13-7 エンドポイントと認可(追記)

> ### 13-7. エンドポイントと認可(2026-09-12)
>
> | op | エンドポイント | 認可 |
> |---|---|---|
> | 台帳の状態 | `GET /auth/key-wraps`(200) | 認証済み主体すべて(**セッション主体も可** — §5 の許可列挙へ追加。`recovery/status` と同じ性格)。ラップ・分片・パラメータの秘密を運ばない: 種別ごとの登録有無・wrap_id / group_id・mode・保護者の user_id と鍵 FP・更新時刻のみ |
> | passkey 登録 | `POST /auth/key-wraps/passkey`(201 → `{ wrapId }`) | `*` × admin スコープのトークンのみ(§13-2 の鍵素材条件と同じ。**セッション主体は拒否**) |
> | passkey ブロブ取得 | `GET /auth/key-wraps/passkey/:wrapId`(200 / 404) | 同上 + 合算レート制限(13-8) |
> | passkey 削除 | `DELETE /auth/key-wraps/passkey/:wrapId`(204) | 同上 |
> | 保護者グループ作成 | `POST /auth/key-wraps/guardians`(201 → `{ groupId }`) | 同上。payload = mode + ラップ + 分片 n 個(13-9)。分片の `guardian_user_id` は実在ユーザーであること。**鍵の正しさ(チェーン導出鍵との一致)はサーバーが検証しない** — 真実源は ward クライアントの確認(CRYPTO_SPEC §8.3)であり、二重の真実源を作らない |
> | 保護者グループ削除 | `DELETE /auth/key-wraps/guardians/:groupId`(204) | 同上(ward のみ) |
> | グループのブロブ取得 | `GET /auth/key-wraps/guardians/:groupId`(200 / 404) | 同上(ward のみ)+ 合算レート制限 |
> | 自分が保護者である ward の一覧 | `GET /auth/guardian/wards`(200) | `*` × admin トークン。応答 = `[{ wardUserId, wardLogin, groupId, mode, shareIndex, createdAtMs }]`。`wardLogin` は `linked_identities.provider_login` の表示用スナップショット(識別子として使わない — §2) |
> | 自分宛の分片取得 | `GET /auth/guardian/shares/:groupId`(200 / 404) | 同上(当該グループの分片保持者のみ)+ 承認窓で計数(13-8)。要監視イベント |
> | ハンドオフ要求 | `POST /auth/handoff`(201 → `{ expiresAtMs }`。body: `{ requestId }`) | `*` × admin トークン(ward)。要求は 5 回 / 時 / user。既存 id との衝突は 409 |
> | 要求の照会(承認者) | `GET /auth/handoff/:requestId`(200) | `*` × admin トークン。呼び出し主体が ward 本人、または ward のいずれかのグループの分片保持者であること。**それ以外・不明・失効は一律 404**(§11-2 と同じ存在秘匿)。応答 = `{ wardUserId, wardLogin, expiresAtMs, roles: [ "device" \| { groupId, mode, shareIndex } ] }`(呼び出し主体が取れる承認の形) |
> | 承認 | `POST /auth/handoff/:requestId/approvals`(201) | `*` × admin トークン。`source = "device"` は ward 本人のみ、`source = group_id` は当該グループで `share_index` の分片保持者のみ(照合は保存行から — ワイヤ申告値で認可しない)。同一 (request, source, share_index) の二重承認は 409。承認は 20 回 / 時 / 承認者 |
> | 承認の取得(要求者) | `GET /auth/handoff/:requestId/approvals`(200) | `*` × admin トークン(ward のみ)。応答 = 承認の列挙(13-9)。1 件以上を返した応答は `auth.key_handoff_collected` を記録する |
> | 要求の取消 | `DELETE /auth/handoff/:requestId`(204) | ward のみ |
>
> - 未認証は常に 401。404 が返るのは認証済みかつ権限のある主体に対してのみ
> - **セッション主体の能力制限(§5)への追加**: 許可列挙に `GET /auth/key-wraps` のみを追加する。登録・削除・取得・承認はすべて端末限定(ADR-0018 改訂 2: 資格の生成と鍵素材は端末)
> - hosted Web(`apps/web`)は KL3 では台帳に触れない(状態表示は後続の W 系列。削除も v1 では端末限定 — 鍵素材の可用性に関わる操作をセッション XSS の射程に置かない)

### B-4. §13-8 レート制限・有効期間・受理ポリシー(追記)

> ### 13-8. レート制限・有効期間・受理ポリシー(2026-09-12)
>
> - **ブロブ取得の合算窓**: `GET /auth/recovery`・`GET /auth/key-wraps/passkey/:id`・`GET /auth/key-wraps/guardians/:id`(いずれも B のラップ本体を返す)は **user 単位の 1 つの固定窓で合算して 1 時間 5 回**(§13-3 の上限値を種別合算に読み替える)。超過は 429 + retryAfterSeconds。計数は専用カウンタ行の 1 文条件付き UPSERT(AUDIT_SPEC §3.1 のカウンタ行と同形)。未登録 404 は計数しない
> - **承認窓**: `GET /auth/guardian/shares/:groupId` と `POST /auth/handoff/:id/approvals` は承認者 user 単位の固定窓で合算して **1 時間 20 回**
> - **要求窓**: `POST /auth/handoff` は ward user 単位 **1 時間 5 回**
> - **要求の有効期間**: 15 分。失効した要求への照会・承認・取得は 404。承認は要求とともに消える
> - 受理ポリシー(合意規則ではない — セルフホストでの引き上げ可): passkey-prf ラップ ≤ 5 / user、保護者グループ ≤ 5 / user、分片 1..5 / グループ(`all` は ≥ 2)、`params` ≤ 4 KiB、ラップ暗号文はタグ込み 16 バイト以上 16 KiB 以下(§13-4 と同じ)、分片暗号文 = 48 バイト・enc = 32 バイト(固定長)、承認 ≤ (グループ数 + 1) × 5 / 要求
> - 各 mutation は strict 受理(§12-10 (1))

### B-5. §13-9 ワイヤ表現(追記)

> ### 13-9. ワイヤ表現(2026-09-12)
>
> ```
> MasterKeyWrap = { suite: "maruhi/v1", nonceHex, ciphertextHex }          // RecoveryWrap(§13-4)と同形
> PasskeyWrapRegistration = { wrap: MasterKeyWrap, credentialIdHex, prfSaltHex /* 64 */, rpId: "localhost", label? }
> PasskeyWrapResult       = PasskeyWrapRegistration + { wrapId, updatedAtMs }
> GuardianShare = { shareIndex, guardianUserId, guardianEncPubHex, guardianKeyFingerprintHex, encHex, ciphertextHex }
> GuardianGroupRegistration = { mode: "any" | "all", wrap: MasterKeyWrap, shares: GuardianShare[] }
> GuardianGroupResult       = { groupId, mode, wrap: MasterKeyWrap, createdAtMs }
> HandoffApproval = { source: "device" | groupId, shareIndex, encHex, ciphertextHex, blob?: MasterKeyWrap /* device のみ必須 */ }
> HandoffApprovalResult = HandoffApproval + { approverUserId, approverKeyFingerprintHex, createdAtMs }
> ```
>
> - 配布は保存値をそのまま返す(サーバーは解釈しない)。B の直列化形式・ハンドオフコードの表示形はクライアント(CLI)の契約
> - `label` は passkey の識別用の短い表示文字列(制御文字・bidi 禁止 — §6 のトークン名と同じ受理規律)

### B-6. §13-10 監査イベント(追記)

> ### 13-10. 監査イベント(2026-09-12)
>
> AUDIT_SPEC §3.1 の追加事件(D1 側。レコード操作と同一 batch)。既存の `auth.recovery_blob_fetched` / `auth.recovery_code_reissued` は recovery-code 経路のまま名前を変えない。429 / 404 の拒否は記録しない(配布・受理していないものを記録しない — §13-5 と同じ線引き)。

---

## C. AUDIT_SPEC の改訂案(§3.1 認証系への追記)

> | イベント | 主な属性 | 備考 |
> |---|---|---|
> | `auth.key_wrap_registered` | kind(`passkey-prf` / `guardian`)、wrapId / groupId、mode、recipientCount | 台帳への登録(AUTH_SPEC §13-7)。actor = ward |
> | `auth.key_wrap_removed` | kind、wrapId / groupId | 台帳からの削除。actor = ward |
> | `auth.key_wrap_fetched` | kind、wrapId / groupId | passkey / 保護者グループのラップ本体の取得(**要監視** — `auth.recovery_blob_fetched` と同格)。actor = ward |
> | `auth.guardian_designated` / `auth.guardian_released` | groupId、mode、shareIndex | 保護者の指名・解除。actor = ward、**target = 保護者**(保護者の本人軸にも現れる)。分片 1 つにつき 1 行 |
> | `auth.guardian_share_fetched` | groupId、shareIndex | 保護者が自分宛の分片を取得した(**要監視**)。actor = 保護者(user_id + 鍵 FP)、target = ward |
> | `auth.key_handoff_requested` | requestId | ハンドオフ要求の作成。actor = ward |
> | `auth.key_handoff_approved` | requestId、source(`device` / groupId)、shareIndex | 承認の受理(**要監視**)。actor = 承認者(user_id + 鍵 FP)、target = ward |
> | `auth.key_handoff_collected` | requestId、approvalCount | 要求者が 1 件以上の承認を取得した = 復元が起きた事実。actor = ward |
>
> - **可視性**: ユーザー系(§6)どおり本人軸 — actor または target が本人の行を本人が読める。保護者は自分が指名・承認した事実を、ward は誰に指名し誰が承認したかを、それぞれ自分の監査で追える
> - **アイデンティティ規則(§1-2)は不変**: 保護者・ward・承認者はすべて内部 user_id + 鍵 FP。`wardLogin` 等の表示用スナップショットは API 応答のみで監査行には書かない
> - 要ローテーション検出(§4)には関与しない(プロジェクトの外の事象)
> - 版: 1.6-draft(KL3)。本改訂を含む実装 PR のマージをもって所有者承認とする
