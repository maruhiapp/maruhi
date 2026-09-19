# DK 仕様改訂ドラフト — デバイス鍵分離(端末単位の失効)(2026-09-19 起草・所有者承認待ち)

**位置づけ**: DK フェーズ 1(設計セッション)の成果物。設計の全体像・裁定の反復記録・実装分割・承認依頼項目は docs/notes/dk-design.md。本ファイルは正本 3 文書(CRYPTO_SPEC / AUTH_SPEC / AUDIT_SPEC)への**改訂案の起草**であり、正本自体は触っていない。所有者が設計録 §4 の承認項目に答えた後、K1 で正本へ反映する(反映後は経緯の記録として残す — 差異が生じた場合は正本が勝つ)。

各ドラフトは「差し替え」または「追記」で示す。既存本文のうち変えない部分は引用しない。版番号は CRYPTO_SPEC 0.11 → **0.12-draft**、AUTH_SPEC 0.23 → **0.24-draft**、AUDIT_SPEC 1.8 → **1.9-draft**。各 Status 行への追記文は末尾 D に置く。裁定番号(DK-A〜)は設計録 §2 を指す。

用語(本ドラフト共通): **端末鍵(device key)** = 端末ごとの enc(X25519)+ sig(Ed25519)の鍵対。鍵フィンガープリント(§3)で識別する。**予備鍵(reserve key)** = 秘密鍵が §8 の台帳にだけ住む端末鍵(チェーン上では他の端末鍵と区別しない)。**端末の上限(cap)** = `add_device` payload の (role_cap, scope_kind, scope_environments)。**端末の実効権限** = (min(人の role, role_cap), 人の scope ∩ 端末の scope)。`add_member` / `genesis` が載せる最初の鍵の cap は構造的に (owner, all)(= 人の権限そのもの)。

---

## A. CRYPTO_SPEC の改訂案

### A-1. §3 の差し替え(鍵階層の図と最終 2 項目 — DK-A)

> ```
> User(チェーンのメンバー — user_id・role・scope)
> ├─ 端末鍵 d1 … dn(端末ごと。各 enc: X25519 + sig: Ed25519)
> │     cap = (role_cap, scope) — 端末の実効権限 = (min(role, role_cap), scope ∩ scope_d)
> └─ 予備鍵 r(端末鍵と同じ形。秘密鍵は §8 の台帳にだけ住む)
>         │
>         └─ ラップ対象: Environment Epoch DEK(プロジェクト × 環境 × エポックごと)— 受信者は (user, 端末鍵)
>                 └─ 暗号化対象: 変数値、および将来の秘匿メタデータ
> ```
>
> - **端末鍵(2026-09-19 DK — 旧「User master keypair」)**: 端末ごとにクライアントで生成する。秘密鍵はサーバーに送信せず、その端末のセキュアストレージ(CLI: OS キーチェーン、または `maruhi agent` のメモリ)にだけ置く。**端末鍵を他の端末へ複製しない**。チェーン上のメンバー(user_id)は端末鍵の**集合**を持ち、`add_member` / `genesis` が最初の 1 つを、`add_device` / `revoke_device`(§6.2)がその後の増減を載せる。署名者の同定は従来どおり (user_id, 鍵フィンガープリント) であり、フィンガープリントが端末を指す
> - **予備鍵(2026-09-19 DK)**: 端末鍵と同じ形の鍵対のうち、秘密鍵を**日常の端末に置かず §8 の台帳にだけ置く**もの。チェーン上では `add_device`(cap = (owner, all))で登録された普通の端末鍵であり、DEK ラップを受け取る(全端末を失った後の復元で、他の端末が無くてもバックフィルできるため)。復元(§8)後は新しい端末鍵を `add_device` してから、予備鍵の秘密を端末から消す
> - **鍵フィンガープリント**: `SHA-256(enc公開鍵 || sig公開鍵)` の先頭 16 バイト。ログ・UI での鍵識別に使う — **不変**。DK 以後、フィンガープリントは端末を識別する
> - ~~v1 の簡略化: デバイスごとの鍵は持たず、master keypair を各デバイスに配置する。デバイス追加はリカバリーコードの入力による(§8)。デバイス鍵分離とパスキー PRF は将来課題(**未決事項 #2**)~~ **2026-09-19 改訂(DK — 未決 #2 の解消)**: デバイス鍵分離を上記のとおり導入する。端末の追加は本人の別端末による `add_device`(儀式なし — §6.2)、失効は `revoke_device`(`remove_member` と同型の rotate 義務 — §7)。設計録は docs/notes/dk-design.md

### A-2. §5.1 の追記(クライアント検証の 1 文 — DK-A)

> - **端末鍵(2026-09-19 DK)**: 「署名者フィンガープリントが一致するもの」は、その user_id の**端末鍵の有効区間**(`add_member` / `genesis` の鍵は在籍区間、`add_device` で載った鍵は `add_device` 以後 `revoke_device` より前)の中で選ぶ。規則の形は不変(フィンガープリントによる鍵選択)

### A-3. §6.2 の差し替え・追記(role 表・op 表・合意規則「端末鍵」・四眼の票の字面・鍵一意性 — DK-A / DK-C / DK-D)

role 表の `reader` 行を差し替える:

> | `reader` | scope 内の環境の値の取得・復号のみ(DEK ラップは scope 内の環境について受け取る)。チェーン追記は**自分の端末の `add_device` / `revoke_device` のみ**(2026-09-19 DK) |

op 表に 2 行を追記する(`withdraw` の後):

> | **`add_device`** | **enc_pub_hex、sig_pub_hex、role_cap、scope_kind、scope_environments_lp_hex**(新端末の公開鍵と上限) | **全 role(actor 本人の端末を足す — 対象は actor 自身。新端末の cap ≤ actor 端末の実効 cap)** |
> | **`revoke_device`** | **target_user_id、device_fingerprints_lp_hex**(失効する端末 FP のリスト) | **自分の端末: 全 role。他人の端末: `remove_member` と同じ role 規則(reader / member の端末は admin 以上、admin / owner の端末は owner)+ 対象の scope ⊆ actor の実効 scope。失効端末の実効 scope の全環境の `rotate_epoch` を伴う(§7)** |

合意規則ブロックを追記する(「環境スコープ」ブロックの直後):

> - **端末鍵(2026-09-19 DK — 旧未決事項 #2。設計録 docs/notes/dk-design.md)**: メンバーは端末鍵の**集合**を持つ。`genesis` / `add_member` は最初の端末鍵を載せ(payload は不変。その鍵の cap は構造的に (owner, all))、`add_device` / `revoke_device` が増減させる。**原則 D1 — 鍵は端末に属し、権限は人に属する**: role・scope・四眼の票の distinct は user_id で数え、鍵素材とその失効は端末で扱う。署名者は (user_id, 鍵 FP) で同定し、FP が端末を選ぶ。**端末の実効権限** = (min(人の role, 端末の role_cap), 人の scope ∩ 端末の scope) であり、**本仕様のあらゆる「actor / writer / author / issuer / attester の role・scope」の検査は、署名した端末の実効権限に対して行う**(role 規則・原則 1 の包含・環境対象 op・§6.3 の 1 / 3 / 3′・§6.6・四眼の票)。以下の個別規則はこの原則からの導出である
>   - **payload と構造(構造検査の段)**: `add_device` = `[enc_pub_hex, sig_pub_hex, role_cap, scope_kind, scope_environments_lp_hex]`(公開鍵は hex 小文字 64。`role_cap` ∈ {`reader`, `member`, `admin`, `owner`} — `owner` は「上限なし」。scope の 2 フィールドは「環境スコープ」と同じ符号化・同じ構造規則〔`all` ⇒ 空リスト・256 要素以下・重複無効・`listed` の空リストは有効 = DEK を受け取らない端末〕)。`revoke_device` = `[target_user_id, device_fingerprints_lp_hex]`(FP〔hex 小文字 32〕のリストを §2.1 で入れ子 LP 化した hex。1 要素以上・256 要素以下・重複無効。順序は署名対象。生成は昇順 SHOULD・検証は集合)
>   - **`add_device` の認可**: actor は現メンバー(role 不問 — reader も可)。対象は actor 自身(payload に target を持たない)。新端末の各公開鍵は、現メンバー集合の**全端末鍵**の同種公開鍵と重複してはならない(`duplicate-member-key` の対象を端末集合へ拡張。有効な `grant_server` のサーバー鍵との衝突は `add_member` と同じく本規則の対象外)。`listed` の各 environment_id は `create_environment` が先行していること(`unknown-environment`)。**単調性(原則 D2)**: 新端末の cap は署名した端末の**実効** cap を超えてはならない — role_cap ≤ 実効 role、かつ端末 scope ⊆ 実効 scope(集合代数は「環境スコープ」と同じ: `all` = U。拒否理由 `device-cap-exceeded`)。盗まれた端末が自分より強い端末を作れないための規則であり、予備鍵(cap (owner, all))は最初の端末鍵(cap (owner, all))が登録する
>   - **`revoke_device` の認可**: 対象 = actor 自身なら role 不問。他人なら `remove_member` と同じ role 規則(対象の role で決まる)と、原則 1 の包含(対象の scope ⊆ actor の実効 scope — 失効の rotate 義務〔§7〕を履行できる者だけが失効させられる。拒否理由 `scope-not-contained`)。各 FP は対象の**現在有効な**端末でなければならない(`unknown-device`)。失効後に対象の端末が 0 になるエントリは無効(`last-device-protected` — 端末のないメンバーは復帰不能であり、その形は `remove_member` で表す)。自分がいま署名している端末を失効させてよい(エントリ時点では有効。以後の署名は無効)
>   - **端末の有効区間**: 端末鍵は `add_device`(または `add_member` / `genesis`)の seq から `revoke_device` の seq の**直前**まで有効(inclusive 規約 — `revoke_device` エントリの適用後状態にはその端末は含まれない)。検証状態は現メンバーごとの端末集合(FP → 公開鍵・cap)を、履歴索引は端末ごとの有効区間と cap を導出する(§6.3 の鍵選択・3′・AUTH_SPEC §12-6 の受信者判定の入力)。`remove_member` は対象の全端末を同時に終える。同一 user_id の再追加(`add_member`)は最初の端末 1 つから始まる
>   - **受信者集合 R(E)(端末軸)**: 環境 E の DEK ラップの宛先の完全集合 = { (m, d) | m ∈ 現メンバー, d ∈ 端末(m), E ∈ scope(m) ∩ scope(d) } ∪ { 有効 `grant_server` g | E ∈ scope_environments(g) }。判定は受信者クラスを跨いで「同定(id + 鍵)∧ E ∈ 実効 scope」の 1 述語
>   - **四眼との関係**: `add_device` / `revoke_device` は `set_approval_policy` の `ops` に含められず(構造検査 — `invalid-payload`)、提案もできない(`approval-not-required`)— 端末の追加は user_id を増やさず定足数に影響せず、失効は安全側の操作(`rotate_epoch` と同じ線)である。原則 2 の S の要素 (user_id, 鍵 FP) は不変で、FP は署名した端末を指す(下記 `approve` の字面)
>   - **検査順序(理由コードごとベクターで固定)**: `add_device` = actor 規則(`actor-not-member` / `actor-key-mismatch`)→ `duplicate-member-key` → `unknown-environment` → `device-cap-exceeded`。`revoke_device` = role 規則(自分なら通る・他人なら `insufficient-role`)→ `unknown-target` → `unknown-device` → `last-device-protected` → `scope-not-contained`(他人のみ)。既存 op の検査順序は不変(実効権限への置換は各検査の入力が変わるだけ)
>   - 本規則の導入は新 op の追加であり、既存 op の payload 形式には触れない。導入前に受理された既存チェーンは新規則で**有効**(各メンバーの端末 = 最初の鍵 1 つ)。`chain-entries.json` は追記で拡張する(§11)

「四眼」ブロックの `approve` の票の字面を差し替える(該当箇所のみ):

> - **`approve`**(端末鍵の語彙 — 2026-09-19 DK): actor はその時点の owner で、署名した端末の実効 role が owner であること(`insufficient-role` — cap < owner の端末は票を入れられない)。actor の user_id が S に**生きている票**(適用時点でその人の有効な端末による署名)を既に持つなら `duplicate-approval`(同じ端末の 2 票目も、別端末の 2 票目も重複 — 1 人 1 票)。票数 = S の要素のうち「この `approve` の時点で、その FP が現 owner の有効な端末であり、端末の実効 role が owner」であるものの distinct な user_id 数。**失効した端末の票は失効する**(`revoke_device` は「その鍵は侵害されたかもしれない」の宣言であり、鍵更新で旧鍵の票が失効する 2026-09-15 裁定と同じ)。失効した端末鍵を同じ人が `add_device` で再登録すれば旧票は復活する(「失効は単調ではない」の端末形 — 帰結。CLI は失効済み FP の再登録に警告する)。`proposal-void` の「提案時と同じ鍵 FP」は「提案した端末が適用時点でも有効で、その実効 role が内側 op に足りる」と読む

「メンバー鍵の一意性」ブロックの判定単位の 1 文を差し替える:

> - **判定単位は enc / sig の個別鍵**(鍵フィンガープリント = enc‖sig の一致ではない)。比較対象は現メンバー集合の**全端末鍵**(2026-09-19 DK — 端末鍵は人ごとに複数あり、片方の鍵の共有は端末を跨いでも同じ多義性を生む)。enc と sig の種類を跨いだ比較は行わない

### A-4. §6.3 の追記(4 箇所 — DK-A / DK-E)

> - **端末鍵の選択(2026-09-19 DK)**: 1 の「宣言ヘッド時点でその user_id に有効に束縛されていた鍵」は、その user_id の端末鍵の有効区間(§6.2)に宣言ヘッドが含まれる鍵を指す。失効した端末が失効 seq 以後のヘッドを宣言した署名は `*-key-mismatch-at-head`(既存の理由コード — 在籍区間跨ぎと同じ形)。3 の role・3′ の scope は**署名した端末の実効権限**で判定する(cap < member の端末の値署名は `*-role-insufficient-at-head`、端末 scope 外は `*-environment-out-of-scope-at-head` — いずれも既存コードで、入力が実効権限に変わるだけ)
> - **ラップ先 = R(E)(端末軸)**: 「scope 内の現メンバー」は「scope 内の現メンバーの、実効 scope に E を含む各端末」と読む(§6.2 の R(E))。受信側: 自分宛のラップで環境 ∉ **この端末の実効 scope** のものは使用せず警告する(規範は不変)
> - **(a) 招待リンクアンカー**: 「当該 seq 時点のチェーン上で招待者 user_id に束縛された sig 公開鍵がリンクの `is` と一致」は「招待者の当該 seq 時点で有効な端末鍵のいずれかの sig 公開鍵と一致」と読む(招待は端末から発行される)
> - **スコープ外環境の扱い**: 人の scope に加えて端末 scope の外の環境も同じ扱い(メタは見える・DEK は受け取らない)。端末 scope は人の scope の部分集合なので、人の可視範囲(裁定 G)を超えることはない

### A-5. §6.4 の追記(受理ポリシー 1 項目 — DK-E)

> - **端末数(2026-09-19 DK)**: メンバー 1 人あたりの有効な端末は **16** まで(受理ポリシー — 合意規則ではない。超過の `add_device` は型付きエラー — AUTH_SPEC §12-8)。`revoke_device` の受理副作用: 対象端末の申告行の削除(AUTH_SPEC §16-1)・要ローテーション検出(AUDIT_SPEC §4.1 の `revoke_device` 変種)・ミラー(§3.4)。`add_device` の受理副作用: ミラーのみ(DEK のバックフィルはクライアント — §7)。`add_device` / `revoke_device` は汎用チェーン追記 API で受理する(AUTH_SPEC §11)

### A-6. §6.5 の追記(1 文 — DK-D)

> - **端末鍵との関係(2026-09-19 DK)**: 招待を受諾する鍵・招待を発行する鍵はいずれも**その操作を行った端末の端末鍵**である。裏付け元(`github-signing-keys`)へ登録する(`maruhi key publish`)のは受諾に使う端末の sig 公開鍵(端末ごとに登録してよい — GitHub は複数の署名鍵を持てる)。本人が自分の他の端末を足す経路は招待ではなく `add_device`(§6.2 — 第三者保証も相互確認も要さない: 本人が自分の鍵を増やす操作であり、運ぶのは FP〔公開情報〕だけで、サーバーが公開鍵をすり替えれば FP 照合で落ちる)。検証済み指紋帳(充足形 3)の記録は (origin, user_id) → FP の**集合**とし、既知の相手の未知の FP は鍵変更と同じ扱い(警告 + 儀式)とする

### A-7. §6.6 の追記(1 文 — DK-A)

> - **端末鍵(2026-09-19 DK)**: attester の鍵は署名した端末の端末鍵。クライアント検証 (1)(2) の「申告ヘッド時点で有効だった鍵」は端末の有効区間で判定する。申告はメンバーごとでなく**端末ごと**に最新 1 行を保存・配布する(AUTH_SPEC §16-1 — 端末は独立に同期するため、端末を跨いだ seq 単調性は要求しない)

### A-8. §7 の追記(2 項目 — DK-B)

> - **端末の失効(2026-09-19 DK)**: `revoke_device` は、失効した各端末の**実効 scope**(人の scope ∩ 端末の scope)の全環境について、`remove_member` と同じ `rotate_epoch` 義務を伴う(機密性 — その端末が保持していた DEK の失効。scope が空の端末〔票だけの端末〕の失効は義務を伴わない)。義務の起点は当該 `revoke_device` の seq。履行者は失効を署名した actor(同じ人の別端末、または他人の端末を失効させた admin / owner — 原則 1 の包含により DEK を持つ)。**reader が自分の端末を失効させた場合**、actor は `rotate_epoch` の権限を持たないため履行できない — この失効は合意規則で拒否せず(失効は安全側の操作であり、`rotate_epoch` を四眼で遅らせないのと同じ線)、義務は要ローテーション検出(AUDIT_SPEC §4.1 の `revoke_device` 変種)と `project verify` の未収束義務の警告で当該環境の member 以上に見せ、CLI は本人に「rotate を頼む相手」を表示する
> - **端末追加のバックフィル**: `add_device` の actor(同じ人の端末)は、新端末の実効 scope の各環境について**全エポック**の DEK を新端末の enc 公開鍵へラップして登録する(AUTH_SPEC §12-6 の追記経路 — `add_member` 後のバックフィルと同型。予備鍵〔cap (owner, all)〕を含む)。actor は同じ人の端末であり当該 DEK を持つ(「ラップの実行者 = DEK 保持者」)。reader の端末も自分宛のバックフィルを登録できる(AUTH_SPEC §12-3 — 受信者がすべて自分の端末鍵に限る)。四眼経由の適用(`add_member` / scope 拡大)のバックフィルを承認者が行う場合、宛先は対象の**全端末**(R(E) のとおり)

### A-9. §8 の差し替え(見出し・8.1・8.3・8.4・8.5 — DK-G)

> ## 8. 予備鍵ラップ台帳(リカバリーコード・パスキー PRF・保護者・ハンドオフ)
>
> **2026-09-19 改訂(DK)**: 台帳のラップ対象 B は **予備鍵**(§3 — 秘密鍵が台帳にだけ住む端末鍵)のブロブとする。旧「master 鍵」は端末鍵(日常の端末に置く)と予備鍵(台帳に置く)に分かれ、台帳が守るのは後者だけである。台帳の構造(クラス S / G / H)・AAD・分片・ハンドオフの要求 / 承認 payload・`recovery-wrap.json` のバイト列は不変。変わるのは (1) B の意味、(2) ハンドオフの旧端末経路(`kind = "device"` / `source = "device"`)の**削除**(日常の端末は B を持たないため成立しない — 端末の追加は §6.2 の `add_device` が担う)、(3) 保護者分片の封印先が保護者の**各端末鍵**になること、(4) 台帳の変更(ラップの追加・再発行・保護者の指名)に**予備鍵の開封**が要ること(予備鍵は端末に無いため、クライアントはまずコードかパスキーで B を開いてから新しいラップを作る。初回の鍵生成では端末鍵と予備鍵を同時に生成し、その場でリカバリーコードのラップと任意のパスキーラップを作る)
>
> ### 8.1 共通規定(差し替え箇所のみ)
>
> - **ラップ対象 B**: 予備鍵(enc / sig)の不透明ブロブ。直列化形式はクライアント(CLI)の契約であり、サーバーは関知しない(現行 = キーチェーンレコードの JSON。端末鍵のレコードと同じ形。復元側は自己検証を通してから、**端末鍵の発行にだけ用い、日常の保存先には置かない**)
> - **受信者クラス**: (S) 対称 KEK — `recovery-code` / `passkey-prf`。(G) 保護者グループ — `guardian`。(H) ハンドオフ — 一時受信者(保護者の承認を要求者へ運ぶ応答スコープ)
> - `kind` ∈ {`passkey-prf`, `guardian`}(`device` は 2026-09-19 に削除 — 8.4)。`wrap_ref` = passkey-prf: `wrap_id` / guardian: `group_id`。`mode` = guardian のみ `any` | `all`、それ以外は空文字列。**例外: `recovery-code` は旧 AAD のまま**(不変)
>
> ### 8.3 保護者グループ(差し替え箇所のみ)
>
> - **分片の封印先**: 保護者の**現在有効な各端末鍵**の enc 公開鍵(チェーン導出 — §6.2 の端末集合)。同じ `s_i` を保護者の端末数ぶん封印する(info は端末を含まないが受信者鍵が異なるため相互に開けない)。台帳は分片ごとに保護者の user_id と端末の鍵 FP を併置し、クライアントは保護者の現端末集合(チェーン導出)と突合して、封印先の端末がすべて失効 / 更新されていれば不一致(STALE)を警告する — `all` では 1 人の不一致でグループが復元不能になる。保護者が端末を足しても既存の分片は追随しない(ward が再作成する)
>
> ### 8.4 ハンドオフ(差し替え箇所のみ)
>
> - 「端末移行」の項を削除する。承認者は**保護者のみ**(`source = group_id`)。`source = "device"`・`KEK_h`・承認への B の同送は無い。要求者の組み立ては「当該グループの `mode` に従い KEK を得て、台帳から取得したグループのラップを開く」の 1 形
> - **端末の追加は本節の対象外**(§6.2 `add_device` — 秘密を運ばない)。全端末喪失からの復元は、本節の経路で予備鍵 B を得た端末が、予備鍵で `add_device` を署名して自分の新しい端末鍵を登録し、予備鍵の秘密を端末から消す(§3)
>
> ### 8.5 禁止事項(追記)
>
> - 予備鍵の秘密鍵を日常の端末の保存先(キーチェーン・agent メモリ)に**留める**こと(復元・台帳変更の間だけメモリに置き、用が済んだら消す)
> - 予備鍵を端末に束縛された封印器(SE / TPM 等)で封印すること(復元はどの端末でも行える必要がある — 台帳のみ)

### A-10. §11 テストベクターへの追記

> - 0.12-draft(DK)で追加・改訂されるベクター(**所有者承認後の実装 PR〔K2 — 実装分割は docs/notes/dk-design.md §3〕で、実装より先にコミットする**): `chain-entries.json` の**追記**(seq 25〜 — `add_device` / `revoke_device` の正例〔予備鍵・票だけの端末 (owner, listed{})・CI 箱 (member, listed{dev})・第 2 端末による有効な値署名の派生・自己 / 一括 / admin による失効・失効端末の票が数えられない派生・別端末での再投票〕と負例〔`duplicate-member-key`・`unknown-device`・`last-device-protected`・`device-cap-exceeded` の role / scope 各軸・`scope-not-contained`・失効端末の署名 = `actor-key-mismatch`・cap < owner の approve = `insufficient-role`・同じ人の別端末の 2 票目 = `duplicate-approval`・`add_device` の提案 = `approval-not-required`・検査順序の固定形〕。`expected_head_states` の members に `devices` を追加。**正規チェーン seq 1〜24 のバイト列・ハッシュは不変** — 既存 op の payload 形式に触れないため全再生成は不要〔`checkpoint` op 追加時と同じ型〕)、`value-signature.json` / `metadata-signature.json` / `env-manifest.json` / `head-attestation.json` の**追記**(端末軸の負例 = 失効端末の宣言ヘッド〔`*-key-mismatch-at-head`〕・cap 不足〔`*-role-insufficient-at-head`〕・端末 scope 外〔`*-environment-out-of-scope-at-head`〕と第 2 端末の正例。既存の正例・負例は不変)、`master-key-wrap.json` の**再生成**(`handoff-device` 正例と kind `device` への付け替え負例の削除 — 互換経路を作らない裁定の写し。他のケースのバイト列は不変。README 規約 28 として意図的な例外を明記)。**他のベクターは不変**(HPKE info・AAD・登録署名・発行文・受諾文・申告の LP に触れない)

### A-11. §13 未決事項の差し替え(#2)

> 2. ~~デバイス鍵分離・パスキー PRF(WebAuthn PRF 拡張)対応(Phase 2 以降)~~ **解消(2026-09-19 起草 — 本改訂 PR のマージをもって確定)**: パスキー PRF は KL3(0.9-draft — §8.2)で、デバイス鍵分離は DK(§3 / §6.2 / §7 / §8 — 端末鍵・予備鍵・`add_device` / `revoke_device`)で設計。設計録は docs/notes/dk-design.md

### A-12. §14.2 / §14.3 への追記

> 11. **端末単位の失効の保証(2026-09-19 — DK)**: 検証済みチェーン上で `revoke_device` により失効した端末鍵 d(seq s)について、s 以後のエポックの DEK ラップは仕様適合クライアントによって d 宛に生成されず、仕様適合サーバーによって受理されない(§6.2 の R(E) / AUTH_SPEC §12-6)。d による s 以後のヘッドを宣言した値・メタ・マニフェスト・申告の署名、s 以後の d によるチェーンエントリ・四眼の票は全検証者が拒否する。人(user_id)の在籍・role・scope・他の端末は影響を受けない(再招待・票の入れ直しは要らない)。**保証しないもの**: d が失効前に取得した DEK・平文の取り消し(§1 原則 5 — §7 の rotate 義務と要ローテーション検出が補う)、d が失効前に `add_device` で登録した端末の自動失効(チェーン上に「d が追加した」と見える — 失効者が同じエントリで一括して失効する)、cap の単調性を超える端末の作成の**事前**防止以上のこと(盗まれた端末は自分以下の端末を作れる)

> 10. **予備鍵の露出(2026-09-19 — §8 / DK)**: 全端末喪失からの復元では予備鍵 B が復元に使う端末のメモリに置かれる。その端末が侵害されていれば予備鍵も侵害される(暗号は防がない — 復元後の `key reserve rotate`〔新予備鍵の登録 + 旧予備鍵の失効 = rotate 義務〕が回復手段)。予備鍵は日常の端末に留めない(§8.5)ことで露出の機会を復元と台帳変更の瞬間に限る

---

## B. AUTH_SPEC の改訂案

### B-1. §5 の追記(セッション許可列挙 — DK-K)

> - 許可列挙(認証・自己情報系)に **`GET /auth/devices`**(§13-11 — 端末登録簿の読み取り。表示名と鍵 FP・公開鍵のみ。秘密を運ばない)を追加する。端末の追加要求・登録簿の書き込み・削除はセッション主体に拒否する(端末限定 — 2026-09-19 DK)

### B-2. §6 の追記(1 文 — DK-L)

> - **端末鍵との対応(2026-09-19 DK)**: CLI ログインで発行するトークン(既定名 `cli:<hostname>`)は 1 端末に 1 本であり、端末鍵と同じ端末に住む。端末の失効(`revoke_device` — CRYPTO_SPEC §6.2)はチェーンの事実でありトークンとは独立だが、クライアントは失効時に当該端末のトークンの指定失効(本節)を提案する。対応は端末登録簿(§13-11)の `tokenId`(任意・advisory)で持つ

### B-3. §11-1 の追記(1 文 — DK-F)

> - **`add_device` / `revoke_device`(CRYPTO_SPEC §6.2。2026-09-19 DK)は汎用追記 API で受理する**(付随データを持たない)。トークン水準は `add_member` 等と同じ **admin**(§6)。`revoke_device` の受理副作用 = 対象端末の申告行の削除(§16-1)・要ローテーション検出(AUDIT_SPEC §4.1)・ミラー。端末数の上限は §12-8

### B-4. §12-3 の追記(表 1 行 — DK-E)

> | DEK ラップ登録(**受信者がすべて呼び出し主体自身の端末鍵**の場合 — 2026-09-19 DK) | write | **reader 以上** | 環境 ∈ 呼び出し主体の実効 scope(受信者側も) |
>
> - reader が自分の新端末(予備鍵を含む)へ自分の DEK を包み直す経路(CRYPTO_SPEC §7 の端末追加バックフィル)。reader は当該 DEK を正当に保持しており、自分の鍵へ包み直しても他者の能力は増えない。受信者に他人の鍵が 1 つでも含まれれば従来どおり member 以上

### B-5. §12-6 の差し替え(4 箇所 — DK-E)

> - 受信者の同定は **user_id と enc 公開鍵の両方**(不変)。2026-09-19 DK 以後、同じ user_id が複数の enc 公開鍵(端末鍵)を持つため、公開鍵は端末を同定する。チェーン導出の現メンバーの**有効な端末鍵**と両方が厳密一致し、かつ対象環境が**その端末の実効 scope**に含まれる(CRYPTO_SPEC §6.2 — scope 外は 422 `scope-out-of-range`)ことを受理条件とする。保存のスロットは **(environment_id, epoch, recipient_user_id, recipient_enc_pub_hex)**(旧 (environment_id, epoch, recipient_user_id) — 端末ごとに 1 スロット)。上書き禁止(409 `DekWrapExists` — `storedRecipientEncPubHex` の同梱は不変)・完全一致・不足分追記・修復経路は不変
> - **旧鍵宛ラップの掃除**: `add_member` の再追加受理時は、対象 user_id 宛の保存済みラップのうち受信者 enc 公開鍵が**追加された端末鍵**と一致しないものを削除する(旧規則の端末形 — 再追加は端末 1 つから始まる)。`revoke_device` / `remove_member` では削除しない(同一鍵の再登録で復帰する既存規律)
> - **独立登録 API が残る経路**に 6 番目を加える: 「**`add_device` 後の、同じ人の端末による新端末宛の全エポックのバックフィル**(新端末の実効 scope の環境。予備鍵を含む — CRYPTO_SPEC §7。reader の自己バックフィルは §12-3)」。受理規則は全経路共通(署名者 = 呼び出し主体、受信者 ∈ R(E)、上書き禁止)
> - **登録者(署名者)の scope**: 「署名者 = 呼び出し主体」の判定は不変。scope は**署名した端末の実効 scope**で判定する(§12-3 の 403 `InsufficientScope`)。呼び出し主体の user_id と署名端末の user_id の一致は §5.1 の signer_user_id 束縛が担う

### B-6. §12-8 の追記(表 1 行)

> | 有効な端末数 / メンバー / プロジェクト | 16(`add_device` の受理時に判定。超過は型付き 422 `DeviceLimit`。`revoke_device` / `remove_member` で解放 — 2026-09-19 DK) |

### B-7. §13 の差し替え・追記(前文・13-1・13-6・13-7・13-9・新 13-11 — DK-G / DK-F / DK-D)

前文の 1 文を差し替える:

> CRYPTO_SPEC §8(**予備鍵**ラップ台帳 — 2026-09-19 DK)のサーバー保存・配布面の規定。台帳のラップ対象は予備鍵のブロブであり、端末鍵は台帳に載らない(端末の追加は §13-11 の要求行と CRYPTO_SPEC §6.2 の `add_device`)。

§13-1 の 1 文を追記する:

> - 2026-09-19 DK: ブロブの中身は予備鍵(CRYPTO_SPEC §3)。既存の `recovery_wraps` 行(master 鍵の複製)は移行で予備鍵のラップへ**置換**される(再発行と同じ upsert — 移行手順は docs/SELF_HOSTING.md "Updates")

§13-6 の差し替え(`guardian_shares` と `key_handoff_approvals` のみ):

> ```sql
> guardian_shares (
>   group_id        TEXT NOT NULL REFERENCES guardian_groups(id) ON DELETE CASCADE,
>   share_index     INTEGER NOT NULL,     -- 1..n(論理分片 — 保護者 1 人につき 1 つ)
>   guardian_user_id TEXT NOT NULL REFERENCES users(id),
>   guardian_key_fingerprint_hex TEXT NOT NULL,   -- 封印先の端末鍵(2026-09-19 DK — 保護者の各端末に 1 行)
>   guardian_enc_pub_hex TEXT NOT NULL,
>   enc_hex, ciphertext_hex,              -- HPKE(guardian-wrap 形。info は端末を含まない — 同じ s_i を端末ごとに封印)
>   PRIMARY KEY (group_id, share_index, guardian_key_fingerprint_hex),
>   UNIQUE (group_id, guardian_user_id, guardian_key_fingerprint_hex)
> )
> key_handoff_approvals (
>   request_id      TEXT NOT NULL REFERENCES key_handoff_requests(id) ON DELETE CASCADE,
>   source          TEXT NOT NULL,        -- group_id(2026-09-19 DK — 'device' は削除)
>   share_index     INTEGER NOT NULL,
>   approver_user_id TEXT NOT NULL,
>   approver_key_fingerprint_hex TEXT NOT NULL,   -- 承認に使った端末鍵
>   enc_hex, ciphertext_hex,              -- HPKE(handoff-wrap 形)
>   created_at,
>   PRIMARY KEY (request_id, source, share_index)
> )
> ```
>
> - `blob_suite / blob_nonce_hex / blob_ciphertext_hex`(旧 `source = 'device'` の同送ブロブ)は削除する。受理ポリシーの「分片 1..5 / グループ」は**論理分片**(保護者数)の上限で、端末行はその 16 倍(§12-8 の端末数)まで

§13-7 の差し替え(該当行のみ):

> | 要求の照会(承認者) | `GET /auth/handoff/:requestId`(200) | 呼び出し主体が ward のいずれかのグループの分片保持者(いずれかの端末鍵で)であること。**ward 本人の照会は無い**(旧端末の承認経路は削除 — 2026-09-19 DK)。それ以外・不明・失効は一律 404。応答 = `{ wardUserId, wardLogin, expiresAtMs, roles: [ { groupId, mode, shareIndex } ] }` |
> | 承認 | `POST /auth/handoff/:requestId/approvals`(201) | `source = group_id` で当該グループの `share_index` の分片保持者のみ(照合は保存行から — 承認に使う端末鍵の FP が分片行のいずれかと一致)。`source = "device"` は受け付けない(Schema 400) |

§13-9 の差し替え(該当行のみ):

> ```
> GuardianShare = { shareIndex, guardianUserId, guardianKeyFingerprintHex, guardianEncPubHex, encHex, ciphertextHex }   // 端末ごとに 1 要素(同じ shareIndex が複数)
> HandoffApproval = { source: groupId, shareIndex, encHex, ciphertextHex }                                              // blob は無い
> ```

新設 §13-11:

> ### 13-11. 端末登録簿と端末追加要求(2026-09-19 DK — advisory)
>
> 端末鍵の真実源は各プロジェクトのチェーン(CRYPTO_SPEC §6.2 — `add_device` / `revoke_device`)である。本節の登録簿は**表示名・トークンの対応・追加要求の公開鍵の置き場**であり、**いかなる検証・認可の入力にもならない**(サーバーが行を差し込んでもクライアントは端末を足さない — クライアントが `add_device` してよい鍵は、自分が生成した鍵・自分が承認した鍵・検証済みチェーン上でその人の端末として観測した鍵に限る — CRYPTO_SPEC §6.5 の充足形と同じく、サーバー申告を鍵の出所にしない)。
>
> ```sql
> devices (                                -- 端末登録簿(D1・user 単位・advisory)
>   user_id TEXT NOT NULL REFERENCES users(id),
>   key_fingerprint_hex TEXT NOT NULL,     -- 端末鍵 FP(CRYPTO_SPEC §3)
>   enc_pub_hex TEXT NOT NULL, sig_pub_hex TEXT NOT NULL,
>   label TEXT NOT NULL,                   -- 表示名(§6 のトークン名と同じ受理規律 — 制御文字・bidi 禁止・128 文字以下)
>   token_id TEXT,                         -- 任意: この端末の API トークン id(§6)
>   created_at INTEGER NOT NULL,
>   PRIMARY KEY (user_id, key_fingerprint_hex)
> )
> device_add_requests (                    -- 新端末の公開鍵を承認端末へ渡す要求行(TTL 15 分)
>   user_id TEXT NOT NULL, key_fingerprint_hex TEXT NOT NULL,
>   enc_pub_hex TEXT NOT NULL, sig_pub_hex TEXT NOT NULL, label TEXT NOT NULL,
>   created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
>   PRIMARY KEY (user_id, key_fingerprint_hex)
> )
> ```
>
> | op | エンドポイント | 認可 |
> |---|---|---|
> | 登録簿の読み取り | `GET /auth/devices`(200) | 認証済み主体すべて(**セッション主体も可** — §5)。応答 = `[{ keyFingerprintHex, encPubHex, sigPubHex, label, tokenId?, createdAtMs }]`。秘密を運ばない |
> | 登録簿の登録・表示名の更新 | `PUT /auth/devices/:fp`(204。body: `{ encPubHex, sigPubHex, label, tokenId? }`) | `*` × admin トークン(§13-2 と同水準。セッション主体は拒否)。`fp` は body の公開鍵から再計算した値と一致すること(400)。行は user あたり 32 まで(429) |
> | 登録簿からの削除 | `DELETE /auth/devices/:fp`(204 / 404) | 同上(advisory の削除 — チェーンの失効とは独立) |
> | 追加要求の作成 | `POST /auth/devices/requests`(201。body: `{ encPubHex, sigPubHex, label }`) | `*` × admin トークン(新端末自身 — 端末は先に §4 でログインしている)。user あたり 5 回 / 時(429)。同じ FP の要求・登録簿の既存行との衝突は 409 |
> | 追加要求の一覧・照会 | `GET /auth/devices/requests`(200)/ `GET /auth/devices/requests/:fp`(200 / 404) | `*` × admin トークン(承認する端末 — 本人のみ)。応答 = `[{ keyFingerprintHex, encPubHex, sigPubHex, label, expiresAtMs }]`。**承認クライアントは応答の公開鍵から FP を再計算し、人が運んだ FP と一致するもの以外を無視する**(サーバーによる公開鍵のすり替えは FP 照合で落ちる) |
> | 追加要求の取消 | `DELETE /auth/devices/requests/:fp`(204) | 同上(本人)。承認後にクライアントが消す。失効行は日和見削除 |
>
> - 監査イベントは持たない(値・鍵素材に触れない自己情報の帳簿 — §6 のトークン一覧と同じ規律。端末の追加・失効の記録はチェーンのミラー行 — AUDIT_SPEC §3.4 — が担う)
> - hosted Web は登録簿の読み取りだけを表示してよい(「サーバー申告」として — ADR-0018 改訂 2・4 項。失効の導線はトークンの指定失効〔§6〕までで、チェーンの `revoke_device` は CLI)

### B-8. §16-1 の追記(1 項目 — DK-A)

> - **端末ごとの申告(2026-09-19 DK)**: 保存・配布はメンバーごとでなく **(attester_user_id, attester_key_fingerprint_hex) ごと**に最新 1 行(端末は独立に同期するため、端末を跨いだ seq の単調性は課さない — 後退の 409 は同じ端末の保存行に対してのみ)。`revoke_device` の受理時に当該端末の申告行を、`remove_member` の受理時に対象の全端末の申告行を削除する。受理ポリシーの窓(1 時間 60 回)はメンバー単位のまま

---

## C. AUDIT_SPEC の改訂案

### C-1. §2 の追記(1 文 — DK-F)

> - **鍵 FP は端末を指す(2026-09-19 DK)**: 端末鍵の導入後、`key_fingerprint` は「その時点でその user_id がその操作に使った端末」を同定する。actor に端末の別フィールドは持たない(識別子は user_id + 鍵 FP のまま — §1-2 不変)

### C-2. §3.4 の追記(表 2 行 + 1 項目)

> | **`chain.device_added`** | `add_device`(target_user_id = actor、payload = { deviceKeyFingerprint, roleCap, scopeKind, scopeEnvironmentIds }。2026-09-19 DK) |
> | **`chain.device_revoked`** ★ | `revoke_device`(target_user_id = 対象、payload = { deviceKeyFingerprints }。**§4.1 の検出契機になる**ため ★) |
>
> - 端末の追加・失効も 1 エントリ 1 行(全単射不変)。`chain.device_added` は検出の契機ではないが、§4.1 の端末の窓の開始点として Q1 が読む

### C-3. §4.1 の追記(変種 1 つ — DK-B / DK-F)

> **`revoke_device` の変種(2026-09-19 DK)**: 同じ骨格で次を差し替える — 手順 1 の区間は失効した各端末の**有効区間**(`chain.device_added`〔または `add_member` / `genesis` の最初の鍵は在籍区間の開始〕〜 `chain.device_revoked`)と、対象者の環境別アクセス窓(手順 2)および端末の scope(`chain.device_added` の payload)の**共通部分**。手順 3 の (a) は在籍区間内の `var.read` のうち **`actor_key_fingerprint` が失効した FP 集合に含まれる行**(端末単位で「確実に取得した」が言える — user_id で照合する remove の変種より精密。集約形の `var.read` も actor 鍵 FP を持つ)。手順 4〜5 は同じ。`rotation.recommended` の `trigger = revoke_device`、payload に対象 user_id と失効 FP 集合。対象者は在籍を続けるため在籍区間は閉じない(降格の変種と同じく「契機 seq で切った窓」で検出する)。scope が空の端末(票だけの端末)の失効は候補が空になり行を書かない

### C-4. §4.2 の追記(Q1 の 1 文)

> Q1 の列挙に `chain.device_added` / `chain.device_revoked` を加える(payload の FP と cap が端末の窓の開閉点 — §4.1 の `revoke_device` 変種)。索引 (target_user_id, seq) は不変(`chain.device_added` の target は actor 自身)

### C-5. §6 の追記(1 項目)

> - **端末鍵は可視性クラスを変えない(2026-09-19 DK)**: `chain.device_added` / `chain.device_revoked` はクラス 1(`chain.*`)。端末登録簿(AUTH_SPEC §13-11)は監査対象外(トークン一覧と同じ規律)。要ローテーションフラグのビューは `revoke_device` 変種を含めてクラス 1

---

## D. Status 行への追記文

CRYPTO_SPEC:

> 0.12-draft = DK(デバイス鍵分離 — 端末単位の失効。2026-09-19 設計セッション。設計録は docs/notes/dk-design.md、起草時のドラフトは docs/notes/dk-spec-drafts.md): §3 の端末鍵 / 予備鍵 / cap(v1 簡略化の解消 — 未決 #2)/ §5.1 の端末鍵の選択 / §6.2 の `add_device` / `revoke_device`(原則 D1 = 鍵は端末に属し権限は人に属する・実効権限の置換・単調性・鍵一意性の端末集合・R(E) の端末軸・四眼の票の端末語彙)/ §6.3 の鍵選択と 3′ / §6.4 の端末数 / §6.5 / §6.6 の 1 文 / §7 の失効の義務とバックフィル / §8 の予備鍵化と `kind = "device"` の削除・保護者分片の端末展開 / §11 ベクターの追記と `master-key-wrap.json` の再生成 / §13 #2 の解消 / §14.2 保証 11・§14.3 非保証 10。設計の 16 項目は所有者承認待ち(設計録 §4) — **本改訂 PR のマージをもって所有者承認とする**

AUTH_SPEC:

> 0.24-draft = DK(2026-09-19 — CRYPTO_SPEC 0.12-draft。設計録は docs/notes/dk-design.md): §5 の端末登録簿の読み取り / §6 の端末とトークンの対応 / §11-1 の 2 op / §12-3 の reader 自己バックフィル / §12-6 のスロットの端末軸と 6 番目の登録経路 / §12-8 の端末数 / §13 の予備鍵化・旧端末経路の削除・保護者分片の端末行・新 §13-11 端末登録簿と追加要求 / §16-1 の端末ごとの申告 — **本改訂 PR のマージをもって所有者承認とする**

AUDIT_SPEC:

> 1.9-draft = DK(2026-09-19): §2 の鍵 FP = 端末の注記 / §3.4 の `chain.device_added` / `chain.device_revoked` / §4.1 の `revoke_device` 変種(端末の窓・actor 鍵 FP による (a) の照合)/ §4.2 Q1 の列挙 / §6 のクラス不変 — **本改訂 PR のマージをもって所有者承認とする**
