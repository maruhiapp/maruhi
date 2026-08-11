# packages/crypto/test-vectors

CRYPTO_SPEC §11 のテストベクター。**実装より先にコミットし、`packages/crypto` の実装はこれらを通ることを必須とする。**
鍵・ID・値はすべて決定論的なダミー(パターンバイト列)であり、本物のシークレットは含まれない。

## ファイル一覧

| ファイル | 対象 | 期待値の算出(参照ツール) |
|---|---|---|
| `hpke/rfc9180-base-x25519-hkdfsha256-aes256gcm.json` | HPKE 層(RFC 9180 公式ベクター。本スイート Base mode の抽出) | IETF cfrg/draft-irtf-cfrg-hpke の test-vectors.json から抽出(抽出・4 環境検証の経緯は docs/notes/spike-c.md 参照) |
| `encoding.json` | §2.1 長さプレフィックス付きエンコーディング | Python 3 標準ライブラリ(`tools/generate_reference.py`) |
| `variable-encryption.json` | §4 変数値の AES-256-GCM + AAD | pyca/cryptography(同上) |
| `chain-entries.json` | §6 チェーンエントリ正規化 + Ed25519 署名 + ハッシュ連鎖 | pyca/cryptography(同上) |
| `recovery-wrap.json` | §8 リカバリーラップ(HKDF salt=空 + AES-256-GCM + AAD) | pyca/cryptography(同上) |
| `dek-wrap.json` | §5 DEK ラップ(HPKE 単発 Seal) | hpke-js(`tools/generate-dek-wrap.mjs`。ekm derandomize で Seal 方向を固定) |
| `dek-wrap-signature.json` | §5.1 DEK ラップの登録署名(Ed25519 + §2.1 LP) | Python 3 + pyca/cryptography(`tools/generate_reference.py`。ラップ本体は dek-wrap.json の basic ベクターを読み込む) |
| `dek-commitment.json` | §5.2 エポック DEK のコミットメント(SHA-256 + §2.1 LP) | Python 3 標準ライブラリ(`tools/generate_reference.py`。DEK・座標は dek-wrap.json の basic ベクターを読み込む) |
| `value-signature.json` | §4.1 値の書き込み署名(Ed25519 + §2.1 LP) | Python 3 + pyca/cryptography(`tools/generate_reference.py`。チェーン・鍵・DEK は chain-entries.json の正規チェーンを読み込む) |
| `metadata-signature.json` | §4.2 変数・環境メタデータの署名付きステートメント(Ed25519 + §2.1 LP) | Python 3 + pyca/cryptography(`tools/generate_reference.py`。チェーン・鍵は chain-entries.json の正規チェーンを読み込む) |

## 期待値の算出方法(独立参照ツール)

実装対象スタック(WebCrypto + panva `hpke`)とは**別の実装系**で期待値を算出している:

- `tools/generate_reference.py` — Python 3.11 + pyca/cryptography。encoding / variable-encryption / chain-entries / recovery-wrap を生成
- `tools/generate-dek-wrap.mjs` — hpke-js(@hpke/core 1.9.0 + @hpke/dhkem-x25519 1.8.0)。dek-wrap を生成。panva hpke は意図的に Seal の derandomize 手段を持たないため(docs/notes/spike-c.md)、Seal 方向の固定には ekm を注入できる hpke-js を使う。hpke-js 自体は RFC 9180 公式ベクターで Seal 方向まで一致することを spike-c で検証済み
- `tools/verify_reference.mjs` — 生成系とさらに別の実装系による突き合わせ検証: WebCrypto(Bun)で encoding / AES-GCM / HKDF / Ed25519 / SHA-256 を、**panva hpke(実装が採用予定のライブラリ)の KeyPair 渡し Open** で dek-wrap を検証する。全 PASS を確認してからコミットする

再生成・再検証(`tools/` ディレクトリで実行):

```sh
cd tools
bun install            # hpke-js / panva hpke(厳密ピン)
bun run generate       # python3 generate_reference.py + generate-dek-wrap.mjs
bun run verify         # verify_reference.mjs(exit 0 = 全検証通過)
```

`tools/` は使い捨ての参照ツールであり製品コードではない。製品コード(`packages/crypto/src`)から import してはならない。

## ベクターが固定する仕様(人間レビューで特に確認すべき点)

1. **§2.1 エンコーディング**: `uint32-BE 長さ + UTF-8 本体` の連結。数値は 10 進文字列化。`("ab","c")` と `("a","bc")` が異なるバイト列になることをベクターで固定
2. **チェーン正規化(§6.1 の「実装はテストベクターで固定する」の実体)**:
   - `signed_bytes = LP(suite, seq, prev_hash_hex, op, actor_user_id, actor_key_fingerprint_hex, payload_bytes, timestamp_ms)`
   - `payload_bytes` = op ごとに固定したフィールド順(chain-entries.json の `canonicalization.payload_field_order`)の LP エンコードを 1 フィールドとして埋め込む(入れ子 LP)
   - `entry_bytes = LP(signed_bytes の 8 フィールド, signature_hex)`、`entry_hash = SHA-256(entry_bytes)` が次エントリの `prev_hash`
   - バイナリ値(prev_hash / 公開鍵 / FP / 署名)は **hex 小文字文字列**として LP に載せる(生バイトではない)
3. **鍵フィンガープリント**: `SHA-256(enc_pub(32B) || sig_pub(32B))` の先頭 16 バイト。両公開鍵が固定長のためここは素の連結(§2.1 の LP 適用対象は AAD / info / 正規化バイト列)。→ この解釈の妥当性はレビューで確認
4. **§5 DEK ラップの aad は空**(文脈束縛は info が担う)。§4 変数暗号化は AAD、§8 リカバリーラップは AAD + info 固定文字列
5. **§8 の HKDF salt = 空**: negative `wrong-salt` で「空以外の salt では復号不能」を固定
6. **サーバー鍵フィンガープリント(2026-08-02 所有者裁定)**: `SHA-256(server_enc_pub(32B))` の先頭 16 バイト。サーバーは enc 鍵のみ保持(§9)で §3 のユーザー FP 定義(enc||sig)を適用できないため。CRYPTO_SPEC §9 に明文化済み
7. **grant_server の scope_environments(2026-08-02 所有者裁定)**: environment_id のリストを LP エンコード(入れ子 LP)し、その **hex 小文字文字列**を `scope_environments_lp_hex` として payload の 1 フィールドに載せる(binary_encoding 規約と同型)。リストの順序は署名対象バイト列の一部(negative `grant-server-scope-reorder` / `grant-server-scope-flat-concat` で固定)。生成時はソート・重複なしを推奨(SHOULD。検証は集合として扱う)。CRYPTO_SPEC §6.2 に明文化済み
8. **再 grant はスコープ拡大のみ(2026-08-02 所有者裁定)**: 有効な grant と同一サーバー鍵への grant_server は旧スコープ ⊆ 新スコープの場合のみ受理。縮小は `revoke_server`(§7 の全環境ローテーション義務を伴う)を経由させる(negative `authz-grant-scope-narrowed` で固定)
9. **エポック = 環境ごとのカウンタ(2026-08-02 所有者裁定・案 3。2026-08-03 の規約 13 に追随)**: エポックは `create_environment` で 1 に始まり、`rotate_epoch` の new_epoch は「現エポック + 1」と厳密一致。巻き戻し・重複・ジャンプは拒否(negative `authz-epoch-rollback` / `authz-epoch-duplicate` / `authz-epoch-jump` / `authz-epoch-first-jump`〔create 直後のエポック 1 環境への初回 rotate は 2 のみ〕で固定)。**「未観測なら初期値 1」の既定値は廃止**(規約 13 の `unknown-environment`)
10. **フィールドサイズ上限(2026-08-02 所有者裁定・案 2)**: 自由文字列フィールドは UTF-8 で 1024 バイト以下、scope_environments は 256 要素以下。超過は無効(negative `authz-field-too-long` / `authz-scope-too-many` で固定。チェーン有効性の合意規則のためベクターで定数を固定する)
11. **§5.1 DEK ラップの登録署名(2026-08-02 所有者裁定 2-E。セッション 09 起草)**: `signed_bytes = LP("<suite>/dek-wrap-sig", project_id, environment_id, epoch, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex, signer_user_id)` を署名者のチェーン sig 鍵(Ed25519)で署名。suite の束縛はドメイン文字列(negative `suite-mismatch` で固定)、バイナリ列は hex 小文字文字列として LP に載せる(規約 2 の binary_encoding と同じ)。`signer_user_id` の束縛は、起草時のチェーンが同一公開鍵の複数メンバーを許していたことによる帰属付け替え対策(negative `transplant-signer` で固定 — セッション 09 レビューループ 1。規約 12 のメンバー鍵一意性が根本原因側を禁止した後も独立の防衛層として維持)。署名改竄(`tampered-signature`)・ラップ改竄(`tampered-ciphertext` / `tampered-enc`)・座標移植(`transplant-project` / `-environment` / `-epoch` / `-recipient`)・受信者鍵差し替え(`recipient-key-mismatch`)・署名者鍵不一致(`wrong-signer-key`)を negative で固定。素連結の負例は置かない(正例の signed_bytes 一致検査が誤エンコード実装を直接落とすため — chain-entries の flat-concat が守った入れ子 LP のような subtlety がない)。**このベクター自体も PR レビューでの人間確認対象**(§5.1 の仕様起草と同時にコミットし、実装より先行する)
12. **メンバー鍵の一意性(2026-08-03 決定 — セッション 10。CRYPTO_SPEC §6.2)**: `add_member` は対象の enc / sig 公開鍵の**いずれか**が現メンバー集合の**同種**鍵と一致する場合に拒否する(negative `authz-add-member-duplicate-key` / `-duplicate-enc-key` / `-duplicate-sig-key` / `-duplicate-owner-key` で固定。期待理由 `duplicate-member-key`)。判定は enc / sig の個別鍵単位(FP = enc‖sig の一致判定ではない — 片鍵流用の negative 2 件がこれを固定する)。genesis 由来の owner 鍵も索引対象(`-duplicate-owner-key` が固定 — add_member 由来の鍵だけを索引する誤実装を落とす)。禁止範囲は**現メンバー集合のみ**: 削除済みメンバーの鍵は同一 user_id での復帰も別 user_id での再利用も拒否しない(positive `valid_appends` の `readd-removed-member-same-key` / `reuse-removed-member-key-new-user` で固定 — 「履歴全体との重複禁止」を誤実装した検証器はここで落ちる)。検査順序は role 規則 → `duplicate-member`(user_id)→ `duplicate-member-key`(鍵): role → 鍵の順は negative `authz-add-member-role-precedes-duplicate-key` が、user_id → 鍵の順は negative `authz-add-member-duplicate-user-precedes-key`(+ 実装テスト「add_member duplicate user id wins over duplicate key」)が固定する(既存 `authz-admin-adds-admin` は流用元が削除済みメンバーのため順序に依存せず insufficient-role のまま)。**このベクター自体も PR レビューでの人間確認対象**(§6.2 の合意規則改訂と同時にコミットし、実装より先行する)

13. **環境ライフサイクルのチェーン束縛 + DEK コミットメント(2026-08-03 セッション 12 = CRYPTO_SPEC 0.4-draft §5.2 / §6.2。セッション 13 の実装 PR-1 でベクター化)**: 環境の作成はチェーン op `create_environment`(payload 順 `[environment_id, dek_commitment_hex]`)で行い、`rotate_epoch` は payload 末尾に新エポックの `dek_commitment_hex` を持つ(4 フィールド)。コミットメントは `lower_hex(SHA-256(LP("<suite>/dek-commit", project_id, environment_id, epoch, dek_hex)))`(project_id = genesis エントリハッシュ。単体ベクターは dek-commitment.json、チェーン掲載値は `environment_deks` セクションのダミー DEK からの実計算値)。合意規則: environment_id は**チェーン履歴全体で一意**(negative `authz-create-env-duplicate`)、`rotate_epoch` は `create_environment` の先行が必須(negative `authz-rotate-unknown-environment` — new_epoch 2 は旧「未観測 = 1」意味論なら受理された値で、既定値フォールバック実装を落とす)。`create_environment` の必要 role は member 以上(negative `authz-create-env-reader`)。認可段の検査順序 = role → duplicate / unknown → エポック順序(negative `authz-create-env-role-precedes-duplicate` / `authz-rotate-role-precedes-unknown` / `authz-rotate-unknown-precedes-epoch`)。`dek_commitment_hex` の形式(hex 小文字 64 文字)は **payload 構造検査**に属し認可判定に先行する(negative `create-env-commitment-uppercase-hex` / `create-env-commitment-bad-length` / `rotate-commitment-uppercase-hex` / `create-env-commitment-format-precedes-role`)。コミットメントも署名対象(negative `create-env-tampered-commitment` / `rotate-tampered-commitment`)。許容境界は `valid_appends` の `create-environment-fresh-id`(未使用 ID の作成)と `rotate-freshly-created-environment`(create 直後の rotate = 2)が固定。**この改訂に伴い正規チェーンは全再生成**(旧チェーンは create 非先行の rotate を含み新合意規則で無効 — 単なる追記ではない。影響一覧は docs/notes/session-12.md §8-4)。**このベクター自体も PR レビューでの人間確認対象**(実装より先行してコミット)

14. **§4.1 値の書き込み署名(2026-08-03 セッション 12 = CRYPTO_SPEC 0.4-draft §4.1。セッション 14 の実装 PR-2 でベクター化)**: `value_signed_bytes = LP("<suite>/value-sig", project_id, environment_id, epoch, variable_id, version, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex, writer_user_id, chain_head_hash_hex, chain_head_seq)` を writer のチェーン sig 鍵(Ed25519)で署名。suite の束縛はドメイン文字列(negative `suite-mismatch`)、数値は 10 進文字列化・バイナリは hex 小文字文字列(規約 2 と同じ)。`prev_value_sig_hash_hex` は直前 version の signed_bytes の SHA-256(version 1 は空文字列 — 正例 `v1-basic` / `v2-chained` の連鎖と rule negative `v1-nonempty-prev` / `v2-empty-prev` の形検査で固定)。チェーン状態を要する検証規則系は **chain-entries.json の正規 12 エントリチェーンを参照**し(cross-file の先例 = 規約 11)、ciphertext は `environment_deks` のダミー DEK による実 AES-GCM 暗号文(値署名 → §4 復号が一続きの実データ)。宣言ヘッド時点の **inclusive 規約**(§6.3)は正例が固定する: `create-head-inclusive`(create_environment エントリ自身をヘッドにする直後 push)/ `removed-writer-in-tenure`(削除済み writer の在籍区間内・自身の rotate エントリをヘッドにする過去値 — 削除後も当時の鍵で検証できる)/ `rotate-head-reencryption`(rotate 実行者の再暗号化 push = エポック単調 prev 連鎖)。改竄・移植系 negative(`tampered-*` / `transplant-*` / `chain-head-swap` / `chain-head-seq-mismatch` / `tampered-prev-hash` / `wrong-signer-key` / `transplant-signer`)は元署名の Ed25519 検証失敗を、検証規則系 negative(kind = "authorization"。`head-not-in-chain` / `head-beyond-local-seq` / `writer-role-insufficient` / `writer-removed-at-head` / `epoch-not-current-at-head` / `head-before-environment-create` / `key-from-other-tenure` / `writer-unknown-in-history` / `prev-hash-mismatch` / `epoch-regression-across-versions` 等)は**署名は有効**のまま `expected_reason` の理由コードでの拒否を固定する(`chain-head-mismatch`〔seq ≤ 自ヘッドの不一致 = 即時証拠〕と `chain-head-future`〔seq > 自ヘッド = 再同期の入口〕の 2 種の区別 — §6.3-2 — を含む)。`key-from-other-tenure` は `tenure_extension`(正規 12 エントリ + seq 13 の新鍵 re-add)の派生チェーンで検証する(chain-entries.json 本体は変更しない)。`fork_same_version` は同一座標に対する 2 つの**有効**署名で、equivocation の証拠化(§14.2-5 — 防止でなく検出)を固定する。**このベクター自体も PR レビューでの人間確認対象**(実装より先行してコミット)

15. **§4.2 変数・環境メタデータの署名付きステートメント(2026-08-03 セッション 12 = CRYPTO_SPEC 0.4-draft §4.2。セッション 15 の実装 PR-3 でベクター化)**: `var_meta_signed_bytes = LP("<suite>/var-meta-sig", project_id, environment_id, variable_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)`、`env_meta_signed_bytes = LP("<suite>/env-meta-sig", project_id, environment_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)` を author のチェーン sig 鍵(Ed25519)で署名。suite と var / env の別はドメイン文字列が束縛(negative `suite-mismatch` / `cross-kind-transplant`)。`name` は UTF-8 バイト列を **byte-exact** に束縛し検証者は正規化しない(negative `nfc-variant` — NFC 正規形で署名した名前の NFD 変種は署名検証に失敗する。NFC 正規化は署名前のクライアントの責務 — §4.2 / AUTH_SPEC §12-1)。prev 連鎖・削除時の name 保持は正例 `var-create` → `var-rename` → `var-delete`(deleted は直前 active 名を保持)が、削除後の再 active 化の禁止は rule negative `revive-after-delete`(predecessor.status = deleted — 署名・prev 連鎖が有効でも拒否)が固定。**メタステートメントはエポックアンカーを持たない**(§4.2 / §14.3-5): 値署名の `epoch-not-current-at-head` / `head-before-environment-create` に相当する規則は存在せず、`var-meta-head-before-env-create` は **positive**(環境作成前ヘッドの var メタは受理される — AUTH_SPEC §12-4 の意図された非対称)。環境作成の複合同梱形(宣言ヘッド = 追記前の現ヘッド)は正例 `env-create-meta` が、環境削除のみ admin 水準である差は rule negative `env-delete-role-insufficient`(+ 正例 `env-delete-admin`)が固定。名前 ↔ ID の付け替え(`DATABASE_URL` ↔ `DEBUG_ENDPOINT`)は `name_swap` セクション(正規 2 本は有効・name だけ入れ替えたバイト列は署名失敗)が、同一 metaVersion の分岐の証拠化は `rename_fork` セクション(両 branch とも有効 = equivocation の証拠 — §14.2-5)が固定。検証規則系 negative は value-signature と同じ運び方(kind = "authorization"、署名は有効のまま `expected_reason` で拒否。`tenure_extension` の派生チェーンも同一内容)。**このベクター自体も PR レビューでの人間確認対象**(実装より先行してコミット)

## panva hpke の制約と検証方針(spike-c の知見)

- panva は単発 Seal の derandomize 不可 → **実装テストは「Open 方向ベクター一致 + DeriveKeyPair 一致 + 自己ラウンドトリップ」**で書く。Seal 方向の完全固定は hpke-js 生成の本ベクター(+ RFC 9180 公式ベクター)が担う
- Open は **KeyPair(公開鍵込み)渡しを標準**とする(秘密鍵単体渡しは extractable=true を強制されるため使わない)。`tools/verify_reference.mjs` は非抽出(extractable=false)の KeyPair で Open が通ることを確認している

## negative ベクターの規約

`negative` 配列の各要素は `must_fail: true` を持ち、`base`(または `base_seq`)のベクターに対して差し替えるフィールド(`decrypt_aad_hex` / `open_info_hex` / `ciphertext_hex` 等)だけを指定する。実装テストはこれらで「復号・検証が失敗すること」を必須で検査する(改竄・移植・順序入替の検出)。

chain-entries.json には加えて `kind: "authorization"` の negative がある(セッション 04 追加)。これは**暗号学的には有効**(署名・正規化・prev_hash がすべて正しい)な完全なエントリで、検証規則(§6.2 の role 権限、エポック順序、再 grant 規則)によってのみ拒否されるべきもの。※ payload 構造検査段で拒否される `invalid-payload` の negative(フィールドサイズ上限・dek_commitment_hex の形式違反)も、完全なエントリ + `expected_reason` を持つ同じデータ形のためこの `kind` で運ぶ — 拒否の**段**は expected_reason(と検査順序固定の negative)が規定する。`entry` に完全なエントリ、`expected_reason` に期待する拒否理由(`insufficient-role` / `actor-not-member` / `last-owner-protected` / `actor-key-mismatch` / `grant-scope-narrowed` / `epoch-out-of-sequence` / `duplicate-member` / `duplicate-member-key` / `duplicate-environment` / `unknown-environment` / `invalid-payload`)を持つ。`verify_reference.mjs` は署名が**有効であること**を確認し(拒否理由が暗号検証でないことの保証)、権限規則での拒否は実装テストが検査する。

また `expected_head_states`(セッション 04 追加。セッション 13 = 規約 13 で意味論拡張)は、検証済みチェーンから導出される「現メンバー集合(role 付き)+ 有効 grant_server 集合 + **環境集合**(環境ごとの現エポック・作成 seq・エポック開始 seq・エポックごとの DEK コミットメント — §6.3 の「各エポックの有効区間」)」の期待値を `after_seq` 時点ごとに固定する(§6.3 のクライアント検証 API の出力を固定するもの)。旧 `environment_epochs`(既定値 1 の観測エポック)は環境集合の導出に置換された。

chain-entries.json の `valid_appends`(セッション 10 追加)は、正規チェーン(seq 12 まで)へ独立に追記できる**有効な**完全エントリで、合意規則の**許容側の境界**を固定する(メンバー鍵一意性の「禁止範囲 = 現メンバー集合のみ」の 2 ケース + 環境ライフサイクルの 2 ケース — 規約 13)。`entry` に完全なエントリ、`expected_members` に受理後の現メンバー集合(role 付き)、`expected_environments` に受理後の環境ごとの現エポックを持つ。`verify_reference.mjs` は署名・正規化・prev_hash の有効性を確認し、受理されること自体は実装テストが検査する。

## 実装時の CI(§11)

ラウンドトリップ + 本ベクターの検証はブラウザ(Chromium)/ Bun / workerd の 3 環境すべてで実行する。vitest 構成の実体は `packages/crypto` の `vitest.config.ts`(node)/ `vitest.browser.config.ts`(browser)/ `vitest.workerd.config.ts`(workerd)+ `test/run-in-bun.ts`(Bun 直接実行)。
