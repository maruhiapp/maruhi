# packages/crypto/test-vectors

CRYPTO_SPEC §11 のテストベクター。**実装より先にコミットし、`packages/crypto` の実装はこれらを通ることを必須とする。**
鍵・ID・値はすべて決定論的なダミー(パターンバイト列)であり、本物のシークレットは含まれない。

## ファイル一覧

| ファイル | 対象 | 期待値の算出(参照ツール) |
|---|---|---|
| `hpke/rfc9180-base-x25519-hkdfsha256-aes256gcm.json` | HPKE 層(RFC 9180 公式ベクター。本スイート Base mode の抽出) | IETF cfrg/draft-irtf-cfrg-hpke の test-vectors.json から抽出(spikes/spike-c で抽出・4 環境で検証済みのコピー) |
| `encoding.json` | §2.1 長さプレフィックス付きエンコーディング | Python 3 標準ライブラリ(`tools/generate_reference.py`) |
| `variable-encryption.json` | §4 変数値の AES-256-GCM + AAD | pyca/cryptography(同上) |
| `chain-entries.json` | §6 チェーンエントリ正規化 + Ed25519 署名 + ハッシュ連鎖 | pyca/cryptography(同上) |
| `recovery-wrap.json` | §8 リカバリーラップ(HKDF salt=空 + AES-256-GCM + AAD) | pyca/cryptography(同上) |
| `dek-wrap.json` | §5 DEK ラップ(HPKE 単発 Seal) | hpke-js(`tools/generate-dek-wrap.mjs`。ekm derandomize で Seal 方向を固定) |

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
6. **サーバー鍵フィンガープリント(セッション 04 追加)**: `SHA-256(server_enc_pub(32B))` の先頭 16 バイト。サーバーは enc 鍵のみ保持(§9)で §3 のユーザー FP 定義(enc||sig)を適用できないため。→ 仕様に明文がない解釈。**要レビュー**
7. **grant_server の scope_environments(セッション 04 追加)**: environment_id のリストを LP エンコード(入れ子 LP)し、その **hex 小文字文字列**を `scope_environments_lp_hex` として payload の 1 フィールドに載せる(binary_encoding 規約と同型)。リストの順序は署名対象バイト列の一部(negative `grant-server-scope-reorder` / `grant-server-scope-flat-concat` で固定)。→ **要レビュー**
8. **再 grant はスコープ拡大のみ(2026-08-02 所有者裁定)**: 有効な grant と同一サーバー鍵への grant_server は旧スコープ ⊆ 新スコープの場合のみ受理。縮小は `revoke_server`(§7 の全環境ローテーション義務を伴う)を経由させる(negative `authz-grant-scope-narrowed` で固定)
9. **エポック = 環境ごとのカウンタ(2026-08-02 所有者裁定・案 3)**: 初期エポックは 1、`rotate_epoch` の new_epoch は「観測済みエポック(未観測なら 1)+ 1」と厳密一致。巻き戻し・重複・ジャンプは拒否(negative `authz-epoch-rollback` / `authz-epoch-duplicate` / `authz-epoch-jump` / `authz-epoch-first-jump` で固定)

## panva hpke の制約と検証方針(spike-c の知見)

- panva は単発 Seal の derandomize 不可 → **実装テストは「Open 方向ベクター一致 + DeriveKeyPair 一致 + 自己ラウンドトリップ」**で書く。Seal 方向の完全固定は hpke-js 生成の本ベクター(+ RFC 9180 公式ベクター)が担う
- Open は **KeyPair(公開鍵込み)渡しを標準**とする(秘密鍵単体渡しは extractable=true を強制されるため使わない)。`tools/verify_reference.mjs` は非抽出(extractable=false)の KeyPair で Open が通ることを確認している

## negative ベクターの規約

`negative` 配列の各要素は `must_fail: true` を持ち、`base`(または `base_seq`)のベクターに対して差し替えるフィールド(`decrypt_aad_hex` / `open_info_hex` / `ciphertext_hex` 等)だけを指定する。実装テストはこれらで「復号・検証が失敗すること」を必須で検査する(改竄・移植・順序入替の検出)。

chain-entries.json には加えて `kind: "authorization"` の negative がある(セッション 04 追加)。これは**暗号学的には有効**(署名・正規化・prev_hash がすべて正しい)な完全なエントリで、検証規則(§6.2 の role 権限、エポック順序、再 grant 規則)によってのみ拒否されるべきもの。`entry` に完全なエントリ、`expected_reason` に期待する拒否理由(`insufficient-role` / `actor-not-member` / `last-owner-protected` / `actor-key-mismatch` / `grant-scope-narrowed` / `epoch-out-of-sequence`)を持つ。`verify_reference.mjs` は署名が**有効であること**を確認し(拒否理由が暗号検証でないことの保証)、権限規則での拒否は実装テストが検査する。

また `expected_head_states`(セッション 04 追加)は、検証済みチェーンから導出される「現メンバー集合(role 付き)+ 有効 grant_server 集合 + 環境ごとの観測エポック」の期待値を `after_seq` 時点ごとに固定する(§6.3 のクライアント検証 API の出力を固定するもの)。

## 実装時の CI(§11)

ラウンドトリップ + 本ベクターの検証はブラウザ(Chromium)/ Bun / workerd の 3 環境すべてで実行する。vitest 構成の雛形は spikes/spike-c(node / workerd / browser の 3 プロジェクト + Bun 直接実行)を参照。
