#!/usr/bin/env python3
"""maruhi 固有テストベクターの参照生成器(独立参照ツール)。

実装対象(packages/crypto = WebCrypto + panva hpke)とは独立の実装系
(Python 3.11 + pyca/cryptography)で期待値を算出する。
出力先: ../encoding.json, ../variable-encryption.json, ../chain-entries.json,
        ../recovery-wrap.json(dek-wrap.json は generate-dek-wrap.mjs が生成)

これは使い捨ての参照ツールであり、製品コードではない。製品コードから import しない。
すべての鍵・ID・値はダミー(本物のシークレットを置かない)。

再生成: python3 generate_reference.py(このディレクトリで実行)
依存: cryptography >= 41(AESGCM / HKDF / Ed25519 / X25519)
"""

import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

# ---------------------------------------------------------------------------
# CRYPTO_SPEC §2.1: 長さプレフィックス付き決定論的エンコーディング
# 各フィールドを UTF-8 バイト列とし、uint32-BE 長さ + 本体で連結する。
# 数値は 10 進文字列化してから同様に扱う。


def lp_encode(fields: list) -> bytes:
    out = b""
    for f in fields:
        if isinstance(f, int):
            b = str(f).encode("utf-8")
        elif isinstance(f, str):
            b = f.encode("utf-8")
        elif isinstance(f, bytes):
            b = f
        else:
            raise TypeError(f"unsupported field type: {type(f)}")
        out += len(b).to_bytes(4, "big") + b
    return out


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def write(name: str, obj) -> None:
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"wrote {name}")


# 決定論的なダミーバイト列(パターン化。本物の鍵素材ではない)
def pat(prefix: int, n: int) -> bytes:
    return bytes((prefix + i) % 256 for i in range(n))


# ---------------------------------------------------------------------------
# 1. encoding.json — §2.1 エンコーダ自体のベクター

def gen_encoding():
    cases = []

    def case(name, fields, note=None):
        entry = {
            "name": name,
            "fields": [str(f) if isinstance(f, int) else f for f in fields],
            "expected_hex": lp_encode(fields).hex(),
        }
        if note:
            entry["note"] = note
        cases.append(entry)

    case(
        "ambiguity-ab-c",
        ["ab", "c"],
        note="次の ambiguity-a-bc と素の文字列連結では同一になるが、LP では異なることが本質",
    )
    case("ambiguity-a-bc", ["a", "bc"])
    case("empty-field", [""], note="空フィールドは 00000000 のみ")
    case("empty-list", [], note="フィールド 0 個は空バイト列")
    case("utf8-multibyte", ["㊙"], note="UTF-8 マルチバイト(3 バイト)")
    case("number-decimal", ["epoch", 42], note="数値は 10 進文字列化(42 → \"42\")")
    case(
        "aad-shape-example",
        ["maruhi/v1", "proj-0001", "env-prod-0001", 3, "var-database-url-0001", 7],
        note="variable-encryption.json の basic ベクターの AAD と同一バイト列",
    )
    write(
        "encoding.json",
        {
            "description": "CRYPTO_SPEC §2.1 の長さプレフィックス付きエンコーディング(uint32-BE 長さ + UTF-8 本体)のベクター",
            "cases": cases,
        },
    )


# ---------------------------------------------------------------------------
# 2. variable-encryption.json — §4 変数値の AES-256-GCM + AAD

VAR_KEY = pat(0x00, 32)
VAR_NONCE = pat(0xA0, 12)
AAD_FIELDS_ORDER = ["suite", "project_id", "environment_id", "epoch", "variable_id", "version"]


def var_aad(suite, project_id, environment_id, epoch, variable_id, version) -> bytes:
    return lp_encode([suite, project_id, environment_id, epoch, variable_id, version])


def gen_variable_encryption():
    suite = "maruhi/v1"
    project_id = "proj-0001"
    environment_id = "env-prod-0001"
    epoch = 3
    variable_id = "var-database-url-0001"
    version = 7
    plaintext = "postgres://dummy:dummy@db.example.internal:5432/app"

    aad = var_aad(suite, project_id, environment_id, epoch, variable_id, version)
    ct = AESGCM(VAR_KEY).encrypt(VAR_NONCE, plaintext.encode(), aad)  # ct || tag(16B)

    tampered = bytearray(ct)
    tampered[-1] ^= 0x01

    write(
        "variable-encryption.json",
        {
            "description": "CRYPTO_SPEC §4: 変数値の AES-256-GCM 暗号化。AAD は §2.1 エンコーディング",
            "aad_fields_order": AAD_FIELDS_ORDER,
            "note": "ciphertext_hex は ct || tag(16 bytes)。WebCrypto / pyca AESGCM と同じ連結形式",
            "vectors": [
                {
                    "name": "basic",
                    "key_hex": VAR_KEY.hex(),
                    "nonce_hex": VAR_NONCE.hex(),
                    "suite": suite,
                    "project_id": project_id,
                    "environment_id": environment_id,
                    "epoch": epoch,
                    "variable_id": variable_id,
                    "version": version,
                    "plaintext_utf8": plaintext,
                    "aad_hex": aad.hex(),
                    "ciphertext_hex": ct.hex(),
                }
            ],
            "negative": [
                {
                    "name": "aad-environment-mismatch",
                    "base": "basic",
                    "decrypt_aad_hex": var_aad(suite, project_id, "env-dev-0002", epoch, variable_id, version).hex(),
                    "must_fail": True,
                    "note": "environment_id 差し替え(環境間の移植攻撃)は復号失敗",
                },
                {
                    "name": "aad-epoch-mismatch",
                    "base": "basic",
                    "decrypt_aad_hex": var_aad(suite, project_id, environment_id, 4, variable_id, version).hex(),
                    "must_fail": True,
                    "note": "epoch 差し替え(ローテーション跨ぎの移植)は復号失敗",
                },
                {
                    "name": "ciphertext-bit-flip",
                    "base": "basic",
                    "ciphertext_hex": bytes(tampered).hex(),
                    "must_fail": True,
                    "note": "タグ末尾 1 bit 反転は復号失敗",
                },
                {
                    "name": "nonce-mismatch",
                    "base": "basic",
                    "decrypt_nonce_hex": pat(0xB0, 12).hex(),
                    "must_fail": True,
                },
            ],
        },
    )


# ---------------------------------------------------------------------------
# 3. chain-entries.json — §6 チェーンエントリの正規化 + Ed25519 署名
#
# 正規化(このベクターが固定する定義。README 参照):
#   signed_bytes = LP(suite, seq, prev_hash_hex, op, actor_user_id,
#                     actor_key_fingerprint_hex, payload_bytes, timestamp)
#   payload_bytes = LP(op ごとに固定した順のフィールド列)を 1 フィールドとして埋め込む
#   entry_bytes  = LP(上記 8 フィールド, signature_hex)
#   entry_hash   = SHA-256(entry_bytes) — 次エントリの prev_hash になる
#   バイナリ値(prev_hash / 公開鍵 / FP / 署名)はすべて hex 小文字文字列として扱う

PAYLOAD_FIELD_ORDER = {
    "genesis": ["enc_pub_hex", "sig_pub_hex"],
    "add_member": ["target_user_id", "enc_pub_hex", "sig_pub_hex", "role"],
    "remove_member": ["target_user_id"],
    "change_role": ["target_user_id", "new_role"],
    "rotate_epoch": ["environment_id", "new_epoch", "reason"],
    "grant_server": ["server_enc_pub_hex", "server_key_fingerprint_hex", "scope_environments_lp_hex"],
    "revoke_server": ["server_key_fingerprint_hex"],
}


def make_user(enc_seed: bytes, sig_seed: bytes):
    enc_sk = X25519PrivateKey.from_private_bytes(enc_seed)
    sig_sk = Ed25519PrivateKey.from_private_bytes(sig_seed)
    raw = serialization.Encoding.Raw
    pub = serialization.PublicFormat.Raw
    enc_pub = enc_sk.public_key().public_bytes(raw, pub)
    sig_pub = sig_sk.public_key().public_bytes(raw, pub)
    # CRYPTO_SPEC §3: FP = SHA-256(enc公開鍵 || sig公開鍵) 先頭 16 バイト。
    # 両公開鍵は固定長 32B のため、ここは素の連結(§2.1 の LP 対象は AAD/info/正規化列)
    fp = sha256(enc_pub + sig_pub)[:16]
    return {
        "sig_sk": sig_sk,
        "enc_pub_hex": enc_pub.hex(),
        "sig_pub_hex": sig_pub.hex(),
        "fp_hex": fp.hex(),
    }


def make_server(enc_seed: bytes):
    # サーバー(デプロイメント)鍵は X25519 enc のみ(CRYPTO_SPEC §9。署名鍵を持たない)。
    # サーバー鍵 FP は SHA-256(server_enc_pub(32B)) の先頭 16 バイト(要レビュー:
    # §3 のユーザー FP 定義は enc||sig の連結だが、サーバーには sig 鍵が存在しないため)
    enc_sk = X25519PrivateKey.from_private_bytes(enc_seed)
    raw = serialization.Encoding.Raw
    pub = serialization.PublicFormat.Raw
    enc_pub = enc_sk.public_key().public_bytes(raw, pub)
    fp = sha256(enc_pub)[:16]
    return {"enc_pub_hex": enc_pub.hex(), "fp_hex": fp.hex()}


def scope_environments_lp_hex(environment_ids: list) -> str:
    # grant_server の許可スコープ: environment_id のリストを LP エンコード(入れ子 LP)し、
    # その hex 小文字文字列を payload の 1 フィールドとして外側 LP に載せる
    # (binary_encoding 規約「バイナリ値は hex 文字列として LP に載せる」と同型)。
    # リストの順序は署名対象バイト列の一部(検証は as-signed 順で再構築する)
    return lp_encode(environment_ids).hex()


def gen_chain_entries():
    owner_id = "user-owner-0001"
    member_id = "user-member-0002"
    admin_id = "user-admin-0003"
    owner = make_user(pat(0x10, 32), pat(0x20, 32))
    member = make_user(pat(0x30, 32), pat(0x40, 32))
    admin = make_user(pat(0x50, 32), pat(0x60, 32))
    server = make_server(pat(0x90, 32))
    suite = "maruhi/v1"

    def payload_bytes(op: str, payload: dict) -> bytes:
        return lp_encode([payload[k] for k in PAYLOAD_FIELD_ORDER[op]])

    entries = []
    prev_hash_hex = "0" * 64

    def build_entry(seq, op, actor_id, actor, payload, timestamp, prev_hex):
        pb = payload_bytes(op, payload)
        signed = lp_encode([suite, seq, prev_hex, op, actor_id, actor["fp_hex"], pb, timestamp])
        sig = actor["sig_sk"].sign(signed)
        entry_bytes = lp_encode(
            [suite, seq, prev_hex, op, actor_id, actor["fp_hex"], pb, timestamp, sig.hex()]
        )
        return {
            "seq": seq,
            "suite": suite,
            "prev_hash_hex": prev_hex,
            "op": op,
            "actor": {"user_id": actor_id, "key_fingerprint_hex": actor["fp_hex"]},
            "payload": payload,
            "timestamp_ms": timestamp,
            "payload_bytes_hex": pb.hex(),
            "signed_bytes_hex": signed.hex(),
            "signature_hex": sig.hex(),
            "entry_bytes_hex": entry_bytes.hex(),
            "entry_hash_hex": sha256(entry_bytes).hex(),
        }

    def add_entry(seq, op, actor_id, actor, payload, timestamp):
        nonlocal prev_hash_hex
        entry = build_entry(seq, op, actor_id, actor, payload, timestamp, prev_hash_hex)
        entries.append(entry)
        prev_hash_hex = entry["entry_hash_hex"]

    grant_scope = ["env-prod-0001", "env-dev-0002"]
    grant_payload = {
        "server_enc_pub_hex": server["enc_pub_hex"],
        "server_key_fingerprint_hex": server["fp_hex"],
        "scope_environments": grant_scope,  # 可読性のための平文表現(正規化対象は次行)
        "scope_environments_lp_hex": scope_environments_lp_hex(grant_scope),
    }

    t0 = 1754006400000  # 2025-08-01T00:00:00Z 相当の固定値(ダミー)
    add_entry(1, "genesis", owner_id, owner,
              {"enc_pub_hex": owner["enc_pub_hex"], "sig_pub_hex": owner["sig_pub_hex"]}, t0)
    add_entry(2, "add_member", owner_id, owner,
              {"target_user_id": member_id, "enc_pub_hex": member["enc_pub_hex"],
               "sig_pub_hex": member["sig_pub_hex"], "role": "member"}, t0 + 1000)
    add_entry(3, "rotate_epoch", member_id, member,
              {"environment_id": "env-prod-0001", "new_epoch": "2", "reason": "scheduled"}, t0 + 2000)
    add_entry(4, "remove_member", owner_id, owner,
              {"target_user_id": member_id}, t0 + 3000)
    # seq 5〜9: grant_server / revoke_server / change_role のベクター(セッション 04 で補完)
    add_entry(5, "add_member", owner_id, owner,
              {"target_user_id": admin_id, "enc_pub_hex": admin["enc_pub_hex"],
               "sig_pub_hex": admin["sig_pub_hex"], "role": "reader"}, t0 + 4000)
    add_entry(6, "change_role", owner_id, owner,
              {"target_user_id": admin_id, "new_role": "admin"}, t0 + 5000)
    add_entry(7, "grant_server", owner_id, owner, grant_payload, t0 + 6000)
    add_entry(8, "rotate_epoch", admin_id, admin,
              {"environment_id": "env-dev-0002", "new_epoch": "2", "reason": "scheduled"}, t0 + 7000)
    add_entry(9, "revoke_server", owner_id, owner,
              {"server_key_fingerprint_hex": server["fp_hex"]}, t0 + 8000)

    # negative 1: payload 改竄(role を admin に)。署名はそのまま → 検証失敗すべき
    e2 = entries[1]
    tampered_payload = dict(e2["payload"], role="admin")
    tampered_signed = lp_encode(
        [suite, 2, entries[0]["entry_hash_hex"], "add_member", owner_id, owner["fp_hex"],
         payload_bytes("add_member", tampered_payload), t0 + 1000]
    )
    negatives = [
        {
            "name": "tampered-payload-role",
            "base_seq": 2,
            "payload": tampered_payload,
            "signed_bytes_hex": tampered_signed.hex(),
            "signature_hex": e2["signature_hex"],
            "verify_key_hex": owner["sig_pub_hex"],
            "must_fail": True,
            "note": "role を書き換えると元の署名は検証に失敗する",
        },
        {
            "name": "field-order-swap",
            "base_seq": 2,
            "signed_bytes_hex": lp_encode(
                [suite, 2, entries[0]["entry_hash_hex"], "add_member",
                 owner["fp_hex"], owner_id,  # actor の 2 フィールドを入れ替え
                 bytes.fromhex(e2["payload_bytes_hex"]), t0 + 1000]
            ).hex(),
            "signature_hex": e2["signature_hex"],
            "verify_key_hex": owner["sig_pub_hex"],
            "must_fail": True,
            "note": "正規化のフィールド順を入れ替えたバイト列では署名検証に失敗する(順序固定の確認)",
        },
        {
            "name": "wrong-signer",
            "base_seq": 3,
            "signed_bytes_hex": entries[2]["signed_bytes_hex"],
            "signature_hex": owner["sig_sk"].sign(bytes.fromhex(entries[2]["signed_bytes_hex"])).hex(),
            "verify_key_hex": member["sig_pub_hex"],
            "must_fail": True,
            "note": "actor(member)以外の鍵による署名は actor の公開鍵で検証に失敗する",
        },
        {
            "name": "prev-hash-mismatch",
            "base_seq": 3,
            "claimed_prev_hash_hex": entries[0]["entry_hash_hex"],
            "expected_prev_hash_hex": entries[1]["entry_hash_hex"],
            "must_fail": True,
            "note": "seq 3 の prev_hash が seq 2 の entry_hash と一致しないチェーンは検証失敗",
        },
    ]

    # --- grant_server / revoke_server / change_role の署名系 negative --------------
    e7 = entries[6]  # grant_server
    e6 = entries[5]  # change_role
    e9 = entries[8]  # revoke_server
    reordered_scope = dict(grant_payload, **{
        "scope_environments": list(reversed(grant_scope)),
        "scope_environments_lp_hex": scope_environments_lp_hex(list(reversed(grant_scope))),
    })
    # 入れ子 LP を使わず環境 ID を素の連結にした誤エンコード(曖昧性の温床)。
    # 正規化はこのバイト列を生まないことを固定する
    flat_scope = dict(grant_payload, **{
        "scope_environments_lp_hex": "".join(grant_scope).encode("utf-8").hex(),
    })
    tampered_revoke_fp = bytearray(bytes.fromhex(server["fp_hex"]))
    tampered_revoke_fp[0] ^= 0x01

    def resign_variant(name, base_entry, payload, note):
        # payload だけ差し替えた signed_bytes に対して「元の署名」を検証 → 失敗すべき
        pb = payload_bytes(base_entry["op"], payload)
        signed = lp_encode([
            suite, base_entry["seq"], base_entry["prev_hash_hex"], base_entry["op"],
            base_entry["actor"]["user_id"], base_entry["actor"]["key_fingerprint_hex"],
            pb, base_entry["timestamp_ms"],
        ])
        return {
            "name": name,
            "base_seq": base_entry["seq"],
            "signed_bytes_hex": signed.hex(),
            "signature_hex": base_entry["signature_hex"],
            "verify_key_hex": owner["sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    negatives += [
        resign_variant(
            "grant-server-scope-reorder", e7, reordered_scope,
            "scope_environments の順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象)",
        ),
        resign_variant(
            "grant-server-scope-flat-concat", e7, flat_scope,
            "scope を入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する(§2.1 の曖昧性排除)",
        ),
        resign_variant(
            "change-role-tampered-new-role", e6,
            {"target_user_id": admin_id, "new_role": "owner"},
            "new_role の書き換え(admin → owner)は署名検証に失敗する",
        ),
        resign_variant(
            "revoke-server-tampered-fp", e9,
            {"server_key_fingerprint_hex": bytes(tampered_revoke_fp).hex()},
            "失効対象フィンガープリントの改竄は署名検証に失敗する",
        ),
    ]

    # --- 認可系 negative: 署名・ハッシュ連鎖は正しいが §6.2 の権限規則で拒否すべき ---
    # kind = "authorization"。署名は有効(verify_reference.mjs は署名が通ることを確認し、
    # 実装テストはチェーン検証が expected_reason で失敗することを検査する)
    head9 = entries[8]["entry_hash_hex"]
    head5 = entries[4]["entry_hash_hex"]

    def authz(name, entry, expected_reason, note):
        return {
            "name": name,
            "kind": "authorization",
            "entry": entry,
            "verify_key_hex": None,  # 下で actor の sig_pub を入れる
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
        }

    authz_cases = []

    def add_authz(name, seq, prev_hex, op, actor_id, actor, payload, ts, expected_reason, note):
        entry = build_entry(seq, op, actor_id, actor, payload, ts, prev_hex)
        case = authz(name, entry, expected_reason, note)
        case["verify_key_hex"] = {"user-owner-0001": owner, "user-member-0002": member,
                                  "user-admin-0003": admin}[actor_id]["sig_pub_hex"]
        authz_cases.append(case)

    add_authz(
        "authz-admin-grant-server", 10, head9, "grant_server", admin_id, admin,
        grant_payload, t0 + 9000, "insufficient-role",
        "grant_server は owner のみ。admin による正しく署名されたエントリでも拒否する",
    )
    add_authz(
        "authz-reader-rotate-epoch", 6, head5, "rotate_epoch", admin_id, admin,
        {"environment_id": "env-prod-0001", "new_epoch": "3", "reason": "scheduled"},
        t0 + 5000, "insufficient-role",
        "seq 5 時点の user-admin-0003 は reader。rotate_epoch は member 以上のみ",
    )
    add_authz(
        "authz-nonmember-actor", 10, head9, "rotate_epoch", member_id, member,
        {"environment_id": "env-prod-0001", "new_epoch": "3", "reason": "scheduled"},
        t0 + 9000, "actor-not-member",
        "seq 4 で削除済みの user-member-0002 はチェーンに追記できない(ゴーストメンバー対策)",
    )
    add_authz(
        "authz-remove-last-owner", 10, head9, "remove_member", owner_id, owner,
        {"target_user_id": owner_id}, t0 + 9000, "last-owner-protected",
        "最後の owner は削除不可(§6.2)",
    )
    add_authz(
        "authz-demote-last-owner", 10, head9, "change_role", owner_id, owner,
        {"target_user_id": owner_id, "new_role": "member"}, t0 + 9000, "last-owner-protected",
        "最後の owner は降格不可(§6.2)",
    )
    add_authz(
        "authz-admin-adds-admin", 10, head9, "add_member", admin_id, admin,
        {"target_user_id": member_id, "enc_pub_hex": member["enc_pub_hex"],
         "sig_pub_hex": member["sig_pub_hex"], "role": "admin"},
        t0 + 9000, "insufficient-role",
        "admin / owner ロールの付与は owner のみ(admin は reader / member のみ追加可)",
    )
    # 再 grant のスコープ縮小は拒否(2026-08-02 所有者裁定): 縮小は revoke_server +
    # rotate_epoch(§7 の全環境ローテーション義務)を経由させる。拡大(旧 ⊆ 新)のみ受理
    head7 = entries[6]["entry_hash_hex"]
    narrowed_scope = ["env-prod-0001"]
    add_authz(
        "authz-grant-scope-narrowed", 8, head7, "grant_server", owner_id, owner,
        dict(grant_payload, **{
            "scope_environments": narrowed_scope,
            "scope_environments_lp_hex": scope_environments_lp_hex(narrowed_scope),
        }),
        t0 + 7000, "grant-scope-narrowed",
        "有効な grant のスコープを狭める再 grant は owner 署名でも拒否する(§7 のローテーション義務を迂回させない)",
    )

    # エポック順序規則(2026-08-02 所有者裁定・案 3): エポックは環境ごとのカウンタ
    # (初期値 1)で、rotate_epoch は必ず +1。巻き戻し(削除済みメンバー保持の旧 DEK
    # への再露出)・重複・ジャンプ(member 権限 1 署名でのエポック空間焼き尽くし DoS)
    # をすべて拒否する。seq 9 時点の観測値: env-prod-0001 = 2, env-dev-0002 = 2
    for name, env, bad_epoch, note in [
        ("authz-epoch-rollback", "env-prod-0001", "1",
         "観測済みエポック(2)からの巻き戻しは拒否する"),
        ("authz-epoch-duplicate", "env-prod-0001", "2",
         "観測済みエポックと同値の rotate は拒否する(期待値は 3)"),
        ("authz-epoch-jump", "env-prod-0001", "10",
         "エポックのジャンプは拒否する(期待値は 3。焼き尽くし DoS 対策)"),
        ("authz-epoch-first-jump", "env-staging-9999", "5",
         "チェーン上で未観測の環境の初回 rotate は初期値 1 + 1 = 2 のみ受理する"),
    ]:
        add_authz(
            name, 10, head9, "rotate_epoch", admin_id, admin,
            {"environment_id": env, "new_epoch": bad_epoch, "reason": "scheduled"},
            t0 + 9000, "epoch-out-of-sequence", note,
        )

    # フィールドサイズ上限(2026-08-02 所有者裁定・案 2): 自由文字列フィールドは
    # UTF-8 で 1024 バイト以下、scope_environments は 256 要素以下。超過は無効
    # (巨大 payload による検証クライアントの資源消費対策。上限は合意規則なので
    # ベクターで固定する)。署名は有効だが形状検証(invalid-payload)で拒否すべき
    add_authz(
        "authz-field-too-long", 10, head9, "rotate_epoch", admin_id, admin,
        {"environment_id": "env-prod-0001", "new_epoch": "3", "reason": "x" * 1025},
        t0 + 9000, "invalid-payload",
        "reason が 1025 バイト(上限 1024 超過)のエントリは署名が有効でも拒否する",
    )
    oversized_scope = [f"env-bulk-{i:04d}" for i in range(257)]
    add_authz(
        "authz-scope-too-many", 10, head9, "grant_server", owner_id, owner,
        dict(grant_payload, **{
            "scope_environments": oversized_scope,
            "scope_environments_lp_hex": scope_environments_lp_hex(oversized_scope),
        }),
        t0 + 9000, "invalid-payload",
        "scope_environments が 257 要素(上限 256 超過)のエントリは拒否する",
    )

    # actor の申告 FP・署名鍵が「チェーンに登録された actor の鍵」と一致しない偽装。
    # member の鍵で署名し FP も member のものだが、user_id は owner を騙る
    impostor = build_entry(10, "rotate_epoch", owner_id, member,
                           {"environment_id": "env-prod-0001", "new_epoch": "3",
                            "reason": "scheduled"}, t0 + 9000, head9)
    authz_cases.append({
        "name": "authz-actor-key-mismatch",
        "kind": "authorization",
        "entry": impostor,
        "verify_key_hex": member["sig_pub_hex"],
        "expected_reason": "actor-key-mismatch",
        "must_fail": True,
        "note": "actor.user_id (owner) の登録鍵と申告 FP・署名鍵 (member のもの) が一致しないエントリは拒否する",
    })

    negatives += authz_cases

    # --- 検証済みチェーンから導出される状態の期待値(実装の導出 API を固定する)------
    expected_head_states = [
        {
            "after_seq": 4,
            "members": {owner_id: "owner"},
            "server_grants": [],
            "environment_epochs": {"env-prod-0001": "2"},
        },
        {
            "after_seq": 7,
            "members": {owner_id: "owner", admin_id: "admin"},
            "server_grants": [
                {
                    "server_key_fingerprint_hex": server["fp_hex"],
                    "server_enc_pub_hex": server["enc_pub_hex"],
                    "scope_environments": grant_scope,
                }
            ],
            "environment_epochs": {"env-prod-0001": "2"},
        },
        {
            "after_seq": 9,
            "members": {owner_id: "owner", admin_id: "admin"},
            "server_grants": [],
            "environment_epochs": {"env-prod-0001": "2", "env-dev-0002": "2"},
        },
    ]

    write(
        "chain-entries.json",
        {
            "description": "CRYPTO_SPEC §6: チェーンエントリの正規化バイト列と Ed25519 署名・ハッシュ連鎖のベクター",
            "canonicalization": {
                "signed_bytes": "LP(suite, seq, prev_hash_hex, op, actor_user_id, actor_key_fingerprint_hex, payload_bytes, timestamp_ms)",
                "payload_bytes": "LP(payload_field_order[op] の順のフィールド列)を 1 フィールドとして埋め込む",
                "entry_bytes": "LP(signed_bytes の 8 フィールド, signature_hex)",
                "entry_hash": "SHA-256(entry_bytes)。次エントリの prev_hash になる",
                "binary_encoding": "prev_hash / 公開鍵 / FP / 署名は hex 小文字文字列として LP に載せる",
                "payload_field_order": PAYLOAD_FIELD_ORDER,
                "key_fingerprint": "SHA-256(enc_pub(32B) || sig_pub(32B)) の先頭 16 バイト(固定長のため素の連結)",
                "server_key_fingerprint": "SHA-256(server_enc_pub(32B)) の先頭 16 バイト(サーバーは enc 鍵のみ。§9)→ 要レビュー",
                "scope_environments": "environment_id のリストを LP エンコード(入れ子 LP)し、その hex 小文字文字列を scope_environments_lp_hex として payload に載せる。リストの順序は署名対象の一部(検証は as-signed 順で再構築)→ 要レビュー",
            },
            "keys": {
                "user-owner-0001": {
                    "enc_sk_seed_hex": pat(0x10, 32).hex(),
                    "sig_sk_seed_hex": pat(0x20, 32).hex(),
                    "enc_pub_hex": owner["enc_pub_hex"],
                    "sig_pub_hex": owner["sig_pub_hex"],
                    "key_fingerprint_hex": owner["fp_hex"],
                },
                "user-member-0002": {
                    "enc_sk_seed_hex": pat(0x30, 32).hex(),
                    "sig_sk_seed_hex": pat(0x40, 32).hex(),
                    "enc_pub_hex": member["enc_pub_hex"],
                    "sig_pub_hex": member["sig_pub_hex"],
                    "key_fingerprint_hex": member["fp_hex"],
                },
                "user-admin-0003": {
                    "enc_sk_seed_hex": pat(0x50, 32).hex(),
                    "sig_sk_seed_hex": pat(0x60, 32).hex(),
                    "enc_pub_hex": admin["enc_pub_hex"],
                    "sig_pub_hex": admin["sig_pub_hex"],
                    "key_fingerprint_hex": admin["fp_hex"],
                },
            },
            "server_key": {
                "enc_sk_seed_hex": pat(0x90, 32).hex(),
                "enc_pub_hex": server["enc_pub_hex"],
                "key_fingerprint_hex": server["fp_hex"],
            },
            "entries": entries,
            "expected_head_states": expected_head_states,
            "negative": negatives,
        },
    )


# ---------------------------------------------------------------------------
# 4. recovery-wrap.json — §8 リカバリーコードによる master 秘密鍵ラップ

def gen_recovery_wrap():
    recovery_secret = pat(0x50, 32)
    user_id = "user-owner-0001"
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,  # RFC 5869: salt 未指定は HashLen バイトのゼロ列 = 「salt = 空」規定の実装形
        info=b"maruhi/v1/recovery",
    ).derive(recovery_secret)

    # ラップ対象の master 秘密鍵ブロブ。直列化形式は実装課題のためベクターでは不透明な
    # 固定 64 バイト(enc_sk 32B 相当 || sig_sk 32B 相当)として扱う
    master_blob = pat(0x60, 64)
    nonce = pat(0xC0, 12)
    aad = lp_encode(["maruhi/v1/recovery-wrap", user_id])
    ct = AESGCM(kek).encrypt(nonce, master_blob, aad)

    tampered = bytearray(ct)
    tampered[0] ^= 0x80

    write(
        "recovery-wrap.json",
        {
            "description": "CRYPTO_SPEC §8: KEK = HKDF-SHA256(recovery_secret, salt=空, info=\"maruhi/v1/recovery\")、AES-256-GCM ラップ(AAD = LP(\"maruhi/v1/recovery-wrap\", user_id))",
            "vectors": [
                {
                    "name": "basic",
                    "recovery_secret_hex": recovery_secret.hex(),
                    "user_id": user_id,
                    "hkdf": {"salt": "", "info_utf8": "maruhi/v1/recovery", "length": 32},
                    "kek_hex": kek.hex(),
                    "master_secret_blob_hex": master_blob.hex(),
                    "nonce_hex": nonce.hex(),
                    "aad_hex": aad.hex(),
                    "ciphertext_hex": ct.hex(),
                }
            ],
            "negative": [
                {
                    "name": "aad-user-mismatch",
                    "base": "basic",
                    "decrypt_aad_hex": lp_encode(["maruhi/v1/recovery-wrap", "user-member-0002"]).hex(),
                    "must_fail": True,
                    "note": "他ユーザーの鍵ブロブへの移植は復号失敗",
                },
                {
                    "name": "ciphertext-bit-flip",
                    "base": "basic",
                    "ciphertext_hex": bytes(tampered).hex(),
                    "must_fail": True,
                },
                {
                    "name": "wrong-salt",
                    "base": "basic",
                    "decrypt_kek_hex": HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=pat(0x00, 32),
                        info=b"maruhi/v1/recovery",
                    ).derive(recovery_secret).hex(),
                    "must_fail": True,
                    "note": "salt を空以外にすると別 KEK になり復号失敗(salt = 空の規定の固定)",
                },
            ],
        },
    )


if __name__ == "__main__":
    gen_encoding()
    gen_variable_encryption()
    gen_chain_entries()
    gen_recovery_wrap()
