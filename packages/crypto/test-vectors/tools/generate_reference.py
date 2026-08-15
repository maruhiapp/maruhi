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
import unicodedata
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
    # 2026-08-03(セッション 12 / CRYPTO_SPEC 0.4-draft): 環境作成のチェーン op 化
    # (§6.2 create_environment)と rotate_epoch payload 末尾への dek_commitment_hex 追加
    "create_environment": ["environment_id", "dek_commitment_hex"],
    "rotate_epoch": ["environment_id", "new_epoch", "reason", "dek_commitment_hex"],
    # 2026-08-12(セッション 22 / CRYPTO_SPEC 0.5-draft §6.2): grant_server payload の
    # リースポリシー拡張。lease_policy_lp_hex を末尾に追加した 4 フィールドで確定
    # (公開前が形式を確定できる最後の窓 — grandfathering を持たない)
    "grant_server": [
        "server_enc_pub_hex", "server_key_fingerprint_hex",
        "scope_environments_lp_hex", "lease_policy_lp_hex",
    ],
    "revoke_server": ["server_key_fingerprint_hex"],
}

# CRYPTO_SPEC §5.2: エポック DEK のコミットメント。
#   dek_commitment_hex = lower_hex(SHA-256(LP("maruhi/v1/dek-commit",
#                                             project_id, environment_id, epoch, dek_hex)))
# ドメイン文字列が suite を束縛し、座標(project / environment / epoch)を原像に含める。
# dek_hex は DEK 32 バイトの hex 小文字文字列(binary_encoding 規約と同じ)。
DEK_COMMIT_DOMAIN = "maruhi/v1/dek-commit"


def dek_commitment_hex(project_id: str, environment_id: str, epoch, dek: bytes) -> str:
    return sha256(
        lp_encode([DEK_COMMIT_DOMAIN, project_id, environment_id, epoch, dek.hex()])
    ).hex()


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


def lease_policy_lp_hex(policy: list) -> str:
    # grant_server の lease_policy(CRYPTO_SPEC §6.2 / §9.1): issuer 汎用の
    # ワークロード ID フェデレーション制約のリスト。正規化は scope_environments と
    # 同じ入れ子 LP で、階層は 3 段:
    #   constraint_bytes = LP(claim_name, claim_value)
    #   element_bytes    = LP(issuer_url, audience, LP(constraint_bytes...))
    #   lease_policy_lp_hex = lower_hex(LP(element_bytes...))
    # 内側の LP はバイト列としてそのまま外側 LP のフィールドになる(chain の
    # payload_bytes → signed_bytes の入れ子と同型)。リスト順(要素・制約とも)は
    # 署名対象バイト列の一部。空リスト = 「リース経路なし」で hex は空文字列
    elements = []
    for element in policy:
        constraints = lp_encode([
            lp_encode([c["claim_name"], c["claim_value"]])
            for c in element["claim_constraints"]
        ])
        elements.append(lp_encode([element["issuer_url"], element["audience"], constraints]))
    return lp_encode(elements).hex()


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
    # 正規チェーンの lease_policy(CRYPTO_SPEC §6.2 / AUTH_SPEC §14-1):
    # 同一 (issuer, audience) で claim 制約の異なる複数要素は正当な表現(完全一致のみの
    # v1 で複数ブランチを許可する形)。要素・制約ともコードポイント昇順(SHOULD)。
    # 値はすべてダミー(実在リポジトリを指さない)
    grant_lease_policy = [
        {
            "issuer_url": "https://token.actions.githubusercontent.com",
            "audience": "https://maruhi-dogfood.example.com",
            "claim_constraints": [
                {"claim_name": "ref", "claim_value": "refs/heads/main"},
                {"claim_name": "repository", "claim_value": "acme-dummy/widget-app"},
            ],
        },
        {
            "issuer_url": "https://token.actions.githubusercontent.com",
            "audience": "https://maruhi-dogfood.example.com",
            "claim_constraints": [
                {"claim_name": "sub",
                 "claim_value": "repo:acme-dummy/widget-app:ref:refs/heads/release"},
            ],
        },
    ]

    def grant_payload_for(scope: list, policy: list) -> dict:
        return {
            "server_enc_pub_hex": server["enc_pub_hex"],
            "server_key_fingerprint_hex": server["fp_hex"],
            "scope_environments": scope,  # 可読性のための平文表現(正規化対象は *_lp_hex)
            "scope_environments_lp_hex": scope_environments_lp_hex(scope),
            "lease_policy": policy,  # 同上
            "lease_policy_lp_hex": lease_policy_lp_hex(policy),
        }

    grant_payload = grant_payload_for(grant_scope, grant_lease_policy)

    t0 = 1754006400000  # 2025-08-01T00:00:00Z 相当の固定値(ダミー)
    add_entry(1, "genesis", owner_id, owner,
              {"enc_pub_hex": owner["enc_pub_hex"], "sig_pub_hex": owner["sig_pub_hex"]}, t0)

    # プロジェクト ID = genesis エントリハッシュ(§6.4)。§5.2 のコミットメント原像の
    # project_id 座標に使う(チェーンとコミットメントの座標が一続きの実データになる)
    project_id = entries[0]["entry_hash_hex"]

    # 各 (environment, epoch) の決定論的ダミー DEK。コミットメントの内容は
    # チェーン検証では検証不能(§6.2)だが、実装テストが §5.2 の照合
    # (DEK → コミットメント再計算 → チェーン掲載値と一致)まで検査できるよう、
    # 実際に計算したコミットメントを payload に載せる
    environment_deks = {
        "env-prod-0001": {1: pat(0xC0, 32), 2: pat(0xC4, 32), 3: pat(0xF0, 32)},
        "env-dev-0002": {1: pat(0xC8, 32), 2: pat(0xCC, 32)},
        "env-stage-0003": {1: pat(0xD4, 32), 2: pat(0xD8, 32)},
        "env-fresh-0004": {1: pat(0xDC, 32)},
        # negative 用(チェーンに載らない座標のプレースホルダ DEK)
        "env-ghost-9999": {2: pat(0xE4, 32), 7: pat(0xE8, 32)},
        "env-reader-blocked-0008": {1: pat(0xEC, 32)},
    }

    def commit(environment_id: str, epoch: int) -> str:
        return dek_commitment_hex(project_id, environment_id, epoch, environment_deks[environment_id][epoch])

    def create_env_payload(environment_id: str):
        return {"environment_id": environment_id, "dek_commitment_hex": commit(environment_id, 1)}

    def rotate_payload(environment_id: str, new_epoch: int, reason: str = "scheduled"):
        return {
            "environment_id": environment_id,
            "new_epoch": str(new_epoch),
            "reason": reason,
            "dek_commitment_hex": commit(environment_id, new_epoch),
        }

    # 正規チェーン(2026-08-03 再生成 — セッション 12 §8-4): 全 rotate_epoch に
    # create_environment が先行し、rotate payload はコミットメント込みの 4 フィールド。
    # seq 11 の env-stage-0003 はローテーション未実施(エポック 1)の環境として残し、
    # 「create 直後の初回 rotate は 2 のみ」の境界(authz-epoch-first-jump)と
    # エポック 1 環境の head state を固定する
    add_entry(2, "add_member", owner_id, owner,
              {"target_user_id": member_id, "enc_pub_hex": member["enc_pub_hex"],
               "sig_pub_hex": member["sig_pub_hex"], "role": "member"}, t0 + 1000)
    add_entry(3, "create_environment", member_id, member,
              create_env_payload("env-prod-0001"), t0 + 2000)
    add_entry(4, "rotate_epoch", member_id, member,
              rotate_payload("env-prod-0001", 2), t0 + 3000)
    add_entry(5, "remove_member", owner_id, owner,
              {"target_user_id": member_id}, t0 + 4000)
    add_entry(6, "add_member", owner_id, owner,
              {"target_user_id": admin_id, "enc_pub_hex": admin["enc_pub_hex"],
               "sig_pub_hex": admin["sig_pub_hex"], "role": "reader"}, t0 + 5000)
    add_entry(7, "change_role", owner_id, owner,
              {"target_user_id": admin_id, "new_role": "admin"}, t0 + 6000)
    add_entry(8, "create_environment", admin_id, admin,
              create_env_payload("env-dev-0002"), t0 + 7000)
    add_entry(9, "grant_server", owner_id, owner, grant_payload, t0 + 8000)
    add_entry(10, "rotate_epoch", admin_id, admin,
              rotate_payload("env-dev-0002", 2), t0 + 9000)
    add_entry(11, "create_environment", owner_id, owner,
              create_env_payload("env-stage-0003"), t0 + 10000)
    add_entry(12, "revoke_server", owner_id, owner,
              {"server_key_fingerprint_hex": server["fp_hex"]}, t0 + 11000)

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
            "note": "actor(member。seq 3 = create_environment)以外の鍵による署名は actor の公開鍵で検証に失敗する",
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

    # --- grant_server / revoke_server / change_role / commitment の署名系 negative ---
    e_grant = entries[8]   # seq 9: grant_server
    e_change = entries[6]  # seq 7: change_role
    e_revoke = entries[11]  # seq 12: revoke_server
    e_create_stage = entries[10]  # seq 11: create_environment env-stage-0003
    e_rotate_dev = entries[9]     # seq 10: rotate_epoch env-dev-0002 → 2
    reordered_scope = dict(grant_payload, **{
        "scope_environments": list(reversed(grant_scope)),
        "scope_environments_lp_hex": scope_environments_lp_hex(list(reversed(grant_scope))),
    })
    # 入れ子 LP を使わず環境 ID を素の連結にした誤エンコード(曖昧性の温床)。
    # 正規化はこのバイト列を生まないことを固定する
    flat_scope = dict(grant_payload, **{
        "scope_environments_lp_hex": "".join(grant_scope).encode("utf-8").hex(),
    })
    # lease_policy の順序も署名対象(要素順・制約順とも)
    reordered_policy = list(reversed(grant_lease_policy))
    reordered_lease_elements = dict(grant_payload, **{
        "lease_policy": reordered_policy,
        "lease_policy_lp_hex": lease_policy_lp_hex(reordered_policy),
    })
    reordered_claims_policy = [
        dict(grant_lease_policy[0],
             claim_constraints=list(reversed(grant_lease_policy[0]["claim_constraints"]))),
        grant_lease_policy[1],
    ]
    reordered_lease_claims = dict(grant_payload, **{
        "lease_policy": reordered_claims_policy,
        "lease_policy_lp_hex": lease_policy_lp_hex(reordered_claims_policy),
    })
    # 3 段の入れ子 LP を使わず全文字列を 1 段の LP に平坦化した誤エンコード
    # (要素・制約の境界が消える曖昧性の温床)
    flat_lease_fields = []
    for element in grant_lease_policy:
        flat_lease_fields += [element["issuer_url"], element["audience"]]
        for constraint in element["claim_constraints"]:
            flat_lease_fields += [constraint["claim_name"], constraint["claim_value"]]
    flat_lease = dict(grant_payload, **{
        "lease_policy_lp_hex": lp_encode(flat_lease_fields).hex(),
    })
    tampered_revoke_fp = bytearray(bytes.fromhex(server["fp_hex"]))
    tampered_revoke_fp[0] ^= 0x01

    def resign_variant(name, base_entry, payload, note, verify_key_hex=None):
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
            "verify_key_hex": verify_key_hex if verify_key_hex is not None else owner["sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    negatives += [
        resign_variant(
            "grant-server-scope-reorder", e_grant, reordered_scope,
            "scope_environments の順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象)",
        ),
        resign_variant(
            "grant-server-scope-flat-concat", e_grant, flat_scope,
            "scope を入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する(§2.1 の曖昧性排除)",
        ),
        resign_variant(
            "grant-server-lease-policy-reorder", e_grant, reordered_lease_elements,
            "lease_policy の要素順を入れ替えると元の署名は検証に失敗する(要素順も署名対象 — §6.2)",
        ),
        resign_variant(
            "grant-server-lease-claims-reorder", e_grant, reordered_lease_claims,
            "lease_policy 内の claim 制約の順を入れ替えると元の署名は検証に失敗する(制約順も署名対象)",
        ),
        resign_variant(
            "grant-server-lease-policy-flat-concat", e_grant, flat_lease,
            "lease_policy を 3 段の入れ子 LP でなく 1 段の平坦 LP でエンコードしたバイト列では署名検証に失敗する(要素・制約の境界の曖昧性排除)",
        ),
        {
            # 旧 3 フィールド形式(lease_policy_lp_hex なし)で組んだバイト列に対して
            # 正規エントリの署名を検証 → 失敗すべき。旧形式実装が新チェーンを
            # 検証できない(4 フィールドが必須である)ことの明示的な固定
            "name": "grant-server-lease-policy-dropped",
            "base_seq": e_grant["seq"],
            "signed_bytes_hex": lp_encode([
                suite, e_grant["seq"], e_grant["prev_hash_hex"], e_grant["op"],
                e_grant["actor"]["user_id"], e_grant["actor"]["key_fingerprint_hex"],
                lp_encode([grant_payload["server_enc_pub_hex"],
                           grant_payload["server_key_fingerprint_hex"],
                           grant_payload["scope_environments_lp_hex"]]),
                e_grant["timestamp_ms"],
            ]).hex(),
            "signature_hex": e_grant["signature_hex"],
            "verify_key_hex": owner["sig_pub_hex"],
            "must_fail": True,
            "note": "lease_policy_lp_hex を落とした旧 3 フィールド形式のバイト列では署名検証に失敗する(payload は 4 フィールドが正規形)",
        },
        resign_variant(
            "change-role-tampered-new-role", e_change,
            {"target_user_id": admin_id, "new_role": "owner"},
            "new_role の書き換え(admin → owner)は署名検証に失敗する",
        ),
        resign_variant(
            "revoke-server-tampered-fp", e_revoke,
            {"server_key_fingerprint_hex": bytes(tampered_revoke_fp).hex()},
            "失効対象フィンガープリントの改竄は署名検証に失敗する",
        ),
        # dek_commitment_hex も署名対象(payload の一部): 差し替えは検証失敗(§5.2 の
        # 「チェーンエントリは作成者の署名で覆われる」の負例側)
        resign_variant(
            "create-env-tampered-commitment", e_create_stage,
            dict(e_create_stage["payload"], dek_commitment_hex=commit("env-fresh-0004", 1)),
            "create_environment の dek_commitment_hex の差し替えは署名検証に失敗する(§5.2)",
        ),
        resign_variant(
            "rotate-tampered-commitment", e_rotate_dev,
            dict(e_rotate_dev["payload"], dek_commitment_hex=commit("env-prod-0001", 2)),
            "rotate_epoch の dek_commitment_hex の差し替えは署名検証に失敗する(§5.2)",
            verify_key_hex=admin["sig_pub_hex"],
        ),
    ]

    # --- 認可系 negative: 署名・ハッシュ連鎖は正しいが §6.2 の権限規則で拒否すべき ---
    # kind = "authorization"。署名は有効(verify_reference.mjs は署名が通ることを確認し、
    # 実装テストはチェーン検証が expected_reason で失敗することを検査する)
    head12 = entries[11]["entry_hash_hex"]
    head6 = entries[5]["entry_hash_hex"]

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
        "authz-admin-grant-server", 13, head12, "grant_server", admin_id, admin,
        grant_payload, t0 + 12000, "insufficient-role",
        "grant_server は owner のみ。admin による正しく署名されたエントリでも拒否する",
    )
    add_authz(
        "authz-reader-rotate-epoch", 7, head6, "rotate_epoch", admin_id, admin,
        rotate_payload("env-prod-0001", 3),
        t0 + 6000, "insufficient-role",
        "seq 6 時点の user-admin-0003 は reader。rotate_epoch は member 以上のみ",
    )
    add_authz(
        "authz-nonmember-actor", 13, head12, "rotate_epoch", member_id, member,
        rotate_payload("env-prod-0001", 3),
        t0 + 12000, "actor-not-member",
        "seq 5 で削除済みの user-member-0002 はチェーンに追記できない(ゴーストメンバー対策)",
    )
    add_authz(
        "authz-remove-last-owner", 13, head12, "remove_member", owner_id, owner,
        {"target_user_id": owner_id}, t0 + 12000, "last-owner-protected",
        "最後の owner は削除不可(§6.2)",
    )
    add_authz(
        "authz-demote-last-owner", 13, head12, "change_role", owner_id, owner,
        {"target_user_id": owner_id, "new_role": "member"}, t0 + 12000, "last-owner-protected",
        "最後の owner は降格不可(§6.2)",
    )
    add_authz(
        "authz-admin-adds-admin", 13, head12, "add_member", admin_id, admin,
        {"target_user_id": member_id, "enc_pub_hex": member["enc_pub_hex"],
         "sig_pub_hex": member["sig_pub_hex"], "role": "admin"},
        t0 + 12000, "insufficient-role",
        "admin / owner ロールの付与は owner のみ(admin は reader / member のみ追加可)",
    )
    # 再 grant のスコープ縮小は拒否(2026-08-02 所有者裁定): 縮小は revoke_server +
    # rotate_epoch(§7 の全環境ローテーション義務)を経由させる。拡大(旧 ⊆ 新)のみ受理
    head9 = entries[8]["entry_hash_hex"]
    narrowed_scope = ["env-prod-0001"]
    add_authz(
        "authz-grant-scope-narrowed", 10, head9, "grant_server", owner_id, owner,
        dict(grant_payload, **{
            "scope_environments": narrowed_scope,
            "scope_environments_lp_hex": scope_environments_lp_hex(narrowed_scope),
        }),
        t0 + 9000, "grant-scope-narrowed",
        "有効な grant のスコープを狭める再 grant は owner 署名でも拒否する(§7 のローテーション義務を迂回させない)",
    )
    # 再 grant 規則の二層化(2026-08-12 — §6.3): 判定はフィールドごとに独立。
    # lease_policy を自由改訂(ここでは全削除)しても、scope 縮小は縮小のまま拒否される
    add_authz(
        "authz-grant-scope-narrowed-policy-revised", 10, head9, "grant_server",
        owner_id, owner,
        grant_payload_for(narrowed_scope, []),
        t0 + 9000, "grant-scope-narrowed",
        "scope 縮小 × lease_policy 全削除の再 grant も grant-scope-narrowed で拒否する(二層判定の独立性 — policy の改訂自由は scope 縮小を救済しない)",
    )
    # 検査順序の固定(role 規則 → 再 grant 規則): seq 9 時点の admin による
    # scope 縮小の再 grant は、再 grant 規則より先に role 規則で拒否される
    add_authz(
        "authz-grant-role-precedes-scope-narrowed", 10, head9, "grant_server",
        admin_id, admin,
        grant_payload_for(narrowed_scope, grant_lease_policy),
        t0 + 9000, "insufficient-role",
        "role 不足 × scope 縮小の複合違反は role 規則が先に判定される(§6.2 の検査順序: role → 再 grant 規則)",
    )

    # サーバー鍵の一意性(2026-08-12 — §6.2 duplicate-server-key): サーバー enc
    # 公開鍵が現メンバーの enc 公開鍵と一致する grant_server は拒否する
    # (「鍵 → 主体」逆引きの一意性の受信者クラス横断版)。head12 時点の現メンバー:
    # owner / admin。admin の enc 鍵をサーバー鍵として grant する形で固定する
    # (FP は SHA-256(enc_pub)[:16] のサーバー鍵定義 — §9 — で整合させ、
    # 拒否理由が payload 整合でなく鍵重複であることを保証する)
    admin_enc_as_server_fp = sha256(bytes.fromhex(admin["enc_pub_hex"]))[:16].hex()

    def duplicate_key_payload(scope: list, policy: list) -> dict:
        return {
            "server_enc_pub_hex": admin["enc_pub_hex"],
            "server_key_fingerprint_hex": admin_enc_as_server_fp,
            "scope_environments": scope,
            "scope_environments_lp_hex": scope_environments_lp_hex(scope),
            "lease_policy": policy,
            "lease_policy_lp_hex": lease_policy_lp_hex(policy),
        }

    add_authz(
        "authz-grant-duplicate-server-key", 13, head12, "grant_server", owner_id, owner,
        duplicate_key_payload(grant_scope, []),
        t0 + 12000, "duplicate-server-key",
        "現メンバー(user-admin-0003)の enc 公開鍵をサーバー鍵として grant するエントリは owner 署名でも拒否する(§6.2 サーバー鍵の一意性。空 lease_policy は形式として有効 = 拒否理由が鍵重複であることの保証)",
    )
    # 検査順序の固定(role 規則 → 鍵重複): admin による鍵重複 grant は
    # 鍵重複より先に role 規則で拒否される
    add_authz(
        "authz-grant-role-precedes-duplicate-server-key", 13, head12, "grant_server",
        admin_id, admin,
        duplicate_key_payload(grant_scope, []),
        t0 + 12000, "insufficient-role",
        "role 不足 × サーバー鍵重複の複合違反は role 規則が先に判定される(§6.2 の検査順序: role → 鍵重複)",
    )

    # lease_policy のサイズ上限(§6.2 — 合意規則): issuer 要素 8 以下、
    # issuer あたり claim 制約 8 以下。超過は payload 構造検査(invalid-payload)
    def dummy_policy_elements(count: int) -> list:
        return [
            {
                "issuer_url": f"https://issuer-{i:02d}.example.com",
                "audience": "https://maruhi-dogfood.example.com",
                "claim_constraints": [
                    {"claim_name": "sub", "claim_value": f"repo:acme-dummy/repo-{i:02d}"},
                ],
            }
            for i in range(count)
        ]

    oversized_policy = dummy_policy_elements(9)
    add_authz(
        "authz-grant-lease-policy-too-many", 13, head12, "grant_server", owner_id, owner,
        grant_payload_for(grant_scope, oversized_policy),
        t0 + 12000, "invalid-payload",
        "lease_policy が 9 要素(上限 8 超過)のエントリは署名が有効でも拒否する",
    )
    oversized_claims_policy = [
        {
            "issuer_url": "https://token.actions.githubusercontent.com",
            "audience": "https://maruhi-dogfood.example.com",
            "claim_constraints": [
                {"claim_name": f"claim-{i:02d}", "claim_value": f"value-{i:02d}"}
                for i in range(9)
            ],
        },
    ]
    add_authz(
        "authz-grant-lease-claims-too-many", 13, head12, "grant_server", owner_id, owner,
        grant_payload_for(grant_scope, oversized_claims_policy),
        t0 + 12000, "invalid-payload",
        "1 要素の claim 制約が 9 件(上限 8 超過)のエントリは拒否する",
    )
    add_authz(
        "grant-lease-policy-too-many-precedes-role", 13, head12, "grant_server",
        admin_id, admin,
        grant_payload_for(grant_scope, oversized_policy),
        t0 + 12000, "invalid-payload",
        "サイズ上限違反 × role 不足(admin)の複合違反は構造検査が先に判定される(検証段順: 構造 → 認可。create-env-commitment-format-precedes-role と同型)",
    )

    # --- 拡張チェーン: 「再 grant 規則 → 鍵重複」の順序固定に要る前提状態 ------------
    # 「有効 grant があり、かつサーバー enc 鍵が現メンバーの enc 鍵と一致する」状態は、
    # grant(seq 9)の後にサーバー enc 鍵を流用したメンバーを追加することでのみ作れる
    # (逆順は duplicate-server-key が先に grant を拒否する)。この add_member 自体は
    # 現行の合意規則で**有効**である: §6.2 のメンバー鍵一意性の索引は現メンバーの鍵のみで、
    # 有効 grant のサーバー鍵は対象外(仕様の明示的な線引き — 逆方向の衝突禁止は §6.2 の
    # 「注意」の先送り事項のまま)。value-signature.json の tenure_extension と同じ
    # 「派生チェーン」の運び方で、chain-entries 本体の正規チェーンは変更しない
    sock_sig_sk = Ed25519PrivateKey.from_private_bytes(pat(0xB0, 32))
    sock_sig_pub = sock_sig_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sock_fp = sha256(bytes.fromhex(server["enc_pub_hex"]) + sock_sig_pub)[:16]
    sock = {
        "sig_sk": sock_sig_sk,
        "enc_pub_hex": server["enc_pub_hex"],  # サーバー enc 鍵の流用(意図的)
        "sig_pub_hex": sock_sig_pub.hex(),
        "fp_hex": sock_fp.hex(),
    }
    sock_id = "user-sock-0006"
    sock_add_entry = build_entry(
        10, "add_member", owner_id, owner,
        {"target_user_id": sock_id, "enc_pub_hex": sock["enc_pub_hex"],
         "sig_pub_hex": sock["sig_pub_hex"], "role": "reader"},
        t0 + 9000, head9,
    )
    extended_chains = {
        "server-key-member-sock": {
            "description": (
                "正規チェーン seq 1〜9(grant 有効)に、サーバー enc 鍵を流用したメンバー"
                "(user-sock-0006)の add_member を追記した派生チェーン。この追記は現行の"
                "合意規則で有効(§6.2 のメンバー鍵一意性はメンバー鍵のみを索引し、"
                "grant_server のサーバー鍵は対象外)。「有効 grant × サーバー鍵 = メンバー鍵」"
                "の状態を作り、再 grant 規則 → duplicate-server-key の検査順序を固定する"
            ),
            "base_seq": 9,
            "entries": [sock_add_entry],
            "keys": {
                sock_id: {
                    "enc_sk_seed_hex": pat(0x90, 32).hex(),  # = server_key の seed(流用)
                    "sig_sk_seed_hex": pat(0xB0, 32).hex(),
                    "enc_pub_hex": sock["enc_pub_hex"],
                    "sig_pub_hex": sock["sig_pub_hex"],
                    "key_fingerprint_hex": sock["fp_hex"],
                },
            },
            "expected_members": {owner_id: "owner", admin_id: "admin", sock_id: "reader"},
        },
    }
    sock_head = sock_add_entry["entry_hash_hex"]

    def add_extended_authz(name, seq, prev_hex, payload, expected_reason, note):
        entry = build_entry(seq, "grant_server", owner_id, owner, payload, t0 + 10000, prev_hex)
        case = authz(name, entry, expected_reason, note)
        case["verify_key_hex"] = owner["sig_pub_hex"]
        case["chain"] = "server-key-member-sock"
        authz_cases.append(case)

    add_extended_authz(
        "authz-grant-narrowed-precedes-duplicate-key", 11, sock_head,
        grant_payload_for(narrowed_scope, grant_lease_policy),
        "grant-scope-narrowed",
        "scope 縮小 × サーバー鍵重複(sock メンバーが同鍵を保持)の複合違反は再 grant 規則が先に判定される(§6.2 の検査順序: 再 grant 規則 → 鍵重複)",
    )
    add_extended_authz(
        "authz-grant-duplicate-key-on-regrant", 11, sock_head,
        grant_payload_for(grant_scope, []),
        "duplicate-server-key",
        "scope 不変(再 grant 規則は通過)でも、サーバー鍵が現メンバーの鍵と重複していれば拒否する(lease_policy の改訂自由は鍵重複検査を迂回しない)",
    )

    # 環境ライフサイクルのチェーン束縛(2026-08-03 — CRYPTO_SPEC §6.2):
    # create_environment の environment_id はチェーン履歴全体で一意
    # (duplicate-environment)、rotate_epoch は create_environment の先行が必須
    # (unknown-environment)。認可段の検査順序は role → duplicate / unknown →
    # エポック順序(理由コードごと本ベクターで固定する)
    add_authz(
        "authz-create-env-duplicate", 13, head12, "create_environment", owner_id, owner,
        create_env_payload("env-prod-0001"),
        t0 + 12000, "duplicate-environment",
        "作成済み environment_id の再作成は拒否する(履歴全体一意 — データプレーンで削除済みの ID の再作成も、チェーンは削除を観測しないため同じ理由で拒否される)",
    )
    add_authz(
        "authz-rotate-unknown-environment", 13, head12, "rotate_epoch", admin_id, admin,
        rotate_payload("env-ghost-9999", 2),
        t0 + 12000, "unknown-environment",
        "create_environment が先行しない環境への rotate は拒否する。new_epoch = 2 は旧意味論(未観測 = 1 + 1)なら受理された値であり、既定値フォールバック実装はここで落ちる",
    )
    add_authz(
        "authz-rotate-unknown-precedes-epoch", 13, head12, "rotate_epoch", admin_id, admin,
        rotate_payload("env-ghost-9999", 7),
        t0 + 12000, "unknown-environment",
        "未知環境 × 不正エポックの複合違反は unknown-environment が先に判定される(認可段の検査順序: duplicate / unknown → エポック順序)",
    )
    add_authz(
        "authz-create-env-reader", 7, head6, "create_environment", admin_id, admin,
        create_env_payload("env-reader-blocked-0008"),
        t0 + 6000, "insufficient-role",
        "seq 6 時点の user-admin-0003 は reader。create_environment は member 以上のみ",
    )
    add_authz(
        "authz-create-env-role-precedes-duplicate", 7, head6, "create_environment",
        admin_id, admin,
        create_env_payload("env-prod-0001"),
        t0 + 6000, "insufficient-role",
        "role 不足 × ID 重複の複合違反は role 規則が先に判定される(認可段の検査順序: role → duplicate-environment)",
    )
    add_authz(
        "authz-rotate-role-precedes-unknown", 7, head6, "rotate_epoch", admin_id, admin,
        rotate_payload("env-ghost-9999", 2),
        t0 + 6000, "insufficient-role",
        "role 不足 × 未知環境の複合違反は role 規則が先に判定される(認可段の検査順序: role → unknown-environment)",
    )

    # エポック順序規則(2026-08-02 所有者裁定・案 3。2026-08-03 の §6.2 環境ライフ
    # サイクル束縛に追随): エポックは create_environment で 1 に始まる環境ごとの
    # カウンタで、rotate_epoch は必ず +1。巻き戻し(削除済みメンバー保持の旧 DEK
    # への再露出)・重複・ジャンプ(member 権限 1 署名でのエポック空間焼き尽くし
    # DoS)をすべて拒否する。head12 時点の現エポック: env-prod-0001 = 2,
    # env-dev-0002 = 2, env-stage-0003 = 1(未ローテーション)
    for name, env, bad_epoch, note in [
        ("authz-epoch-rollback", "env-prod-0001", 1,
         "現エポック(2)からの巻き戻しは拒否する"),
        ("authz-epoch-duplicate", "env-prod-0001", 2,
         "現エポックと同値の rotate は拒否する(期待値は 3)"),
        ("authz-epoch-jump", "env-prod-0001", 10,
         "エポックのジャンプは拒否する(期待値は 3。焼き尽くし DoS 対策)"),
        ("authz-epoch-first-jump", "env-stage-0003", 5,
         "create_environment 直後(エポック 1)の環境の初回 rotate は 2 のみ受理する"),
    ]:
        # 誤エポックのコミットメントは「その環境のエポック 2 用 DEK」で計算する
        # (形式は有効。拒否理由がコミットメントでなくエポック順序であることを固定)
        payload = {
            "environment_id": env,
            "new_epoch": str(bad_epoch),
            "reason": "scheduled",
            "dek_commitment_hex": dek_commitment_hex(
                project_id, env, bad_epoch, environment_deks[env][2]
            ),
        }
        add_authz(
            name, 13, head12, "rotate_epoch", admin_id, admin,
            payload, t0 + 12000, "epoch-out-of-sequence", note,
        )

    # dek_commitment_hex の形式違反(大文字 hex・長さ不正)は payload 構造検査の
    # negative(§6.2 — 既存の検証段順「構造 → actor → 署名 → 認可」の構造段に属し、
    # 認可判定に先行する)。署名は有効(署名対象は形式違反の文字列そのもの)
    fresh_commit = commit("env-fresh-0004", 1)
    add_authz(
        "create-env-commitment-uppercase-hex", 13, head12, "create_environment",
        owner_id, owner,
        {"environment_id": "env-fresh-0004", "dek_commitment_hex": fresh_commit.upper()},
        t0 + 12000, "invalid-payload",
        "dek_commitment_hex の大文字 hex は payload 構造検査で拒否する(hex 小文字 64 文字が正規形 — §6.2)",
    )
    add_authz(
        "create-env-commitment-bad-length", 13, head12, "create_environment",
        owner_id, owner,
        {"environment_id": "env-fresh-0004", "dek_commitment_hex": fresh_commit[:62]},
        t0 + 12000, "invalid-payload",
        "dek_commitment_hex の長さ不正(62 文字)は payload 構造検査で拒否する",
    )
    add_authz(
        "rotate-commitment-uppercase-hex", 13, head12, "rotate_epoch", admin_id, admin,
        dict(rotate_payload("env-prod-0001", 3), dek_commitment_hex=commit("env-prod-0001", 2).upper()),
        t0 + 12000, "invalid-payload",
        "rotate_epoch の dek_commitment_hex の大文字 hex も payload 構造検査で拒否する",
    )
    add_authz(
        "create-env-commitment-format-precedes-role", 7, head6, "create_environment",
        admin_id, admin,
        {"environment_id": "env-reader-blocked-0008",
         "dek_commitment_hex": commit("env-reader-blocked-0008", 1).upper()},
        t0 + 6000, "invalid-payload",
        "形式違反 × role 不足(seq 6 時点の reader)の複合違反は構造検査が先に判定される(検証段順: 構造 → 認可)",
    )

    # フィールドサイズ上限(2026-08-02 所有者裁定・案 2): 自由文字列フィールドは
    # UTF-8 で 1024 バイト以下、scope_environments は 256 要素以下。超過は無効
    # (巨大 payload による検証クライアントの資源消費対策。上限は合意規則なので
    # ベクターで固定する)。署名は有効だが形状検証(invalid-payload)で拒否すべき
    add_authz(
        "authz-field-too-long", 13, head12, "rotate_epoch", admin_id, admin,
        dict(rotate_payload("env-prod-0001", 3), reason="x" * 1025),
        t0 + 12000, "invalid-payload",
        "reason が 1025 バイト(上限 1024 超過)のエントリは署名が有効でも拒否する",
    )
    oversized_scope = [f"env-bulk-{i:04d}" for i in range(257)]
    add_authz(
        "authz-scope-too-many", 13, head12, "grant_server", owner_id, owner,
        dict(grant_payload, **{
            "scope_environments": oversized_scope,
            "scope_environments_lp_hex": scope_environments_lp_hex(oversized_scope),
        }),
        t0 + 12000, "invalid-payload",
        "scope_environments が 257 要素(上限 256 超過)のエントリは拒否する",
    )

    # メンバー鍵の一意性(CRYPTO_SPEC §6.2。2026-08-03 決定 — セッション 10):
    # add_member は対象の enc / sig 公開鍵のいずれかが現メンバー集合の同種鍵と
    # 一致する場合に拒否する(duplicate-member-key)。判定は個別鍵単位 — 片方の
    # 鍵だけを流用したソック垢も拒否する(FP = enc‖sig の一致判定ではない)。
    # head12 時点の現メンバー: user-owner-0001(owner)/ user-admin-0003(admin)。
    # actor は owner(role 規則を通過)・target_user_id は新規(duplicate-member を
    # 通過)にし、鍵重複の検査だけで拒否されるエントリにする
    clone = make_user(pat(0x70, 32), pat(0x80, 32))  # 流用しない側の新鮮な鍵
    for name, enc_hex, sig_hex, note in [
        ("authz-add-member-duplicate-key", admin["enc_pub_hex"], admin["sig_pub_hex"],
         "現メンバー(user-admin-0003)の enc / sig 鍵一式を流用した別 user_id の追加は拒否する(鍵流用ソック垢)"),
        ("authz-add-member-duplicate-enc-key", admin["enc_pub_hex"], clone["sig_pub_hex"],
         "enc 公開鍵だけが現メンバーと一致する追加も拒否する(判定は個別鍵単位)"),
        ("authz-add-member-duplicate-sig-key", clone["enc_pub_hex"], admin["sig_pub_hex"],
         "sig 公開鍵だけが現メンバーと一致する追加も拒否する(判定は個別鍵単位)"),
        ("authz-add-member-duplicate-owner-key", owner["enc_pub_hex"], owner["sig_pub_hex"],
         "genesis 由来の owner の鍵一式の流用も拒否する(genesis もメンバー鍵索引の対象 — レビューループ 1 [高])"),
    ]:
        add_authz(
            name, 13, head12, "add_member", owner_id, owner,
            {"target_user_id": "user-clone-0004", "enc_pub_hex": enc_hex,
             "sig_pub_hex": sig_hex, "role": "member"},
            t0 + 12000, "duplicate-member-key", note,
        )
    # 検査順序の固定(role 規則 → 鍵重複): actor = admin が現メンバー鍵を流用した
    # 対象に role "admin" を付与しようとするエントリは、鍵重複より先に role 規則で
    # 拒否される(insufficient-role。duplicate-member-key ではない)
    add_authz(
        "authz-add-member-role-precedes-duplicate-key", 13, head12, "add_member",
        admin_id, admin,
        {"target_user_id": "user-clone-0004", "enc_pub_hex": owner["enc_pub_hex"],
         "sig_pub_hex": owner["sig_pub_hex"], "role": "admin"},
        t0 + 12000, "insufficient-role",
        "role 規則(admin/owner 付与は owner のみ)は鍵重複検査より先に判定される(§6.2 の検査順序の固定)",
    )
    # 検査順序の固定(user_id 重複 → 鍵重複): 対象 user_id と鍵の両方が重複する
    # エントリは duplicate-member で拒否される(duplicate-member-key ではない)
    add_authz(
        "authz-add-member-duplicate-user-precedes-key", 13, head12, "add_member",
        owner_id, owner,
        {"target_user_id": admin_id, "enc_pub_hex": owner["enc_pub_hex"],
         "sig_pub_hex": owner["sig_pub_hex"], "role": "member"},
        t0 + 12000, "duplicate-member",
        "対象 user_id の重複は鍵重複検査より先に判定される(§6.2 の検査順序の固定)",
    )

    # actor の申告 FP・署名鍵が「チェーンに登録された actor の鍵」と一致しない偽装。
    # member の鍵で署名し FP も member のものだが、user_id は owner を騙る
    impostor = build_entry(13, "rotate_epoch", owner_id, member,
                           rotate_payload("env-prod-0001", 3), t0 + 12000, head12)
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

    # --- 有効な追記の positive(合意規則の許容側の境界を固定する)-------------------
    # (1) メンバー鍵一意性(§6.2)の禁止範囲が「現メンバー集合のみ」であることの固定:
    #     削除済みメンバー(seq 5 の user-member-0002)の鍵は現集合に属さないため、
    #     同一 user_id での復帰も、別 user_id での再利用も拒否されない。
    #     「履歴全体との重複禁止」を誤って実装した検証器はここで落ちる
    # (2) 環境ライフサイクル(§6.2)の許容側: 未使用 ID の create_environment と、
    #     create 済み環境(エポック 1)への初回 rotate(new_epoch 2)は受理される。
    #     チェーンは環境の削除を観測しない(データプレーンの tombstone 後も
    #     duplicate-environment のまま)ため、「削除後の再作成」の許容側は
    #     「別 ID での作成が有効」がその全体である
    base_environments = {
        "env-prod-0001": "2",
        "env-dev-0002": "2",
        "env-stage-0003": "1",
    }

    # grant_seq(2026-08-15 / Wave 2 A2): 当該サーバー鍵の**有効 grant を確立した
    # エントリの seq**。再 grant では最新の grant_server エントリの seq に置き換わる。
    # AUDIT_SPEC §3.5 の server.lease_issued payload の grant_chain_seq は
    # この導出値が唯一の出所であり(サーバー側で再 grant 二層規則を再実装しない
    # ため)、導出状態の一部としてベクターで固定する
    def grant_state(scope: list, policy: list, grant_seq: int) -> dict:
        return {
            "server_key_fingerprint_hex": server["fp_hex"],
            "server_enc_pub_hex": server["enc_pub_hex"],
            "scope_environments": scope,
            "lease_policy": policy,
            "grant_seq": grant_seq,
        }

    valid_appends = [
        {
            "name": "readd-removed-member-same-key",
            "entry": build_entry(13, "add_member", owner_id, owner,
                                 {"target_user_id": member_id,
                                  "enc_pub_hex": member["enc_pub_hex"],
                                  "sig_pub_hex": member["sig_pub_hex"],
                                  "role": "member"},
                                 t0 + 12000, head12),
            "expected_members": {owner_id: "owner", admin_id: "admin", member_id: "member"},
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "note": "削除済みメンバーを同一 user_id・同一鍵で再追加する(同一人物の復帰)は受理される(§6.2 の禁止範囲は現メンバー集合のみ)",
        },
        {
            "name": "reuse-removed-member-key-new-user",
            "entry": build_entry(13, "add_member", owner_id, owner,
                                 {"target_user_id": "user-newcomer-0005",
                                  "enc_pub_hex": member["enc_pub_hex"],
                                  "sig_pub_hex": member["sig_pub_hex"],
                                  "role": "member"},
                                 t0 + 12000, head12),
            "expected_members": {owner_id: "owner", admin_id: "admin",
                                 "user-newcomer-0005": "member"},
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "note": "削除済みメンバーの鍵を別 user_id で再登録することも拒否されない(admin/owner の add_member 権限内の行為と等価 — §6.2)",
        },
        {
            "name": "create-environment-fresh-id",
            "entry": build_entry(13, "create_environment", owner_id, owner,
                                 create_env_payload("env-fresh-0004"), t0 + 12000, head12),
            "expected_members": {owner_id: "owner", admin_id: "admin"},
            "expected_environments": dict(base_environments, **{"env-fresh-0004": "1"}),
            "expected_server_grants": [],
            "note": "未使用 ID の create_environment は受理され、環境はエポック 1 で環境集合に加わる(§6.2)",
        },
        {
            "name": "rotate-freshly-created-environment",
            "entry": build_entry(13, "rotate_epoch", admin_id, admin,
                                 rotate_payload("env-stage-0003", 2), t0 + 12000, head12),
            "expected_members": {owner_id: "owner", admin_id: "admin"},
            "expected_environments": dict(base_environments, **{"env-stage-0003": "2"}),
            "expected_server_grants": [],
            "note": "create_environment 済み(エポック 1)の環境への初回 rotate(new_epoch 2)は受理される(create → rotate の境界)",
        },
        {
            # 再 grant 二層規則の受理側(2026-08-12 — §6.3): scope 不変のまま
            # lease_policy を縮小(ここでは全削除 = 空リスト)する再 grant は受理され、
            # 導出状態の lease_policy が置換される。ポリシーはリース経路の ACL であり
            # 既知 DEK 集合を変えないため、締め付けに全環境ローテーションを課さない
            "name": "regrant-lease-policy-revised",
            "entry": build_entry(10, "grant_server", owner_id, owner,
                                 grant_payload_for(grant_scope, []), t0 + 9000, head9),
            "expected_members": {owner_id: "owner", admin_id: "admin"},
            "expected_environments": {"env-prod-0001": "2", "env-dev-0002": "1"},
            # grant_seq は再 grant エントリ自身の seq(10)へ前進する — 有効 grant を
            # 確立したエントリが置き換わるため(seq 9 のままにする実装はここで落ちる)
            "expected_server_grants": [grant_state(grant_scope, [], 10)],
            "note": "scope 不変 × lease_policy 全削除の再 grant は受理され、ポリシーが空(リース経路なし)へ置換される(§6.3 再 grant 二層化の受理側。seq 9 のヘッドへの追記)。導出 grant_seq は再 grant エントリの seq へ前進する",
        },
    ]

    # --- 検証済みチェーンから導出される状態の期待値(実装の導出 API を固定する)------
    # 2026-08-03(§6.2 / §6.3): 環境の存在・エポック開始 seq・エポックごとの DEK
    # コミットメントがチェーン導出値になった。「未観測なら初期値 1」の既定値は廃止
    # (チェーンに create_environment がない環境は環境集合に存在しない)
    def env_state(environment_id, current_epoch, created_at_seq, epoch_start_seqs):
        return {
            "current_epoch": str(current_epoch),
            "created_at_seq": created_at_seq,
            "epoch_start_seqs": {str(epoch): seq for epoch, seq in epoch_start_seqs.items()},
            "dek_commitments": {
                str(epoch): commit(environment_id, epoch) for epoch in epoch_start_seqs
            },
        }

    expected_head_states = [
        {
            "after_seq": 5,
            "members": {owner_id: "owner"},
            "server_grants": [],
            "environments": {
                "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
            },
        },
        {
            "after_seq": 9,
            "members": {owner_id: "owner", admin_id: "admin"},
            "server_grants": [grant_state(grant_scope, grant_lease_policy, 9)],
            "environments": {
                "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
                "env-dev-0002": env_state("env-dev-0002", 1, 8, {1: 8}),
            },
        },
        {
            "after_seq": 12,
            "members": {owner_id: "owner", admin_id: "admin"},
            "server_grants": [],
            "environments": {
                "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
                "env-dev-0002": env_state("env-dev-0002", 2, 8, {1: 8, 2: 10}),
                "env-stage-0003": env_state("env-stage-0003", 1, 11, {1: 11}),
            },
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
                "lease_policy": "constraint = LP(claim_name, claim_value)、element = LP(issuer_url, audience, LP(constraint...))、lease_policy_lp_hex = lower_hex(LP(element...))(3 段の入れ子 LP — §6.2)。リスト順(要素・制約とも)は署名対象の一部。空リストは hex 空文字列 = リース経路なし。上限: 要素 8 / 要素あたり制約 8 / 各文字列 1024 バイト(§6.1)→ 要レビュー",
                "dek_commitment": "dek_commitment_hex = lower_hex(SHA-256(LP(\"maruhi/v1/dek-commit\", project_id, environment_id, epoch, dek_hex)))(§5.2)。project_id = genesis エントリハッシュ。形式は hex 小文字 64 文字(形式検査は payload 構造検査の段 — §6.2)。内容の照合は受信者の §5.2 検証が担い、チェーン検証は形式のみ検査する",
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
            # 各 (environment, epoch) のダミー DEK と §5.2 コミットメント。
            # チェーン payload の dek_commitment_hex はここから計算した実値で、
            # 実装テストは「DEK → コミットメント再計算 → チェーン掲載値と一致」の
            # §5.2 照合まで検査できる(negative は dek-commitment.json 側)
            "environment_deks": {
                environment_id: {
                    str(epoch): {
                        "dek_hex": dek.hex(),
                        "dek_commitment_hex": dek_commitment_hex(
                            project_id, environment_id, epoch, dek
                        ),
                    }
                    for epoch, dek in per_env.items()
                }
                for environment_id, per_env in environment_deks.items()
            },
            "entries": entries,
            "expected_head_states": expected_head_states,
            "valid_appends": valid_appends,
            "extended_chains": extended_chains,
            "negative": negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.5 dek-wrap-signature.json — §5.1 DEK ラップの登録署名(Ed25519 + §2.1 LP)
#
# signed_bytes = LP(domain, project_id, environment_id, epoch, recipient_user_id,
#                   recipient_enc_pub_hex, enc_hex, ciphertext_hex, signer_user_id)
#   domain = "<suite>/dek-wrap-sig"(suite の束縛はドメイン文字列が担う — §5 info と同型)
#   バイナリ列(受信者 enc 公開鍵 / HPKE enc / ラップ暗号文)は grant_server の
#   scope_environments と同じく hex 小文字文字列として LP に載せる
#   signer_user_id は署名者自身の内部 user_id(チェーンが同一鍵の複数メンバーを
#   許すため、鍵流用による帰属の付け替えを塞ぐ — §5.1)
# ラップ本体(enc/ct/受信者鍵)は dek-wrap.json の basic ベクターを読み込んで使う
# (ラップ → 登録署名が一続きの実データになる)。署名者は chain-entries.json の
# user-owner-0001 / user-member-0002 と同一のダミー鍵

SIGNED_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "epoch", "recipient_user_id",
    "recipient_enc_pub_hex", "enc_hex", "ciphertext_hex", "signer_user_id",
]


def wrap_signature_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([
        ctx["domain"], ctx["project_id"], ctx["environment_id"], ctx["epoch"],
        ctx["recipient_user_id"], ctx["recipient_enc_pub_hex"],
        ctx["enc_hex"], ctx["ciphertext_hex"], ctx["signer_user_id"],
    ])


def gen_dek_wrap_signature():
    with open(os.path.join(OUT_DIR, "dek-wrap.json"), encoding="utf-8") as fh:
        dek_wrap = json.load(fh)
    wrap = dek_wrap["vectors"][0]

    owner = make_user(pat(0x10, 32), pat(0x20, 32))     # = chain-entries user-owner-0001
    member = make_user(pat(0x30, 32), pat(0x40, 32))    # = chain-entries user-member-0002

    base_ctx = {
        "suite": "maruhi/v1",
        "domain": "maruhi/v1/dek-wrap-sig",
        "project_id": wrap["project_id"],
        "environment_id": wrap["environment_id"],
        "epoch": wrap["epoch"],
        "recipient_user_id": wrap["recipient_user_id"],
        "recipient_enc_pub_hex": dek_wrap["recipient_keypair"]["pkRm_hex"],
        "enc_hex": wrap["enc_hex"],
        "ciphertext_hex": wrap["ciphertext_hex"],
        "signer_user_id": "user-owner-0001",
    }
    base_signed = wrap_signature_signed_bytes(base_ctx)
    base_sig = owner["sig_sk"].sign(base_signed)

    tampered_ct = bytearray(bytes.fromhex(base_ctx["ciphertext_hex"]))
    tampered_ct[-1] ^= 0x01
    tampered_enc = bytearray(bytes.fromhex(base_ctx["enc_hex"]))
    tampered_enc[0] ^= 0x01
    tampered_sig = bytearray(base_sig)
    tampered_sig[-1] ^= 0x01

    def negative(name, overrides, verify_key_hex, note, signature=None):
        # overrides を適用した文脈で signed_bytes を再構築し、「元の署名」
        # (signature 指定時はその署名)を検証 → 失敗すべき
        ctx = dict(base_ctx, **overrides)
        return {
            "name": name,
            "base": "basic",
            "context": ctx,
            "verify_signed_bytes_hex": wrap_signature_signed_bytes(ctx).hex(),
            "signature_hex": (signature if signature is not None else base_sig).hex(),
            "verify_key_hex": verify_key_hex,
            "must_fail": True,
            "note": note,
        }

    negatives = [
        negative(
            "tampered-signature",
            {},
            owner["sig_pub_hex"],
            "署名バイト自体の末尾 1 bit 反転は検証に失敗する",
            signature=bytes(tampered_sig),
        ),
        negative(
            "tampered-ciphertext",
            {"ciphertext_hex": bytes(tampered_ct).hex()},
            owner["sig_pub_hex"],
            "ラップ暗号文の末尾 1 bit 反転(毒ラップへの差し替え)は署名検証に失敗する",
        ),
        negative(
            "tampered-enc",
            {"enc_hex": bytes(tampered_enc).hex()},
            owner["sig_pub_hex"],
            "HPKE encapsulated key の改竄は署名検証に失敗する",
        ),
        negative(
            "transplant-project",
            {"project_id": "proj-0002"},
            owner["sig_pub_hex"],
            "別プロジェクトへの座標移植は署名検証に失敗する",
        ),
        negative(
            "transplant-environment",
            {"environment_id": "env-dev-0002"},
            owner["sig_pub_hex"],
            "別環境への座標移植は署名検証に失敗する",
        ),
        negative(
            "transplant-epoch",
            {"epoch": 4},
            owner["sig_pub_hex"],
            "別エポックへの座標移植は署名検証に失敗する",
        ),
        negative(
            "transplant-recipient",
            {"recipient_user_id": "user-owner-0001"},
            owner["sig_pub_hex"],
            "別受信者への座標移植は署名検証に失敗する",
        ),
        negative(
            "recipient-key-mismatch",
            {"recipient_enc_pub_hex": owner["enc_pub_hex"]},
            owner["sig_pub_hex"],
            "受信者 enc 公開鍵の差し替えは署名検証に失敗する(recipient_enc_pub_hex も署名対象)",
        ),
        negative(
            "wrong-signer-key",
            {},
            member["sig_pub_hex"],
            "署名者以外の鍵では検証に失敗する(呼び出し主体 = 署名者の受理条件を支える)",
        ),
        negative(
            "transplant-signer",
            {"signer_user_id": "user-member-0002"},
            owner["sig_pub_hex"],
            "署名者 user_id の差し替えは同一鍵でも検証に失敗する(鍵流用ソック垢への帰属付け替え対策 — §5.1)",
        ),
        negative(
            "suite-mismatch",
            {"suite": "maruhi/v2", "domain": "maruhi/v2/dek-wrap-sig"},
            owner["sig_pub_hex"],
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
    ]

    # --- 受信者クラス server(CRYPTO_SPEC §9 / AUTH_SPEC §12-6。2026-08-12)---------
    # サーバー宛ラップの登録署名: signed_bytes の recipient_user_id 位置には
    # サーバー鍵 FP(hex 小文字)を用いる(HPKE info と同じ置き換え — §9)。
    # recipient_enc_pub_hex はサーバー enc 公開鍵。ラップ本体は dek-wrap.json の
    # server-basic ベクターと同一(ラップ → 登録署名が一続きの実データ)
    server_wrap = next(v for v in dek_wrap["vectors"] if v["name"] == "server-basic")
    server_ctx = {
        "suite": "maruhi/v1",
        "domain": "maruhi/v1/dek-wrap-sig",
        "project_id": server_wrap["project_id"],
        "environment_id": server_wrap["environment_id"],
        "epoch": server_wrap["epoch"],
        "recipient_user_id": server_wrap["server_key_fingerprint_hex"],
        "recipient_enc_pub_hex": dek_wrap["server_keypair"]["pkSm_hex"],
        "enc_hex": server_wrap["enc_hex"],
        "ciphertext_hex": server_wrap["ciphertext_hex"],
        "signer_user_id": "user-owner-0001",
    }
    server_signed = wrap_signature_signed_bytes(server_ctx)
    server_sig = owner["sig_sk"].sign(server_signed)

    def server_negative(name, overrides, note):
        ctx = dict(server_ctx, **overrides)
        return {
            "name": name,
            "base": "server-basic",
            "context": ctx,
            "verify_signed_bytes_hex": wrap_signature_signed_bytes(ctx).hex(),
            "signature_hex": server_sig.hex(),
            "verify_key_hex": owner["sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    wrong_server_fp_first_byte = bytes.fromhex(server_wrap["server_key_fingerprint_hex"])[0] ^ 0x01
    wrong_server_fp = (
        f"{wrong_server_fp_first_byte:02x}{server_wrap['server_key_fingerprint_hex'][2:]}"
    )
    negatives += [
        server_negative(
            "server-transplant-recipient-class",
            {"recipient_user_id": wrap["recipient_user_id"]},
            "recipient 位置をサーバー鍵 FP からメンバー user_id へ差し替えると署名検証に失敗する(受信者クラス間の移植拒否 — §9)",
        ),
        server_negative(
            "server-transplant-fp",
            {"recipient_user_id": wrong_server_fp},
            "別サーバー鍵の FP への差し替えは署名検証に失敗する",
        ),
        server_negative(
            "server-recipient-key-mismatch",
            {"recipient_enc_pub_hex": dek_wrap["recipient_keypair"]["pkRm_hex"]},
            "サーバー enc 公開鍵の差し替え(メンバー鍵へ)は署名検証に失敗する(recipient_enc_pub_hex も署名対象)",
        ),
    ]

    write(
        "dek-wrap-signature.json",
        {
            # description の LP 列挙から signer_user_id が欠落していた(signed_fields_order は
            # 当初から正しい)。セッション 12 §13 の申し送りどおり PR-2 で修正(2026-08-04)
            "description": "CRYPTO_SPEC §5.1: DEK ラップの登録署名(Ed25519)。signed_bytes = LP(\"<suite>/dek-wrap-sig\", project_id, environment_id, epoch, recipient_user_id, recipient_enc_pub_hex, enc_hex, ciphertext_hex, signer_user_id)。ラップ本体は dek-wrap.json の basic ベクターと同一",
            "signed_fields_order": SIGNED_FIELDS_ORDER,
            "binary_encoding": "受信者 enc 公開鍵 / HPKE enc / ラップ暗号文は hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)",
            "signer": {
                "user_id": "user-owner-0001",
                "sig_sk_seed_hex": pat(0x20, 32).hex(),
                "sig_pub_hex": owner["sig_pub_hex"],
                "key_fingerprint_hex": owner["fp_hex"],
                "note": "chain-entries.json の user-owner-0001 と同一のダミー鍵",
            },
            "wrong_signer": {
                "user_id": "user-member-0002",
                "sig_pub_hex": member["sig_pub_hex"],
                "note": "wrong-signer-key negative 用(chain-entries.json の user-member-0002)",
            },
            "server_recipient_note": "受信者クラス server(§9 / AUTH_SPEC §12-6。2026-08-12): recipient_user_id 位置にサーバー鍵 FP(hex 小文字)、recipient_enc_pub_hex にサーバー enc 公開鍵。server-basic とその負例が固定する",
            "vectors": [
                dict(
                    base_ctx,
                    name="basic",
                    signed_bytes_hex=base_signed.hex(),
                    signature_hex=base_sig.hex(),
                ),
                dict(
                    server_ctx,
                    name="server-basic",
                    recipient_class="server",
                    signed_bytes_hex=server_signed.hex(),
                    signature_hex=server_sig.hex(),
                ),
            ],
            "negative": negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.6 dek-commitment.json — §5.2 エポック DEK のコミットメント(SHA-256 + §2.1 LP)
#
# dek_commitment_hex = lower_hex(SHA-256(LP("<suite>/dek-commit",
#                                           project_id, environment_id, epoch, dek_hex)))
#   domain = "<suite>/dek-commit"(suite の束縛はドメイン文字列が担う — §5.1 と同型)
#   dek_hex = DEK 32 バイトの hex 小文字文字列(binary_encoding 規約)
# 基本ベクターの DEK・座標は dek-wrap.json の basic と同一(ラップ → コミットメント
# 照合が一続きの実データになる)。コミットメントは受信者集合・ラップ暗号文に
# 依存しない(§5.2 — backfill・修復再登録・HPKE ランダム性・受信者集合の事後拡大の
# すべてに不変)ことを rewrap_invariance が固定する

COMMITMENT_FIELDS_ORDER = ["domain", "project_id", "environment_id", "epoch", "dek_hex"]


def commitment_preimage(ctx: dict) -> bytes:
    return lp_encode([
        ctx["domain"], ctx["project_id"], ctx["environment_id"], ctx["epoch"], ctx["dek_hex"],
    ])


def gen_dek_commitment():
    with open(os.path.join(OUT_DIR, "dek-wrap.json"), encoding="utf-8") as fh:
        dek_wrap = json.load(fh)
    wrap = dek_wrap["vectors"][0]

    base_ctx = {
        "suite": "maruhi/v1",
        "domain": DEK_COMMIT_DOMAIN,
        "project_id": wrap["project_id"],
        "environment_id": wrap["environment_id"],
        "epoch": wrap["epoch"],
        "dek_hex": wrap["dek_hex"],
    }
    base_preimage = commitment_preimage(base_ctx)
    base_commitment = sha256(base_preimage).hex()

    def positive(name, overrides, note):
        ctx = dict(base_ctx, **overrides)
        preimage = commitment_preimage(ctx)
        return dict(
            ctx,
            name=name,
            preimage_hex=preimage.hex(),
            commitment_hex=sha256(preimage).hex(),
            note=note,
        )

    vectors = [
        positive("basic", {},
                 "dek-wrap.json の basic と同一の DEK・座標(epoch 3 = rotate 由来)"),
        positive("epoch-1-create", {"epoch": 1},
                 "エポック 1(create_environment 由来 — §6.2)のコミットメント。座標が原像に入るため basic とは異なる値になる"),
    ]

    other_dek = pat(0xF8, 32)

    def negative(name, overrides, note):
        # overrides を適用した文脈でコミットメントを再計算 → basic と一致しないはず
        ctx = dict(base_ctx, **overrides)
        preimage = commitment_preimage(ctx)
        return {
            "name": name,
            "base": "basic",
            "context": ctx,
            "computed_commitment_hex": sha256(preimage).hex(),
            "expected_commitment_hex": base_commitment,
            "must_fail": True,
            "note": note,
        }

    negatives = [
        negative(
            "dek-mismatch",
            {"dek_hex": other_dek.hex()},
            "別の DEK はコミットメント照合に失敗する(偽 DEK 注入の遮断 — §5.2 / §14.2-1)",
        ),
        negative(
            "transplant-project",
            {"project_id": "proj-0002"},
            "別プロジェクト座標のコミットメントとは一致しない(座標が原像に入る)",
        ),
        negative(
            "transplant-environment",
            {"environment_id": "env-dev-0002"},
            "別環境座標のコミットメントとは一致しない",
        ),
        negative(
            "transplant-epoch",
            {"epoch": 4},
            "別エポック座標のコミットメントとは一致しない",
        ),
        negative(
            "wrong-domain",
            {"suite": "maruhi/v2", "domain": "maruhi/v2/dek-commit"},
            "suite が異なればドメイン文字列が異なり、スイート間のコミットメント移植は照合に失敗する",
        ),
        negative(
            "uppercase-hex",
            {"dek_hex": wrap["dek_hex"].upper()},
            "dek_hex の大文字 hex は別バイト列になり照合に失敗する(原像の正規形は hex 小文字 — 実装は入力を小文字 hex に正規化してから計算すること)",
        ),
    ]

    write(
        "dek-commitment.json",
        {
            "description": "CRYPTO_SPEC §5.2: エポック DEK のコミットメント。dek_commitment_hex = lower_hex(SHA-256(LP(\"<suite>/dek-commit\", project_id, environment_id, epoch, dek_hex)))。DEK・座標は dek-wrap.json の basic ベクターと同一",
            "preimage_fields_order": COMMITMENT_FIELDS_ORDER,
            "binary_encoding": "dek_hex は DEK 32 バイトの hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)",
            "rewrap_invariance": {
                "note": "コミットメントの原像はラップ・受信者に依存しない(§5.2): add_member 後の過去エポック backfill、修復経路の削除 → 再登録、HPKE のランダム性による同一 DEK のラップ暗号文の変動、受信者集合の事後拡大のいずれでもコミットメントは不変。実装テストは同一 DEK を新しくラップし直し(HPKE Seal はランダム)、unwrap した DEK が本コミットメントに照合成功することを固定する",
                "dek_hex": wrap["dek_hex"],
                "commitment_hex": base_commitment,
                "wrap_reference": "dek-wrap.json vectors[0](同一 DEK のラップ実データ)",
            },
            "vectors": vectors,
            "negative": negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.7 value-signature.json — §4.1 値の書き込み署名(Ed25519 + §2.1 LP)
#
# value_signed_bytes = LP("<suite>/value-sig", project_id, environment_id, epoch,
#                         variable_id, version, nonce_hex, ciphertext_hex,
#                         prev_value_sig_hash_hex, writer_user_id,
#                         chain_head_hash_hex, chain_head_seq)
#   domain = "<suite>/value-sig"(suite の束縛はドメイン文字列が担う — §5.1 と同型)
#   数値(epoch / version / chain_head_seq)は 10 進文字列化、バイナリ(nonce /
#   ciphertext / ハッシュ)は hex 小文字文字列として LP に載せる
#   prev_value_sig_hash_hex = 直前 version の value_signed_bytes の SHA-256
#   (version 1 は空文字列)
#
# チェーン状態を要する検証規則系は chain-entries.json の正規 12 エントリチェーンを
# 参照して構成する(dek-wrap-signature.json が dek-wrap.json を読む cross-file の
# 先例)。ciphertext は environment_deks のダミー DEK による実 AES-GCM 暗号文
# (AAD = §4)で、値署名 → 復号が一続きの実データになる。

VALUE_SIG_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "epoch", "variable_id", "version",
    "nonce_hex", "ciphertext_hex", "prev_value_sig_hash_hex", "writer_user_id",
    "chain_head_hash_hex", "chain_head_seq",
]


def value_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([
        ctx["domain"], ctx["project_id"], ctx["environment_id"], ctx["epoch"],
        ctx["variable_id"], ctx["version"], ctx["nonce_hex"], ctx["ciphertext_hex"],
        ctx["prev_value_sig_hash_hex"], ctx["writer_user_id"],
        ctx["chain_head_hash_hex"], ctx["chain_head_seq"],
    ])


def gen_value_signature():
    with open(os.path.join(OUT_DIR, "chain-entries.json"), encoding="utf-8") as fh:
        chain = json.load(fh)
    entries = chain["entries"]
    project_id = entries[0]["entry_hash_hex"]
    suite = "maruhi/v1"
    domain = "maruhi/v1/value-sig"

    def head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"]

    def signer_of(user_id: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(chain["keys"][user_id]["sig_sk_seed_hex"])
        )

    def sig_pub_of(user_id: str) -> str:
        return chain["keys"][user_id]["sig_pub_hex"]

    def fp_of(user_id: str) -> str:
        return chain["keys"][user_id]["key_fingerprint_hex"]

    def dek_of(environment_id: str, epoch: int) -> bytes:
        return bytes.fromhex(chain["environment_deks"][environment_id][str(epoch)]["dek_hex"])

    def encrypt(environment_id: str, epoch: int, variable_id: str, version: int,
                nonce: bytes, plaintext: str) -> str:
        aad = var_aad(suite, project_id, environment_id, epoch, variable_id, version)
        return AESGCM(dek_of(environment_id, epoch)).encrypt(
            nonce, plaintext.encode("utf-8"), aad
        ).hex()

    owner_id = "user-owner-0001"
    member_id = "user-member-0002"
    admin_id = "user-admin-0003"

    def make_value(name, writer_id, environment_id, epoch, variable_id, version,
                   nonce, plaintext, prev_hash_hex, head_seq, note, prev_base=None):
        ct_hex = encrypt(environment_id, epoch, variable_id, version, nonce, plaintext)
        ctx = {
            "suite": suite,
            "domain": domain,
            "project_id": project_id,
            "environment_id": environment_id,
            "epoch": epoch,
            "variable_id": variable_id,
            "version": version,
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ct_hex,
            "prev_value_sig_hash_hex": prev_hash_hex,
            "writer_user_id": writer_id,
            "chain_head_hash_hex": head_hash(head_seq),
            "chain_head_seq": head_seq,
        }
        signed = value_signed_bytes(ctx)
        vector = {
            "name": name,
            "context": ctx,
            "writer_key_fingerprint_hex": fp_of(writer_id),
            "plaintext_utf8": plaintext,
            "aad_hex": var_aad(suite, project_id, environment_id, epoch, variable_id, version).hex(),
            "dek_ref": {"environment_id": environment_id, "epoch": epoch},
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer_of(writer_id).sign(signed).hex(),
            "note": note,
        }
        if prev_base is not None:
            vector["prev_base"] = prev_base
        return vector

    # --- 正例(§8-1)。宣言ヘッド時点の inclusive 規約(§6.3)を境界で固定する ---
    v1_basic = make_value(
        "v1-basic", admin_id, "env-prod-0001", 2, "var-api-key-0001", 1,
        pat(0xA4, 12), "sk-dummy-api-key-v1", "", 12,
        "version 1(prev 空)。writer は head 12 時点の admin(member 以上)、env-prod-0001 の現エポック 2",
    )
    v2_chained = make_value(
        "v2-chained", admin_id, "env-prod-0001", 2, "var-api-key-0001", 2,
        pat(0xA5, 12), "sk-dummy-api-key-v2",
        v1_basic["signed_bytes_sha256_hex"], 12,
        "version 2。prev = v1-basic の value_signed_bytes の SHA-256(§4.1 の連鎖)",
        prev_base="v1-basic",
    )
    vectors = [
        v1_basic,
        v2_chained,
        make_value(
            "create-head-inclusive", member_id, "env-prod-0001", 1, "var-database-url-0001", 1,
            pat(0xA6, 12), "postgres://dummy:dummy@db.example.internal:5432/app", "", 3,
            "create_environment エントリ(seq 3)自身を宣言ヘッドにする直後 push(§6.3 の inclusive 規約): "
            "head 3 で env-prod-0001 は作成済み・エポック 1 有効、writer(member)も seq 2 の add 以降有効",
        ),
        make_value(
            "removed-writer-in-tenure", member_id, "env-prod-0001", 2, "var-legacy-0002", 1,
            pat(0xA7, 12), "legacy-secret-dummy", "", 4,
            "seq 5 で削除済みの writer による在籍区間内(head 4 = 自身の rotate_epoch エントリ)の過去値。"
            "rotate エントリ自身を宣言ヘッドにする再暗号化 push の座標(エポック 2 は head 4 で有効 — inclusive)であり、"
            "削除後も当時の鍵で検証できる(§6.3-1)",
        ),
        make_value(
            "env-dev-v1", admin_id, "env-dev-0002", 1, "var-service-token-0003", 1,
            pat(0xA8, 12), "svc-token-dummy-rotates", "", 8,
            "env-dev-0002 の作成エントリ(seq 8)自身を宣言ヘッドにする version 1(エポック 1)",
        ),
    ]
    vectors.append(
        make_value(
            "rotate-head-reencryption", admin_id, "env-dev-0002", 2, "var-service-token-0003", 2,
            pat(0xA9, 12), "svc-token-dummy-rotates",
            vectors[-1]["signed_bytes_sha256_hex"], 10,
            "ローテーション実行者による再暗号化 push(§7 = §4.1): rotate_epoch エントリ(seq 10)自身を"
            "宣言ヘッドにし、平文は同一のまま新エポック DEK で暗号化、prev は旧エポックの version 1 に連鎖"
            "(エポック単調性 2 ≥ 1)",
            prev_base="env-dev-v1",
        )
    )

    # --- fork-same-version(§14.3-5 / §8-1): 同一座標(variable × version)に対する
    # 内容の異なる 2 つの有効署名。単体ではどちらも全検証を通り、組になって初めて
    # equivocation の暗号学的証拠になる(signed_bytes_sha256 の相違で機械判定)
    fork_prev = v2_chained["signed_bytes_sha256_hex"]
    fork_branches = [
        make_value(
            "fork-branch-a", admin_id, "env-prod-0001", 2, "var-api-key-0001", 3,
            pat(0xAA, 12), "fork-branch-a-dummy", fork_prev, 12,
            "version 3 の分岐 A(admin が署名)", prev_base="v2-chained",
        ),
        make_value(
            "fork-branch-b", owner_id, "env-prod-0001", 2, "var-api-key-0001", 3,
            pat(0xAB, 12), "fork-branch-b-dummy", fork_prev, 12,
            "version 3 の分岐 B(owner が署名)。A と同一座標・同一 prev で内容が異なる", prev_base="v2-chained",
        ),
    ]

    # --- tenure 跨ぎ検査用の派生チェーン(chain-entries.json 本体は変更しない):
    # 正規 12 エントリを prefix に、seq 13 で user-member-0002 を新鍵で re-add する。
    # 旧鍵(在籍区間 1)× 新区間のヘッド(seq 13)の組合せは §6.3-1 のヘッド時点
    # 鍵束縛で拒否されるべき
    rejoined = make_user(pat(0x74, 32), pat(0x84, 32))
    readd_payload = {
        "target_user_id": member_id,
        "enc_pub_hex": rejoined["enc_pub_hex"],
        "sig_pub_hex": rejoined["sig_pub_hex"],
        "role": "member",
    }
    owner_keys = chain["keys"][owner_id]
    owner_fp = owner_keys["key_fingerprint_hex"]
    readd_pb = lp_encode([readd_payload[k] for k in PAYLOAD_FIELD_ORDER["add_member"]])
    readd_ts = 1754006400000 + 12000
    readd_signed = lp_encode(
        [suite, 13, head_hash(12), "add_member", owner_id, owner_fp, readd_pb, readd_ts]
    )
    readd_sig = signer_of(owner_id).sign(readd_signed)
    readd_entry_bytes = lp_encode(
        [suite, 13, head_hash(12), "add_member", owner_id, owner_fp, readd_pb, readd_ts,
         readd_sig.hex()]
    )
    tenure_extension = {
        "note": "key-from-other-tenure 用の派生チェーン: 正規 12 エントリの後に seq 13 で "
                "user-member-0002 を新鍵で re-add する(remove → re-add = 別 tenure)。"
                "chain-entries.json 本体は変更しない",
        "rejoined_member": {
            "user_id": member_id,
            "enc_sk_seed_hex": pat(0x74, 32).hex(),
            "sig_sk_seed_hex": pat(0x84, 32).hex(),
            "enc_pub_hex": rejoined["enc_pub_hex"],
            "sig_pub_hex": rejoined["sig_pub_hex"],
            "key_fingerprint_hex": rejoined["fp_hex"],
        },
        "entry": {
            "seq": 13,
            "suite": suite,
            "prev_hash_hex": head_hash(12),
            "op": "add_member",
            "actor": {"user_id": owner_id, "key_fingerprint_hex": owner_fp},
            "payload": readd_payload,
            "timestamp_ms": readd_ts,
            "payload_bytes_hex": readd_pb.hex(),
            "signed_bytes_hex": readd_signed.hex(),
            "signature_hex": readd_sig.hex(),
            "entry_bytes_hex": readd_entry_bytes.hex(),
            "entry_hash_hex": sha256(readd_entry_bytes).hex(),
        },
    }

    # --- negative(署名系): 改竄・移植 = 元署名を維持したまま signed_bytes を
    # 差し替え、Ed25519 検証が失敗することを固定する(dek-wrap-signature と同じ形)
    base_ctx = v1_basic["context"]
    base_sig = bytes.fromhex(v1_basic["signature_hex"])
    admin_pub = sig_pub_of(admin_id)
    tampered_sig = bytearray(base_sig)
    tampered_sig[-1] ^= 0x01
    tampered_ct = bytearray(bytes.fromhex(base_ctx["ciphertext_hex"]))
    tampered_ct[-1] ^= 0x01
    tampered_nonce = bytearray(bytes.fromhex(base_ctx["nonce_hex"]))
    tampered_nonce[0] ^= 0x01

    def make_negative(name, overrides, note, base_vector=None, verify_key_hex=None,
                      signature=None):
        source = base_vector if base_vector is not None else v1_basic
        ctx = dict(source["context"], **overrides)
        return {
            "name": name,
            "base": source["name"],
            "context": ctx,
            "verify_signed_bytes_hex": value_signed_bytes(ctx).hex(),
            "signature_hex": (signature.hex() if signature is not None
                              else source["signature_hex"]),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None else admin_pub,
            "must_fail": True,
            "note": note,
        }

    negatives = [
        make_negative(
            "tampered-signature", {},
            "署名バイト自体の末尾 1 bit 反転は検証に失敗する",
            signature=bytes(tampered_sig),
        ),
        make_negative(
            "tampered-ciphertext", {"ciphertext_hex": bytes(tampered_ct).hex()},
            "暗号文の末尾 1 bit 反転(タグ含む差し替え)は元署名の検証に失敗する",
        ),
        make_negative(
            "tampered-nonce", {"nonce_hex": bytes(tampered_nonce).hex()},
            "nonce の改竄は元署名の検証に失敗する(nonce も署名対象)",
        ),
        make_negative(
            "transplant-project", {"project_id": "proj-other-0002"},
            "別プロジェクトへの座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-environment", {"environment_id": "env-dev-0002"},
            "別環境への座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-epoch", {"epoch": 1},
            "別エポックへの座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-variable", {"variable_id": "var-other-9999"},
            "別変数への座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-version", {"version": 2},
            "別バージョンへの座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-signer", {"writer_user_id": owner_id},
            "writer_user_id の差し替えは同一鍵でも検証に失敗する(帰属の付け替え対策 — §4.1 の user_id 焼き込み)",
        ),
        make_negative(
            "wrong-signer-key", {},
            "署名者以外の鍵では検証に失敗する(FP 付け替えによる別鍵検証の遮断)",
            verify_key_hex=sig_pub_of(owner_id),
        ),
        make_negative(
            "chain-head-swap", {"chain_head_hash_hex": head_hash(11)},
            "chain_head_hash_hex の差し替え(seq は維持)は署名検証に失敗する(認可時点の付け替え対策)",
        ),
        make_negative(
            "chain-head-seq-mismatch", {"chain_head_seq": 11},
            "chain_head_seq の差し替え(hash は維持)は署名検証に失敗する(hash と seq の両方が署名対象)",
        ),
        make_negative(
            "tampered-prev-hash",
            {"prev_value_sig_hash_hex": sha256(b"bogus-predecessor").hex()},
            "prev_value_sig_hash_hex の差し替えは元署名の検証に失敗する(連鎖の改竄は署名で固定される)",
            base_vector=v2_chained,
        ),
        make_negative(
            "suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/value-sig"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
    ]

    # --- negative(検証規則系。kind = "authorization"): 署名は有効だが、
    # 検証済みチェーン履歴に対する §6.3 の検証規則で拒否されるべきもの。
    # expected_reason は実装の理由コードを固定する(chain-entries の authz と同じ運び方)
    ghost = make_user(pat(0x78, 32), pat(0x88, 32))
    ghost_signer = Ed25519PrivateKey.from_private_bytes(pat(0x88, 32))

    def rule_negative(name, writer_id, environment_id, epoch, variable_id, version,
                      nonce, plaintext, prev_hash_hex, head_hash_hex, head_seq,
                      expected_reason, note, chain_ref="canonical",
                      writer_fp=None, sign_with=None, verify_key_hex=None,
                      predecessor=None):
        # epoch 座標と同じエポックの DEK で実暗号化する(環境の全対象エポックの
        # ダミー DEK は environment_deks に存在する)
        ct_hex = encrypt(environment_id, epoch, variable_id, version, nonce, plaintext)
        ctx = {
            "suite": suite,
            "domain": domain,
            "project_id": project_id,
            "environment_id": environment_id,
            "epoch": epoch,
            "variable_id": variable_id,
            "version": version,
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ct_hex,
            "prev_value_sig_hash_hex": prev_hash_hex,
            "writer_user_id": writer_id,
            "chain_head_hash_hex": head_hash_hex,
            "chain_head_seq": head_seq,
        }
        signed = value_signed_bytes(ctx)
        signer = sign_with if sign_with is not None else signer_of(writer_id)
        case = {
            "name": name,
            "kind": "authorization",
            "chain": chain_ref,
            "context": ctx,
            "writer_key_fingerprint_hex": writer_fp if writer_fp is not None else fp_of(writer_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None else sig_pub_of(writer_id),
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
        }
        if predecessor is not None:
            case["predecessor"] = predecessor
        return case

    rule_negatives = [
        rule_negative(
            "head-not-in-chain", admin_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB0, 12), "rule-dummy", "", sha256(b"not-in-chain").hex(), 12,
            "chain-head-mismatch",
            "seq 12 は自ビューに実在するがハッシュが一致しない = チェーン分岐(equivocation)"
            "または偽造の硬い証拠として即時拒否(§6.3-2a)",
        ),
        rule_negative(
            "head-beyond-local-seq", admin_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB1, 12), "rule-dummy", "", sha256(b"future-head").hex(), 13,
            "chain-head-future",
            "seq 13 は自ビューのヘッド(12)より先 = 自チェーンが古いだけの可能性。まず再同期し、"
            "延長として一致すれば受理・しなければ分岐の証拠(§6.3-2b)。この理由コードは"
            "「即時拒否せず再同期を試みる」分岐の入口を固定する",
        ),
        rule_negative(
            "writer-role-insufficient", admin_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB2, 12), "rule-dummy", "", head_hash(6), 6,
            "writer-role-insufficient-at-head",
            "head 6 時点の user-admin-0003 は reader(change_role は seq 7)。値の push は"
            "宣言ヘッド時点で member 以上が必要(§6.3-3)",
        ),
        rule_negative(
            "writer-removed-at-head", member_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB3, 12), "rule-dummy", "", head_hash(12), 12,
            "writer-not-member-at-head",
            "seq 5 で削除済みの writer が削除後のヘッド(12)を宣言する形は拒否する"
            "(削除済みメンバーの鍵による新規登録の遮断 — §6.3-3)",
        ),
        rule_negative(
            "epoch-not-current-at-head", admin_id, "env-prod-0001", 1, "var-rule-0004", 1,
            pat(0xB4, 12), "rule-dummy", "", head_hash(12), 12,
            "epoch-not-current-at-head",
            "head 12 時点の env-prod-0001 の現エポックは 2。エポック 1 への署名は拒否する"
            "(削除済みメンバーの鍵で現エポックの値を偽造する経路の対偶 — §6.3-4)",
        ),
        rule_negative(
            "head-before-environment-create", member_id, "env-prod-0001", 1, "var-rule-0004", 1,
            pat(0xB5, 12), "rule-dummy", "", head_hash(2), 2,
            "environment-not-created-at-head",
            "宣言ヘッド(seq 2)が env-prod-0001 の create_environment(seq 3)より前 = 環境未存在で"
            "エポックが定義されない。既定値へのフォールバック実装を禁止する(§6.3-4 後段)",
        ),
        rule_negative(
            "key-from-other-tenure", member_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB6, 12), "rule-dummy", "",
            tenure_extension["entry"]["entry_hash_hex"], 13,
            "writer-key-mismatch-at-head",
            "remove → 別鍵 re-add(派生チェーン seq 13)の user_id で、旧在籍区間の鍵 × 新区間の"
            "ヘッド(13)の組合せは拒否する(§6.3-1 のヘッド時点鍵束縛 — 同じ鍵の dedupe で"
            "tenure を消した実装はここで落ちる)",
            chain_ref="tenure-extension",
        ),
        rule_negative(
            "writer-unknown-in-history", "user-ghost-0042", "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB7, 12), "rule-dummy", "", head_hash(12), 12,
            "writer-unknown",
            "チェーン履歴のどの時点にも存在しない writer_user_id / 鍵 FP の組は検証鍵を選択"
            "できず拒否する(署名自体は本 negative の鍵で有効)",
            writer_fp=ghost["fp_hex"], sign_with=ghost_signer,
            verify_key_hex=ghost["sig_pub_hex"],
        ),
        rule_negative(
            "v1-nonempty-prev", admin_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xB8, 12), "rule-dummy", sha256(b"phantom-predecessor").hex(),
            head_hash(12), 12,
            "prev-shape-mismatch",
            "version 1 の prev_value_sig_hash_hex は空文字列でなければならない(§4.1)。"
            "latest-only 検証でも必ず検査する形の規則(session-14 裁定 B)",
        ),
        rule_negative(
            "v2-empty-prev", admin_id, "env-prod-0001", 2, "var-rule-0005", 2,
            pat(0xB9, 12), "rule-dummy", "", head_hash(12), 12,
            "prev-shape-mismatch",
            "version > 1 の prev_value_sig_hash_hex は 64 文字 hex でなければならない(§4.1)。"
            "predecessor を保持しない latest-only 検証でも形は必ず検査する(裁定 B)",
        ),
        rule_negative(
            "prev-hash-mismatch", admin_id, "env-prod-0001", 2, "var-api-key-0001", 2,
            pat(0xBA, 12), "rule-dummy", sha256(b"wrong-predecessor").hex(),
            head_hash(12), 12,
            "prev-hash-mismatch",
            "既知の直前 version(v1-basic)の signed_bytes ハッシュと prev が一致しない連鎖不整合"
            "(§6.3-6)。署名は有効 — Ed25519 failure に潰してはならない(裁定 B)",
            predecessor={
                "base": "v1-basic",
                "signed_bytes_sha256_hex": v1_basic["signed_bytes_sha256_hex"],
                "epoch": 2,
            },
        ),
        rule_negative(
            "epoch-regression-across-versions", member_id, "env-prod-0001", 1,
            "var-api-key-0001", 3,
            pat(0xBB, 12), "rule-dummy", v2_chained["signed_bytes_sha256_hex"],
            head_hash(3), 3,
            "epoch-regressed",
            "version 3 の epoch(1)が直前 version(v2-chained、epoch 2)より小さい = §4.1 の"
            "エポック単調性違反。head 3 は writer(member)の在籍区間内・エポック 1 が当時の"
            "現エポックで他の全検証を通る「前進 version への旧エポック注入」の形",
            predecessor={
                "base": "v2-chained",
                "signed_bytes_sha256_hex": v2_chained["signed_bytes_sha256_hex"],
                "epoch": 2,
            },
        ),
    ]

    write(
        "value-signature.json",
        {
            "description": "CRYPTO_SPEC §4.1: 値の書き込み署名(Ed25519)。value_signed_bytes = LP(\"<suite>/value-sig\", project_id, environment_id, epoch, variable_id, version, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex, writer_user_id, chain_head_hash_hex, chain_head_seq)。チェーン・鍵・DEK は chain-entries.json の正規 12 エントリチェーンを参照",
            "signed_fields_order": VALUE_SIG_FIELDS_ORDER,
            "binary_encoding": "nonce / ciphertext / ハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(epoch / version / chain_head_seq)は 10 進文字列化",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、writer 鍵 = keys、DEK = environment_deks(ciphertext は実 AES-GCM 暗号文で、AAD は §4 の LP)",
            "extra_keys": {
                "ghost": {
                    "note": "writer-unknown-in-history 用(チェーン履歴に存在しない鍵)",
                    "enc_sk_seed_hex": pat(0x78, 32).hex(),
                    "sig_sk_seed_hex": pat(0x88, 32).hex(),
                    "enc_pub_hex": ghost["enc_pub_hex"],
                    "sig_pub_hex": ghost["sig_pub_hex"],
                    "key_fingerprint_hex": ghost["fp_hex"],
                },
            },
            "tenure_extension": tenure_extension,
            "vectors": vectors,
            "fork_same_version": {
                "note": "同一座標(var-api-key-0001 × version 3)に対する内容の異なる 2 つの有効署名。"
                        "各 branch は単体で §6.3 の全検証を通り(両方 verify 成功)、組として "
                        "signed_bytes_sha256_hex の相違 = サーバー equivocation の否認不能な証拠になる"
                        "(§14.2-5。防止ではなく証拠化 — 検出は同一座標の突合で行う)",
                "branches": fork_branches,
            },
            "negative": negatives + rule_negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.8 metadata-signature.json — §4.2 変数・環境メタデータの署名付きステートメント
#
# var_meta_signed_bytes = LP("<suite>/var-meta-sig", project_id, environment_id,
#                            variable_id, name, status, meta_version,
#                            prev_meta_sig_hash_hex, author_user_id,
#                            chain_head_hash_hex, chain_head_seq)
# env_meta_signed_bytes = LP("<suite>/env-meta-sig", project_id, environment_id,
#                            name, status, meta_version, prev_meta_sig_hash_hex,
#                            author_user_id, chain_head_hash_hex, chain_head_seq)
#   domain = "<suite>/var-meta-sig" / "<suite>/env-meta-sig"(suite の束縛は
#   ドメイン文字列が担う — §4.1 と同型)。数値(meta_version / chain_head_seq)は
#   10 進文字列化、バイナリ(ハッシュ)は hex 小文字文字列として LP に載せる
#   prev_meta_sig_hash_hex = 直前ステートメントの signed_bytes の SHA-256
#   (meta_version 1 は空文字列)。name は UTF-8 バイト列としてそのまま束縛
#   (byte-exact — NFC 正規化は署名前のクライアントの責務。§4.2)
#
# チェーン状態を要する検証規則系は chain-entries.json の正規 12 エントリチェーンを
# 参照して構成する(value-signature.json と同じ cross-file の先例)。
# メタステートメントはエポックアンカーを持たない(§4.2 / §14.3-5)ため、値署名の
# epoch-not-current / environment-not-created に相当する規則は存在しない —
# var-meta-head-before-env-create は **positive**(意図された非対称の固定。
# AUTH_SPEC §12-4)。

VAR_META_SIG_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "variable_id", "name", "status",
    "meta_version", "prev_meta_sig_hash_hex", "author_user_id",
    "chain_head_hash_hex", "chain_head_seq",
]
ENV_META_SIG_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "name", "status",
    "meta_version", "prev_meta_sig_hash_hex", "author_user_id",
    "chain_head_hash_hex", "chain_head_seq",
]


def meta_signed_bytes(ctx: dict) -> bytes:
    order = VAR_META_SIG_FIELDS_ORDER if ctx["kind"] == "variable" else ENV_META_SIG_FIELDS_ORDER
    return lp_encode([ctx[key] for key in order])


def gen_metadata_signature():
    with open(os.path.join(OUT_DIR, "chain-entries.json"), encoding="utf-8") as fh:
        chain = json.load(fh)
    entries = chain["entries"]
    project_id = entries[0]["entry_hash_hex"]
    suite = "maruhi/v1"

    def head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"]

    def signer_of(user_id: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(chain["keys"][user_id]["sig_sk_seed_hex"])
        )

    def sig_pub_of(user_id: str) -> str:
        return chain["keys"][user_id]["sig_pub_hex"]

    def fp_of(user_id: str) -> str:
        return chain["keys"][user_id]["key_fingerprint_hex"]

    owner_id = "user-owner-0001"
    member_id = "user-member-0002"
    admin_id = "user-admin-0003"

    def make_context(kind, environment_id, variable_id, name, status, meta_version,
                     prev_hash_hex, author_id, head_hash_hex, head_seq):
        ctx = {
            "kind": kind,
            "suite": suite,
            "domain": f"{suite}/{'var' if kind == 'variable' else 'env'}-meta-sig",
            "project_id": project_id,
            "environment_id": environment_id,
        }
        if kind == "variable":
            ctx["variable_id"] = variable_id
        ctx.update({
            "name": name,
            "status": status,
            "meta_version": meta_version,
            "prev_meta_sig_hash_hex": prev_hash_hex,
            "author_user_id": author_id,
            "chain_head_hash_hex": head_hash_hex,
            "chain_head_seq": head_seq,
        })
        return ctx

    def make_statement(name, kind, environment_id, variable_id, display_name, status,
                       meta_version, prev_hash_hex, author_id, head_seq, note,
                       prev_base=None):
        ctx = make_context(kind, environment_id, variable_id, display_name, status,
                           meta_version, prev_hash_hex, author_id, head_hash(head_seq), head_seq)
        signed = meta_signed_bytes(ctx)
        vector = {
            "name": name,
            "context": ctx,
            "author_key_fingerprint_hex": fp_of(author_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer_of(author_id).sign(signed).hex(),
            "note": note,
        }
        if prev_base is not None:
            vector["prev_base"] = prev_base
        return vector

    # --- 正例(session-12 §8-2)。宣言ヘッド時点の inclusive 規約(§6.3)と
    # 「作成 → rename → 削除」の prev 連鎖・削除時の name 保持を固定する ---
    var_create = make_statement(
        "var-create", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY",
        "active", 1, "", admin_id, 12,
        "変数作成(metaVersion 1、prev 空、status active)。author は head 12 時点の admin(member 以上)",
    )
    var_rename = make_statement(
        "var-rename", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_ROTATED",
        "active", 2, var_create["signed_bytes_sha256_hex"], admin_id, 12,
        "rename(metaVersion 2)。prev = var-create の signed_bytes の SHA-256(§4.2 の連鎖)",
        prev_base="var-create",
    )
    var_delete = make_statement(
        "var-delete", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_ROTATED",
        "deleted", 3, var_rename["signed_bytes_sha256_hex"], admin_id, 12,
        "削除(status deleted、metaVersion 3)。name は直前の active 名をそのまま保持する(§4.2 — 削除で空にしない)",
        prev_base="var-rename",
    )
    nfc_name = unicodedata.normalize("NFC", "CAF\u00c9_URL")
    var_nfc = make_statement(
        "var-nfc-name", "variable", "env-prod-0001", "var-cafe-0009", nfc_name,
        "active", 1, "", admin_id, 12,
        "NFC 正規形の非 ASCII 名。署名は name の UTF-8 バイト列に byte-exact に束縛される(§4.2)",
    )
    env_create = make_statement(
        "env-create-meta", "environment", "env-prod-0001", None, "Production",
        "active", 1, "", member_id, 2,
        "環境作成の複合リクエスト同梱ステートメント(metaVersion 1): 宣言ヘッドは追記前の現ヘッド"
        "(seq 2 = create_environment エントリの prev — AUTH_SPEC §12-4)。宣言ヘッド時点に環境は"
        "未存在だが、メタステートメントの検証は環境の存在を検査しない(§12-4 の意図された非対称)",
    )
    env_rename = make_statement(
        "env-rename", "environment", "env-prod-0001", None, "Production EU",
        "active", 2, env_create["signed_bytes_sha256_hex"], admin_id, 12,
        "環境 rename(metaVersion 2、member 以上)。prev = env-create-meta の signed_bytes の SHA-256",
        prev_base="env-create-meta",
    )
    env_delete = make_statement(
        "env-delete-admin", "environment", "env-prod-0001", None, "Production EU",
        "deleted", 3, env_rename["signed_bytes_sha256_hex"], admin_id, 12,
        "環境削除(status deleted)。環境の削除のみ宣言ヘッド時点 admin 以上(§4.2 / §12-3 の水準差)。"
        "head 12 時点の user-admin-0003 は admin。name は直前 active 名を保持",
        prev_base="env-rename",
    )
    vectors = [
        var_create,
        var_rename,
        var_delete,
        var_nfc,
        env_create,
        env_rename,
        env_delete,
        make_statement(
            "removed-author-in-tenure", "variable", "env-prod-0001", "var-legacy-0002",
            "LEGACY_TOKEN", "active", 1, "", member_id, 4,
            "seq 5 で削除済みの author による在籍区間内(head 4)の過去ステートメント。"
            "削除後も当時の鍵で検証できる(§6.3-1 — value-signature の removed-writer-in-tenure の対応物)",
        ),
        make_statement(
            "var-meta-head-before-env-create", "variable", "env-prod-0001", "var-early-0005",
            "EARLY_BIRD", "active", 1, "", member_id, 2,
            "positive: 宣言ヘッド(seq 2)が env-prod-0001 の create_environment(seq 3)より前でも"
            "var メタステートメントは受理される。メタはエポックアンカーを持たず環境の存在を検査しない"
            "(値署名の §6.3-4 と意図的に非対称 — AUTH_SPEC §12-4。§14.3-5 の既知残余の対価)",
        ),
    ]

    # --- rename-fork(§14.2-5 / §8-2): 同一 (variable, metaVersion) に対する内容の
    # 異なる 2 つの有効ステートメント。単体ではどちらも全検証を通り、組になって
    # 初めて equivocation の暗号学的証拠になる(signed_bytes_sha256 の相違で機械判定)
    fork_branches = [
        make_statement(
            "rename-fork-a", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_BLUE",
            "active", 2, var_create["signed_bytes_sha256_hex"], admin_id, 12,
            "metaVersion 2 の分岐 A(admin が署名)", prev_base="var-create",
        ),
        make_statement(
            "rename-fork-b", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_GREEN",
            "active", 2, var_create["signed_bytes_sha256_hex"], owner_id, 12,
            "metaVersion 2 の分岐 B(owner が署名)。A と同一座標・同一 prev で name が異なる",
            prev_base="var-create",
        ),
    ]

    # --- name-swap(§8-2): 2 変数の名前入替。正規ステートメントは名前を
    # variable_id へ署名で束縛しており、名前フィールドだけを入れ替えたバイト列では
    # 元署名の検証に失敗する(サーバーによる名前 ↔ 暗号文の付け替えの遮断 — §4.2)
    swap_a = make_statement(
        "name-swap-var-a", "variable", "env-prod-0001", "var-swap-a-0006", "DATABASE_URL",
        "active", 1, "", admin_id, 12,
        "name-swap の正規側 A(DATABASE_URL → var-swap-a-0006)",
    )
    swap_b = make_statement(
        "name-swap-var-b", "variable", "env-prod-0001", "var-swap-b-0007", "DEBUG_ENDPOINT",
        "active", 1, "", admin_id, 12,
        "name-swap の正規側 B(DEBUG_ENDPOINT → var-swap-b-0007)",
    )

    def swapped_negative(name, base_vector, swapped_name, note):
        ctx = dict(base_vector["context"], name=swapped_name)
        return {
            "name": name,
            "base": base_vector["name"],
            "context": ctx,
            "verify_signed_bytes_hex": meta_signed_bytes(ctx).hex(),
            "signature_hex": base_vector["signature_hex"],
            "verify_key_hex": sig_pub_of(admin_id),
            "must_fail": True,
            "note": note,
        }

    name_swap = {
        "note": "2 変数の名前入替(DATABASE_URL ↔ DEBUG_ENDPOINT)。正規ステートメント 2 本は"
                "各々検証を通るが、name フィールドだけを入れ替えたバイト列では元署名の検証に失敗する"
                "(名前 ↔ ID の対応は署名が束縛する — §4.2。付け替えられた側の配布は座標整合 §6.3-5 でも落ちる)",
        "statements": [swap_a, swap_b],
        "swapped": [
            swapped_negative(
                "name-swap-a-to-b", swap_a, "DEBUG_ENDPOINT",
                "var-swap-a-0006 のステートメントに var-swap-b-0007 の名前を載せ替えると署名検証に失敗する",
            ),
            swapped_negative(
                "name-swap-b-to-a", swap_b, "DATABASE_URL",
                "var-swap-b-0007 のステートメントに var-swap-a-0006 の名前を載せ替えると署名検証に失敗する",
            ),
        ],
    }

    # --- tenure 跨ぎ検査用の派生チェーン(value-signature.json と同一の派生形。
    # chain-entries.json 本体は変更しない): 正規 12 エントリの後に seq 13 で
    # user-member-0002 を新鍵で re-add する
    rejoined = make_user(pat(0x74, 32), pat(0x84, 32))
    readd_payload = {
        "target_user_id": member_id,
        "enc_pub_hex": rejoined["enc_pub_hex"],
        "sig_pub_hex": rejoined["sig_pub_hex"],
        "role": "member",
    }
    owner_fp = chain["keys"][owner_id]["key_fingerprint_hex"]
    readd_pb = lp_encode([readd_payload[k] for k in PAYLOAD_FIELD_ORDER["add_member"]])
    readd_ts = 1754006400000 + 12000
    readd_signed = lp_encode(
        [suite, 13, head_hash(12), "add_member", owner_id, owner_fp, readd_pb, readd_ts]
    )
    readd_sig = signer_of(owner_id).sign(readd_signed)
    readd_entry_bytes = lp_encode(
        [suite, 13, head_hash(12), "add_member", owner_id, owner_fp, readd_pb, readd_ts,
         readd_sig.hex()]
    )
    tenure_extension = {
        "note": "key-from-other-tenure 用の派生チェーン(value-signature.json と同一内容): "
                "正規 12 エントリの後に seq 13 で user-member-0002 を新鍵で re-add する"
                "(remove → re-add = 別 tenure)。chain-entries.json 本体は変更しない",
        "rejoined_member": {
            "user_id": member_id,
            "enc_sk_seed_hex": pat(0x74, 32).hex(),
            "sig_sk_seed_hex": pat(0x84, 32).hex(),
            "enc_pub_hex": rejoined["enc_pub_hex"],
            "sig_pub_hex": rejoined["sig_pub_hex"],
            "key_fingerprint_hex": rejoined["fp_hex"],
        },
        "entry": {
            "seq": 13,
            "suite": suite,
            "prev_hash_hex": head_hash(12),
            "op": "add_member",
            "actor": {"user_id": owner_id, "key_fingerprint_hex": owner_fp},
            "payload": readd_payload,
            "timestamp_ms": readd_ts,
            "payload_bytes_hex": readd_pb.hex(),
            "signed_bytes_hex": readd_signed.hex(),
            "signature_hex": readd_sig.hex(),
            "entry_bytes_hex": readd_entry_bytes.hex(),
            "entry_hash_hex": sha256(readd_entry_bytes).hex(),
        },
    }

    # --- negative(署名系): 改竄・移植 = 元署名を維持したまま signed_bytes を
    # 差し替え、Ed25519 検証が失敗することを固定する(value-signature と同じ形)
    base_sig = bytes.fromhex(var_create["signature_hex"])
    tampered_sig = bytearray(base_sig)
    tampered_sig[-1] ^= 0x01

    def make_negative(name, overrides, note, base_vector=None, verify_key_hex=None,
                      signature=None):
        source = base_vector if base_vector is not None else var_create
        ctx = dict(source["context"], **overrides)
        return {
            "name": name,
            "base": source["name"],
            "context": ctx,
            "verify_signed_bytes_hex": meta_signed_bytes(ctx).hex(),
            "signature_hex": (signature.hex() if signature is not None
                              else source["signature_hex"]),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None
            else sig_pub_of(admin_id),
            "must_fail": True,
            "note": note,
        }

    nfd_name = unicodedata.normalize("NFD", nfc_name)
    assert nfd_name != nfc_name  # NFC / NFD で byte が異なる名前であること
    negatives = [
        make_negative(
            "tampered-signature", {},
            "署名バイト自体の末尾 1 bit 反転は検証に失敗する",
            signature=bytes(tampered_sig),
        ),
        make_negative(
            "tampered-status", {"status": "deleted"},
            "status の書き換え(active → deleted)は元署名の検証に失敗する(無署名の削除偽造の遮断 — §4.2 の tombstone 署名化)",
        ),
        make_negative(
            "transplant-project", {"project_id": "proj-other-0002"},
            "別プロジェクトへの座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-environment", {"environment_id": "env-dev-0002"},
            "別環境への座標移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-variable", {"variable_id": "var-other-9999"},
            "別変数への座標移植は署名検証に失敗する(値 — variable_id 束縛 — と名前の対応の付け替え対策)",
        ),
        make_negative(
            "transplant-meta-version", {"meta_version": 2},
            "別 metaVersion への移植は署名検証に失敗する",
        ),
        make_negative(
            "transplant-signer", {"author_user_id": owner_id},
            "author_user_id の差し替えは同一鍵でも検証に失敗する(帰属の付け替え対策 — §4.2 の user_id 焼き込み)",
        ),
        make_negative(
            "wrong-signer-key", {},
            "署名者以外の鍵では検証に失敗する(FP 付け替えによる別鍵検証の遮断)",
            verify_key_hex=sig_pub_of(owner_id),
        ),
        make_negative(
            "chain-head-swap", {"chain_head_hash_hex": head_hash(11)},
            "chain_head_hash_hex の差し替え(seq は維持)は署名検証に失敗する(認可時点の付け替え対策)",
        ),
        make_negative(
            "chain-head-seq-mismatch", {"chain_head_seq": 11},
            "chain_head_seq の差し替え(hash は維持)は署名検証に失敗する(hash と seq の両方が署名対象)",
        ),
        make_negative(
            "tampered-prev-hash",
            {"prev_meta_sig_hash_hex": sha256(b"bogus-meta-predecessor").hex()},
            "prev_meta_sig_hash_hex の差し替えは元署名の検証に失敗する(連鎖の改竄は署名で固定される)",
            base_vector=var_rename,
        ),
        make_negative(
            "suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/var-meta-sig"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
        make_negative(
            "nfc-variant", {"name": nfd_name},
            "NFC 正規形で署名された name を NFD 変種に置き換えると byte 列が異なり署名検証に失敗する"
            "(署名は byte-exact — 正規化は署名前のクライアントの責務で、検証者は正規化しない。§4.2)",
            base_vector=var_nfc,
        ),
        make_negative(
            "env-transplant-environment", {"environment_id": "env-dev-0002"},
            "環境ステートメントの別環境への座標移植は署名検証に失敗する",
            base_vector=env_create,
            verify_key_hex=sig_pub_of(member_id),
        ),
        make_negative(
            "cross-kind-transplant",
            {"kind": "variable", "domain": "maruhi/v1/var-meta-sig",
             "variable_id": "var-cross-0008"},
            "環境ステートメントの署名を変数ステートメントのバイト列(var-meta-sig ドメイン)で検証すると失敗する"
            "(var / env のドメイン分離の固定)",
            base_vector=env_create,
            verify_key_hex=sig_pub_of(member_id),
        ),
    ]

    # --- negative(検証規則系。kind = "authorization"): 署名は有効だが、検証済み
    # チェーン履歴に対する §6.3 の検証規則で拒否されるべきもの。expected_reason は
    # 実装の理由コードを固定する(value-signature の rule negative と同じ運び方)。
    # メタにはエポック整合(§6.3-4)が存在しない — epoch-not-current /
    # environment-not-created 相当の規則系 negative は意図して置かない(§14.3-5)
    ghost = make_user(pat(0x78, 32), pat(0x88, 32))
    ghost_signer = Ed25519PrivateKey.from_private_bytes(pat(0x88, 32))

    def rule_negative(name, kind, environment_id, variable_id, display_name, status,
                      meta_version, prev_hash_hex, author_id, head_hash_hex, head_seq,
                      expected_reason, note, chain_ref="canonical",
                      author_fp=None, sign_with=None, verify_key_hex=None,
                      predecessor=None):
        ctx = make_context(kind, environment_id, variable_id, display_name, status,
                           meta_version, prev_hash_hex, author_id, head_hash_hex, head_seq)
        signed = meta_signed_bytes(ctx)
        signer = sign_with if sign_with is not None else signer_of(author_id)
        case = {
            "name": name,
            "kind": "authorization",
            "chain": chain_ref,
            "context": ctx,
            "author_key_fingerprint_hex": author_fp if author_fp is not None else fp_of(author_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None
            else sig_pub_of(author_id),
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
        }
        if predecessor is not None:
            case["predecessor"] = predecessor
        return case

    rule_negatives = [
        rule_negative(
            "head-not-in-chain", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", admin_id, sha256(b"not-in-chain").hex(), 12,
            "chain-head-mismatch",
            "seq 12 は自ビューに実在するがハッシュが一致しない = チェーン分岐(equivocation)"
            "または偽造の硬い証拠として即時拒否(§6.3-2a)",
        ),
        rule_negative(
            "head-beyond-local-seq", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", admin_id, sha256(b"future-head").hex(), 13,
            "chain-head-future",
            "seq 13 は自ビューのヘッド(12)より先 = 自チェーンが古いだけの可能性。まず再同期し、"
            "延長として一致すれば受理・しなければ分岐の証拠(§6.3-2b)。値署名と同じ有界再同期の"
            "入口が流用されることを固定する",
        ),
        rule_negative(
            "author-removed-at-head", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", member_id, head_hash(12), 12,
            "author-not-member-at-head",
            "seq 5 で削除済みの author が削除後のヘッド(12)を宣言する形は拒否する"
            "(削除済みメンバーの鍵による新規ステートメントの遮断 — §6.3-3)",
        ),
        rule_negative(
            "author-role-insufficient", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", admin_id, head_hash(6), 6,
            "author-role-insufficient-at-head",
            "head 6 時点の user-admin-0003 は reader(change_role は seq 7)。変数の作成・rename・"
            "削除は宣言ヘッド時点で member 以上が必要(§4.2 / §6.3-3)",
        ),
        rule_negative(
            "env-delete-role-insufficient", "environment", "env-prod-0001", None, "Production",
            "deleted", 2, env_create["signed_bytes_sha256_hex"], member_id, head_hash(4), 4,
            "author-role-insufficient-at-head",
            "head 4 時点の user-member-0002 は member。環境の削除ステートメントのみ宣言ヘッド時点で"
            "admin 以上が必要(§4.2 / §12-3 の水準差の固定 — 環境の作成・rename は member 水準)",
        ),
        rule_negative(
            "key-from-other-tenure", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", member_id,
            tenure_extension["entry"]["entry_hash_hex"], 13,
            "author-key-mismatch-at-head",
            "remove → 別鍵 re-add(派生チェーン seq 13)の user_id で、旧在籍区間の鍵 × 新区間の"
            "ヘッド(13)の組合せは拒否する(§6.3-1 のヘッド時点鍵束縛)",
            chain_ref="tenure-extension",
        ),
        rule_negative(
            "author-unknown-in-history", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", "user-ghost-0042", head_hash(12), 12,
            "author-unknown",
            "チェーン履歴のどの時点にも存在しない author_user_id / 鍵 FP の組は検証鍵を選択"
            "できず拒否する(署名自体は本 negative の鍵で有効)",
            author_fp=ghost["fp_hex"], sign_with=ghost_signer,
            verify_key_hex=ghost["sig_pub_hex"],
        ),
        rule_negative(
            "v1-nonempty-prev", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, sha256(b"phantom-meta-predecessor").hex(), admin_id, head_hash(12), 12,
            "prev-shape-mismatch",
            "metaVersion 1 の prev_meta_sig_hash_hex は空文字列でなければならない(§4.2)。"
            "predecessor を保持しない latest-only 検証でも形は必ず検査する(session-14 裁定 B の同型)",
        ),
        rule_negative(
            "v2-empty-prev", "variable", "env-prod-0001", "var-rule-0005", "RULE_VAR_2",
            "active", 2, "", admin_id, head_hash(12), 12,
            "prev-shape-mismatch",
            "metaVersion > 1 の prev_meta_sig_hash_hex は 64 文字 hex でなければならない(§4.2)",
        ),
        rule_negative(
            "prev-hash-mismatch", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_FORGED",
            "active", 2, sha256(b"wrong-meta-predecessor").hex(), admin_id, head_hash(12), 12,
            "prev-hash-mismatch",
            "既知の直前 metaVersion(var-create)の signed_bytes ハッシュと prev が一致しない"
            "連鎖不整合(§6.3-6)。署名は有効 — Ed25519 failure に潰してはならない",
            predecessor={
                "base": "var-create",
                "signed_bytes_sha256_hex": var_create["signed_bytes_sha256_hex"],
                "status": "active",
            },
        ),
        rule_negative(
            "revive-after-delete", "variable", "env-prod-0001", "var-api-key-0001", "API_KEY_REVIVED",
            "active", 4, var_delete["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "revived-after-delete",
            "deleted(var-delete、metaVersion 3)の後の active 化は、prev 連鎖・署名が有効でも"
            "拒否する(§4.2 — ID 再利用禁止のステートメント層での対応物。削除済み変数の無断復活の遮断)",
            predecessor={
                "base": "var-delete",
                "signed_bytes_sha256_hex": var_delete["signed_bytes_sha256_hex"],
                "status": "deleted",
            },
        ),
    ]

    write(
        "metadata-signature.json",
        {
            "description": "CRYPTO_SPEC §4.2: 変数・環境メタデータの署名付きステートメント(Ed25519)。var_meta_signed_bytes = LP(\"<suite>/var-meta-sig\", project_id, environment_id, variable_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)、env_meta_signed_bytes = LP(\"<suite>/env-meta-sig\", project_id, environment_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)。チェーン・鍵は chain-entries.json の正規 12 エントリチェーンを参照",
            "var_signed_fields_order": VAR_META_SIG_FIELDS_ORDER,
            "env_signed_fields_order": ENV_META_SIG_FIELDS_ORDER,
            "binary_encoding": "ハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(meta_version / chain_head_seq)は 10 進文字列化。name は UTF-8 バイト列を byte-exact に束縛(NFC 正規化は署名前のクライアントの責務 — §4.2)",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、author 鍵 = keys",
            "no_epoch_anchor": "メタステートメントはエポックアンカーを持たない(§4.2)。値署名の epoch-not-current-at-head / environment-not-created-at-head に相当する検証規則は存在せず、前進 meta_version への注入は v1 未検出の既知残余(§14.3-5)。var-meta-head-before-env-create が positive であることがこの非対称の固定",
            "extra_keys": {
                "ghost": {
                    "note": "author-unknown-in-history 用(チェーン履歴に存在しない鍵)",
                    "enc_sk_seed_hex": pat(0x78, 32).hex(),
                    "sig_sk_seed_hex": pat(0x88, 32).hex(),
                    "enc_pub_hex": ghost["enc_pub_hex"],
                    "sig_pub_hex": ghost["sig_pub_hex"],
                    "key_fingerprint_hex": ghost["fp_hex"],
                },
            },
            "tenure_extension": tenure_extension,
            "vectors": vectors,
            "rename_fork": {
                "note": "同一座標(var-api-key-0001 × metaVersion 2)に対する内容の異なる 2 つの"
                        "有効ステートメント。各 branch は単体で §6.3 の全検証を通り(両方 verify 成功)、"
                        "組として signed_bytes_sha256_hex の相違 = サーバー equivocation の否認不能な"
                        "証拠になる(§14.2-5。防止ではなく証拠化)",
                "branches": fork_branches,
            },
            "name_swap": name_swap,
            "negative": negatives + rule_negatives,
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
    gen_dek_wrap_signature()
    gen_dek_commitment()
    gen_value_signature()  # chain-entries.json / 上記の出力を参照するため後段で生成
    gen_metadata_signature()  # 同上(chain-entries.json を参照)
    gen_recovery_wrap()
