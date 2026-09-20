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
    # 2026-09-14(CRYPTO_SPEC 0.11-draft §6.2 — ES): add_member / change_role の
    # payload 末尾に scope_kind("all" | "listed")と scope_environments_lp_hex
    # (grant_server の scope_environments と同じ入れ子 LP)を追加した形が正規形。
    # 旧 4 / 2 フィールド形式は互換経路を持たない(negative add-member-scope-dropped /
    # change-role-scope-dropped が「旧形式のバイト列では正規署名が検証に失敗する」を固定)
    "add_member": ["target_user_id", "enc_pub_hex", "sig_pub_hex", "role",
                   "scope_kind", "scope_environments_lp_hex"],
    "remove_member": ["target_user_id"],
    "change_role": ["target_user_id", "new_role", "scope_kind", "scope_environments_lp_hex"],
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
    # 2026-08-27(セッション 33 / CRYPTO_SPEC 0.7-draft §6.2 の checkpoint op を
    # PR-F3a で実装 — M2 の前倒し)。環境エントリのリストは scope_environments と
    # 同じ入れ子 LP の hex 文字列として 1 フィールドに載せる
    "checkpoint": ["environments_lp_hex", "audit_head_hash_hex"],
    # 2026-09-14(CRYPTO_SPEC 0.11-draft §6.2 — PF1 四眼): 4 op を追加。
    # ops_lp_hex = op 名リストの入れ子 LP の hex(scope_environments と同型)、
    # inner_payload_lp_hex = 内側 op の payload_bytes(§6.1 の入れ子 LP)の hex、
    # proposal_hash_hex = 提案エントリの entry_hash(hex 小文字 64)
    "set_approval_policy": ["ops_lp_hex", "required_approvals"],
    "propose": ["inner_op", "inner_payload_lp_hex", "expires_at_ms"],
    "approve": ["proposal_hash_hex"],
    "withdraw": ["proposal_hash_hex"],
    # 2026-09-20(CRYPTO_SPEC 0.12-draft §6.2 — DK 端末鍵): 2 op を追加。add_device の
    # scope 2 フィールドは「環境スコープ」と同じ符号化、revoke_device の
    # device_fingerprints_lp_hex = FP(hex 小文字 32)リストの入れ子 LP の hex
    "add_device": ["enc_pub_hex", "sig_pub_hex", "role_cap", "scope_kind",
                   "scope_environments_lp_hex"],
    "revoke_device": ["target_user_id", "device_fingerprints_lp_hex"],
}

# CRYPTO_SPEC §6.2: checkpoint の values_digest。
#   values_digest_hex = lower_hex(SHA-256(LP("maruhi/v1/env-values-digest", v_1, …, v_m)))
#   v_j = LP(variable_id, version, value_sig_hash_hex) — variable_id のバイト昇順。
#   active 変数のみ(tombstone はマニフェスト側 — §4.3 — が捕捉する)。空集合も有効
ENV_VALUES_DIGEST_DOMAIN = "maruhi/v1/env-values-digest"


def env_values_digest_hex(value_entries: list) -> str:
    ordered = sorted(value_entries, key=lambda v: v["variable_id"].encode("utf-8"))
    fields = [ENV_VALUES_DIGEST_DOMAIN] + [
        lp_encode([v["variable_id"], v["version"], v["value_sig_hash_hex"]])
        for v in ordered
    ]
    return sha256(lp_encode(fields)).hex()


# --- チェーンエントリ構築の共有ヘルパ(gen_chain_entries と、env-manifest の
# ハッシュを要するため後段で実行する gen_checkpoint_boundary_chains が共用)---

CHAIN_SUITE = "maruhi/v1"


def chain_payload_bytes(op: str, payload: dict) -> bytes:
    return lp_encode([payload[k] for k in PAYLOAD_FIELD_ORDER[op]])


def build_chain_entry(seq, op, actor_id, actor, payload, timestamp, prev_hex):
    pb = chain_payload_bytes(op, payload)
    signed = lp_encode(
        [CHAIN_SUITE, seq, prev_hex, op, actor_id, actor["fp_hex"], pb, timestamp]
    )
    sig = actor["sig_sk"].sign(signed)
    entry_bytes = lp_encode(
        [CHAIN_SUITE, seq, prev_hex, op, actor_id, actor["fp_hex"], pb, timestamp, sig.hex()]
    )
    return {
        "seq": seq,
        "suite": CHAIN_SUITE,
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


def checkpoint_env_entry_tuple(environment_id, epoch, manifest_version,
                               manifest_sig_hash_hex, values_digest_hex) -> dict:
    return {
        "environment_id": environment_id,
        "epoch": str(epoch),
        "manifest_version": str(manifest_version),
        "manifest_sig_hash_hex": manifest_sig_hash_hex,
        "values_digest_hex": values_digest_hex,
    }


def checkpoint_environments_lp_hex(env_entries: list) -> str:
    # scope_environments / lease_policy と同じ入れ子 LP: 各環境エントリを
    # LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
    # values_digest_hex) のバイト列にし、リストの LP の hex 小文字文字列を
    # payload の 1 フィールドに載せる。リスト順は署名対象の一部
    # (生成は environment_id のバイト昇順 SHOULD — 検証は順序を規範にしない)
    return lp_encode([
        lp_encode([e["environment_id"], e["epoch"], e["manifest_version"],
                   e["manifest_sig_hash_hex"], e["values_digest_hex"]])
        for e in env_entries
    ]).hex()


def checkpoint_payload(env_entries: list, audit_head_hash_hex: str = "") -> dict:
    return {
        "environments": env_entries,  # 可読性のための平文表現(正規化対象は *_lp_hex)
        "environments_lp_hex": checkpoint_environments_lp_hex(env_entries),
        "audit_head_hash_hex": audit_head_hash_hex,
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


# --- ES / PF1 の payload ヘルパ(CRYPTO_SPEC 0.11-draft §6.2)-----------------------

def scope_fields(kind: str, environment_ids: list) -> dict:
    """メンバー scope の payload フィールド(add_member / change_role の末尾 2 つ)。

    scope_kind ∈ {"all", "listed"}。"all" のリストは空でなければならない(非空は
    invalid-payload — 構造規則)。リストは grant_server の scope_environments と同じ
    入れ子 LP(順序は署名対象。生成はコードポイント昇順 SHOULD・検証は集合)。
    scope_environments は可読性のための平文表現(正規化対象は *_lp_hex)。
    """
    return {
        "scope_kind": kind,
        "scope_environments": list(environment_ids),
        "scope_environments_lp_hex": scope_environments_lp_hex(list(environment_ids)),
    }


def approval_ops_lp_hex(ops: list) -> str:
    # set_approval_policy の ops: op 名のリストを LP エンコード(入れ子 LP)し、その
    # hex 小文字文字列を payload の 1 フィールドに載せる(scope_environments と同型)。
    # リスト順は署名対象の一部(生成はコードポイント昇順 SHOULD・検証は集合)
    return lp_encode(list(ops)).hex()


def policy_payload(ops: list, required_approvals: int) -> dict:
    return {
        "ops": list(ops),  # 可読性のための平文表現(正規化対象は ops_lp_hex)
        "ops_lp_hex": approval_ops_lp_hex(ops),
        "required_approvals": str(required_approvals),
    }


def propose_payload(inner_op: str, inner_payload: dict, expires_at_ms: int) -> dict:
    # inner_payload_lp_hex = 内側 op の payload_bytes(PAYLOAD_FIELD_ORDER[inner_op] の
    # 順の LP)の hex 小文字。内側 op が scope / ops の入れ子 LP を持つ場合は 2 段の
    # 入れ子になる(payload_bytes → signed_bytes の入れ子と同型)
    return {
        "inner_op": inner_op,
        "inner_payload": inner_payload,  # 可読性のための平文表現(正規化対象は *_lp_hex)
        "inner_payload_lp_hex": chain_payload_bytes(inner_op, inner_payload).hex(),
        "expires_at_ms": str(expires_at_ms),
    }


def proposal_ref_payload(proposal_entry: dict) -> dict:
    return {"proposal_hash_hex": proposal_entry["entry_hash_hex"]}


def member_state(role: str, kind: str, environment_ids: list | None = None) -> dict:
    """expected_* のメンバー状態表現(§6.2 の検証状態 = role + scope)。"""
    scope = {"kind": kind}
    if kind == "listed":
        scope["environments"] = list(environment_ids or [])
    else:
        assert not environment_ids
    return {"role": role, "scope": scope}


def gen_chain_entries():
    owner_id = "user-owner-0001"
    member_id = "user-member-0002"
    admin_id = "user-admin-0003"
    owner = make_user(pat(0x10, 32), pat(0x20, 32))
    member = make_user(pat(0x30, 32), pat(0x40, 32))
    admin = make_user(pat(0x50, 32), pat(0x60, 32))
    server = make_server(pat(0x90, 32))
    suite = "maruhi/v1"

    # ES / PF1(2026-09-14)で正規チェーンへ加わるメンバー(seed は他ベクターと非重複)
    devmember_id = "user-devmember-0010"    # member listed{dev} → seq 17 で {dev, stage} → seq 22 で reader{dev}
    devadmin_id = "user-devadmin-0011"      # admin listed{dev, stage}(dev 専任 admin — 裁定 C-2)
    prodreader_id = "user-prodreader-0012"  # reader listed{prod}
    allmember_id = "user-allmember-0013"    # member all
    owner2_id = "user-owner-0014"           # owner all(四眼の承認者)
    owner3_id = "user-owner-0015"           # owner all(3 人目 — 降格しても定足数 2 を保てる)
    devmember = make_user(pat(0x3A, 32), pat(0x4A, 32))
    devadmin = make_user(pat(0x3B, 32), pat(0x4B, 32))
    prodreader = make_user(pat(0x3C, 32), pat(0x4C, 32))
    allmember = make_user(pat(0x3D, 32), pat(0x4D, 32))
    owner2 = make_user(pat(0x3E, 32), pat(0x4E, 32))
    owner3 = make_user(pat(0x3F, 32), pat(0x4F, 32))
    users = {
        owner_id: owner, member_id: member, admin_id: admin,
        devmember_id: devmember, devadmin_id: devadmin, prodreader_id: prodreader,
        allmember_id: allmember, owner2_id: owner2, owner3_id: owner3,
    }
    ALL = scope_fields("all", [])
    DEV = "env-dev-0002"
    PROD = "env-prod-0001"
    STAGE = "env-stage-0003"

    def add_payload(target_id: str, target: dict, role: str, kind: str = "all",
                    environment_ids: list | None = None) -> dict:
        return {
            "target_user_id": target_id,
            "enc_pub_hex": target["enc_pub_hex"],
            "sig_pub_hex": target["sig_pub_hex"],
            "role": role,
            **scope_fields(kind, environment_ids or []),
        }

    def change_payload(target_id: str, new_role: str, kind: str = "all",
                       environment_ids: list | None = None) -> dict:
        return {
            "target_user_id": target_id,
            "new_role": new_role,
            **scope_fields(kind, environment_ids or []),
        }

    # モジュールレベルの共有ヘルパ(build_chain_entry — 2026-08-27 に
    # gen_checkpoint_boundary_chains と共用化)への別名。出力は不変
    payload_bytes = chain_payload_bytes
    build_entry = build_chain_entry

    entries = []
    prev_hash_hex = "0" * 64

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
        "env-dev-0002": {1: pat(0xC8, 32), 2: pat(0xCC, 32), 3: pat(0xD0 + 0x60, 32)},
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
              add_payload(member_id, member, "member"), t0 + 1000)
    add_entry(3, "create_environment", member_id, member,
              create_env_payload("env-prod-0001"), t0 + 2000)
    add_entry(4, "rotate_epoch", member_id, member,
              rotate_payload("env-prod-0001", 2), t0 + 3000)
    add_entry(5, "remove_member", owner_id, owner,
              {"target_user_id": member_id}, t0 + 4000)
    add_entry(6, "add_member", owner_id, owner,
              add_payload(admin_id, admin, "reader"), t0 + 5000)
    add_entry(7, "change_role", owner_id, owner,
              change_payload(admin_id, "admin"), t0 + 6000)
    add_entry(8, "create_environment", admin_id, admin,
              create_env_payload("env-dev-0002"), t0 + 7000)
    add_entry(9, "grant_server", owner_id, owner, grant_payload, t0 + 8000)
    add_entry(10, "rotate_epoch", admin_id, admin,
              rotate_payload("env-dev-0002", 2), t0 + 9000)
    add_entry(11, "create_environment", owner_id, owner,
              create_env_payload("env-stage-0003"), t0 + 10000)
    add_entry(12, "revoke_server", owner_id, owner,
              {"server_key_fingerprint_hex": server["fp_hex"]}, t0 + 11000)

    # --- ES + PF1 の追記(2026-09-14 — CRYPTO_SPEC 0.11-draft §6.2 / §11)-------------
    # seq 1〜12 の構造は据え置き(seq 2 / 6 / 7 に scope = all を足しただけ)。value /
    # meta / manifest / head-attestation の正例が参照する seq の意味は不変。
    # seq 13〜19: listed / all の各 scope のメンバー(方針オフ)。seq 17 は dev 専任
    # admin による scope のみの変更(原則 1 の許容側: 対称差 {stage} ⊆ actor scope)。
    # seq 20〜24: set_approval_policy → propose → approve(適用)→ propose → withdraw。
    # 提案の期限は t0 + 7 日(CLI 既定値 — AUTH_SPEC §12-8 の上界 30 日以内)
    EXPIRES = t0 + 7 * 24 * 60 * 60 * 1000
    POLICY_OPS = ["change_role", "grant_server", "remove_member", "set_approval_policy"]
    add_entry(13, "add_member", owner_id, owner,
              add_payload(devmember_id, devmember, "member", "listed", [DEV]), t0 + 12000)
    add_entry(14, "add_member", owner_id, owner,
              add_payload(devadmin_id, devadmin, "admin", "listed", [DEV, STAGE]), t0 + 13000)
    add_entry(15, "add_member", owner_id, owner,
              add_payload(prodreader_id, prodreader, "reader", "listed", [PROD]), t0 + 14000)
    add_entry(16, "add_member", owner_id, owner,
              add_payload(allmember_id, allmember, "member"), t0 + 15000)
    add_entry(17, "change_role", devadmin_id, devadmin,
              change_payload(devmember_id, "member", "listed", [DEV, STAGE]), t0 + 16000)
    add_entry(18, "add_member", owner_id, owner,
              add_payload(owner2_id, owner2, "owner"), t0 + 17000)
    add_entry(19, "add_member", owner_id, owner,
              add_payload(owner3_id, owner3, "owner"), t0 + 18000)
    add_entry(20, "set_approval_policy", owner_id, owner,
              policy_payload(POLICY_OPS, 2), t0 + 19000)
    demote_devmember = change_payload(devmember_id, "reader", "listed", [DEV])
    add_entry(21, "propose", owner_id, owner,
              propose_payload("change_role", demote_devmember, EXPIRES), t0 + 20000)
    p21 = entries[20]
    add_entry(22, "approve", owner2_id, owner2, proposal_ref_payload(p21), t0 + 21000)
    remove_devmember = {"target_user_id": devmember_id}
    add_entry(23, "propose", devadmin_id, devadmin,
              propose_payload("remove_member", remove_devmember, EXPIRES), t0 + 22000)
    p23 = entries[22]
    add_entry(24, "withdraw", owner3_id, owner3, proposal_ref_payload(p23), t0 + 23000)
    head19 = entries[18]["entry_hash_hex"]
    head21 = entries[20]["entry_hash_hex"]
    head23 = entries[22]["entry_hash_hex"]
    head24 = entries[23]["entry_hash_hex"]
    HEAD_SEQ = len(entries)

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
            change_payload(admin_id, "owner"),
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

    def add_authz(name, seq, prev_hex, op, actor_id, actor, payload, ts, expected_reason, note,
                  chain=None):
        entry = build_entry(seq, op, actor_id, actor, payload, ts, prev_hex)
        case = authz(name, entry, expected_reason, note)
        case["verify_key_hex"] = users[actor_id]["sig_pub_hex"]
        if chain is not None:
            case["chain"] = chain
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
        change_payload(owner_id, "member"), t0 + 12000, "last-owner-protected",
        "最後の owner は降格不可(§6.2)",
    )
    add_authz(
        "authz-admin-adds-admin", 13, head12, "add_member", admin_id, admin,
        add_payload(member_id, member, "admin"),
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
         "sig_pub_hex": sock["sig_pub_hex"], "role": "reader", **ALL},
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
            "expected_members": {owner_id: member_state("owner", "all"),
                                 admin_id: member_state("admin", "all"),
                                 sock_id: member_state("reader", "all")},
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
             "sig_pub_hex": sig_hex, "role": "member", **ALL},
            t0 + 12000, "duplicate-member-key", note,
        )
    # 検査順序の固定(role 規則 → 鍵重複): actor = admin が現メンバー鍵を流用した
    # 対象に role "admin" を付与しようとするエントリは、鍵重複より先に role 規則で
    # 拒否される(insufficient-role。duplicate-member-key ではない)
    add_authz(
        "authz-add-member-role-precedes-duplicate-key", 13, head12, "add_member",
        admin_id, admin,
        {"target_user_id": "user-clone-0004", "enc_pub_hex": owner["enc_pub_hex"],
         "sig_pub_hex": owner["sig_pub_hex"], "role": "admin", **ALL},
        t0 + 12000, "insufficient-role",
        "role 規則(admin/owner 付与は owner のみ)は鍵重複検査より先に判定される(§6.2 の検査順序の固定)",
    )
    # 検査順序の固定(user_id 重複 → 鍵重複): 対象 user_id と鍵の両方が重複する
    # エントリは duplicate-member で拒否される(duplicate-member-key ではない)
    add_authz(
        "authz-add-member-duplicate-user-precedes-key", 13, head12, "add_member",
        owner_id, owner,
        {"target_user_id": admin_id, "enc_pub_hex": owner["enc_pub_hex"],
         "sig_pub_hex": owner["sig_pub_hex"], "role": "member", **ALL},
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
    # head 12 時点の現メンバー(role + scope — §6.2 の検証状態)。ES 改訂で
    # メンバー状態は role 文字列から {role, scope} へ拡張した
    OWNER_ADMIN = {owner_id: member_state("owner", "all"), admin_id: member_state("admin", "all")}

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
                                 add_payload(member_id, member, "member"),
                                 t0 + 12000, head12),
            "expected_members": {owner_id: member_state("owner", "all"),
                                 admin_id: member_state("admin", "all"),
                                 member_id: member_state("member", "all")},
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
                                  "role": "member", **ALL},
                                 t0 + 12000, head12),
            "expected_members": {owner_id: member_state("owner", "all"),
                                 admin_id: member_state("admin", "all"),
                                 "user-newcomer-0005": member_state("member", "all")},
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "note": "削除済みメンバーの鍵を別 user_id で再登録することも拒否されない(admin/owner の add_member 権限内の行為と等価 — §6.2)",
        },
        {
            "name": "create-environment-fresh-id",
            "entry": build_entry(13, "create_environment", owner_id, owner,
                                 create_env_payload("env-fresh-0004"), t0 + 12000, head12),
            "expected_members": OWNER_ADMIN,
            "expected_environments": dict(base_environments, **{"env-fresh-0004": "1"}),
            "expected_server_grants": [],
            "note": "未使用 ID の create_environment は受理され、環境はエポック 1 で環境集合に加わる(§6.2)",
        },
        {
            "name": "rotate-freshly-created-environment",
            "entry": build_entry(13, "rotate_epoch", admin_id, admin,
                                 rotate_payload("env-stage-0003", 2), t0 + 12000, head12),
            "expected_members": OWNER_ADMIN,
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
            "expected_members": OWNER_ADMIN,
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

    # 四眼の検証状態(§6.2 / §6.3): approval_policy = {ops, required_approvals} | null
    # (null = 方針なし = オフ)、pending_proposals = 提案エントリの entry_hash →
    # {proposal_seq, 提案者(user_id・鍵 FP・提案時 role)、内側 op と payload、期限、
    # approvals(受理済み approve エントリの actor の列)}。票は S = {提案者} ∪ approvals
    # のうち各 approve 時点で owner である distinct な数で数え直す(原則 2)。提案時 role は
    # 情報値であり票の入力ではない(設計録 §8 K2-6 / 正本への申し送り ②)
    def policy_state(ops: list, required: int) -> dict:
        return {"ops": list(ops), "required_approvals": str(required)}

    # 票 = (user_id, 署名時の鍵 FP)(2026-09-15 所有者委任裁定 ⑤ — 設計録 §8 K2-11)。
    # approvals には user_id(現在の鍵)か、鍵を明示した dict(再追加前の旧鍵の票)を渡す
    def vote(user_id: str, user: dict | None = None) -> dict:
        return {"user_id": user_id, "key_fingerprint_hex": (user or users[user_id])["fp_hex"]}

    def pending_state(proposal_entry: dict, proposer_role: str, approvals: list) -> dict:
        payload = proposal_entry["payload"]
        return {
            "proposal_seq": proposal_entry["seq"],
            "proposer_user_id": proposal_entry["actor"]["user_id"],
            "proposer_key_fingerprint_hex": proposal_entry["actor"]["key_fingerprint_hex"],
            "proposer_role_at_proposal": proposer_role,
            "inner_op": payload["inner_op"],
            "inner_payload": payload["inner_payload"],
            "expires_at_ms": payload["expires_at_ms"],
            "approvals": [a if isinstance(a, dict) else vote(a) for a in approvals],
        }

    def pending_map(*items) -> dict:
        return {entry["entry_hash_hex"]: pending_state(entry, role, approvals)
                for entry, role, approvals in items}

    full_environments = {
        "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
        "env-dev-0002": env_state("env-dev-0002", 2, 8, {1: 8, 2: 10}),
        "env-stage-0003": env_state("env-stage-0003", 1, 11, {1: 11}),
    }
    canonical_policy = policy_state(POLICY_OPS, 2)
    # head 19(方針オフ・全メンバー在籍)のメンバー状態
    members_19 = {
        owner_id: member_state("owner", "all"),
        admin_id: member_state("admin", "all"),
        devmember_id: member_state("member", "listed", [DEV, STAGE]),
        devadmin_id: member_state("admin", "listed", [DEV, STAGE]),
        prodreader_id: member_state("reader", "listed", [PROD]),
        allmember_id: member_state("member", "all"),
        owner2_id: member_state("owner", "all"),
        owner3_id: member_state("owner", "all"),
    }
    # head 22 以降(提案 21 の適用 = devmember は reader{dev})
    members_24 = dict(members_19, **{devmember_id: member_state("reader", "listed", [DEV])})
    members_24_without_devmember = {k: v for k, v in members_24.items() if k != devmember_id}

    expected_head_states = [
        {
            "after_seq": 5,
            "members": {owner_id: member_state("owner", "all")},
            "server_grants": [],
            "environments": {
                "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
            },
            "approval_policy": None,
            "pending_proposals": {},
        },
        {
            "after_seq": 9,
            "members": OWNER_ADMIN,
            "server_grants": [grant_state(grant_scope, grant_lease_policy, 9)],
            "environments": {
                "env-prod-0001": env_state("env-prod-0001", 2, 3, {1: 3, 2: 4}),
                "env-dev-0002": env_state("env-dev-0002", 1, 8, {1: 8}),
            },
            "approval_policy": None,
            "pending_proposals": {},
        },
        {
            "after_seq": 12,
            "members": OWNER_ADMIN,
            "server_grants": [],
            "environments": full_environments,
            "approval_policy": None,
            "pending_proposals": {},
        },
        {
            # ES: listed / all の各 scope のメンバー + dev 専任 admin による scope のみの
            # 変更(seq 17)を適用した状態。方針はまだ無い
            "after_seq": 19,
            "members": members_19,
            "server_grants": [],
            "environments": full_environments,
            "approval_policy": None,
            "pending_proposals": {},
        },
        {
            # PF1: 方針有効 + owner の提案が pending(提案者 owner の票 = 1)
            "after_seq": 21,
            "members": members_19,
            "server_grants": [],
            "environments": full_environments,
            "approval_policy": canonical_policy,
            "pending_proposals": pending_map((p21, "owner", [])),
        },
        {
            # PF1: 別 owner の approve で定足数 2 に到達 → seq 22 で内側 change_role を
            # 適用(inclusive — devmember は seq 22 から reader{dev})。pending は空
            "after_seq": 22,
            "members": members_24,
            "server_grants": [],
            "environments": full_environments,
            "approval_policy": canonical_policy,
            "pending_proposals": {},
        },
        {
            # PF1: 非 owner(dev 専任 admin)の提案(票 0)を owner が withdraw した後
            "after_seq": 24,
            "members": members_24,
            "server_grants": [],
            "environments": full_environments,
            "approval_policy": canonical_policy,
            "pending_proposals": {},
        },
    ]

    # --- checkpoint op(CRYPTO_SPEC §6.2。2026-08-27 セッション 33 = PR-F3a)--------
    # M2 の前倒し実装(session-32 §5-1 の分割 F3a)。合意規則が検証するのは
    # 形式・actor role・座標整合のみで、タプル内容(マニフェスト・値・監査ヘッド)は
    # チェーン検証では検証不能(§6.2 の「形式は合意規則、内容は照合側」)。
    # よって本セクションの manifest_sig_hash / 監査ヘッドは決定論的なダミー値で足りる。
    # 実マニフェストのハッシュと結線した境界チェックポイントの派生チェーンは
    # PR-F3b(マニフェスト検証規則の consumer 側)で追加する

    def dummy_manifest_sig_hash(environment_id: str, manifest_version: int) -> str:
        return sha256(
            f"maruhi-vector-dummy-manifest:{environment_id}:{manifest_version}".encode()
        ).hex()

    def dummy_value_sig_hash(variable_id: str, version: int) -> str:
        return sha256(f"maruhi-vector-dummy-value:{variable_id}:{version}".encode()).hex()

    empty_values_digest = env_values_digest_hex([])
    dummy_audit_head = sha256(b"maruhi-vector-dummy-audit-head").hex()

    def checkpoint_env_entry(environment_id, epoch, manifest_version,
                             values_digest_hex=None, manifest_sig_hash_hex=None):
        # ダミー既定値つきの薄いラッパ(タプル構築の実体はモジュールレベルの
        # checkpoint_env_entry_tuple — 2026-08-27 に共用化)
        return checkpoint_env_entry_tuple(
            environment_id, epoch, manifest_version,
            (manifest_sig_hash_hex if manifest_sig_hash_hex is not None
             else dummy_manifest_sig_hash(environment_id, manifest_version)),
            values_digest_hex if values_digest_hex is not None else empty_values_digest,
        )

    # head12 時点の現エポック: env-prod-0001 = 2 / env-dev-0002 = 2 / env-stage-0003 = 1
    head4 = entries[3]["entry_hash_hex"]
    cp_prod_values = env_values_digest_hex([
        {"variable_id": "var-database-url-0001", "version": "3",
         "value_sig_hash_hex": dummy_value_sig_hash("var-database-url-0001", 3)},
        {"variable_id": "var-api-key-0002", "version": "1",
         "value_sig_hash_hex": dummy_value_sig_hash("var-api-key-0002", 1)},
    ])
    # 同一 (environment, manifest_version) の正当な再公証(rotate 境界 checkpoint の
    # 後、再暗号化完了後の周期 checkpoint が同じ manifestVersion を新しい値集合で
    # 公証する — §6.3 発行 SHOULD (i)。値 push はマニフェスト版を進めない §4.3)
    cp_prod_values_reencrypted = env_values_digest_hex([
        {"variable_id": "var-database-url-0001", "version": "4",
         "value_sig_hash_hex": dummy_value_sig_hash("var-database-url-0001", 4)},
        {"variable_id": "var-api-key-0002", "version": "2",
         "value_sig_hash_hex": dummy_value_sig_hash("var-api-key-0002", 2)},
    ])
    cp_dev_entry = checkpoint_env_entry("env-dev-0002", 2, 3)
    cp_prod_entry = checkpoint_env_entry("env-prod-0001", 2, 2, values_digest_hex=cp_prod_values)
    cp_prod_reattested = checkpoint_env_entry(
        "env-prod-0001", 2, 2, values_digest_hex=cp_prod_values_reencrypted)
    cp13 = build_entry(13, "checkpoint", admin_id, admin,
                       checkpoint_payload([cp_dev_entry, cp_prod_entry]), t0 + 12000, head12)
    cp14 = build_entry(14, "checkpoint", admin_id, admin,
                       checkpoint_payload([cp_prod_reattested], dummy_audit_head),
                       t0 + 13000, cp13["entry_hash_hex"])

    def expected_checkpoint(seq: int, env_entry: dict) -> dict:
        return {
            "seq": seq,
            "epoch": env_entry["epoch"],
            "manifest_version": env_entry["manifest_version"],
            "manifest_sig_hash_hex": env_entry["manifest_sig_hash_hex"],
            "values_digest_hex": env_entry["values_digest_hex"],
        }

    extended_chains["checkpoint-baseline"] = {
        "description": (
            "正規チェーン seq 1〜12 に standalone checkpoint 2 エントリを追記した"
            "派生チェーン。seq 13(admin。監査ヘッドなし)が env-dev / env-prod の"
            "部分集合を公証し、seq 14(admin。監査ヘッド公証あり)が env-prod を"
            "同一 manifest_version・別 values_digest で再公証する — manifest_version"
            "非後退の等号側(checkpoint-regression の許容境界)と「環境ごとの最新"
            "チェックポイント」導出(env-dev は seq 13、env-prod は seq 14 が最新)を"
            "同時に固定する。checkpoint-regression 系 negative の前提チェーン"
        ),
        "base_seq": 12,
        "entries": [cp13, cp14],
        "expected_members": OWNER_ADMIN,
        "expected_checkpoints": {
            "env-dev-0002": expected_checkpoint(13, cp_dev_entry),
            "env-prod-0001": expected_checkpoint(14, cp_prod_reattested),
        },
    }

    checkpoint_negatives = []

    def add_checkpoint_authz(name, seq, prev_hex, actor_id, actor, payload, ts,
                             expected_reason, note, chain=None):
        entry = build_entry(seq, "checkpoint", actor_id, actor, payload, ts, prev_hex)
        case = authz(name, entry, expected_reason, note)
        case["verify_key_hex"] = actor["sig_pub_hex"]
        if chain is not None:
            case["chain"] = chain
        checkpoint_negatives.append(case)

    # 認可段の検査順序(§6.2): role(member 以上)→ 非空監査ヘッドの admin role →
    # unknown-environment → checkpoint-epoch-mismatch → checkpoint-regression。
    # 複数環境エントリ間は検査段ごとに全エントリを走査する(stage-wise —
    # authz-checkpoint-unknown-precedes-epoch が固定。session-33 裁定 C)
    add_checkpoint_authz(
        "authz-checkpoint-reader-role", 7, head6, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 2, 1)]),
        t0 + 6000, "insufficient-role",
        "seq 6 時点の user-admin-0003 は reader。checkpoint の発行は member 以上のみ(§6.2)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-audit-role-insufficient", 5, head4, member_id, member,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 2, 1)], dummy_audit_head),
        t0 + 4000, "checkpoint-audit-role-insufficient",
        "非空の監査ヘッドを公証できる actor は admin 以上のみ。member(seq 4 時点の user-member-0002)の監査ヘッド付き checkpoint は拒否する(§6.2)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-role-precedes-audit-role", 7, head6, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 2, 1)], dummy_audit_head),
        t0 + 6000, "insufficient-role",
        "role 不足(reader)× 監査ヘッド公証の複合違反は role 規則が先に判定される(§6.2 の検査順序: role → 監査 admin)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-unknown-environment", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-ghost-9999", 2, 1)]),
        t0 + 12000, "unknown-environment",
        "create_environment が先行しない環境を含む checkpoint は拒否する(rotate_epoch と同じ理由コード — §6.2)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-epoch-rollback", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 1, 2)]),
        t0 + 12000, "checkpoint-epoch-mismatch",
        "環境エントリの epoch はエントリ時点(自エントリ適用前)の現エポック(env-prod-0001 = 2)と厳密一致。旧エポック(1)の公証は拒否する(巻き戻し公証の遮断 — §6.2)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-epoch-ahead", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 3, 2)]),
        t0 + 12000, "checkpoint-epoch-mismatch",
        "未来エポック(3)の公証も拒否する(厳密一致 — 「現エポック以上」の誤実装はここで落ちる)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-audit-role-precedes-unknown", 5, head4, member_id, member,
        checkpoint_payload([checkpoint_env_entry("env-ghost-9999", 1, 1)], dummy_audit_head),
        t0 + 4000, "checkpoint-audit-role-insufficient",
        "監査 admin 不足 × 未知環境の複合違反は監査 role 規則が先に判定される(§6.2 の検査順序: 監査 admin → unknown-environment)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-unknown-precedes-epoch", 13, head12, admin_id, admin,
        checkpoint_payload([
            checkpoint_env_entry("env-prod-0001", 1, 2),   # epoch 不一致(リスト先頭)
            checkpoint_env_entry("env-ghost-9999", 2, 1),  # 未知環境(リスト後方)
        ]),
        t0 + 12000, "unknown-environment",
        "複数環境エントリの複合違反は検査段ごとに全エントリを走査する(stage-wise): リスト後方の unknown-environment がリスト先頭の epoch 不一致より先に判定される(session-33 裁定 C)",
    )
    add_checkpoint_authz(
        "authz-checkpoint-regression", 15, cp14["entry_hash_hex"], admin_id, admin,
        checkpoint_payload([
            checkpoint_env_entry("env-prod-0001", 2, 1, values_digest_hex=cp_prod_values),
        ]),
        t0 + 14000, "checkpoint-regression",
        "同一環境を含む直近の先行 checkpoint(seq 14 = manifest_version 2)より小さい manifest_version の公証は拒否する(床なしクライアントの検出基準の巻き戻し遮断 — §6.2)",
        chain="checkpoint-baseline",
    )
    add_checkpoint_authz(
        "authz-checkpoint-epoch-precedes-regression", 15, cp14["entry_hash_hex"],
        admin_id, admin,
        checkpoint_payload([
            checkpoint_env_entry("env-prod-0001", 1, 1, values_digest_hex=cp_prod_values),
        ]),
        t0 + 14000, "checkpoint-epoch-mismatch",
        "epoch 不一致 × manifest_version 後退の複合違反は epoch 厳密一致が先に判定される(§6.2 の検査順序: checkpoint-epoch-mismatch → checkpoint-regression)",
        chain="checkpoint-baseline",
    )

    # payload 構造検査(invalid-payload — 検証段順「構造 → actor → 署名 → 認可」の
    # 構造段。dek_commitment_hex の形式検査と同型で認可判定に先行する)
    add_checkpoint_authz(
        "checkpoint-manifest-hash-uppercase-hex", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry(
            "env-prod-0001", 2, 2,
            values_digest_hex=cp_prod_values,
            manifest_sig_hash_hex=dummy_manifest_sig_hash("env-prod-0001", 2).upper(),
        )]),
        t0 + 12000, "invalid-payload",
        "manifest_sig_hash_hex の大文字 hex は payload 構造検査で拒否する(hex 小文字 64 文字が正規形)",
    )
    add_checkpoint_authz(
        "checkpoint-values-digest-bad-length", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry(
            "env-prod-0001", 2, 2, values_digest_hex=cp_prod_values[:62])]),
        t0 + 12000, "invalid-payload",
        "values_digest_hex の長さ不正(62 文字)は payload 構造検査で拒否する",
    )
    add_checkpoint_authz(
        "checkpoint-audit-head-bad-length", 13, head12, admin_id, admin,
        checkpoint_payload([cp_prod_entry], dummy_audit_head[:32]),
        t0 + 12000, "invalid-payload",
        "audit_head_hash_hex は空文字列(公証なし)または hex 小文字 64 文字のみ。中途半端な長さは payload 構造検査で拒否する",
    )
    add_checkpoint_authz(
        "checkpoint-duplicate-environment", 13, head12, admin_id, admin,
        checkpoint_payload([cp_prod_entry, cp_prod_entry]),
        t0 + 12000, "invalid-payload",
        "重複 environment_id を含む payload は無効(MUST — §6.2)。同一環境の 2 エントリを許すと §6.3 の基準・checkpoint-regression の比較対象が非決定になる",
    )
    add_checkpoint_authz(
        "checkpoint-manifest-version-zero", 13, head12, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry("env-prod-0001", 2, 0)]),
        t0 + 12000, "invalid-payload",
        "manifest_version は 1 始まりの正整数。0 は payload 構造検査で拒否する",
    )
    add_checkpoint_authz(
        "checkpoint-format-precedes-role", 7, head6, admin_id, admin,
        checkpoint_payload([checkpoint_env_entry(
            "env-prod-0001", 2, 1, values_digest_hex=empty_values_digest[:62])]),
        t0 + 6000, "invalid-payload",
        "形式違反 × role 不足(seq 6 時点の reader)の複合違反は構造検査が先に判定される(create-env-commitment-format-precedes-role と同型)",
    )

    # 署名系 negative: environments の改竄と入れ子 LP の平坦化(いずれも元署名が
    # 検証に失敗し、正規化はこのバイト列を生まない)。base は checkpoint-baseline の
    # seq 13 エントリ(正規 12 エントリチェーンに checkpoint op が存在しないため、
    # 派生チェーンのエントリを chain フィールドで参照する)
    tampered_cp_payload = checkpoint_payload([
        cp_dev_entry,
        checkpoint_env_entry(
            "env-prod-0001", 2, 3,
            values_digest_hex=cp_prod_values,
            manifest_sig_hash_hex=cp_prod_entry["manifest_sig_hash_hex"],
        ),
    ])
    checkpoint_negatives.append({
        "name": "checkpoint-tampered-environments",
        "base_seq": 13,
        "chain": "checkpoint-baseline",
        "payload": tampered_cp_payload,
        "signed_bytes_hex": lp_encode([
            suite, 13, head12, "checkpoint", admin_id, admin["fp_hex"],
            payload_bytes("checkpoint", tampered_cp_payload), t0 + 12000,
        ]).hex(),
        "signature_hex": cp13["signature_hex"],
        "verify_key_hex": admin["sig_pub_hex"],
        "must_fail": True,
        "note": "環境エントリの manifest_version を書き換えると元の署名は検証に失敗する(タプルは署名対象)",
    })
    flat_cp_fields = []
    for e in [cp_dev_entry, cp_prod_entry]:
        flat_cp_fields += [e["environment_id"], e["epoch"], e["manifest_version"],
                           e["manifest_sig_hash_hex"], e["values_digest_hex"]]
    flat_cp_payload = {
        "environments": [cp_dev_entry, cp_prod_entry],
        "environments_lp_hex": lp_encode(flat_cp_fields).hex(),
        "audit_head_hash_hex": "",
    }
    checkpoint_negatives.append({
        "name": "checkpoint-environments-flat-concat",
        "base_seq": 13,
        "chain": "checkpoint-baseline",
        "signed_bytes_hex": lp_encode([
            suite, 13, head12, "checkpoint", admin_id, admin["fp_hex"],
            payload_bytes("checkpoint", flat_cp_payload), t0 + 12000,
        ]).hex(),
        "signature_hex": cp13["signature_hex"],
        "verify_key_hex": admin["sig_pub_hex"],
        "must_fail": True,
        "note": "環境エントリを入れ子 LP でなく 1 段の平坦 LP でエンコードしたバイト列では署名検証に失敗する(エントリ境界の曖昧性排除 — §2.1)",
    })

    negatives += checkpoint_negatives

    valid_appends += [
        {
            "name": "standalone-checkpoint-all-environments",
            "entry": build_entry(13, "checkpoint", admin_id, admin,
                                 checkpoint_payload([
                                     checkpoint_env_entry("env-dev-0002", 2, 3),
                                     checkpoint_env_entry("env-prod-0001", 2, 2,
                                                          values_digest_hex=cp_prod_values),
                                     checkpoint_env_entry("env-stage-0003", 1, 1),
                                 ]), t0 + 12000, head12),
            "expected_members": OWNER_ADMIN,
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "expected_checkpoints": {
                "env-dev-0002": expected_checkpoint(13, checkpoint_env_entry("env-dev-0002", 2, 3)),
                "env-prod-0001": expected_checkpoint(
                    13, checkpoint_env_entry("env-prod-0001", 2, 2,
                                             values_digest_hex=cp_prod_values)),
                "env-stage-0003": expected_checkpoint(
                    13, checkpoint_env_entry("env-stage-0003", 1, 1)),
            },
            "note": "member 以上による全環境カバーの standalone checkpoint(環境エントリは environment_id のバイト昇順 — 生成 SHOULD)は受理され、各環境の最新チェックポイントが導出される(§6.2 / §6.3。エポック 1 のままの環境 = env-stage-0003 も公証できる)",
        },
        {
            "name": "checkpoint-empty-environments",
            "entry": build_entry(13, "checkpoint", owner_id, owner,
                                 checkpoint_payload([], dummy_audit_head), t0 + 12000, head12),
            "expected_members": OWNER_ADMIN,
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "expected_checkpoints": {},
            "note": "環境エントリ 0 件(environments_lp_hex = 空文字列)+ 監査ヘッド公証のみの checkpoint も有効(§6.2 の「要素 0 も有効」。owner は admin 以上なので監査ヘッドを公証できる)",
        },
    ]

    # env values digest の単体ベクター(§6.2 の values_digest 正規形 —
    # env-manifest.json の digests セクションと同型の固定)
    values_digests = [
        {
            "name": "empty-set",
            "entries": [],
            "values_digest_hex": empty_values_digest,
            "note": "変数ゼロの環境(環境作成の境界 checkpoint — AUTH_SPEC §12-4)も有効なダイジェストを持つ(要素 0 の LP)",
        },
        {
            "name": "single-entry",
            "entries": [
                {"variable_id": "var-database-url-0001", "version": "3",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-database-url-0001", 3)},
            ],
            "values_digest_hex": env_values_digest_hex([
                {"variable_id": "var-database-url-0001", "version": "3",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-database-url-0001", 3)},
            ]),
            "note": "v_j = LP(variable_id, version, value_sig_hash_hex)。version は 10 進文字列化(§2.1)",
        },
        {
            "name": "byte-ascending-order",
            "entries": [
                {"variable_id": "var-a-0010", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-a-0010", 1)},
                {"variable_id": "var-㊙-0001", "version": "2",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-㊙-0001", 2)},
                {"variable_id": "var-Z-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-Z-0001", 1)},
                {"variable_id": "var-a-0002", "version": "10",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-a-0002", 10)},
            ],
            "values_digest_hex": env_values_digest_hex([
                {"variable_id": "var-a-0010", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-a-0010", 1)},
                {"variable_id": "var-㊙-0001", "version": "2",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-㊙-0001", 2)},
                {"variable_id": "var-Z-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-Z-0001", 1)},
                {"variable_id": "var-a-0002", "version": "10",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-a-0002", 10)},
            ]),
            "note": "正規順は variable_id の UTF-8 バイト昇順: var-Z-0001(0x5A)< var-a-0002 < var-a-0010 < var-㊙-0001(0xE3…)。ロケール・数値順でなくバイト順であることを固定する(entries は非正規順で列挙 — 実装は内部でソートして同じダイジェストに到達する)",
        },
        {
            # サロゲートペア境界(session-31 M1-T2 — 2026-08-28): BMP 高位
            # U+FFE5(UTF-8 EF BF A5)は astral U+1F511(UTF-8 F0 9F 94 91)より
            # 先。UTF-16 コード単位比較(JS の素の文字列比較)ではサロゲート
            # 0xD83D < 0xFFE5 で逆順になるため、この対が両実装を判別する
            "name": "surrogate-boundary-order",
            "entries": [
                {"variable_id": "var-\U0001F511-0001", "version": "2",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-\U0001F511-0001", 2)},
                {"variable_id": "var-￥-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-￥-0001", 1)},
                {"variable_id": "var-㊙-0001", "version": "3",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-㊙-0001", 3)},
                {"variable_id": "var-z-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-z-0001", 1)},
            ],
            "values_digest_hex": env_values_digest_hex([
                {"variable_id": "var-\U0001F511-0001", "version": "2",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-\U0001F511-0001", 2)},
                {"variable_id": "var-￥-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-￥-0001", 1)},
                {"variable_id": "var-㊙-0001", "version": "3",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-㊙-0001", 3)},
                {"variable_id": "var-z-0001", "version": "1",
                 "value_sig_hash_hex": dummy_value_sig_hash("var-z-0001", 1)},
            ]),
            "note": "サロゲートペア境界の byte-ascending(session-31 M1-T2): 正規順は var-z-0001(0x7A)< var-㊙-0001(0xE3…)< var-￥-0001(U+FFE5 = 0xEF BF A5)< var-🔑-0001(U+1F511 = 0xF0 9F 94 91)。UTF-16 コード単位順(JS の素の文字列比較)はサロゲート(0xD83D)< U+FFE5 のため最後の 2 要素が逆転する — UTF-8 バイト順の実装だけがこのダイジェストに到達する(entries は非正規順で列挙)",
        },
    ]

    # =========================================================================
    # ES + PF1(2026-09-14 — CRYPTO_SPEC 0.11-draft §6.2 / §11。設計録 §3-ter の
    # 2 原則ごとに負例を列挙する): 署名系 negative・構造 / 認可系 negative・
    # 派生チェーン(四眼の状態を要する前提)・許容側(valid_appends)
    # =========================================================================
    es_start = len(authz_cases)
    e2 = entries[1]     # add_member member all
    e7 = entries[6]     # change_role admin all
    e13 = entries[12]   # add_member devmember listed{dev}
    e14 = entries[13]   # add_member devadmin listed{dev, stage}
    e17 = entries[16]   # change_role by devadmin(scope のみ)
    e20 = entries[19]   # set_approval_policy
    e21 = entries[20]   # propose(owner)
    e22 = entries[21]   # approve(owner2)
    GHOST = "env-ghost-9999"
    FRESH = "env-fresh-0004"
    newcomer_id = "user-newcomer-0005"  # seq 5 で削除済み member の鍵を持つ新規 user_id
    newcomer = member
    BOGUS_HASH = sha256(b"maruhi-vector-bogus-proposal").hex()

    def resign_actor(name, base_entry, payload, note):
        return resign_variant(name, base_entry, payload, note,
                              verify_key_hex=users[base_entry["actor"]["user_id"]]["sig_pub_hex"])

    def dropped_form(name, base_entry, old_fields, note):
        # 旧形式(フィールド欠落)のバイト列に対して正規エントリの署名を検証 → 失敗すべき。
        # 旧実装が新チェーンを検証できない(= 互換経路が無い)ことの明示的な固定
        # (grant-server-lease-policy-dropped と同型)
        signed = lp_encode([
            suite, base_entry["seq"], base_entry["prev_hash_hex"], base_entry["op"],
            base_entry["actor"]["user_id"], base_entry["actor"]["key_fingerprint_hex"],
            lp_encode([base_entry["payload"][k] for k in old_fields]),
            base_entry["timestamp_ms"],
        ])
        return {
            "name": name,
            "base_seq": base_entry["seq"],
            "signed_bytes_hex": signed.hex(),
            "signature_hex": base_entry["signature_hex"],
            "verify_key_hex": users[base_entry["actor"]["user_id"]]["sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    def raw_signed(name, base_entry, payload_bytes_value: bytes, note):
        signed = lp_encode([
            suite, base_entry["seq"], base_entry["prev_hash_hex"], base_entry["op"],
            base_entry["actor"]["user_id"], base_entry["actor"]["key_fingerprint_hex"],
            payload_bytes_value, base_entry["timestamp_ms"],
        ])
        return {
            "name": name,
            "base_seq": base_entry["seq"],
            "signed_bytes_hex": signed.hex(),
            "signature_hex": base_entry["signature_hex"],
            "verify_key_hex": users[base_entry["actor"]["user_id"]]["sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    tampered_hash = bytearray(bytes.fromhex(e22["payload"]["proposal_hash_hex"]))
    tampered_hash[0] ^= 0x01
    flat_propose = lp_encode([
        e21["payload"]["inner_op"],
        *[e21["payload"]["inner_payload"][k] for k in PAYLOAD_FIELD_ORDER["change_role"]],
        e21["payload"]["expires_at_ms"],
    ])
    negatives += [
        dropped_form(
            "add-member-scope-dropped", e2, ["target_user_id", "enc_pub_hex", "sig_pub_hex", "role"],
            "scope_kind / scope_environments_lp_hex を落とした旧 4 フィールド形式のバイト列では正規署名(seq 2)が検証に失敗する — ES 改訂前の実装は新チェーンを seq 2 で bad-signature として拒否する(互換経路なし — 2026-09-14 所有者裁定)",
        ),
        dropped_form(
            "change-role-scope-dropped", e7, ["target_user_id", "new_role"],
            "scope を落とした旧 2 フィールド形式の change_role のバイト列では正規署名(seq 7)が検証に失敗する(payload は 4 フィールドが正規形)",
        ),
        resign_actor(
            "add-member-scope-reorder", e14,
            dict(e14["payload"], **scope_fields("listed", [STAGE, DEV])),
            "scope_environments の順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象 — grant_server の scope と同型)",
        ),
        resign_actor(
            "add-member-scope-flat-concat", e14,
            dict(e14["payload"], scope_environments_lp_hex="".join([DEV, STAGE]).encode("utf-8").hex()),
            "scope を入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する(§2.1 の曖昧性排除)",
        ),
        resign_actor(
            "add-member-scope-relabel-all", e13,
            dict(e13["payload"], **scope_fields("all", [])),
            "scope_kind の書き換え(listed{dev} → all)は署名検証に失敗する(scope は署名対象 — 付与範囲の付け替え対策)",
        ),
        resign_actor(
            "change-role-tampered-scope", e17,
            dict(e17["payload"], **scope_fields("listed", [DEV])),
            "change_role の scope_environments の書き換え({dev, stage} → {dev})は署名検証に失敗する",
        ),
        resign_actor(
            "policy-ops-reorder", e20,
            policy_payload(list(reversed(POLICY_OPS)), 2),
            "set_approval_policy の ops の順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象。生成は昇順 SHOULD・検証は集合 — §6.2)",
        ),
        resign_actor(
            "policy-ops-flat-concat", e20,
            dict(e20["payload"], ops_lp_hex="".join(POLICY_OPS).encode("utf-8").hex()),
            "ops を入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する",
        ),
        resign_actor(
            "policy-tampered-required", e20,
            policy_payload(POLICY_OPS, 3),
            "required_approvals の書き換え(2 → 3)は署名検証に失敗する",
        ),
        resign_actor(
            "propose-tampered-inner-payload", e21,
            propose_payload("change_role", change_payload(devmember_id, "member", "listed", [DEV]), EXPIRES),
            "内側 payload(new_role reader → member)の書き換えは署名検証に失敗する(inner_payload_lp_hex は署名対象)",
        ),
        resign_actor(
            "propose-tampered-expires", e21,
            propose_payload("change_role", demote_devmember, EXPIRES + 1),
            "expires_at_ms の書き換えは署名検証に失敗する(期限は署名対象 — 提案者が決める)",
        ),
        raw_signed(
            "propose-inner-payload-flat", e21, flat_propose,
            "内側 payload を入れ子 LP(inner_payload_lp_hex)でなく外側 LP に平坦に展開したバイト列では署名検証に失敗する(内側 op の境界の曖昧性排除 — §6.2 の payload 正規化)",
        ),
        resign_actor(
            "approve-tampered-hash", e22,
            {"proposal_hash_hex": bytes(tampered_hash).hex()},
            "参照する提案ハッシュの改竄は署名検証に失敗する",
        ),
    ]

    # --- 構造(invalid-payload — 検証段順「構造 → actor → 署名 → 認可」の構造段)-----
    es_cases = []

    def add_es(name, seq, prev_hex, op, actor_id, payload, ts, expected_reason, note, chain=None):
        add_authz(name, seq, prev_hex, op, actor_id, users[actor_id], payload, ts,
                  expected_reason, note, chain=chain)
        es_cases.append(name)

    T19 = t0 + 19000
    T21 = t0 + 21000
    T23 = t0 + 23000
    T24 = t0 + 24000
    add_es(
        "scope-all-nonempty-list", 20, head19, "add_member", owner_id,
        dict(add_payload(newcomer_id, newcomer, "member"), **scope_fields("all", [DEV])),
        T19, "invalid-payload",
        "scope_kind = all のとき scope_environments は空リストでなければならない(§6.2 構造規則 — 非空は invalid-payload)",
    )
    add_es(
        "scope-duplicate-id", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "member", "listed", [DEV, DEV]),
        T19, "invalid-payload",
        "重複 environment_id を含む scope は無効(§6.2 構造規則 — checkpoint と同じ「非決定性の芽を構造段で摘む」線)",
    )
    add_es(
        "add-member-scope-too-many", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "member", "listed",
                    [f"env-bulk-{i:04d}" for i in range(257)]),
        T19, "invalid-payload",
        "scope が 257 要素(上限 256 超過)の add_member は署名が有効でも拒否する(grant_server の scope_environments と同じ上限 — §6.1 / §6.2。構造検査は unknown-environment に先行)",
    )
    add_es(
        "scope-kind-unknown", 20, head19, "add_member", owner_id,
        dict(add_payload(newcomer_id, newcomer, "member"), scope_kind="some"),
        T19, "invalid-payload",
        "scope_kind は閉集合 {all, listed}。それ以外は構造段で拒否する",
    )
    add_es(
        "scope-format-precedes-role", 20, head19, "add_member", prodreader_id,
        dict(add_payload(newcomer_id, newcomer, "member"), **scope_fields("all", [PROD])),
        T19, "invalid-payload",
        "scope の構造違反 × role 不足(reader)の複合違反は構造検査が先に判定される(検証段順: 構造 → 認可)",
    )
    add_es(
        "policy-required-one", 20, head19, "set_approval_policy", owner_id,
        policy_payload(POLICY_OPS, 1), T19, "invalid-payload",
        "required_approvals は 0(オフ)または 2 以上(§6.2)。1 は構造段で拒否する",
    )
    add_es(
        "policy-ops-rotate", 20, head19, "set_approval_policy", owner_id,
        policy_payload(["rotate_epoch"], 2), T19, "invalid-payload",
        "ops は {grant_server, revoke_server, remove_member, change_role, add_member, set_approval_policy} の部分集合でなければならない(§6.2 — rotate / create / checkpoint はデータ・安全側の操作なので対象にできない)。構造段で拒否する",
    )
    add_es(
        "policy-ops-unknown-op", 20, head19, "set_approval_policy", owner_id,
        policy_payload(["self_destruct"], 2), T19, "invalid-payload",
        "未知の op 名を含む ops は構造段で拒否する",
    )
    add_es(
        "policy-format-precedes-role", 20, head19, "set_approval_policy", admin_id,
        policy_payload(POLICY_OPS, 1), T19, "invalid-payload",
        "構造違反(required_approvals = 1)× role 不足(admin)の複合違反は構造検査が先に判定される",
    )
    add_es(
        "propose-inner-op-unknown", 25, head24, "propose", owner_id,
        {"inner_op": "self_destruct", "inner_payload": {}, "inner_payload_lp_hex": "",
         "expires_at_ms": str(EXPIRES)},
        T24, "invalid-payload",
        "未知の内側 op を持つ propose は構造段で拒否する(内側 payload の形状は内側 op の形状表で検査する)",
    )
    add_es(
        "propose-inner-op-nested", 25, head24, "propose", owner_id,
        propose_payload("propose", propose_payload("remove_member", remove_devmember, EXPIRES), EXPIRES),
        T24, "invalid-payload",
        "内側 op に propose / approve / withdraw を置く形(提案の入れ子)は構造段で拒否する — これらは方針の対象になりえず(§6.2)、再帰的な内側 payload の検査を持たない(設計録 §8 K2 追記)",
    )
    add_es(
        "propose-expires-negative", 25, head24, "propose", owner_id,
        propose_payload("remove_member", remove_devmember, -1),
        T24, "invalid-payload",
        "expires_at_ms は非負の安全整数(§2.1 / §6.2)。負数は構造段で拒否する",
    )
    add_es(
        "propose-inner-shape-precedes-role", 25, head24, "propose", prodreader_id,
        {"inner_op": "remove_member", "inner_payload": {}, "inner_payload_lp_hex": "",
         "expires_at_ms": str(EXPIRES)},
        T24, "invalid-payload",
        "内側 payload の構造違反(target_user_id 欠落)× role 不足(reader)の複合違反は構造検査が先に判定される",
    )
    add_es(
        "approve-hash-uppercase", 22, head21, "approve", owner2_id,
        {"proposal_hash_hex": p21["entry_hash_hex"].upper()}, T21, "invalid-payload",
        "proposal_hash_hex の大文字 hex は構造段で拒否する(hex 小文字 64 文字が正規形)",
    )
    add_es(
        "approve-hash-bad-length", 22, head21, "approve", owner2_id,
        {"proposal_hash_hex": p21["entry_hash_hex"][:62]}, T21, "invalid-payload",
        "proposal_hash_hex の長さ不正(62 文字)は構造段で拒否する",
    )

    # --- 原則 1(権限の変更可能性 — §6.2): 権限変化の環境集合の各要素が actor の scope
    # 外にある形を、op ごと・集合代数の各形ごとに列挙する。actor = dev 専任 admin
    # (devadmin: listed{dev, stage})。head 19 = 方針オフ(approval-required が scope 検査に
    # 先行しない状態)-------------------------------------------------------------
    add_es(
        "authz-add-member-unknown-scope-environment", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "member", "listed", [GHOST]), T19, "unknown-environment",
        "listed の各 environment_id はそのエントリ時点でチェーン上に create_environment が先行していなければならない(typo の fail-closed — rotate / checkpoint と同じ理由コード)",
    )
    add_es(
        "authz-add-member-owner-listed", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "owner", "listed", [DEV]), T19, "scope-role-mismatch",
        "owner は常に all(§6.2 — 最後の owner 保護・grant_server・全環境 rotate 義務の履行者)。owner に listed を付ける add_member は無効",
    )
    add_es(
        "authz-change-role-owner-listed", 20, head19, "change_role", owner_id,
        change_payload(allmember_id, "owner", "listed", [DEV]), T19, "scope-role-mismatch",
        "owner へ昇格する change_role も scope = all でなければ無効",
    )
    add_es(
        "authz-add-member-scope-not-contained", 20, head19, "add_member", devadmin_id,
        add_payload(newcomer_id, newcomer, "member", "listed", [PROD]), T19, "scope-not-contained",
        "原則 1(add_member = 新 scope): dev 専任 admin は prod を含む scope を付与できない(prod の DEK を持たず、ラップを作れない — §7 の暗号的必然)",
    )
    add_es(
        "authz-add-member-all-scope-not-contained", 20, head19, "add_member", devadmin_id,
        add_payload(newcomer_id, newcomer, "member"), T19, "scope-not-contained",
        "原則 1(all の付与): listed の actor は all を包含しない(all = 将来の環境を含む U — §6.2 の集合代数)",
    )
    add_es(
        "authz-change-role-promotion-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(prodreader_id, "member", "listed", [PROD]), T19, "scope-not-contained",
        "原則 1(scope 不変の昇格 — pullfrog 第 9 巡の穴): role が変わるなら権限変化の環境集合は 旧 ∪ 新 = {prod}。dev 専任 admin は prod の reader を member に上げられない(義務は生じないが権限は変わる)",
    )
    add_es(
        "authz-change-role-widen-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(devmember_id, "member", "listed", [DEV, PROD, STAGE]), T19, "scope-not-contained",
        "原則 1(scope の拡大): role 不変なら権限変化の環境集合は対称差 = {prod} で actor scope 外",
    )
    add_es(
        "authz-change-role-narrow-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(prodreader_id, "reader", "listed", []), T19, "scope-not-contained",
        "原則 1(scope の縮小): 縮小分 {prod} も権限変化(= remove 相当 — §7 の rotate 義務)であり actor scope 外なら無効(A-2 の訂正「旧 ∪ 新」の対称差側)",
    )
    add_es(
        "authz-change-role-to-all-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(devmember_id, "member"), T19, "scope-not-contained",
        "原則 1(all への出): listed{dev, stage} △ all = U \\ {dev, stage} は listed の actor に包含されない(Cursor Bugbot 指摘対応 — all を現存環境へ展開してはならない)",
    )
    add_es(
        "authz-change-role-from-all-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(allmember_id, "member", "listed", [DEV, STAGE]), T19, "scope-not-contained",
        "原則 1(all からの入): all △ listed{dev, stage} = U \\ {dev, stage} — listed の actor は all の対象を listed にできない(将来環境の DEK を回収する義務を負えない)",
    )
    add_es(
        "authz-change-role-union-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(prodreader_id, "member", "listed", [DEV]), T19, "scope-not-contained",
        "原則 1(role と scope が同時に変わる形): 旧 ∪ 新 = {prod, dev} で prod が actor scope 外(新 scope だけを見る誤実装はここで落ちる)",
    )
    add_es(
        "authz-remove-member-scope-not-contained", 20, head19, "remove_member", devadmin_id,
        {"target_user_id": prodreader_id}, T19, "scope-not-contained",
        "原則 1(remove_member = 現 scope): dev 専任 admin は prod メンバーを消せない(消せる = 縮小分の rotate 義務を履行できる)",
    )
    add_es(
        "authz-remove-member-all-scope-not-contained", 20, head19, "remove_member", devadmin_id,
        {"target_user_id": allmember_id}, T19, "scope-not-contained",
        "原則 1(all の対象の remove): 現 scope = all は listed の actor に包含されない",
    )
    # --- 環境対象 op(§6.2 裁定 E): 対象環境 ∈ actor scope。create は all の actor のみ
    add_es(
        "authz-create-env-listed-admin", 20, head19, "create_environment", devadmin_id,
        create_env_payload(FRESH), T19, "environment-out-of-scope",
        "create_environment の新 environment_id は actor の scope に含まれていなければならない — listed の scope に未存在の環境は含まれえないので、環境の作成は all の actor のみ(admin でも listed なら不可)",
    )
    add_es(
        "authz-create-env-listed-member", 20, head19, "create_environment", devmember_id,
        create_env_payload(FRESH), T19, "environment-out-of-scope",
        "listed の member による環境作成も同じ述語で拒否する(作成者が受け取れない環境を作らない)",
    )
    add_es(
        "authz-rotate-out-of-scope", 20, head19, "rotate_epoch", devmember_id,
        rotate_payload(PROD, 3), T19, "environment-out-of-scope",
        "scope 外の環境への rotate_epoch は拒否する(再暗号化に旧 DEK が要る — 履行不能)",
    )
    add_es(
        "authz-checkpoint-out-of-scope", 20, head19, "checkpoint", devmember_id,
        checkpoint_payload([checkpoint_env_entry(PROD, 2, 1)]), T19, "environment-out-of-scope",
        "scope 外の環境のタプルを含む checkpoint は拒否する(values_digest の原像は値付き pull でしか得られない)",
    )
    # --- 検査順序の固定形(§6.2 の各列。scope 系は既存の検査列の後ろ)------------------
    add_es(
        "authz-add-member-duplicate-key-precedes-unknown-environment", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, admin, "member", "listed", [GHOST]), T19, "duplicate-member-key",
        "鍵重複 × 未知環境の複合違反は鍵重複が先に判定される(add_member: … → duplicate-member-key → unknown-environment)",
    )
    add_es(
        "authz-add-member-unknown-environment-precedes-scope-role-mismatch", 20, head19, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "owner", "listed", [GHOST]), T19, "unknown-environment",
        "未知環境 × owner に listed の複合違反は unknown-environment が先に判定される(add_member: unknown-environment → scope-role-mismatch)",
    )
    add_es(
        "authz-add-member-unknown-environment-precedes-scope-not-contained", 20, head19, "add_member", devadmin_id,
        add_payload(newcomer_id, newcomer, "member", "listed", [GHOST]), T19, "unknown-environment",
        "未知環境 × scope 外の複合違反は unknown-environment が先に判定される(add_member: unknown-environment → scope-not-contained)",
    )
    add_es(
        "authz-add-member-role-precedes-scope", 20, head19, "add_member", devmember_id,
        add_payload(newcomer_id, newcomer, "member", "listed", [PROD]), T19, "insufficient-role",
        "role 不足(member)× scope 外の複合違反は role 規則が先に判定される",
    )
    add_es(
        "authz-change-role-unknown-target-precedes-scope", 20, head19, "change_role", devadmin_id,
        change_payload("user-ghost-9999", "member", "listed", [PROD]), T19, "unknown-target",
        "未知の対象 × scope 外の複合違反は unknown-target が先に判定される(change_role: unknown-target → … → scope-not-contained)",
    )
    add_es(
        "authz-change-role-last-owner-precedes-unknown-environment", 13, head12, "change_role", owner_id,
        change_payload(owner_id, "member", "listed", [GHOST]), t0 + 12000, "last-owner-protected",
        "最後の owner の降格 × 未知環境の複合違反は last-owner-protected が先に判定される(change_role: last-owner-protected → unknown-environment)",
    )
    add_es(
        "authz-change-role-unknown-environment-precedes-scope-not-contained", 20, head19, "change_role", devadmin_id,
        change_payload(devmember_id, "member", "listed", [DEV, GHOST]), T19, "unknown-environment",
        "未知環境 × scope 外(ghost は actor scope 外)の複合違反は unknown-environment が先に判定される(change_role: unknown-environment → scope-not-contained)",
    )
    add_es(
        "authz-change-role-unknown-environment-precedes-scope-role-mismatch", 20, head19, "change_role", owner_id,
        change_payload(allmember_id, "owner", "listed", [GHOST]), T19, "unknown-environment",
        "未知環境 × owner に listed の複合違反は unknown-environment が先に判定される(change_role: unknown-environment → scope-role-mismatch)",
    )
    add_es(
        "authz-remove-unknown-target-precedes-scope", 20, head19, "remove_member", devadmin_id,
        {"target_user_id": "user-ghost-9999"}, T19, "unknown-target",
        "未知の対象 × scope 外の複合違反は unknown-target が先に判定される(remove_member: unknown-target → … → scope-not-contained)",
    )
    add_es(
        "authz-rotate-unknown-precedes-out-of-scope", 20, head19, "rotate_epoch", devmember_id,
        rotate_payload(GHOST, 2), T19, "unknown-environment",
        "未知環境 × scope 外の複合違反は unknown-environment が先に判定される(rotate_epoch: unknown-environment → environment-out-of-scope)",
    )
    add_es(
        "authz-rotate-out-of-scope-precedes-epoch", 20, head19, "rotate_epoch", devmember_id,
        {"environment_id": PROD, "new_epoch": "7", "reason": "scheduled",
         "dek_commitment_hex": dek_commitment_hex(project_id, PROD, 7, environment_deks[PROD][2])},
        T19, "environment-out-of-scope",
        "scope 外 × 不正エポックの複合違反は environment-out-of-scope が先に判定される(rotate_epoch: environment-out-of-scope → エポック順序)",
    )
    add_es(
        "authz-create-env-duplicate-precedes-out-of-scope", 20, head19, "create_environment", devadmin_id,
        create_env_payload(PROD), T19, "duplicate-environment",
        "ID 重複 × listed actor の複合違反は duplicate-environment が先に判定される(create_environment: duplicate-environment → environment-out-of-scope)",
    )
    add_es(
        "authz-checkpoint-audit-role-precedes-out-of-scope", 20, head19, "checkpoint", devmember_id,
        checkpoint_payload([checkpoint_env_entry(PROD, 2, 1)], dummy_audit_head), T19,
        "checkpoint-audit-role-insufficient",
        "監査 admin 不足 × scope 外タプルの複合違反は監査 role 規則が先に判定される(checkpoint: 監査 admin → … → environment-out-of-scope)",
    )
    add_es(
        "authz-checkpoint-unknown-precedes-out-of-scope", 20, head19, "checkpoint", devmember_id,
        checkpoint_payload([checkpoint_env_entry(PROD, 2, 1), checkpoint_env_entry(GHOST, 2, 1)]), T19,
        "unknown-environment",
        "scope 外タプル(先頭)× 未知環境(後方)の複合違反は unknown-environment が先に判定される(stage-wise: 段ごとに全タプルを走査)",
    )
    add_es(
        "authz-checkpoint-out-of-scope-precedes-epoch", 20, head19, "checkpoint", devmember_id,
        checkpoint_payload([checkpoint_env_entry(DEV, 1, 1), checkpoint_env_entry(PROD, 2, 1)]), T19,
        "environment-out-of-scope",
        "epoch 不一致(先頭 = scope 内の dev)× scope 外(後方 = prod)の複合違反は environment-out-of-scope が先に判定される(stage-wise — checkpoint: environment-out-of-scope → checkpoint-epoch-mismatch)",
    )

    # --- 原則 2(署名者集合 S による認可 — §6.2)と方針の単調性 -------------------------
    # 直接追記の拒否(方針有効 × 対象 op): head 24(方針 = POLICY_OPS / required 2)
    add_es(
        "authz-approval-required-change-role", 25, head24, "change_role", owner_id,
        change_payload(allmember_id, "reader"), T24, "approval-required",
        "方針が有効で ops に含まれる change_role の直接追記は S = {actor} で |S ∩ owners| ≤ 1 < 2 のため無効(原則 2 の導出 — 検査は role 規則の直後)",
    )
    add_es(
        "authz-approval-required-remove-member", 25, head24, "remove_member", owner_id,
        remove_devmember, T24, "approval-required",
        "remove_member の直接追記も同様に無効",
    )
    add_es(
        "authz-approval-required-grant-server", 25, head24, "grant_server", owner_id,
        grant_payload, T24, "approval-required",
        "grant_server の直接追記も同様に無効(サーバーへの鍵開示は四眼の本命の対象)",
    )
    add_es(
        "authz-approval-required-set-approval-policy", 25, head24, "set_approval_policy", owner_id,
        policy_payload(POLICY_OPS, 2), T24, "approval-required",
        "方針が有効な間、set_approval_policy 自身は ops の列挙に依らず常に対象(オフにするにも四眼が要る — 方針の単調性 (a))",
    )
    add_es(
        "authz-approval-required-add-member-owner", 25, head24, "add_member", owner_id,
        add_payload(newcomer_id, newcomer, "owner"), T24, "approval-required",
        "owner role を確立する add_member は add_member が ops に無くても常に対象(owner 身元の自作で定足数を満たす経路を閉じる — 方針の単調性 (a))",
    )
    add_es(
        "authz-approval-required-change-role-to-owner", 25, head24, "change_role", owner_id,
        change_payload(allmember_id, "owner"), T24, "approval-required",
        "owner へ昇格する change_role も常に対象",
    )
    add_es(
        "authz-role-precedes-approval-required", 25, head24, "change_role", devmember_id,
        change_payload(prodreader_id, "member", "listed", [PROD]), T24, "insufficient-role",
        "role 不足(reader)× 方針下の直接追記の複合違反は role 規則が先に判定される(change_role: role → approval-required)",
    )
    add_es(
        "authz-approval-required-precedes-unknown-target", 25, head24, "change_role", owner_id,
        change_payload("user-ghost-9999", "member"), T24, "approval-required",
        "方針下の直接追記 × 未知の対象の複合違反は approval-required が先に判定される(change_role: approval-required → unknown-target)",
    )
    add_es(
        "authz-approval-required-precedes-scope", 25, head24, "change_role", devadmin_id,
        change_payload(prodreader_id, "member", "listed", [PROD]), T24, "approval-required",
        "方針下の直接追記 × scope 外の複合違反は approval-required が先に判定される(change_role: approval-required → … → scope-not-contained)",
    )
    add_es(
        "authz-approval-required-precedes-quorum", 25, head24, "set_approval_policy", owner_id,
        policy_payload(POLICY_OPS, 4), T24, "approval-required",
        "方針下の直接変更 × 到達不能な定足数の複合違反は approval-required が先に判定される(set_approval_policy: approval-required → approval-quorum-unreachable)",
    )
    add_es(
        "authz-policy-role-precedes-approval-required", 25, head24, "set_approval_policy", admin_id,
        policy_payload(POLICY_OPS, 2), T24, "insufficient-role",
        "set_approval_policy は owner のみ。admin による方針変更は role 規則で拒否される(role → approval-required)",
    )
    # 設計録 §8-ter(K2-8 の原則「隣接する検査対はベクターで固定されているか共起不能か」の
    # 機械照合で未固定と判明した対): approval-required は role 規則の直後 = op 固有の
    # 検査(duplicate-member / duplicate-member-key / duplicate-server-key)より前
    add_es(
        "authz-approval-required-precedes-duplicate-member", 25, head24, "add_member", owner_id,
        add_payload(allmember_id, allmember, "owner"), T24, "approval-required",
        "方針下の owner 確立 add_member × 既存 user_id(user-allmember-0013)の複合違反は approval-required が先に判定される(add_member: role → approval-required → duplicate-member)",
    )
    add_es(
        "authz-approval-required-precedes-duplicate-member-key", 25, head24, "add_member", owner_id,
        add_payload(newcomer_id, allmember, "owner"), T24, "approval-required",
        "方針下の owner 確立 add_member × 現メンバー(user-allmember-0013)の鍵重複の複合違反は approval-required が先に判定される(add_member: role → approval-required → duplicate-member-key)",
    )
    add_es(
        "authz-approval-required-precedes-duplicate-server-key", 25, head24, "grant_server", owner_id,
        duplicate_key_payload(grant_scope, []), T24, "approval-required",
        "方針下(ops に grant_server)の直接 grant × サーバー鍵重複(user-admin-0003 の enc 鍵)の複合違反は approval-required が先に判定される(grant_server: role → approval-required → 鍵重複)",
    )
    add_es(
        "authz-add-member-role-precedes-duplicate-member", 25, head24, "add_member", devmember_id,
        add_payload(allmember_id, allmember, "member"), T24, "insufficient-role",
        "role 不足(reader)× 既存 user_id の複合違反は role 規則が先に判定される(add_member: role → duplicate-member。role → duplicate-member-key と duplicate-member → duplicate-member-key の推移からは決まらないため独立に固定)",
    )
    # approval-not-required / 方針の到達可能性
    add_es(
        "authz-propose-policy-off", 20, head19, "propose", owner_id,
        propose_payload("remove_member", remove_devmember, EXPIRES), T19, "approval-not-required",
        "方針がオフのときの propose は無効(§6.2 — 直接追記できる op を提案する意味を持たない)",
    )
    add_es(
        "authz-propose-untargeted-op", 25, head24, "propose", owner_id,
        propose_payload("add_member", add_payload(newcomer_id, newcomer, "member"), EXPIRES), T24,
        "approval-not-required",
        "方針の対象でない op(add_member は ops に無く、member role は常時対象でもない)の propose は無効",
    )
    add_es(
        "authz-propose-rotate-not-required", 25, head24, "propose", devadmin_id,
        propose_payload("rotate_epoch", rotate_payload(DEV, 3), EXPIRES), T24, "approval-not-required",
        "rotate_epoch は方針の対象になりえない(データ・安全側の操作)ため、その propose は approval-not-required",
    )
    add_es(
        "authz-propose-role-precedes-not-required", 25, head24, "propose", devmember_id,
        propose_payload("add_member", add_payload(newcomer_id, newcomer, "member"), EXPIRES), T24,
        "insufficient-role",
        "propose の role 規則は内側 op の規則(add_member = admin 以上)で判定し、approval-not-required に先行する(propose: role → approval-not-required)",
    )
    add_es(
        "authz-propose-not-required-precedes-inner", 25, head24, "propose", owner_id,
        propose_payload("add_member", add_payload(newcomer_id, newcomer, "member", "listed", [GHOST]), EXPIRES),
        T24, "approval-not-required",
        "対象外 op × 内側 op の違反(未知環境)の複合違反は approval-not-required が先に判定される(propose: approval-not-required → 内側 op の合意規則)",
    )
    add_es(
        "authz-propose-inner-unknown-environment", 25, head24, "propose", owner_id,
        propose_payload("change_role", change_payload(devmember_id, "member", "listed", [GHOST]), EXPIRES),
        T24, "unknown-environment",
        "内側 op が合意規則(未知環境)を満たさない提案は無効(pending に積まない)— 理由コードは内側 op の理由をそのまま用いる",
    )
    add_es(
        "authz-propose-inner-scope-not-contained", 25, head24, "propose", devadmin_id,
        propose_payload("remove_member", {"target_user_id": prodreader_id}, EXPIRES), T24,
        "scope-not-contained",
        "提案者の scope で原則 1 を検査する(直接追記できる op であることの確認 — dev 専任 admin は prod メンバーの remove を提案できない)",
    )
    add_es(
        "authz-propose-inner-unknown-target", 25, head24, "propose", owner_id,
        propose_payload("remove_member", {"target_user_id": "user-ghost-9999"}, EXPIRES), T24,
        "unknown-target",
        "内側 op の対象が存在しない提案は無効",
    )
    add_es(
        "authz-propose-inner-role", 25, head24, "propose", devadmin_id,
        propose_payload("remove_member", {"target_user_id": admin_id}, EXPIRES), T24,
        "insufficient-role",
        "admin を対象とする remove_member は owner のみ — 提案者の role 規則は内側 op の規則で判定する",
    )
    add_es(
        "authz-propose-inner-quorum-unreachable", 25, head24, "propose", owner_id,
        propose_payload("set_approval_policy", policy_payload(POLICY_OPS, 4), EXPIRES), T24,
        "approval-quorum-unreachable",
        "内側 op(方針変更)が到達可能性を満たさない(owner 3 < 4)提案は提案段で無効",
    )
    add_es(
        "authz-policy-single-owner", 13, head12, "set_approval_policy", owner_id,
        policy_payload(POLICY_OPS, 2), t0 + 12000, "approval-quorum-unreachable",
        "有効化は現 owner 数 ≥ required_approvals でなければ無効(owner 1 名では有効化できない)",
    )
    add_es(
        "authz-policy-quorum-unreachable", 20, head19, "set_approval_policy", owner_id,
        policy_payload(POLICY_OPS, 4), T19, "approval-quorum-unreachable",
        "owner 3 名で required 4 の有効化は無効(有効化条件は ≥ — 承認項目 17)",
    )
    # approve / withdraw の各理由(head 21 = 提案 21 が pending・提案者 owner の票 1)
    add_es(
        "authz-approve-non-owner", 22, head21, "approve", admin_id,
        proposal_ref_payload(p21), T21, "insufficient-role",
        "承認者は owner のみ(原則 2: S ∩ owners を数える — admin の署名は票にならない)",
    )
    add_es(
        "authz-approve-reader", 22, head21, "approve", prodreader_id,
        proposal_ref_payload(p21), T21, "insufficient-role",
        "reader の approve も無効",
    )
    add_es(
        "authz-approve-self", 22, head21, "approve", owner_id,
        proposal_ref_payload(p21), T21, "duplicate-approval",
        "原則 2(重複): owner として提案した提案者の提案は 1 票であり、自己承認は duplicate-approval(distinct な身元で数える)",
    )
    add_es(
        "authz-approve-expired", 22, head21, "approve", owner2_id,
        proposal_ref_payload(p21), EXPIRES + 1, "proposal-expired",
        "approve エントリの timestamp_ms が提案の expires_at_ms を超えると無効(本仕様で timestamp を合意規則に用いる唯一の箇所 — 正直な承認者向けの UX 安全装置)",
    )
    add_es(
        "authz-approve-unknown-hash", 25, head24, "approve", owner_id,
        {"proposal_hash_hex": BOGUS_HASH}, T24, "unknown-proposal",
        "存在しない提案ハッシュへの approve は無効",
    )
    add_es(
        "authz-approve-applied-proposal", 25, head24, "approve", owner3_id,
        proposal_ref_payload(p21), T24, "unknown-proposal",
        "適用済み(seq 22 で完成)の提案への approve は unknown-proposal(pending でない提案は存在しないのと同じ扱い)",
    )
    add_es(
        "authz-approve-withdrawn-proposal", 25, head24, "approve", owner2_id,
        proposal_ref_payload(p23), T24, "unknown-proposal",
        "撤回済み(seq 24)の提案への approve は unknown-proposal",
    )
    add_es(
        "authz-withdraw-unknown-proposal", 25, head24, "withdraw", owner_id,
        {"proposal_hash_hex": BOGUS_HASH}, T24, "unknown-proposal",
        "存在しない提案の withdraw は無効",
    )
    add_es(
        "authz-withdraw-closed-proposal", 25, head24, "withdraw", owner_id,
        proposal_ref_payload(p23), T24, "unknown-proposal",
        "撤回済みの提案の再 withdraw は unknown-proposal",
    )
    add_es(
        "authz-withdraw-non-proposer", 24, head23, "withdraw", admin_id,
        proposal_ref_payload(p23), T23, "insufficient-role",
        "withdraw は提案者または owner のみ(admin-0003 は提案者でも owner でもない)",
    )
    add_es(
        "authz-withdraw-role-precedes-unknown", 25, head24, "withdraw", admin_id,
        {"proposal_hash_hex": BOGUS_HASH}, T24, "insufficient-role",
        "role 不足 × 未知の提案の複合違反は role 規則が先に判定される(withdraw: role → unknown-proposal)",
    )
    add_es(
        "authz-approve-role-precedes-unknown", 25, head24, "approve", admin_id,
        {"proposal_hash_hex": BOGUS_HASH}, T24, "insufficient-role",
        "role 不足 × 未知の提案の複合違反は role 規則が先に判定される(approve: role → unknown-proposal)",
    )
    add_es(
        "authz-approve-unknown-precedes-duplicate", 25, head24, "approve", owner2_id,
        proposal_ref_payload(p21), T24, "unknown-proposal",
        "適用済み提案 × 投票済み owner の複合違反は unknown-proposal が先に判定される(approve: unknown-proposal → duplicate-approval)",
    )

    # --- 派生チェーン(四眼の状態を要する前提 — 規約 16 / 19 の先例)-----------------------
    def extend(base_seq, base_hash, steps):
        """steps = [(op, actor_id, payload, ts)] を base の直後へ連鎖して署名する。"""
        out = []
        prev = base_hash
        seq = base_seq
        for op, actor_id, payload, ts in steps:
            seq += 1
            entry = build_entry(seq, op, actor_id, users[actor_id], payload, ts, prev)
            out.append(entry)
            prev = entry["entry_hash_hex"]
        return out

    def chain_doc(description, base_seq, ext_entries, members, policy, pending, **extra):
        return {
            "description": description,
            "base_seq": base_seq,
            "entries": ext_entries,
            "expected_members": members,
            "expected_policy": policy,
            "expected_pending": pending,
            **extra,
        }

    def at(ext_entries, seq):
        return next(e for e in ext_entries if e["seq"] == seq)

    def approve_of(entry):
        return proposal_ref_payload(entry)

    # (1) 非 owner の提案(23)への 1 票目は pending のまま。timestamp = expires_at_ms
    #     ちょうどは有効(境界は ≤)
    one_vote = extend(23, head23, [
        ("approve", owner2_id, approve_of(p23), EXPIRES),
    ])
    extended_chains["proposal-one-vote"] = chain_doc(
        "提案 23(dev 専任 admin による remove_member — 提案者の票 0)へ owner-0014 が 1 票"
        "(timestamp = expires_at_ms ちょうど — 期限の ≤ 境界)。定足数 2 に届かないため"
        "適用されず pending のまま(approvals = [owner-0014])。duplicate-approval の前提チェーン",
        23, one_vote, members_24, canonical_policy, pending_map((p23, "admin", [owner2_id])),
    )
    add_es(
        "authz-approve-duplicate-owner", 25, one_vote[-1]["entry_hash_hex"], "approve", owner2_id,
        approve_of(p23), T24, "duplicate-approval",
        "原則 2(重複): 同じ owner の 2 票目は duplicate-approval(票は distinct な owner で数える)",
        chain="proposal-one-vote",
    )
    # (2) 非 owner の提案 + owner 2 票で完成 → seq 25 で適用(devmember の在籍終了)
    completed = extend(23, head23, [
        ("approve", owner2_id, approve_of(p23), T23),
        ("approve", owner3_id, approve_of(p23), t0 + 24000),
    ])
    extended_chains["proposal-completed"] = chain_doc(
        "提案 23 へ owner-0014・owner-0015 が順に投票し、2 票目(seq 25)で定足数に達して内側"
        " remove_member を適用する(devmember は seq 25 で在籍終了 — inclusive)。適用した"
        "内側 op の actor は提案者(devadmin)として扱う",
        23, completed, members_24_without_devmember, canonical_policy, {},
    )
    # (3) 原則 2「時点違い」— 提案者(owner)の票が降格で失効する。提案者は admin(all)
    #     として remove_member の role を保つため proposal-void にはならず、他の owner 2 票で
    #     完成する
    p25s = build_entry(25, "propose", owner_id, owner,
                       propose_payload("remove_member", remove_devmember, EXPIRES), T24, head24)
    demote_owner1 = propose_payload("change_role", change_payload(owner_id, "admin"), EXPIRES)
    stale_proposer_steps = [
        ("propose", owner2_id, demote_owner1, t0 + 25000),                       # 26: 票 [0014]
    ]
    stale_proposer = [p25s] + extend(25, p25s["entry_hash_hex"], stale_proposer_steps)
    p26s = stale_proposer[1]
    stale_proposer += extend(26, p26s["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p26s), t0 + 26000),                    # 27: 適用 — owner-0001 は admin
        ("approve", owner2_id, approve_of(p25s), t0 + 27000),                    # 28: 票 {0014} ∪ ({0001} ∩ owners = ∅) = 1 → pending
    ])
    members_stale_proposer = dict(members_24, **{owner_id: member_state("admin", "all")})
    extended_chains["stale-proposer-vote"] = chain_doc(
        "原則 2 の「時点違い」(提案者側): owner-0001 が remove_member を提案(seq 25、票 1)"
        "した後、提案経由で admin に降格される(seq 26 提案 → seq 27 適用)。seq 28 の"
        " owner-0014 の approve は、提案者の票を「今の approve 時点でも owner か」で数え直す"
        "ため 1 票にしかならず、有効だが適用されない(pending・approvals = [owner-0014])。"
        "投票時の owner 資格だけで数える誤実装はここで完成させてしまう(Cursor Bugbot 指摘対応)",
        24, stale_proposer, members_stale_proposer, canonical_policy,
        pending_map((p25s, "owner", [owner2_id])),
    )
    stale_proposer_completed = stale_proposer + extend(28, stale_proposer[-1]["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p25s), t0 + 28000),                    # 29: {0015, 0014} = 2 → 適用
    ])
    extended_chains["stale-proposer-vote-completed"] = chain_doc(
        "stale-proposer-vote の先で owner-0015 が投票(seq 29)し、現 owner の票 {0014, 0015} = 2"
        " で完成する。適用時の提案者は admin(all)で remove_member(対象 reader)の role を持つ"
        "ため proposal-void ではなく、devmember は seq 29 で在籍終了",
        24, stale_proposer_completed,
        {k: v for k, v in members_stale_proposer.items() if k != devmember_id},
        canonical_policy, {},
    )
    # (4) 原則 2「時点違い」— 投票者(owner)の票が降格で失効する
    p25a = build_entry(25, "propose", devadmin_id, devadmin,
                       propose_payload("remove_member", remove_devmember, EXPIRES), T24, head24)
    stale_approver = [p25a] + extend(25, p25a["entry_hash_hex"], [
        ("approve", owner_id, approve_of(p25a), t0 + 25000),                     # 26: 票 [0001]
        ("propose", owner2_id, demote_owner1, t0 + 26000),                       # 27: 票 [0014]
    ])
    p27a = stale_approver[2]
    stale_approver += extend(27, p27a["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p27a), t0 + 27000),                    # 28: 適用 — owner-0001 は admin
        ("approve", owner2_id, approve_of(p25a), t0 + 28000),                    # 29: {0014} ∪ ({0001} ∩ owners = ∅) = 1 → pending
    ])
    extended_chains["stale-approver-vote"] = chain_doc(
        "原則 2 の「時点違い」(投票者側): dev 専任 admin の提案(seq 25、票 0)に owner-0001 が"
        "投票(seq 26)した後、owner-0001 が提案経由で admin に降格される(seq 27 → 28)。"
        "seq 29 の owner-0014 の approve は過去の投票者を「今の approve 時点でも owner か」で"
        "数え直すため 1 票にしかならず、有効だが適用されない(approvals = [owner-0001, owner-0014] —"
        " 受理済み approve の actor は記録に残るが票には数えない)",
        24, stale_approver, members_stale_proposer, canonical_policy,
        pending_map((p25a, "admin", [owner_id, owner2_id])),
    )
    stale_approver_completed = stale_approver + extend(29, stale_approver[-1]["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p25a), t0 + 29000),                    # 30: {0015, 0014} = 2 → 適用
    ])
    extended_chains["stale-approver-vote-completed"] = chain_doc(
        "stale-approver-vote の先で owner-0015 が投票(seq 30)し、現 owner の票 {0014, 0015} = 2"
        " で完成する(提案者 devadmin は在籍・同鍵・admin{dev, stage} ⊇ {dev} で有効)",
        24, stale_approver_completed,
        {k: v for k, v in members_stale_proposer.items() if k != devmember_id},
        canonical_policy, {},
    )
    # (5) proposal-void の 3 形 — 提案者(devadmin)が提案 23 の後に削除 / 別鍵で再追加 /
    #     reader へ降格され、定足数到達時の適用検査で無効になる
    remove_devadmin = propose_payload("remove_member", {"target_user_id": devadmin_id}, EXPIRES)
    proposer_removed = extend(23, head23, [
        ("propose", owner_id, remove_devadmin, T23),                             # 24: 票 [0001]
    ])
    p24r = proposer_removed[0]
    proposer_removed += extend(24, p24r["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p24r), t0 + 24000),                    # 25: 適用 — devadmin 削除
        ("approve", owner2_id, approve_of(p23), t0 + 25000),                     # 26: 提案 23 へ 1 票(pending)
    ])
    members_without_devadmin = {k: v for k, v in members_24.items() if k != devadmin_id}
    extended_chains["proposer-removed"] = chain_doc(
        "提案 23 の提案者(devadmin)を提案経由で削除(seq 24 → 25)した後、owner-0014 が提案 23 へ"
        " 1 票(seq 26 — 定足数未達なので有効・pending)。次の approve は定足数に達するが提案者が"
        "現メンバーでないため proposal-void になる(negative の前提)",
        23, proposer_removed, members_without_devadmin, canonical_policy,
        pending_map((p23, "admin", [owner2_id])),
    )
    void_head = proposer_removed[-1]["entry_hash_hex"]
    add_es(
        "authz-approve-proposer-removed", 27, void_head, "approve", owner3_id,
        approve_of(p23), t0 + 26000, "proposal-void",
        "定足数到達時の適用検査: 提案者が現メンバーでない提案は完成できない(proposal-void)。承認エントリは無効で提案は pending のまま(withdraw で閉じる)",
        chain="proposer-removed",
    )
    add_es(
        "authz-approve-expired-precedes-void", 27, void_head, "approve", owner3_id,
        approve_of(p23), EXPIRES + 1, "proposal-expired",
        "期限超過 × 提案者不在の複合違反は proposal-expired が先に判定される(approve: proposal-expired → proposal-void)",
        chain="proposer-removed",
    )
    rekeyed_devadmin = make_user(pat(0x3B + 0x10, 32), pat(0x4B + 0x10, 32))
    users["user-devadmin-0011(rekeyed)"] = rekeyed_devadmin
    proposer_rekeyed = proposer_removed[:2] + extend(25, proposer_removed[1]["entry_hash_hex"], [
        ("add_member", owner_id,
         {"target_user_id": devadmin_id, "enc_pub_hex": rekeyed_devadmin["enc_pub_hex"],
          "sig_pub_hex": rekeyed_devadmin["sig_pub_hex"], "role": "admin",
          **scope_fields("listed", [DEV, STAGE])}, t0 + 25000),                  # 26: 別鍵で再追加(admin の add は直接追記可)
        ("approve", owner2_id, approve_of(p23), t0 + 26000),                     # 27: 提案 23 へ 1 票
    ])
    members_rekeyed = dict(members_24)  # devadmin は同 user_id・同 role / scope で在籍(鍵だけ違う)
    extended_chains["proposer-rekeyed"] = chain_doc(
        "提案者(devadmin)を削除(seq 24 → 25)し、同じ user_id を**別の鍵**で再追加(seq 26 —"
        " add_member の admin 付与は ops に無く直接追記できる)した後、owner-0014 が提案 23 へ 1 票"
        "(seq 27)。提案者は在籍し role も足りるが鍵 FP が提案時と異なるため、完成は proposal-void",
        23, proposer_rekeyed, members_rekeyed, canonical_policy,
        pending_map((p23, "admin", [owner2_id])),
        keys={
            "user-devadmin-0011": {
                "note": "seq 26 で再追加された devadmin の新鍵(提案 23 の提案時の鍵とは別)",
                "enc_sk_seed_hex": pat(0x3B + 0x10, 32).hex(),
                "sig_sk_seed_hex": pat(0x4B + 0x10, 32).hex(),
                "enc_pub_hex": rekeyed_devadmin["enc_pub_hex"],
                "sig_pub_hex": rekeyed_devadmin["sig_pub_hex"],
                "key_fingerprint_hex": rekeyed_devadmin["fp_hex"],
            },
        },
    )
    add_es(
        "authz-approve-proposer-rekeyed", 28, proposer_rekeyed[-1]["entry_hash_hex"], "approve", owner3_id,
        approve_of(p23), t0 + 27000, "proposal-void",
        "適用検査: 提案者が提案時と同じ鍵 FP を持たない提案は完成できない(削除 → 別鍵で再追加された同一 user_id)",
        chain="proposer-rekeyed",
    )
    demote_devadmin = propose_payload("change_role", change_payload(devadmin_id, "reader", "listed", [DEV, STAGE]), EXPIRES)
    proposer_demoted = extend(23, head23, [
        ("propose", owner_id, demote_devadmin, T23),                             # 24
    ])
    p24d = proposer_demoted[0]
    proposer_demoted += extend(24, p24d["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p24d), t0 + 24000),                    # 25: 適用 — devadmin は reader
        ("approve", owner2_id, approve_of(p23), t0 + 25000),                     # 26: 提案 23 へ 1 票
    ])
    members_demoted = dict(members_24, **{devadmin_id: member_state("reader", "listed", [DEV, STAGE])})
    extended_chains["proposer-demoted"] = chain_doc(
        "提案者(devadmin)を提案経由で reader に降格(seq 24 → 25)した後、owner-0014 が提案 23 へ"
        " 1 票(seq 26)。提案者は在籍・同鍵だが remove_member に必要な role(admin)を失って"
        "いるため、完成は proposal-void",
        23, proposer_demoted, members_demoted, canonical_policy,
        pending_map((p23, "admin", [owner2_id])),
    )
    add_es(
        "authz-approve-proposer-demoted", 27, proposer_demoted[-1]["entry_hash_hex"], "approve", owner3_id,
        approve_of(p23), t0 + 26000, "proposal-void",
        "適用検査: 提案者が内側 op に必要な role を失った提案は完成できない(insufficient-role ではなく proposal-void)",
        chain="proposer-demoted",
    )
    # (6) proposal-void → 内側 op の合意規則 の順序: 提案者も対象も居ない
    void_then_inner = proposer_removed[:2] + extend(25, proposer_removed[1]["entry_hash_hex"], [
        ("propose", owner_id, propose_payload("remove_member", remove_devmember, EXPIRES), t0 + 25000),  # 26
    ])
    p26v = void_then_inner[-1]
    void_then_inner += extend(26, p26v["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p26v), t0 + 26000),                    # 27: 適用 — devmember 削除
        ("approve", owner2_id, approve_of(p23), t0 + 27000),                     # 28: 提案 23 へ 1 票
    ])
    extended_chains["proposer-removed-target-gone"] = chain_doc(
        "proposer-removed の先で、提案 23 の対象(devmember)も別の提案(seq 26 → 27)で削除し、"
        "owner-0014 が提案 23 へ 1 票(seq 28)。完成時の検査は proposal-void が内側 op の"
        "合意規則(unknown-target)に先行する(negative の前提)",
        23, void_then_inner,
        {k: v for k, v in members_24.items() if k not in (devadmin_id, devmember_id)},
        canonical_policy, pending_map((p23, "admin", [owner2_id])),
    )
    add_es(
        "authz-approve-void-precedes-inner", 29, void_then_inner[-1]["entry_hash_hex"], "approve", owner3_id,
        approve_of(p23), t0 + 28000, "proposal-void",
        "提案者不在 × 対象不在の複合違反は proposal-void が先に判定される(approve: proposal-void → 内側 op の合意規則)",
        chain="proposer-removed-target-gone",
    )
    # (7) 競合する 2 提案: 後の適用が内側 op の規則で失敗し pending に残る
    competing = extend(24, head24, [
        ("propose", owner_id, propose_payload("remove_member", remove_devmember, EXPIRES), T24),      # 25: 票 [0001]
        ("propose", devadmin_id, propose_payload("remove_member", remove_devmember, EXPIRES), t0 + 25000),  # 26: 票 []
    ])
    p25c, p26c = competing
    competing += extend(26, p26c["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p26c), t0 + 26000),                    # 27: 票 [0014]
        ("approve", owner3_id, approve_of(p26c), t0 + 27000),                    # 28: 適用 — devmember 削除
    ])
    extended_chains["competing-proposals"] = chain_doc(
        "同一対象(devmember)の remove_member を owner-0001(seq 25、票 1)と devadmin(seq 26、"
        "票 0)が並行して提案し、後者が owner 2 票(seq 27 → 28)で先に完成する。前者は pending"
        " に残り、その完成は内側 op の適用時検査(unknown-target)で失敗する(negative の前提)",
        24, competing, members_24_without_devmember, canonical_policy,
        pending_map((p25c, "owner", [])),
    )
    add_es(
        "authz-approve-inner-apply-fails", 29, competing[-1]["entry_hash_hex"], "approve", owner2_id,
        approve_of(p25c), t0 + 28000, "unknown-target",
        "定足数到達時に内側 op を適用時点の状態で再検査する: 対象が既に削除済みなら unknown-target で承認エントリは無効、提案は pending のまま(withdraw で閉じる)",
        chain="competing-proposals",
    )
    # (7b) ② 字面の読み(2026-09-15 所有者委任裁定 — 設計録 §8 K2-11): 票は owner として
    #      作られた署名。admin として提案した提案者が後に owner へ昇格しても提案署名は S に
    #      入らず(1 票にならない)、owner として approve を追記すればその票は数える(自己承認は
    #      duplicate-approval にならない — S の要素ではないため)
    promote_admin = propose_payload("change_role", change_payload(admin_id, "owner"), EXPIRES)
    promoted = extend(24, head24, [
        ("propose", admin_id, propose_payload("remove_member", remove_devmember, EXPIRES), T24),  # 25: admin の提案(S = ∅)
        ("propose", owner_id, promote_admin, t0 + 25000),                        # 26: admin-0003 の owner 昇格提案(票 [0001])
    ])
    p25p, p26p = promoted
    promoted += extend(26, p26p["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p26p), t0 + 26000),                    # 27: 適用 — admin-0003 は owner(all)
    ])
    members_promoted = dict(members_24, **{admin_id: member_state("owner", "all")})
    promoted_other = promoted + extend(27, promoted[-1]["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p25p), t0 + 27000),                    # 28: S = {0015} = 1(提案者は admin として提案 → S 外)→ pending
    ])
    extended_chains["proposer-promoted"] = chain_doc(
        "字面の読み(2026-09-15 裁定 ②): admin-0003 が remove_member を提案(seq 25 — admin としての"
        "提案署名は票ではない)した後、提案経由で owner へ昇格(seq 26 → 27)。seq 28 の owner-0015 の"
        " approve は S = {0015} の 1 票にしかならず、有効だが適用されない(pending・approvals = [0015])。"
        "「S = {提案者} ∪ 承認者」で提案者を無条件に数える実装はここで完成させてしまう",
        24, promoted_other, members_promoted, canonical_policy,
        pending_map((p25p, "admin", [owner3_id])),
    )
    promoted_self = promoted + extend(27, promoted[-1]["entry_hash_hex"], [
        ("approve", admin_id, approve_of(p25p), t0 + 27000),                     # 28: 昇格した提案者の自己承認 — S 外なので重複でなく 1 票(pending)
    ])
    extended_chains["proposer-promoted-self-vote"] = chain_doc(
        "proposer-promoted の分岐: 昇格した提案者 admin-0003(現 owner)が自分の提案 25 を approve"
        "(seq 28)。提案署名は S の要素ではないため duplicate-approval にならず、owner としての"
        " approve が 1 票になる(pending・approvals = [0003])",
        24, promoted_self, members_promoted, canonical_policy,
        pending_map((p25p, "admin", [admin_id])),
    )
    promoted_completed = promoted_self + extend(28, promoted_self[-1]["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p25p), t0 + 28000),                    # 29: {0003, 0015} = 2 → 適用
    ])
    extended_chains["proposer-promoted-completed"] = chain_doc(
        "proposer-promoted-self-vote の先で owner-0015 が投票(seq 29)し、{0003, 0015} = 2 で完成する"
        "(適用時の提案者 admin-0003 は在籍・同鍵・owner で remove_member の role を持つ)。"
        "定足数の各票が owner role での署名に対応する — 監査は署名だけで定足数を追える",
        24, promoted_completed,
        {k: v for k, v in members_promoted.items() if k != devmember_id},
        canonical_policy, {},
    )
    # (7c) ⑤ 投票者の鍵束縛(2026-09-15 所有者委任裁定 — 設計録 §8 K2-11): S の要素は
    #      (user_id, 署名時の鍵 FP)。投票後に削除され別鍵で再追加された owner の旧票は失効し
    #      (鍵更新は侵害鍵の票を失効させる)、新鍵で改めて投票できる
    rekeyed_owner = make_user(pat(0x71, 32), pat(0x81, 32))
    users["user-owner-0001(rekeyed)"] = rekeyed_owner
    remove_owner1 = propose_payload("remove_member", {"target_user_id": owner_id}, EXPIRES)
    readd_owner1 = propose_payload("add_member", {
        "target_user_id": owner_id, "enc_pub_hex": rekeyed_owner["enc_pub_hex"],
        "sig_pub_hex": rekeyed_owner["sig_pub_hex"], "role": "owner", **scope_fields("all", []),
    }, EXPIRES)
    readded = extend(24, head24, [
        ("propose", devadmin_id, propose_payload("remove_member", remove_devmember, EXPIRES), T24),  # 25: S = ∅
    ])
    p25k = readded[0]
    readded += extend(25, p25k["entry_hash_hex"], [
        ("approve", owner_id, approve_of(p25k), t0 + 25000),                     # 26: 票 [(0001, 旧鍵)]
        ("propose", owner2_id, remove_owner1, t0 + 26000),                       # 27: owner-0001 の削除提案(票 [0014]。owner 3 → 2 ≥ 2)
    ])
    p27k = readded[-1]
    readded += extend(27, p27k["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p27k), t0 + 27000),                    # 28: 適用 — owner-0001 削除
        ("propose", owner2_id, readd_owner1, t0 + 28000),                        # 29: 別鍵で owner として再追加の提案(owner 確立 = 常時対象)
    ])
    p29k = readded[-1]
    readded += extend(29, p29k["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p29k), t0 + 29000),                    # 30: 適用 — owner-0001 は新鍵で owner
        ("approve", owner2_id, approve_of(p25k), t0 + 30000),                    # 31: S = {(0001, 旧鍵), 0014} → 0001 の現鍵 ≠ 旧鍵 → 1 票 → pending
    ])
    rekeyed_owner_keys = {
        "user-owner-0001": {
            "note": "seq 29 → 30 で再追加された owner-0001 の新鍵(seq 26 の投票時の鍵とは別)",
            "enc_sk_seed_hex": pat(0x71, 32).hex(),
            "sig_sk_seed_hex": pat(0x81, 32).hex(),
            "enc_pub_hex": rekeyed_owner["enc_pub_hex"],
            "sig_pub_hex": rekeyed_owner["sig_pub_hex"],
            "key_fingerprint_hex": rekeyed_owner["fp_hex"],
        },
    }
    extended_chains["readded-approver-vote"] = chain_doc(
        "投票者の鍵束縛(2026-09-15 裁定 ⑤): dev 専任 admin の提案 25 に owner-0001 が旧鍵で投票"
        "(seq 26)した後、owner-0001 を提案経由で削除(seq 27 → 28)し、**別の鍵**で owner として"
        "再追加(seq 29 → 30)。seq 31 の owner-0014 の approve は、(0001, 旧鍵) の票を「今の鍵 FP を"
        "持つ現 owner か」で数え直すため 1 票にしかならず、有効だが適用されない(pending・approvals ="
        " [(0001, 旧鍵), 0014])。user_id だけで束縛する実装は侵害鍵の票を鍵更新後も数えてしまう",
        24, readded, members_24, canonical_policy,
        pending_map((p25k, "admin", [vote(owner_id, owner), owner2_id])),
        keys=rekeyed_owner_keys,
    )
    revote = build_entry(32, "approve", owner_id, rekeyed_owner, approve_of(p25k), t0 + 31000,
                         readded[-1]["entry_hash_hex"])
    extended_chains["readded-approver-revote"] = chain_doc(
        "readded-approver-vote の先で、再追加された owner-0001 が**新鍵**で改めて投票(seq 32)。"
        "(0001, 新鍵) は S の要素ではないため duplicate-approval にならず、{0014, 0001} = 2 で完成する"
        "(提案者 devadmin は在籍・同鍵・admin{dev, stage} ⊇ {dev} で有効。devmember は seq 32 で在籍終了)",
        24, readded + [revote], members_24_without_devmember, canonical_policy, {},
        keys=rekeyed_owner_keys,
    )
    # (7d) ⑤ の裏側 — 同一鍵での再追加(§6.2 が「同一人物の復帰」として許容)では鍵の支配者が
    #      変わらないため旧票は生きている(在籍区間〔tenure〕束縛を採らなかった側の固定。
    #      pullfrog 第 1 巡 — 採らなかった案は設計録 §8 K2-11 ⑤ 行)
    readd_owner1_same_key = propose_payload("add_member", {
        "target_user_id": owner_id, "enc_pub_hex": owner["enc_pub_hex"],
        "sig_pub_hex": owner["sig_pub_hex"], "role": "owner", **scope_fields("all", []),
    }, EXPIRES)
    same_key = readded[:4] + extend(28, readded[3]["entry_hash_hex"], [
        ("propose", owner2_id, readd_owner1_same_key, t0 + 28000),               # 29: 同一鍵で owner として再追加の提案
    ])
    p29s = same_key[-1]
    same_key += extend(29, p29s["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p29s), t0 + 29000),                    # 30: 適用 — owner-0001 は同一鍵で owner
    ])
    extended_chains["readded-approver-same-key"] = chain_doc(
        "readded-approver-vote と同じ経路で owner-0001 を削除(seq 27 → 28)した後、**同一の鍵**で"
        " owner として再追加(seq 29 → 30)。(0001, 鍵) の票は S に残り、0001 は同じ鍵を持つ現 owner"
        "なので票は生きている(pending・approvals = [(0001, 鍵)] — 在籍区間で束縛する実装との"
        "分岐点。同一鍵の再追加は §6.2 が許容し鍵の支配者が変わらないため、票の失効理由がない)",
        24, same_key, members_24, canonical_policy,
        pending_map((p25k, "admin", [owner_id])),
    )
    same_key_completed = same_key + extend(30, same_key[-1]["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p25k), t0 + 30000),                    # 31: {0001(同一鍵・現 owner), 0014} = 2 → 適用
    ])
    extended_chains["readded-approver-same-key-completed"] = chain_doc(
        "readded-approver-same-key の先で owner-0014 が投票(seq 31)し、旧票 (0001, 鍵) が生きている"
        "ため {0001, 0014} = 2 で完成する(在籍区間束縛の実装は 1 票にしかならず pending に残す —"
        " ここで分かれる)",
        24, same_key_completed, members_24_without_devmember, canonical_policy, {},
    )
    add_es(
        "authz-approve-readded-same-key-duplicate", 31, same_key[-1]["entry_hash_hex"], "approve", owner_id,
        approve_of(p25k), t0 + 30000, "duplicate-approval",
        "同一鍵で再追加された投票者の 2 票目: (0001, 鍵) は S の要素のままなので duplicate-approval(別鍵で再追加された readded-approver-revote との対比)",
        chain="readded-approver-same-key",
    )
    # (8) 方針の縮小(ops から remove_member を外す)と pending 提案の関係
    NARROW_OPS = ["grant_server", "set_approval_policy"]
    narrowed = extend(23, head23, [
        ("approve", owner2_id, approve_of(p23), T23),                            # 24: 提案 23 へ 1 票
        ("propose", owner_id, propose_payload("set_approval_policy", policy_payload(NARROW_OPS, 2), EXPIRES), t0 + 24000),  # 25
    ])
    p25n = narrowed[1]
    narrowed += extend(25, p25n["entry_hash_hex"], [
        ("approve", owner3_id, approve_of(p25n), t0 + 25000),                    # 26: 適用 — 方針縮小
    ])
    narrowed_policy = policy_state(NARROW_OPS, 2)
    extended_chains["policy-narrowed"] = chain_doc(
        "提案 23 へ owner-0014 が 1 票(seq 24)した後、方針を提案経由で縮小(ops から remove_member"
        " / change_role を外す — seq 25 → 26)。pending 提案は各 approve 時点の現方針で判定するため、"
        "以後の提案 23 への approve は approval-not-required(対象外になった op は直接追記できる)",
        23, narrowed, members_24, narrowed_policy, pending_map((p23, "admin", [owner2_id])),
    )
    narrowed_head = narrowed[-1]["entry_hash_hex"]
    add_es(
        "authz-approve-not-required-after-policy-change", 27, narrowed_head, "approve", owner3_id,
        approve_of(p23), t0 + 26000, "approval-not-required",
        "方針変更後に対象外となった提案への approve は無効(approval-not-required)。提案は pending のまま",
        chain="policy-narrowed",
    )
    add_es(
        "authz-approve-duplicate-precedes-not-required", 27, narrowed_head, "approve", owner2_id,
        approve_of(p23), t0 + 26000, "duplicate-approval",
        "投票済み × 対象外の複合違反は duplicate-approval が先に判定される(approve: duplicate-approval → approval-not-required)",
        chain="policy-narrowed",
    )
    add_es(
        "authz-approve-not-required-precedes-expired", 27, narrowed_head, "approve", owner3_id,
        approve_of(p23), EXPIRES + 1, "approval-not-required",
        "対象外 × 期限超過の複合違反は approval-not-required が先に判定される(approve: approval-not-required → proposal-expired)",
        chain="policy-narrowed",
    )
    add_es(
        "authz-propose-narrowed-op", 27, narrowed_head, "propose", owner_id,
        propose_payload("remove_member", remove_devmember, EXPIRES), t0 + 26000, "approval-not-required",
        "縮小後の方針で対象外の op の propose は無効(直接追記の経路が開いている)",
        chain="policy-narrowed",
    )
    # (9) required 3 の方針(head 19 = owner 3 名): 到達可能性の不変条件
    required3 = extend(19, head19, [
        ("set_approval_policy", owner_id, policy_payload(["grant_server"], 3), T19),  # 20
    ])
    extended_chains["policy-required-3"] = chain_doc(
        "head 19(owner 3 名)で ops = {grant_server} / required 3 の方針を有効化した派生チェーン"
        "(有効化条件 ≥ の等号側)。remove_member / change_role は ops に無いので直接追記できるが、"
        "owner 数を 3 未満にする op は到達可能性の不変条件で無効(negative の前提)",
        19, required3, members_19, policy_state(["grant_server"], 3), {},
    )
    req3_head = required3[-1]["entry_hash_hex"]
    add_es(
        "authz-remove-owner-quorum-unreachable", 21, req3_head, "remove_member", owner_id,
        {"target_user_id": owner3_id}, t0 + 20000, "approval-quorum-unreachable",
        "方針が有効な間、現 owner 数を required_approvals 未満にする remove_member は無効(last-owner-protected の一般化 — 検査は remove_member の列の末尾)",
        chain="policy-required-3",
    )
    add_es(
        "authz-demote-owner-quorum-unreachable", 21, req3_head, "change_role", owner_id,
        change_payload(owner3_id, "admin"), t0 + 20000, "approval-quorum-unreachable",
        "owner から他 role への change_role で owner 数が required 未満になる形も無効(検査は change_role の列の末尾)",
        chain="policy-required-3",
    )
    # (10) 方針のオフ化(required 0)にも四眼が要る。オフ後は propose が無効
    off = extend(24, head24, [
        ("propose", owner_id, propose_payload("set_approval_policy", policy_payload([], 0), EXPIRES), T24),  # 25
    ])
    p25o = off[0]
    off += extend(25, p25o["entry_hash_hex"], [
        ("approve", owner2_id, approve_of(p25o), t0 + 25000),                    # 26: 適用 — オフ
    ])
    extended_chains["policy-off"] = chain_doc(
        "方針を提案経由でオフ(required 0 / ops 空 — seq 25 → 26)にした派生チェーン。オフにする"
        "にも四眼が要る(方針の単調性 (a))。オフ後は対象 op を直接追記でき、propose は無効",
        24, off, members_24, None, {},
    )
    off_head = off[-1]["entry_hash_hex"]
    add_es(
        "authz-propose-after-policy-off", 27, off_head, "propose", owner_id,
        propose_payload("remove_member", remove_devmember, EXPIRES), t0 + 26000, "approval-not-required",
        "方針オフ後の propose は無効(approval-not-required)",
        chain="policy-off",
    )

    # --- 許容側(valid_appends)。chain 指定つきは派生チェーンの末尾へ接続する -----------
    def append_case(name, seq, prev_hex, op, actor_id, payload, ts, members, note,
                    policy="canonical", pending=None, chain=None, environments=None,
                    checkpoints=None):
        case = {
            "name": name,
            "entry": build_entry(seq, op, actor_id, users[actor_id], payload, ts, prev_hex),
            "expected_members": members,
            "expected_environments": environments if environments is not None else base_environments,
            "expected_server_grants": [],
            "expected_policy": canonical_policy if policy == "canonical" else policy,
            "expected_pending": pending if pending is not None else {},
            "note": note,
        }
        if chain is not None:
            case["chain"] = chain
        if checkpoints is not None:
            case["expected_checkpoints"] = checkpoints
        return case

    def members_with(base, **changes):
        out = dict(base)
        for k, v in changes.items():
            if v is None:
                out.pop(k, None)
            else:
                out[k] = v
        return out

    dev_scoped_checkpoint = checkpoint_env_entry(DEV, 2, 1)
    valid_appends += [
        append_case(
            "listed-admin-adds-in-scope", 20, head19, "add_member", devadmin_id,
            add_payload(newcomer_id, newcomer, "member", "listed", [DEV]), T19,
            members_with(members_19, **{newcomer_id: member_state("member", "listed", [DEV])}),
            "原則 1 の許容側: dev 専任 admin は自分の scope の部分集合を付与できる(削除済み member の鍵の別 user_id での再利用も §6.2 の禁止範囲外)",
            policy=None,
        ),
        append_case(
            "listed-admin-adds-empty-listed", 20, head19, "add_member", devadmin_id,
            add_payload(newcomer_id, newcomer, "reader", "listed", []), T19,
            members_with(members_19, **{newcomer_id: member_state("reader", "listed", [])}),
            "listed の空リストは有効(= どの環境の DEK も受け取らないメンバー — 管理のみ・後で入れる予定の表現。§6.2 裁定 B (3))。空集合はどの scope にも包含される",
            policy=None,
        ),
        append_case(
            "owner-adds-empty-listed-member", 20, head19, "add_member", owner_id,
            add_payload(newcomer_id, newcomer, "member", "listed", []), T19,
            members_with(members_19, **{newcomer_id: member_state("member", "listed", [])}),
            "owner による listed{} の member 追加も有効(all と listed{} は別の状態)",
            policy=None,
        ),
        append_case(
            "listed-admin-removes-in-scope", 20, head19, "remove_member", devadmin_id,
            remove_devmember, T19, members_with(members_19, **{devmember_id: None}),
            "原則 1 の許容側(remove): 対象の現 scope {dev, stage} ⊆ actor scope なら dev 専任 admin が消せる(縮小分の rotate 義務を履行できる)",
            policy=None,
        ),
        append_case(
            "listed-admin-demotes-and-narrows", 20, head19, "change_role", devadmin_id,
            change_payload(devmember_id, "reader", "listed", [DEV]), T19,
            members_with(members_19, **{devmember_id: member_state("reader", "listed", [DEV])}),
            "原則 1 の許容側(role と scope が同時に変わる): 旧 ∪ 新 = {dev, stage} ⊆ actor scope",
            policy=None,
        ),
        append_case(
            "listed-admin-demotes-in-scope", 20, head19, "change_role", devadmin_id,
            change_payload(devmember_id, "reader", "listed", [DEV, STAGE]), T19,
            members_with(members_19, **{devmember_id: member_state("reader", "listed", [DEV, STAGE])}),
            "原則 1 の許容側(scope 不変の降格): 旧 ∪ 新 = {dev, stage} ⊆ actor scope",
            policy=None,
        ),
        append_case(
            "owner-narrows-all-member", 20, head19, "change_role", owner_id,
            change_payload(allmember_id, "member", "listed", [PROD]), T19,
            members_with(members_19, **{allmember_id: member_state("member", "listed", [PROD])}),
            "all の actor は all △ listed{prod} = U \\ {prod} を包含する(all の対象を listed にできるのは all の actor だけ — §6.2 の集合代数)。縮小分の rotate 義務は §7",
            policy=None,
        ),
        append_case(
            "listed-member-rotates-in-scope", 20, head19, "rotate_epoch", devmember_id,
            rotate_payload(DEV, 3), T19, members_19,
            "listed の member は scope 内の環境を rotate できる(§6.2 環境対象 op の許容側)",
            policy=None, environments=dict(base_environments, **{DEV: "3"}),
        ),
        append_case(
            "listed-member-checkpoints-in-scope", 20, head19, "checkpoint", devmember_id,
            checkpoint_payload([dev_scoped_checkpoint]), T19, members_19,
            "listed の member は scope 内の環境のタプルだけを公証できる(環境集合は部分集合でよい — §6.2)",
            policy=None,
            checkpoints={DEV: expected_checkpoint(20, dev_scoped_checkpoint)},
        ),
        append_case(
            "owner-withdraws-others-proposal", 22, head21, "withdraw", owner2_id,
            approve_of(p21), T21, members_19,
            "withdraw は提案者でない owner もできる(seq 21 の owner-0001 の提案を owner-0014 が閉じる)",
        ),
        append_case(
            "proposer-withdraws-own-proposal", 24, head23, "withdraw", devadmin_id,
            approve_of(p23), T23, members_24,
            "提案者(非 owner)は自分の提案を withdraw できる",
        ),
        append_case(
            "add-member-under-policy", 25, head24, "add_member", owner_id,
            add_payload(newcomer_id, newcomer, "member"), T24,
            members_with(members_24, **{newcomer_id: member_state("member", "all")}),
            "方針が有効でも、ops に無く owner を確立しない add_member は直接追記できる(原則 2: required = 1 の op は通常の role 規則のみ)",
        ),
        append_case(
            "rotate-under-policy", 25, head24, "rotate_epoch", devadmin_id,
            rotate_payload(DEV, 3), T24, members_24,
            "rotate_epoch は方針の対象になりえない(インシデント対応を遅らせない)ため、方針下でも直接追記できる",
            environments=dict(base_environments, **{DEV: "3"}),
        ),
    ]
    propose_grant = build_entry(25, "propose", owner_id, owner,
                                propose_payload("grant_server", grant_payload, EXPIRES), T24, head24)
    propose_by_admin = build_entry(25, "propose", devadmin_id, devadmin,
                                   propose_payload("change_role", change_payload(devmember_id, "member", "listed", [DEV]), EXPIRES),
                                   T24, head24)
    valid_appends += [
        {
            "name": "propose-grant-server-by-owner",
            "entry": propose_grant,
            "expected_members": members_24,
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "expected_policy": canonical_policy,
            "expected_pending": pending_map((propose_grant, "owner", [])),
            "note": "owner による grant_server の提案は受理され pending に載る(提案者の票 1)。内側 payload は grant_server の正規化 payload_bytes(3 段入れ子 LP の lease_policy を含む)の入れ子",
        },
        {
            "name": "propose-by-listed-admin-in-scope",
            "entry": propose_by_admin,
            "expected_members": members_24,
            "expected_environments": base_environments,
            "expected_server_grants": [],
            "expected_policy": canonical_policy,
            "expected_pending": pending_map((propose_by_admin, "admin", [])),
            "note": "提案者は内側 op を通常の規則で実行できる role でよい(dev 専任 admin が scope 内の change_role を提案 — 票は 0)",
        },
        append_case(
            "direct-remove-after-policy-narrowed", 27, narrowed_head, "remove_member", devadmin_id,
            remove_devmember, t0 + 26000, members_24_without_devmember,
            "方針縮小後、ops から外れた remove_member は直接追記できる(提案 23 は pending のまま残る — 完成は unknown-target で失敗する)",
            policy=narrowed_policy, pending=pending_map((p23, "admin", [owner2_id])), chain="policy-narrowed",
        ),
        append_case(
            "direct-remove-after-policy-off", 27, off_head, "remove_member", devadmin_id,
            remove_devmember, t0 + 26000, members_24_without_devmember,
            "方針オフ後は対象だった op を直接追記できる",
            policy=None, chain="policy-off",
        ),
        append_case(
            "re-enable-policy-after-off", 27, off_head, "set_approval_policy", owner_id,
            policy_payload(POLICY_OPS, 2), t0 + 26000, members_24,
            "オフの方針は owner 1 名の直接追記で再び有効化できる(オフ = 方針なしと同じ扱い)",
            policy=canonical_policy, chain="policy-off",
        ),
    ]

    negatives += authz_cases[es_start:]

    # =========================================================================
    # DK(2026-09-20 K2 — CRYPTO_SPEC 0.12-draft §6.2 / §11): 端末鍵の 2 op
    # `add_device` / `revoke_device` の正例・負例。**正規チェーン seq 1〜24 は 1 バイトも
    # 変えない**: DK の正例列は seq 25〜37 の派生チェーン(extended_chains — 規約 19 の
    # `checkpoint` op と同じ「追記で拡張」の型。value / meta / manifest / attestation の
    # 端末軸ケースは `chain: "device-ops"` でこの派生チェーンのヘッドを指す)。途中の
    # ヘッド(29 / 33 / 34 / 36)を要する負例のために、同じ列のプレフィックスを独立の
    # 派生チェーンとして重ねて置く(エントリのバイト列は同一 — 設計録 dk-design.md §7 K2-10)。
    #
    # 端末の配役(cap = (role_cap, scope) — 設計録 §1-2 の絵):
    #   owner-0001: D1(最初の鍵 — 構造的に (owner, all))/ R = 予備鍵 (owner, all)〔予備鍵で
    #     あることは CLI の規律 — チェーン上は普通の端末鍵〕/ P = 電話 (owner, listed{}) =
    #     票だけの端末 / D1n = 予備鍵で登録し直した新端末 (owner, all)
    #   allmember-0013(member, all): C = CI 箱 (member, listed{dev, stage}) → 実効 (member, {dev, stage})
    #   owner-0014: D14b = 第 2 端末 (owner, all)(票を入れた後に自己失効 → 票は数えられない)
    #   owner-0015: L = cap (reader, all) の端末(approve できない・値を書けない)
    # =========================================================================
    dk_start = len(authz_cases)
    reserve = make_user(pat(0x5A, 32), pat(0x6A, 32))       # owner-0001 の予備鍵 R
    phone = make_user(pat(0x5B, 32), pat(0x6B, 32))         # owner-0001 の電話 P
    cibox = make_user(pat(0x5C, 32), pat(0x6C, 32))         # allmember-0013 の CI 箱 C
    owner2_second = make_user(pat(0x5D, 32), pat(0x6D, 32))  # owner-0014 の第 2 端末 D14b
    owner3_readercap = make_user(pat(0x5E, 32), pat(0x6E, 32))  # owner-0015 の cap reader 端末 L
    recovered = make_user(pat(0x5F, 32), pat(0x6F, 32))     # owner-0001 の復帰後の新端末 D1n
    reader_second = make_user(pat(0x59, 32), pat(0x69, 32))  # prodreader-0012 の第 2 端末
    fresh_device = make_user(pat(0x58, 32), pat(0x68, 32))   # 未使用の端末鍵(許容側・負例の材料)

    def device_payload(dev: dict, role_cap: str, kind: str = "all",
                       environment_ids: list | None = None) -> dict:
        return {
            "enc_pub_hex": dev["enc_pub_hex"],
            "sig_pub_hex": dev["sig_pub_hex"],
            "role_cap": role_cap,
            **scope_fields(kind, environment_ids or []),
        }

    def revoke_payload(target_id: str, fps: list) -> dict:
        # device_fingerprints_lp_hex = FP(hex 小文字 32)リストの入れ子 LP の hex(scope と同型。
        # 順序は署名対象 — 生成は昇順 SHOULD・検証は集合)
        return {
            "target_user_id": target_id,
            "device_fingerprints": list(fps),  # 可読性のための平文表現(正規化対象は *_lp_hex)
            "device_fingerprints_lp_hex": lp_encode(list(fps)).hex(),
        }

    def device_state(dev: dict, role_cap: str, kind: str, environment_ids: list | None,
                     added_seq: int) -> dict:
        scope = {"kind": kind}
        if kind == "listed":
            scope["environments"] = list(environment_ids or [])
        return {"role_cap": role_cap, "scope": scope, "added_seq": added_seq}

    def first_device(user: dict, added_seq: int) -> dict:
        # genesis / add_member の最初の鍵は構造的に cap (owner, all)(§6.2)
        return {user["fp_hex"]: device_state(user, "owner", "all", None, added_seq)}

    def member_state_dk(role: str, kind: str, environment_ids: list | None, devices: dict) -> dict:
        return {**member_state(role, kind, environment_ids), "devices": devices}

    def ts_at(seq: int) -> int:
        return t0 + (seq - 1) * 1000

    def extend_dk(base_seq, base_hash, steps):
        """steps = [(op, actor_id, actor_keys, payload)] を base の直後へ連鎖して署名する(端末鍵で署名する
        エントリは actor_keys に端末の鍵を渡す — actor.user_id は人・FP は端末)。"""
        out = []
        prev = base_hash
        seq = base_seq
        for op, actor_id, actor_keys, payload in steps:
            seq += 1
            entry = build_entry(seq, op, actor_id, actor_keys, payload, ts_at(seq), prev)
            out.append(entry)
            prev = entry["entry_hash_hex"]
        return out

    # --- 正例列 seq 25〜37 ---------------------------------------------------------
    dk_entries = extend_dk(24, head24, [
        ("add_device", owner_id, owner, device_payload(reserve, "owner")),                       # 25 予備鍵 R
        ("add_device", owner_id, owner, device_payload(phone, "owner", "listed", [])),            # 26 電話 P
        ("add_device", allmember_id, allmember, device_payload(cibox, "member", "listed", [DEV, STAGE])),  # 27 CI 箱 C
        ("add_device", owner2_id, owner2, device_payload(owner2_second, "owner")),               # 28 第 2 端末 D14b
        ("add_device", owner3_id, owner3, device_payload(owner3_readercap, "reader")),           # 29 cap reader の端末 L
    ])
    p30_payload = propose_payload("remove_member", remove_devmember, EXPIRES)
    dk_entries += extend_dk(29, dk_entries[-1]["entry_hash_hex"], [
        ("propose", devadmin_id, devadmin, p30_payload),                                         # 30 提案(票 0)
    ])
    p30 = dk_entries[-1]
    dk_entries += extend_dk(30, p30["entry_hash_hex"], [
        ("approve", owner2_id, owner2_second, approve_of(p30)),                                  # 31 D14b の票
        ("revoke_device", owner2_id, owner2, revoke_payload(owner2_id, [owner2_second["fp_hex"]])),  # 32 自己失効
        ("approve", owner_id, phone, approve_of(p30)),                                           # 33 電話の票(D14b の票は死票 → 未完成)
        ("approve", owner2_id, owner2, approve_of(p30)),                                         # 34 別端末で再投票 → 完成(devmember 削除)
        ("revoke_device", owner_id, owner, revoke_payload(owner_id, sorted([owner["fp_hex"], phone["fp_hex"]]))),  # 35 一括 + 署名中の端末
        ("add_device", owner_id, reserve, device_payload(recovered, "owner")),                   # 36 予備鍵で新端末を登録
        ("revoke_device", admin_id, admin, revoke_payload(allmember_id, [cibox["fp_hex"]])),     # 37 admin による他人の端末の失効
    ])
    assert [e["seq"] for e in dk_entries] == list(range(25, 38))
    dk_at = {e["seq"]: e for e in dk_entries}
    dk_head = {seq: dk_at[seq]["entry_hash_hex"] for seq in dk_at}
    dk_head[24] = head24

    def dk_prefix(upto: int) -> list:
        return [e for e in dk_entries if e["seq"] <= upto]

    # --- 導出状態(端末つき)----------------------------------------------------------
    # 端末は members[user_id].devices に FP → {role_cap, scope, added_seq}(payload の 2 フィールドと
    # 1:1 の scope 表現)。`devices` を省略した既存の状態は「最初の鍵 1 つ = cap (owner, all)」
    # を意味する(既存ベクターのバイト列を変えない — 設計録 §7 K2-1)
    def base_devices(members: dict) -> dict:
        added = {owner_id: 1, admin_id: 6, devmember_id: 13, devadmin_id: 14,
                 prodreader_id: 15, allmember_id: 16, owner2_id: 18, owner3_id: 19}
        return {
            uid: member_state_dk(st["role"], st["scope"]["kind"], st["scope"].get("environments"),
                                 first_device(users[uid], added[uid]))
            for uid, st in members.items()
        }

    def with_devices(members: dict, uid: str, *extra: dict) -> dict:
        out = dict(members)
        devices = dict(out[uid]["devices"])
        for d in extra:
            devices.update(d)
        out[uid] = {**out[uid], "devices": devices}
        return out

    def without_device(members: dict, uid: str, *fps: str) -> dict:
        out = dict(members)
        devices = {fp: st for fp, st in out[uid]["devices"].items() if fp not in fps}
        out[uid] = {**out[uid], "devices": devices}
        return out

    dev_R = {reserve["fp_hex"]: device_state(reserve, "owner", "all", None, 25)}
    dev_P = {phone["fp_hex"]: device_state(phone, "owner", "listed", [], 26)}
    dev_C = {cibox["fp_hex"]: device_state(cibox, "member", "listed", [DEV, STAGE], 27)}
    dev_D14b = {owner2_second["fp_hex"]: device_state(owner2_second, "owner", "all", None, 28)}
    dev_L = {owner3_readercap["fp_hex"]: device_state(owner3_readercap, "reader", "all", None, 29)}
    dev_D1n = {recovered["fp_hex"]: device_state(recovered, "owner", "all", None, 36)}

    members_29 = base_devices(members_24)
    members_29 = with_devices(members_29, owner_id, dev_R, dev_P)
    members_29 = with_devices(members_29, allmember_id, dev_C)
    members_29 = with_devices(members_29, owner2_id, dev_D14b)
    members_29 = with_devices(members_29, owner3_id, dev_L)
    members_33 = without_device(members_29, owner2_id, owner2_second["fp_hex"])
    members_34 = {k: v for k, v in members_33.items() if k != devmember_id}
    members_36 = with_devices(
        without_device(members_34, owner_id, owner["fp_hex"], phone["fp_hex"]), owner_id, dev_D1n)
    members_37 = without_device(members_36, allmember_id, cibox["fp_hex"])
    dead_vote_pending = pending_map((p30, "admin", [vote(owner2_id, owner2_second), vote(owner_id, phone)]))

    dk_chain_docs = {
        "device-added": (29, members_29, canonical_policy, {},
                         "正規チェーン seq 1〜24 に端末 5 台の `add_device`(seq 25〜29)を追記した派生チェーン: "
                         "owner-0001 の予備鍵 R (owner, all)〔予備鍵であることは CLI の規律 — チェーン上は普通の端末鍵〕と"
                         "電話 P (owner, listed{}) = 票だけの端末、allmember-0013(member, all)の CI 箱 C (member, listed{dev, stage})、"
                         "owner-0014 の第 2 端末 D14b (owner, all)、owner-0015 の cap (reader, all) の端末 L。"
                         "単調性(新端末の cap ≤ 署名端末自身の cap — 最初の鍵は構造的に (owner, all))の許容側"),
        "device-dead-vote": (33, members_33, canonical_policy, dead_vote_pending,
                             "device-added に続けて、devadmin の提案(seq 30 = remove_member devmember。票 0)へ owner-0014 が"
                             "第 2 端末 D14b で投票(seq 31)→ owner-0014 が D14b を自己失効(seq 32)→ owner-0001 が電話 P で投票"
                             "(seq 33)。S = {(0014, D14b), (0001, P)} のうち生きている票は (0001, P) の 1 票だけ(失効端末の票は"
                             "数えない — §6.2 approve の端末語彙)ため定足数 2 に届かず pending のまま"),
        "device-revote-applied": (34, members_34, canonical_policy, {},
                                  "device-dead-vote に続けて owner-0014 が最初の端末 K14 で改めて投票(seq 34 — 別端末での再投票は"
                                  "duplicate-approval にならない)。生きている票 = (0001, P) + (0014, K14) = 2 で定足数に達し、"
                                  "内側 remove_member を seq 34 で適用(devmember は seq 34 で在籍終了 — inclusive)"),
        "device-recovered": (36, members_36, canonical_policy, {},
                             "device-revote-applied に続けて owner-0001 が最初の端末 D1 で D1 自身と電話 P を一括失効(seq 35 — "
                             "自分がいま署名している端末を失効させてよい・FP リストは昇順)し、残った予備鍵 R で新端末 D1n (owner, all) を"
                             "登録する(seq 36 — 全端末喪失からの復帰の形。予備鍵からは任意の cap を作れる)"),
        "device-ops": (37, members_37, canonical_policy, {},
                       "DK の正例列の全体(seq 25〜37)。末尾の seq 37 は admin-0003(admin, all)による他人(allmember-0013 — "
                       "member)の CI 箱 C の失効(remove_member と同じ role 規則 + 対象の人の scope ⊆ actor の実効 scope)。"
                       "value-signature / metadata-signature / env-manifest / head-attestation の端末軸ケースはこのチェーンを "
                       "`chain: \"device-ops\"` で参照する(C は seq 27〜36 で有効・seq 37 以後は失効端末)"),
    }
    for name, (upto, members, policy, pending, description) in dk_chain_docs.items():
        extended_chains[name] = chain_doc(description, 24, dk_prefix(upto), members, policy, pending)

    # (a) reader が自分の端末を足す(role 不問 — reader も可)
    reader_add = extend_dk(37, dk_head[37], [
        ("add_device", prodreader_id, prodreader,
         device_payload(reader_second, "reader", "listed", [PROD])),
    ])
    members_38_reader = with_devices(members_37, prodreader_id, {
        reader_second["fp_hex"]: device_state(reader_second, "reader", "listed", [PROD], 38)})
    extended_chains["reader-second-device"] = chain_doc(
        "device-ops に続けて reader(prodreader-0012 — listed{prod})が自分の第 2 端末 (reader, listed{prod}) を"
        "足す(seq 38)。`add_device` の actor は role 不問(reader も可 — §6.2 role 表)。自分の端末の "
        "`revoke_device` も role 不問(valid_appends の reader-revokes-own-device)",
        24, dk_entries + reader_add, members_38_reader, canonical_policy, {},
        keys={
            f"{prodreader_id}@second": {
                "user_id": prodreader_id,
                "label": "second",
                "enc_sk_seed_hex": pat(0x59, 32).hex(),
                "sig_sk_seed_hex": pat(0x69, 32).hex(),
                "enc_pub_hex": reader_second["enc_pub_hex"],
                "sig_pub_hex": reader_second["sig_pub_hex"],
                "key_fingerprint_hex": reader_second["fp_hex"],
            },
        },
    )
    reader_head = reader_add[-1]["entry_hash_hex"]

    # (b) 提案した端末の失効 → 定足数到達時に proposal-void
    void_steps = extend_dk(37, dk_head[37], [
        ("propose", owner_id, recovered,
         propose_payload("remove_member", {"target_user_id": prodreader_id}, EXPIRES)),          # 38 owner の提案(票 1: (0001, D1n))
    ])
    p38 = void_steps[-1]
    void_steps += extend_dk(38, p38["entry_hash_hex"], [
        ("revoke_device", owner_id, reserve, revoke_payload(owner_id, [recovered["fp_hex"]])),   # 39 提案端末 D1n を予備鍵で失効
        ("approve", owner2_id, owner2, approve_of(p38)),                                         # 40 生きている票 = (0014) の 1 票 → pending
    ])
    members_void = without_device(members_37, owner_id, recovered["fp_hex"])
    extended_chains["proposer-device-revoked"] = chain_doc(
        "device-ops に続けて owner-0001 が新端末 D1n で提案(seq 38 — owner の提案は 1 票 = (0001, D1n))し、"
        "予備鍵 R で D1n を失効(seq 39)。owner-0014 の approve(seq 40)の時点で提案者の票は死票(端末失効)"
        "なので生きている票は 1 で pending のまま。次の owner の approve は定足数に達するが、提案した端末が"
        "有効でないため proposal-void(§6.2 — 提案端末の有効性で判定)",
        24, dk_entries + void_steps, members_void, canonical_policy,
        pending_map((p38, "owner", [owner2_id])),
    )
    void_head = void_steps[-1]["entry_hash_hex"]

    # --- 署名系 negative(改竄・順序入替 — 端末 op のフィールドは署名対象)-----------------
    e25 = dk_at[25]
    e27 = dk_at[27]
    e35 = dk_at[35]
    e37 = dk_at[37]

    def resign_dk(name, base_entry, actor_keys, payload, note):
        case = resign_variant(name, base_entry, payload, note, verify_key_hex=actor_keys["sig_pub_hex"])
        case["chain"] = "device-ops"
        return case

    negatives += [
        resign_dk(
            "add-device-tampered-role-cap", e27, allmember,
            device_payload(cibox, "owner", "listed", [DEV, STAGE]),
            "role_cap の書き換え(member → owner)は署名検証に失敗する(cap は署名対象 — 上限の付け替え対策)",
        ),
        resign_dk(
            "add-device-scope-relabel-all", e27, allmember,
            device_payload(cibox, "member", "all"),
            "端末 scope の書き換え(listed{dev, stage} → all)は署名検証に失敗する",
        ),
        resign_dk(
            "add-device-scope-reorder", e27, allmember,
            device_payload(cibox, "member", "listed", [STAGE, DEV]),
            "端末 scope の環境 id の順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象 — add_member の scope と同型)",
        ),
        resign_dk(
            "add-device-scope-flat-concat", e27, allmember,
            dict(device_payload(cibox, "member", "listed", [DEV, STAGE]),
                 scope_environments_lp_hex="".join([DEV, STAGE]).encode("utf-8").hex()),
            "端末 scope を入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する(§2.1 の曖昧性排除)",
        ),
        resign_dk(
            "add-device-tampered-enc-pub", e25, owner,
            dict(device_payload(reserve, "owner"), enc_pub_hex=fresh_device["enc_pub_hex"]),
            "新端末の enc 公開鍵の差し替えは署名検証に失敗する(登録する鍵は署名対象 — サーバーによる鍵のすり替え対策)",
        ),
        resign_dk(
            "revoke-device-fp-reorder", e35, owner,
            revoke_payload(owner_id, sorted([owner["fp_hex"], phone["fp_hex"]], reverse=True)),
            "失効 FP リストの順序を入れ替えると元の署名は検証に失敗する(入れ子 LP の順序も署名対象。生成は昇順 SHOULD・検証は集合)",
        ),
        resign_dk(
            "revoke-device-fp-flat-concat", e35, owner,
            dict(revoke_payload(owner_id, sorted([owner["fp_hex"], phone["fp_hex"]])),
                 device_fingerprints_lp_hex="".join(sorted([owner["fp_hex"], phone["fp_hex"]])).encode("utf-8").hex()),
            "FP リストを入れ子 LP でなく素の連結でエンコードしたバイト列では署名検証に失敗する",
        ),
        resign_dk(
            "revoke-device-tampered-target", e37, admin,
            revoke_payload(owner3_id, [cibox["fp_hex"]]),
            "失効対象 user_id の差し替えは署名検証に失敗する(対象は署名対象)",
        ),
    ]

    # --- 認可系 negative(構造 → actor → 署名 → 認可の段順。理由コードは §6.2「端末鍵」の検査順序)---
    dk_cases = []

    def add_dk(name, seq, prev_hex, op, actor_id, actor_keys, payload, expected_reason, note,
               chain="device-ops"):
        entry = build_entry(seq, op, actor_id, actor_keys, payload, ts_at(seq), prev_hex)
        case = authz(name, entry, expected_reason, note)
        case["verify_key_hex"] = actor_keys["sig_pub_hex"]
        case["chain"] = chain
        authz_cases.append(case)
        dk_cases.append(name)

    # 構造(invalid-payload)。actor = owner-0001 の新端末 D1n(head 37)
    add_dk("add-device-role-cap-unknown", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), role_cap="superuser"), "invalid-payload",
           "role_cap は閉集合 {reader, member, admin, owner}。それ以外は構造段で拒否する")
    add_dk("add-device-scope-all-nonempty", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), **scope_fields("all", [DEV])), "invalid-payload",
           "端末 scope も「環境スコープ」と同じ構造規則: scope_kind = all のとき scope_environments は空リスト")
    add_dk("add-device-scope-duplicate-id", 38, dk_head[37], "add_device", owner_id, recovered,
           device_payload(fresh_device, "owner", "listed", [DEV, DEV]), "invalid-payload",
           "重複 environment_id を含む端末 scope は無効(構造段)")
    add_dk("add-device-enc-pub-bad-length", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), enc_pub_hex=fresh_device["enc_pub_hex"][:62]), "invalid-payload",
           "enc_pub_hex の長さ不正(62 文字)は構造段で拒否する(hex 小文字 64 が正規形)")
    add_dk("add-device-sig-pub-uppercase-hex", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), sig_pub_hex=fresh_device["sig_pub_hex"].upper()), "invalid-payload",
           "sig_pub_hex の大文字 hex は構造段で拒否する")
    add_dk("revoke-device-empty-list", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, []), "invalid-payload",
           "失効 FP リストは 1 要素以上(§6.2 — 空の失効は意味を持たない。黙って成功させない)")
    add_dk("revoke-device-duplicate-fp", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, [reserve["fp_hex"], reserve["fp_hex"]]), "invalid-payload",
           "重複 FP を含む失効リストは無効(構造段)")
    add_dk("revoke-device-fp-bad-length", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, [reserve["fp_hex"][:30]]), "invalid-payload",
           "FP の長さ不正(30 文字)は構造段で拒否する(hex 小文字 32 が正規形)")
    add_dk("revoke-device-too-many-fps", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, [f"{i:032x}" for i in range(257)]), "invalid-payload",
           "失効 FP リストが 257 要素(上限 256 超過)のエントリは署名が有効でも拒否する")
    add_dk("add-device-format-precedes-actor", 38, dk_head[37], "add_device", devmember_id, devmember,
           dict(device_payload(fresh_device, "owner"), role_cap="superuser"), "invalid-payload",
           "構造違反 × 非メンバー actor(seq 34 で削除済みの devmember)の複合違反は構造検査が先に判定される(検証段順: 構造 → actor)")
    add_dk("policy-ops-add-device", 38, dk_head[37], "set_approval_policy", owner_id, recovered,
           policy_payload(["add_device"], 2), "invalid-payload",
           "`add_device` / `revoke_device` は set_approval_policy の ops に含められない(構造検査 — 端末の追加は定足数に影響せず、失効は安全側の操作 — §6.2 端末鍵「四眼との関係」)")
    add_dk("policy-ops-revoke-device", 38, dk_head[37], "set_approval_policy", owner_id, recovered,
           policy_payload(["revoke_device"], 2), "invalid-payload",
           "同上(revoke_device)")

    # add_device の認可: actor 規則 → duplicate-member-key → unknown-environment → device-cap-exceeded
    add_dk("authz-add-device-nonmember-actor", 38, dk_head[37], "add_device", devmember_id, devmember,
           device_payload(fresh_device, "reader", "listed", [DEV]), "actor-not-member",
           "seq 34 で削除済みの devmember はチェーンに追記できない(端末の追加も同じ — 削除済みメンバーの鍵は現メンバーの端末でない)")
    add_dk("authz-add-device-revoked-device-actor", 38, dk_head[37], "add_device", owner_id, owner,
           device_payload(fresh_device, "owner"), "actor-key-mismatch",
           "seq 35 で失効した端末 D1 による以後の署名は無効(actor の FP が現メンバーの有効な端末でない = actor-key-mismatch。失効端末が端末を増やす経路を閉じる)")
    add_dk("authz-add-device-duplicate-key-other-member", 38, dk_head[37], "add_device", owner_id, recovered,
           device_payload(owner2, "owner"), "duplicate-member-key",
           "他人(owner-0014)の端末鍵一式を自分の端末として登録することは拒否する(メンバー鍵の一意性の対象は現メンバーの全端末鍵 — §6.2)")
    add_dk("authz-add-device-duplicate-own-key", 38, dk_head[37], "add_device", owner_id, recovered,
           device_payload(reserve, "owner"), "duplicate-member-key",
           "自分の既存端末(予備鍵 R)の鍵一式の再登録も拒否する(同じ鍵は同時に 2 端末になれない)")
    add_dk("authz-add-device-duplicate-enc-key", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), enc_pub_hex=reserve["enc_pub_hex"]), "duplicate-member-key",
           "enc 公開鍵だけが現メンバーの端末鍵と一致する登録も拒否する(判定は個別鍵単位 — add_member と同じ)")
    add_dk("authz-add-device-duplicate-sig-key", 38, dk_head[37], "add_device", owner_id, recovered,
           dict(device_payload(fresh_device, "owner"), sig_pub_hex=owner3_readercap["sig_pub_hex"]), "duplicate-member-key",
           "sig 公開鍵だけが他人(owner-0015 の端末 L)の鍵と一致する登録も拒否する")
    add_dk("authz-add-device-unknown-environment", 38, dk_head[37], "add_device", owner_id, recovered,
           device_payload(fresh_device, "owner", "listed", [GHOST]), "unknown-environment",
           "listed の各 environment_id は create_environment が先行していなければならない(typo の fail-closed — scope と同じ理由コード)")
    add_dk("authz-add-device-cap-role-exceeded", 38, dk_head[37], "add_device", owner3_id, owner3_readercap,
           device_payload(fresh_device, "member"), "device-cap-exceeded",
           "単調性(原則 D2)の role 軸: cap (reader, all) の端末 L は role_cap member の端末を作れない(比較は署名端末自身の cap 同士 — 人の role〔owner〕ではない)")
    add_dk("authz-add-device-cap-scope-exceeded-listed", 37, dk_head[36], "add_device", allmember_id, cibox,
           device_payload(fresh_device, "member", "listed", [DEV, PROD, STAGE]), "device-cap-exceeded",
           "単調性の scope 軸: cap (member, listed{dev, stage}) の CI 箱 C は listed{dev, prod, stage} の端末を作れない(端末 scope_new ⊆ 端末 scope_signer)",
           chain="device-recovered")
    add_dk("authz-add-device-cap-scope-exceeded-all", 37, dk_head[36], "add_device", allmember_id, cibox,
           device_payload(fresh_device, "member"), "device-cap-exceeded",
           "listed の端末は all の端末を作れない(all = U は listed に包含されない — 集合代数は環境スコープと同じ)",
           chain="device-recovered")
    add_dk("authz-add-device-cap-scope-exceeded-empty", 35, dk_head[34], "add_device", owner_id, phone,
           device_payload(fresh_device, "owner", "listed", [DEV]), "device-cap-exceeded",
           "票だけの端末 P (owner, listed{}) は listed{dev} の端末を作れない(空 scope の端末が作れるのは空 scope の端末だけ — 盗まれた電話が読める端末を作れない)",
           chain="device-revote-applied")
    add_dk("authz-add-device-cap-both-axes-exceeded", 38, dk_head[37], "add_device", owner3_id, owner3_readercap,
           device_payload(fresh_device, "owner", "listed", [DEV]), "device-cap-exceeded",
           "role 軸(reader → owner)と scope 軸(all ⊇ listed は通る)の複合: 1 軸でも超えれば device-cap-exceeded")
    add_dk("authz-add-device-actor-not-member-precedes-duplicate-key", 38, dk_head[37], "add_device", devmember_id, devmember,
           device_payload(reserve, "reader"), "actor-not-member",
           "非メンバー × 鍵重複(予備鍵 R の流用)の複合違反は actor 規則が先に判定される(add_device: actor 規則 → duplicate-member-key)")
    add_dk("authz-add-device-key-mismatch-precedes-duplicate-key", 38, dk_head[37], "add_device", owner_id, owner,
           device_payload(owner2, "owner"), "actor-key-mismatch",
           "失効端末の署名 × 鍵重複の複合違反は actor 規則(actor-key-mismatch)が先に判定される")
    add_dk("authz-add-device-duplicate-key-precedes-unknown-environment", 38, dk_head[37], "add_device", owner_id, recovered,
           device_payload(reserve, "owner", "listed", [GHOST]), "duplicate-member-key",
           "鍵重複 × 未知環境の複合違反は duplicate-member-key が先に判定される(add_device: duplicate-member-key → unknown-environment)")
    add_dk("authz-add-device-unknown-environment-precedes-cap", 38, dk_head[37], "add_device", owner3_id, owner3_readercap,
           device_payload(fresh_device, "owner", "listed", [GHOST]), "unknown-environment",
           "未知環境 × cap 超過(reader の端末が owner を作る)の複合違反は unknown-environment が先に判定される(add_device: unknown-environment → device-cap-exceeded)")

    # revoke_device の認可: unknown-target → unknown-device → 対象依存の role 規則 → last-device-protected →
    # scope-not-contained(他人のみ)
    add_dk("authz-revoke-device-unknown-target", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload("user-ghost-9999", [reserve["fp_hex"]]), "unknown-target",
           "対象 user_id が現メンバーでなければ unknown-target(削除済みメンバーの端末も失効できない — 端末は remove_member で同時に終わっている)")
    add_dk("authz-revoke-device-unknown-device", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, [owner2["fp_hex"]]), "unknown-device",
           "各 FP は対象の現在有効な端末でなければならない(他人の端末の FP を自分の失効リストに載せても unknown-device)")
    add_dk("authz-revoke-device-already-revoked", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, [owner["fp_hex"]]), "unknown-device",
           "seq 35 で失効済みの端末 D1 の再失効は unknown-device(失効は冪等でなく、有効な端末に対してのみ成立する)")
    add_dk("authz-revoke-device-member-revokes-admin", 38, dk_head[37], "revoke_device", allmember_id, allmember,
           revoke_payload(admin_id, [admin["fp_hex"]]), "insufficient-role",
           "他人の端末の失効は remove_member と同じ role 規則: member は誰の端末も失効させられない")
    add_dk("authz-revoke-device-admin-revokes-owner", 38, dk_head[37], "revoke_device", admin_id, admin,
           revoke_payload(owner_id, [reserve["fp_hex"]]), "insufficient-role",
           "admin / owner の端末の失効は owner のみ(対象の role で決まる — admin は owner の端末を失効させられない)")
    add_dk("authz-revoke-device-reader-revokes-other", 38, dk_head[37], "revoke_device", prodreader_id, prodreader,
           revoke_payload(owner3_id, [owner3_readercap["fp_hex"]]), "insufficient-role",
           "reader が他人の端末を失効させる形は role 規則で拒否する(reader に許されるのは自分の端末の add / revoke のみ)")
    add_dk("authz-revoke-device-last-device-self", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload(owner_id, sorted([reserve["fp_hex"], recovered["fp_hex"]])), "last-device-protected",
           "失効後に対象の端末が 0 になるエントリは無効(端末のないメンバーは復帰不能 — その形は remove_member で表す)。自分の全端末の一括失効も同じ")
    add_dk("authz-revoke-device-last-device-other", 38, dk_head[37], "revoke_device", admin_id, admin,
           revoke_payload(allmember_id, [allmember["fp_hex"]]), "last-device-protected",
           "admin が他人(allmember — seq 37 で C を失効済み・残り 1 台)の最後の端末を失効させる形も無効")
    add_dk("authz-revoke-device-scope-not-contained", 37, dk_head[36], "revoke_device", devadmin_id, devadmin,
           revoke_payload(allmember_id, [cibox["fp_hex"]]), "scope-not-contained",
           "原則 1 の包含は対象**の人**の scope で判定する(設計録 §6 K1-10 (3)(a)): dev 専任 admin(listed{dev, stage})は、端末 C の scope が {dev, stage} ⊆ 自分の scope でも、"
           "人(allmember)の scope = all を包含しないため C を失効させられない(失効の rotate 義務〔人の scope ∩ 端末の scope〕の履行者は人の scope を包含する者)",
           chain="device-recovered")
    add_dk("authz-revoke-device-unknown-target-precedes-unknown-device", 38, dk_head[37], "revoke_device", owner_id, recovered,
           revoke_payload("user-ghost-9999", ["ab" * 16]), "unknown-target",
           "未知の対象 × 未知の FP の複合違反は unknown-target が先に判定される(revoke_device: unknown-target → unknown-device)")
    add_dk("authz-revoke-device-unknown-device-precedes-role", 38, dk_head[37], "revoke_device", allmember_id, allmember,
           revoke_payload(admin_id, ["ab" * 16]), "unknown-device",
           "未知の FP × role 不足(member が admin の端末を失効)の複合違反は unknown-device が先に判定される(revoke_device: unknown-device → 対象依存の role 規則 — 対象の存在を先に解決する remove_member と同じ形)")
    add_dk("authz-revoke-device-role-precedes-last-device", 38, dk_head[37], "revoke_device", admin_id, admin,
           revoke_payload(owner2_id, [owner2["fp_hex"]]), "insufficient-role",
           "role 不足(admin が owner の端末を失効)× 最後の端末の複合違反は role 規則が先に判定される(revoke_device: role 規則 → last-device-protected)")
    add_dk("authz-revoke-device-last-device-precedes-scope", 38, dk_head[37], "revoke_device", devadmin_id, devadmin,
           revoke_payload(prodreader_id, [prodreader["fp_hex"]]), "last-device-protected",
           "最後の端末 × scope 外(prodreader の scope {prod} ⊄ {dev, stage})の複合違反は last-device-protected が先に判定される(revoke_device: last-device-protected → scope-not-contained)")
    add_dk("authz-revoke-device-revoked-actor", 38, dk_head[37], "revoke_device", owner_id, phone,
           revoke_payload(owner_id, [reserve["fp_hex"]]), "actor-key-mismatch",
           "seq 35 で失効した電話 P による失効エントリは actor-key-mismatch(失効端末は他の端末を失効させられない)")

    # 実効権限の置換 — チェーン op の役割・包含・環境対象の各検査(§1 原則 7: 署名した端末の実効権限)
    add_dk("authz-rotate-by-reader-cap-device", 38, dk_head[37], "rotate_epoch", owner3_id, owner3_readercap,
           rotate_payload(PROD, 3), "insufficient-role",
           "役割: owner-0015 の cap (reader, all) の端末 L の実効 role は min(owner, reader) = reader。rotate_epoch(member 以上)は拒否する")
    add_dk("authz-add-member-by-reader-cap-device", 38, dk_head[37], "add_member", owner3_id, owner3_readercap,
           add_payload(newcomer_id, newcomer, "member"), "insufficient-role",
           "役割: 端末 L からの add_member(admin 以上)も実効 role reader で拒否する")
    add_dk("authz-add-member-by-empty-scope-device", 35, dk_head[34], "add_member", owner_id, phone,
           add_payload(newcomer_id, newcomer, "member", "listed", [DEV]), "scope-not-contained",
           "包含(原則 1): 電話 P (owner, listed{}) の実効 scope は all ∩ {} = {}。listed{dev} の付与は包含できない(add_member は ops に無く、member の付与は常時対象でもないので approval-required には当たらない)",
           chain="device-revote-applied")
    add_dk("authz-propose-by-empty-scope-device", 35, dk_head[34], "propose", owner_id, phone,
           propose_payload("remove_member", {"target_user_id": prodreader_id}, EXPIRES), "scope-not-contained",
           "包含(原則 1・提案段): 電話 P の実効 scope {} は prodreader の scope {prod} を包含しないので、remove_member の提案は提案者の実効 scope で拒否する",
           chain="device-revote-applied")
    add_dk("authz-revoke-device-by-empty-scope-device", 35, dk_head[34], "revoke_device", owner_id, phone,
           revoke_payload(allmember_id, [cibox["fp_hex"]]), "scope-not-contained",
           "包含(revoke_device): 電話 P の実効 scope {} は allmember の scope(all)を包含しない — 他人の端末の失効も署名端末の実効 scope で判定する",
           chain="device-revote-applied")
    add_dk("authz-rotate-out-of-device-scope", 37, dk_head[36], "rotate_epoch", allmember_id, cibox,
           rotate_payload(PROD, 3), "environment-out-of-scope",
           "環境対象 op: CI 箱 C の実効 scope は all ∩ {dev, stage} = {dev, stage}。prod の rotate_epoch は人の scope(all)に含まれても端末の実効 scope 外なので拒否する",
           chain="device-recovered")
    add_dk("authz-create-env-by-listed-device", 37, dk_head[36], "create_environment", allmember_id, cibox,
           create_env_payload(FRESH), "environment-out-of-scope",
           "環境対象 op: listed の端末は環境を作れない(新 environment_id は端末の実効 scope に含まれえない — 人が all でも同じ)",
           chain="device-recovered")
    add_dk("authz-checkpoint-out-of-device-scope", 37, dk_head[36], "checkpoint", allmember_id, cibox,
           checkpoint_payload([checkpoint_env_entry(PROD, 2, 1)]), "environment-out-of-scope",
           "環境対象 op: 端末の実効 scope 外の環境のタプルを含む checkpoint は拒否する",
           chain="device-recovered")

    # 四眼の票 × 端末(§6.2 approve の端末語彙)
    add_dk("authz-approve-revoked-device", 34, dk_head[33], "approve", owner2_id, owner2_second,
           approve_of(p30), "actor-key-mismatch",
           "失効した端末 D14b(seq 32)による approve は actor-key-mismatch(失効端末の票は入れられない・既に入れた票も数えない — device-dead-vote)",
           chain="device-dead-vote")
    add_dk("authz-approve-other-device-duplicate", 34, dk_head[33], "approve", owner_id, owner,
           approve_of(p30), "duplicate-approval",
           "同じ人の別端末からの 2 票目: owner-0001 は電話 P で投票済み(seq 33)なので、端末 D1 からの approve は duplicate-approval(distinct は user_id — 1 人 1 票)",
           chain="device-dead-vote")
    add_dk("authz-approve-cap-below-owner", 34, dk_head[33], "approve", owner3_id, owner3_readercap,
           approve_of(p30), "insufficient-role",
           "cap (reader, all) の端末 L の実効 role は reader なので、owner-0015 でも L からは票を入れられない(approve の role 規則は署名した端末の実効 role — §6.2)",
           chain="device-dead-vote")
    add_dk("authz-approve-cap-precedes-unknown-proposal", 38, dk_head[37], "approve", owner3_id, owner3_readercap,
           {"proposal_hash_hex": BOGUS_HASH}, "insufficient-role",
           "実効 role 不足 × 未知の提案の複合違反は role 規則が先に判定される(approve: role → unknown-proposal)")
    add_dk("authz-propose-add-device", 38, dk_head[37], "propose", owner_id, recovered,
           propose_payload("add_device", device_payload(fresh_device, "owner"), EXPIRES), "approval-not-required",
           "add_device は方針の対象にできない(§6.2 端末鍵「四眼との関係」)ため、その提案は approval-not-required")
    add_dk("authz-propose-revoke-device", 38, dk_head[37], "propose", owner_id, recovered,
           propose_payload("revoke_device", revoke_payload(owner_id, [reserve["fp_hex"]]), EXPIRES), "approval-not-required",
           "revoke_device の提案も approval-not-required(失効は安全側の操作 — rotate と同じ線)")
    add_dk("authz-approve-proposer-device-revoked", 41, void_head, "approve", owner3_id, owner3,
           approve_of(p38), "proposal-void",
           "定足数到達時(生きている票 = (0014, K14) + (0015, K15) = 2)に提案した端末 D1n が失効済み(seq 39)なら proposal-void(提案端末の有効性で判定 — 提案者の在籍・鍵 FP の端末語彙)",
           chain="proposer-device-revoked")

    negatives += authz_cases[dk_start:]

    # --- 許容側(valid_appends)------------------------------------------------------------
    def dk_append(name, seq, prev_hex, op, actor_id, actor_keys, payload, members, note,
                  chain="device-ops", pending=None, environments=None):
        case = {
            "name": name,
            "entry": build_entry(seq, op, actor_id, actor_keys, payload, ts_at(seq), prev_hex),
            "chain": chain,
            "expected_members": members,
            "expected_environments": environments if environments is not None else base_environments,
            "expected_server_grants": [],
            "expected_policy": canonical_policy,
            "expected_pending": pending if pending is not None else {},
            "note": note,
        }
        return case

    valid_appends += [
        dk_append(
            "member-registers-reserve-key", 38, dk_head[37], "add_device", allmember_id, allmember,
            device_payload(fresh_device, "owner"),
            with_devices(members_37, allmember_id, {fresh_device["fp_hex"]: device_state(fresh_device, "owner", "all", None, 38)}),
            "member(allmember-0013)が最初の端末(構造的に cap (owner, all))から cap (owner, all) の端末 = 予備鍵を登録できる(単調性は署名端末自身の cap 同士の比較 — 実効権限 min(member, owner) = member で比べない。2026-09-19 Cursor Bugbot 指摘対応)。登録された端末の実効権限は (member, all) のまま",
        ),
        dk_append(
            "readd-revoked-device-same-key", 38, dk_head[37], "add_device", allmember_id, allmember,
            device_payload(cibox, "member", "listed", [DEV, STAGE]),
            with_devices(members_37, allmember_id, {cibox["fp_hex"]: device_state(cibox, "member", "listed", [DEV, STAGE], 38)}),
            "seq 37 で失効した端末 C の鍵一式を同じ人が再登録することは拒否されない(鍵一意性の対象は現メンバーの**有効な**端末鍵のみ — 失効した鍵の再登録で旧票が復活する「失効は単調ではない」の端末形の帰結。CLI は失効済み FP の再登録に警告する)",
        ),
        dk_append(
            "reader-revokes-own-device", 39, reader_head, "revoke_device", prodreader_id, prodreader,
            revoke_payload(prodreader_id, [reader_second["fp_hex"]]), members_37,
            "reader が自分の端末を失効させる(role 不問。§7 — reader は rotate 義務を履行できないが失効は拒否しない〔安全側の操作を止めない〕)",
            chain="reader-second-device",
        ),
        dk_append(
            "other-owner-completes-after-dead-vote", 34, dk_head[33], "approve", owner3_id, owner3,
            approve_of(p30), members_34,
            "device-dead-vote(生きている票 = (0001, P) の 1 票)へ owner-0015 が投票すると定足数 2 に達して内側 remove_member を適用する(失効端末 D14b の票は数えず、別の owner の票で完成する形)",
            chain="device-dead-vote",
        ),
        dk_append(
            "ci-device-rotates-in-scope", 37, dk_head[36], "rotate_epoch", allmember_id, cibox,
            rotate_payload(DEV, 3), members_36,
            "CI 箱 C(実効 (member, {dev, stage}))は端末の実効 scope 内の環境を rotate できる(環境対象 op の許容側)",
            chain="device-recovered", environments=dict(base_environments, **{DEV: "3"}),
        ),
        dk_append(
            "ci-device-checkpoints-in-scope", 37, dk_head[36], "checkpoint", allmember_id, cibox,
            checkpoint_payload([dev_scoped_checkpoint]), members_36,
            "CI 箱 C は端末の実効 scope 内の環境のタプルだけを公証できる",
            chain="device-recovered",
        ),
        dk_append(
            "phone-approves-then-listed-device-added", 35, dk_head[34], "add_device", owner_id, phone,
            device_payload(fresh_device, "owner", "listed", []), with_devices(
                members_34, owner_id, {fresh_device["fp_hex"]: device_state(fresh_device, "owner", "listed", [], 35)}),
            "電話 P (owner, listed{}) は同じ cap (owner, listed{}) の端末を作れる(単調性の等号側 — 空 scope ⊆ 空 scope)",
            chain="device-revote-applied",
        ),
    ]
    valid_appends[-2]["expected_checkpoints"] = {DEV: expected_checkpoint(37, dev_scoped_checkpoint)}

    device_keys = {
        f"{owner_id}@reserve": ("reserve", owner_id, reserve, 0x5A, 0x6A),
        f"{owner_id}@phone": ("phone", owner_id, phone, 0x5B, 0x6B),
        f"{allmember_id}@ci-box": ("ci-box", allmember_id, cibox, 0x5C, 0x6C),
        f"{owner2_id}@second": ("second", owner2_id, owner2_second, 0x5D, 0x6D),
        f"{owner3_id}@reader-cap": ("reader-cap", owner3_id, owner3_readercap, 0x5E, 0x6E),
        f"{owner_id}@recovered": ("recovered", owner_id, recovered, 0x5F, 0x6F),
    }

    def key_record(user: dict, enc_prefix: int, sig_prefix: int) -> dict:
        return {
            "enc_sk_seed_hex": pat(enc_prefix, 32).hex(),
            "sig_sk_seed_hex": pat(sig_prefix, 32).hex(),
            "enc_pub_hex": user["enc_pub_hex"],
            "sig_pub_hex": user["sig_pub_hex"],
            "key_fingerprint_hex": user["fp_hex"],
        }

    write(
        "chain-entries.json",
        {
            "description": "CRYPTO_SPEC §6: チェーンエントリの正規化バイト列と Ed25519 署名・ハッシュ連鎖のベクター(2026-09-14 ES + PF1 で全再生成 — 正規チェーンは 24 エントリ)",
            "canonicalization": {
                "signed_bytes": "LP(suite, seq, prev_hash_hex, op, actor_user_id, actor_key_fingerprint_hex, payload_bytes, timestamp_ms)",
                "payload_bytes": "LP(payload_field_order[op] の順のフィールド列)を 1 フィールドとして埋め込む",
                "entry_bytes": "LP(signed_bytes の 8 フィールド, signature_hex)",
                "entry_hash": "SHA-256(entry_bytes)。次エントリの prev_hash になる",
                "binary_encoding": "prev_hash / 公開鍵 / FP / 署名は hex 小文字文字列として LP に載せる",
                "payload_field_order": PAYLOAD_FIELD_ORDER,
                "member_scope": "add_member / change_role の末尾 2 フィールド: scope_kind(\"all\" | \"listed\")と scope_environments_lp_hex(environment_id リストの LP の hex 小文字 — grant_server の scope_environments と同じ入れ子 LP。順序は署名対象。生成は昇順 SHOULD・検証は集合)。構造規則: all ⇒ 空リスト必須・256 要素以下・重複 id は無効・listed の空リストは有効(§6.2 — 2026-09-14 ES)。genesis は scope を持たず作成者は構造的に all → 要レビュー",
                "approval_policy": "set_approval_policy = LP(ops_lp_hex, required_approvals)。ops_lp_hex = op 名リストの LP の hex(入れ子 LP。順序は署名対象。生成は昇順 SHOULD・検証は集合)。ops ⊆ {grant_server, revoke_server, remove_member, change_role, add_member, set_approval_policy}、required_approvals は 0(オフ)または 2 以上(§6.2 — 2026-09-14 PF1)→ 要レビュー",
                "proposal": "propose = LP(inner_op, inner_payload_lp_hex, expires_at_ms)。inner_payload_lp_hex = 内側 op の payload_bytes(PAYLOAD_FIELD_ORDER[inner_op] の順の LP — §6.1 の入れ子 LP)の hex 小文字(内側 op が scope / ops / lease_policy を持てば 2 段以上の入れ子)。内側 op は propose / approve / withdraw 以外(再帰なし — 構造段で拒否)。approve / withdraw = LP(proposal_hash_hex) — 提案エントリの entry_hash(hex 小文字 64)→ 要レビュー",
                "device_ops": "add_device = LP(enc_pub_hex, sig_pub_hex, role_cap, scope_kind, scope_environments_lp_hex)(role_cap ∈ {reader, member, admin, owner} — owner = 上限なし。scope の 2 フィールドは member_scope と同じ符号化・構造規則)、revoke_device = LP(target_user_id, device_fingerprints_lp_hex)(FP〔hex 小文字 32〕リストの入れ子 LP の hex。1 要素以上・256 要素以下・重複無効。順序は署名対象 — 生成は昇順 SHOULD・検証は集合)。正規チェーン seq 1〜24 は不変で、2 op の正例列は派生チェーン device-ops(seq 25〜37)とそのプレフィックス(device-added / device-dead-vote / device-revote-applied / device-recovered)。端末の導出状態は members[user_id].devices = FP → {role_cap, scope, added_seq}(省略 = 最初の鍵 1 つ = cap (owner, all))(§6.2 — 2026-09-20 DK)→ 要レビュー",
                "key_fingerprint": "SHA-256(enc_pub(32B) || sig_pub(32B)) の先頭 16 バイト(固定長のため素の連結)",
                "server_key_fingerprint": "SHA-256(server_enc_pub(32B)) の先頭 16 バイト(サーバーは enc 鍵のみ。§9)→ 要レビュー",
                "scope_environments": "environment_id のリストを LP エンコード(入れ子 LP)し、その hex 小文字文字列を scope_environments_lp_hex として payload に載せる。リストの順序は署名対象の一部(検証は as-signed 順で再構築)→ 要レビュー",
                "lease_policy": "constraint = LP(claim_name, claim_value)、element = LP(issuer_url, audience, LP(constraint...))、lease_policy_lp_hex = lower_hex(LP(element...))(3 段の入れ子 LP — §6.2)。リスト順(要素・制約とも)は署名対象の一部。空リストは hex 空文字列 = リース経路なし。上限: 要素 8 / 要素あたり制約 8 / 各文字列 1024 バイト(§6.1)→ 要レビュー",
                "dek_commitment": "dek_commitment_hex = lower_hex(SHA-256(LP(\"maruhi/v1/dek-commit\", project_id, environment_id, epoch, dek_hex)))(§5.2)。project_id = genesis エントリハッシュ。形式は hex 小文字 64 文字(形式検査は payload 構造検査の段 — §6.2)。内容の照合は受信者の §5.2 検証が担い、チェーン検証は形式のみ検査する",
                "checkpoint_environments": "環境エントリ = LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex, values_digest_hex)、environments_lp_hex = lower_hex(LP(entry...))(scope_environments と同じ入れ子 LP — §6.2)。リスト順は署名対象の一部(生成は environment_id のバイト昇順 SHOULD — 検証は順序を規範にしない)。重複 environment_id は payload 構造検査で無効(invalid-payload)。manifest_sig_hash_hex / values_digest_hex は hex 小文字 64 文字、audit_head_hash_hex は空文字列(公証なし)または hex 小文字 64 文字。タプル内容(マニフェスト・値・監査ヘッド)はチェーン検証では検証不能であり、照合はサーバー受理検証(§6.4)とクライアントの配布時照合(§6.3)が担う → 要レビュー",
                "env_values_digest": "values_digest_hex = lower_hex(SHA-256(LP(\"maruhi/v1/env-values-digest\", v_1, …, v_m)))、v_j = LP(variable_id, version, value_sig_hash_hex)(variable_id の UTF-8 バイト昇順。active 変数のみ — tombstone はマニフェスト側 §4.3 が捕捉)。空集合も有効。単体ベクターは values_digests セクション → 要レビュー",
            },
            "keys": {
                owner_id: key_record(owner, 0x10, 0x20),
                member_id: key_record(member, 0x30, 0x40),
                admin_id: key_record(admin, 0x50, 0x60),
                # 2026-09-14 ES / PF1 で加わったメンバー(seq 13〜19)
                devmember_id: key_record(devmember, 0x3A, 0x4A),
                devadmin_id: key_record(devadmin, 0x3B, 0x4B),
                prodreader_id: key_record(prodreader, 0x3C, 0x4C),
                allmember_id: key_record(allmember, 0x3D, 0x4D),
                owner2_id: key_record(owner2, 0x3E, 0x4E),
                owner3_id: key_record(owner3, 0x3F, 0x4F),
                # 2026-09-20 DK: 端末鍵(派生チェーン device-ops の seq 25〜36 で足す端末)。
                # キーは "<user_id>@<label>"、user_id / label を併記する。検証器は actor の
                # (user_id, FP) で鍵を選ぶ(FP が端末を指す — §1 原則 7)
                **{
                    label_key: {"user_id": uid, "label": label, **key_record(dev, enc_p, sig_p)}
                    for label_key, (label, uid, dev, enc_p, sig_p) in device_keys.items()
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
            # checkpoint の values_digest 正規形の単体ベクター(§6.2 — PR-F3a)
            "values_digests": values_digests,
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
                   nonce, plaintext, prev_hash_hex, head_seq, note, prev_base=None,
                   key=None, chain_ref=None, head_hash_hex=None):
        # key / chain_ref / head_hash_hex(2026-09-20 DK): 端末鍵で署名する正例は鍵記録
        # (chain-entries.json の keys の端末エントリ)と参照チェーン名を明示する
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
            "chain_head_hash_hex": head_hash_hex if head_hash_hex is not None else head_hash(head_seq),
            "chain_head_seq": head_seq,
        }
        signed = value_signed_bytes(ctx)
        signer = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["sig_sk_seed_hex"]))
                  if key is not None else signer_of(writer_id))
        vector = {
            "name": name,
            "context": ctx,
            "writer_key_fingerprint_hex": key["key_fingerprint_hex"] if key is not None else fp_of(writer_id),
            "plaintext_utf8": plaintext,
            "aad_hex": var_aad(suite, project_id, environment_id, epoch, variable_id, version).hex(),
            "dek_ref": {"environment_id": environment_id, "epoch": epoch},
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "note": note,
        }
        if prev_base is not None:
            vector["prev_base"] = prev_base
        if chain_ref is not None:
            vector["chain"] = chain_ref
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
        **scope_fields("all", []),
    }
    head_seq = len(entries)  # 正規チェーンのヘッド(2026-09-14 ES + PF1 で 24)
    readd_seq = head_seq + 1
    owner_keys = chain["keys"][owner_id]
    owner_fp = owner_keys["key_fingerprint_hex"]
    readd_pb = lp_encode([readd_payload[k] for k in PAYLOAD_FIELD_ORDER["add_member"]])
    readd_ts = 1754006400000 + 1000 * head_seq
    readd_signed = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts]
    )
    readd_sig = signer_of(owner_id).sign(readd_signed)
    readd_entry_bytes = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts,
         readd_sig.hex()]
    )
    tenure_extension = {
        "note": "key-from-other-tenure 用の派生チェーン: 正規チェーン(24 エントリ)の後に "
                "seq 25 で user-member-0002 を新鍵で re-add する(remove → re-add = 別 tenure)。"
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
            "seq": readd_seq,
            "suite": suite,
            "prev_hash_hex": head_hash(head_seq),
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
            pat(0xB1, 12), "rule-dummy", "", sha256(b"future-head").hex(), len(entries) + 1,
            "chain-head-future",
            "seq 25 は自ビューのヘッド(24)より先 = 自チェーンが古いだけの可能性。まず再同期し、"
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
            tenure_extension["entry"]["entry_hash_hex"], readd_seq,
            "writer-key-mismatch-at-head",
            "remove → 別鍵 re-add(派生チェーン seq 25)の user_id で、旧在籍区間の鍵 × 新区間の"
            "ヘッド(25)の組合せは拒否する(§6.3-1 のヘッド時点鍵束縛 — 同じ鍵の dedupe で"
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

    # --- 3′ スコープの認可時点検査(2026-09-14 ES — CRYPTO_SPEC §6.3): 宣言ヘッド時点の
    # writer の scope が当該 environment_id を含むこと。role 検査(3)の直後・エポック整合(4)
    # の前。listed の writer = user-devmember-0010(head 19 時点 member listed{dev, stage}、
    # head 22 以降 reader listed{dev})
    devmember_id = "user-devmember-0010"
    vectors.append(
        make_value(
            "listed-writer-in-scope", devmember_id, "env-dev-0002", 2, "var-dev-scoped-0006", 1,
            pat(0xAC, 12), "dev-scoped-dummy-v1", "", 19,
            "listed の writer(head 19 時点 member listed{dev, stage})による scope 内の環境(env-dev-0002)"
            "への push は通る(3′ の許容側)",
        )
    )
    rule_negatives += [
        rule_negative(
            "writer-environment-out-of-scope", devmember_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xBC, 12), "rule-dummy", "", head_hash(19), 19,
            "writer-environment-out-of-scope-at-head",
            "head 19 時点の user-devmember-0010 は member listed{dev, stage}。scope 外の env-prod-0001 への"
            "署名は、role(member 以上)を満たしても宣言ヘッド時点の scope 検査(3′)で拒否する",
        ),
        rule_negative(
            "writer-role-precedes-scope", devmember_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xBD, 12), "rule-dummy", "", head_hash(24), 24,
            "writer-role-insufficient-at-head",
            "head 24 時点の user-devmember-0010 は reader listed{dev}(seq 22 の適用)。role 不足 × scope 外の"
            "複合違反は role 検査(3)が scope 検査(3′)に先行する",
        ),
        rule_negative(
            "writer-scope-precedes-epoch", devmember_id, "env-prod-0001", 1, "var-rule-0004", 1,
            pat(0xBE, 12), "rule-dummy", "", head_hash(19), 19,
            "writer-environment-out-of-scope-at-head",
            "scope 外 × 旧エポック(1 — head 19 の現エポックは 2)の複合違反は scope 検査(3′)が"
            "エポック整合(4)に先行する",
        ),
    ]

    # --- 端末軸(2026-09-20 DK — CRYPTO_SPEC 0.12-draft §6.3「端末鍵の選択と実効権限」):
    # 検証規則 1 の鍵選択は端末の有効区間、3 / 3′ は署名した端末の実効権限で判定する。
    # 参照チェーンは chain-entries.json の派生チェーン device-ops(seq 25〜37 — 既存の
    # 正例・負例と `canonical` の意味は不変。規約 28)。理由コードはいずれも既存のもの
    dk_chain = chain["extended_chains"]["device-ops"]["entries"]

    def dk_head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"] if seq <= len(entries) else dk_chain[seq - 25]["entry_hash_hex"]

    def device_key(label: str) -> dict:
        return chain["keys"][label]

    def device_signer(label: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(device_key(label)["sig_sk_seed_hex"]))

    cibox = device_key("user-allmember-0013@ci-box")           # C: 実効 (member, {dev, stage})。seq 27〜36 有効
    readercap = device_key("user-owner-0015@reader-cap")       # L: 実効 (reader, all)
    allmember_id = "user-allmember-0013"
    owner3_id = "user-owner-0015"
    vectors.append(
        make_value(
            "second-device-writer-in-scope", allmember_id, "env-dev-0002", 2, "var-ci-scoped-0007", 1,
            pat(0xAD, 12), "ci-scoped-dummy-v1", "", 28,
            "第 2 端末の正例: allmember-0013(member, all)の CI 箱 C(cap (member, listed{dev, stage}) — seq 27)による"
            "実効 scope 内の環境(env-dev-0002)への push は通る(宣言ヘッド 28 は C の有効区間内)",
            key=cibox, chain_ref="device-ops", head_hash_hex=dk_head_hash(28),
        )
    )
    rule_negatives += [
        rule_negative(
            "writer-device-revoked-at-head", allmember_id, "env-dev-0002", 2, "var-ci-scoped-0007", 1,
            pat(0xBF, 12), "rule-dummy", "", dk_head_hash(37), 37,
            "writer-key-mismatch-at-head",
            "seq 37 で失効した端末 C が失効後のヘッド(37)を宣言した署名は writer-key-mismatch-at-head"
            "(端末の有効区間 = add_device 以後・revoke_device の直前まで。人〔allmember〕は在籍のまま — "
            "在籍区間跨ぎと同じ既存の理由コード)",
            chain_ref="device-ops", writer_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
        rule_negative(
            "writer-device-role-insufficient", owner3_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xC0, 12), "rule-dummy", "", dk_head_hash(29), 29,
            "writer-role-insufficient-at-head",
            "owner-0015 の cap (reader, all) の端末 L(seq 29)の実効 role は min(owner, reader) = reader。"
            "人が owner でも、この端末による値の push は writer-role-insufficient-at-head",
            chain_ref="device-ops", writer_fp=readercap["key_fingerprint_hex"],
            sign_with=device_signer("user-owner-0015@reader-cap"), verify_key_hex=readercap["sig_pub_hex"],
        ),
        rule_negative(
            "writer-device-environment-out-of-scope", allmember_id, "env-prod-0001", 2, "var-rule-0004", 1,
            pat(0xC1, 12), "rule-dummy", "", dk_head_hash(28), 28,
            "writer-environment-out-of-scope-at-head",
            "CI 箱 C の実効 scope は all ∩ {dev, stage} = {dev, stage}。人(allmember)の scope が all でも、"
            "端末 scope 外の env-prod-0001 への署名は writer-environment-out-of-scope-at-head",
            chain_ref="device-ops", writer_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
        rule_negative(
            "writer-device-unknown-before-add", allmember_id, "env-dev-0002", 2, "var-rule-0004", 1,
            pat(0xC2, 12), "rule-dummy", "", dk_head_hash(26), 26,
            "writer-key-mismatch-at-head",
            "端末 C の add_device(seq 27)より前のヘッド(26)を宣言した C の署名は writer-key-mismatch-at-head"
            "(有効区間の開始境界 — 追加前の端末は人に束縛されていない)",
            chain_ref="device-ops", writer_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
    ]

    write(
        "value-signature.json",
        {
            "description": "CRYPTO_SPEC §4.1: 値の書き込み署名(Ed25519)。value_signed_bytes = LP(\"<suite>/value-sig\", project_id, environment_id, epoch, variable_id, version, nonce_hex, ciphertext_hex, prev_value_sig_hash_hex, writer_user_id, chain_head_hash_hex, chain_head_seq)。チェーン・鍵・DEK は chain-entries.json の正規 12 エントリチェーンを参照",
            "signed_fields_order": VALUE_SIG_FIELDS_ORDER,
            "binary_encoding": "nonce / ciphertext / ハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(epoch / version / chain_head_seq)は 10 進文字列化",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、writer 鍵 = keys、DEK = environment_deks(ciphertext は実 AES-GCM 暗号文で、AAD は §4 の LP)。正規チェーンは 24 エントリ(2026-09-14 ES + PF1 — 正例の意味は不変、負例に writer-environment-out-of-scope-at-head を追加)",
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
# CRYPTO_SPEC §4.2 レイアウト v2(0.8-draft — 2026-08-30 セッション 46): 変数メタ
# ステートメントの第 2 レイアウト。ドメイン分離文字列は "<suite>/var-meta-sig-v2"
# (レイアウト版はステートメント種ローカル — suite は据え置き)。スキーマ欄
# (var_type / required / description)を status の直後に挟む。環境メタは v1 のまま
VAR_META_SIG_V2_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "variable_id", "name", "status",
    "var_type", "required", "description",
    "meta_version", "prev_meta_sig_hash_hex", "author_user_id",
    "chain_head_hash_hex", "chain_head_seq",
]


def meta_signed_bytes(ctx: dict) -> bytes:
    if ctx.get("layout_version", 1) == 2:
        order = VAR_META_SIG_V2_FIELDS_ORDER
    else:
        order = (VAR_META_SIG_FIELDS_ORDER if ctx["kind"] == "variable"
                 else ENV_META_SIG_FIELDS_ORDER)
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
                       prev_base=None, key=None, chain_ref=None, head_hash_hex=None):
        # key / chain_ref / head_hash_hex(2026-09-20 DK): 端末鍵で署名する正例の鍵記録と参照チェーン
        ctx = make_context(kind, environment_id, variable_id, display_name, status,
                           meta_version, prev_hash_hex, author_id,
                           head_hash_hex if head_hash_hex is not None else head_hash(head_seq),
                           head_seq)
        signed = meta_signed_bytes(ctx)
        signer = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["sig_sk_seed_hex"]))
                  if key is not None else signer_of(author_id))
        vector = {
            "name": name,
            "context": ctx,
            "author_key_fingerprint_hex": key["key_fingerprint_hex"] if key is not None else fp_of(author_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "note": note,
        }
        if prev_base is not None:
            vector["prev_base"] = prev_base
        if chain_ref is not None:
            vector["chain"] = chain_ref
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

    # --- レイアウト v2 の正例(CRYPTO_SPEC §4.2 レイアウト v2 / §11 の 0.8-draft 項。
    # 2026-08-30 セッション 46 — S0 承認済み・S1 でベクター化)。既存 v1 ベクターは
    # 1 バイトも変えない(レイアウト v2 は新ドメイン文字列の追加 — 追記で拡張)---
    def make_v2_context(environment_id, variable_id, name, status, var_type, required,
                        description, meta_version, prev_hash_hex, author_id,
                        head_hash_hex, head_seq):
        return {
            "kind": "variable",
            "suite": suite,
            "domain": f"{suite}/var-meta-sig-v2",
            "layout_version": 2,
            "project_id": project_id,
            "environment_id": environment_id,
            "variable_id": variable_id,
            "name": name,
            "status": status,
            "var_type": var_type,
            "required": required,
            "description": description,
            "meta_version": meta_version,
            "prev_meta_sig_hash_hex": prev_hash_hex,
            "author_user_id": author_id,
            "chain_head_hash_hex": head_hash_hex,
            "chain_head_seq": head_seq,
        }

    def make_v2_statement(name, environment_id, variable_id, display_name, status,
                          var_type, required, description, meta_version, prev_hash_hex,
                          author_id, head_seq, note, prev_base=None):
        ctx = make_v2_context(environment_id, variable_id, display_name, status,
                              var_type, required, description, meta_version,
                              prev_hash_hex, author_id, head_hash(head_seq), head_seq)
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

    v2_typed = make_v2_statement(
        "var-v2-create-typed", "env-prod-0001", "var-v2-typed-0010", "SERVICE_URL",
        "active", "url", "true", "Primary service endpoint URL", 1, "", admin_id, 12,
        "レイアウト v2 の変数作成(スキーマ欄あり・status active)。ドメイン分離文字列は"
        " maruhi/v1/var-meta-sig-v2(レイアウト版はステートメント種ローカル — suite は据え置き。§4.2)。"
        "スキーマ欄(var_type / required / description)は status の直後に署名対象として並ぶ",
    )
    v2_untyped = make_v2_statement(
        "var-v2-create-untyped", "env-prod-0001", "var-v2-untyped-0011", "OPTIONAL_FLAG",
        "active", "", "false", "", 1, "", admin_id, 12,
        "レイアウト v2 の未指定型(var_type = \"\" は閉集合の正当な値 — §4.2)。"
        "description も空文字列を許す(required のみ明示必須 — 空文字列不可)",
    )
    v2_declared = make_v2_statement(
        "var-v2-declared-create", "env-prod-0001", "var-v2-declared-0012", "STRIPE_API_KEY",
        "declared", "string", "true", "Stripe secret key (set before first deploy)",
        1, "", admin_id, 12,
        "declared 作成(metaVersion 1・値なし — §4.2 レイアウト v2 の第 3 の status)。"
        "作成は active(値同梱)または declared(値なし)のいずれか",
    )
    v2_activation = make_v2_statement(
        "var-v2-activation", "env-prod-0001", "var-v2-declared-0012", "STRIPE_API_KEY",
        "active", "string", "true", "Stripe secret key (set before first deploy)",
        2, v2_declared["signed_bytes_sha256_hex"], admin_id, 12,
        "declared → active 遷移(activation — 最初の値 push との複合。複合の受理検査は"
        " AUTH_SPEC §12-5 = S2 で、本ベクターはステートメント単体の encode / verify と"
        "「declared な predecessor の active 化は正当」を固定する)",
        prev_base="var-v2-declared-create",
    )
    v2_delete = make_v2_statement(
        "var-v2-delete-keeps-schema", "env-prod-0001", "var-v2-typed-0010", "SERVICE_URL",
        "deleted", "url", "true", "Primary service endpoint URL",
        2, v2_typed["signed_bytes_sha256_hex"], admin_id, 12,
        "レイアウト v2 の削除(status deleted)。name と同じ規約でスキーマ欄とレイアウトを"
        "直前ステートメントからそのまま保持する(§4.2 — 削除ステートメントのみ完全保持を要求)",
        prev_base="var-v2-create-typed",
    )
    vectors += [v2_typed, v2_untyped, v2_declared, v2_activation, v2_delete]

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
        **scope_fields("all", []),
    }
    head_seq = len(entries)  # 正規チェーンのヘッド(2026-09-14 ES + PF1 で 24)
    readd_seq = head_seq + 1
    owner_fp = chain["keys"][owner_id]["key_fingerprint_hex"]
    readd_pb = lp_encode([readd_payload[k] for k in PAYLOAD_FIELD_ORDER["add_member"]])
    readd_ts = 1754006400000 + 1000 * head_seq
    readd_signed = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts]
    )
    readd_sig = signer_of(owner_id).sign(readd_signed)
    readd_entry_bytes = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts,
         readd_sig.hex()]
    )
    tenure_extension = {
        "note": "key-from-other-tenure 用の派生チェーン(value-signature.json と同一内容): "
                "正規チェーン(24 エントリ)の後に seq 25 で user-member-0002 を新鍵で re-add する"
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
            "seq": readd_seq,
            "suite": suite,
            "prev_hash_hex": head_hash(head_seq),
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
            "active", 1, "", admin_id, sha256(b"future-head").hex(), len(entries) + 1,
            "chain-head-future",
            "seq 25 は自ビューのヘッド(24)より先 = 自チェーンが古いだけの可能性。まず再同期し、"
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
            tenure_extension["entry"]["entry_hash_hex"], readd_seq,
            "author-key-mismatch-at-head",
            "remove → 別鍵 re-add(派生チェーン seq 25)の user_id で、旧在籍区間の鍵 × 新区間の"
            "ヘッド(25)の組合せは拒否する(§6.3-1 のヘッド時点鍵束縛)",
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

    # --- レイアウト v2 の負例(§11 の 0.8-draft 項の列挙)------------------------
    # 署名系(改竄・移植): 元署名を維持したまま signed_bytes を差し替え、Ed25519
    # 検証が失敗することを固定する(既存 negative と同じ形)
    def v2_tamper_negative(name, overrides, note, base_vector=None):
        source = base_vector if base_vector is not None else v2_typed
        ctx = dict(source["context"], **overrides)
        return {
            "name": name,
            "base": source["name"],
            "context": ctx,
            "verify_signed_bytes_hex": meta_signed_bytes(ctx).hex(),
            "signature_hex": source["signature_hex"],
            "verify_key_hex": sig_pub_of(admin_id),
            "must_fail": True,
            "note": note,
        }

    # レイアウト混同の双方向(§4.2 — v1 と v2 の相互解釈は署名不一致で構造的に失敗
    # する〔§1 原則 6〕。layoutVersion の虚偽申告は別レイアウトでの signed_bytes
    # 再計算 = 署名不一致に退化する — 裁定 CR の既知の残余の固定)
    confusion_v2_as_v1_ctx = make_context(
        "variable", "env-prod-0001", "var-v2-typed-0010", "SERVICE_URL", "active",
        1, "", admin_id, head_hash(12), 12)
    confusion_v1_as_v2_ctx = make_v2_context(
        "env-prod-0001", "var-api-key-0001", "API_KEY", "active", "", "false", "",
        1, "", admin_id, head_hash(12), 12)
    layout_negatives = [
        {
            "name": "layout-confusion-v2-as-v1",
            "base": v2_typed["name"],
            "context": confusion_v2_as_v1_ctx,
            "verify_signed_bytes_hex": meta_signed_bytes(confusion_v2_as_v1_ctx).hex(),
            "signature_hex": v2_typed["signature_hex"],
            "verify_key_hex": sig_pub_of(admin_id),
            "must_fail": True,
            "note": "v2 で署名されたステートメント(var-v2-create-typed)をスキーマ欄を落として"
                    " v1 レイアウト(v1 ドメイン文字列)で再計算したバイト列では署名検証に失敗する"
                    "(layoutVersion の虚偽申告 v2 → v1 は署名不一致に退化 — 裁定 CR)",
        },
        {
            "name": "layout-confusion-v1-as-v2",
            "base": "var-create",
            "context": confusion_v1_as_v2_ctx,
            "verify_signed_bytes_hex": meta_signed_bytes(confusion_v1_as_v2_ctx).hex(),
            "signature_hex": var_create["signature_hex"],
            "verify_key_hex": sig_pub_of(admin_id),
            "must_fail": True,
            "note": "v1 で署名されたステートメント(var-create)に空のスキーマ欄を補って"
                    " v2 レイアウト(v2 ドメイン文字列)で再計算したバイト列では署名検証に失敗する"
                    "(layoutVersion の虚偽申告 v1 → v2 — 逆方向の混同も同様に退化する)",
        },
        v2_tamper_negative(
            "tampered-var-type", {"var_type": "string"},
            "var_type の書き換え(url → string)は元署名の検証に失敗する(スキーマ欄は署名対象 — §4.2)",
        ),
        v2_tamper_negative(
            "tampered-required", {"required": "false"},
            "required の書き換え(true → false)は元署名の検証に失敗する(presence 保証 §14.2-8 の"
            "前提 — required 宣言は署名済みの明示操作なしに変わらない)",
        ),
        v2_tamper_negative(
            "tampered-description", {"description": "Rewritten by the server"},
            "description の書き換えは元署名の検証に失敗する(description も byte-exact に署名対象 — §4.2)",
        ),
        v2_tamper_negative(
            "v2-suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/var-meta-sig-v2"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は v2 レイアウトでも"
            "検証に失敗する(レイアウト版はステートメント種ローカルで suite 束縛は不変 — §4.2)",
        ),
    ]

    # 検証規則系(kind = "authorization"): 署名は有効だが遷移・レイアウト規則で拒否
    def v2_rule_negative(name, ctx, expected_reason, note, predecessor):
        signed = meta_signed_bytes(ctx)
        return {
            "name": name,
            "kind": "authorization",
            "chain": "canonical",
            "context": ctx,
            "author_key_fingerprint_hex": fp_of(admin_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer_of(admin_id).sign(signed).hex(),
            "verify_key_hex": sig_pub_of(admin_id),
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
            "predecessor": predecessor,
        }

    v2_rule_negatives = [
        v2_rule_negative(
            "declared-after-active",
            make_v2_context("env-prod-0001", "var-v2-typed-0010", "SERVICE_URL", "declared",
                            "url", "true", "Primary service endpoint URL",
                            2, v2_typed["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12),
            "declared-after-active",
            "active な predecessor の後続を declared にする形は、署名・prev 連鎖が有効でも拒否する"
            "(§4.2 — active → declared 禁止: 値の存在の巻き戻し表現を作らない。値を取り除く"
            "唯一の経路は削除)",
            predecessor={
                "base": "var-v2-create-typed",
                "signed_bytes_sha256_hex": v2_typed["signed_bytes_sha256_hex"],
                "status": "active",
                "layout_version": 2,
            },
        ),
        v2_rule_negative(
            "declared-after-delete",
            make_v2_context("env-prod-0001", "var-v2-typed-0010", "SERVICE_URL", "declared",
                            "url", "true", "Primary service endpoint URL",
                            3, v2_delete["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12),
            "revived-after-delete",
            "deleted な predecessor の後続は declared でも拒否する(§4.2 — 「deleted 後の"
            "再 active 化禁止」は declared への遷移にも適用。tombstone は終端 — 既存理由コード"
            " revived-after-delete の適用範囲の固定)",
            predecessor={
                "base": "var-v2-delete-keeps-schema",
                "signed_bytes_sha256_hex": v2_delete["signed_bytes_sha256_hex"],
                "status": "deleted",
                "layout_version": 2,
            },
        ),
        v2_rule_negative(
            "layout-regression-rename",
            make_context("variable", "env-prod-0001", "var-v2-typed-0010", "SERVICE_URL_RENAMED",
                         "active", 2, v2_typed["signed_bytes_sha256_hex"], admin_id,
                         head_hash(12), 12),
            "layout-regression",
            "直前ステートメントが v2 の変数への v1 後続ステートメント(rename 形)は、署名・"
            "prev 連鎖が有効でも拒否する(§4.2 の変数単位のレイアウト単調性 — 後退を許すと"
            " rename 1 回でスキーマ欄が黙って消え、presence 保証 §14.2-8 と schema-locked"
            "〔AUTH_SPEC §12-11〕が迂回できる)",
            predecessor={
                "base": "var-v2-create-typed",
                "signed_bytes_sha256_hex": v2_typed["signed_bytes_sha256_hex"],
                "status": "active",
                "layout_version": 2,
            },
        ),
    ]

    # 構造違反系(kind = "invalid-input"): ワイヤ形の構造違反は署名検証にも履歴検証
    # にも到達させず、型付き InvalidInput で拒否する(fail-closed)。署名自体は本
    # negative の鍵で有効 — 拒否が暗号検証によるものでないことを verify_reference が
    # 確認する(kind = "authorization" と同じ運び方)
    def v2_invalid_input_negative(name, ctx, note):
        signed = meta_signed_bytes(ctx)
        return {
            "name": name,
            "kind": "invalid-input",
            "context": ctx,
            "author_key_fingerprint_hex": fp_of(admin_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer_of(admin_id).sign(signed).hex(),
            "verify_key_hex": sig_pub_of(admin_id),
            "expected_error": "InvalidInput",
            "must_fail": True,
            "note": note,
        }

    invalid_input_negatives = [
        v2_invalid_input_negative(
            "v1-declared-status",
            make_context("variable", "env-prod-0001", "var-rule-0006", "DECLARED_V1",
                         "declared", 1, "", admin_id, head_hash(12), 12),
            "v1 レイアウトに declared は存在しない(§4.2 / 裁定 CS — 「v1 は不変」という移行の"
            "核を守る)。status の語彙違反は構造違反として InvalidInput で拒否する — 署名は"
            "本バイト列に対して有効であり、拒否は暗号検証によるものではない",
        ),
        v2_invalid_input_negative(
            "v2-empty-required",
            make_v2_context("env-prod-0001", "var-rule-0007", "RULE_VAR_V2", "active",
                            "string", "", "Rule fixture", 1, "", admin_id, head_hash(12), 12),
            "v2 の required は \"true\" | \"false\" の明示必須で空文字列を許さない(§4.2 — "
            "省略時の既定値解釈をクライアント実装に分散させない fail-closed)。構造違反として"
            " InvalidInput で拒否する",
        ),
    ]

    # --- 3′ スコープの認可時点検査(2026-09-14 ES — §6.3): author の scope が当該環境を含む
    # こと。変数メタ・環境メタの両方が環境対象。role 検査(3)の直後
    devmember_id = "user-devmember-0010"
    vectors.append(
        make_statement(
            "listed-author-in-scope", "variable", "env-dev-0002", "var-dev-scoped-0006", "DEV_SCOPED",
            "active", 1, "", devmember_id, 19,
            "listed の author(head 19 時点 member listed{dev, stage})による scope 内の環境(env-dev-0002)"
            "の変数ステートメントは通る(3′ の許容側)",
        )
    )
    rule_negatives += [
        rule_negative(
            "author-environment-out-of-scope", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", devmember_id, head_hash(19), 19,
            "author-environment-out-of-scope-at-head",
            "head 19 時点の user-devmember-0010 は member listed{dev, stage}。scope 外の env-prod-0001 の"
            "変数ステートメントは role を満たしても宣言ヘッド時点の scope 検査(3′)で拒否する",
        ),
        rule_negative(
            "env-author-environment-out-of-scope", "environment", "env-prod-0001", None, "Production Renamed",
            "active", 1, "", devmember_id, head_hash(19), 19,
            "author-environment-out-of-scope-at-head",
            "環境メタステートメント(rename)も環境対象: scope 外の環境への署名は 3′ で拒否する",
        ),
        rule_negative(
            "author-role-precedes-scope", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", devmember_id, head_hash(24), 24,
            "author-role-insufficient-at-head",
            "head 24 時点の user-devmember-0010 は reader listed{dev}。role 不足 × scope 外の複合違反は"
            " role 検査(3)が scope 検査(3′)に先行する",
        ),
    ]

    # --- 端末軸(2026-09-20 DK — §6.3「端末鍵の選択と実効権限」。参照チェーンは派生チェーン
    # device-ops。既存の正例・負例と `canonical` の意味は不変 — 規約 28)
    dk_chain = chain["extended_chains"]["device-ops"]["entries"]

    def dk_head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"] if seq <= len(entries) else dk_chain[seq - 25]["entry_hash_hex"]

    def device_key(label: str) -> dict:
        return chain["keys"][label]

    def device_signer(label: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(device_key(label)["sig_sk_seed_hex"]))

    cibox = device_key("user-allmember-0013@ci-box")
    readercap = device_key("user-owner-0015@reader-cap")
    allmember_id = "user-allmember-0013"
    owner3_id = "user-owner-0015"
    vectors.append(
        make_statement(
            "second-device-author-in-scope", "variable", "env-dev-0002", "var-ci-scoped-0007", "CI_SCOPED",
            "active", 1, "", allmember_id, 28,
            "第 2 端末の正例: allmember-0013 の CI 箱 C(cap (member, listed{dev, stage}))による実効 scope 内の"
            "環境(env-dev-0002)の変数ステートメントは通る",
            key=cibox, chain_ref="device-ops", head_hash_hex=dk_head_hash(28),
        )
    )
    rule_negatives += [
        rule_negative(
            "author-device-revoked-at-head", "variable", "env-dev-0002", "var-ci-scoped-0007", "CI_SCOPED",
            "active", 1, "", allmember_id, dk_head_hash(37), 37,
            "author-key-mismatch-at-head",
            "seq 37 で失効した端末 C が失効後のヘッド(37)を宣言したステートメントは author-key-mismatch-at-head",
            chain_ref="device-ops", author_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
        rule_negative(
            "author-device-role-insufficient", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", owner3_id, dk_head_hash(29), 29,
            "author-role-insufficient-at-head",
            "owner-0015 の cap (reader, all) の端末 L の実効 role は reader。変数ステートメント(member 以上)は拒否する",
            chain_ref="device-ops", author_fp=readercap["key_fingerprint_hex"],
            sign_with=device_signer("user-owner-0015@reader-cap"), verify_key_hex=readercap["sig_pub_hex"],
        ),
        rule_negative(
            "author-device-environment-out-of-scope", "variable", "env-prod-0001", "var-rule-0004", "RULE_VAR",
            "active", 1, "", allmember_id, dk_head_hash(28), 28,
            "author-environment-out-of-scope-at-head",
            "CI 箱 C の実効 scope {dev, stage} 外の env-prod-0001 のステートメントは、人の scope が all でも拒否する",
            chain_ref="device-ops", author_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
        rule_negative(
            "env-author-device-environment-out-of-scope", "environment", "env-prod-0001", None, "Production Renamed",
            "active", 1, "", allmember_id, dk_head_hash(28), 28,
            "author-environment-out-of-scope-at-head",
            "環境メタステートメント(rename)も端末の実効 scope で判定する",
            chain_ref="device-ops", author_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
    ]

    write(
        "metadata-signature.json",
        {
            "description": "CRYPTO_SPEC §4.2: 変数・環境メタデータの署名付きステートメント(Ed25519)。var_meta_signed_bytes = LP(\"<suite>/var-meta-sig\", project_id, environment_id, variable_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)、env_meta_signed_bytes = LP(\"<suite>/env-meta-sig\", project_id, environment_id, name, status, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)。チェーン・鍵は chain-entries.json の正規 12 エントリチェーンを参照",
            "var_signed_fields_order": VAR_META_SIG_FIELDS_ORDER,
            "env_signed_fields_order": ENV_META_SIG_FIELDS_ORDER,
            "var_v2_signed_fields_order": VAR_META_SIG_V2_FIELDS_ORDER,
            "binary_encoding": "ハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(meta_version / chain_head_seq)は 10 進文字列化。name は UTF-8 バイト列を byte-exact に束縛(NFC 正規化は署名前のクライアントの責務 — §4.2)",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、author 鍵 = keys。正規チェーンは 24 エントリ(2026-09-14 ES + PF1 — 正例の意味は不変、負例に author-environment-out-of-scope-at-head を追加)",
            "no_epoch_anchor": "メタステートメントはエポックアンカーを持たない(§4.2)。値署名の epoch-not-current-at-head / environment-not-created-at-head に相当する検証規則は存在せず、前進 meta_version への注入は v1 未検出の既知残余(§14.3-5)。var-meta-head-before-env-create が positive であることがこの非対称の固定",
            "layout_v2": "CRYPTO_SPEC §4.2 レイアウト v2(0.8-draft — セッション 46 裁定 CR / CS): 変数メタステートメントの第 2 レイアウト。var_meta_signed_bytes_v2 = LP(\"<suite>/var-meta-sig-v2\", project_id, environment_id, variable_id, name, status, var_type, required, description, meta_version, prev_meta_sig_hash_hex, author_user_id, chain_head_hash_hex, chain_head_seq)。context の layout_version(省略 = 1)がワイヤの layoutVersion に対応し、どのレイアウトで signed_bytes を再計算するかを選択する。検証者は署名検証より前にサポート範囲を検査し、超過は型付きエラー(未対応レイアウト)で拒否する(署名不正に潰さない誠実な破壊様式 — 本件は拒否ケースに参照期待値が存在しないため規約 21 の分担どおりハーネス側で固定)。status は 3 値(active | deleted | declared — declared は v2 限定)、var_type は閉集合(\"\" | string | number | boolean | url)、required は明示必須(\"true\" | \"false\")。環境メタステートメントは v1 のまま(本改訂の対象外)。既存 v1 ベクターは 1 バイトも不変(追記で拡張 — §11)",
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
            "negative": negatives + rule_negatives + layout_negatives + v2_rule_negatives
            + invalid_input_negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.8b env-manifest.json — §4.3 環境マニフェスト(Ed25519 + §2.1 LP)
#
# env_manifest_signed_bytes = LP("<suite>/env-manifest-sig", project_id,
#                                environment_id, epoch, manifest_version,
#                                variables_digest_hex,
#                                env_meta_version, env_meta_sig_hash_hex,
#                                prev_manifest_sig_hash_hex,
#                                issuer_user_id, chain_head_hash_hex, chain_head_seq)
# variables_digest_hex = lower_hex(SHA-256(LP("<suite>/env-manifest-vars",
#                                             entry_1, …, entry_n)))
# entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)
#   (variable_id のバイト昇順。tombstone 込みの全ステートメントの最新形。空集合可。
#    各 entry は入れ子 LP のバイト列として 1 フィールドで埋め込む —
#    scope_environments と同じ規約)
#
# チェーン状態を要する検証規則系は chain-entries.json の正規 12 エントリチェーンを
# 参照して構成する(value-signature / metadata-signature と同じ cross-file の先例)。
# 発行契機と epoch 焼き込み(§4.3): 複合発行(環境作成・rotate)の宣言ヘッドは
# 追記前の現ヘッドで、エポック整合は「宣言ヘッド時点の現エポックと一致、または
# 宣言ヘッドの**次の**エントリ(= 同梱チェーンエントリ)が当該環境にちょうど
# そのエポックを確立する」(AUTH_SPEC §12-5 (4) の「同梱エントリ適用後の状態」の
# 検証側の形)。manifest-v1-create / manifest-rotate がこの形を positive で固定する。

ENV_MANIFEST_SIG_FIELDS_ORDER = [
    "domain", "project_id", "environment_id", "epoch", "manifest_version",
    "variables_digest_hex", "env_meta_version", "env_meta_sig_hash_hex",
    "prev_manifest_sig_hash_hex", "issuer_user_id",
    "chain_head_hash_hex", "chain_head_seq",
]

ENV_MANIFEST_VARS_DOMAIN = "maruhi/v1/env-manifest-vars"


def manifest_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([ctx[key] for key in ENV_MANIFEST_SIG_FIELDS_ORDER])


def variables_digest_input(entries: list, sort: bool = True) -> bytes:
    """LP("<suite>/env-manifest-vars", entry_1, …, entry_n)(正規形は昇順)。"""
    ordered = (
        sorted(entries, key=lambda e: e["variable_id"].encode("utf-8")) if sort else entries
    )
    fields: list = [ENV_MANIFEST_VARS_DOMAIN]
    for entry in ordered:
        fields.append(lp_encode([
            entry["variable_id"], entry["status"],
            entry["meta_version"], entry["meta_sig_hash_hex"],
        ]))
    return lp_encode(fields)


def variables_digest_hex(entries: list, sort: bool = True) -> str:
    return sha256(variables_digest_input(entries, sort)).hex()


def gen_env_manifest():
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
    env_id = "env-prod-0001"

    # --- フィクスチャのメタステートメント(metadata-signature.json と同一入力・
    # 同一ハッシュ。ダイジェストが要するのは (variable_id, status, meta_version,
    # meta_sig_hash_hex) のタプルのみ — §4.3)---
    def meta_hash(kind, environment_id, variable_id, name, status, meta_version,
                  prev_hash_hex, author_id, head_seq):
        ctx = {
            "kind": kind,
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
            "chain_head_hash_hex": head_hash(head_seq),
            "chain_head_seq": head_seq,
        })
        return ctx, sha256(meta_signed_bytes(ctx)).hex()

    env_meta_ctx, env_meta_v1_hash = meta_hash(
        "environment", env_id, None, "Production", "active", 1, "", member_id, 2)
    api_v1_ctx, api_v1_hash = meta_hash(
        "variable", env_id, "var-api-key-0001", "API_KEY", "active", 1, "", admin_id, 12)
    api_v2_ctx, api_v2_hash = meta_hash(
        "variable", env_id, "var-api-key-0001", "API_KEY_ROTATED", "active", 2,
        api_v1_hash, admin_id, 12)
    api_v3_ctx, api_v3_hash = meta_hash(
        "variable", env_id, "var-api-key-0001", "API_KEY_ROTATED", "deleted", 3,
        api_v2_hash, admin_id, 12)
    legacy_ctx, legacy_hash = meta_hash(
        "variable", env_id, "var-legacy-0002", "LEGACY_TOKEN", "active", 1, "", member_id, 4)
    # env-dev-0002 の環境メタ(作成複合の同梱 — 宣言ヘッドは追記前の現ヘッド seq 7。
    # listed の issuer の scope 内マニフェスト(3′ の許容側)の env_meta 束縛先)
    dev_env_meta_ctx, dev_env_meta_v1_hash = meta_hash(
        "environment", "env-dev-0002", None, "Development", "active", 1, "", admin_id, 7)

    def digest_entry(variable_id, status, meta_version, meta_sig_hash_hex):
        return {
            "variable_id": variable_id,
            "status": status,
            "meta_version": meta_version,
            "meta_sig_hash_hex": meta_sig_hash_hex,
        }

    api_v1_entry = digest_entry("var-api-key-0001", "active", 1, api_v1_hash)
    api_v2_entry = digest_entry("var-api-key-0001", "active", 2, api_v2_hash)
    api_v3_entry = digest_entry("var-api-key-0001", "deleted", 3, api_v3_hash)
    legacy_entry = digest_entry("var-legacy-0002", "active", 1, legacy_hash)

    # レイアウト v2 の declared ステートメント(metadata-signature.json の
    # var-v2-declared-create と同一入力・同一ハッシュ — §4.2 レイアウト v2)。
    # entry・ダイジェストのエンコーダは不変で、status に "declared" が新しい文字列値
    # として現れるだけ(§4.3 のスキーマ欄の被覆 — マニフェスト層の変更なしの自動継承)
    declared_v2_ctx = {
        "kind": "variable",
        "domain": f"{suite}/var-meta-sig-v2",
        "layout_version": 2,
        "project_id": project_id,
        "environment_id": env_id,
        "variable_id": "var-v2-declared-0012",
        "name": "STRIPE_API_KEY",
        "status": "declared",
        "var_type": "string",
        "required": "true",
        "description": "Stripe secret key (set before first deploy)",
        "meta_version": 1,
        "prev_meta_sig_hash_hex": "",
        "author_user_id": admin_id,
        "chain_head_hash_hex": head_hash(12),
        "chain_head_seq": 12,
    }
    declared_v2_hash = sha256(meta_signed_bytes(declared_v2_ctx)).hex()
    declared_v2_entry = digest_entry("var-v2-declared-0012", "declared", 1, declared_v2_hash)

    def make_context(environment_id, epoch, manifest_version, digest_hex,
                     env_meta_version, env_meta_hash, prev_hash_hex, issuer_id,
                     head_hash_hex, head_seq):
        return {
            "suite": suite,
            "domain": f"{suite}/env-manifest-sig",
            "project_id": project_id,
            "environment_id": environment_id,
            "epoch": epoch,
            "manifest_version": manifest_version,
            "variables_digest_hex": digest_hex,
            "env_meta_version": env_meta_version,
            "env_meta_sig_hash_hex": env_meta_hash,
            "prev_manifest_sig_hash_hex": prev_hash_hex,
            "issuer_user_id": issuer_id,
            "chain_head_hash_hex": head_hash_hex,
            "chain_head_seq": head_seq,
        }

    def make_manifest(name, environment_id, epoch, manifest_version, digest_entries,
                      env_meta_version, env_meta_hash, prev_hash_hex, issuer_id,
                      head_seq, note, prev_base=None, key=None, chain_ref=None,
                      head_hash_hex=None):
        # key / chain_ref / head_hash_hex(2026-09-20 DK): 端末鍵で署名する正例の鍵記録と参照チェーン
        digest_hex = variables_digest_hex(digest_entries)
        ctx = make_context(environment_id, epoch, manifest_version, digest_hex,
                           env_meta_version, env_meta_hash, prev_hash_hex, issuer_id,
                           head_hash_hex if head_hash_hex is not None else head_hash(head_seq),
                           head_seq)
        signed = manifest_signed_bytes(ctx)
        signer = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["sig_sk_seed_hex"]))
                  if key is not None else signer_of(issuer_id))
        vector = {
            "name": name,
            "context": ctx,
            "issuer_key_fingerprint_hex": key["key_fingerprint_hex"] if key is not None else fp_of(issuer_id),
            # ダイジェストの原像(正規形 = variable_id のバイト昇順)。検証側は
            # これを再ダイジェストして context の variables_digest_hex と照合する
            "entries": sorted(digest_entries, key=lambda e: e["variable_id"].encode("utf-8")),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "note": note,
        }
        if prev_base is not None:
            vector["prev_base"] = prev_base
        if chain_ref is not None:
            vector["chain"] = chain_ref
        return vector

    # --- 正例(session-27 §13-2): 発行契機ごとの manifest_version 連鎖。
    # mv1(環境作成)→ mv2(rotate)→ mv3(削除済み issuer の在籍中座標)→
    # mv4(変数作成)→ mv5(rename)→ mv6(削除 = tombstone 込みダイジェスト)---
    mv1 = make_manifest(
        "manifest-v1-create", env_id, 1, 1, [], 1, env_meta_v1_hash, "", member_id, 2,
        "環境作成複合の同梱マニフェスト(manifestVersion 1、変数空集合、epoch 1)。"
        "宣言ヘッドは追記前の現ヘッド(seq 2 = create_environment エントリの prev — AUTH_SPEC §12-4)。"
        "宣言ヘッド時点に環境は未存在で、検証は境界 checkpoint タプル(chain-entries.json の "
        "checkpoint-boundary-create 派生チェーン seq 4)との完全一致による(§4.3 (2) — "
        "2026-08-27 セッション 33 で旧 H+1 例外を廃止。checkpoint を欠く正規チェーンに対する"
        "同データは negative composite-head-without-checkpoint-create)",
    )
    mv2 = make_manifest(
        "manifest-rotate", env_id, 2, 2, [], 1, env_meta_v1_hash,
        mv1["signed_bytes_sha256_hex"], member_id, 3,
        "rotate 複合の同梱マニフェスト(エポック前進の反映 — メタ集合は不変でも再発行する。§4.3)。"
        "検証は境界 checkpoint タプル(checkpoint-boundary-rotate 派生チェーン seq 6)との"
        "完全一致による(§4.3 (2)。checkpoint を欠く正規チェーンに対する同データは "
        "negative composite-head-without-checkpoint-rotate)",
        prev_base="manifest-v1-create",
    )
    mv3 = make_manifest(
        "manifest-removed-issuer", env_id, 2, 3, [legacy_entry], 1, env_meta_v1_hash,
        mv2["signed_bytes_sha256_hex"], member_id, 4,
        "seq 5 で削除済みの issuer による在籍区間内(head 4)の過去マニフェスト"
        "(変数 var-legacy-0002 の作成に伴う発行)。削除後も当時の鍵・当時の現エポック"
        "(head 4 時点 = 2)で検証できる(§6.3-1 の対応物)",
        prev_base="manifest-rotate",
    )
    mv4 = make_manifest(
        "manifest-var-create", env_id, 2, 4, [api_v1_entry, legacy_entry], 1, env_meta_v1_hash,
        mv3["signed_bytes_sha256_hex"], admin_id, 12,
        "変数作成(var-api-key-0001)後のマニフェスト。ダイジェストは 2 変数を "
        "variable_id のバイト昇順で列挙する",
        prev_base="manifest-removed-issuer",
    )
    mv5 = make_manifest(
        "manifest-var-rename", env_id, 2, 5, [api_v2_entry, legacy_entry], 1, env_meta_v1_hash,
        mv4["signed_bytes_sha256_hex"], admin_id, 12,
        "rename(metaVersion 2)後のマニフェスト。prev = manifest-var-create の signed_bytes の "
        "SHA-256(§4.3 の連鎖)",
        prev_base="manifest-var-create",
    )
    mv6 = make_manifest(
        "manifest-var-delete", env_id, 2, 6, [api_v3_entry, legacy_entry], 1, env_meta_v1_hash,
        mv5["signed_bytes_sha256_hex"], admin_id, 12,
        "削除後のマニフェスト。ダイジェストは tombstone(status deleted、metaVersion 3)を"
        "含む(§4.3 — tombstone 隠しは digest-tombstone-omitted が negative で固定)",
        prev_base="manifest-var-rename",
    )
    vectors = [mv1, mv2, mv3, mv4, mv5, mv6]

    # --- fork(§14.2-5): 同一 (environment, manifestVersion, prev) に対する内容の
    # 異なる 2 つの有効マニフェスト。単体ではどちらも全検証を通り、組になって
    # 初めて equivocation の暗号学的証拠になる(signed_bytes_sha256 の相違)---
    fork_branches = [
        make_manifest(
            "manifest-fork-a", env_id, 2, 5, [api_v2_entry, legacy_entry], 1, env_meta_v1_hash,
            mv4["signed_bytes_sha256_hex"], admin_id, 12,
            "manifestVersion 5 の分岐 A(admin が署名。rename 適用後の集合)",
            prev_base="manifest-var-create",
        ),
        make_manifest(
            "manifest-fork-b", env_id, 2, 5, [legacy_entry], 1, env_meta_v1_hash,
            mv4["signed_bytes_sha256_hex"], owner_id, 12,
            "manifestVersion 5 の分岐 B(owner が署名。var-api-key-0001 を落とした集合)。"
            "A と同一座標・同一 prev でダイジェストが異なる",
            prev_base="manifest-var-create",
        ),
    ]

    # --- ダイジェストの LP 正規形の固定(空集合・単一・複数・バイト昇順)---
    order_entries = [
        digest_entry("alpha-var-0001", "active", 1, sha256(b"digest-fixture-alpha").hex()),
        digest_entry("Zeta-var-0002", "active", 2, sha256(b"digest-fixture-zeta").hex()),
    ]
    # サロゲートペア境界の判別対(session-31 M1-T2)。tombstone を 1 本混ぜ、
    # 非 ASCII の variable_id でも status / meta_version が正規形に載ることを兼ねる
    surrogate_entries = [
        digest_entry("var-\U0001F511-0001", "active", 2,
                     sha256(b"digest-fixture-astral-key").hex()),
        digest_entry("var-￥-0001", "deleted", 3, sha256(b"digest-fixture-bmp-yen").hex()),
        digest_entry("var-㊙-0001", "active", 1, sha256(b"digest-fixture-bmp-maruhi").hex()),
        digest_entry("var-z-0001", "active", 1, sha256(b"digest-fixture-ascii-z").hex()),
    ]
    digest_cases = [
        {
            "name": "empty-set",
            "entries": [],
            "digest_input_hex": variables_digest_input([]).hex(),
            "variables_digest_hex": variables_digest_hex([]),
            "note": "変数ゼロの環境では要素 0 の LP(空集合も有効なダイジェストを持つ — §4.3)",
        },
        {
            "name": "single-entry",
            "entries": [api_v1_entry],
            "digest_input_hex": variables_digest_input([api_v1_entry]).hex(),
            "variables_digest_hex": variables_digest_hex([api_v1_entry]),
            "note": "entry = LP(variable_id, status, meta_version, meta_sig_hash_hex) を"
                    "入れ子 LP の 1 フィールドとして埋め込む",
        },
        {
            "name": "tombstone-entry",
            "entries": [api_v3_entry, legacy_entry],
            "digest_input_hex": variables_digest_input([api_v3_entry, legacy_entry]).hex(),
            "variables_digest_hex": variables_digest_hex([api_v3_entry, legacy_entry]),
            "note": "tombstone(status deleted)も全ステートメントの最新形として列挙に含む",
        },
        {
            "name": "byte-ascending-order",
            "entries": sorted(order_entries, key=lambda e: e["variable_id"].encode("utf-8")),
            "digest_input_hex": variables_digest_input(order_entries).hex(),
            "variables_digest_hex": variables_digest_hex(order_entries),
            "note": "順序は variable_id の**バイト**昇順(UTF-8): 'Zeta-var-0002'(Z = 0x5a)が "
                    "'alpha-var-0001'(a = 0x61)より先に来る(ロケール・大文字小文字非依存の固定)",
        },
        {
            # サロゲートペア境界(session-31 M1-T2 — 2026-08-28): 既存ケースは
            # ASCII / BMP 止まりで、UTF-16 コード単位比較(JS の素の文字列比較)と
            # UTF-8 バイト比較が食い違う対(BMP 高位 U+E000〜U+FFFF × astral)を
            # 固定していなかった。U+FFE5(EF BF A5)< U+1F511(F0 9F 94 91)が
            # バイト昇順、UTF-16 ではサロゲート 0xD83D < 0xFFE5 で逆転する
            "name": "surrogate-boundary-order",
            "entries": sorted(surrogate_entries, key=lambda e: e["variable_id"].encode("utf-8")),
            "digest_input_hex": variables_digest_input(surrogate_entries).hex(),
            "variables_digest_hex": variables_digest_hex(surrogate_entries),
            "note": "サロゲートペア境界の byte-ascending(session-31 M1-T2): 正規順は "
                    "var-z-0001(0x7A)< var-㊙-0001(0xE3…)< var-￥-0001(U+FFE5 = "
                    "0xEF BF A5)< var-🔑-0001(U+1F511 = 0xF0 9F 94 91)。UTF-16 コード"
                    "単位順(JS の素の文字列比較)はサロゲート(0xD83D)< U+FFE5 のため"
                    "最後の 2 要素が逆転する — UTF-8 バイト順の実装だけがこのダイジェストに到達する",
        },
        {
            # レイアウト v2 の declared entry(§4.2 / §11 の 0.8-draft 項 — 2026-08-30)
            "name": "declared-entry",
            "entries": sorted([legacy_entry, declared_v2_entry],
                              key=lambda e: e["variable_id"].encode("utf-8")),
            "digest_input_hex": variables_digest_input([legacy_entry, declared_v2_entry]).hex(),
            "variables_digest_hex": variables_digest_hex([legacy_entry, declared_v2_entry]),
            "note": "status = declared(§4.2 レイアウト v2)の entry も全ステートメントの最新形"
                    "として列挙に含む。entry・ダイジェストのエンコーダは不変で、status に新しい"
                    "文字列値が現れるだけ(§4.3 のスキーマ欄の被覆 — meta_sig_hash は v2 の"
                    " signed_bytes〔metadata-signature.json の var-v2-declared-create〕から計算される)",
        },
    ]

    # --- tenure 跨ぎ検査用の派生チェーン(value / metadata と同一内容。
    # chain-entries.json 本体は変更しない)---
    rejoined = make_user(pat(0x74, 32), pat(0x84, 32))
    readd_payload = {
        "target_user_id": member_id,
        "enc_pub_hex": rejoined["enc_pub_hex"],
        "sig_pub_hex": rejoined["sig_pub_hex"],
        "role": "member",
        **scope_fields("all", []),
    }
    head_seq = len(entries)  # 正規チェーンのヘッド(2026-09-14 ES + PF1 で 24)
    readd_seq = head_seq + 1
    owner_fp = chain["keys"][owner_id]["key_fingerprint_hex"]
    readd_pb = lp_encode([readd_payload[k] for k in PAYLOAD_FIELD_ORDER["add_member"]])
    readd_ts = 1754006400000 + 1000 * head_seq
    readd_signed = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts]
    )
    readd_sig = signer_of(owner_id).sign(readd_signed)
    readd_entry_bytes = lp_encode(
        [suite, readd_seq, head_hash(head_seq), "add_member", owner_id, owner_fp, readd_pb, readd_ts,
         readd_sig.hex()]
    )
    tenure_extension = {
        "note": "key-from-other-tenure 用の派生チェーン(value-signature.json / "
                "metadata-signature.json と同一内容): 正規チェーン(24 エントリ)の後に seq 25 で "
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
            "seq": readd_seq,
            "suite": suite,
            "prev_hash_hex": head_hash(head_seq),
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
    # 差し替え、Ed25519 検証が失敗することを固定する(metadata-signature と同じ形)---
    base_sig = bytes.fromhex(mv4["signature_hex"])
    tampered_sig = bytearray(base_sig)
    tampered_sig[-1] ^= 0x01

    def make_negative(name, overrides, note, base_vector=None, verify_key_hex=None,
                      signature=None):
        source = base_vector if base_vector is not None else mv4
        ctx = dict(source["context"], **overrides)
        return {
            "name": name,
            "base": source["name"],
            "context": ctx,
            "verify_signed_bytes_hex": manifest_signed_bytes(ctx).hex(),
            "signature_hex": (signature.hex() if signature is not None
                              else source["signature_hex"]),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None
            else sig_pub_of(admin_id),
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
            "tampered-digest", {"variables_digest_hex": variables_digest_hex([])},
            "variables_digest_hex の差し替え(集合の改竄)は元署名の検証に失敗する"
            "(ダイジェストは署名対象 — §4.3)",
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
            "transplant-issuer", {"issuer_user_id": owner_id},
            "issuer_user_id の差し替えは同一鍵でも検証に失敗する(帰属の付け替え対策 — "
            "§4.3 の issuer 焼き込み)",
        ),
        make_negative(
            "wrong-issuer-key", {},
            "issuer 以外の鍵では検証に失敗する(FP 付け替えによる別鍵検証の遮断)",
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
            "suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/env-manifest-sig"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
    ]

    # --- negative(検証規則系。kind = "authorization"): 署名は有効だが、検証済み
    # チェーン履歴・検証済みステートメント集合・直前マニフェストに対する §4.3 / §6.3 の
    # 検証規則で拒否されるべきもの。expected_reason は実装の理由コードを固定する。
    # verify_entries / verify_env_meta は「検証側が再計算に使う集合・環境メタ」が
    # 署名された内容と食い違う形(欠落・注入・tombstone 隠し)の表現 ---
    ghost = make_user(pat(0x78, 32), pat(0x88, 32))
    ghost_signer = Ed25519PrivateKey.from_private_bytes(pat(0x88, 32))

    def rule_negative(name, environment_id, epoch, manifest_version, digest_entries,
                      env_meta_version, env_meta_hash, prev_hash_hex, issuer_id,
                      head_hash_hex, head_seq, expected_reason, note,
                      chain_ref="canonical", issuer_fp=None, sign_with=None,
                      verify_key_hex=None, predecessor=None, verify_entries=None,
                      verify_env_meta=None, digest_sort=True):
        digest_hex = variables_digest_hex(digest_entries, sort=digest_sort)
        ctx = make_context(environment_id, epoch, manifest_version, digest_hex,
                           env_meta_version, env_meta_hash, prev_hash_hex, issuer_id,
                           head_hash_hex, head_seq)
        signed = manifest_signed_bytes(ctx)
        signer = sign_with if sign_with is not None else signer_of(issuer_id)
        case = {
            "name": name,
            "kind": "authorization",
            "chain": chain_ref,
            "context": ctx,
            "issuer_key_fingerprint_hex": issuer_fp if issuer_fp is not None else fp_of(issuer_id),
            "entries": (digest_entries if digest_sort
                        else sorted(digest_entries,
                                    key=lambda e: e["variable_id"].encode("utf-8"))),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None
            else sig_pub_of(issuer_id),
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
        }
        if predecessor is not None:
            case["predecessor"] = predecessor
        if verify_entries is not None:
            case["verify_entries"] = verify_entries
        if verify_env_meta is not None:
            case["verify_env_meta"] = verify_env_meta
        return case

    def predecessor_of(vector):
        return {
            "base": vector["name"],
            "signed_bytes_sha256_hex": vector["signed_bytes_sha256_hex"],
            "epoch": vector["context"]["epoch"],
        }

    rule_negatives = [
        rule_negative(
            "head-not-in-chain", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, sha256(b"not-in-chain").hex(), 12,
            "chain-head-mismatch",
            "seq 12 は自ビューに実在するがハッシュが一致しない = チェーン分岐(equivocation)"
            "または偽造の硬い証拠として即時拒否(§6.3-2a)",
        ),
        rule_negative(
            "head-beyond-local-seq", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, sha256(b"future-head").hex(), len(entries) + 1,
            "chain-head-future",
            "seq 25 は自ビューのヘッド(24)より先 = 自チェーンが古いだけの可能性。まず再同期し、"
            "延長として一致すれば受理・しなければ分岐の証拠(§6.3-2b)",
        ),
        rule_negative(
            "issuer-removed-at-head", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], member_id, head_hash(12), 12,
            "issuer-not-member-at-head",
            "seq 5 で削除済みの issuer が削除後のヘッド(12)を宣言する形は拒否する"
            "(削除済みメンバーの鍵による新規マニフェストの遮断 — §6.3-3)",
        ),
        rule_negative(
            "issuer-role-insufficient", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, head_hash(6), 6,
            "issuer-role-insufficient-at-head",
            "head 6 時点の user-admin-0003 は reader(change_role は seq 7)。マニフェストの"
            "発行契機はすべて member 以上のメタ操作 — reader 署名は拒否する(§4.3)",
        ),
        rule_negative(
            "key-from-other-tenure", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], member_id,
            tenure_extension["entry"]["entry_hash_hex"], readd_seq,
            "issuer-key-mismatch-at-head",
            "remove → 別鍵 re-add(派生チェーン seq 25)の user_id で、旧在籍区間の鍵 × 新区間の"
            "ヘッド(25)の組合せは拒否する(§6.3-1 のヘッド時点鍵束縛)",
            chain_ref="tenure-extension",
        ),
        rule_negative(
            "issuer-unknown-in-history", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], "user-ghost-0042", head_hash(12), 12,
            "issuer-unknown",
            "チェーン履歴のどの時点にも存在しない issuer_user_id / 鍵 FP の組は検証鍵を選択"
            "できず拒否する(署名自体は本 negative の鍵で有効)",
            issuer_fp=ghost["fp_hex"], sign_with=ghost_signer,
            verify_key_hex=ghost["sig_pub_hex"],
        ),
        rule_negative(
            "environment-not-created-at-head", "env-stage-0003", 1, 1, [], 1,
            sha256(b"stage-env-meta-placeholder").hex(), "", owner_id, head_hash(2), 2,
            "environment-not-created-at-head",
            "env-stage-0003 の create_environment は seq 11。宣言ヘッド(seq 2)時点に環境は"
            "未存在で、次エントリ(seq 3)も当該環境のエポックを確立しない — 既定値への"
            "フォールバック実装を禁止する(値署名の §6.3-4 後段と同型)",
        ),
        rule_negative(
            "epoch-not-current-at-head", env_id, 1, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "epoch-not-current-at-head",
            "head 12 時点の env-prod-0001 の現エポックは 2(rotate は seq 4)。旧エポック 1 を"
            "焼き込んだマニフェストは、宣言ヘッド時点のエポック整合で拒否する(§4.3 の核 — "
            "write 資格を失った鍵は現エポックのマニフェストを署名できない)",
        ),
        rule_negative(
            "epoch-regression", env_id, 1, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], member_id, head_hash(3), 3,
            "epoch-regressed",
            "rotate(seq 4 → epoch 2)後に、在籍区間内の旧ヘッド(seq 3 — 当時の現エポック 1)を"
            "宣言して旧エポックを焼き込んだ前進 manifest_version(4)。宣言ヘッド時点の"
            "エポック整合は通るが、検証済みの直前マニフェスト(epoch 2)からのエポック後退として"
            "拒否する(§4.1 単調性のマニフェスト版 — 本設計の核となる negative)",
            predecessor=predecessor_of(mv3),
        ),
        rule_negative(
            "v1-nonempty-prev", env_id, 1, 1, [], 1, env_meta_v1_hash,
            sha256(b"phantom-manifest-predecessor").hex(), member_id, head_hash(2), 2,
            "prev-shape-mismatch",
            "manifestVersion 1 の prev_manifest_sig_hash_hex は空文字列でなければならない(§4.3)。"
            "predecessor を保持しない latest-only 検証でも形は必ず検査する",
        ),
        rule_negative(
            "v2-empty-prev", env_id, 2, 4, [], 1, env_meta_v1_hash,
            "", admin_id, head_hash(12), 12,
            "prev-shape-mismatch",
            "manifestVersion > 1 の prev_manifest_sig_hash_hex は 64 文字 hex でなければならない(§4.3)",
        ),
        rule_negative(
            "prev-hash-mismatch", env_id, 2, 4, [], 1, env_meta_v1_hash,
            sha256(b"wrong-manifest-predecessor").hex(), admin_id, head_hash(12), 12,
            "prev-hash-mismatch",
            "既知の直前 manifestVersion(manifest-removed-issuer)の signed_bytes ハッシュと "
            "prev が一致しない連鎖不整合(§6.3-6)。署名は有効 — Ed25519 failure に潰さない",
            predecessor=predecessor_of(mv3),
        ),
        rule_negative(
            "digest-variable-omitted", env_id, 2, 4, [api_v1_entry, legacy_entry], 1,
            env_meta_v1_hash, mv3["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "variables-digest-mismatch",
            "マニフェストは 2 変数のダイジェストを署名しているが、配布から "
            "var-api-key-0001 のステートメントを落とした集合での再計算は一致しない"
            "(ステートメントの欠落の検出 — §4.3 (3))",
            verify_entries=[legacy_entry],
        ),
        rule_negative(
            "digest-tombstone-omitted", env_id, 2, 6, [api_v3_entry, legacy_entry], 1,
            env_meta_v1_hash, mv5["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "variables-digest-mismatch",
            "tombstone(var-api-key-0001 の deleted ステートメント)を配布から隠した集合での"
            "再計算は一致しない(削除の隠蔽 = 無断復活の入口の検出 — §4.3 (3))",
            verify_entries=[legacy_entry],
        ),
        rule_negative(
            "digest-order-swap", env_id, 2, 4,
            [legacy_entry, api_v1_entry], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "variables-digest-mismatch",
            "昇順違反(降順)で計算されたダイジェストを署名したマニフェストは、正規形"
            "(バイト昇順)での再計算と一致しない(順序はダイジェストの正規形の一部 — §4.3)",
            digest_sort=False,
        ),
        rule_negative(
            "env-meta-mismatch", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], admin_id, head_hash(12), 12,
            "env-meta-mismatch",
            "マニフェストの (env_meta_version, env_meta_sig_hash_hex) が検証済みの環境メタ"
            "ステートメントと一致しない(環境メタの差し替え・古い環境メタへの固定の検出 — "
            "AUTH_SPEC §12-5 (7) の再計算対象)",
            verify_env_meta={
                "meta_version": 2,
                "meta_sig_hash_hex": sha256(b"other-env-meta").hex(),
            },
        ),
    ]

    # --- チェックポイント束縛(§4.3 (2) の改訂 — 2026-08-27 セッション 33 = PR-F3b。
    # 旧 H+1 例外の廃止)の negative。束縛の照合先(境界 checkpoint タプルを含む
    # 派生チェーン)は chain-entries.json の checkpoint-boundary-* を参照する
    # (gen_checkpoint_boundary_chains が本関数の後に追記する)---
    rule_negatives += [
        rule_negative(
            "composite-head-without-checkpoint-create", env_id, 1, 1, [], 1,
            env_meta_v1_hash, "", member_id, head_hash(2), 2,
            "environment-not-created-at-head",
            "manifest-v1-create と同一データを checkpoint タプルを持たない正規チェーンに"
            "対して検証すると strict(宣言ヘッド時点)に落ち、宣言ヘッド(seq 2)時点で"
            "環境未存在として拒否する — 旧 H+1 例外(宣言ヘッドの次エントリでエポックが"
            "成立する複合形の無条件許容)の廃止の固定(§4.3 (2))",
        ),
        rule_negative(
            "composite-head-without-checkpoint-rotate", env_id, 2, 2, [], 1,
            env_meta_v1_hash, mv1["signed_bytes_sha256_hex"], member_id, head_hash(3), 3,
            "epoch-not-current-at-head",
            "manifest-rotate と同一データを checkpoint タプルを持たない正規チェーンに"
            "対して検証すると strict に落ち、宣言ヘッド(seq 3)時点の現エポック(1)との"
            "不一致で拒否する(旧 H+1 例外の廃止の rotate 側)",
        ),
        rule_negative(
            "checkpoint-binding-mismatch", env_id, 1, 1, [], 1,
            env_meta_v1_hash, "", owner_id, head_hash(2), 2,
            "checkpoint-binding-mismatch",
            "検証済みチェーン上に (env-prod-0001, manifestVersion 1) の checkpoint タプルが"
            "存在する場合、マニフェストの signed_bytes ハッシュはタプルと完全一致しなければ"
            "ならない(strict は代替経路にならない — 選言禁止)。owner が署名した同座標の"
            "別内容マニフェスト(issuer が異なるためハッシュが異なる)は、署名・ヘッド・"
            "エポックが有効でも拒否する。latest checkpoint(manifestVersion 2)より古い版への"
            "照合でも束縛が先に判定される(検査順序: 束縛 (2) → 非後退 (4))",
            chain_ref="checkpoint-boundary-rotate",
        ),
        rule_negative(
            "checkpoint-equivocation", env_id, 2, 2, [], 1,
            env_meta_v1_hash, mv1["signed_bytes_sha256_hex"], member_id, head_hash(3), 3,
            "checkpoint-equivocation",
            "同一 (environment_id, manifest_version) に (epoch, manifest_sig_hash) の異なる"
            "checkpoint タプルが検証済みチェーン上に併存する場合は、マニフェスト "
            "equivocation の硬い証拠として当該環境の配布を拒否する(§4.3 (2)。"
            "manifest-rotate 自体は正当でも、チェーンが矛盾タプルを運んだ時点で拒否)",
            chain_ref="checkpoint-boundary-equivocation",
        ),
        rule_negative(
            "checkpoint-regressed", env_id, 1, 1, [], 1,
            env_meta_v1_hash, "", member_id, head_hash(2), 2,
            "checkpoint-regressed",
            "チェックポイント整合の規則 1(§6.3 / §4.3 (4)): 配布マニフェストの "
            "manifestVersion は当該環境の最新 checkpoint(checkpoint-boundary-rotate では "
            "manifestVersion 2)以上でなければならない。タプル(manifestVersion 1)との"
            "完全一致を通る正当な旧マニフェストでも、基準より古い版の配布は巻き戻しとして"
            "拒否する(境界チェックポイントが供給する下限 — タプルを持つ版への照合の"
            "下方回避を塞ぐ)",
            chain_ref="checkpoint-boundary-rotate",
        ),
    ]

    # --- 3′ スコープの認可時点検査(2026-09-14 ES — §6.3): issuer の scope が当該環境を含む
    # こと。role 検査(3)の直後・prev / エポック整合の前
    devmember_id = "user-devmember-0010"
    vectors.append(
        make_manifest(
            "manifest-listed-issuer-in-scope", "env-dev-0002", 2, 1, [], 1, dev_env_meta_v1_hash, "",
            devmember_id, 19,
            "listed の issuer(head 19 時点 member listed{dev, stage})による scope 内の環境(env-dev-0002 —"
            "エポック 2・manifestVersion 1・変数空集合)のマニフェストは通る(3′ の許容側。env-dev の"
            " checkpoint タプルは正規チェーンに無いため strict 経路)",
        )
    )
    rule_negatives += [
        rule_negative(
            "issuer-environment-out-of-scope", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], devmember_id, head_hash(19), 19,
            "issuer-environment-out-of-scope-at-head",
            "head 19 時点の user-devmember-0010 は member listed{dev, stage}。scope 外の env-prod-0001 の"
            "マニフェストは role を満たしても宣言ヘッド時点の scope 検査(3′)で拒否する",
        ),
        rule_negative(
            "issuer-role-precedes-scope", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], devmember_id, head_hash(24), 24,
            "issuer-role-insufficient-at-head",
            "head 24 時点の user-devmember-0010 は reader listed{dev}。role 不足 × scope 外の複合違反は"
            " role 検査(3)が scope 検査(3′)に先行する",
        ),
        rule_negative(
            "issuer-scope-precedes-prev", env_id, 2, 4, [], 1, env_meta_v1_hash,
            "", devmember_id, head_hash(19), 19,
            "issuer-environment-out-of-scope-at-head",
            "scope 外 × prev の形違反(manifestVersion 4 で prev 空)の複合違反は scope 検査(3′)が"
            " prev 連鎖(§4.3 (1))に先行する",
        ),
    ]

    # --- 端末軸(2026-09-20 DK — §6.3「端末鍵の選択と実効権限」。参照チェーンは派生チェーン
    # device-ops。既存の正例・負例と `canonical` の意味は不変 — 規約 28)
    dk_chain = chain["extended_chains"]["device-ops"]["entries"]

    def dk_head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"] if seq <= len(entries) else dk_chain[seq - 25]["entry_hash_hex"]

    def device_key(label: str) -> dict:
        return chain["keys"][label]

    def device_signer(label: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(device_key(label)["sig_sk_seed_hex"]))

    cibox = device_key("user-allmember-0013@ci-box")
    readercap = device_key("user-owner-0015@reader-cap")
    allmember_id = "user-allmember-0013"
    owner3_id = "user-owner-0015"
    vectors.append(
        make_manifest(
            "manifest-second-device-issuer-in-scope", "env-dev-0002", 2, 1, [], 1, dev_env_meta_v1_hash, "",
            allmember_id, 28,
            "第 2 端末の正例: allmember-0013 の CI 箱 C(cap (member, listed{dev, stage}))による実効 scope 内の"
            "環境(env-dev-0002 — エポック 2・manifestVersion 1・変数空集合)のマニフェストは通る(strict 経路)",
            key=cibox, chain_ref="device-ops", head_hash_hex=dk_head_hash(28),
        )
    )
    rule_negatives += [
        rule_negative(
            "issuer-device-revoked-at-head", "env-dev-0002", 2, 1, [], 1, dev_env_meta_v1_hash,
            "", allmember_id, dk_head_hash(37), 37,
            "issuer-key-mismatch-at-head",
            "seq 37 で失効した端末 C が失効後のヘッド(37)を宣言したマニフェストは issuer-key-mismatch-at-head",
            chain_ref="device-ops", issuer_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
        rule_negative(
            "issuer-device-role-insufficient", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], owner3_id, dk_head_hash(29), 29,
            "issuer-role-insufficient-at-head",
            "owner-0015 の cap (reader, all) の端末 L の実効 role は reader。マニフェストの発行(member 以上)は拒否する",
            chain_ref="device-ops", issuer_fp=readercap["key_fingerprint_hex"],
            sign_with=device_signer("user-owner-0015@reader-cap"), verify_key_hex=readercap["sig_pub_hex"],
        ),
        rule_negative(
            "issuer-device-environment-out-of-scope", env_id, 2, 4, [], 1, env_meta_v1_hash,
            mv3["signed_bytes_sha256_hex"], allmember_id, dk_head_hash(28), 28,
            "issuer-environment-out-of-scope-at-head",
            "CI 箱 C の実効 scope {dev, stage} 外の env-prod-0001 のマニフェストは、人の scope が all でも拒否する",
            chain_ref="device-ops", issuer_fp=cibox["key_fingerprint_hex"],
            sign_with=device_signer("user-allmember-0013@ci-box"), verify_key_hex=cibox["sig_pub_hex"],
        ),
    ]

    write(
        "env-manifest.json",
        {
            "description": "CRYPTO_SPEC §4.3: 環境マニフェスト(Ed25519)。env_manifest_signed_bytes = LP(\"<suite>/env-manifest-sig\", project_id, environment_id, epoch, manifest_version, variables_digest_hex, env_meta_version, env_meta_sig_hash_hex, prev_manifest_sig_hash_hex, issuer_user_id, chain_head_hash_hex, chain_head_seq)、variables_digest_hex = lower_hex(SHA-256(LP(\"<suite>/env-manifest-vars\", entry_1, …, entry_n)))、entry_i = LP(variable_id, status, meta_version, meta_sig_hash_hex)(variable_id のバイト昇順。tombstone 込み。空集合可)。チェーン・鍵は chain-entries.json の正規 12 エントリチェーンを参照",
            "manifest_signed_fields_order": ENV_MANIFEST_SIG_FIELDS_ORDER,
            "digest_entry_fields_order": [
                "variable_id", "status", "meta_version", "meta_sig_hash_hex",
            ],
            "binary_encoding": "ハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(epoch / manifest_version / env_meta_version / meta_version / chain_head_seq)は 10 進文字列化。ダイジェストの各 entry は入れ子 LP のバイト列を 1 フィールドとして埋め込む(scope_environments と同じ規約)",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、issuer 鍵 = keys。正規チェーンは 24 エントリ(2026-09-14 ES + PF1 — 正例の意味は不変、負例に issuer-environment-out-of-scope-at-head を追加)",
            "composite_epoch_rule": "エポック整合(§4.3 (2) — 2026-08-27 セッション 33 = PR-F3b でチェックポイント束縛へ改訂。旧 H+1 例外は廃止): 検証済みチェーン上に当該 (environment_id, manifest_version) の checkpoint タプルが存在する場合、その (epoch, manifest_sig_hash) と完全一致しなければならない(strict は代替経路にならない — checkpoint-binding-mismatch が negative)。同座標に (epoch, manifest_sig_hash) の異なるタプルが併存すれば equivocation の硬い証拠として拒否(checkpoint-equivocation)。タプルが存在しない場合のみ宣言ヘッド時点の現エポックとの strict 一致(epoch-not-current-at-head / environment-not-created-at-head が negative。複合発行形の manifest-v1-create / manifest-rotate は chain-entries.json の checkpoint-boundary-* 派生チェーンに対する positive で、checkpoint を欠くチェーンに対しては composite-head-without-checkpoint-* の negative)。さらにチェックポイント整合の規則 1(§6.3): manifestVersion・epoch は当該環境の最新 checkpoint 以上(checkpoint-regressed が negative)",
            "statements": {
                "note": "ダイジェスト入力のフィクスチャ(metadata-signature.json と同一入力・同一ハッシュのステートメント)。ダイジェストが要するのは (variable_id, status, meta_version, meta_sig_hash_hex) のみ(§4.3)",
                "env_meta_v1": {"context": env_meta_ctx, "signed_bytes_sha256_hex": env_meta_v1_hash},
                "api_key_v1": {"context": api_v1_ctx, "signed_bytes_sha256_hex": api_v1_hash},
                "api_key_v2_rename": {"context": api_v2_ctx, "signed_bytes_sha256_hex": api_v2_hash},
                "api_key_v3_delete": {"context": api_v3_ctx, "signed_bytes_sha256_hex": api_v3_hash},
                "legacy_v1": {"context": legacy_ctx, "signed_bytes_sha256_hex": legacy_hash},
                "dev_env_meta_v1": {"context": dev_env_meta_ctx, "signed_bytes_sha256_hex": dev_env_meta_v1_hash},
            },
            "extra_keys": {
                "ghost": {
                    "note": "issuer-unknown-in-history 用(チェーン履歴に存在しない鍵)",
                    "enc_sk_seed_hex": pat(0x78, 32).hex(),
                    "sig_sk_seed_hex": pat(0x88, 32).hex(),
                    "enc_pub_hex": ghost["enc_pub_hex"],
                    "sig_pub_hex": ghost["sig_pub_hex"],
                    "key_fingerprint_hex": ghost["fp_hex"],
                },
            },
            "tenure_extension": tenure_extension,
            "digests": digest_cases,
            "vectors": vectors,
            "manifest_fork": {
                "note": "同一座標(env-prod-0001 × manifestVersion 5)に対する内容の異なる 2 つの"
                        "有効マニフェスト。各 branch は単体で §4.3 / §6.3 の全検証を通り(両方 "
                        "verify 成功)、組として signed_bytes_sha256_hex の相違 = サーバー "
                        "equivocation の否認不能な証拠になる(§14.2-5。防止ではなく証拠化)",
                "branches": fork_branches,
            },
            "negative": negatives + rule_negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.8.5 chain-entries.json への境界チェックポイント派生チェーンの追記
# (2026-08-27 セッション 33 = PR-F3b — CRYPTO_SPEC §4.3 (2) / §6.3 / AUTH_SPEC §12-4)
#
# 環境作成・rotate 複合の必須同梱(境界 checkpoint = 複合エントリの直後 seq)を、
# 実マニフェストのハッシュ(env-manifest.json の manifest-v1-create /
# manifest-rotate)と結線した派生チェーンとして固定する。マニフェストのハッシュを
# 要するため gen_env_manifest の**後**に実行し、chain-entries.json をロードして
# extended_chains へ**追記のみ**行う(既存セクションは 1 バイトも変えない)。
# env-manifest.json の checkpoint-binding-mismatch / checkpoint-equivocation /
# checkpoint-regressed / positive の複合 2 例がこれらのチェーンを参照する。


def gen_checkpoint_boundary_chains():
    chain_path = os.path.join(OUT_DIR, "chain-entries.json")
    with open(chain_path, encoding="utf-8") as fh:
        chain = json.load(fh)
    with open(os.path.join(OUT_DIR, "env-manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    manifest_by_name = {v["name"]: v for v in manifest["vectors"]}
    mv1_hash = manifest_by_name["manifest-v1-create"]["signed_bytes_sha256_hex"]
    mv2_hash = manifest_by_name["manifest-rotate"]["signed_bytes_sha256_hex"]

    owner_id = "user-owner-0001"
    member_id = "user-member-0002"
    member = make_user(pat(0x30, 32), pat(0x40, 32))
    env_id = "env-prod-0001"
    t0 = 1754006400000
    head3 = chain["entries"][2]["entry_hash_hex"]
    empty_values = env_values_digest_hex([])
    # rotate 境界分の values_digest も空集合: この派生チェーンの世界では env-prod に
    # 値が push されていない = 受理時点の現在値の列挙は空(AUTH_SPEC §12-4 の
    # 「受理時点の現在値から構成」と整合する正直な値)
    rotate_payload = {
        "environment_id": env_id,
        "new_epoch": "2",
        "reason": "scheduled",
        "dek_commitment_hex": chain["environment_deks"][env_id]["2"]["dek_commitment_hex"],
    }

    cb4 = build_chain_entry(
        4, "checkpoint", member_id, member,
        checkpoint_payload([
            checkpoint_env_entry_tuple(env_id, 1, 1, mv1_hash, empty_values),
        ]),
        t0 + 3000, head3,
    )
    cb5 = build_chain_entry(
        5, "rotate_epoch", member_id, member, rotate_payload, t0 + 4000,
        cb4["entry_hash_hex"],
    )
    cb6 = build_chain_entry(
        6, "checkpoint", member_id, member,
        checkpoint_payload([
            checkpoint_env_entry_tuple(env_id, 2, 2, mv2_hash, empty_values),
        ]),
        t0 + 5000, cb5["entry_hash_hex"],
    )
    # 同座標 (env-prod-0001, manifestVersion 2) を別ハッシュで公証する 2 本目の
    # checkpoint。チェーン合意規則では有効(非後退は等号を許し、タプル内容は
    # チェーン検証で検証不能)だが、マニフェスト検証(§4.3 (2))はこの併存を
    # equivocation の硬い証拠として拒否する
    cb7 = build_chain_entry(
        7, "checkpoint", member_id, member,
        checkpoint_payload([
            checkpoint_env_entry_tuple(
                env_id, 2, 2,
                sha256(b"maruhi-vector-forged-manifest:env-prod-0001:2").hex(),
                empty_values,
            ),
        ]),
        t0 + 6000, cb6["entry_hash_hex"],
    )

    def expected_checkpoint(seq: int, entry: dict) -> dict:
        tuple_ = entry["payload"]["environments"][0]
        return {
            "seq": seq,
            "epoch": tuple_["epoch"],
            "manifest_version": tuple_["manifest_version"],
            "manifest_sig_hash_hex": tuple_["manifest_sig_hash_hex"],
            "values_digest_hex": tuple_["values_digest_hex"],
        }

    members = {owner_id: member_state("owner", "all"), member_id: member_state("member", "all")}
    chain["extended_chains"]["checkpoint-boundary-create"] = {
        "description": (
            "環境作成複合の境界 checkpoint(AUTH_SPEC §12-4: create = H+1、checkpoint = "
            "H+2。ここでは正規チェーン seq 3 の create_environment の直後 seq 4 に、"
            "manifest-v1-create の実ハッシュを束縛する checkpoint を置く)。"
            "manifest-v1-create の positive(§4.3 (2) のチェックポイント束縛経路)の"
            "照合先チェーン"
        ),
        "base_seq": 3,
        "entries": [cb4],
        "expected_members": members,
        "expected_checkpoints": {env_id: expected_checkpoint(4, cb4)},
    }
    chain["extended_chains"]["checkpoint-boundary-rotate"] = {
        "description": (
            "rotate 複合の境界 checkpoint まで進めた派生チェーン(seq 4 = 作成境界分、"
            "seq 5 = rotate_epoch(epoch 2)、seq 6 = manifest-rotate の実ハッシュを束縛"
            "する境界 checkpoint)。manifest-rotate の positive と、checkpoint-binding-"
            "mismatch / checkpoint-regressed(env-manifest.json)の照合先チェーン"
        ),
        "base_seq": 3,
        "entries": [cb4, cb5, cb6],
        "expected_members": members,
        "expected_checkpoints": {env_id: expected_checkpoint(6, cb6)},
    }
    chain["extended_chains"]["checkpoint-boundary-equivocation"] = {
        "description": (
            "checkpoint-boundary-rotate の先へ、同座標 (env-prod-0001, manifestVersion 2) "
            "を**別ハッシュ**で公証する checkpoint(seq 7)を追記した派生チェーン。追記"
            "自体は合意規則で有効(非後退の等号 + タプル内容はチェーン検証で検証不能)で、"
            "マニフェスト検証(§4.3 (2))が checkpoint-equivocation として拒否する材料に"
            "なる(env-manifest.json の同名 negative の照合先)"
        ),
        "base_seq": 3,
        "entries": [cb4, cb5, cb6, cb7],
        "expected_members": members,
        "expected_checkpoints": {env_id: expected_checkpoint(7, cb7)},
    }
    write("chain-entries.json", chain)


# ---------------------------------------------------------------------------
# 3.9 invite-accept-signature.json — §6.5 受諾の共同署名(Ed25519 + §2.1 LP。
#     2026-09-13 IV 改訂で v2 として**再生成** — 旧 token_hash 束縛の形は残さない)
#
# signed_bytes = LP(domain, project_id, link_pub_hex,
#                   invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)
#   domain = "<suite>/invite-accept-v2"(suite の束縛はドメイン文字列 — §5.1 と同型。
#   旧 "<suite>/invite-accept" は invite_token_hash_hex を束縛した — 版上げで構造的に拒否)
#   link_pub_hex = リンク鍵(招待ごとの Ed25519 鍵ペア — 招待者クライアントが種 k から
#   導出。種はリンクのフラグメントにのみ載り、サーバーは受け取らない)の公開鍵
#   同一バイト列に 2 つの署名: accept_signature(受諾者のチェーン sig 鍵 — 検証鍵は
#   署名対象内の invitee_sig_pub_hex)と link_signature(リンク鍵 — 検証鍵は署名対象内の
#   link_pub_hex)。どちらも自己束縛(検証鍵を署名対象外から与える形は作らない)

INVITE_ACCEPT_FIELDS_ORDER = [
    "domain", "project_id", "link_pub_hex",
    "invitee_user_id", "invitee_enc_pub_hex", "invitee_sig_pub_hex",
]

# リンク鍵の種(決定論的ダミー。他ベクターの seed・DEK のパターン値と非重複 —
# 0xD4 / 0xD8 / 0xDC は chain-entries.json の環境 DEK が使うので避ける)
INVITE_LINK_SEED = pat(0xD0, 32)
OTHER_LINK_SEED = pat(0xE0, 32)


def make_link_key(seed: bytes):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"sk": sk, "seed_hex": seed.hex(), "pub_hex": pub.hex()}


def invite_accept_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([ctx[key] for key in INVITE_ACCEPT_FIELDS_ORDER])


def gen_invite_accept_signature():
    # 受諾者は未登録ユーザー = チェーン外の新規ダミー鍵(seed は他ベクターと非重複)。
    # 鍵すり替え・署名者不一致役は chain-entries.json の user-member-0002 と同一鍵
    invitee = make_user(pat(0xA4, 32), pat(0xB4, 32))
    other = make_user(pat(0x30, 32), pat(0x40, 32))  # = chain-entries user-member-0002
    link = make_link_key(INVITE_LINK_SEED)
    other_link = make_link_key(OTHER_LINK_SEED)  # 別招待のリンク鍵(移植・偽造の negative 用)

    base_ctx = {
        "suite": "maruhi/v1",
        "domain": "maruhi/v1/invite-accept-v2",
        "project_id": "proj-0001",
        "link_pub_hex": link["pub_hex"],
        "invitee_user_id": "user-invitee-0004",
        "invitee_enc_pub_hex": invitee["enc_pub_hex"],
        "invitee_sig_pub_hex": invitee["sig_pub_hex"],
    }
    base_signed = invite_accept_signed_bytes(base_ctx)
    base_sig = invitee["sig_sk"].sign(base_signed)
    base_link_sig = link["sk"].sign(base_signed)

    def flip_last_bit(sig: bytes) -> bytes:
        out = bytearray(sig)
        out[-1] ^= 0x01
        return bytes(out)

    def negative(name, overrides, note, signature=None, key_field="invitee_sig_pub_hex"):
        # overrides を適用した文脈で signed_bytes を再構築し、「元の署名」
        # (signature 指定時はその署名)を検証 → 失敗すべき。検証鍵は常に
        # 文脈内の宣言鍵(受諾署名 = invitee_sig_pub_hex / リンク署名 = link_pub_hex)
        ctx = dict(base_ctx, **overrides)
        return {
            "name": name,
            "base": "basic",
            "context": ctx,
            "verify_signed_bytes_hex": invite_accept_signed_bytes(ctx).hex(),
            "signature_hex": (signature if signature is not None else base_sig).hex(),
            "verify_key_hex": ctx[key_field],
            "must_fail": True,
            "note": note,
        }

    def link_negative(name, overrides, note, signature=None):
        return negative(
            name, overrides, note,
            signature=(signature if signature is not None else base_link_sig),
            key_field="link_pub_hex",
        )

    negatives = [
        negative(
            "tampered-signature",
            {},
            "署名バイト自体の末尾 1 bit 反転は検証に失敗する",
            signature=flip_last_bit(base_sig),
        ),
        negative(
            "transplant-link-pub",
            {"link_pub_hex": other_link["pub_hex"]},
            "別招待(別リンク公開鍵)への受諾署名の移植は検証に失敗する(単回使用の同一招待上の衝突顕在化 — §6.5 — を署名面で支える)",
        ),
        negative(
            "transplant-project",
            {"project_id": "proj-0002"},
            "別プロジェクトの招待への移植は検証に失敗する(project_id はサーバーが保存行から再構成する — AUTH_SPEC §15-2)",
        ),
        negative(
            "transplant-invitee",
            {"invitee_user_id": "user-member-0002"},
            "受諾者 user_id の差し替えは同一鍵でも検証に失敗する(呼び出し主体 = invitee_user_id の受理条件を署名側でも束縛する)",
        ),
        negative(
            "enc-key-mismatch",
            {"invitee_enc_pub_hex": other["enc_pub_hex"]},
            "enc 公開鍵のすり替えは検証に失敗する(鍵すり替えの署名面の遮断)",
        ),
        negative(
            "sig-key-mismatch",
            {"invitee_sig_pub_hex": other["sig_pub_hex"]},
            "sig 公開鍵のすり替えは検証に失敗する(検証鍵は署名対象内の宣言鍵 — すり替えた鍵では正規受諾者の署名は通らない)",
        ),
        negative(
            "wrong-signer-key",
            {},
            "invitee_sig_pub 以外の鍵で作った署名は検証に失敗する(署名者不一致)",
            signature=other["sig_sk"].sign(base_signed),
        ),
        negative(
            "suite-mismatch",
            {"suite": "maruhi/v2", "domain": "maruhi/v2/invite-accept-v2"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
        # 旧形式の**有効な**受諾(v1 ドメイン文字列で組んだバイト列への正規の署名)を
        # v2 の検証器に提示すると失敗する — 旧形式を構造的に拒否する固定
        # (AUTH_SPEC §12-10 (2))。verify_signed_bytes_hex は v1 バイト列で、
        # 署名はその上で有効(独立検証器は「有効な v1 署名であること」を確認し、
        # 実装側ハーネスは「v2 で組んだバイト列では落ちること」を確認する)
        negative(
            "legacy-domain",
            {"domain": "maruhi/v1/invite-accept"},
            "旧ドメイン文字列(v1 = token_hash 束縛の形)で作った有効な受諾署名は、v2 のドメイン文字列で組み直す検証器では検証に失敗する(旧形式は構造的に拒否 — AUTH_SPEC §12-10 (2))",
            signature=invitee["sig_sk"].sign(
                invite_accept_signed_bytes(dict(base_ctx, domain="maruhi/v1/invite-accept"))
            ),
        ),
    ]

    link_negatives = [
        link_negative(
            "link-tampered-signature",
            {},
            "リンク署名の末尾 1 bit 反転は検証に失敗する",
            signature=flip_last_bit(base_link_sig),
        ),
        link_negative(
            "link-wrong-link-key",
            {},
            "別のリンク鍵で作ったリンク署名は検証に失敗する(サーバーが自分のリンク鍵で受諾を偽造する形 — サーバーは正規のリンク秘密鍵を持たない)",
            signature=other_link["sk"].sign(base_signed),
        ),
        link_negative(
            "link-transplant-link-pub",
            {"link_pub_hex": other_link["pub_hex"]},
            "別招待への移植は、検証鍵が署名対象内の link_pub_hex なので検証に失敗する",
        ),
        link_negative(
            "link-enc-key-mismatch",
            {"invitee_enc_pub_hex": other["enc_pub_hex"]},
            "受諾者 enc 鍵のすり替えはリンク署名でも落ちる(鍵すり替えを暗号的に不可能にする本体)",
        ),
        link_negative(
            "link-sig-key-mismatch",
            {"invitee_sig_pub_hex": other["sig_pub_hex"]},
            "受諾者 sig 鍵のすり替えはリンク署名でも落ちる",
        ),
        link_negative(
            "link-transplant-invitee",
            {"invitee_user_id": "user-member-0002"},
            "受諾者 user_id の差し替えはリンク署名でも落ちる",
        ),
        link_negative(
            "link-transplant-project",
            {"project_id": "proj-0002"},
            "別プロジェクトへの移植はリンク署名でも落ちる",
        ),
        link_negative(
            "link-suite-mismatch",
            {"suite": "maruhi/v2", "domain": "maruhi/v2/invite-accept-v2"},
            "suite が異なればドメイン文字列が異なり、リンク署名も移植できない",
        ),
    ]

    write(
        "invite-accept-signature.json",
        {
            "description": "CRYPTO_SPEC §6.5(2026-09-13 IV 改訂 — v2): 受諾の共同署名(Ed25519)。signed_bytes = LP(\"<suite>/invite-accept-v2\", project_id, link_pub_hex, invitee_user_id, invitee_enc_pub_hex, invitee_sig_pub_hex)。同一バイト列に受諾署名(検証鍵 = 署名対象内の invitee_sig_pub_hex)とリンク署名(検証鍵 = 署名対象内の link_pub_hex)の 2 つを付ける。旧 v1(invite_token_hash_hex 束縛)のベクターは残さない",
            "signed_fields_order": INVITE_ACCEPT_FIELDS_ORDER,
            "binary_encoding": "リンク公開鍵・invitee の enc/sig 公開鍵は hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)",
            "invitee": {
                "user_id": "user-invitee-0004",
                "enc_seed_hex": pat(0xA4, 32).hex(),
                "sig_sk_seed_hex": pat(0xB4, 32).hex(),
                "enc_pub_hex": invitee["enc_pub_hex"],
                "sig_pub_hex": invitee["sig_pub_hex"],
                "key_fingerprint_hex": invitee["fp_hex"],
                "note": "未登録ユーザーの新規ダミー鍵(チェーン外)。受諾署名の署名者",
            },
            "other_signer": {
                "user_id": "user-member-0002",
                "enc_pub_hex": other["enc_pub_hex"],
                "sig_pub_hex": other["sig_pub_hex"],
                "note": "鍵すり替え・署名者不一致の negative 用(chain-entries.json の user-member-0002 と同一のダミー鍵)",
            },
            "link_key": {
                "seed_hex": link["seed_hex"],
                "pub_hex": link["pub_hex"],
                "note": "リンク鍵(招待ごとの Ed25519 鍵ペア)。種はリンクのフラグメントにのみ載る(invite-link.json の link_key と同一)。リンク署名の署名者",
            },
            "other_link_key": {
                "seed_hex": other_link["seed_hex"],
                "pub_hex": other_link["pub_hex"],
                "note": "別招待のリンク鍵(移植・サーバー偽造の negative 用)",
            },
            "vectors": [
                dict(
                    base_ctx,
                    name="basic",
                    signed_bytes_hex=base_signed.hex(),
                    signature_hex=base_sig.hex(),
                    link_signature_hex=base_link_sig.hex(),
                ),
            ],
            "negative": negatives,
            "link_negative": link_negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.9a invite-link.json — §6.5 リンク鍵の導出・発行署名・OpenSSH 符号化(IV)
#
# invite_issue_signed_bytes = LP("<suite>/invite-issue",
#                                invite_id, project_id, link_pub_hex,
#                                head_hash_hex, head_seq, role,
#                                inviter_user_id, inviter_enc_pub_hex, inviter_sig_pub_hex)
#   検証鍵は署名対象内の inviter_sig_pub_hex(自己束縛)。招待者・ヘッドは
#   chain-entries.json の正規チェーン(owner = user-owner-0001、seq 12)を参照する
#   (value-signature 等と同じ cross-file の先例)
# OpenSSH 公開鍵行(裏付け元 = GitHub の SSH 署名鍵一覧との相互運用):
#   "ssh-ed25519 " + base64(uint32-BE len ‖ "ssh-ed25519" ‖ uint32-BE len ‖ 32 バイト鍵)
#   (RFC 4253 §6.6 / RFC 8709)。SSH ワイヤ形式の長さプレフィックスは §2.1 の LP と
#   同じ uint32-BE(バイト列をそのまま載せる)

# 2026-09-14(CRYPTO_SPEC 0.11-draft §6.5 — ES): 発行文の末尾に付与予定の scope
# (scope_kind, scope_environments_lp_hex — §6.2 と同じ符号化)を追加。旧 10 フィールド
# 形式は互換経路を持たない(negative scope-dropped)
INVITE_ISSUE_FIELDS_ORDER = [
    "domain", "invite_id", "project_id", "link_pub_hex", "head_hash_hex", "head_seq", "role",
    "inviter_user_id", "inviter_enc_pub_hex", "inviter_sig_pub_hex",
    "scope_kind", "scope_environments_lp_hex",
]


def invite_issue_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([ctx[key] for key in INVITE_ISSUE_FIELDS_ORDER])


def openssh_ed25519_line(pub: bytes, comment: str | None = None) -> str:
    import base64 as _b64
    blob = lp_encode([b"ssh-ed25519", pub])
    line = "ssh-ed25519 " + _b64.b64encode(blob).decode("ascii")
    return line if comment is None else f"{line} {comment}"


def gen_invite_link():
    with open(os.path.join(OUT_DIR, "chain-entries.json"), encoding="utf-8") as fh:
        chain = json.load(fh)
    owner_keys = chain["keys"]["user-owner-0001"]
    inviter = make_user(bytes.fromhex(owner_keys["enc_sk_seed_hex"]), bytes.fromhex(owner_keys["sig_sk_seed_hex"]))
    assert inviter["sig_pub_hex"] == owner_keys["sig_pub_hex"]
    member = make_user(pat(0x30, 32), pat(0x40, 32))  # user-member-0002(鍵差し替え・署名者不一致役)
    head = chain["entries"][-1]
    link = make_link_key(INVITE_LINK_SEED)
    other_link = make_link_key(OTHER_LINK_SEED)
    invitee = make_user(pat(0xA4, 32), pat(0xB4, 32))  # invite-accept-signature.json の受諾者

    base_ctx = {
        "suite": "maruhi/v1",
        "domain": "maruhi/v1/invite-issue",
        "invite_id": "invite-0001",
        "project_id": "proj-0001",
        "link_pub_hex": link["pub_hex"],
        "head_hash_hex": head["entry_hash_hex"],
        "head_seq": head["seq"],
        "role": "member",
        "inviter_user_id": "user-owner-0001",
        "inviter_enc_pub_hex": inviter["enc_pub_hex"],
        "inviter_sig_pub_hex": inviter["sig_pub_hex"],
        **scope_fields("all", []),
    }
    base_signed = invite_issue_signed_bytes(base_ctx)
    base_sig = inviter["sig_sk"].sign(base_signed)
    tampered = bytearray(base_sig)
    tampered[-1] ^= 0x01
    listed_envs = ["env-dev-0002", "env-stage-0003"]
    listed_ctx = dict(base_ctx, invite_id="invite-0003", **scope_fields("listed", listed_envs))
    listed_signed = invite_issue_signed_bytes(listed_ctx)
    listed_sig = inviter["sig_sk"].sign(listed_signed)
    # 旧 10 フィールド形式(scope 無し)のバイト列に対する正規署名の検証 → 失敗
    dropped_signed = lp_encode([base_ctx[k] for k in INVITE_ISSUE_FIELDS_ORDER[:-2]])
    flat_signed = lp_encode(
        [listed_ctx[k] for k in INVITE_ISSUE_FIELDS_ORDER[:-1]]
        + ["".join(listed_envs).encode("utf-8").hex()]
    )

    def negative(name, overrides, note, signature=None):
        ctx = dict(base_ctx, **overrides)
        return {
            "name": name,
            "base": "basic",
            "context": ctx,
            "verify_signed_bytes_hex": invite_issue_signed_bytes(ctx).hex(),
            "signature_hex": (signature if signature is not None else base_sig).hex(),
            "verify_key_hex": ctx["inviter_sig_pub_hex"],
            "must_fail": True,
            "note": note,
        }

    negatives = [
        negative("tampered-signature", {}, "署名バイトの末尾 1 bit 反転は検証に失敗する", signature=bytes(tampered)),
        negative("transplant-invite-id", {"invite_id": "invite-0002"}, "別の招待 id への移植は検証に失敗する(サーバーが発行文を別行へ移植できない)"),
        negative("transplant-project", {"project_id": "proj-0002"}, "別プロジェクトへの移植は検証に失敗する"),
        negative("transplant-link-pub", {"link_pub_hex": other_link["pub_hex"]}, "別のリンク公開鍵への付け替えは検証に失敗する(行の link_pub のすり替え検出)"),
        negative("head-hash-swap", {"head_hash_hex": chain["entries"][-2]["entry_hash_hex"]}, "アンカーのヘッドハッシュ差し替えは検証に失敗する(リンク経路上の改竄検出 — §6.3 (a))"),
        negative("head-seq-mismatch", {"head_seq": head["seq"] - 1}, "ヘッド seq の差し替えは検証に失敗する(hash と seq の両方が署名対象)"),
        negative("role-relabel", {"role": "admin"}, "付与予定 role の差し替えは検証に失敗する(r は表示専用から署名対象へ格上げ)"),
        negative("inviter-enc-key-mismatch", {"inviter_enc_pub_hex": member["enc_pub_hex"]}, "招待者 enc 鍵の差し替えは検証に失敗する(FP は ie‖is から導出される)"),
        negative("inviter-sig-key-mismatch", {"inviter_sig_pub_hex": member["sig_pub_hex"]}, "招待者 sig 鍵の差し替えは検証に失敗する(検証鍵は署名対象内の宣言鍵 — ゴースト追加者は招待者名義の署名を作れない)"),
        negative("transplant-inviter", {"inviter_user_id": "user-member-0002"}, "招待者 user_id の付け替えは同一鍵でも検証に失敗する"),
        negative("wrong-signer-key", {}, "inviter_sig_pub 以外の鍵で作った署名は検証に失敗する(署名者不一致)", signature=member["sig_sk"].sign(base_signed)),
        negative("suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/invite-issue"}, "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する"),
        # 2026-09-14 ES: scope も発行署名が覆う(r と同じ地位 — 同意の範囲を発行時に固定する)
        negative("scope-kind-relabel", scope_fields("listed", ["env-dev-0002"]), "付与予定 scope の差し替え(all → listed{dev})は検証に失敗する(受諾者が読む「どの環境に入るか」の改竄検出)"),
        {
            "name": "scope-environments-relabel",
            "base": "listed-scope",
            "context": dict(listed_ctx, **scope_fields("listed", ["env-dev-0002", "env-prod-0001"])),
            "verify_signed_bytes_hex": invite_issue_signed_bytes(dict(listed_ctx, **scope_fields("listed", ["env-dev-0002", "env-prod-0001"]))).hex(),
            "signature_hex": listed_sig.hex(),
            "verify_key_hex": listed_ctx["inviter_sig_pub_hex"],
            "must_fail": True,
            "note": "listed の環境集合の差し替え({dev, stage} → {dev, prod})は検証に失敗する",
        },
        {
            "name": "scope-dropped",
            "kind": "encoding",
            "base": "basic",
            "context": base_ctx,
            "verify_signed_bytes_hex": dropped_signed.hex(),
            "signature_hex": base_sig.hex(),
            "verify_key_hex": base_ctx["inviter_sig_pub_hex"],
            "must_fail": True,
            "note": "scope を落とした旧 10 フィールド形式のバイト列では正規署名が検証に失敗する(ES 改訂前の実装は新リンクを受諾せず、新実装は旧リンクを受諾しない — 互換経路なし)",
        },
        {
            "name": "scope-flat-concat",
            "kind": "encoding",
            "base": "listed-scope",
            "context": listed_ctx,
            "verify_signed_bytes_hex": flat_signed.hex(),
            "signature_hex": listed_sig.hex(),
            "verify_key_hex": listed_ctx["inviter_sig_pub_hex"],
            "must_fail": True,
            "note": "scope の環境集合を入れ子 LP でなく素の連結で符号化したバイト列では検証に失敗する(§2.1 の曖昧性排除)",
        },
    ]

    invitee_pub = bytes.fromhex(invitee["sig_pub_hex"])
    inviter_pub = bytes.fromhex(inviter["sig_pub_hex"])
    import base64 as _b64
    good_blob_b64 = _b64.b64encode(lp_encode([b"ssh-ed25519", invitee_pub])).decode("ascii")
    rsa_like_blob = _b64.b64encode(lp_encode([b"ssh-rsa", pat(0x00, 3), pat(0x01, 64)])).decode("ascii")
    sk_blob = _b64.b64encode(lp_encode([b"sk-ssh-ed25519@openssh.com", invitee_pub, b"ssh:"])).decode("ascii")
    short_blob = _b64.b64encode(lp_encode([b"ssh-ed25519", invitee_pub[:31]])).decode("ascii")
    type_mismatch_blob = _b64.b64encode(lp_encode([b"ssh-rsa", invitee_pub])).decode("ascii")
    trailing_blob = _b64.b64encode(lp_encode([b"ssh-ed25519", invitee_pub]) + b"\x00").decode("ascii")

    openssh = {
        "note": "OpenSSH 公開鍵行の符号化と解析(GitHub の ssh_signing_keys 応答の key フィールドと同形)。解析は ssh-ed25519 のみ受理し、32 バイト鍵をバイト一致で返す",
        "encode": [
            {"name": "invitee-sig-key", "public_key_hex": invitee["sig_pub_hex"], "expected_line": openssh_ed25519_line(invitee_pub)},
            {"name": "inviter-sig-key", "public_key_hex": inviter["sig_pub_hex"], "expected_line": openssh_ed25519_line(inviter_pub)},
        ],
        "parse": [
            {"name": "bare-line", "line": openssh_ed25519_line(invitee_pub), "expected_public_key_hex": invitee["sig_pub_hex"]},
            {"name": "with-comment", "line": openssh_ed25519_line(invitee_pub, "maruhi 27b7f9a4"), "expected_public_key_hex": invitee["sig_pub_hex"]},
            {"name": "with-multiword-comment", "line": openssh_ed25519_line(invitee_pub, "bob laptop key"), "expected_public_key_hex": invitee["sig_pub_hex"]},
            {"name": "trailing-newline", "line": openssh_ed25519_line(invitee_pub) + "\n", "expected_public_key_hex": invitee["sig_pub_hex"]},
        ],
        "parse_negative": [
            {"name": "rsa-key", "line": "ssh-rsa " + rsa_like_blob, "note": "種別が ssh-ed25519 でない行は受理しない"},
            {"name": "security-key-ed25519", "line": "sk-ssh-ed25519@openssh.com " + sk_blob, "note": "FIDO の sk-ssh-ed25519 は別種別(鍵の後に application が続く)— 受理しない"},
            {"name": "uppercase-type", "line": "SSH-ED25519 " + good_blob_b64, "note": "種別文字列は大文字小文字を区別する"},
            {"name": "short-key", "line": "ssh-ed25519 " + short_blob, "note": "鍵長 31 バイトは拒否"},
            {"name": "blob-type-mismatch", "line": "ssh-ed25519 " + type_mismatch_blob, "note": "外側の種別と blob 内の種別文字列が食い違う行は拒否"},
            {"name": "trailing-bytes", "line": "ssh-ed25519 " + trailing_blob, "note": "blob の末尾に余分なバイトがある行は拒否"},
            {"name": "corrupt-base64", "line": "ssh-ed25519 " + good_blob_b64[:-2] + "!!", "note": "base64 として不正な行は拒否"},
            {"name": "missing-blob", "line": "ssh-ed25519", "note": "blob の無い行は拒否"},
            {"name": "empty-line", "line": "", "note": "空行は拒否"},
        ],
    }

    write(
        "invite-link.json",
        {
            "description": "CRYPTO_SPEC §6.5(2026-09-13 IV。2026-09-14 ES で発行文の末尾に scope を追加して再生成): リンク鍵の種からの導出、発行文と発行署名(Ed25519 + §2.1 LP)、OpenSSH 公開鍵行の符号化・解析。招待者・ヘッドは chain-entries.json の正規チェーン(user-owner-0001・seq 24)を参照する",
            "signed_fields_order": INVITE_ISSUE_FIELDS_ORDER,
            "binary_encoding": "リンク公開鍵・ヘッドハッシュ・招待者の enc/sig 公開鍵は hex 小文字文字列、head_seq は 10 進文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。scope_environments_lp_hex は environment_id リストの LP の hex 小文字(§6.2 の member_scope と同じ入れ子 LP — scope_kind = all なら空文字列)",
            "link_key": {
                "seed_hex": link["seed_hex"],
                "pub_hex": link["pub_hex"],
                "note": "種 k(32 バイト乱数)→ Ed25519 鍵ペア(RFC 8032 の seed としてそのまま用いる)。pub_hex は導出の期待値",
            },
            "other_link_key": {"seed_hex": other_link["seed_hex"], "pub_hex": other_link["pub_hex"]},
            "inviter": {
                "user_id": "user-owner-0001",
                "enc_pub_hex": inviter["enc_pub_hex"],
                "sig_pub_hex": inviter["sig_pub_hex"],
                "key_fingerprint_hex": inviter["fp_hex"],
                "note": "chain-entries.json の owner と同一鍵(seed は同ファイル参照)",
            },
            "issue": {
                "vectors": [
                    dict(base_ctx, name="basic", signed_bytes_hex=base_signed.hex(), signature_hex=base_sig.hex()),
                    dict(listed_ctx, name="listed-scope", signed_bytes_hex=listed_signed.hex(), signature_hex=listed_sig.hex(),
                         note="listed{dev, stage} を付与予定の発行文(2026-09-14 ES)。scope_environments_lp_hex は §6.2 と同じ入れ子 LP"),
                ],
                "negative": negatives,
            },
            "openssh": openssh,
        },
    )


# ---------------------------------------------------------------------------
# 3.9b head-attestation.json — §6.6 ヘッド申告(Ed25519 + §2.1 LP。PR-M4)
#
# head_attestation_signed_bytes = LP("<suite>/head-attestation",
#                                    project_id, attester_user_id,
#                                    chain_head_hash_hex, chain_head_seq)
#   - タイムスタンプ・ノンスは含めない(意味論は帰属であり鮮度証明ではない —
#     §6.6。申告の新旧は chain_head_seq が順序付ける)
#   - attester_user_id の焼き込みは §5.1 の signer_user_id と同じ帰属付け替え対策
#   - チェーン状態を要する検証規則系は chain-entries.json の正規 12 エントリ
#     チェーンを参照する(value-signature / metadata-signature と同じ先例)
#
# 正例は session-27 §13-3 の 3 種(基本 / reader の申告 / 削除済みメンバーの
# 在籍中ヘッドへの過去申告)。3 つ目は「§6.6 の署名・ヘッド時点検証は通るが、
# attester が現メンバーでないため配布・照合の対象にならない」意図の固定
# (サーバーは remove_member 受理時に申告行を削除し — §6.4 — クライアントは
# 現メンバーでない attester の申告を照合材料にしない — §6.6 (1))。

HEAD_ATTESTATION_FIELDS_ORDER = [
    "domain", "project_id", "attester_user_id", "chain_head_hash_hex", "chain_head_seq",
]


def head_attestation_signed_bytes(ctx: dict) -> bytes:
    return lp_encode([ctx[key] for key in HEAD_ATTESTATION_FIELDS_ORDER])


def gen_head_attestation():
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

    def make_context(attester_id, head_hash_hex, head_seq, ctx_suite=suite):
        return {
            "suite": ctx_suite,
            "domain": f"{ctx_suite}/head-attestation",
            "project_id": project_id,
            "attester_user_id": attester_id,
            "chain_head_hash_hex": head_hash_hex,
            "chain_head_seq": head_seq,
        }

    def make_attestation(name, attester_id, head_seq, note, key=None, chain_ref=None,
                         head_hash_hex=None):
        # key / chain_ref / head_hash_hex(2026-09-20 DK): 端末鍵で署名する正例の鍵記録と参照チェーン
        ctx = make_context(attester_id,
                           head_hash_hex if head_hash_hex is not None else head_hash(head_seq),
                           head_seq)
        signed = head_attestation_signed_bytes(ctx)
        signer = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key["sig_sk_seed_hex"]))
                  if key is not None else signer_of(attester_id))
        vector = {
            "name": name,
            "context": ctx,
            "attester_key_fingerprint_hex": key["key_fingerprint_hex"] if key is not None else fp_of(attester_id),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "note": note,
        }
        if chain_ref is not None:
            vector["chain"] = chain_ref
        return vector

    basic = make_attestation(
        "basic", owner_id, len(entries),
        "基本形: owner が現ヘッド(seq 24)を申告する。§6.6 の全検証(署名・ヘッド束縛・"
        "申告ヘッド時点の在籍)を通る",
    )
    vectors = [
        basic,
        make_attestation(
            "reader-attestation", admin_id, 6,
            "reader の申告: head 6 時点の user-admin-0003 は reader(change_role は seq 7)。"
            "申告は reader を含む全メンバーが提出できる(§6.3 ヘッドゴシップ / §6.6 — "
            "必要 role の下限は reader)",
        ),
        make_attestation(
            "removed-attester-in-tenure", member_id, 4,
            "seq 5 で削除済みの attester による在籍区間内(head 4)の過去申告。§6.6 の"
            "署名・ヘッド時点検証は通る(検証鍵は当時の鍵 — チェーンは鍵履歴を保持する)が、"
            "attester は現メンバーでないため配布対象外(サーバーは remove_member 受理時に"
            "申告行を削除 — §6.4)であり、配布されてもクライアントは照合材料にしない"
            "(§6.6 (1) — 現メンバー検査)。この二層の意図をベクターで固定する",
        ),
    ]

    # --- negative(署名系): 元署名を維持したまま signed_bytes を差し替え、
    # Ed25519 検証が失敗することを固定する(metadata-signature と同じ形)
    base_sig = bytes.fromhex(basic["signature_hex"])
    tampered_sig = bytearray(base_sig)
    tampered_sig[-1] ^= 0x01

    def make_negative(name, overrides, note, verify_key_hex=None, signature=None):
        ctx = dict(basic["context"], **overrides)
        return {
            "name": name,
            "base": "basic",
            "context": ctx,
            "verify_signed_bytes_hex": head_attestation_signed_bytes(ctx).hex(),
            "signature_hex": (signature.hex() if signature is not None
                              else basic["signature_hex"]),
            "verify_key_hex": verify_key_hex if verify_key_hex is not None
            else sig_pub_of(owner_id),
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
            "transplant-project", {"project_id": "proj-other-0002"},
            "別プロジェクトへの申告の移植は署名検証に失敗する(project_id の文脈束縛 — §6.6)",
        ),
        make_negative(
            "transplant-attester", {"attester_user_id": admin_id},
            "attester_user_id の差し替えは同一鍵でも検証に失敗する(帰属の付け替え対策 — "
            "§5.1 の signer_user_id と同型)",
        ),
        make_negative(
            "wrong-attester-key", {},
            "attester 以外の鍵では検証に失敗する(FP 付け替えによる別鍵検証の遮断)",
            verify_key_hex=sig_pub_of(admin_id),
        ),
        make_negative(
            "head-seq-mismatch", {"chain_head_seq": len(entries) - 1},
            "chain_head_seq の差し替え(hash は維持)は署名検証に失敗する(hash と seq の"
            "両方が署名対象 — §6.6)",
        ),
        make_negative(
            "suite-mismatch", {"suite": "maruhi/v2", "domain": "maruhi/v2/head-attestation"},
            "suite が異なればドメイン文字列が異なり、スイート間の署名移植は検証に失敗する",
        ),
    ]

    # --- negative(検証規則系。kind = "authorization"): 署名は有効だが、検証済み
    # チェーン履歴に対する §6.6 / §6.3-2 の検証規則で拒否されるべきもの。
    # expected_reason は実装の理由コードを固定する(value / meta と同じ運び方)
    def rule_negative(name, attester_id, head_hash_hex, head_seq, expected_reason, note,
                      chain_ref="canonical", attester_key=None):
        ctx = make_context(attester_id, head_hash_hex, head_seq)
        signed = head_attestation_signed_bytes(ctx)
        signer = (Ed25519PrivateKey.from_private_bytes(bytes.fromhex(attester_key["sig_sk_seed_hex"]))
                  if attester_key is not None else signer_of(attester_id))
        return {
            "name": name,
            "kind": "authorization",
            "chain": chain_ref,
            "context": ctx,
            "attester_key_fingerprint_hex": (attester_key["key_fingerprint_hex"] if attester_key is not None
                                             else fp_of(attester_id)),
            "signed_bytes_hex": signed.hex(),
            "signed_bytes_sha256_hex": sha256(signed).hex(),
            "signature_hex": signer.sign(signed).hex(),
            "verify_key_hex": (attester_key["sig_pub_hex"] if attester_key is not None
                               else sig_pub_of(attester_id)),
            "expected_reason": expected_reason,
            "must_fail": True,
            "note": note,
        }

    rule_negatives = [
        rule_negative(
            "head-not-in-chain", owner_id, sha256(b"not-in-chain-attestation").hex(), len(entries),
            "chain-head-mismatch",
            "seq 24 は自ビューに実在するがハッシュが一致しない = 分岐(equivocation)または"
            "偽造の硬い証拠(§6.3-2a / §6.6 の照合 (a) — 当該同期の成果物の使用を中断し、"
            "証拠を保存する)",
        ),
        rule_negative(
            "head-beyond-local-seq", owner_id, sha256(b"future-attestation-head").hex(), len(entries) + 1,
            "chain-head-future",
            "seq 25 は自ビューのヘッド(24)より先 = 自分のチェーンが古いだけの可能性"
            "(§6.3-2b / §6.6 の照合 (b))。まず有界再同期し、延長として一致すれば正常・"
            "解決しなければ (a) と同じ扱い。この理由での即時証拠化は誤り",
        ),
        rule_negative(
            "attester-removed-at-head", member_id, head_hash(len(entries)), len(entries),
            "attester-not-member-at-head",
            "seq 5 で削除済みの attester が削除後のヘッド(24)を申告する形は拒否する"
            "(§6.6 (1) の申告ヘッド時点在籍 — removed-attester-in-tenure との対比で"
            "在籍区間の境界を固定する)",
        ),
    ]


    # --- 端末軸(2026-09-20 DK — §6.6「端末鍵」: attester の鍵 = 署名した端末。申告ヘッド時点で
    # 有効だった鍵は端末の有効区間で判定する。参照チェーンは派生チェーン device-ops — 規約 28)
    dk_chain = chain["extended_chains"]["device-ops"]["entries"]

    def dk_head_hash(seq: int) -> str:
        return entries[seq - 1]["entry_hash_hex"] if seq <= len(entries) else dk_chain[seq - 25]["entry_hash_hex"]

    def device_key(label: str) -> dict:
        return chain["keys"][label]

    def device_signer(label: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(device_key(label)["sig_sk_seed_hex"]))

    phone = device_key("user-owner-0001@phone")            # P: (owner, listed{}) — seq 26〜34 有効
    readercap = device_key("user-owner-0015@reader-cap")   # L: 実効 (reader, all)
    owner3_id = "user-owner-0015"
    vectors += [
        make_attestation(
            "phone-attestation", owner_id, 33,
            "第 2 端末の正例: owner-0001 の電話 P(cap (owner, listed{}) — DEK を受け取らない票だけの端末)が"
            "有効区間内のヘッド(33)を申告する。申告は端末ごと(AUTH_SPEC §16-1)",
            key=phone, chain_ref="device-ops", head_hash_hex=dk_head_hash(33),
        ),
        make_attestation(
            "reader-cap-device-attestation", owner3_id, 37,
            "cap (reader, all) の端末 L による現ヘッド(37)の申告: 申告の必要 role の下限は reader なので、"
            "実効 role reader の端末でも申告できる",
            key=readercap, chain_ref="device-ops", head_hash_hex=dk_head_hash(37),
        ),
    ]
    rule_negatives += [
        rule_negative(
            "attester-device-revoked-at-head", owner_id, dk_head_hash(37), 37,
            "attester-key-mismatch-at-head",
            "seq 35 で失効した電話 P が失効後のヘッド(37)を申告する形は attester-key-mismatch-at-head"
            "(人〔owner-0001〕は在籍のまま — 端末の有効区間の終了境界)",
            chain_ref="device-ops", attester_key=phone,
        ),
    ]

    write(
        "head-attestation.json",
        {
            "description": "CRYPTO_SPEC §6.6: ヘッド申告(Ed25519)。head_attestation_signed_bytes = LP(\"<suite>/head-attestation\", project_id, attester_user_id, chain_head_hash_hex, chain_head_seq)。チェーン・鍵は chain-entries.json の正規チェーン(24 エントリ — 2026-09-14 ES + PF1 の全再生成に追随してハッシュのみ変化。正例・負例の意味は不変)を参照",
            "signed_fields_order": HEAD_ATTESTATION_FIELDS_ORDER,
            "binary_encoding": "チェーンヘッドハッシュは hex 小文字文字列として LP に載せる(chain-entries.json の binary_encoding と同じ規約)。数値(chain_head_seq)は 10 進文字列化。タイムスタンプ・ノンスは署名対象に含めない(§6.6 — 意味論は帰属であり鮮度証明ではない)",
            "chain_reference": "chain-entries.json: project_id = genesis エントリハッシュ、chain_head_hash_hex = entries[chain_head_seq - 1].entry_hash_hex、attester 鍵 = keys",
            "distribution_note": "removed-attester-in-tenure は §6.6 の検証(署名・申告ヘッド時点の在籍)を通る正例だが、attester が現メンバーでないため配布対象外(remove_member 受理時にサーバーが申告行を削除 — §6.4)であり、配布されてもクライアントは照合材料にしない(§6.6 (1))。この現メンバー検査は本ファイルの検証ベクターの外(実装テスト — session-27 §13-5)",
            "vectors": vectors,
            "negative": negatives + rule_negatives,
        },
    )


# ---------------------------------------------------------------------------
# 3.10 audit-head.json — AUDIT_SPEC §5.1 監査ヘッド累積ハッシュ(SHA-256 + §2.1 LP)
#
# row_digest = lower_hex(SHA-256(LP(seq, row_id, server_ts, client_ts, event,
#                                   actor_type, actor_user_id,
#                                   actor_key_fingerprint, actor_api_token_id,
#                                   target_user_id, target_key_fingerprint,
#                                   environment_id, variable_id, epoch, version,
#                                   chain_seq, payload)))
#   - 列は AUDIT_SPEC §5.1 の固定順 17 列。数値は 10 進文字列化(§2.1)
#   - NULL 許容列(seq / server_ts / event / actor_type 以外の 13 列)は
#     タグ付きバイト列: NULL = 0x00 の 1 バイト、非 NULL = 0x01 + 値のバイト列
#     (NULL と空文字列を同一プリイメージにしない — §5.1)
#   - payload は保存された TEXT のバイト列をそのまま使う(JSON 正規化はしない)
# h_n = lower_hex(SHA-256(LP("maruhi/v1/audit-head", h_{n-1}, seq, row_digest)))
#   - h_0 = 空文字列。h_{n-1} / row_digest はともに hex 小文字**文字列**として
#     LP フィールドに載せる(h_0 = "" の規定と整合する唯一の一様な表現 —
#     本ベクターがこの表現を固定する)

AUDIT_HEAD_DOMAIN = "maruhi/v1/audit-head"

# AUDIT_SPEC §5.1 の固定列順。値 None = NULL(タグ 0x00)
AUDIT_ROW_COLUMNS = [
    ("seq", "int"), ("row_id", "nullable-str"), ("server_ts", "int"),
    ("client_ts", "nullable-int"), ("event", "str"), ("actor_type", "str"),
    ("actor_user_id", "nullable-str"), ("actor_key_fingerprint", "nullable-str"),
    ("actor_api_token_id", "nullable-str"), ("target_user_id", "nullable-str"),
    ("target_key_fingerprint", "nullable-str"), ("environment_id", "nullable-str"),
    ("variable_id", "nullable-str"), ("epoch", "nullable-int"),
    ("version", "nullable-int"), ("chain_seq", "nullable-int"),
    ("payload", "nullable-str"),
]


def audit_row_digest_hex(row: dict) -> str:
    fields = []
    for (column, kind) in AUDIT_ROW_COLUMNS:
        value = row[column]
        if kind in ("nullable-str", "nullable-int"):
            if value is None:
                fields.append(b"\x00")
            else:
                text = str(value) if kind == "nullable-int" else value
                fields.append(b"\x01" + text.encode("utf-8"))
        else:
            fields.append(value)
    return sha256(lp_encode(fields)).hex()


def audit_head_hash_hex(prev_head_hex: str, seq: int, row_digest_hex: str) -> str:
    return sha256(lp_encode([AUDIT_HEAD_DOMAIN, prev_head_hex, seq, row_digest_hex])).hex()


def gen_audit_head():
    # 正規チェーン(累積列): 行は project DO の現実的なイベント形。row_id は
    # 16 バイト乱数 hex の位置づけだがベクターでは決定論的なパターンバイト列
    def row(seq, **columns):
        base = {column: None for (column, _kind) in AUDIT_ROW_COLUMNS}
        base["seq"] = seq
        base["row_id"] = pat(0xA0 + seq, 16).hex()
        return {**base, **columns}

    rows = [
        # 1: チェーンミラー行(chain_seq あり・payload あり)
        row(
            1, server_ts=1_755_500_000_000, client_ts=1_755_499_999_000,
            event="chain.genesis", actor_type="user", actor_user_id="user-owner-0001",
            actor_key_fingerprint=pat(0x10, 16).hex(), target_user_id="user-owner-0001",
            chain_seq=1, payload='{"role":"owner"}',
        ),
        # 2: NULL 許容列が全て NULL の最小行(system actor)
        row(2, row_id=None, server_ts=1_755_500_000_001, event="rotation.recommended",
            actor_type="system"),
        # 3: データ系行(数値列 epoch / version が非 NULL)+ 非 ASCII payload
        #    (保存 TEXT のバイト列そのまま — JSON 正規化をしないことの固定)
        row(
            3, server_ts=1_755_500_000_002, event="var.version_pushed", actor_type="user",
            actor_user_id="user-member-0002", actor_key_fingerprint=pat(0x20, 16).hex(),
            environment_id="env-prod-0001", variable_id="var-database-url-0001",
            epoch=3, version=7, payload='{"note":"㊙ reencryption","reencryption":true}',
        ),
        # 4: 空文字列の非 NULL 列(target_user_id / payload)— NULL(行 2)との
        #    プリイメージ相違はタグバイトが担う
        row(4, server_ts=1_755_500_000_003, event="var.read", actor_type="user",
            actor_user_id="user-reader-0003", target_user_id="", payload=""),
    ]

    head = ""
    chain_cases = []
    for entry in rows:
        digest = audit_row_digest_hex(entry)
        head = audit_head_hash_hex(head, entry["seq"], digest)
        chain_cases.append({
            "row": entry,
            "expected_row_digest_hex": digest,
            "expected_head_hash_hex": head,
        })

    # NULL vs 空文字列の判別対(同一行の target_user_id だけを変える)
    null_row = row(5, server_ts=1_755_500_000_004, event="dek.deleted", actor_type="user",
                   actor_user_id="user-owner-0001", environment_id="env-prod-0001", epoch=2)
    empty_row = {**null_row, "target_user_id": ""}
    null_vs_empty = {
        "note": "target_user_id が NULL の行と空文字列の行は row_digest が異なる"
                "(タグ付きバイト列 0x00 / 0x01 — AUDIT_SPEC §5.1)",
        "null_row": null_row,
        "null_row_digest_hex": audit_row_digest_hex(null_row),
        "empty_row": empty_row,
        "empty_row_digest_hex": audit_row_digest_hex(empty_row),
    }

    write(
        "audit-head.json",
        {
            "description": "AUDIT_SPEC §5.1 監査ヘッド累積ハッシュ: row_digest = SHA-256(固定 17 列の LP。NULL 許容列はタグ付きバイト列 0x00 / 0x01 + 値)、h_n = SHA-256(LP(\"maruhi/v1/audit-head\", h_{n-1}, seq, row_digest))。h_0 = 空文字列。h_{n-1} と row_digest は hex 小文字文字列として LP に載せる",
            "domain": AUDIT_HEAD_DOMAIN,
            "row_columns_order": [column for (column, _kind) in AUDIT_ROW_COLUMNS],
            "initial_head": "",
            "chain": chain_cases,
            "null_vs_empty": null_vs_empty,
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


# ---------------------------------------------------------------------------
# checkpoint-digest.json — §6.2 values_digest の対象選別(declared の除外。
# 0.8-draft — 2026-08-30 セッション 46 / §11 の 0.8-draft 項)
#
# values_digest のエンコーダ(LP 正規形・バイト昇順・重複拒否)は chain-entries.json
# の values_digests セクションが固定済みで不変。本ファイルが固定するのは**対象選別の
# 規則**: v_j に載るのは status = active の変数のみで、status = declared(§4.2
# レイアウト v2 — 値未設定)の変数は values_digest に現れない(値が存在せず公証する
# 座標がない — §6.2)。tombstone(deleted)の対象外は既存規則(マニフェスト側 —
# §4.3 — が捕捉)で、混在ケースが選別の全 3 status を同時に固定する。
# chain-entries.json は変更しない(チェーン形式に触れない — §11)。


def gen_checkpoint_digest():
    def value_hash(variable_id: str, version: int) -> str:
        return sha256(f"checkpoint-digest value {variable_id} v{version}".encode()).hex()

    def active_var(variable_id: str, version: int) -> dict:
        return {
            "variable_id": variable_id,
            "status": "active",
            "version": str(version),
            "value_sig_hash_hex": value_hash(variable_id, version),
        }

    def digest_entry_of(var: dict) -> dict:
        return {
            "variable_id": var["variable_id"],
            "version": var["version"],
            "value_sig_hash_hex": var["value_sig_hash_hex"],
        }

    def values_digest_input(value_entries: list) -> bytes:
        ordered = sorted(value_entries, key=lambda v: v["variable_id"].encode("utf-8"))
        fields = [ENV_VALUES_DIGEST_DOMAIN] + [
            lp_encode([v["variable_id"], v["version"], v["value_sig_hash_hex"]])
            for v in ordered
        ]
        return lp_encode(fields)

    active_api = active_var("var-api-key-0001", 1)
    active_db = active_var("var-database-url-0001", 3)
    declared_var = {"variable_id": "var-v2-declared-0012", "status": "declared"}
    tombstone_var = {"variable_id": "var-legacy-0002", "status": "deleted"}

    mixed_entries = [digest_entry_of(active_api), digest_entry_of(active_db)]
    cases = [
        {
            "name": "declared-excluded",
            "variables": [active_api, declared_var, tombstone_var, active_db],
            "values_digest_entries": mixed_entries,
            "digest_input_hex": values_digest_input(mixed_entries).hex(),
            "values_digest_hex": env_values_digest_hex(mixed_entries),
            "note": "values_digest の対象は status = active の変数のみ(§6.2)。declared"
                    "(§4.2 レイアウト v2 — 値・バージョンが存在しない)は現れず、tombstone"
                    "(deleted)の対象外は既存規則(マニフェスト側 — §4.3 — が捕捉)。"
                    "ダイジェストは active 2 変数のみの集合と同値になる",
        },
        {
            "name": "all-declared-empty",
            "variables": [declared_var],
            "values_digest_entries": [],
            "digest_input_hex": values_digest_input([]).hex(),
            "values_digest_hex": env_values_digest_hex([]),
            "note": "declared のみの環境の values_digest は空集合のダイジェスト"
                    "(chain-entries.json values_digests の empty-set と同値)に一致する — "
                    "「declared に値が配布されないことは正当」(§6.3)の対象選別側の固定",
        },
    ]

    write(
        "checkpoint-digest.json",
        {
            "description": "CRYPTO_SPEC §6.2: checkpoint values_digest の対象選別 — status = declared(§4.2 レイアウト v2・値未設定)の変数は values_digest に現れない(2026-08-30)。values_digest_hex = lower_hex(SHA-256(LP(\"maruhi/v1/env-values-digest\", v_1, …, v_m)))、v_j = LP(variable_id, version, value_sig_hash_hex)(variable_id の UTF-8 バイト昇順・active 変数のみ)。エンコーダの LP 正規形は chain-entries.json の values_digests セクションが固定済みで不変 — 本ファイルは対象選別の規則のみを固定する(chain-entries.json は変更しない — §11)",
            "encoding_reference": "chain-entries.json の values_digests(LP 正規形・バイト昇順・重複拒否・数値の 10 進文字列化)",
            "selection_rule": "variables(ステートメント status 込みの変数集合)から values_digest_entries(active のみ)を選別する。active は最新 version の値座標(version / value_sig_hash_hex)を必ず持ち、declared / deleted は値座標を持たない(active の値配布要求と「declared に値が配布されないことは正当」— §6.3)",
            "cases": cases,
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
    gen_env_manifest()  # 同上(chain-entries.json を参照。§4.3)
    gen_checkpoint_boundary_chains()  # env-manifest のハッシュを参照するため後段(§4.3 (2))
    gen_head_attestation()  # 同上(chain-entries.json を参照。§6.6)
    gen_audit_head()  # AUDIT_SPEC §5.1(単独 — 他ファイルを参照しない)
    gen_invite_accept_signature()
    gen_invite_link()  # chain-entries.json を参照(§6.5 発行署名)
    gen_recovery_wrap()
    gen_checkpoint_digest()  # §6.2 values_digest の対象選別(単独 — 他ファイルを参照しない)
