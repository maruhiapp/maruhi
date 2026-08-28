// CRYPTO_SPEC §6.1: チェーンエントリの正規化(決定論的シリアライズ)。
// 実体は test-vectors/chain-entries.json の canonicalization 定義で固定されている:
//   signed_bytes = LP(suite, seq, prev_hash_hex, op, actor_user_id,
//                     actor_key_fingerprint_hex, payload_bytes, timestamp_ms)
//   payload_bytes = LP(op ごとの固定フィールド順) を 1 フィールドとして埋め込む(入れ子 LP)
//   entry_bytes  = LP(signed_bytes の 8 フィールド, signature_hex)
//   entry_hash   = SHA-256(entry_bytes)
// バイナリ値(prev_hash / 公開鍵 / FP / 署名)は hex 小文字文字列として LP に載せる。
// grant_server の scope_environments は環境 ID リストの LP の hex 文字列(入れ子 LP)。
// grant_server の lease_policy は 3 段の入れ子 LP の hex 文字列(§6.2。2026-08-12)。
// checkpoint の environments は環境タプルリストの入れ子 LP の hex 文字列(§6.2。2026-08-27)。

import { encodeHex } from "./bytes.ts";
import type {
  ChainEntry,
  ChainOperation,
  CheckpointEnvironmentEntry,
  LeasePolicyIssuer,
  UnsignedChainEntry,
} from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import { sha256 } from "./hash.ts";

/**
 * Canonical bytes of a grant_server lease policy (CRYPTO_SPEC §6.2): a
 * three-level nested length-prefixed encoding —
 * `constraint = LP(claim_name, claim_value)`,
 * `element = LP(issuer_url, audience, LP(constraint...))`,
 * `policy = LP(element...)`. Fixed by chain-entries.json. The empty policy
 * encodes to the empty byte string ("no lease path").
 */
function canonicalLeasePolicyBytes(policy: readonly LeasePolicyIssuer[]): Uint8Array {
  return encodeLengthPrefixed(
    policy.map((element) =>
      encodeLengthPrefixed([
        element.issuerUrl,
        element.audience,
        encodeLengthPrefixed(
          element.claimConstraints.map((constraint) =>
            encodeLengthPrefixed([constraint.claimName, constraint.claimValue]),
          ),
        ),
      ]),
    ),
  );
}

/**
 * Canonical bytes of a checkpoint's environment tuple list (CRYPTO_SPEC
 * §6.2): a nested length-prefixed encoding —
 * `entry = LP(environment_id, epoch, manifest_version, manifest_sig_hash_hex,
 * values_digest_hex)`, `environments = LP(entry...)`. Fixed by
 * chain-entries.json. The empty list encodes to the empty byte string
 * (a checkpoint with no environment tuples — audit-head attestation only).
 */
function canonicalCheckpointEnvironmentsBytes(
  environments: readonly CheckpointEnvironmentEntry[],
): Uint8Array {
  return encodeLengthPrefixed(
    environments.map((entry) =>
      encodeLengthPrefixed([
        entry.environmentId,
        entry.epoch,
        entry.manifestVersion,
        entry.manifestSigHashHex,
        entry.valuesDigestHex,
      ]),
    ),
  );
}

/**
 * Canonical payload bytes for a chain operation: the length-prefixed encoding
 * of the operation's fixed field order (fixed by chain-entries.json).
 */
export function canonicalChainPayloadBytes(operation: ChainOperation): Uint8Array {
  switch (operation.op) {
    case "genesis": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.encPubHex, p.sigPubHex]);
    }
    case "add_member": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.targetUserId, p.encPubHex, p.sigPubHex, p.role]);
    }
    case "remove_member": {
      return encodeLengthPrefixed([operation.payload.targetUserId]);
    }
    case "change_role": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.targetUserId, p.newRole]);
    }
    case "create_environment": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.environmentId, p.dekCommitmentHex]);
    }
    case "rotate_epoch": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.environmentId, p.newEpoch, p.reason, p.dekCommitmentHex]);
    }
    case "grant_server": {
      const p = operation.payload;
      const scopeLpHex = encodeHex(encodeLengthPrefixed(p.scopeEnvironmentIds));
      const leasePolicyLpHex = encodeHex(canonicalLeasePolicyBytes(p.leasePolicy));
      return encodeLengthPrefixed([
        p.serverEncPubHex,
        p.serverKeyFingerprintHex,
        scopeLpHex,
        leasePolicyLpHex,
      ]);
    }
    case "revoke_server": {
      return encodeLengthPrefixed([operation.payload.serverKeyFingerprintHex]);
    }
    case "checkpoint": {
      const p = operation.payload;
      const environmentsLpHex = encodeHex(canonicalCheckpointEnvironmentsBytes(p.environments));
      return encodeLengthPrefixed([environmentsLpHex, p.auditHeadHashHex]);
    }
  }
}

/**
 * Canonical byte string signed by the entry's actor (Ed25519, CRYPTO_SPEC §6.1).
 */
export function canonicalChainSignedBytes(entry: UnsignedChainEntry): Uint8Array {
  return encodeLengthPrefixed([
    entry.suite,
    entry.seq,
    entry.prevHashHex,
    entry.op,
    entry.actor.userId,
    entry.actor.keyFingerprintHex,
    canonicalChainPayloadBytes(entry),
    entry.timestampMs,
  ]);
}

/**
 * Canonical byte string of the complete entry (signed bytes fields plus the
 * signature). Its SHA-256 is the entry hash referenced by the next entry's
 * `prev_hash`.
 */
export function canonicalChainEntryBytes(entry: ChainEntry): Uint8Array {
  return encodeLengthPrefixed([
    entry.suite,
    entry.seq,
    entry.prevHashHex,
    entry.op,
    entry.actor.userId,
    entry.actor.keyFingerprintHex,
    canonicalChainPayloadBytes(entry),
    entry.timestampMs,
    entry.signatureHex,
  ]);
}

/** Computes the entry hash (lowercase hex): `SHA-256(entry_bytes)`. */
export async function computeChainEntryHash(entry: ChainEntry): Promise<string> {
  return encodeHex(await sha256(canonicalChainEntryBytes(entry)));
}
