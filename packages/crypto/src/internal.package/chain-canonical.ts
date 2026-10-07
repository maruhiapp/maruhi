// CRYPTO_SPEC §6.1: normalization of chain entries (deterministic serialization).
// The substance is pinned by the canonicalization definition in
// test-vectors/chain-entries.json:
//   signed_bytes = LP(suite, seq, prev_hash_hex, op, actor_user_id,
//                     actor_key_fingerprint_hex, payload_bytes, timestamp_ms)
//   payload_bytes = LP(the op's fixed field order), embedded as a single field (nested LP)
//   entry_bytes  = LP(the 8 fields of signed_bytes, signature_hex)
//   entry_hash   = SHA-256(entry_bytes)
// Binary values (prev_hash / public keys / FP / signature) go onto the LP as
// lowercase hex strings.
// grant_server's scope_environments is the hex string of the LP of the
// environment id list (nested LP).
// grant_server's lease_policy is the hex string of a 3-level nested LP (§6.2).
// checkpoint's environments is the hex string of a nested LP of environment
// tuples (§6.2).
// add_member / change_role's scope and set_approval_policy's ops are the hex
// of a nested LP of the environment-id / op-name list; propose's inner payload
// is the hex of the inner op's payload_bytes (2026-09-14).
// add_device's scope is the same nested LP as member scope; revoke_device's
// device_fingerprints is the hex of a nested LP of the FP list (2026-09-19 DK — §6.2).
// delete_environment's payload is LP(environment_id) (2026-10-07 — §6.2).

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
import { canonicalScopeEnvironmentsHex } from "./member-scope.ts";

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
      // 2026-09-14 ES: scope_kind / scope_environments_lp_hex appended at the end (§6.2).
      // The scope's environment list is the same nested-LP hex as grant_server's scope
      const p = operation.payload;
      return encodeLengthPrefixed([
        p.targetUserId,
        p.encPubHex,
        p.sigPubHex,
        p.role,
        p.scopeKind,
        canonicalScopeEnvironmentsHex(p.scopeEnvironmentIds),
      ]);
    }
    case "remove_member": {
      return encodeLengthPrefixed([operation.payload.targetUserId]);
    }
    case "change_role": {
      const p = operation.payload;
      return encodeLengthPrefixed([
        p.targetUserId,
        p.newRole,
        p.scopeKind,
        canonicalScopeEnvironmentsHex(p.scopeEnvironmentIds),
      ]);
    }
    case "create_environment": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.environmentId, p.dekCommitmentHex]);
    }
    // 2026-10-07 (§6.2): one field. Domain separation is the op name inside
    // signed_bytes, like every chain op
    case "delete_environment": {
      return encodeLengthPrefixed([operation.payload.environmentId]);
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
    // Four-eyes (2026-09-14 PF1 — §6.2). ops is the same nested-LP hex as scope;
    // the inner payload is the hex of the inner op's own payload_bytes
    // (same shape as the §6.1 nesting — it can nest two or more levels deep)
    case "set_approval_policy": {
      const p = operation.payload;
      return encodeLengthPrefixed([encodeHex(encodeLengthPrefixed(p.ops)), p.requiredApprovals]);
    }
    case "propose": {
      const p = operation.payload;
      return encodeLengthPrefixed([
        p.inner.op,
        encodeHex(canonicalChainPayloadBytes(p.inner)),
        p.expiresAtMs,
      ]);
    }
    case "approve":
    case "withdraw": {
      return encodeLengthPrefixed([operation.payload.proposalHashHex]);
    }
    // Device keys (2026-09-19 DK — §6.2). add_device = [enc_pub_hex, sig_pub_hex, role_cap,
    // scope_kind, scope_environments_lp_hex]; revoke_device = [target_user_id,
    // device_fingerprints_lp_hex] (nested LP of the FP list — order is signed over)
    case "add_device": {
      const p = operation.payload;
      return encodeLengthPrefixed([
        p.encPubHex,
        p.sigPubHex,
        p.roleCap,
        p.scopeKind,
        canonicalScopeEnvironmentsHex(p.scopeEnvironmentIds),
      ]);
    }
    case "revoke_device": {
      const p = operation.payload;
      return encodeLengthPrefixed([
        p.targetUserId,
        encodeHex(encodeLengthPrefixed(p.deviceFingerprintsHex)),
      ]);
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
