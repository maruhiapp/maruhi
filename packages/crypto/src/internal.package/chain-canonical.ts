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

export function canonicalChainPayloadBytes(operation: ChainOperation): Uint8Array {
  switch (operation.op) {
    case "genesis": {
      const p = operation.payload;
      return encodeLengthPrefixed([p.encPubHex, p.sigPubHex]);
    }
    case "add_member": {
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

export async function computeChainEntryHash(entry: ChainEntry): Promise<string> {
  return encodeHex(await sha256(canonicalChainEntryBytes(entry)));
}
