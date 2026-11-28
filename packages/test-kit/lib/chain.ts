import type {
  ApprovalTargetOp,
  ChainEntry,
  ChainOperation,
  EnvironmentId,
  GrantServerPayload,
  ProposableOperation,
  UnsignedChainEntry,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  encodeHex,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import type { BuiltChain, LazyChainOperation } from "@maruhi/crypto/test-support";
import {
  BASE_TIME_MS,
  buildChainWith,
  hexBytes,
  testDekCommitmentHex,
  testEnvironmentId,
  testKeyFingerprintHex,
  unwrapResult,
} from "@maruhi/crypto/test-support";

import type { SigningIdentity, TestIdentity } from "./identity.ts";
import { signingKeyOf } from "./identity.ts";

export type TestRole = "owner" | "admin" | "member" | "reader";

export type TestScope = readonly string[] | undefined;

export interface ChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

export interface ChainStep {
  readonly actor: TestIdentity;
  readonly operation: ChainOperation | LazyChainOperation;
}

export interface SignedEntry {
  readonly entry: ChainEntry;
  readonly hash: string;
}

async function signEntry(
  signer: SigningIdentity,
  unsigned: UnsignedChainEntry,
): Promise<ChainEntry> {
  return unwrapResult(
    await signChainEntry({ entry: unsigned, signingKey: await signingKeyOf(signer) }),
    "signChainEntry",
  );
}

export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: { userId: step.actor.userId, keyFingerprintHex: step.actor.fingerprintHex },
      operation: step.operation,
      signEntry: (unsigned) => signEntry(step.actor, unsigned),
    })),
  );
}

export async function signEntryAt(input: {
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actor: TestIdentity;
  readonly operation: ChainOperation;
}): Promise<SignedEntry> {
  const unsigned: UnsignedChainEntry = {
    ...input.operation,
    suite: SUITE_ID,
    seq: input.seq,
    prevHashHex: input.prevHashHex,
    actor: { userId: input.actor.userId, keyFingerprintHex: input.actor.fingerprintHex },
    timestampMs: BASE_TIME_MS + input.seq * 1000,
  };
  const entry = await signEntry(input.actor, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

export async function resignEntryAt(
  base: ChainEntry,
  seq: number,
  prevHashHex: string,
  signer: SigningIdentity,
): Promise<SignedEntry> {
  const { signatureHex: _signatureHex, ...rest } = base;
  const unsigned: UnsignedChainEntry = {
    ...rest,
    seq,
    prevHashHex,
    timestampMs: base.op === "approve" ? base.timestampMs : BASE_TIME_MS + seq * 1000,
  };
  const entry = await signEntry(signer, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

export function headOf(built: BuiltChain, seq: number): ChainHead {
  const hashHex = built.hashes[seq - 1];
  if (hashHex === undefined) {
    throw new Error(`headOf: chain has no seq ${seq}`);
  }
  return { seq, hashHex };
}

function scopeFieldsOf(scope: TestScope): {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
} {
  return scope === undefined
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: scope.map(testEnvironmentId) };
}

type PublicIdentity = Pick<TestIdentity, "userId" | "encPubHex" | "sigPubHex">;

export function genesisOp(founder: PublicIdentity): ChainOperation {
  return {
    op: "genesis",
    payload: { encPubHex: founder.encPubHex, sigPubHex: founder.sigPubHex },
  };
}

export function addDeviceOp(
  device: PublicIdentity,
  roleCap: TestRole,
  scope?: TestScope,
): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap,
      ...scopeFieldsOf(scope),
    },
  };
}

export function addMemberOp(
  target: PublicIdentity,
  role: TestRole,
  scope?: TestScope,
): ChainOperation {
  return {
    op: "add_member",
    payload: {
      targetUserId: target.userId,
      encPubHex: target.encPubHex,
      sigPubHex: target.sigPubHex,
      role,
      ...scopeFieldsOf(scope),
    },
  };
}

export function changeRoleOp(
  target: Pick<TestIdentity, "userId">,
  newRole: TestRole,
  scope?: TestScope,
): ChainOperation {
  return {
    op: "change_role",
    payload: { targetUserId: target.userId, newRole, ...scopeFieldsOf(scope) },
  };
}

export function removeMemberOp(target: Pick<TestIdentity, "userId">): ChainOperation {
  return { op: "remove_member", payload: { targetUserId: target.userId } };
}

export function createEnvironmentOp(environmentId: string, dek: Uint8Array): LazyChainOperation;
export function createEnvironmentOp(
  environmentId: string,
  dekCommitmentHex: string,
): ChainOperation;
export function createEnvironmentOp(
  environmentId: string,
  dekOrCommitmentHex: Uint8Array | string,
): ChainOperation | LazyChainOperation {
  if (typeof dekOrCommitmentHex === "string") {
    return {
      op: "create_environment",
      payload: {
        environmentId: testEnvironmentId(environmentId),
        dekCommitmentHex: dekOrCommitmentHex,
      },
    };
  }
  return async (projectId) => ({
    op: "create_environment",
    payload: {
      environmentId: testEnvironmentId(environmentId),
      dekCommitmentHex: await testDekCommitmentHex(projectId, environmentId, 1, dekOrCommitmentHex),
    },
  });
}

export function deleteEnvironmentOp(environmentId: string): ChainOperation {
  return { op: "delete_environment", payload: { environmentId: testEnvironmentId(environmentId) } };
}

export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dek: Uint8Array,
  reason?: string,
): LazyChainOperation;
export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dekCommitmentHex: string,
  reason?: string,
): ChainOperation;
export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dekOrCommitmentHex: Uint8Array | string,
  reason = "scheduled",
): ChainOperation | LazyChainOperation {
  if (typeof dekOrCommitmentHex === "string") {
    return {
      op: "rotate_epoch",
      payload: {
        environmentId: testEnvironmentId(environmentId),
        newEpoch,
        reason,
        dekCommitmentHex: dekOrCommitmentHex,
      },
    };
  }
  return async (projectId) => ({
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId(environmentId),
      newEpoch,
      reason,
      dekCommitmentHex: await testDekCommitmentHex(
        projectId,
        environmentId,
        newEpoch,
        dekOrCommitmentHex,
      ),
    },
  });
}

export function checkpointOp(input: {
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
  readonly auditHeadHashHex?: string;
}): ChainOperation {
  return {
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: testEnvironmentId(input.environmentId),
          epoch: input.epoch,
          manifestVersion: input.manifestVersion,
          manifestSigHashHex: input.manifestSigHashHex,
          valuesDigestHex: input.valuesDigestHex,
        },
      ],
      auditHeadHashHex: input.auditHeadHashHex ?? "",
    },
  };
}

export async function grantServerOp(
  scopeEnvironmentIds: readonly string[],
  leasePolicy: GrantServerPayload["leasePolicy"] = [],
  serverEncPubHex?: string,
): Promise<ChainOperation> {
  let serverEncPub: Uint8Array;
  if (serverEncPubHex === undefined) {
    const serverPair = await generateEncryptionKeyPair({ extractable: true });
    serverEncPub = await exportEncryptionPublicKey(serverPair.publicKey);
  } else {
    serverEncPub = hexBytes(serverEncPubHex);
  }
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", serverEncPub as BufferSource),
  );
  return {
    op: "grant_server",
    payload: {
      serverEncPubHex: encodeHex(serverEncPub),
      serverKeyFingerprintHex: testKeyFingerprintHex(encodeHex(digest.slice(0, 16))),
      scopeEnvironmentIds: scopeEnvironmentIds.map(testEnvironmentId),
      leasePolicy,
    },
  };
}

export function revokeServerOp(serverKeyFingerprintHex: string): ChainOperation {
  return {
    op: "revoke_server",
    payload: { serverKeyFingerprintHex: testKeyFingerprintHex(serverKeyFingerprintHex) },
  };
}

export function setApprovalPolicyOp(
  ops: readonly ApprovalTargetOp[],
  requiredApprovals: number,
): ChainOperation {
  return {
    op: "set_approval_policy",
    payload: { ops: [...ops].toSorted(), requiredApprovals },
  };
}

export function proposeOp(
  inner: ProposableOperation,
  expiresAtMs = 4_000_000_000_000,
): ChainOperation {
  return { op: "propose", payload: { inner, expiresAtMs } };
}

export function approveOp(proposalHashHex: string): ChainOperation {
  return { op: "approve", payload: { proposalHashHex } };
}

export function withdrawOp(proposalHashHex: string): ChainOperation {
  return { op: "withdraw", payload: { proposalHashHex } };
}

export function innerOf(operation: ChainOperation): ProposableOperation {
  if (operation.op === "propose" || operation.op === "approve" || operation.op === "withdraw") {
    throw new Error(`${operation.op} cannot be proposed`);
  }
  return operation;
}
