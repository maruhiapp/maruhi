import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry, ChainOperation } from "@maruhi/crypto";
import type {
  BuiltChain,
  ChainHead,
  GeneratedIdentity,
  LazyChainOperation,
  TestRole,
  WireDistributedManifest,
  WireDistributedValue,
  WireRecipientDek,
} from "@maruhi/test-kit";
import {
  addDeviceOp,
  addMemberOp,
  buildChain,
  changeRoleOp as changeRoleScopedOp,
  createEnvironmentOp,
  distributedValueOf,
  distributedWrapOf,
  encryptValue,
  genesisOp,
  rotateEpochOp as rotateEpochWithReasonOp,
  wrapDekTo,
} from "@maruhi/test-kit";

export type {
  BuiltChain,
  ChainStep,
  LazyChainOperation,
  WireCheckpointSnapshot,
  WireDistributedEnvironmentStatement,
  WireDistributedManifest,
  WireDistributedValue,
  WireDistributedVariableStatement,
  WireEncryptedPayload,
  WireRecipientDek,
  WireStatementSchema,
} from "@maruhi/test-kit";
export {
  addMemberOp,
  approveOp,
  buildChain,
  checkpointSnapshotValuesOf,
  createEnvironmentOp,
  decryptValue as decryptWire,
  deleteEnvironmentOp,
  distributedEnvironmentStatement as environmentStatementFor,
  distributedManifest as manifestFor,
  distributedManifestHashOf as manifestHashOf,
  distributedStatementHashOf as statementHashOf,
  distributedVariablesDigestOf as variablesDigestOf,
  distributedVariableStatement as statementFor,
  generateIdentity as makeTestUser,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  innerOf,
  proposeOp,
  removeMemberOp,
  revokeServerOp,
  setApprovalPolicyOp,
  testEnvironmentId,
  testProjectId,
  testUserId,
  testVariableId,
  valueSignedBytesHashOf as valueHashOf,
  withdrawOp,
} from "@maruhi/test-kit";

export type TestUser = GeneratedIdentity;

export function addOwnerDeviceOp(device: TestUser): ChainOperation {
  return addDeviceOp(device, "owner");
}

export function addScopedMemberOp(
  target: TestUser,
  role: Exclude<TestRole, "owner">,
  environmentIds: readonly string[],
): ChainOperation {
  return addMemberOp(target, role, environmentIds.toSorted());
}

export function changeRoleOp(
  target: TestUser,
  role: TestRole,
  environmentIds: readonly string[] | null,
): ChainOperation {
  return changeRoleScopedOp(
    target,
    role,
    environmentIds === null ? undefined : environmentIds.toSorted(),
  );
}

export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dek: Uint8Array,
): LazyChainOperation {
  return rotateEpochWithReasonOp(environmentId, newEpoch, dek, "test");
}

export async function wrapDekFor(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipient: TestUser;
  readonly signer: TestUser;
}): Promise<WireRecipientDek> {
  return distributedWrapOf(await wrapDekTo(input), input.signer);
}

export async function rotatedEnvironmentFor(input: {
  readonly owner: TestUser;
  readonly environmentId: string;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
}): Promise<{
  readonly chain: BuiltChain;
  readonly wraps: readonly [WireRecipientDek, WireRecipientDek];
}> {
  const { owner, environmentId, dek1, dek2 } = input;
  const chain = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(environmentId, dek1) },
    { actor: owner, operation: rotateEpochOp(environmentId, 2, dek2) },
  ]);
  const common = { projectId: chain.projectId, environmentId, recipient: owner, signer: owner };
  const wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1 }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2 }),
  ] as const;
  return { chain, wraps };
}

export interface WireRotateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & {
    readonly op: "rotate_epoch";
    readonly payload: {
      readonly environmentId: string;
      readonly newEpoch: number;
      readonly reason: string;
      readonly dekCommitmentHex: string;
    };
  };
  readonly deks: readonly WrappedDek[];
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

export async function encryptValueFor(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
  readonly writer: TestUser;
  readonly head: ChainHead;
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
  const payload = await encryptValue({
    ...input,
    prevValueSigHashHex: input.prevValueSigHashHex ?? (input.version === 1 ? "" : "cd".repeat(32)),
  });
  return distributedValueOf(payload, input.writer);
}
