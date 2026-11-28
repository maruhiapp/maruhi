import type { ChainEntry, ChainOperation, VariableContext } from "@maruhi/crypto";
import { generateDek } from "@maruhi/crypto";
import type { WireEncryptedPayload } from "@maruhi/crypto/test-support";
import { vectorKeys } from "@maruhi/crypto/test-support";
import type {
  BuiltChain,
  ChainHead,
  SignedEntry,
  TestIdentity,
  TestRole,
  TestScope,
  UnsignedMetaStatement,
  UnsignedWrap,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
  WireWrappedDek,
} from "@maruhi/test-kit";
import {
  addMemberOp,
  buildChain as buildChainAs,
  changeRoleOp,
  createVariableStatement as createVariableStatementAs,
  encryptValue as encryptValueAs,
  genesisOp,
  resignEntryAt as resignEntryAs,
  signEntryAt as signEntryAs,
  signManifest,
  signMetaStatement,
  signValueAt,
  signWrap,
  testDekCommitmentHex,
  testUserId,
  unwrapAndDecrypt as unwrapAndDecryptAs,
  vectorIdentity,
  vectorIdentityByFingerprint,
  verifyWrapSignature,
  wrapDekTo as wrapDekToRecipient,
} from "@maruhi/test-kit";

export type { WireEncryptedPayload };
export type {
  WireDigestEntry,
  WireEnvironmentManifest,
  WireVariableMetaStatement,
  WireWrappedDek,
} from "@maruhi/test-kit";
export {
  checkpointOp as checkpointOperation,
  createEnvironmentOp as createEnvironmentOperation,
  hexBytes,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  rotateEpochOp as rotateEpochOperation,
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  testVariableId,
  valuesDigestOf,
  valueSignedBytesHashOf,
  variablesDigestOf as digestOf,
} from "@maruhi/test-kit";

export type WireEnvironmentMetaStatement = Omit<
  WireVariableMetaStatement,
  "variableId" | "layoutVersion" | "varType" | "required" | "description" | "maxAgeDays" | "status"
> & { readonly status: "active" | "deleted" };

const VECTOR_KEY_ALIASES: Record<string, string> = {
  "user-reader-0003": "user-admin-0003",
};

const deviceKeyOverrides = new Map<string, string>();

export function useDeviceKey(userId: string, vectorKeyName: string | null): void {
  if (vectorKeyName === null) {
    deviceKeyOverrides.delete(userId);
  } else {
    deviceKeyOverrides.set(userId, vectorKeyName);
  }
}

export function resetDeviceKeys(): void {
  deviceKeyOverrides.clear();
}

export function vectorKeyNamed(name: string) {
  const keys = vectorKeys[name];
  if (keys === undefined) {
    throw new Error(`no vector keys named ${name}`);
  }
  return keys;
}

function vectorKeyNameOf(userId: string): string {
  return deviceKeyOverrides.get(userId) ?? VECTOR_KEY_ALIASES[userId] ?? userId;
}

export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[vectorKeyNameOf(userId)];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${userId}`);
  }
  return keys;
}

function identityOf(userId: string): TestIdentity {
  return vectorIdentity(vectorKeyNameOf(userId), userId);
}

export async function signEntryAt(input: {
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actorUserId: string;
  readonly operation: ChainOperation;
}): Promise<SignedEntry> {
  return signEntryAs({
    seq: input.seq,
    prevHashHex: input.prevHashHex,
    actor: identityOf(input.actorUserId),
    operation: input.operation,
  });
}

export async function resignEntryAt(
  base: ChainEntry,
  seq: number,
  prevHashHex: string,
): Promise<SignedEntry> {
  const signer =
    vectorIdentityByFingerprint(base.actor.keyFingerprintHex, base.actor.userId) ??
    identityOf(base.actor.userId);
  return resignEntryAs(base, seq, prevHashHex, signer);
}

export async function buildChain(
  steps: readonly { readonly actorUserId: string; readonly operation: ChainOperation }[],
): Promise<BuiltChain> {
  return buildChainAs(
    steps.map((step) => ({ actor: identityOf(step.actorUserId), operation: step.operation })),
  );
}

export function genesisOperation(userId: string): ChainOperation {
  return genesisOp(identityOf(userId));
}

export function addMemberOperation(
  targetUserId: string,
  role: TestRole,
  scope?: TestScope,
): ChainOperation {
  return addMemberOp(identityOf(targetUserId), role, scope);
}

export function changeRoleOperation(
  targetUserId: string,
  newRole: TestRole,
  scope?: TestScope,
): ChainOperation {
  return changeRoleOp({ userId: testUserId(targetUserId) }, newRole, scope);
}

export const commitmentOf = testDekCommitmentHex;

export function makeDek(): Uint8Array {
  return generateDek();
}

export async function signWrapAs<T extends UnsignedWrap>(
  signerUserId: string,
  projectId: string,
  environmentId: string,
  wrap: T,
): Promise<T & { readonly signatureHex: string }> {
  return signWrap(identityOf(signerUserId), projectId, environmentId, wrap);
}

export async function verifyDistributedWrapSignature(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly wrap: {
    readonly suite: string;
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
    readonly signatureHex: string;
    readonly signerUserId: string;
  };
}): Promise<boolean> {
  return verifyWrapSignature({
    projectId: input.projectId,
    environmentId: input.environmentId,
    recipient: { userId: input.recipientUserId, encPubHex: input.recipientEncPubHex },
    wrap: input.wrap,
    signer: identityOf(input.wrap.signerUserId),
  });
}

export async function wrapDekTo(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
  readonly signerUserId: string;
}): Promise<WireWrappedDek> {
  return wrapDekToRecipient({
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    dek: input.dek,
    recipient: {
      userId: input.recipientUserId,
      encPubHex: input.recipientEncPubHex ?? vectorKeyOf(input.recipientUserId).enc_pub_hex,
    },
    signer: identityOf(input.signerUserId),
  });
}

export async function wrapDekToServer(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly serverKeyFingerprintHex: string;
  readonly serverEncPubHex: string;
  readonly signerUserId: string;
}): Promise<WireWrappedDek> {
  return wrapDekToRecipient({
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    dek: input.dek,
    recipient: { userId: input.serverKeyFingerprintHex, encPubHex: input.serverEncPubHex },
    recipientClass: "server",
    signer: identityOf(input.signerUserId),
  });
}

export async function wrapDekForAll(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserIds: readonly string[];
  readonly signerUserId: string;
}): Promise<WireWrappedDek[]> {
  const wraps: WireWrappedDek[] = [];
  for (const recipientUserId of input.recipientUserIds) {
    wraps.push(await wrapDekTo({ ...input, recipientUserId }));
  }
  return wraps;
}

export async function signValueAs(
  writerUserId: string,
  unsigned: Omit<WireEncryptedPayload, "signatureHex">,
  head: ChainHead,
): Promise<WireEncryptedPayload> {
  return signValueAt(identityOf(writerUserId), unsigned, head);
}

export async function encryptValue(
  dek: Uint8Array,
  context: VariableContext,
  plaintext: string,
  signing: {
    readonly writerUserId: string;
    readonly head: ChainHead;
    readonly prevValueSigHashHex?: string;
  },
): Promise<WireEncryptedPayload> {
  return encryptValueAs({
    dek,
    ...context,
    plaintext,
    writer: identityOf(signing.writerUserId),
    head: signing.head,
    prevValueSigHashHex: signing.prevValueSigHashHex ?? "",
  });
}

export async function signMetaStatementAs<T extends UnsignedMetaStatement>(
  authorUserId: string,
  projectId: string,
  unsigned: T,
): Promise<T & { readonly signatureHex: string }> {
  return signMetaStatement(identityOf(authorUserId), projectId, unsigned);
}

export async function signEnvManifestAs(
  issuerUserId: string,
  projectId: string,
  unsigned: Omit<WireEnvironmentManifest, "signatureHex">,
): Promise<WireEnvironmentManifest> {
  return signManifest(identityOf(issuerUserId), projectId, unsigned);
}

export async function createVariableStatement(input: {
  readonly authorUserId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly head: ChainHead;
}): Promise<WireVariableMetaStatement> {
  return createVariableStatementAs({ ...input, author: identityOf(input.authorUserId) });
}

export async function unwrapAndDecrypt(input: {
  readonly recipientUserId: string;
  readonly wrapped: {
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
  };
  readonly projectId: string;
  readonly environmentId: string;
  readonly payload: WireEncryptedPayload;
}): Promise<string> {
  return unwrapAndDecryptAs({
    recipient: identityOf(input.recipientUserId),
    wrapped: input.wrapped,
    projectId: input.projectId,
    environmentId: input.environmentId,
    payload: input.payload,
  });
}
