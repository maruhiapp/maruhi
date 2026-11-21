import type {
  EnvironmentId,
  ChainEntry,
  ChainOperation,
  EnvValuesDigestEntry,
  MetaStatementTarget,
  UnsignedChainEntry,
  VariableContext,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvManifestSignedBytesHash,
  computeEnvValuesDigest,
  computeMetaSignedBytesHash,
  computeVariablesDigest,
  decryptVariable,
  encodeHex,
  encryptVariable,
  generateDek,
  importEncryptionKeyPair,
  importEncryptionPublicKey,
  importSigningKeyPair,
  importSigningPublicKey,
  signChainEntry,
  signDekWrap,
  signEnvManifest,
  signMetaStatement,
  signValue,
  SUITE_ID,
  unwrapDek,
  verifyDekWrapSignature,
  wrapDek,
} from "@maruhi/crypto";
import type { BuiltChain, WireEncryptedPayload } from "@maruhi/crypto/test-support";
import {
  BASE_TIME_MS,
  buildChainWith,
  hexBytes,
  testDekCommitmentHex,
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  testVariableId,
  unwrapResult,
  valueContextOf,
  vectorKeys,
} from "@maruhi/crypto/test-support";

export type { BuiltChain, WireEncryptedPayload };
export { hexBytes, valueSignedBytesHashOf } from "@maruhi/crypto/test-support";
export {
  testEnvironmentId,
  testKeyFingerprintHex,
  testProjectId,
  testUserId,
  testVariableId,
} from "@maruhi/crypto/test-support";

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

export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[deviceKeyOverrides.get(userId) ?? VECTOR_KEY_ALIASES[userId] ?? userId];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${userId}`);
  }
  return keys;
}

function vectorKeyByFingerprint(fingerprintHex: string) {
  return Object.values(vectorKeys).find((keys) => keys.key_fingerprint_hex === fingerprintHex);
}

async function signAs(userId: string, unsigned: UnsignedChainEntry): Promise<ChainEntry> {
  const keys = vectorKeyByFingerprint(unsigned.actor.keyFingerprintHex) ?? vectorKeyOf(userId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  return unwrapResult(
    await signChainEntry({ entry: unsigned, signingKey: pair.privateKey }),
    "signChainEntry",
  );
}

export interface ChainStep {
  readonly actorUserId: string;
  readonly operation: ChainOperation;
}

export async function signEntryAt(input: {
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actorUserId: string;
  readonly operation: ChainOperation;
}): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const keys = vectorKeyOf(input.actorUserId);
  const unsigned: UnsignedChainEntry = {
    ...input.operation,
    suite: SUITE_ID,
    seq: input.seq,
    prevHashHex: input.prevHashHex,
    actor: {
      userId: testUserId(input.actorUserId),
      keyFingerprintHex: testKeyFingerprintHex(keys.key_fingerprint_hex),
    },
    timestampMs: BASE_TIME_MS + input.seq * 1000,
  };
  const entry = await signAs(input.actorUserId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

export async function resignEntryAt(
  base: ChainEntry,
  seq: number,
  prevHashHex: string,
): Promise<{ readonly entry: ChainEntry; readonly hash: string }> {
  const { signatureHex: _signatureHex, ...rest } = base;
  const unsigned: UnsignedChainEntry = {
    ...rest,
    seq,
    prevHashHex,
    timestampMs: base.op === "approve" ? base.timestampMs : BASE_TIME_MS + seq * 1000,
  };
  const entry = await signAs(base.actor.userId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: {
        userId: testUserId(step.actorUserId),
        keyFingerprintHex: testKeyFingerprintHex(vectorKeyOf(step.actorUserId).key_fingerprint_hex),
      },
      operation: step.operation,
      signEntry: (unsigned) => signAs(step.actorUserId, unsigned),
    })),
  );
}

export function genesisOperation(userId: string): ChainOperation {
  const keys = vectorKeyOf(userId);
  return {
    op: "genesis",
    payload: { encPubHex: keys.enc_pub_hex, sigPubHex: keys.sig_pub_hex },
  };
}

export type TestScope = readonly string[] | undefined;

function scopeFieldsOf(scope: TestScope): {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
} {
  return scope === undefined
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: scope.map(testEnvironmentId) };
}

export function addMemberOperation(
  targetUserId: string,
  role: "owner" | "admin" | "member" | "reader",
  scope?: TestScope,
): ChainOperation {
  const keys = vectorKeyOf(targetUserId);
  return {
    op: "add_member",
    payload: {
      targetUserId: testUserId(targetUserId),
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
      ...scopeFieldsOf(scope),
    },
  };
}

export function changeRoleOperation(
  targetUserId: string,
  newRole: "owner" | "admin" | "member" | "reader",
  scope?: TestScope,
): ChainOperation {
  return {
    op: "change_role",
    payload: { targetUserId: testUserId(targetUserId), newRole, ...scopeFieldsOf(scope) },
  };
}

export const commitmentOf = testDekCommitmentHex;

export function createEnvironmentOperation(
  environmentId: string,
  dekCommitmentHex: string,
): ChainOperation {
  return {
    op: "create_environment",
    payload: { environmentId: testEnvironmentId(environmentId), dekCommitmentHex },
  };
}

export async function valuesDigestOf(entries: readonly EnvValuesDigestEntry[]): Promise<string> {
  return unwrapResult(await computeEnvValuesDigest(SUITE_ID, entries), "computeEnvValuesDigest");
}

export function checkpointOperation(input: {
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

export function rotateEpochOperation(
  environmentId: string,
  newEpoch: number,
  dekCommitmentHex: string,
  reason = "scheduled",
): ChainOperation {
  return {
    op: "rotate_epoch",
    payload: {
      environmentId: testEnvironmentId(environmentId),
      newEpoch,
      reason,
      dekCommitmentHex,
    },
  };
}

export function makeDek(): Uint8Array {
  return generateDek();
}

export interface WireWrappedDek {
  readonly suite: string;
  readonly epoch: number;
  readonly recipientClass: "member" | "server";
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

export async function signWrapAs(
  signerUserId: string,
  projectId: string,
  environmentId: string,
  wrap: Omit<WireWrappedDek, "signatureHex">,
): Promise<WireWrappedDek> {
  const keys = vectorKeyOf(signerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signDekWrap({
      context: {
        suite: wrap.suite,
        projectId: testProjectId(projectId),
        environmentId: testEnvironmentId(environmentId),
        epoch: wrap.epoch,
        recipientUserId: testUserId(wrap.recipientUserId),
        recipientEncPubHex: wrap.recipientEncPubHex,
        encHex: wrap.encHex,
        ciphertextHex: wrap.ciphertextHex,
        signerUserId: testUserId(signerUserId),
      },
      signingKey: pair.privateKey,
    }),
    "signDekWrap",
  );
  return { ...wrap, signatureHex };
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
  const signerKeys = vectorKeyOf(input.wrap.signerUserId);
  const publicKey = unwrapResult(
    await importSigningPublicKey(hexBytes(signerKeys.sig_pub_hex)),
    "importSigningPublicKey",
  );
  const result = await verifyDekWrapSignature({
    context: {
      suite: input.wrap.suite,
      projectId: testProjectId(input.projectId),
      environmentId: testEnvironmentId(input.environmentId),
      epoch: input.wrap.epoch,
      recipientUserId: testUserId(input.recipientUserId),
      recipientEncPubHex: input.recipientEncPubHex,
      encHex: input.wrap.encHex,
      ciphertextHex: input.wrap.ciphertextHex,
      signerUserId: testUserId(input.wrap.signerUserId),
    },
    signatureHex: input.wrap.signatureHex,
    signerPublicKey: publicKey,
  });
  return result.ok;
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
  const encPubHex = input.recipientEncPubHex ?? vectorKeyOf(input.recipientUserId).enc_pub_hex;
  const publicKey = unwrapResult(
    await importEncryptionPublicKey(hexBytes(encPubHex)),
    "importEncryptionPublicKey",
  );
  const wrapped = unwrapResult(
    await wrapDek({
      recipientPublicKey: publicKey,
      dek: input.dek,
      context: {
        projectId: testProjectId(input.projectId),
        environmentId: testEnvironmentId(input.environmentId),
        epoch: input.epoch,
        recipientUserId: testUserId(input.recipientUserId),
      },
    }),
    "wrapDek",
  );
  return signWrapAs(input.signerUserId, input.projectId, input.environmentId, {
    suite: SUITE_ID,
    epoch: input.epoch,
    recipientClass: "member",
    recipientUserId: testUserId(input.recipientUserId),
    recipientEncPubHex: encPubHex,
    encHex: encodeHex(wrapped.enc),
    ciphertextHex: encodeHex(wrapped.ciphertext),
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
  const wrap = await wrapDekTo({
    projectId: testProjectId(input.projectId),
    environmentId: testEnvironmentId(input.environmentId),
    epoch: input.epoch,
    dek: input.dek,
    recipientUserId: testUserId(input.serverKeyFingerprintHex),
    recipientEncPubHex: input.serverEncPubHex,
    signerUserId: testUserId(input.signerUserId),
  });
  return { ...wrap, recipientClass: "server" };
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

export interface ValueChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

export async function signValueAs(
  writerUserId: string,
  unsigned: Omit<WireEncryptedPayload, "signatureHex">,
  head: ValueChainHead,
): Promise<WireEncryptedPayload> {
  const keys = vectorKeyOf(writerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const withHead = {
    ...unsigned,
    chainHeadHashHex: head.hashHex,
    chainHeadSeq: head.seq,
    signatureHex: "",
  };
  const signatureHex = unwrapResult(
    await signValue({
      context: valueContextOf(withHead, writerUserId),
      signingKey: pair.privateKey,
    }),
    "signValue",
  );
  return { ...withHead, signatureHex };
}

export async function encryptValue(
  dek: Uint8Array,
  context: VariableContext,
  plaintext: string,
  signing: {
    readonly writerUserId: string;
    readonly head: ValueChainHead;
    readonly prevValueSigHashHex?: string;
  },
): Promise<WireEncryptedPayload> {
  const encrypted = unwrapResult(
    await encryptVariable({
      dek,
      context,
      plaintext: new TextEncoder().encode(plaintext),
    }),
    "encryptVariable",
  );
  return signValueAs(
    signing.writerUserId,
    {
      suite: SUITE_ID,
      aad: { ...context },
      nonceHex: encodeHex(encrypted.nonce),
      ciphertextHex: encodeHex(encrypted.ciphertext),
      prevValueSigHashHex: signing.prevValueSigHashHex ?? "",
      chainHeadHashHex: signing.head.hashHex,
      chainHeadSeq: signing.head.seq,
    },
    signing.head,
  );
}

export interface WireVariableMetaStatement {
  readonly suite: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly layoutVersion?: number;
  readonly varType?: "" | "string" | "number" | "boolean" | "url";
  readonly required?: boolean;
  readonly description?: string;
  readonly maxAgeDays?: number | null;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export type WireEnvironmentMetaStatement = Omit<
  WireVariableMetaStatement,
  "variableId" | "layoutVersion" | "varType" | "required" | "description" | "maxAgeDays"
> & { readonly status: "active" | "deleted" };

function metaTargetOf(statement: { readonly variableId?: string }): MetaStatementTarget {
  return statement.variableId === undefined
    ? { kind: "environment" }
    : { kind: "variable", variableId: testVariableId(statement.variableId) };
}

function metaContextOf(
  projectId: string,
  statement: Omit<WireVariableMetaStatement, "signatureHex" | "variableId"> & {
    readonly variableId?: string;
  },
  authorUserId: string,
) {
  return {
    suite: statement.suite,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(statement.environmentId),
    target: metaTargetOf(statement),
    name: statement.name,
    status: statement.status,
    layoutVersion: statement.layoutVersion,
    ...(statement.layoutVersion === undefined ||
    statement.varType === undefined ||
    statement.required === undefined ||
    statement.description === undefined
      ? {}
      : {
          schema: {
            varType: statement.varType,
            required: statement.required ? ("true" as const) : ("false" as const),
            description: statement.description,
            maxAgeDays:
              statement.maxAgeDays === undefined || statement.maxAgeDays === null
                ? ""
                : String(statement.maxAgeDays),
          },
        }),
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    authorUserId: testUserId(authorUserId),
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
  };
}

export async function signMetaStatementAs<
  T extends Omit<WireVariableMetaStatement, "signatureHex" | "variableId"> & {
    readonly variableId?: string;
  },
>(authorUserId: string, projectId: string, unsigned: T): Promise<T & { signatureHex: string }> {
  const keys = vectorKeyOf(authorUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signMetaStatement({
      context: metaContextOf(projectId, unsigned, authorUserId),
      signingKey: pair.privateKey,
    }),
    "signMetaStatement",
  );
  return { ...unsigned, signatureHex };
}

export async function metaSignedBytesHashOf(
  projectId: string,
  statement: Omit<WireVariableMetaStatement, "variableId"> & { readonly variableId?: string },
  authorUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeMetaSignedBytesHash(metaContextOf(projectId, statement, authorUserId)),
    "computeMetaSignedBytesHash",
  );
}

export interface WireDigestEntry {
  readonly variableId: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

export interface WireEnvironmentManifest {
  readonly suite: typeof SUITE_ID;
  readonly environmentId: string;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export async function digestOf(entries: readonly WireDigestEntry[]): Promise<string> {
  return unwrapResult(
    await computeVariablesDigest(
      SUITE_ID,
      entries.map((entry) => ({ ...entry, variableId: testVariableId(entry.variableId) })),
    ),
    "computeVariablesDigest",
  );
}

function manifestContextOf(
  projectId: string,
  manifest: Omit<WireEnvironmentManifest, "signatureHex">,
  issuerUserId: string,
) {
  return {
    suite: manifest.suite,
    projectId: testProjectId(projectId),
    environmentId: testEnvironmentId(manifest.environmentId),
    epoch: manifest.epoch,
    manifestVersion: manifest.manifestVersion,
    variablesDigestHex: manifest.variablesDigestHex,
    envMetaVersion: manifest.envMetaVersion,
    envMetaSigHashHex: manifest.envMetaSigHashHex,
    prevManifestSigHashHex: manifest.prevManifestSigHashHex,
    issuerUserId: testUserId(issuerUserId),
    chainHeadHashHex: manifest.chainHeadHashHex,
    chainHeadSeq: manifest.chainHeadSeq,
  };
}

export async function signEnvManifestAs(
  issuerUserId: string,
  projectId: string,
  unsigned: Omit<WireEnvironmentManifest, "signatureHex">,
): Promise<WireEnvironmentManifest> {
  const keys = vectorKeyOf(issuerUserId);
  const pair = unwrapResult(
    await importSigningKeyPair({
      publicKey: hexBytes(keys.sig_pub_hex),
      privateSeed: hexBytes(keys.sig_sk_seed_hex),
    }),
    "importSigningKeyPair",
  );
  const signatureHex = unwrapResult(
    await signEnvManifest({
      context: manifestContextOf(projectId, unsigned, issuerUserId),
      signingKey: pair.privateKey,
    }),
    "signEnvManifest",
  );
  return { ...unsigned, signatureHex };
}

export async function manifestSignedBytesHashOf(
  projectId: string,
  manifest: WireEnvironmentManifest,
  issuerUserId: string,
): Promise<string> {
  return unwrapResult(
    await computeEnvManifestSignedBytesHash(manifestContextOf(projectId, manifest, issuerUserId)),
    "computeEnvManifestSignedBytesHash",
  );
}

export async function createVariableStatement(input: {
  readonly authorUserId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly head: ValueChainHead;
}): Promise<WireVariableMetaStatement> {
  return signMetaStatementAs(input.authorUserId, input.projectId, {
    suite: SUITE_ID,
    environmentId: testEnvironmentId(input.environmentId),
    variableId: testVariableId(input.variableId),
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

async function unwrapDistributedDek(input: {
  readonly recipientUserId: string;
  readonly wrapped: {
    readonly epoch: number;
    readonly encHex: string;
    readonly ciphertextHex: string;
  };
  readonly projectId: string;
  readonly environmentId: string;
}): Promise<Uint8Array> {
  const keys = vectorKeyOf(input.recipientUserId);
  const pair = unwrapResult(
    await importEncryptionKeyPair({
      publicKey: hexBytes(keys.enc_pub_hex),
      privateKey: hexBytes(keys.enc_sk_seed_hex),
    }),
    "importEncryptionKeyPair",
  );
  return unwrapResult(
    await unwrapDek({
      recipientKeyPair: pair,
      wrapped: {
        enc: hexBytes(input.wrapped.encHex),
        ciphertext: hexBytes(input.wrapped.ciphertextHex),
      },
      context: {
        projectId: testProjectId(input.projectId),
        environmentId: testEnvironmentId(input.environmentId),
        epoch: input.wrapped.epoch,
        recipientUserId: testUserId(input.recipientUserId),
      },
    }),
    "unwrapDek",
  );
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
  const dek = await unwrapDistributedDek(input);
  const plaintext = unwrapResult(
    await decryptVariable({
      dek,
      context: {
        projectId: testProjectId(input.payload.aad.projectId),
        environmentId: testEnvironmentId(input.payload.aad.environmentId),
        epoch: input.payload.aad.epoch,
        variableId: testVariableId(input.payload.aad.variableId),
        version: input.payload.aad.version,
      },
      nonce: hexBytes(input.payload.nonceHex),
      ciphertext: hexBytes(input.payload.ciphertextHex),
    }),
    "decryptVariable",
  );
  return new TextDecoder().decode(plaintext);
}
