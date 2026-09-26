// Real crypto fixtures for tests (public @maruhi/crypto API only).
// Builds real data — chain signatures, DEK wraps, value encryption — from
// freshly generated keys each run.
// The shared core for chain assembly and wire values lives in
// @maruhi/crypto/test-support (shared with the server test support —
// session-11 §5 ruling).

import type {
  ApprovalTargetOp,
  ChainOperation,
  EncryptionKeyPair,
  GrantServerPayload,
  ProposableOperation,
  SigningKeyPair,
} from "@maruhi/crypto";
import {
  computeDekCommitment,
  computeEnvManifestSignedBytesHash,
  computeMetaSignedBytesHash,
  computeUserKeyFingerprint,
  computeVariablesDigest,
  encodeHex,
  encryptVariable,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  importEncryptionPublicKey,
  signChainEntry,
  signDekWrap,
  signEnvManifest,
  signMetaStatement,
  signValue,
  SUITE_ID,
  wrapDek,
} from "@maruhi/crypto";
import type {
  BuiltChain,
  LazyChainOperation,
  WireEncryptedPayload as SharedWireEncryptedPayload,
} from "@maruhi/crypto/test-support";
import {
  buildChainWith,
  hexBytes,
  unwrapResult,
  valueSignedBytesHashOf,
} from "@maruhi/crypto/test-support";

export type { BuiltChain, LazyChainOperation };
export { hexBytes, valueSignedBytesHashOf as valueHashOf } from "@maruhi/crypto/test-support";

/** A test user with freshly generated (exportable) master keys. */
export interface TestUser {
  readonly userId: string;
  readonly encPubHex: string;
  readonly encSkHex: string;
  readonly sigPubHex: string;
  readonly sigSkSeedHex: string;
  readonly fingerprintHex: string;
  readonly encKeyPair: EncryptionKeyPair;
  readonly sigKeyPair: SigningKeyPair;
}

export async function makeTestUser(userId: string): Promise<TestUser> {
  const encKeyPair = await generateEncryptionKeyPair({ extractable: true });
  const sigKeyPair = await generateSigningKeyPair({ extractable: true });
  const encPub = await exportEncryptionPublicKey(encKeyPair.publicKey);
  const sigPub = await exportSigningPublicKey(sigKeyPair.publicKey);
  const encSk = unwrapResult(await exportEncryptionPrivateKey(encKeyPair.privateKey), "exportEnc");
  const sigSeed = unwrapResult(await exportSigningPrivateSeed(sigKeyPair.privateKey), "exportSig");
  const fingerprint = unwrapResult(await computeUserKeyFingerprint(encPub, sigPub), "fingerprint");
  return {
    userId,
    encPubHex: encodeHex(encPub),
    encSkHex: encodeHex(encSk),
    sigPubHex: encodeHex(sigPub),
    sigSkSeedHex: encodeHex(sigSeed),
    fingerprintHex: encodeHex(fingerprint),
    encKeyPair,
    sigKeyPair,
  };
}

export interface ChainStep {
  readonly actor: TestUser;
  readonly operation: ChainOperation | LazyChainOperation;
}

/** Builds a valid signed chain (seq / prev_hash / timestamp are automatic). */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: { userId: step.actor.userId, keyFingerprintHex: step.actor.fingerprintHex },
      operation: step.operation,
      signEntry: async (unsigned) =>
        unwrapResult(
          await signChainEntry({ entry: unsigned, signingKey: step.actor.sigKeyPair.privateKey }),
          "signChainEntry",
        ),
    })),
  );
}

export function genesisOp(user: TestUser): ChainOperation {
  return { op: "genesis", payload: { encPubHex: user.encPubHex, sigPubHex: user.sigPubHex } };
}

/** add_device(cap (owner, all) — the reserve-key enrollment shape. actor is a valid device of the same person — CRYPTO_SPEC §6.2). */
export function addOwnerDeviceOp(device: TestUser): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: "owner",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  };
}

export function addMemberOp(
  target: TestUser,
  role: "owner" | "admin" | "member" | "reader",
): ChainOperation {
  return {
    op: "add_member",
    payload: {
      targetUserId: target.userId,
      encPubHex: target.encPubHex,
      sigPubHex: target.sigPubHex,
      role,
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  };
}

/** add_member(listed scope — the ES of CRYPTO_SPEC §6.2; environments are signed in ascending order). */
export function addScopedMemberOp(
  target: TestUser,
  role: "admin" | "member" | "reader",
  environmentIds: readonly string[],
): ChainOperation {
  return {
    op: "add_member",
    payload: {
      targetUserId: target.userId,
      encPubHex: target.encPubHex,
      sigPubHex: target.sigPubHex,
      role,
      scopeKind: "listed",
      scopeEnvironmentIds: [...environmentIds].toSorted(),
    },
  };
}

/** change_role (full replacement of (role, scope) — §6.2). `environmentIds = null` means all. */
export function changeRoleOp(
  target: TestUser,
  role: "owner" | "admin" | "member" | "reader",
  environmentIds: readonly string[] | null,
): ChainOperation {
  return {
    op: "change_role",
    payload: {
      targetUserId: target.userId,
      newRole: role,
      scopeKind: environmentIds === null ? "all" : "listed",
      scopeEnvironmentIds: environmentIds === null ? [] : [...environmentIds].toSorted(),
    },
  };
}

export function removeMemberOp(target: TestUser): ChainOperation {
  return { op: "remove_member", payload: { targetUserId: target.userId } };
}

/** The §5.2 commitment (64 lowercase hex chars). */
async function dekCommitmentFor(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<string> {
  return unwrapResult(
    await computeDekCommitment({
      context: { suite: SUITE_ID, projectId, environmentId, epoch },
      dek,
    }),
    "computeDekCommitment",
  );
}

/**
 * create_environment (with the epoch-1 commitment — §6.2). Because the
 * commitment is computed from the fixture's real DEK, the pull side's §5.2
 * check passes on real data.
 */
export function createEnvironmentOp(environmentId: string, dek: Uint8Array): LazyChainOperation {
  return async (projectId) => ({
    op: "create_environment",
    payload: {
      environmentId,
      dekCommitmentHex: await dekCommitmentFor(projectId, environmentId, 1, dek),
    },
  });
}

/** rotate_epoch (with the new epoch's commitment — §6.2). */
export function rotateEpochOp(
  environmentId: string,
  newEpoch: number,
  dek: Uint8Array,
): LazyChainOperation {
  return async (projectId) => ({
    op: "rotate_epoch",
    payload: {
      environmentId,
      newEpoch,
      reason: "test",
      dekCommitmentHex: await dekCommitmentFor(projectId, environmentId, newEpoch, dek),
    },
  });
}

/** grant_server (the server key is randomly generated; FP = SHA-256(enc)[:16] — §9). */
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
      serverKeyFingerprintHex: encodeHex(digest.slice(0, 16)),
      scopeEnvironmentIds: [...scopeEnvironmentIds],
      leasePolicy,
    },
  };
}

/** revoke_server (§6.2 — the revocation target is identified by server-key FP). */
export function revokeServerOp(serverKeyFingerprintHex: string): ChainOperation {
  return { op: "revoke_server", payload: { serverKeyFingerprintHex } };
}

/** Wire representation of the RecipientDek shape (distribution response). */
export interface WireRecipientDek {
  readonly suite: "maruhi/v1";
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: string;
  readonly signerKeyFingerprintHex: string;
}

/** HPKE-wraps a DEK for the recipient and returns it in the distributed form with the signer's registration signature (§12-2). */
export async function wrapDekFor(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipient: TestUser;
  readonly signer: TestUser;
}): Promise<WireRecipientDek> {
  const publicKey = unwrapResult(
    await importEncryptionPublicKey(hexBytes(input.recipient.encPubHex)),
    "importEncryptionPublicKey",
  );
  const wrapped = unwrapResult(
    await wrapDek({
      recipientPublicKey: publicKey,
      dek: input.dek,
      context: {
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        recipientUserId: input.recipient.userId,
      },
    }),
    "wrapDek",
  );
  const encHex = encodeHex(wrapped.enc);
  const ciphertextHex = encodeHex(wrapped.ciphertext);
  const signatureHex = unwrapResult(
    await signDekWrap({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        recipientUserId: input.recipient.userId,
        recipientEncPubHex: input.recipient.encPubHex,
        encHex,
        ciphertextHex,
        signerUserId: input.signer.userId,
      },
      signingKey: input.signer.sigKeyPair.privateKey,
    }),
    "signDekWrap",
  );
  return {
    suite: SUITE_ID,
    epoch: input.epoch,
    encHex,
    ciphertextHex,
    signatureHex,
    signerUserId: input.signer.userId,
    signerKeyFingerprintHex: input.signer.fingerprintHex,
  };
}

/** Wire representation of the EncryptedPayload shape (with the §4.1 signature block — §12-2). */
export interface WireEncryptedPayload extends SharedWireEncryptedPayload {
  /** CLI tests always build wires of the canonical suite (the shared type is string — for verification negatives). */
  readonly suite: "maruhi/v1";
}

/** The distributed form (DistributedEncryptedPayload — includes the writer's verification material). */
export interface WireDistributedValue extends WireEncryptedPayload {
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/** The layout-v2 schema fields (wire form — §12-2; required is boolean). */
export interface WireStatementSchema {
  readonly varType: "" | "string" | "number" | "boolean" | "url";
  readonly required: boolean;
  readonly description: string;
}

/** The distributed variable meta statement (DistributedVariableMetaStatement — §12-2). */
export interface WireDistributedVariableStatement {
  readonly suite: "maruhi/v1";
  readonly environmentId: string;
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
  /** Layout-v2 carrier fields (§12-2 — all four absent in v1). */
  readonly layoutVersion?: number;
  readonly varType?: WireStatementSchema["varType"];
  readonly required?: boolean;
  readonly description?: string;
}

/** The distributed environment meta statement (same shape minus variableId and the v2 fields). */
export interface WireDistributedEnvironmentStatement {
  readonly suite: "maruhi/v1";
  readonly environmentId: string;
  readonly name: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

interface StatementInputBase {
  readonly projectId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly author: TestUser;
  readonly head: { readonly seq: number; readonly hashHex: string };
  readonly status?: "active" | "deleted" | "declared";
  readonly metaVersion?: number;
  readonly prevMetaSigHashHex?: string;
  /** Layout-v2 schema fields (passing one signs it as a v2 statement). */
  readonly schema?: WireStatementSchema;
}

async function signDistributedStatement(
  input: StatementInputBase,
  target: { kind: "variable"; variableId: string } | { kind: "environment" },
): Promise<WireDistributedEnvironmentStatement & Partial<WireStatementSchema>> {
  const status = input.status ?? "active";
  const metaVersion = input.metaVersion ?? 1;
  const prevMetaSigHashHex = input.prevMetaSigHashHex ?? (metaVersion === 1 ? "" : "cd".repeat(32));
  const signatureHex = unwrapResult(
    await signMetaStatement({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        target,
        name: input.name,
        status,
        // v2 (§4.2): the signed required is an explicit string ("true" | "false")
        ...(input.schema === undefined
          ? {}
          : {
              layoutVersion: 2,
              schema: {
                varType: input.schema.varType,
                required: input.schema.required ? ("true" as const) : ("false" as const),
                description: input.schema.description,
              },
            }),
        metaVersion,
        prevMetaSigHashHex,
        authorUserId: input.author.userId,
        chainHeadHashHex: input.head.hashHex,
        chainHeadSeq: input.head.seq,
      },
      signingKey: input.author.sigKeyPair.privateKey,
    }),
    "signMetaStatement",
  );
  return {
    suite: SUITE_ID,
    environmentId: input.environmentId,
    name: input.name,
    status,
    metaVersion,
    prevMetaSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    signatureHex,
    authorUserId: input.author.userId,
    authorKeyFingerprintHex: input.author.fingerprintHex,
    ...(input.schema === undefined ? {} : { layoutVersion: 2, ...input.schema }),
  };
}

/**
 * Signs a variable meta statement (§4.2) with the author key and returns it in
 * the distributed form (with author info — §12-2). Defaults to the creation
 * shape (metaVersion 1, active, empty prev, v1 layout). Passing `schema` signs
 * it as layout v2 (with schema fields).
 */
export async function statementFor(
  input: StatementInputBase & { readonly variableId: string },
): Promise<WireDistributedVariableStatement> {
  const statement = await signDistributedStatement(input, {
    kind: "variable",
    variableId: input.variableId,
  });
  return { ...statement, variableId: input.variableId };
}

/** The distributed form of an environment meta statement (same shape minus the variableId field). */
export async function environmentStatementFor(
  input: StatementInputBase,
): Promise<WireDistributedEnvironmentStatement> {
  return signDistributedStatement(input, { kind: "environment" });
}

/** The distributed environment manifest (DistributedEnvironmentManifest — §12-2). */
export interface WireDistributedManifest {
  readonly suite: "maruhi/v1";
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
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}

/** Distributed statement → signed-bytes hash (material for digests and envMeta). */
export async function statementHashOf(
  projectId: string,
  statement: WireDistributedEnvironmentStatement & {
    readonly variableId?: string;
  } & Partial<WireStatementSchema> & { readonly layoutVersion?: number },
): Promise<string> {
  return unwrapResult(
    await computeMetaSignedBytesHash({
      suite: statement.suite,
      projectId,
      environmentId: statement.environmentId,
      target:
        statement.variableId === undefined
          ? { kind: "environment" }
          : { kind: "variable", variableId: statement.variableId },
      name: statement.name,
      status: statement.status,
      ...(statement.layoutVersion === undefined ||
      statement.varType === undefined ||
      statement.required === undefined ||
      statement.description === undefined
        ? {}
        : {
            layoutVersion: statement.layoutVersion,
            schema: {
              varType: statement.varType,
              required: statement.required ? ("true" as const) : ("false" as const),
              description: statement.description,
            },
          }),
      metaVersion: statement.metaVersion,
      prevMetaSigHashHex: statement.prevMetaSigHashHex,
      authorUserId: statement.authorUserId,
      chainHeadHashHex: statement.chainHeadHashHex,
      chainHeadSeq: statement.chainHeadSeq,
    }),
    "computeMetaSignedBytesHash",
  );
}

/** Set of distributed statements (tombstones included) → variables_digest (§4.3 (3)). */
export async function variablesDigestOf(
  projectId: string,
  statements: readonly WireDistributedVariableStatement[],
): Promise<string> {
  const entries = await Promise.all(
    statements.map(async (statement) => ({
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: await statementHashOf(projectId, statement),
    })),
  );
  return unwrapResult(await computeVariablesDigest(SUITE_ID, entries), "computeVariablesDigest");
}

/**
 * Signs an environment manifest (§4.3) with the issuer key and returns it in
 * the distributed form (with issuer info — §12-2). The digest is computed for
 * real from the given distributed statements (tombstones included) — pass the
 * same set as the pull-response fixture's statements / deletedVariables (a
 * mismatch makes the client's digest recomputation reject = that is itself a
 * way to build a negative).
 */
export async function manifestFor(input: {
  readonly projectId: string;
  readonly environmentId: string;
  /** The current epoch at issuance (the §4.3 freshness anchor). */
  readonly epoch: number;
  readonly issuer: TestUser;
  readonly head: { readonly seq: number; readonly hashHex: string };
  readonly envStatement: WireDistributedEnvironmentStatement;
  /** The active + tombstone distributed statements (digest input). */
  readonly statements?: readonly WireDistributedVariableStatement[];
  readonly manifestVersion?: number;
  readonly prevManifestSigHashHex?: string;
  /** Digest override (for digest-mismatch negatives). */
  readonly variablesDigestHex?: string;
}): Promise<WireDistributedManifest> {
  const variablesDigestHex =
    input.variablesDigestHex ?? (await variablesDigestOf(input.projectId, input.statements ?? []));
  const context = {
    suite: SUITE_ID,
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion: input.manifestVersion ?? 1,
    variablesDigestHex,
    envMetaVersion: input.envStatement.metaVersion,
    envMetaSigHashHex: await statementHashOf(input.projectId, input.envStatement),
    prevManifestSigHashHex:
      input.prevManifestSigHashHex ?? ((input.manifestVersion ?? 1) === 1 ? "" : "cd".repeat(32)),
    issuerUserId: input.issuer.userId,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  } as const;
  const signatureHex = unwrapResult(
    await signEnvManifest({ context, signingKey: input.issuer.sigKeyPair.privateKey }),
    "signEnvManifest",
  );
  return {
    suite: SUITE_ID,
    environmentId: context.environmentId,
    epoch: context.epoch,
    manifestVersion: context.manifestVersion,
    variablesDigestHex: context.variablesDigestHex,
    envMetaVersion: context.envMetaVersion,
    envMetaSigHashHex: context.envMetaSigHashHex,
    prevManifestSigHashHex: context.prevManifestSigHashHex,
    chainHeadHashHex: context.chainHeadHashHex,
    chainHeadSeq: context.chainHeadSeq,
    signatureHex,
    issuerUserId: context.issuerUserId,
    issuerKeyFingerprintHex: input.issuer.fingerprintHex,
  };
}

/**
 * Distributed manifest → signed-bytes hash (self-computed — §4.3). Material
 * for prevManifestSigHashHex when assembling fixtures that satisfy the
 * adjacent-version prev chain.
 */
export async function manifestHashOf(
  projectId: string,
  manifest: WireDistributedManifest,
): Promise<string> {
  return unwrapResult(
    await computeEnvManifestSignedBytesHash({
      suite: SUITE_ID,
      projectId,
      environmentId: manifest.environmentId,
      epoch: manifest.epoch,
      manifestVersion: manifest.manifestVersion,
      variablesDigestHex: manifest.variablesDigestHex,
      envMetaVersion: manifest.envMetaVersion,
      envMetaSigHashHex: manifest.envMetaSigHashHex,
      prevManifestSigHashHex: manifest.prevManifestSigHashHex,
      issuerUserId: manifest.issuerUserId,
      chainHeadHashHex: manifest.chainHeadHashHex,
      chainHeadSeq: manifest.chainHeadSeq,
    }),
    "computeEnvManifestSignedBytesHash",
  );
}

/** The distributed checkpointSnapshot (§12-7 / §14-2 — structurally identical to CheckpointValueSnapshot). */
export interface WireCheckpointSnapshot {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly values: readonly {
    readonly variableId: string;
    readonly version: number;
    readonly valueSigHashHex: string;
  }[];
}

/**
 * Set of distributed values → checkpoint snapshot listing (models "the latest
 * version of every active variable at acceptance time + value_signed_bytes
 * hash" that the server stores when accepting a checkpoint — §16-2). An
 * honest-server mock calls this with the distributed set at checkpoint
 * acceptance and includes it in subsequent pulls.
 */
export async function checkpointSnapshotValuesOf(
  values: readonly WireDistributedValue[],
): Promise<WireCheckpointSnapshot["values"]> {
  return Promise.all(
    values.map(async (value) => ({
      variableId: value.aad.variableId,
      version: value.aad.version,
      valueSigHashHex: await valueSignedBytesHashOf(value, value.writerUserId),
    })),
  );
}

/** A declared head on a BuiltChain (the entry hash at a seq position). */
export function headOf(built: BuiltChain, seq: number): { seq: number; hashHex: string } {
  const hashHex = built.hashes[seq - 1];
  if (hashHex === undefined) {
    throw new Error(`headOf: chain has no seq ${seq}`);
  }
  return { seq, hashHex };
}

/**
 * Encrypts a variable value with the DEK and returns it in the distributed
 * form (§12-2) with the writer's value signature (§4.1). The declared head is
 * the position of "the chain head the writer last verified at signing time".
 * For version > 1 the prev is specified by the test (default is a dummy 64
 * hex — pull is latest-only, so prev existence is out of scope — ruling B).
 */
export async function encryptValueFor(input: {
  readonly dek: Uint8Array;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  /** Plaintext (strings are UTF-8 encoded; bytes allowed for testing invalid UTF-8 sequences). */
  readonly plaintext: string | Uint8Array;
  readonly writer: TestUser;
  readonly head: { readonly seq: number; readonly hashHex: string };
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
  const context = {
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  const encrypted = unwrapResult(
    await encryptVariable({
      dek: input.dek,
      context,
      plaintext:
        typeof input.plaintext === "string"
          ? new TextEncoder().encode(input.plaintext)
          : input.plaintext,
    }),
    "encryptVariable",
  );
  const nonceHex = encodeHex(encrypted.nonce);
  const ciphertextHex = encodeHex(encrypted.ciphertext);
  const prevValueSigHashHex =
    input.prevValueSigHashHex ?? (input.version === 1 ? "" : "cd".repeat(32));
  const signatureHex = unwrapResult(
    await signValue({
      context: {
        suite: SUITE_ID,
        ...context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex,
        writerUserId: input.writer.userId,
        chainHeadHashHex: input.head.hashHex,
        chainHeadSeq: input.head.seq,
      },
      signingKey: input.writer.sigKeyPair.privateKey,
    }),
    "signValue",
  );
  return {
    suite: SUITE_ID,
    aad: context,
    nonceHex,
    ciphertextHex,
    prevValueSigHashHex,
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
    signatureHex,
    writerUserId: input.writer.userId,
    writerKeyFingerprintHex: input.writer.fingerprintHex,
  };
}

// ---------------------------------------------------------------------------
// The four-eyes 4 ops (CRYPTO_SPEC §6.2 — for PF1 K6 tests)
// ---------------------------------------------------------------------------

/** set_approval_policy (ops are signed in ascending order — a generation SHOULD). required 0 = off. */
export function setApprovalPolicyOp(
  ops: readonly ApprovalTargetOp[],
  requiredApprovals: number,
): ChainOperation {
  return {
    op: "set_approval_policy",
    payload: { ops: [...ops].toSorted(), requiredApprovals },
  };
}

/** propose (inner op and deadline). The default deadline is far in the future (year 2096). */
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

/** Treats an inner op as a ProposableOperation (nested proposes are invalid at the structural layer, so they're excluded by the type). */
export function innerOf(operation: ChainOperation): ProposableOperation {
  if (operation.op === "propose" || operation.op === "approve" || operation.op === "withdraw") {
    throw new Error(`${operation.op} cannot be proposed`);
  }
  return operation;
}
