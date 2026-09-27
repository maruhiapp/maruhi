// Real crypto helpers for data-plane integration tests (run inside workerd).
//
// Real data is built using only the public API of packages/crypto: chain
// entries are signed at test time with the test vectors' fixed keys
// (chain-entries.json's keys), and DEK generation → HPKE wrap → AES-GCM
// encryption → client-side decryption are all executed for real.
// Only acceptance-policy tests that rely on "the server cannot verify the
// contents" use fake ciphertexts (noted in each test).
// The shared core of chain assembly and wire values lives in
// @maruhi/crypto/test-support (shared with the cli test support — session-11 §5 ruling).

import type {
  ChainEntry,
  ChainOperation,
  EnvValuesDigestEntry,
  MetaStatementTarget,
  UnsignedChainEntry,
  VariableContext,
} from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeDekCommitment,
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
  unwrapResult,
  valueContextOf,
  vectorKeys,
} from "@maruhi/crypto/test-support";

export type { BuiltChain, WireEncryptedPayload };
export { hexBytes, valueSignedBytesHashOf } from "@maruhi/crypto/test-support";

/**
 * Key borrowing for user IDs not in the fixed vector key set. The data
 * fixture's reader (user-reader-0003) uses the third vector key (nominally
 * user-admin-0003) — binding between a key and a user ID is done by the
 * chain's add_member, so the vector JSON's nominal user and the test user ID
 * may be independent.
 */
const VECTOR_KEY_ALIASES: Record<string, string> = {
  "user-reader-0003": "user-admin-0003",
};

/**
 * Device key substitution (2026-09-19 DK — K3 test): overrides, per user_id,
 * "the key currently used for signing" with a vector key name
 * (`user-owner-0001@phone` etc.). Subsequent signEntryAt / signValueAs /
 * signMetaStatementAs / signEnvManifestAs / signWrapAs sign with that device
 * key (the actor FP is also that key's). Pass null to clear. data-scenario's
 * beforeEach clears them all.
 */
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

/** Look up a vector key by name (includes device keys `<user>@<label>`). */
export function vectorKeyNamed(name: string) {
  const keys = vectorKeys[name];
  if (keys === undefined) {
    throw new Error(`no vector keys named ${name}`);
  }
  return keys;
}

/** The fixed vector key users (user-owner-0001 / user-member-0002 / user-admin-0003 + borrowers). */
export function vectorKeyOf(userId: string) {
  const keys = vectorKeys[deviceKeyOverrides.get(userId) ?? VECTOR_KEY_ALIASES[userId] ?? userId];
  if (keys === undefined) {
    throw new Error(`no vector keys for ${userId}`);
  }
  return keys;
}

/** Look up a vector key by FP (from all keys including device keys; undefined if none). */
function vectorKeyByFingerprint(fingerprintHex: string) {
  return Object.values(vectorKeys).find((keys) => keys.key_fingerprint_hex === fingerprintHex);
}

/**
 * Sign an entry with a vector seed. If the actor block's FP matches any
 * vector key (including device keys), sign with that key (after DK a single
 * user can hold multiple device keys, so "actor.user_id's key" cannot
 * reproduce device signing). Unknown FPs fall back to the user_id's key
 * (preserving the FP-mismatch negative semantics).
 */
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

/** Build one entry with a test-time signature to follow the tail of an existing chain. */
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
    actor: { userId: input.actorUserId, keyFingerprintHex: keys.key_fingerprint_hex },
    timestampMs: BASE_TIME_MS + input.seq * 1000,
  };
  const entry = await signAs(input.actorUserId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

/**
 * Re-sign an existing entry (vector main line or negative) keeping its op /
 * payload / actor while renumbering seq / prev. For replaying against the API
 * after the head has drifted from the vector's fixed seq due to a composite
 * boundary checkpoint insertion (AUTH_SPEC §12-4). The actor block keeps the
 * original (preserving the key-FP-mismatch negative semantics). When seq /
 * prev / timestamp match the original, Ed25519 determinism makes the bytes
 * identical to the original.
 */
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
    // approve's timestamp_ms is an input to the consensus rule (§6.2
    // `proposal-expired` — the only place this spec uses a timestamp), so keep
    // the original. Other ops get the deterministic value derived from seq
    timestampMs: base.op === "approve" ? base.timestampMs : BASE_TIME_MS + seq * 1000,
  };
  const entry = await signAs(base.actor.userId, unsigned);
  return { entry, hash: await computeChainEntryHash(entry) };
}

/** Assemble a valid chain with test-time signatures (seq / prev_hash / timestamp are automatic). */
export async function buildChain(steps: readonly ChainStep[]): Promise<BuiltChain> {
  return buildChainWith(
    steps.map((step) => ({
      actor: {
        userId: step.actorUserId,
        keyFingerprintHex: vectorKeyOf(step.actorUserId).key_fingerprint_hex,
      },
      operation: step.operation,
      signEntry: (unsigned) => signAs(step.actorUserId, unsigned),
    })),
  );
}

/** Payload for genesis (the actor's own public key set). */
export function genesisOperation(userId: string): ChainOperation {
  const keys = vectorKeyOf(userId);
  return {
    op: "genesis",
    payload: { encPubHex: keys.enc_pub_hex, sigPubHex: keys.sig_pub_hex },
  };
}

/**
 * Test representation of a member's scope (CRYPTO_SPEC §6.2 — 2026-09-14 ES):
 * omitted = all, array = listed (empty array = listed{}).
 */
export type TestScope = readonly string[] | undefined;

/** Map the scope test representation onto the wire's two fields. */
function scopeFieldsOf(scope: TestScope): {
  readonly scopeKind: "all" | "listed";
  readonly scopeEnvironmentIds: readonly string[];
} {
  return scope === undefined
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: scope };
}

/** Payload for add_member (the target's vector public key set; scope omitted = all). */
export function addMemberOperation(
  targetUserId: string,
  role: "owner" | "admin" | "member" | "reader",
  scope?: TestScope,
): ChainOperation {
  const keys = vectorKeyOf(targetUserId);
  return {
    op: "add_member",
    payload: {
      targetUserId,
      encPubHex: keys.enc_pub_hex,
      sigPubHex: keys.sig_pub_hex,
      role,
      ...scopeFieldsOf(scope),
    },
  };
}

/** Payload for change_role (full replacement of (role, scope) — CRYPTO_SPEC §6.2; scope omitted = all). */
export function changeRoleOperation(
  targetUserId: string,
  newRole: "owner" | "admin" | "member" | "reader",
  scope?: TestScope,
): ChainOperation {
  return {
    op: "change_role",
    payload: { targetUserId, newRole, ...scopeFieldsOf(scope) },
  };
}

/** The §5.2 commitment (hex lowercase, 64 chars). */
export async function commitmentOf(
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

/** Payload for create_environment (with the epoch-1 commitment — §6.2). */
export function createEnvironmentOperation(
  environmentId: string,
  dekCommitmentHex: string,
): ChainOperation {
  return { op: "create_environment", payload: { environmentId, dekCommitmentHex } };
}

/** Canonical computation of values_digest (§6.2 — value-level latest form of active variables; empty set allowed). */
export async function valuesDigestOf(entries: readonly EnvValuesDigestEntry[]): Promise<string> {
  return unwrapResult(await computeEnvValuesDigest(SUITE_ID, entries), "computeEnvValuesDigest");
}

/**
 * Operation for a boundary checkpoint (one tuple for the environment +
 * empty audit head — AUTH_SPEC §12-4 / CRYPTO_SPEC §6.3). Overriding the
 * audit head and multiple tuples is allowed for negatives.
 */
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
          environmentId: input.environmentId,
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

/** Payload for rotate_epoch (with the new epoch's commitment — §6.2). */
export function rotateEpochOperation(
  environmentId: string,
  newEpoch: number,
  dekCommitmentHex: string,
  reason = "scheduled",
): ChainOperation {
  return { op: "rotate_epoch", payload: { environmentId, newEpoch, reason, dekCommitmentHex } };
}

/** A new environment epoch DEK (256-bit random). */
export function makeDek(): Uint8Array {
  return generateDek();
}

export interface WireWrappedDek {
  readonly suite: string;
  readonly epoch: number;
  /** Recipient class (AUTH_SPEC §12-6; omitted = member). */
  readonly recipientClass?: "member" | "server";
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/**
 * Add a registration signature (CRYPTO_SPEC §5.1) to an unsigned wire
 * representation. The signer is a fixed-vector-key user (= must match the
 * caller of the API — §12-6). Also used by fake-wrap acceptance-policy tests
 * (the server cannot verify the contents but does verify the signature, so
 * even fakes need the caller's signature).
 */
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
        projectId,
        environmentId,
        epoch: wrap.epoch,
        recipientUserId: wrap.recipientUserId,
        recipientEncPubHex: wrap.recipientEncPubHex,
        encHex: wrap.encHex,
        ciphertextHex: wrap.ciphertextHex,
        signerUserId,
      },
      signingKey: pair.privateKey,
    }),
    "signDekWrap",
  );
  return { ...wrap, signatureHex };
}

/**
 * Verify a distributed wrap's registration signature on the client side
 * (CRYPTO_SPEC §5.1). The verification key is "the sig public key bound to
 * the signer user_id on the chain" — tests pull it from the fixed vector keys.
 */
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
      projectId: input.projectId,
      environmentId: input.environmentId,
      epoch: input.wrap.epoch,
      recipientUserId: input.recipientUserId,
      recipientEncPubHex: input.recipientEncPubHex,
      encHex: input.wrap.encHex,
      ciphertextHex: input.wrap.ciphertextHex,
      signerUserId: input.wrap.signerUserId,
    },
    signatureHex: input.wrap.signatureHex,
    signerPublicKey: publicKey,
  });
  return result.ok;
}

/** HPKE-wrap a DEK to one recipient and return the wire representation with the signer's registration signature (§12-2). */
export async function wrapDekTo(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
  /** The registration-signature signer. Must match the caller of the API (the §12-6 acceptance condition). */
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
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.epoch,
        recipientUserId: input.recipientUserId,
      },
    }),
    "wrapDek",
  );
  return signWrapAs(input.signerUserId, input.projectId, input.environmentId, {
    suite: SUITE_ID,
    epoch: input.epoch,
    recipientUserId: input.recipientUserId,
    recipientEncPubHex: encPubHex,
    encHex: encodeHex(wrapped.enc),
    ciphertextHex: encodeHex(wrapped.ciphertext),
  });
}

/**
 * A wrap with recipient class server (AUTH_SPEC §12-6 / CRYPTO_SPEC §9): the
 * server key FP is used in the HPKE info and in the registration signature's
 * recipient position. Wrap and signature assembly take the same path as
 * member (only the recipientUserId position is replaced), and the wire
 * carries recipientClass: "server".
 */
export async function wrapDekToServer(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly serverKeyFingerprintHex: string;
  readonly serverEncPubHex: string;
  /** The registration-signature signer. Must match the caller of the API (the §12-6 acceptance condition). */
  readonly signerUserId: string;
}): Promise<WireWrappedDek> {
  const wrap = await wrapDekTo({
    projectId: input.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    dek: input.dek,
    recipientUserId: input.serverKeyFingerprintHex,
    recipientEncPubHex: input.serverEncPubHex,
    signerUserId: input.signerUserId,
  });
  return { ...wrap, recipientClass: "server" };
}

/** Wrap a DEK to multiple recipients (for the complete set on environment creation / rotation). */
export async function wrapDekForAll(input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
  readonly recipientUserIds: readonly string[];
  /** The registration-signature signer. Must match the caller of the API (the §12-6 acceptance condition). */
  readonly signerUserId: string;
}): Promise<WireWrappedDek[]> {
  const wraps: WireWrappedDek[] = [];
  for (const recipientUserId of input.recipientUserIds) {
    wraps.push(await wrapDekTo({ ...input, recipientUserId }));
  }
  return wraps;
}

/** The declared head of a value signature (the chain head last verified at signing time — §4.1). */
export interface ValueChainHead {
  readonly seq: number;
  readonly hashHex: string;
}

/**
 * Add a §4.1 value signature to an unsigned wire value (the signer must
 * match the caller of the API — §12-5). Also used by fake-ciphertext
 * acceptance-policy tests (the server cannot decrypt the contents but does
 * verify the value signature, so even fakes need a correct signature by the
 * caller's real key).
 */
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

/** Encrypt a variable value with a DEK and return the wire representation with a §4.1 value signature (§12-2). */
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

// ---------------------------------------------------------------------------
// Test-time signing of metadata statements (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2)
// ---------------------------------------------------------------------------

/**
 * Wire representation of a variable statement (VariableMetaStatement —
 * §12-2). In layout v2, layoutVersion and the four schema fields are all
 * present together (in v1 all are absent; required is a wire boolean).
 */
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
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/** Wire representation of an environment statement (EnvironmentMetaStatement — §12-2; stays v1). */
export type WireEnvironmentMetaStatement = Omit<
  WireVariableMetaStatement,
  "variableId" | "layoutVersion" | "varType" | "required" | "description"
> & { readonly status: "active" | "deleted" };

function metaTargetOf(statement: { readonly variableId?: string }): MetaStatementTarget {
  return statement.variableId === undefined
    ? { kind: "environment" }
    : { kind: "variable", variableId: statement.variableId };
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
    projectId,
    environmentId: statement.environmentId,
    target: metaTargetOf(statement),
    name: statement.name,
    status: statement.status,
    // Layout-v2 carrier fields → signature target (required is "true"/"false" —
    // the LP field representation of CRYPTO_SPEC §4.2)
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
          },
        }),
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    authorUserId,
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
  };
}

/**
 * Add a §4.2 author signature to an unsigned statement (the signer must
 * match the caller of the API — the §12-5 meta rule). Handles both shapes:
 * variable (with variableId) and environment (without).
 */
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

/**
 * SHA-256 of meta_signed_bytes (used for the next metaVersion's
 * prevMetaSigHashHex — the §4.2 chain). author does not appear on the wire,
 * so it is specified explicitly.
 */
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

// ---------------------------------------------------------------------------
// Environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5)
// ---------------------------------------------------------------------------

/** One entry of variables_digest (§4.3 — the latest form of every variable, tombstones included). */
export interface WireDigestEntry {
  readonly variableId: string;
  readonly status: "active" | "deleted" | "declared";
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/** Wire representation of an environment manifest (EnvironmentManifest — §12-2). */
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

/** Canonical computation of variables_digest (empty set allowed — §4.3). */
export async function digestOf(entries: readonly WireDigestEntry[]): Promise<string> {
  return unwrapResult(await computeVariablesDigest(SUITE_ID, entries), "computeVariablesDigest");
}

function manifestContextOf(
  projectId: string,
  manifest: Omit<WireEnvironmentManifest, "signatureHex">,
  issuerUserId: string,
) {
  return {
    suite: manifest.suite,
    projectId,
    environmentId: manifest.environmentId,
    epoch: manifest.epoch,
    manifestVersion: manifest.manifestVersion,
    variablesDigestHex: manifest.variablesDigestHex,
    envMetaVersion: manifest.envMetaVersion,
    envMetaSigHashHex: manifest.envMetaSigHashHex,
    prevManifestSigHashHex: manifest.prevManifestSigHashHex,
    issuerUserId,
    chainHeadHashHex: manifest.chainHeadHashHex,
    chainHeadSeq: manifest.chainHeadSeq,
  };
}

/**
 * Add a §4.3 issuer signature to an unsigned manifest (the signer must match
 * the caller of the API — §12-5 (1)).
 */
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

/**
 * SHA-256 of env_manifest_signed_bytes (used for the next manifestVersion's
 * prevManifestSigHashHex — the §4.3 chain). issuer does not appear on the
 * wire, so it is specified explicitly.
 */
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

/** Sign and return the statement bundled with variable creation (metaVersion 1, active, empty prev). */
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
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: input.name,
    status: "active" as const,
    metaVersion: 1,
    prevMetaSigHashHex: "",
    chainHeadHashHex: input.head.hashHex,
    chainHeadSeq: input.head.seq,
  });
}

/**
 * First half of the client-side receive path: Open the wrapped DEK addressed
 * to oneself with a fixed vector key and return the DEK (material for the
 * §5.2 commitment check and decryption).
 */
export async function unwrapDistributedDek(input: {
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
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.wrapped.epoch,
        recipientUserId: input.recipientUserId,
      },
    }),
    "unwrapDek",
  );
}

/**
 * Client-side receive path: Open the wrapped DEK addressed to oneself and
 * decrypt the EncryptedPayload with it (push→pull→decrypt round-trip check).
 */
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
      context: input.payload.aad,
      nonce: hexBytes(input.payload.nonceHex),
      ciphertext: hexBytes(input.payload.ciphertextHex),
    }),
    "decryptVariable",
  );
  return new TextDecoder().decode(plaintext);
}
