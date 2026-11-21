import { encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId, UserId, VariableId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import type { MetaStatementStatus } from "./meta-sign.ts";
import { computeVariableKeyedDigest } from "./sorted-digest.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

export interface VariablesDigestEntry {
  readonly variableId: VariableId;
  readonly status: MetaStatementStatus;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

function digestEntryInvalidField(entry: VariablesDigestEntry): string | null {
  if (entry.variableId.length === 0) {
    return "entry variableId";
  }
  if (entry.status !== "active" && entry.status !== "deleted" && entry.status !== "declared") {
    return "entry status";
  }
  if (!Number.isSafeInteger(entry.metaVersion) || entry.metaVersion < 1) {
    return "entry metaVersion";
  }
  if (!isLowercaseHexOfLength(entry.metaSigHashHex, SHA256_HEX_LENGTH)) {
    return "entry metaSigHashHex";
  }
  return null;
}

export async function computeVariablesDigest(
  suite: string,
  entries: readonly VariablesDigestEntry[],
): Promise<CryptoResult<string>> {
  return computeVariableKeyedDigest({
    suite,
    domain: "env-manifest-vars",
    entries,
    variableIdOf: (entry) => entry.variableId,
    entryInvalidField: digestEntryInvalidField,
    entryFields: (entry) => [
      entry.variableId,
      entry.status,
      entry.metaVersion,
      entry.metaSigHashHex,
    ],
  });
}

export interface EnvManifestContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly issuerUserId: UserId;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: EnvManifestContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.manifestVersion) || context.manifestVersion < 1) {
    return "context manifestVersion";
  }
  if (!Number.isSafeInteger(context.envMetaVersion) || context.envMetaVersion < 1) {
    return "context envMetaVersion";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

function hexFieldInvalid(context: EnvManifestContext): string | null {
  if (!isLowercaseHexOfLength(context.variablesDigestHex, SHA256_HEX_LENGTH)) {
    return "context variablesDigestHex";
  }
  if (!isLowercaseHexOfLength(context.envMetaSigHashHex, SHA256_HEX_LENGTH)) {
    return "context envMetaSigHashHex";
  }
  if (
    context.prevManifestSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevManifestSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevManifestSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

function contextInvalidField(context: EnvManifestContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  if (context.issuerUserId.length === 0) {
    return "context issuerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

export function manifestContextInvalidField(context: EnvManifestContext): string | null {
  return contextInvalidField(context);
}

export function buildEnvManifestSignedBytes(context: EnvManifestContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/env-manifest-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.manifestVersion,
    context.variablesDigestHex,
    context.envMetaVersion,
    context.envMetaSigHashHex,
    context.prevManifestSigHashHex,
    context.issuerUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

export async function computeEnvManifestSignedBytesHash(
  context: EnvManifestContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildEnvManifestSignedBytes(context))) };
}

export async function signEnvManifest(input: {
  readonly context: EnvManifestContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.manifestVersion === 1) !== (input.context.prevManifestSigHashHex === "")) {
    return invalidInput("context prevManifestSigHashHex");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildEnvManifestSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

export async function verifyEnvManifestSignature(input: {
  readonly context: EnvManifestContext;
  readonly signatureHex: string;
  readonly issuerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildEnvManifestSignedBytes(input.context),
    input.signatureHex,
    input.issuerPublicKey,
    {
      kind: "EnvManifestInvalid",
      reason: "signature-invalid",
    },
  );
}
