import { decodeHex, encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId, UserId, VariableId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const NONCE_HEX_LENGTH = 12 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
const MIN_CIPHERTEXT_HEX_LENGTH = 16 * 2;

export interface ValueSignatureContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly variableId: VariableId;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly writerUserId: UserId;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
}

function numericFieldInvalid(context: ValueSignatureContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.version) || context.version < 1) {
    return "context version";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

function hexFieldInvalid(context: ValueSignatureContext): string | null {
  if (!isLowercaseHexOfLength(context.nonceHex, NONCE_HEX_LENGTH)) {
    return "context nonceHex";
  }
  if (
    context.ciphertextHex.length < MIN_CIPHERTEXT_HEX_LENGTH ||
    context.ciphertextHex.length % 2 !== 0 ||
    decodeHex(context.ciphertextHex) === null
  ) {
    return "context ciphertextHex";
  }
  if (
    context.prevValueSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevValueSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevValueSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

function contextInvalidField(context: ValueSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  if (context.variableId.length === 0) {
    return "context variableId";
  }
  if (context.writerUserId.length === 0) {
    return "context writerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

export function valueContextInvalidField(context: ValueSignatureContext): string | null {
  return contextInvalidField(context);
}

export function buildValueSignedBytes(context: ValueSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/value-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.variableId,
    context.version,
    context.nonceHex,
    context.ciphertextHex,
    context.prevValueSigHashHex,
    context.writerUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

export async function computeValueSignedBytesHash(
  context: ValueSignatureContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildValueSignedBytes(context))) };
}

export async function signValue(input: {
  readonly context: ValueSignatureContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.version === 1) !== (input.context.prevValueSigHashHex === "")) {
    return invalidInput("context prevValueSigHashHex");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildValueSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

export async function verifyValueSignature(input: {
  readonly context: ValueSignatureContext;
  readonly signatureHex: string;
  readonly writerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildValueSignedBytes(input.context),
    input.signatureHex,
    input.writerPublicKey,
    {
      kind: "ValueInvalid",
      reason: "signature-invalid",
    },
  );
}
