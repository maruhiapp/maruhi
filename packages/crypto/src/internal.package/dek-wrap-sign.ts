import type { EnvironmentId, KeyFingerprintHex, ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import {
  invalidInput,
  isLowercaseHexOfLength,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const ENC_PUB_HEX_LENGTH = 32 * 2;
const HPKE_ENC_HEX_LENGTH = 32 * 2;
const WRAP_CIPHERTEXT_HEX_LENGTH = 48 * 2;

export interface DekWrapSignatureContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly recipientUserId: UserId | KeyFingerprintHex;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signerUserId: UserId;
}

function contextInvalidField(context: DekWrapSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.signerUserId.length === 0) {
    return "context signerUserId";
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  if (!isLowercaseHexOfLength(context.recipientEncPubHex, ENC_PUB_HEX_LENGTH)) {
    return "context recipientEncPubHex";
  }
  if (!isLowercaseHexOfLength(context.encHex, HPKE_ENC_HEX_LENGTH)) {
    return "context encHex";
  }
  if (!isLowercaseHexOfLength(context.ciphertextHex, WRAP_CIPHERTEXT_HEX_LENGTH)) {
    return "context ciphertextHex";
  }
  return null;
}

export function buildDekWrapSignatureBytes(context: DekWrapSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/dek-wrap-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.recipientUserId,
    context.recipientEncPubHex,
    context.encHex,
    context.ciphertextHex,
    context.signerUserId,
  ]);
}

export async function signDekWrap(input: {
  readonly context: DekWrapSignatureContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildDekWrapSignatureBytes(input.context), input.signingKey);
}

export async function verifyDekWrapSignature(input: {
  readonly context: DekWrapSignatureContext;
  readonly signatureHex: string;
  readonly signerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildDekWrapSignatureBytes(input.context),
    input.signatureHex,
    input.signerPublicKey,
    {
      kind: "DekWrapSignatureInvalid",
    },
  );
}
