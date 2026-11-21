import type { EnvironmentId, KeyFingerprintHex, ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

export interface DekWrapContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly recipientUserId: UserId | KeyFingerprintHex;
}

export interface WrappedDek {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const DEK_WRAP_DOMAIN = `${SUITE_ID}/dek-wrap`;
const DEK_BYTES = 32;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function checkEpoch(context: DekWrapContext): boolean {
  return Number.isSafeInteger(context.epoch) && context.epoch >= 0;
}

export function buildDekWrapInfo(context: DekWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    DEK_WRAP_DOMAIN,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.recipientUserId,
  ]);
}

export async function wrapDek(input: {
  readonly recipientPublicKey: EncryptionKey;
  readonly dek: Uint8Array;
  readonly context: DekWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  if (!checkEpoch(input.context)) {
    return invalidInput("context epoch");
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.recipientPublicKey,
      input.dek,
      { info: buildDekWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

export async function unwrapDek(input: {
  readonly recipientKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: DekWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  if (!checkEpoch(input.context)) {
    return invalidInput("context epoch");
  }
  try {
    const dek = await hpkeSuite().Open(
      input.recipientKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildDekWrapInfo(input.context) },
    );
    return { ok: true, value: dek };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
