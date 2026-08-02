// CRYPTO_SPEC §5: DEK ラップ(HPKE Base mode 単発 Seal / Open)。
// info = LP("maruhi/v1/dek-wrap", project_id, environment_id, epoch, recipient_user_id)。
// aad は空(文脈束縛は info が担う。テストベクターで固定)。
// Open は KeyPair(公開鍵込み)渡しのみ: 秘密鍵単体渡しは extractable=true を
// 強制されるため経路として存在させない(CRYPTO_SPEC §2、spike-c の知見)。

import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

/** Context that cryptographically binds a wrapped DEK to its recipient (CRYPTO_SPEC §5). */
export interface DekWrapContext {
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly recipientUserId: string;
}

/** A DEK wrapped for one recipient: HPKE encapsulated key + ciphertext. */
export interface WrappedDek {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const DEK_WRAP_DOMAIN = `${SUITE_ID}/dek-wrap`;
const DEK_BYTES = 32;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Builds the HPKE info for a DEK wrap:
 * `LP("maruhi/v1/dek-wrap", project_id, environment_id, epoch, recipient_user_id)`.
 * Opening under any other context (transplant to another project, epoch,
 * environment or recipient) fails (§5).
 */
export function buildDekWrapInfo(context: DekWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    DEK_WRAP_DOMAIN,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.recipientUserId,
  ]);
}

/** Wraps an epoch DEK to one recipient's encryption public key (single-shot HPKE Seal). */
export async function wrapDek(input: {
  readonly recipientPublicKey: EncryptionKey;
  readonly dek: Uint8Array;
  readonly context: DekWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
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

/**
 * Unwraps a DEK with the recipient's key pair (single-shot HPKE Open). Takes
 * the full pair so the private key can stay non-extractable (CRYPTO_SPEC §2).
 */
export async function unwrapDek(input: {
  readonly recipientKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: DekWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
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
