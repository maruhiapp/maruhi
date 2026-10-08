// CRYPTO_SPEC §5: DEK wrap (HPKE Base-mode single-shot Seal / Open).
// info = LP("maruhi/v1/dek-wrap", project_id, environment_id, epoch, recipient_user_id).
// aad is empty (the info carries the context binding; pinned by test vectors).
// Open is KeyPair-only (public key included): passing a bare private key would force
// extractable=true, so that path does not exist (CRYPTO_SPEC §2, the spike-c findings).

import type { EnvironmentId, ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

/** Context that cryptographically binds a wrapped DEK to its recipient (CRYPTO_SPEC §5). */
export interface DekWrapContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly recipientUserId: UserId;
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

// epoch is Result-validated against the LP encoder's precondition (non-negative safe
// integer) (same as variable.ts — a typed error is returned rather than an accidental
// containment via try)
function checkEpoch(context: DekWrapContext): boolean {
  return Number.isSafeInteger(context.epoch) && context.epoch >= 0;
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

/**
 * Unwraps a DEK with the recipient's key pair (single-shot HPKE Open). Takes
 * the full pair so the private key can stay non-extractable (CRYPTO_SPEC §2).
 */
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
