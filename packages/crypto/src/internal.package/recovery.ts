// CRYPTO_SPEC §8: wrap of the user master private-key blob by the recovery code.
// KEK = HKDF-SHA256(recovery_secret, salt = empty (length 0), info = "maruhi/v1/recovery")
// wrap = AES-256-GCM(AAD = LP("maruhi/v1/recovery-wrap", user_id), 96-bit random nonce)
//
// Rationale for salt = empty: recovery_secret is uniformly random 256-bit (RFC 5869 §3.1).
// Purpose separation is carried by info. Introducing a passphrase-derived key requires a spec revision (§8).
// The wrapped master-key blob is treated as an opaque byte string (the serialization format is decided at CLI implementation time).

import type { UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { SUITE_ID } from "./suite.ts";

/** An encrypted master-secret blob: 96-bit nonce + AES-256-GCM ciphertext. */
export interface WrappedMasterSecret {
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

const RECOVERY_SECRET_BYTES = 32;
const NONCE_BYTES = 12;
const HKDF_INFO = `${SUITE_ID}/recovery`;
const WRAP_AAD_DOMAIN = `${SUITE_ID}/recovery-wrap`;

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/** Generates a fresh 256-bit recovery secret (CRYPTO_SPEC §8). */
export function generateRecoverySecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(RECOVERY_SECRET_BYTES));
}

async function deriveKek(recoverySecret: Uint8Array, usage: "encrypt" | "decrypt") {
  const ikm = await crypto.subtle.importKey("raw", recoverySecret as BufferSource, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(HKDF_INFO) as BufferSource,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

function wrapAad(userId: string): Uint8Array {
  return encodeLengthPrefixed([WRAP_AAD_DOMAIN, userId]);
}

/**
 * Wraps the opaque master-secret blob under a KEK derived from the recovery
 * secret. The nonce is freshly random per call. The blob's serialization
 * format is out of scope here (decided with the CLI implementation).
 */
export async function wrapMasterSecret(input: {
  readonly recoverySecret: Uint8Array;
  readonly userId: UserId;
  readonly masterSecretBlob: Uint8Array;
}): Promise<CryptoResult<WrappedMasterSecret>> {
  if (input.recoverySecret.length !== RECOVERY_SECRET_BYTES) {
    return invalidInput("recovery secret length");
  }
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  try {
    const kek = await deriveKek(input.recoverySecret, "encrypt");
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce as BufferSource,
          additionalData: wrapAad(input.userId) as BufferSource,
        },
        kek,
        input.masterSecretBlob as BufferSource,
      ),
    );
    return { ok: true, value: { nonce, ciphertext } };
  } catch {
    // Unexpected WebCrypto failures are also returned as values (symmetric with unwrap)
    return { ok: false, error: { kind: "EncryptFailed", operation: "recovery" } };
  }
}

/**
 * Unwraps a master-secret blob. Any mismatch (wrong recovery secret, another
 * user's blob, tampered ciphertext) yields `DecryptFailed`.
 */
export async function unwrapMasterSecret(input: {
  readonly recoverySecret: Uint8Array;
  readonly userId: UserId;
  readonly wrapped: WrappedMasterSecret;
}): Promise<CryptoResult<Uint8Array>> {
  if (input.recoverySecret.length !== RECOVERY_SECRET_BYTES) {
    return invalidInput("recovery secret length");
  }
  if (input.wrapped.nonce.length !== NONCE_BYTES) {
    return invalidInput("nonce length");
  }
  try {
    const kek = await deriveKek(input.recoverySecret, "decrypt");
    const blob = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: input.wrapped.nonce as BufferSource,
          additionalData: wrapAad(input.userId) as BufferSource,
        },
        kek,
        input.wrapped.ciphertext as BufferSource,
      ),
    );
    return { ok: true, value: blob };
  } catch {
    return { ok: false, error: { kind: "DecryptFailed", operation: "recovery" } };
  }
}
