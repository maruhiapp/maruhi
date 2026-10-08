// CRYPTO_SPEC §5.1: the registration signature of a DEK wrap (Ed25519).
// signed_bytes = LP("<suite>/dek-wrap-sig", project_id, environment_id, epoch,
//                   recipient_user_id, recipient_enc_pub_hex, enc_hex,
//                   ciphertext_hex, signer_user_id)
// The suite binding is carried by the domain string (same shape as the §5 HPKE
// info). Binary values go onto the LP as lowercase hex strings, per the §6.2
// grant_server precedent.
// signer_user_id is the signer's own internal user_id — the signature itself
// closes off attribution swapping via key reuse (§5.1. Kept as an independent
// defense layer even after §6.2's member-key uniqueness banned duplicate-key
// members from existing at all).
// Test vectors: test-vectors/dek-wrap-signature.json
//
// The signature's semantics are attribution, not a freshness proof (no
// timestamp or nonce — §5.1). Built from existing parts only (Ed25519 + the
// §2.1 LP encoder).

import type { EnvironmentId, ProjectId, UserId } from "./chain-types.ts";
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

/**
 * Fields bound by a DEK-wrap registration signature (CRYPTO_SPEC §5.1):
 * the full wire form of one wrapped DEK plus its storage coordinates.
 * Binary values are carried as lowercase hex strings, exactly as on the wire.
 */
export interface DekWrapSignatureContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly recipientUserId: UserId;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  /** The signer's own internal user id (binds attribution to the identity, §5.1). */
  readonly signerUserId: UserId;
}

// Structure validation of the signing target: epoch is validated against the LP
// encoder's precondition (non-negative safe integer), and hex fields are
// lowercase fixed-length (allowing uppercase hex would give one wrap multiple
// normalized forms and break signature uniqueness). suite / signer_user_id
// must be non-empty (the server path validates more strongly via Schema /
// authentication, but as a public API we reject empty domains / signers)
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

/**
 * Builds the canonical byte string signed for one DEK-wrap registration
 * (CRYPTO_SPEC §5.1). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify below do); this builder assumes valid input.
 */
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

/**
 * Signs one DEK-wrap registration with the wrapper's chain signing key
 * (Ed25519, CRYPTO_SPEC §5.1). Returns the signature as lowercase hex —
 * the wire form of `WrappedDek.signatureHex` (AUTH_SPEC §12-2).
 */
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

/**
 * Verifies one DEK-wrap registration signature against the signer's Ed25519
 * public key (CRYPTO_SPEC §5.1). The server verifies with the caller's
 * chain-derived key at acceptance time; clients verify distributed wraps
 * with the key the chain history binds to the reported signer.
 */
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
