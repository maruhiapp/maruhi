// CRYPTO_SPEC §4.1: the value write signature (Ed25519).
// value_signed_bytes = LP("<suite>/value-sig", project_id, environment_id, epoch,
//                         variable_id, version, nonce_hex, ciphertext_hex,
//                         prev_value_sig_hash_hex, writer_user_id,
//                         chain_head_hash_hex, chain_head_seq)
// The suite binding is carried by the domain string (same shape as §5.1).
// Numbers (epoch / version / chain_head_seq) are base-10 stringified per §2.1,
// and binaries (nonce / ciphertext / hash) go onto the LP as lowercase hex
// strings.
// Test vectors: test-vectors/value-signature.json
//
// The signature's semantics: "writer_user_id, knowing the state at chain
// position (chain_head_hash, chain_head_seq), wrote this ciphertext at these
// coordinates" — attribution, content authenticity, and authorization-time
// binding (§4.1). It does not prove the plaintext's correctness or freshness.
// A value signature does not authenticate the name (name ↔ ID authenticity
// belongs to the §4.2 meta statement).
// Verification of the declared head, authorization time, and prev chaining is
// carried by value-verify.ts (history queries by chain-history.ts); this
// module holds only the low-level normalization, signing, and hashing.

import { decodeHex, encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const NONCE_HEX_LENGTH = 12 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
// AES-256-GCM's ct || tag has a 16-byte tag as lower bound (the wire shape of AUTH_SPEC §12-2)
const MIN_CIPHERTEXT_HEX_LENGTH = 16 * 2;

/**
 * Fields bound by a value write signature (CRYPTO_SPEC §4.1): the full wire
 * form of one encrypted variable version plus its authorization anchor.
 * Binary values are carried as lowercase hex strings, exactly as on the wire.
 */
export interface ValueSignatureContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /**
   * SHA-256 (lowercase hex) of the previous version's value_signed_bytes;
   * the empty string for version 1 (the §4.1 chaining convention).
   */
  readonly prevValueSigHashHex: string;
  /** The writer's own internal user id (binds attribution to the identity). */
  readonly writerUserId: string;
  /** Entry hash of the chain head the writer last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

// Numeric fields (epoch / version / chain_head_seq) are 1-based safe integers
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

// Binary values are lowercase hex only (the same discipline as the §5.1
// implementation — allowing uppercase hex would give one value multiple
// normalized forms and break signature uniqueness)
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

// Structure validation of the signing target. The version ↔ prev coupling
// (version 1 = empty / version > 1 = 64-hex) is not checked here: the verify
// side must be able to verify the signature of a "valid signature but
// rule-violating" value first (the vectors' rule negatives such as
// v1-nonempty-prev), and the coupling is rejected with a reason code as a
// verification rule (value-verify.ts's prev-shape-mismatch).
function contextInvalidField(context: ValueSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  // The non-empty checks of projectId / environmentId are for defensive
  // consistency (LP makes even empty values unambiguous = not a
  // vulnerability, but the check level is kept uniform across fields).
  // No legitimate call signs empty coordinates
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.environmentId.length === 0) {
    return "context environmentId";
  }
  // The variable id is required non-empty at the same level as the other
  // coordinates. The API schema rejects empties on the wire, so this is not
  // an external forgery path, but no legitimate call signs empty coordinates
  // (the same discipline as meta-sign.ts's variableId check)
  if (context.variableId.length === 0) {
    return "context variableId";
  }
  if (context.writerUserId.length === 0) {
    return "context writerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/** Validates a value-signature context (shared by sign / verify / hash). */
export function valueContextInvalidField(context: ValueSignatureContext): string | null {
  return contextInvalidField(context);
}

/**
 * Builds the canonical byte string signed for one variable value version
 * (CRYPTO_SPEC §4.1). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify / hash below do); this builder assumes valid
 * input.
 */
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

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next version's `prev_value_sig_hash_hex` (the §4.1 chaining) and compared
 * for fork evidence (two valid signatures over distinct signed bytes at the
 * same coordinate — §14.2-5).
 */
export async function computeValueSignedBytesHash(
  context: ValueSignatureContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildValueSignedBytes(context))) };
}

/**
 * Signs one variable value version with the writer's chain signing key
 * (Ed25519, CRYPTO_SPEC §4.1). Returns the signature as lowercase hex — the
 * wire form of `EncryptedPayload.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the version ↔ prev coupling (version 1 signs an empty
 * prev, later versions sign a 64-hex prev): producing a rule-violating
 * signature is always a caller bug, unlike verification where such wire data
 * must be rejected with a typed reason instead.
 */
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

/**
 * Verifies one value write signature against a writer's Ed25519 public key
 * (CRYPTO_SPEC §4.1). This is the raw signature check only — head existence,
 * head-time authorization / epoch and prev chaining are the history-based
 * checks in `verifyDistributedValue` (value-verify.ts).
 */
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
