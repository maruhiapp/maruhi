// CRYPTO_SPEC §5.3: sealed value proposals (HPKE Base-mode single-shot
// Seal / Open — the **same primitive** as §5 and §9.1; no new primitive is
// introduced).
//
//   info = LP("<suite>/sealed-value", project_id, environment_id,
//             proposal_id, variable_id, base_version, recipient_user_id)
//
// A workload holding only a lease (§9.1) mints a new credential at the
// issuer and seals the proposed value to each device of the members who
// may accept it (W(E) — member or above, environment in scope). The
// server stores the ciphertexts; a member opens its own with its device
// enc key and pushes the plaintext as an ordinary signed version (§4.1).
//
// Three points differ from the §5 persistent wrap:
//   1. The plaintext is a variable value (1 byte to the §4 cap), not a
//      32-byte DEK
//   2. The info carries the proposal id, the variable id and the version
//      the value replaces: a sealed value cannot be re-filed under another
//      proposal, presented as another variable of the same proposal, or
//      re-labelled as minted against a newer version (all negatives of
//      the vector) — "replaces version N" is under the seal, not only in
//      server-declared metadata
//   3. The domain string is `<suite>/sealed-value` — domain separation
//      from §5's `dek-wrap` and §9.1's `lease-wrap`
//
// A sealed value carries no §5.1 registration signature (the workload has
// no on-chain key — attribution is the lease's claims digest, recorded by
// the server). aad is empty like §5 (the info carries the context binding).
// Test vectors: test-vectors/sealed-value.json

import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

const SEALED_VALUE_DOMAIN = `${SUITE_ID}/sealed-value`;

/** The proposal id: 16 random bytes as lowercase hex (client-chosen — §5.3). */
export const PROPOSAL_ID_BYTES = 16;
const PROPOSAL_ID_PATTERN = new RegExp(`^[0-9a-f]{${PROPOSAL_ID_BYTES * 2}}$`);

/** The largest plaintext a sealed value carries (the §4 value cap: 64 KiB of ciphertext minus the tag). */
export const MAX_SEALED_VALUE_BYTES = 64 * 1024 - 16;

/** Context a sealed value is cryptographically bound to (CRYPTO_SPEC §5.3). */
export interface SealedValueContext {
  readonly projectId: string;
  readonly environmentId: string;
  readonly proposalId: string;
  readonly variableId: string;
  /** The version the proposed value replaces (the accepting client pushes base_version + 1 on top of exactly this version). */
  readonly baseVersion: number;
  readonly recipientUserId: string;
}

/** A proposed value sealed to one recipient device: HPKE encapsulated key + ciphertext. */
export interface SealedValue {
  readonly enc: Uint8Array;
  readonly ciphertext: Uint8Array;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/** Whether a string has the proposal id's form (32 lowercase hex characters). */
export function isProposalId(value: string): boolean {
  return PROPOSAL_ID_PATTERN.test(value);
}

function contextInvalidField(context: SealedValueContext): string | null {
  // The proposal id's form is checked structurally: an uppercase or
  // differently sized id would produce "the same proposal, a different
  // info" between the minting client and the accepting client
  if (!isProposalId(context.proposalId)) {
    return "context proposalId";
  }
  // A version starts at 1 (§4.1); the form is checked here, the boundary is the caller's
  if (!Number.isSafeInteger(context.baseVersion) || context.baseVersion < 1) {
    return "context baseVersion";
  }
  for (const [field, value] of [
    ["context projectId", context.projectId],
    ["context environmentId", context.environmentId],
    ["context variableId", context.variableId],
    ["context recipientUserId", context.recipientUserId],
  ] as const) {
    if (value.length === 0) {
      return field;
    }
  }
  return null;
}

/**
 * Builds the HPKE info for a sealed value (CRYPTO_SPEC §5.3):
 * `LP("<suite>/sealed-value", project_id, environment_id, proposal_id, variable_id, base_version, recipient_user_id)`.
 * Opening under any other context — another project, environment,
 * proposal, variable, base version or recipient, or a §5 / §9.1 info —
 * fails. Callers
 * must validate the context first (seal / open below do).
 */
export function buildSealedValueInfo(context: SealedValueContext): Uint8Array {
  return encodeLengthPrefixed([
    SEALED_VALUE_DOMAIN,
    context.projectId,
    context.environmentId,
    context.proposalId,
    context.variableId,
    context.baseVersion,
    context.recipientUserId,
  ]);
}

/**
 * Seals a proposed value to one recipient device's enc public key
 * (single-shot HPKE Seal). The plaintext never leaves the minting
 * process in the clear; the result is what the server stores (§5.3).
 */
export async function sealProposedValue(input: {
  readonly recipientPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: SealedValueContext;
}): Promise<CryptoResult<SealedValue>> {
  if (input.value.length === 0 || input.value.length > MAX_SEALED_VALUE_BYTES) {
    return invalidInput("value length");
  }
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.recipientPublicKey,
      input.value,
      { info: buildSealedValueInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

/**
 * Opens a sealed value with the recipient device's key pair (single-shot
 * HPKE Open). Takes the full pair so the private key can stay
 * non-extractable (CRYPTO_SPEC §2). The accepting client must still
 * verify that the proposal targets a verified active statement before
 * pushing the plaintext (§5.3).
 */
export async function openProposedValue(input: {
  readonly recipientKeyPair: EncryptionKeyPair;
  readonly sealed: SealedValue;
  readonly context: SealedValueContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const value = await hpkeSuite().Open(
      input.recipientKeyPair,
      input.sealed.enc,
      input.sealed.ciphertext,
      { info: buildSealedValueInfo(input.context) },
    );
    return { ok: true, value };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
