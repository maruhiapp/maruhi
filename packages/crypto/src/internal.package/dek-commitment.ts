// CRYPTO_SPEC §5.2: the epoch-DEK commitment.
//   dek_commitment_hex = lower_hex(SHA-256(LP("<suite>/dek-commit",
//                                             project_id, environment_id, epoch, dek_hex)))
// The suite binding is carried by the domain string (same shape as §5.1).
// Including the coordinates (project / environment / epoch) in the preimage
// makes reuse of the same DEK in another context a commitment mismatch, and
// keeps comparison of commitment values from leaking cross-context DEK
// equality. dek_hex is the lowercase hex string of the 32-byte DEK (the same
// binary_encoding convention as the §6.2 grant_server precedent).
// Test vectors: test-vectors/dek-commitment.json
//
// This is not a new primitive: it is built from SHA-256 + the §2.1 LP alone,
// the same "identification by public hash" applied by §3's key fingerprint.
// Since secrecy depends on the input's entropy, the only permitted subject is
// a uniformly random 256-bit DEK (reuse for low-entropy values is forbidden — §12).
//
// A recipient must not use an unwrapped DEK in any cryptographic operation
// (decryption or encryption) until it has been reconciled against this
// commitment (§5.2 / §6.3).

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";

const DEK_BYTES = 32;
const COMMITMENT_HEX_LENGTH = 32 * 2;

/**
 * Coordinates a DEK commitment is bound to (CRYPTO_SPEC §5.2). The suite is
 * embedded via the domain string, so a commitment never transplants across
 * suites; the coordinates keep commitments of the same DEK apart per context.
 */
export interface DekCommitmentContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

function contextInvalidField(context: DekCommitmentContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  return null;
}

/**
 * Builds the canonical commitment preimage (CRYPTO_SPEC §5.2). The DEK is
 * carried as its lowercase-hex form — `encodeHex` is the only producer here,
 * so an uppercase variant can never enter the preimage. Callers must validate
 * the context first (compute / verify below do); this builder assumes valid
 * input.
 */
export function buildDekCommitmentBytes(
  context: DekCommitmentContext,
  dek: Uint8Array,
): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/dek-commit`,
    context.projectId,
    context.environmentId,
    context.epoch,
    encodeHex(dek),
  ]);
}

/**
 * Computes the §5.2 commitment of an epoch DEK as lowercase hex — the value
 * published on the chain by `create_environment` / `rotate_epoch` (§6.2).
 */
export async function computeDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek");
  }
  return {
    ok: true,
    value: encodeHex(await sha256(buildDekCommitmentBytes(input.context, input.dek))),
  };
}

/**
 * Matches an unwrapped DEK against the chain-published commitment for its
 * (environment, epoch) coordinates (CRYPTO_SPEC §5.2 / §6.3). Until this
 * succeeds the DEK must not be used for any cryptographic operation; a
 * mismatch marks the wrap as poisoned (repair path — AUTH_SPEC §12-6).
 */
export async function verifyDekCommitment(input: {
  readonly context: DekCommitmentContext;
  readonly dek: Uint8Array;
  readonly expectedCommitmentHex: string;
}): Promise<CryptoResult<void>> {
  // The expected value accepts only the chain-derived normalized form (lowercase
  // hex, 64 chars). Allowing uppercase would produce multiple "normalized forms
  // used for reconciliation" and split the judgment between implementations
  if (
    input.expectedCommitmentHex.length !== COMMITMENT_HEX_LENGTH ||
    !/^[0-9a-f]+$/.test(input.expectedCommitmentHex)
  ) {
    return invalidInput("expectedCommitmentHex");
  }
  const computed = await computeDekCommitment({ context: input.context, dek: input.dek });
  if (!computed.ok) {
    return computed;
  }
  return computed.value === input.expectedCommitmentHex
    ? { ok: true, value: undefined }
    : { ok: false, error: { kind: "DekCommitmentMismatch" } };
}
