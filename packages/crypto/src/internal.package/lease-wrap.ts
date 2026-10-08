// CRYPTO_SPEC §9.1: the lease wrap of workload leases (HPKE Base-mode
// single-shot Seal / Open — the **same primitive** as §5; no new primitive is
// introduced).
//
//   info = LP("<suite>/lease-wrap", project_id, environment_id, epoch,
//             claims_digest_hex)
//   claims_digest_hex = lower_hex(SHA-256(LP("<suite>/lease-claims",
//                                            issuer_url, subject, audience)))
//
// Only two points differ from the §5 persistent wrap:
//   1. The recipient position of the info is not "the recipient's identifier
//      (user_id / server-key FP)" but claims_digest. The recipient is an
//      ephemeral key the workload generates in memory with no on-chain
//      identifier, so the binding target is replaced by "which workload
//      context it was issued to" = the issuer / sub / aud of the verified
//      OIDC token. Server and workload compute the same value independently,
//      and reuse of a lease response on another job becomes a decryption
//      failure (a consistent application of design principle 3). Note that
//      replay of a still-valid OIDC token within the **same** context is
//      outside what this binding prevents (see CRYPTO_SPEC §9.1's explicit
//      non-guarantee)
//   2. The domain string is `<suite>/lease-wrap`. Domain separation from §5's
//      `<suite>/dek-wrap` makes persistent wraps and lease wraps mutually
//      non-transplantable
//
// A lease wrap is **never persisted** (it does not enter dek_wraps — §9.1).
// Since it exists only in response scope, it carries no §5.1 registration
// signature (signers are members on the chain; a server-generated wrap
// cannot have an attribution signature).
//
// aad is empty like §5 (the info carries the context binding).
// Test vectors: test-vectors/lease-wrap.json

import { encodeHex } from "./bytes.ts";
import type { EnvironmentId, ProjectId } from "./chain-types.ts";
import type { WrappedDek } from "./dek-wrap.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { hpkeSuite } from "./hpke.ts";
import type { EncryptionKey, EncryptionKeyPair } from "./keys.ts";
import { SUITE_ID } from "./suite.ts";

const LEASE_WRAP_DOMAIN = `${SUITE_ID}/lease-wrap`;
const LEASE_CLAIMS_DOMAIN = `${SUITE_ID}/lease-claims`;
const DEK_BYTES = 32;
const CLAIMS_DIGEST_HEX_LENGTH = 32 * 2;

/**
 * The verified OIDC claims a lease is issued against (CRYPTO_SPEC §9.1).
 * These are the *verified* token claims — the server takes them from a token
 * whose signature, issuer and time bounds it has already checked (AUTH_SPEC
 * §14-1), and the workload takes them from the token it minted. Neither side
 * transmits the digest: both compute it.
 */
export interface LeaseClaims {
  readonly issuerUrl: string;
  readonly subject: string;
  readonly audience: string;
}

/**
 * Context a lease wrap is cryptographically bound to (CRYPTO_SPEC §9.1).
 * `claimsDigestHex` is the lowercase-hex digest from `computeLeaseClaimsDigest`.
 */
export interface LeaseWrapContext {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly claimsDigestHex: string;
}

function invalidInput(field: string): { readonly ok: false; readonly error: CryptoError } {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/**
 * Builds the canonical preimage of the claims digest (CRYPTO_SPEC §9.1):
 * `LP("<suite>/lease-claims", issuer_url, subject, audience)`. Exposed so the
 * length-prefixed field order is fixed by the test vector rather than by an
 * implementation detail — `("ab","c")` and `("a","bc")` must not collide.
 */
export function buildLeaseClaimsBytes(claims: LeaseClaims): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_CLAIMS_DOMAIN,
    claims.issuerUrl,
    claims.subject,
    claims.audience,
  ]);
}

/**
 * Computes `claims_digest_hex` (CRYPTO_SPEC §9.1). Empty fields are rejected:
 * an OIDC token always carries a non-empty `iss` / `sub` / `aud`, and letting
 * an empty value through would let distinct contexts collide into one digest.
 */
export async function computeLeaseClaimsDigest(claims: LeaseClaims): Promise<CryptoResult<string>> {
  if (claims.issuerUrl.length === 0) {
    return invalidInput("claims issuerUrl");
  }
  if (claims.subject.length === 0) {
    return invalidInput("claims subject");
  }
  if (claims.audience.length === 0) {
    return invalidInput("claims audience");
  }
  return { ok: true, value: encodeHex(await sha256(buildLeaseClaimsBytes(claims))) };
}

function contextInvalidField(context: LeaseWrapContext): string | null {
  // epoch is Result-validated against the LP encoder's precondition (non-negative
  // safe integer). The epoch starts at 1 (§3), but as in dek-wrap's checkEpoch
  // the boundary is held by the caller (the chain-derived state) — here we only
  // check the form
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  // Check the digest's form: structurally excludes both the misuse of passing
  // raw claims and the implementation divergence of uppercase hex producing
  // "same digest, different info"
  if (!new RegExp(`^[0-9a-f]{${CLAIMS_DIGEST_HEX_LENGTH}}$`).test(context.claimsDigestHex)) {
    return "context claimsDigestHex";
  }
  return null;
}

/**
 * Builds the HPKE info for a lease wrap (CRYPTO_SPEC §9.1):
 * `LP("<suite>/lease-wrap", project_id, environment_id, epoch, claims_digest_hex)`.
 * Opening under any other context — another project, environment, epoch or
 * workload identity, or a §5 persistent-wrap info — fails. Callers must
 * validate the context first (wrap / unwrap below do).
 */
export function buildLeaseWrapInfo(context: LeaseWrapContext): Uint8Array {
  return encodeLengthPrefixed([
    LEASE_WRAP_DOMAIN,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.claimsDigestHex,
  ]);
}

/**
 * Wraps an epoch DEK to a workload's ephemeral public key (single-shot HPKE
 * Seal). The result is response-scoped: it must never be persisted into the
 * DEK wrap store (CRYPTO_SPEC §9.1 / AUTH_SPEC §12-6).
 */
export async function wrapLeaseDek(input: {
  readonly workloadPublicKey: EncryptionKey;
  readonly dek: Uint8Array;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<WrappedDek>> {
  if (input.dek.length !== DEK_BYTES) {
    return invalidInput("dek length");
  }
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const { encapsulatedSecret, ciphertext } = await hpkeSuite().Seal(
      input.workloadPublicKey,
      input.dek,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: { enc: encapsulatedSecret, ciphertext } };
  } catch {
    return { ok: false, error: { kind: "DekWrapFailed" } };
  }
}

/**
 * Unwraps a leased DEK with the workload's ephemeral key pair (single-shot
 * HPKE Open). Takes the full pair so the private key can stay non-extractable
 * (CRYPTO_SPEC §2). The workload must still match the unwrapped DEK against
 * the chain-published commitment (§5.2) before using it (§9.1's verification duty 3).
 */
export async function unwrapLeaseDek(input: {
  readonly workloadKeyPair: EncryptionKeyPair;
  readonly wrapped: WrappedDek;
  readonly context: LeaseWrapContext;
}): Promise<CryptoResult<Uint8Array>> {
  const invalidField = contextInvalidField(input.context);
  if (invalidField !== null) {
    return invalidInput(invalidField);
  }
  try {
    const dek = await hpkeSuite().Open(
      input.workloadKeyPair,
      input.wrapped.enc,
      input.wrapped.ciphertext,
      { info: buildLeaseWrapInfo(input.context) },
    );
    return { ok: true, value: dek };
  } catch {
    return { ok: false, error: { kind: "DekUnwrapFailed" } };
  }
}
