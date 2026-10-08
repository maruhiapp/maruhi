// CRYPTO_SPEC §6.6: the head attestation (Ed25519).
// head_attestation_signed_bytes = LP("<suite>/head-attestation",
//                                    project_id, attester_user_id,
//                                    chain_head_hash_hex, chain_head_seq)
// The suite binding is carried by the domain string (same shape as §5.1).
// The binary value (head hash) goes onto the LP as a lowercase hex string,
// and the number (chain_head_seq) is base-10 stringified per §2.1.
// Test vectors: test-vectors/head-attestation.json
//
// Semantics: the attribution and context binding of "attester_user_id
// accepted this project's chain as verified up to this position" (§6.6). It
// does not prove the chain head's own authenticity — verification is done by
// the receiver reconciling against its own view (§6.3 head gossip). No
// timestamp or nonce enters the signed data (this is not a freshness proof —
// the attestation's recency is ordered by chain_head_seq, and redistribution
// of an old attestation is equivalent to server omission = G8). Baking in
// attester_user_id is the same attribution-substitution countermeasure as
// §5.1's signer_user_id.
//
// The history-based verification (verifyDistributedHeadAttestation) is
// isomorphic to value / meta (no double implementation of the verification
// mechanism — the shared core in validate.ts). **That the attester is a
// current member in the verifier's own view (the first half of §6.6 (1))
// is outside this module's checks**: that is a selection of "is it a
// distribution/reconciliation target", not the attestation's own validity
// (a past attestation by a removed member against an in-tenure head passes
// verification — vector removed-attester-in-tenure); the caller selects
// first with history.memberStateAt(userId, history.headSeq).

import type { ProjectId, UserId } from "./chain-types.ts";
import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { AttestationInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  isLowercaseHexOfLength,
  ROLE_RANK,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * Fields bound by a head attestation (CRYPTO_SPEC §6.6): the project
 * coordinate, the attester's identity, and the verified chain head (hash +
 * seq — both are signed, so a mismatched pair never verifies). Binary values
 * are carried as lowercase hex strings, exactly as on the wire.
 */
export interface HeadAttestationContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  /** The attester's own internal user id (binds attribution — same shape as §5.1). */
  readonly attesterUserId: UserId;
  /** Entry hash of the chain head the attester verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head. */
  readonly chainHeadSeq: number;
}

// Structure validation of the signing target: hex is lowercase fixed-length
// only (allowing uppercase hex would give one attestation multiple
// normalized forms and break signature uniqueness — the same discipline as
// validate.ts). chain_head_seq is bounded by §2.1's numeric limits
// (non-negative safe integer) plus seq being 1-based
function contextInvalidField(context: HeadAttestationContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.attesterUserId.length === 0) {
    return "context attesterUserId";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

/**
 * Builds the canonical byte string signed for one head attestation
 * (CRYPTO_SPEC §6.6). The domain string embeds the suite identifier, so a
 * signature never transplants across suites; project_id binds the context, so
 * an attestation never transplants across projects. Callers must validate the
 * context first (sign / verify below do); this builder assumes valid input.
 */
export function buildHeadAttestationSignedBytes(context: HeadAttestationContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/head-attestation`,
    context.projectId,
    context.attesterUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the digest a
 * verifier records as evidence when a distributed attestation contradicts its
 * own view (evidence-making of §6.6 / §14.2-5).
 */
export async function computeHeadAttestationSignedBytesHash(
  context: HeadAttestationContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildHeadAttestationSignedBytes(context))) };
}

/**
 * Signs one head attestation with the attester's chain signing key (Ed25519,
 * CRYPTO_SPEC §6.6). Returns the signature as lowercase hex — the wire form
 * of the submission's `signatureHex` (AUTH_SPEC §16-1).
 */
export async function signHeadAttestation(input: {
  readonly context: HeadAttestationContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildHeadAttestationSignedBytes(input.context), input.signingKey);
}

/**
 * Verifies one head-attestation signature against an attester's Ed25519
 * public key (CRYPTO_SPEC §6.6). This is the raw signature check only — head
 * binding and head-time membership are the history-based checks in
 * `verifyDistributedHeadAttestation`.
 */
export async function verifyHeadAttestationSignature(input: {
  readonly context: HeadAttestationContext;
  readonly signatureHex: string;
  readonly attesterPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildHeadAttestationSignedBytes(input.context),
    input.signatureHex,
    input.attesterPublicKey,
    { kind: "HeadAttestationInvalid", reason: "signature-invalid" },
  );
}

/** Input of the history-based distributed-attestation verification (§6.6). */
export interface DistributedHeadAttestationInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire attestation fields (§6.3-5 coordinate integrity is the caller's). */
  readonly context: HeadAttestationContext;
  /** Distributed attester key fingerprint (server: acceptance-time member FP). */
  readonly attesterKeyFingerprintHex: string;
  readonly signatureHex: string;
}

function attestationInvalid(reason: AttestationInvalidReason): {
  readonly ok: false;
  readonly error: {
    readonly kind: "HeadAttestationInvalid";
    readonly reason: AttestationInvalidReason;
  };
} {
  return { ok: false, error: { kind: "HeadAttestationInvalid", reason } };
}

// Reason-code mapping of head binding / membership at the attested head
// (§6.6 (1)-(3)). The check itself is headAuthorizationReason (validate.ts —
// shared with value / meta). Since the required-role lower bound is reader
// (every member can attest — §6.3 head gossip), roleInsufficientAtHead can
// never fire structurally (ROLE_RANK.reader = the lowest rank) — the mapping
// folds it into the membership-mismatch reason
const HEAD_ATTESTATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "attester-not-member-at-head",
  keyMismatchAtHead: "attester-key-mismatch-at-head",
  roleInsufficientAtHead: "attester-not-member-at-head",
} as const satisfies HeadAuthorizationReasons<AttestationInvalidReason>;

/**
 * Verifies one distributed (or submitted) head attestation against a
 * verified chain history (CRYPTO_SPEC §6.6): key selection by (user id,
 * fingerprint) over the full history, the Ed25519 signature, then the head
 * binding with the §6.3-2 two-way distinction and the head-time (inclusive)
 * membership / key-binding checks. Returns the signed-bytes hash on success
 * (the evidence anchor — §14.2-5).
 *
 * The reason codes drive the gossip reconciliation (§6.3 head gossip):
 * `chain-head-mismatch` = the hard-evidence branch (a) — the caller must
 * treat the *attestation itself* as evidence (the signature is verified),
 * not merely discard it; `chain-head-future` = the bounded-resync branch
 * (b); any other reason = an invalid attestation that must NOT be used as
 * reconciliation material (excludes warning induction via forged
 * attestations — §6.6).
 *
 * The current-membership gate of §6.6 (1) is the caller's selection step
 * (see the module comment) — a removed attester's in-tenure attestation
 * verifies here by design (vector removed-attester-in-tenure).
 */
export async function verifyDistributedHeadAttestation(
  input: DistributedHeadAttestationInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    contextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
      actorKeyFingerprintField: "attesterKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: undefined,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // Key selection (the lead-in to §6.6 (2); the check order is the same as
  // value / meta: to rule out a broken signature first, the selection covers
  // all tenure and the head-time binding is checked afterwards)
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    onUnknown: { kind: "HeadAttestationInvalid", reason: "attester-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyHeadAttestationSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    attesterPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headAuthorizationReason({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.reader,
    reasons: HEAD_ATTESTATION_REASONS,
  });
  if (headReason !== null) {
    return attestationInvalid(headReason);
  }

  return {
    ok: true,
    value: {
      signedBytesHashHex: encodeHex(await sha256(buildHeadAttestationSignedBytes(input.context))),
    },
  };
}
