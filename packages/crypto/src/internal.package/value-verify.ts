// History-based composite verification of CRYPTO_SPEC §6.3 (value
// verification) / §6.4 (server acceptance verification).
//
// Against the history index of a verified chain (chain-history.ts), checks
// §6.3's items 1-4 and 6 of a distributed (or submitted) value:
//   1. Signature (key selection = FP match among the keys the history binds
//      to writer_user_id)
//   2. Head binding (seq → hash match; distinguishes the 2 kinds of
//      mismatch — mismatch / future)
//   3. Authorization time (membership, key binding, and role at the declared
//      head — including rejection across tenure boundaries)
//   3′. Scope (the writer's scope at the declared head contains the
//      environment — 2026-09-14 ES)
//   4. Epoch integrity (the current epoch at the declared head = the signed
//      epoch; includes rejecting a pre-environment-creation head)
//   6. Chaining integrity (only when a predecessor is passed: prev match +
//      epoch non-decrease)
// Coordinate integrity (§6.3-5) is the caller's duty: construct the context
// passed to this function from expected coordinates (the verified genesis
// hash, the requested environment, the response meta's variableId, etc.),
// not from the declared values.
//
// The limits of latest-only (session-14 ruling B): even without a
// predecessor, the shapes of signature, head, key, role, environment, epoch,
// and prev are always checked. The real match of prev and the epoch
// non-decrease are checked only when a predecessor is passed, and we do not
// falsely claim "checked" when it is not (the caller bears §14.3's
// non-guarantee).
// The check order matches provisional ruling C (broken signature → unknown
// head → state mismatch).

import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ValueInvalidReason } from "./errors.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";
import {
  computeValueSignedBytesHash,
  valueContextInvalidField,
  type ValueSignatureContext,
  verifyValueSignature,
} from "./value-sign.ts";

/**
 * The verified predecessor version's anchor (§6.3-6): its
 * value_signed_bytes hash and its epoch. The caller must have verified the
 * predecessor itself (server: stored acceptance-time values; client: a value
 * that passed this same verification) — chaining onto unverified data would
 * poison the evidence chain (same root as AUTH_SPEC §12-5's 409 discipline).
 */
export interface ValuePredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** Input of the history-based distributed-value verification (§6.3 / §6.4). */
export interface DistributedValueInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire payload fields (see module comment). */
  readonly context: ValueSignatureContext;
  /** Distributed writer key fingerprint (server: acceptance-time caller FP). */
  readonly writerKeyFingerprintHex: string;
  readonly signatureHex: string;
  /** Verified previous version, when the verifier holds one (ruling B). */
  readonly predecessor?: ValuePredecessor | undefined;
}

function valueInvalid(reason: ValueInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "ValueInvalid"; readonly reason: ValueInvalidReason };
} {
  return { ok: false, error: { kind: "ValueInvalid", reason } };
}

// 2-3. Reason-code mapping of head binding / authorization time (§6.3-1 to
// -3). The check itself is headAuthorizationReason (validate.ts — shared
// with meta-verify)
const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "writer-not-member-at-head",
  keyMismatchAtHead: "writer-key-mismatch-at-head",
  roleInsufficientAtHead: "writer-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<ValueInvalidReason>;

function headStateReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { history, context } = input;
  const authorization = headAuthorizationReason<ValueInvalidReason>({
    history,
    chainHeadSeq: context.chainHeadSeq,
    chainHeadHashHex: context.chainHeadHashHex,
    actorUserId: context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
    // 3′. Scope (§6.3 — right after role, before epoch integrity)
    scope: {
      environmentId: context.environmentId,
      outOfScopeAtHead: "writer-environment-out-of-scope-at-head",
    },
  });
  if (authorization !== null) {
    return authorization;
  }
  // 4. Epoch integrity (§6.3-4): a pre-environment-creation head is rejected
  //    (no default fallback)
  const environment = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (environment === undefined) {
    return "environment-not-created-at-head";
  }
  if (environment.currentEpoch !== context.epoch) {
    return "epoch-not-current-at-head";
  }
  return null;
}

function prevReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { context, predecessor } = input;
  // The shape of prev (ruling B: always checked even under latest-only):
  // version 1 = empty, > 1 = 64 hex. The hex form of each field is already
  // checked by valueContextInvalidField, so this is only the coupling with
  // version
  if ((context.version === 1) !== (context.prevValueSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 6. Chaining integrity (§6.3-6): the real match of prev and epoch
  //    non-decrease (§4.1 monotonicity). A prev mismatch must not collapse
  //    into an Ed25519 failure (rulings B / C)
  if (context.prevValueSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) variable value against a verified
 * chain history (CRYPTO_SPEC §6.3 / §6.4). Returns the value's
 * signed-bytes hash on success — the anchor for the next version's prev
 * chain and for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed writer identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5: the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `writer-key-mismatch-at-head` check).
 */
export async function verifyDistributedValue(
  input: DistributedValueInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    valueContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.writerKeyFingerprintHex,
      actorKeyFingerprintField: "writerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // 1. Key selection (the lead-in to §6.3-1; check order = provisional
  //    ruling C): the shared core in validate.ts
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    onUnknown: { kind: "ValueInvalid", reason: "writer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyValueSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    writerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return valueInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return valueInvalid(chainReason);
  }

  const hash = await computeValueSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
