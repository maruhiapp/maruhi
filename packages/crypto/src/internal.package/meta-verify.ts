// History-based composite verification of CRYPTO_SPEC §6.3 (metadata
// statement verification) / §6.4 (server acceptance verification).
// Isomorphic to value-verify.ts (the verification mechanism is not
// double-implemented).
//
// Against the history index of a verified chain (chain-history.ts), checks
// §6.3's items 1-3 and 6 of a distributed (or submitted) statement:
//   1. Signature (key selection = FP match among the keys the history binds
//      to author_user_id)
//   2. Head binding (seq → hash match; distinguishes the 2 kinds of
//      mismatch — mismatch / future)
//   3. Authorization time (membership, key binding, and role at the declared
//      head — including rejection across tenure boundaries. Role levels:
//      variable create / rename / delete and environment create / rename =
//      member or above; only environment delete = admin or above — §4.2 /
//      AUTH_SPEC §12-3)
//   6. Chaining integrity (only when a predecessor is passed: prev match +
//      rejection of re-statement after deletion — §4.2's "no re-activation
//      after deleted" — plus layout v2's transition rules: no
//      active → declared, and per-variable layout monotonicity [rejecting a
//      v2 → v1 regression] — §4.2 layout v2, 0.8-draft)
// Coordinate integrity (§6.3-5) is the caller's duty: construct the context
// passed to this function from expected coordinates (the verified genesis
// hash, the requested environment, the outer response's variableId), not
// from the declared values.
//
// **There is no epoch integrity (§6.3-4)**: meta statements carry no epoch
// anchor (§4.2), and the environment's existence is not checked either
// (AUTH_SPEC §12-4 — at the declared head of a statement bundled into a
// compound environment creation, the environment does not exist yet. An
// intended asymmetry with value signatures). As a structural consequence,
// injecting a forged statement with a forward meta_version (at a declared
// head inside the membership interval) passes signature and chaining
// verification — v1's explicit residue (§14.3-5; fork evidence-making =
// divergence of the prev chain is the extent of the guarantee).
//
// The limits of latest-only (the session-14 ruling-B isomorph): even
// without a predecessor, the shapes of signature, head, key, role, and prev
// are always checked. The real match of prev and the rejection of
// re-statement after deletion are checked only when a predecessor is
// passed, and we do not falsely claim "checked" when it is not (the caller
// bears §14.3's non-guarantee).

import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, MetaInvalidReason } from "./errors.ts";
import {
  computeMetaSignedBytesHash,
  metaContextRejection,
  metaLayoutVersionOf,
  type MetaStatementContext,
  type MetaStatementStatus,
  verifyMetaStatementSignature,
} from "./meta-sign.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";

/**
 * The verified predecessor statement's anchor (§6.3-6): its signed-bytes
 * hash and its status. The caller must have verified the predecessor itself
 * (server: stored acceptance-time statements; client: a statement that
 * passed this same verification) — chaining onto unverified data would
 * poison the evidence chain (same root as AUTH_SPEC §12-5's 409 discipline).
 */
export interface MetaPredecessor {
  readonly signedBytesHashHex: string;
  readonly status: MetaStatementStatus;
  /**
   * The predecessor's wire layout version — the anchor of the per-variable
   * layout monotonicity check (§4.2: a successor of a lower layout than its
   * predecessor — v1 after v2, v2 after v3 — is rejected as `layout-regression`). **Required, not optional-with-default**:
   * this structure is assembled from a *verified* stored statement, and an
   * omitted-means-1 default would make the fail-closed monotonicity check
   * fail-open — a caller that forgets the field would silently wave a v2 → v1
   * regression through, which is the exact schema erasure the rule exists to
   * stop. Wire omission = 1 (§4.2) is the *wire* rule;
   * callers holding a v1 predecessor write `layoutVersion: 1` explicitly, so
   * the type checker catches layout-migration gaps.
   */
  readonly layoutVersion: number;
}

/** Input of the history-based distributed-statement verification (§6.3 / §6.4). */
export interface DistributedMetaStatementInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire statement fields (see module comment). */
  readonly context: MetaStatementContext;
  /** Distributed author key fingerprint (server: acceptance-time caller FP). */
  readonly authorKeyFingerprintHex: string;
  readonly signatureHex: string;
  /** Verified previous statement, when the verifier holds one (the ruling-B isomorph). */
  readonly predecessor?: MetaPredecessor | undefined;
}

function metaInvalid(reason: MetaInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "MetaStatementInvalid"; readonly reason: MetaInvalidReason };
} {
  return { ok: false, error: { kind: "MetaStatementInvalid", reason } };
}

/** §4.2 / §12-3 role levels: only environment delete is admin; everything else is member. */
function requiredRoleRank(context: MetaStatementContext): number {
  return context.target.kind === "environment" && context.status === "deleted"
    ? ROLE_RANK.admin
    : ROLE_RANK.member;
}

// 2-3. Reason-code mapping of head binding / authorization time (§6.3-1 to
// -3). The check itself is headAuthorizationReason (validate.ts — shared
// with value-verify)
const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "author-not-member-at-head",
  keyMismatchAtHead: "author-key-mismatch-at-head",
  roleInsufficientAtHead: "author-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<MetaInvalidReason>;

function headStateReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { history, context } = input;
  // Since epoch integrity (§6.3-4) does not exist for meta (see the module
  // header comment), the shared check (value signatures continue with §6.3-4
  // after it) is the whole thing as-is
  return headAuthorizationReason<MetaInvalidReason>({
    history,
    chainHeadSeq: context.chainHeadSeq,
    chainHeadHashHex: context.chainHeadHashHex,
    actorUserId: context.authorUserId,
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    requiredRoleRank: requiredRoleRank(context),
    reasons: HEAD_AUTHORIZATION_REASONS,
    // 3′. Scope (§6.3 — 2026-09-14 ES): environment meta (rename / delete)
    // and variable meta are all environment-targeting. A statement bundled
    // into a creation compound holds vacuously since the creator's scope is
    // all
    scope: {
      environmentId: context.environmentId,
      outOfScopeAtHead: "author-environment-out-of-scope-at-head",
    },
  });
}

// The predecessor checks of this layer see **only the hash chain,
// transitions, and layout monotonicity**. What the crypto layer
// intentionally does not check (the acceptance surface's domain; consistent
// with the v1 precedent):
// - The "full preservation from the previous" of a delete statement's
//   schema fields and name (§4.2) is an **acceptance check** (AUTH_SPEC
//   §12-5 — the same kind of acceptance check as name's "preserve the
//   previous active name" convention; v1's name preservation is isomorphic
//   and checked by apps/server/src/programs/programs-variable.ts). **The v2-delete
//   "schema fields / layout must match the previous" acceptance check is
//   mandatory on the acceptance surface** — without it, a modified delete
//   with a valid signature (status = deleted with rewritten schema fields)
//   would be accepted
// - metaVersion 1 + status deleted is rejected by the signing API
//   (signMetaStatement) but not by the distributed verification (a known
//   asymmetry since v1 — the acceptance surface [§12-5: a creation is
//   active or v2 declared] is authoritative)
function prevReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { context, predecessor } = input;
  // The shape of prev (always checked even under latest-only):
  // metaVersion 1 = empty, > 1 = 64 hex. The hex form of each field is
  // already checked by metaContextRejection, so this is only the coupling
  // with metaVersion
  if ((context.metaVersion === 1) !== (context.prevMetaSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 6. Chaining integrity (§6.3-6): the real match of prev. A prev mismatch
  //    must not collapse into an Ed25519 failure (the same ruling as
  //    value-verify)
  if (context.prevMetaSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  // §4.2: re-activation after deleted is forbidden (a tombstone is
  // terminal). Any successor of a deleted statement is rejected regardless
  // of status — blocks unauthorized revival of a deleted variable or
  // environment. This applies to a transition into declared too
  // (vector declared-after-delete)
  if (predecessor.status === "deleted") {
    return "revived-after-delete";
  }
  // §4.2 layout v2: active → declared is forbidden (never create a
  // rewinding representation of a value's existence — the only way to take
  // a value out is deletion). declared → declared (re-issuing the schema or
  // renaming while still declared) is legitimate and not rejected here
  if (predecessor.status === "active" && context.status === "declared") {
    return "declared-after-active";
  }
  // §4.2's per-variable layout monotonicity: a v1 successor of a variable
  // whose predecessor is v2 is rejected (allowing the regression would let
  // one rename silently erase the schema fields, bypassing the presence
  // guarantee §14.2-8 and schema-locked [AUTH_SPEC §12-11]). The
  // predecessor side is a mandatory field (fail-closed — see
  // MetaPredecessor's doc); only the context side applies the wire
  // convention (omitted = 1)
  // Generalized at layout 3 (PF6 R9): the layout never decreases (a v2
  // successor on a v3 variable would silently drop the max-age declaration)
  if (metaLayoutVersionOf(context) < predecessor.layoutVersion) {
    return "layout-regression";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) metadata statement against a
 * verified chain history (CRYPTO_SPEC §6.3 / §6.4). Returns the statement's
 * signed-bytes hash on success — the anchor for the next metaVersion's prev
 * chain and for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed author identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5: the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `author-key-mismatch-at-head` check).
 */
export async function verifyDistributedMetaStatement(
  input: DistributedMetaStatementInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  // The layout-selection check (ruling CR) is carried by
  // metaContextRejection: an unsupported layoutVersion is rejected as the
  // typed error UnsupportedMetaLayout before signature verification
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  const field = distributedInputInvalidField({
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    actorKeyFingerprintField: "authorKeyFingerprintHex",
    signatureHex: input.signatureHex,
    predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
  });
  if (field !== null) {
    return invalidInput(field);
  }

  // 1. Key selection (the lead-in to §6.3-1; the check order is the same as
  //    value-verify): the shared core in validate.ts
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.authorUserId,
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    onUnknown: { kind: "MetaStatementInvalid", reason: "author-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyMetaStatementSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    authorPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return metaInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return metaInvalid(chainReason);
  }

  const hash = await computeMetaSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
