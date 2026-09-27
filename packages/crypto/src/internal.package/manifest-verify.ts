// History-based composite verification of CRYPTO_SPEC §4.3 / §6.3
// (environment manifest verification) / §6.4 (server acceptance
// verification). Isomorphic to value-verify.ts / meta-verify.ts (the
// verification mechanism is not double-implemented — the single
// implementation shared by server / CLI, per §4.3's "the canonical
// implementation lives exactly once in packages/crypto").
//
// Against the history index of a verified chain (chain-history.ts), checks
// the §6.3 items 1-3 and 5 isomorphs plus epoch integrity and digest
// recomputation of a distributed (or submitted) manifest:
//   1. Signature (key selection = FP match among the keys the history binds
//      to issuer_user_id)
//   2. Head binding (seq → hash match; distinguishes the 2 kinds of
//      mismatch — mismatch / future)
//   3. Authorization time (membership, key binding, and role at the declared
//      head — every issuing occasion is a member-or-above meta operation
//      — §4.3)
//   4. Epoch integrity (§4.3 (2)): when a `checkpoint` tuple for that
//      (environment_id, manifest_version) exists on the verified chain, the
//      manifest must **exactly match** its (epoch, manifest_sig_hash)
//      (boundary-checkpoint binding — strict is **not** an alternative path
//      in that case. A manifest of a compound environment-creation / rotate
//      is verified through this path via the boundary checkpoint the
//      compound must bundle — AUTH_SPEC §12-4). When tuples with differing
//      (epoch, manifest_sig_hash) coexist at the same coordinate, reject as
//      hard evidence of equivocation. Only when no tuple exists: strict
//      equality with the environment's current epoch at the declared head
//      (strict)
//   5. Environment-meta integrity: (env_meta_version,
//      env_meta_sig_hash_hex) = the latest form of the verified environment
//      meta statement (the recomputation target of AUTH_SPEC §12-5 (7))
//   6. Digest recomputation (§4.3 (3)): a recomputed variables_digest match
//      against all verified statements (tombstones included). A mismatch =
//      detected omission, injection, or ordering violation
//   7. prev chaining (only when a predecessor is passed: prev match +
//      **epoch non-decrease** — the manifest version of the value's §4.1
//      monotonicity; detecting a forward manifestVersion that baked in an
//      old epoch after a rotate is the core of this mechanism)
//   8. Rule 1 of checkpoint integrity (§6.3 / §4.3 (4)): manifestVersion
//      and epoch must be at least the environment's **latest** `checkpoint`
//      baseline (a baseline violation is rejected as a rollback from an
//      already-checkpointed state; this also closes the downward bypass of
//      (4)'s reconciliation for a tuple-bearing version — the check order
//      [binding (4) → this rule] is pinned by vectors
//      checkpoint-binding-mismatch / checkpoint-regressed). Same version /
//      different hash is rejected by (4)'s binding (the baseline = the
//      latest checkpoint's own tuple)
// Coordinate integrity (§6.3-5) is the caller's duty: construct the context
// passed to this function from expected coordinates (the verified genesis
// hash, the requested environment), not from the declared values.
// entries / envMeta must likewise be built from **verified** statements
// (server = stored rows of post-acceptance state; client = distributed
// statements that passed §6.3 verification).
//
// The reconciliation material of checkpoint binding (4) is the history
// index's internal lookup (checkpointTupleFor — session-33 ruling A), not a
// caller input: an explicit-input form would allow the fail-open of
// "forgetting = falling back to strict" as a calling-convention bug (while
// a tuple exists yet the strict path stays alive, the equivocation
// advantage disappears — a reprise of why session-32 §4-2 killed the
// disjunctive form), so the structure is closed.
//
// The limits of latest-only (the session-14 ruling-B isomorph): even
// without a predecessor, the shapes of signature, head, key, role, epoch,
// env-meta, digest, and prev are always checked. The real match of prev and
// the epoch non-decrease are checked only when a predecessor is passed, and
// we do not falsely claim "checked" when it is not (the caller bears
// §14.3's non-guarantee — the floor's manifest expansion and checkpoint
// integrity compensate).

import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ManifestInvalidReason } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  buildEnvManifestSignedBytes,
  computeVariablesDigest,
  type EnvManifestContext,
  manifestContextInvalidField,
  type VariablesDigestEntry,
  verifyEnvManifestSignature,
} from "./manifest-sign.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";

/**
 * The verified predecessor manifest's anchor (the §4.3 chaining): its signed-bytes
 * hash and its epoch. The caller must have verified the predecessor itself
 * (server: the stored latest manifest; client: a manifest that passed this
 * same verification / the local floor's manifest record) — chaining onto
 * unverified data would poison the evidence chain.
 */
export interface EnvManifestPredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** The latest verified environment meta statement the manifest must bind. */
export interface EnvManifestEnvMeta {
  readonly metaVersion: number;
  readonly sigHashHex: string;
}

/** Input of the history-based distributed-manifest verification (§4.3 / §6.3 / §6.4). */
export interface DistributedEnvManifestInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire manifest fields (see module comment). */
  readonly context: EnvManifestContext;
  /** Distributed issuer key fingerprint (server: acceptance-time caller FP). */
  readonly issuerKeyFingerprintHex: string;
  readonly signatureHex: string;
  /**
   * The **verified** statement set the digest is recomputed from — every
   * variable's latest statement including tombstones (§4.3 (3)).
   */
  readonly entries: readonly VariablesDigestEntry[];
  /** The **verified** latest environment meta statement (§12-5 (7)). */
  readonly envMeta: EnvManifestEnvMeta;
  /** Verified previous manifest, when the verifier holds one (the ruling-B isomorph). */
  readonly predecessor?: EnvManifestPredecessor | undefined;
}

function manifestInvalid(reason: ManifestInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason };
} {
  return { ok: false, error: { kind: "EnvManifestInvalid", reason } };
}

// 2-3. Reason-code mapping of head binding / authorization time (§6.3-1 to
// -3). The check itself is headAuthorizationReason (validate.ts — shared
// with value-verify / meta-verify)
const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "issuer-not-member-at-head",
  keyMismatchAtHead: "issuer-key-mismatch-at-head",
  roleInsufficientAtHead: "issuer-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<ManifestInvalidReason>;

/**
 * 4. Epoch integrity (§4.3 (2) — checkpoint binding).
 * When a tuple exists, the reconciliation is against **both** of (epoch,
 * manifest_sig_hash): the hash covers the epoch as a signed field, but a
 * shape where the tuple-side epoch field contradicts the manifest content
 * (a false notarization that landed on the chain) is not detected by hash
 * comparison alone. When a tuple exists, the environment-existence check at
 * the declared head is not performed (the legitimate shape of an
 * environment-creation compound — the environment does not yet exist at
 * declared head H; the create at H+1 and the boundary checkpoint at H+2
 * land in the same transaction).
 */
function epochIntegrityReason(
  input: DistributedEnvManifestInput,
  signedBytesHashHex: string,
): ManifestInvalidReason | null {
  const { history, context } = input;
  const tuple = history.checkpointTupleFor(context.environmentId, context.manifestVersion);
  if (tuple !== undefined) {
    if (tuple.kind === "conflicting") {
      return "checkpoint-equivocation";
    }
    return tuple.epoch === context.epoch && tuple.manifestSigHashHex === signedBytesHashHex
      ? null
      : "checkpoint-binding-mismatch";
  }
  // strict: strict equality with the environment's current epoch at the
  // declared head (deletion and demotion below member both carry an
  // all-environment rotation — §7 — so a key that lost write eligibility
  // cannot sign a manifest at the current epoch)
  const atHead = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (atHead === undefined) {
    return "environment-not-created-at-head";
  }
  return atHead.currentEpoch === context.epoch ? null : "epoch-not-current-at-head";
}

/**
 * 8. Rule 1 of checkpoint integrity (§6.3 / §4.3 (4)): manifestVersion and
 * epoch must not regress below the environment's latest `checkpoint`
 * baseline. Environments without a baseline are out of scope (their
 * guarantee is epoch integrity only — §6.3). Rejection of same version /
 * different hash is carried by (4)'s binding (a tuple for the baseline's
 * version always exists).
 */
function checkpointIntegrityReason(
  input: DistributedEnvManifestInput,
): ManifestInvalidReason | null {
  const baseline = input.history.latestCheckpointFor(input.context.environmentId);
  if (baseline === undefined) {
    return null;
  }
  if (
    input.context.manifestVersion < baseline.manifestVersion ||
    input.context.epoch < baseline.epoch
  ) {
    return "checkpoint-regressed";
  }
  return null;
}

async function contentReason(
  input: DistributedEnvManifestInput,
): Promise<ManifestInvalidReason | null> {
  const { context } = input;
  // 5. Environment-meta integrity (AUTH_SPEC §12-5 (7)): the coordinates
  //    of the environment meta statement the manifest binds must match the
  //    verified latest form
  if (
    context.envMetaVersion !== input.envMeta.metaVersion ||
    context.envMetaSigHashHex !== input.envMeta.sigHashHex
  ) {
    return "env-meta-mismatch";
  }
  // 6. Digest recomputation (§4.3 (3)): a recomputed match from the
  //    verified statement set (tombstones included). A mismatch = statement
  //    omission, injection, or ordering violation
  const digest = await computeVariablesDigest(context.suite, input.entries);
  if (!digest.ok) {
    // entries come from verified statements, so a structure violation is a
    // caller bug. Fold it here into the same reason code as a form mismatch
    // (contains no secrets)
    return "variables-digest-mismatch";
  }
  return digest.value === context.variablesDigestHex ? null : "variables-digest-mismatch";
}

function prevReason(input: DistributedEnvManifestInput): ManifestInvalidReason | null {
  const { context, predecessor } = input;
  // The shape of prev (always checked even under latest-only):
  // manifestVersion 1 = empty, > 1 = 64 hex. The hex form of each field is
  // already checked by manifestContextInvalidField, so this is only the
  // coupling with manifestVersion
  if ((context.manifestVersion === 1) !== (context.prevManifestSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 7. Chaining integrity: the real match of prev and epoch non-decrease
  //    (the manifest version of §4.1 monotonicity — detecting a forward
  //    manifestVersion that baked in an old epoch after a rotate).
  //    A prev mismatch must not collapse into an Ed25519 failure (the same
  //    ruling as value-verify)
  if (context.prevManifestSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) environment manifest against a
 * verified chain history (CRYPTO_SPEC §4.3 / §6.3 / §6.4). Returns the
 * manifest's signed-bytes hash on success — the anchor for the next
 * manifestVersion's prev chain, for the local floor's manifest record and
 * for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed issuer identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5 (1): the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `issuer-key-mismatch-at-head` check).
 */
export async function verifyDistributedEnvManifest(
  input: DistributedEnvManifestInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    manifestContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
      actorKeyFingerprintField: "issuerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // 1. Key selection (the lead-in to §6.3-1; the check order is the same as
  //    value-verify / meta-verify)
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    onUnknown: { kind: "EnvManifestInvalid", reason: "issuer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyEnvManifestSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    issuerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  // 2-3. Head binding / authorization time (every issuing occasion is member
  //    or above — §4.3)
  const headReason = headAuthorizationReason<ManifestInvalidReason>({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
    // 3′. Scope (§6.3 — 2026-09-14 ES): manifests are environment-targeting
    scope: {
      environmentId: input.context.environmentId,
      outOfScopeAtHead: "issuer-environment-out-of-scope-at-head",
    },
  });
  if (headReason !== null) {
    return manifestInvalid(headReason);
  }
  // The prev chaining is part of §4.3 (1) (isomorphic to §6.3-6) and
  // precedes epoch integrity (2) (the vectors pin that the shape checks of
  // v1-nonempty-prev / v2-empty-prev land before the binding judgment)
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return manifestInvalid(chainReason);
  }
  // The reconciliation target of checkpoint binding (2) = the hash of the
  // manifest's own signed_bytes (identical to the success return value —
  // computed early for the binding reconciliation)
  const signedBytesHashHex = encodeHex(await sha256(buildEnvManifestSignedBytes(input.context)));
  const epochReason = epochIntegrityReason(input, signedBytesHashHex);
  if (epochReason !== null) {
    return manifestInvalid(epochReason);
  }
  const digestReason = await contentReason(input);
  if (digestReason !== null) {
    return manifestInvalid(digestReason);
  }
  const checkpointReason = checkpointIntegrityReason(input);
  if (checkpointReason !== null) {
    return manifestInvalid(checkpointReason);
  }
  return { ok: true, value: { signedBytesHashHex } };
}
