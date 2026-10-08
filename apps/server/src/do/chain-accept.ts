// Shared implementation of chain-entry acceptance (CRYPTO_SPEC §6.4).
//
// Every path — the generic chain API (init / append in chain-do.ts) and
// composite requests (create / rotate in composite-programs.ts) — passes
// through the same 4-step acceptance: "canonical-size check → chain
// capacity → verifyChain re-run → insert + audit mirror". This
// structurally prevents a cap-semantics fix from landing on only one side.
// Errors travel as DataRejection; callers only fold them into an outcome.

import type {
  ChainInvalidError,
  ChainMirrorSubject,
  KeyFingerprintHex,
  ProposalIndex,
  UserId,
} from "@maruhi/core";
import { chainMirrorEvents, indexProposals } from "@maruhi/core";
import type { ChainEntry, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput, AuditRotationRead } from "../audit-store.ts";
import type { DataRejectedError } from "../data/data-plane.ts";
import { rejectData } from "../data/data-plane.ts";
import type { StaleWrapRef } from "../data/data-store.ts";
import {
  MAX_CHAIN_ENTRIES,
  MAX_CHAIN_TOTAL_CANONICAL_BYTES,
  MAX_ENTRY_CANONICAL_BYTES,
} from "../policy.ts";
import {
  detectDeviceRevocation,
  detectMemberRemoval,
  detectRoleChange,
  detectServerRevocation,
} from "../rotation-detect.ts";
import type { StoredChain, VerifiedChainView } from "./chain-store.ts";
import { canonicalBytesOf, verifyChainEffect } from "./chain-store.ts";

/** ChainInvalid (verification / encoder failure) → chain-entry-invalid rejection. */
const rejectChainInvalid = (error: ChainInvalidError): DataRejectedError =>
  rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason });

/** §6.4: canonical-size check for one entry. Returns the canonical byte count on pass. */
function checkEntrySize(entry: ChainEntry): Effect.Effect<number, DataRejectedError> {
  return canonicalBytesOf(entry).pipe(
    Effect.mapError(rejectChainInvalid),
    Effect.flatMap((bytes) =>
      bytes > MAX_ENTRY_CANONICAL_BYTES
        ? Effect.fail(
            rejectData({ kind: "chain-entry-too-large", limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
          )
        : Effect.succeed(bytes),
    ),
  );
}

/**
 * Acceptance policy (§6.4): caps on the whole chain's entry count and
 * cumulative byte count. The decision is a pure function of numbers only
 * (exposed for unit tests of the entry-count cap — generating a valid
 * 10,000-entry chain in an integration test is impractical).
 */
export function chainCapacityExceeded(
  entryCount: number,
  totalCanonicalBytes: number,
  addedCanonicalBytes: number,
): boolean {
  return (
    entryCount + 1 > MAX_CHAIN_ENTRIES ||
    totalCanonicalBytes + addedCanonicalBytes > MAX_CHAIN_TOTAL_CANONICAL_BYTES
  );
}

function ensureChainCapacity(
  chain: StoredChain,
  canonicalBytes: number,
): Effect.Effect<void, DataRejectedError> {
  if (chainCapacityExceeded(chain.entries.length, chain.totalCanonicalBytes, canonicalBytes)) {
    return Effect.fail(
      rejectData({
        kind: "chain-capacity-exceeded",
        maxEntries: MAX_CHAIN_ENTRIES,
        maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
      }),
    );
  }
  return Effect.void;
}

/**
 * CAS (§6.4): if the parent head does not match the current head, reject
 * with the current head's information (the worker maps this to a 409). The
 * uninitialized check is assumed done by the caller's preceding stage
 * (loadChainForMember / loadInitializedChain); here only the head match is
 * examined.
 */
export function ensureParentHead(
  chain: { readonly headSeq: number; readonly headHashHex: string },
  parentHeadHashHex: string,
): Effect.Effect<void, DataRejectedError> {
  if (parentHeadHashHex !== chain.headHashHex) {
    return Effect.fail(
      rejectData({
        kind: "chain-head-conflict",
        currentHeadSeq: chain.headSeq,
        currentHeadHashHex: chain.headHashHex,
      }),
    );
  }
  return Effect.void;
}

/**
 * Acceptance check (size → capacity → §6.4's full-chain re-verification =
 * prev_hash continuity, signatures, consensus rules). On acceptance,
 * returns the canonical byte count and the "verified view after applying
 * the entry" (the input for the composite wrap-decision reference state —
 * AUTH_SPEC §12-4 — and for the post-acceptance StateCache update).
 */
export const verifyAcceptableEntry = Effect.fn("chain-accept.verifyAcceptableEntry")(function* (
  chain: StoredChain,
  entry: ChainEntry,
): Effect.fn.Return<
  { readonly canonicalBytes: number; readonly applied: VerifiedChainView },
  DataRejectedError
> {
  const canonicalBytes = yield* checkEntrySize(entry);
  yield* ensureChainCapacity(chain, canonicalBytes);
  const applied = yield* verifyChainEffect([...chain.entries, entry]).pipe(
    Effect.mapError(rejectChainInvalid),
  );
  return { canonicalBytes, applied };
});

/**
 * Acceptance check for the composite's 2 entries (AUTH_SPEC §12-4: H+1 =
 * create / rotate, H+2 = the boundary `checkpoint`). The size check runs
 * per entry; the capacity check counts both entries together; verifyChain
 * (§6.4's consensus rules — the checkpoint's strict epoch equality holds
 * naturally under the "entry time = after H+1 is applied" basis —
 * CRYPTO_SPEC §6.2) runs once over the whole chain with both entries
 * applied. The returned `applied` is the verified view after both entries
 * (a history containing the boundary-checkpoint tuple = the input to the
 * checkpoint-binding verification of the bundled manifest — §4.3 (2)).
 */
export const verifyAcceptableEntryPair = Effect.fn("chain-accept.verifyAcceptableEntryPair")(
  function* (
    chain: StoredChain,
    first: ChainEntry,
    second: ChainEntry,
  ): Effect.fn.Return<
    {
      readonly firstCanonicalBytes: number;
      readonly secondCanonicalBytes: number;
      readonly applied: VerifiedChainView;
    },
    DataRejectedError
  > {
    const firstCanonicalBytes = yield* checkEntrySize(first);
    const secondCanonicalBytes = yield* checkEntrySize(second);
    if (
      chain.entries.length + 2 > MAX_CHAIN_ENTRIES ||
      chain.totalCanonicalBytes + firstCanonicalBytes + secondCanonicalBytes >
        MAX_CHAIN_TOTAL_CANONICAL_BYTES
    ) {
      return yield* Effect.fail(
        rejectData({
          kind: "chain-capacity-exceeded",
          maxEntries: MAX_CHAIN_ENTRIES,
          maxTotalBytes: MAX_CHAIN_TOTAL_CANONICAL_BYTES,
        }),
      );
    }
    const applied = yield* verifyChainEffect([...chain.entries, first, second]).pipe(
      Effect.mapError(rejectChainInvalid),
    );
    return { firstCanonicalBytes, secondCanonicalBytes, applied };
  },
);

/** The store surface insertAcceptedEntrySync writes through (structural subtype). */
export interface ChainAcceptStores {
  readonly chainStore: {
    readonly insertSync: (entry: ChainEntry, entryHashHex: string, canonicalBytes: number) => void;
  };
  readonly audit: {
    readonly appendSync: (event: AuditEventInput) => void;
    readonly appendManySync: (events: readonly AuditEventInput[]) => void;
    readonly readRotationSync: AuditRotationRead;
  };
  readonly dataStore: {
    readonly write: {
      readonly deleteStaleMemberWraps: (
        recipientUserId: UserId,
        keepEncPubHex: string,
      ) => readonly StaleWrapRef[];
      readonly deleteHeadAttestation: (attesterUserId: UserId) => void;
      readonly deleteDeviceHeadAttestation: (
        attesterUserId: UserId,
        keyFingerprintHex: KeyFingerprintHex,
      ) => void;
    };
  };
}

/**
 * The proposal a completed approve applied (the inner op and the proposal
 * entry's seq). Returned from the DO's append to the worker, which performs
 * on the inner op the same D1 post-processing as a directly appended
 * add_member / remove_member (invite completed matching, membership
 * projection) (design record es-design.md §11 K5-H).
 */
export interface AppliedProposal {
  readonly proposalSeq: number;
  readonly inner: ProposableOperation;
}

/**
 * The proposal index of the post-acceptance chain (including the accepted
 * entry) — the input to AUDIT_SPEC §3.4's approve / withdraw rows and the
 * application row. The derivation shares core's indexProposals between
 * server and CLI (K5-F).
 */
export function proposalIndexOf(
  entries: readonly ChainEntry[],
  applied: VerifiedChainView,
): ProposalIndex {
  // entryHashAt is a method on the index object (this-bound), so it is wrapped in an argument
  return indexProposals(
    entries,
    (seq) => applied.history.entryHashAt(seq),
    new Set(applied.state.pendingProposals.keys()),
  );
}

/** The empty index for paths that carry only non-proposable ops (the composite's create / rotate + boundary checkpoint). */
const NO_PROPOSALS: ProposalIndex = new Map();

/**
 * Inserts the accepted entry + §3.4 audit mirror + per-op acceptance side
 * effects (synchronous). Called from inside the caller's write phase so
 * that the chain insert, mirror append, and side effects commit atomically
 * in the same synchronous block (= the same task). serverTs (nowMs) is
 * always received as an argument so that its acquisition timing (after all
 * checks, immediately before the write phase) is uniform across paths.
 * The side effects live here so that future acceptance paths cannot
 * structurally produce shapes like "a remove was accepted but no flag was
 * raised" or "a re-add was accepted but stale key wraps remain" (the same
 * reason the 4 acceptance steps are shared).
 *
 * Four-eyes (K5): a completed approve writes `chain.approved` (completed =
 * true) followed by the inner op's application row (same chain_seq, actor =
 * the proposer, viaProposalSeq), then runs the inner op's side effects
 * anchored at the approve's seq (CRYPTO_SPEC §6.4: "identically to having
 * accepted the inner op directly, inside that approve entry's acceptance
 * task"). The return value is the applied proposal (null when incomplete
 * or non-four-eyes).
 *
 * Device keys (K3): `subject` is the device FP carried by `add_device`
 * (computed on the acceptance side — chain-commit.ts). `revoke_device`
 * deletes the device's attestation rows + the rotation-needed-detection
 * variant (AUDIT_SPEC §4.1).
 */
export function insertAcceptedEntrySync(
  stores: ChainAcceptStores,
  entry: ChainEntry,
  applied: VerifiedChainView,
  canonicalBytes: number,
  nowMs: number,
  proposals: ProposalIndex,
  subject: ChainMirrorSubject = {},
): AppliedProposal | null {
  stores.chainStore.insertSync(entry, applied.state.headHashHex, canonicalBytes);
  const rows = chainMirrorEvents(entry, nowMs, proposals, subject);
  stores.audit.appendManySync(rows);
  applyAcceptanceSideEffectsSync(stores, entry, entry.seq, nowMs);
  if (entry.op !== "approve") {
    return null;
  }
  const proposal = proposals.get(entry.payload.proposalHashHex);
  if (proposal === undefined || proposal.completedAtSeq !== entry.seq) {
    return null;
  }
  // The application row has already been written as the mirror's second
  // row (chainMirrorEvents). The side effects run on the inner op with
  // application seq = this approve's seq (ruling P7 — the obligation's
  // origin is the application time; the rotation-needed detection's
  // triggerChainSeq likewise)
  applyAcceptanceSideEffectsSync(stores, proposal.entry.payload.inner, entry.seq, nowMs);
  return { proposalSeq: proposal.entry.seq, inner: proposal.entry.payload.inner };
}

/**
 * Inserts the composite's 2 entries (H+1 / H+2 — already through
 * verifyAcceptableEntryPair) + mirror + side effects (synchronous, in seq
 * order). H+1's entry hash is H+2's prev_hash (verifyChain has verified
 * the chain linkage); H+2's hash is the head hash after both entries.
 * The checkpoint snapshot store (§6.4) cannot be derived from the entry
 * alone (it reconstructs the stored state at acceptance time), so the
 * caller's write phase performs it inside the same synchronous block, not
 * here. The ops this path carries (create / rotate / checkpoint) cannot
 * be proposed (CRYPTO_SPEC §6.2), so the proposal index may be empty.
 */
export function insertAcceptedEntryPairSync(
  stores: ChainAcceptStores,
  first: ChainEntry,
  second: ChainEntry,
  applied: VerifiedChainView,
  firstCanonicalBytes: number,
  secondCanonicalBytes: number,
  nowMs: number,
): void {
  stores.chainStore.insertSync(first, second.prevHashHex, firstCanonicalBytes);
  stores.audit.appendManySync(chainMirrorEvents(first, nowMs, NO_PROPOSALS));
  applyAcceptanceSideEffectsSync(stores, first, first.seq, nowMs);
  stores.chainStore.insertSync(second, applied.state.headHashHex, secondCanonicalBytes);
  stores.audit.appendManySync(chainMirrorEvents(second, nowMs, NO_PROPOSALS));
  applyAcceptanceSideEffectsSync(stores, second, second.seq, nowMs);
}

/**
 * Per-op acceptance side effects (after the mirror append, inside the same
 * task). The input is the op + payload (a signed entry, or the inner op a
 * completed approve applied) and the application seq.
 *
 * - `add_member`: on re-addition, sweep wraps addressed to the old key
 *   (AUTH_SPEC §12-6 — storage convergence to §6.3's "wrap target = exact
 *   match to a current member key" invariant). The deletion is
 *   dek.deleted (actor = system + cause payload — AUDIT_SPEC §3.3)
 * - `remove_member` / `change_role` (demotion, scope shrink — 2026-09-14
 *   ES) / `revoke_server`: rotation-needed detection (AUDIT_SPEC §4.1).
 *   The detection reads **after** the mirror append — the subject's
 *   membership / grant intervals and access windows are already closed by
 *   the mirror rows just written (via four-eyes it is the application
 *   row — same event name, same target index)
 * - `remove_member` additionally deletes the subject's head-attestation
 *   rows (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-1 — storage convergence to
 *   distributing only to current members; same shape as §12-6's old-key
 *   wrap sweep)
 * - `revoke_device` (2026-09-19 DK — CRYPTO_SPEC §6.4): deletes each
 *   revoked device's attestation rows (AUTH_SPEC §16-1) + the
 *   rotation-needed detection's `revoke_device` variant (AUDIT_SPEC §4.1 —
 *   device's valid interval ∩ person's access window ∩ device scope).
 *   `add_device`'s only side effect is the mirror (backfill is the
 *   client's — §7)
 * - The four-eyes 4 ops themselves (`set_approval_policy` / `propose` /
 *   `approve` / `withdraw`) have no dedicated side effects (a completed
 *   approve's inner op re-enters this function via the caller)
 */
function applyAcceptanceSideEffectsSync(
  stores: ChainAcceptStores,
  operation: ChainOperation,
  seq: number,
  nowMs: number,
): void {
  if (operation.op === "add_member") {
    const stale = stores.dataStore.write.deleteStaleMemberWraps(
      operation.payload.targetUserId,
      operation.payload.encPubHex,
    );
    if (stale.length > 0) {
      stores.audit.appendManySync(
        stale.map((ref) => ({
          event: "dek.deleted",
          serverTs: nowMs,
          actorType: "system" as const,
          targetUserId: operation.payload.targetUserId,
          environmentId: ref.environmentId,
          epoch: ref.epoch,
          payload: { cause: "member-readded", triggerChainSeq: seq },
        })),
      );
    }
    return;
  }
  if (operation.op === "remove_member") {
    stores.dataStore.write.deleteHeadAttestation(operation.payload.targetUserId);
    appendDetected(
      stores,
      detectMemberRemoval({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "change_role") {
    appendDetected(
      stores,
      detectRoleChange({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "revoke_server") {
    appendDetected(
      stores,
      detectServerRevocation({
        read: stores.audit.readRotationSync,
        serverKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
    return;
  }
  if (operation.op === "revoke_device") {
    for (const fingerprintHex of operation.payload.deviceFingerprintsHex) {
      stores.dataStore.write.deleteDeviceHeadAttestation(
        operation.payload.targetUserId,
        fingerprintHex,
      );
    }
    appendDetected(
      stores,
      detectDeviceRevocation({
        read: stores.audit.readRotationSync,
        targetUserId: operation.payload.targetUserId,
        deviceFingerprintsHex: operation.payload.deviceFingerprintsHex,
        triggerChainSeq: seq,
        nowMs,
      }),
    );
  }
}

function appendDetected(stores: ChainAcceptStores, events: readonly AuditEventInput[]): void {
  if (events.length > 0) {
    stores.audit.appendManySync(events);
  }
}
