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

import type { AuditRotationRead } from "../audit-store-rotation-read.ts";
import type { AuditEventInput } from "../audit-store.ts";
import type { DataRejectedError, StaleWrapRef } from "../data.package/index.ts";
import { rejectData } from "../data.package/index.ts";
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

const rejectChainInvalid = (error: ChainInvalidError): DataRejectedError =>
  rejectData({ kind: "chain-entry-invalid", seq: error.seq, reason: error.reason });

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

export interface AppliedProposal {
  readonly proposalSeq: number;
  readonly inner: ProposableOperation;
}

export function proposalIndexOf(
  entries: readonly ChainEntry[],
  applied: VerifiedChainView,
): ProposalIndex {
  return indexProposals(
    entries,
    (seq) => applied.history.entryHashAt(seq),
    new Set(applied.state.pendingProposals.keys()),
  );
}

const NO_PROPOSALS: ProposalIndex = new Map();

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
  applyAcceptanceSideEffectsSync(stores, proposal.entry.payload.inner, entry.seq, nowMs);
  return { proposalSeq: proposal.entry.seq, inner: proposal.entry.payload.inner };
}

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
