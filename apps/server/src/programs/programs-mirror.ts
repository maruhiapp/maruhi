// Mirror programs (AUTH_SPEC §11-7 — PF2, docs/notes/pf2-design.md).
//
// - status: chain role reader or above — the mark, the last replication,
//   the sequence a replication in progress expects, the mirror's head
// - mark / unmark: owner. The mark turns the project read-only at once
//   (the DO's write guard — chain-do.ts); unmarking is the promotion
// - page: admin or above (judged on the mirror's current chain), then
//   the mark, then the storage guard (the staging is growth — §12-8),
//   then the page (do-mirror.ts). The trailer page passes the
//   synchronous checks there; this program then verifies the staged
//   chain in full (every entry decodes, its hash and canonical size match
//   the row, the chain verifies — the existing verifier, no new crypto;
//   `chain-invalid`) before the commit, so a replica whose chain the
//   mirror could not load never replaces the live one. A commit replaces
//   the chain, so the DO's derived caches are discarded and the
//   audit-head column is extended to the end, as after a restore
//
// All run under the DO's permit synchronously. No audit row is written
// for any of them (ruling G: the mirror's log is the source's, followed
// by the rows the mirror itself appends while serving reads and leases).

import { ChainEntrySchema } from "@maruhi/api-schema";
import { cryptoEffect, cryptoPromise } from "@maruhi/core";
import type { ChainEntry, Role } from "@maruhi/crypto";
import {
  canonicalChainEntryBytes,
  computeChainEntryHash,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Clock, Effect, Schema } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, DataRejectedError } from "../data/data-plane.ts";
import { rejectData, requireMemberState, roleAtLeast } from "../data/data-plane.ts";
import type { ChainStore, StateCache } from "../do/chain-store.ts";
import {
  commitMirrorReplica,
  verifyStagedAuditHeads,
  discardMirrorStaging,
  markMirror,
  remarkMirror,
  type MirrorCommit,
  MirrorPageRefusedError,
  readMirrorState,
  stagedChainRows,
  stageMirrorPage,
  unmarkMirror,
} from "../do/do-mirror.ts";
import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../do/do-schema.ts";
import { readWatermarks } from "../do/do-snapshot.ts";
import {
  MAX_EXPORT_PAGE_BYTES,
  MAX_EXPORT_PAGE_ROWS,
  MAX_MIRROR_PAGE_SLACK_BYTES,
} from "../policy.ts";
import { ensureStorageAdmitsGrowth, StorageMeter } from "../storage-guard.ts";

/** The last replication as the status reports it (the commit's position; the re-appended count is a commit's answer only). */
export type MirrorSyncPosition = Omit<MirrorCommit, "ownAuditRows">;

/**
 * The status as the worker returns it (the wire shape of api-schema's
 * MirrorStatusSchema). The audit seq, the attestation mark and the last
 * replication are shown to admins and owners only (ruling G revision —
 * the audit seq is never distributed below admin, AUDIT_SPEC §7 C1); every
 * member sees the mark, the source and the chain head (the fallback read
 * checks them before it trusts a mirror).
 */
export interface MirrorStatusValue {
  readonly mirror: boolean;
  readonly sourceOrigin?: string;
  readonly markedAtMs?: number;
  readonly lastSync?: MirrorSyncPosition;
  readonly nextSequence?: number;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq?: number;
    readonly attestationMark?: number;
    readonly mutationSeq?: number;
  };
}

/** One page's outcome (the wire shape of MirrorPageOutcomeSchema). */
export interface MirrorPageValue {
  readonly nextSequence: number;
  readonly committed?: MirrorCommit;
}

export interface MirrorPageRequest {
  readonly sequence: number;
  readonly lines: readonly string[];
  /** The source's mutation counter as the export's head reported it (the trailer page records it). */
  readonly sourceMutationSeq: number;
}

function statusOf(sql: SqlStorage, role: Role): MirrorStatusValue {
  const marks = readWatermarks(sql);
  const admin = roleAtLeast(role, "admin");
  const head = {
    chainHeadSeq: marks.chainHeadSeq,
    // An initialized project always has a head (the role check passed)
    chainHeadHashHex: marks.chainHeadHashHex ?? "",
    ...(admin
      ? {
          auditMaxSeq: marks.auditMaxSeq,
          attestationMark: marks.attestationMark,
          mutationSeq: marks.mutationSeq,
        }
      : {}),
  };
  const state = readMirrorState(sql);
  if (state === null) {
    return { mirror: false, head };
  }
  return {
    mirror: true,
    sourceOrigin: state.sourceOrigin,
    markedAtMs: state.markedAtMs,
    // The commit writes the sync time and the source's counter together,
    // so both are set exactly when a replication was recorded
    ...(state.lastSyncedAtMs === null || state.lastMutationSeq === null || !admin
      ? {}
      : {
          lastSync: {
            atMs: state.lastSyncedAtMs,
            chainHeadSeq: state.lastHeadSeq,
            chainHeadHashHex: state.lastHeadHashHex,
            auditMaxSeq: state.lastAuditSeq,
            attestationMark: state.lastAttestationMark,
            mutationSeq: state.lastMutationSeq,
          },
        }),
    ...(state.expectedSequence === 0 ? {} : { nextSequence: state.expectedSequence }),
    head,
  };
}

export const mirrorStatusProgram = (
  actor: DataActor,
  sql: SqlStorage,
  cache: StateCache,
): Effect.Effect<MirrorStatusValue, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(actor.userId, "reader", cache), ({ member }) =>
    statusOf(sql, member.role),
  );

export const markMirrorProgram = Effect.fn("programs-mirror.markMirrorProgram")(function* (
  actor: DataActor,
  sourceOrigin: string,
  storage: DurableObjectStorage,
  cache: StateCache,
): Effect.fn.Return<MirrorStatusValue, DataRejectedError, ChainStore> {
  yield* requireMemberState(actor.userId, "owner", cache);
  const sql = storage.sql;
  const current = readMirrorState(sql);
  if (current === null) {
    markMirror(sql, sourceOrigin, yield* Clock.currentTimeMillis);
  } else if (current.sourceOrigin === sourceOrigin) {
    return yield* rejectData({ kind: "mirror-state", reason: "already-mirror" });
  } else {
    // A mark naming another source re-points the mirror (ruling C
    // revision, round 4): the project stays frozen throughout
    remarkMirror(storage, PROJECT_DO_TABLES, sourceOrigin, yield* Clock.currentTimeMillis);
  }
  return statusOf(sql, "owner");
});

/** The promotion (ruling C): the mark goes and the project accepts writes again. */
export const unmarkMirrorProgram = Effect.fn("programs-mirror.unmarkMirrorProgram")(function* (
  actor: DataActor,
  storage: DurableObjectStorage,
  cache: StateCache,
): Effect.fn.Return<MirrorStatusValue, DataRejectedError, ChainStore> {
  yield* requireMemberState(actor.userId, "owner", cache);
  if (readMirrorState(storage.sql) === null) {
    return yield* rejectData({ kind: "mirror-state", reason: "not-mirror" });
  }
  unmarkMirror(storage, PROJECT_DO_TABLES);
  return statusOf(storage.sql, "owner");
});

/** A staging refusal as the data-plane rejection the worker maps to 422 MirrorSyncRejected. */
const refuse = (refusal: MirrorPageRefusedError): DataRejectedError =>
  rejectData({ kind: "mirror-sync-rejected", reason: refusal.reason });

const decodeEntryJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown));
const decodeChainEntry = Schema.decodeUnknownEffect(ChainEntrySchema);

/** One staged row's entry: JSON that does not parse is malformed; a shape the wire schema refuses is an invalid chain. */
function decodeEntry(text: string): Effect.Effect<ChainEntry, MirrorPageRefusedError> {
  return decodeEntryJson(text).pipe(
    Effect.mapError(() => new MirrorPageRefusedError({ reason: "malformed" })),
    Effect.flatMap((parsed) =>
      decodeChainEntry(parsed).pipe(
        Effect.map((entry) => entry as ChainEntry),
        Effect.mapError(() => new MirrorPageRefusedError({ reason: "chain-invalid" })),
      ),
    ),
  );
}

function canonicalLength(entry: ChainEntry): number {
  try {
    return canonicalChainEntryBytes(entry).length;
  } catch {
    return -1;
  }
}

/**
 * The content verification of the staged chain (AUTH_SPEC §11-7 —
 * `chain-invalid`): every entry decodes, its hash and canonical size
 * match the row's, and the whole chain verifies with the same verifier
 * the DO runs on load.
 */
const verifyStagedChain = Effect.fn("programs-mirror.verifyStagedChain")(function* (
  sql: SqlStorage,
): Effect.fn.Return<void, MirrorPageRefusedError> {
  const rows = yield* stagedChainRows(sql);
  const invalid = new MirrorPageRefusedError({ reason: "chain-invalid" });
  const entries: ChainEntry[] = [];
  for (const row of rows) {
    const entry = yield* decodeEntry(row.entryJson);
    // A rejection is a platform defect, the same outcome the bare
    // Promise's rejection propagated as before the bridge
    const hash = yield* cryptoPromise("computeChainEntryHash", () =>
      computeChainEntryHash(entry),
    ).pipe(Effect.orDie);
    if (
      entry.seq !== row.seq ||
      hash !== row.entryHashHex ||
      canonicalLength(entry) !== row.canonicalBytes
    ) {
      return yield* invalid;
    }
    entries.push(entry);
  }
  yield* cryptoEffect(() => verifyChainWithHistory(entries)).pipe(Effect.mapError(() => invalid));
});

export const mirrorPageProgram = Effect.fn("programs-mirror.mirrorPageProgram")(function* (
  actor: DataActor,
  page: MirrorPageRequest,
  storage: DurableObjectStorage,
  cache: StateCache,
): Effect.fn.Return<MirrorPageValue, DataRejectedError, ChainStore | AuditStore | StorageMeter> {
  yield* requireMemberState(actor.userId, "admin", cache);
  const sql = storage.sql;
  const state = readMirrorState(sql);
  if (state === null) {
    return yield* rejectData({ kind: "mirror-state", reason: "not-mirror" });
  }
  yield* ensureStorageAdmitsGrowth;
  // The mirror's own audit-head column must reach the replicated position
  // before the trailer compares the replica's column with it (ruling J
  // revision, round 8); a column that is current costs one read
  const audit = yield* AuditStore;
  while ((yield* audit.ensureHeadCurrent) === "more-remains") {
    // Terminates: every call makes progress (the bounded contract of audit-store.ts)
  }
  const stagedPage = yield* stageMirrorPage({
    storage,
    tables: PROJECT_DO_TABLES,
    schemaVersion: readProjectDoSchemaVersion(sql),
    state,
    sequence: page.sequence,
    lines: page.lines,
    nowMs: yield* Clock.currentTimeMillis,
    maxRows: MAX_EXPORT_PAGE_ROWS,
    maxBytes: MAX_EXPORT_PAGE_BYTES + MAX_MIRROR_PAGE_SLACK_BYTES,
  }).pipe(Effect.catchTag("MirrorPageRefused", refuse));
  if (stagedPage.kind === "staged") {
    return { nextSequence: stagedPage.nextSequence };
  }
  // The trailer page: the staged chain's content, then the swap (the
  // permit is held across the verification's awaits — nothing else
  // runs). These checks run outside the page's transaction, so a
  // refusal discards the staging explicitly before it is mapped
  const discardAndRefuse = (refusal: MirrorPageRefusedError) =>
    Effect.andThen(
      Effect.sync(() => discardMirrorStaging(storage, PROJECT_DO_TABLES)),
      refuse(refusal),
    );
  yield* verifyStagedChain(sql).pipe(Effect.catchTag("MirrorPageRefused", discardAndRefuse));
  // … and the staged audit log's heads, derived before anything live is
  // touched (ruling J revision, round 10)
  yield* verifyStagedAuditHeads(sql, state).pipe(
    Effect.catchTag("MirrorPageRefused", discardAndRefuse),
  );
  const commit = yield* commitMirrorReplica({
    storage,
    tables: PROJECT_DO_TABLES,
    state,
    nowMs: yield* Clock.currentTimeMillis,
    sourceMutationSeq: page.sourceMutationSeq,
  }).pipe(Effect.catchTag("MirrorPageRefused", refuse));
  // The chain and the audit log were replaced: the derived memory is
  // discarded and the audit-head column extended to the end (the same
  // convergence as a restore — chain-do.ts opsRestore)
  yield* Effect.sync(() => {
    cache.chain = null;
    cache.current = null;
    audit.resetSeqCacheSync();
  });
  while ((yield* audit.ensureHeadCurrent) === "more-remains") {
    // Terminates: every call makes progress (the bounded contract of audit-store.ts)
  }
  return { nextSequence: 0, committed: commit };
});
