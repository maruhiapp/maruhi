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
import type { ChainEntry } from "@maruhi/crypto";
import {
  canonicalChainEntryBytes,
  computeChainEntryHash,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Effect, Schema } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { ChainStore, StateCache } from "./chain-store.ts";
import type { DataActor, DataRejectedError } from "./data-plane.ts";
import { rejectData, requireMemberState } from "./data-plane.ts";
import {
  commitMirrorReplica,
  discardMirrorStaging,
  markMirror,
  type MirrorCommit,
  MirrorPageRefusedError,
  readMirrorState,
  stagedChainRows,
  stageMirrorPage,
  unmarkMirror,
} from "./do-mirror.ts";
import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "./do-schema.ts";
import { readWatermarks } from "./do-snapshot.ts";
import {
  MAX_EXPORT_PAGE_BYTES,
  MAX_EXPORT_PAGE_ROWS,
  MAX_MIRROR_PAGE_SLACK_BYTES,
} from "./policy.ts";
import { ensureStorageAdmitsGrowth, StorageMeter } from "./storage-guard.ts";

/** The status as the worker returns it (the wire shape of api-schema's MirrorStatusSchema). */
export interface MirrorStatusValue {
  readonly mirror: boolean;
  readonly sourceOrigin?: string;
  readonly markedAtMs?: number;
  readonly lastSync?: MirrorCommit;
  readonly nextSequence?: number;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq: number;
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
}

function statusOf(sql: SqlStorage): MirrorStatusValue {
  const marks = readWatermarks(sql);
  const head = {
    chainHeadSeq: marks.chainHeadSeq,
    // An initialized project always has a head (the role check passed)
    chainHeadHashHex: marks.chainHeadHashHex ?? "",
    auditMaxSeq: marks.auditMaxSeq,
  };
  const state = readMirrorState(sql);
  if (state === null) {
    return { mirror: false, head };
  }
  return {
    mirror: true,
    sourceOrigin: state.sourceOrigin,
    markedAtMs: state.markedAtMs,
    ...(state.lastSyncedAtMs === null
      ? {}
      : {
          lastSync: {
            atMs: state.lastSyncedAtMs,
            chainHeadSeq: state.lastHeadSeq,
            chainHeadHashHex: state.lastHeadHashHex,
            auditMaxSeq: state.lastAuditSeq,
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
  Effect.map(requireMemberState(actor.userId, "reader", cache), () => statusOf(sql));

export const markMirrorProgram = (
  actor: DataActor,
  sourceOrigin: string,
  sql: SqlStorage,
  cache: StateCache,
): Effect.Effect<MirrorStatusValue, DataRejectedError, ChainStore> =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "owner", cache);
    if (readMirrorState(sql) !== null) {
      return yield* rejectData({ kind: "mirror-state", reason: "already-mirror" });
    }
    markMirror(sql, sourceOrigin, Date.now());
    return statusOf(sql);
  });

/** The promotion (ruling C): the mark goes and the project accepts writes again. */
export const unmarkMirrorProgram = (
  actor: DataActor,
  storage: DurableObjectStorage,
  cache: StateCache,
): Effect.Effect<MirrorStatusValue, DataRejectedError, ChainStore> =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "owner", cache);
    if (readMirrorState(storage.sql) === null) {
      return yield* rejectData({ kind: "mirror-state", reason: "not-mirror" });
    }
    unmarkMirror(storage, PROJECT_DO_TABLES);
    return statusOf(storage.sql);
  });

/** A staging refusal as the data-plane rejection the worker maps to 422 MirrorSyncRejected. */
const refuse = (refusal: MirrorPageRefusedError): DataRejectedError =>
  rejectData({ kind: "mirror-sync-rejected", reason: refusal.reason });

/** Runs a synchronous staging step, folding its refusal into a value (any other throw is a defect). */
function staged<T>(step: () => T): Effect.Effect<T | MirrorPageRefusedError> {
  return Effect.sync(() => {
    try {
      return step();
    } catch (error) {
      if (error instanceof MirrorPageRefusedError) {
        return error;
      }
      throw error;
    }
  });
}

/** One staged row's entry: JSON that does not parse is malformed; a shape the wire schema refuses is an invalid chain. */
function decodeEntry(text: string): Effect.Effect<ChainEntry | MirrorPageRefusedError> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return Effect.succeed(new MirrorPageRefusedError("malformed"));
  }
  return Schema.decodeUnknownEffect(ChainEntrySchema)(parsed).pipe(
    Effect.map((entry): ChainEntry | MirrorPageRefusedError => entry as ChainEntry),
    Effect.catch(() => Effect.succeed(new MirrorPageRefusedError("chain-invalid"))),
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
 * the DO runs on load. Returns the refusal, or null when the chain is good.
 */
function verifyStagedChain(sql: SqlStorage): Effect.Effect<MirrorPageRefusedError | null> {
  return Effect.gen(function* () {
    const rows = yield* staged(() => stagedChainRows(sql));
    if (rows instanceof MirrorPageRefusedError) {
      return rows;
    }
    const invalid = new MirrorPageRefusedError("chain-invalid");
    const entries: ChainEntry[] = [];
    for (const row of rows) {
      const entry = yield* decodeEntry(row.entryJson);
      if (entry instanceof MirrorPageRefusedError) {
        return entry;
      }
      const hash = yield* Effect.promise(() => computeChainEntryHash(entry));
      if (
        entry.seq !== row.seq ||
        hash !== row.entryHashHex ||
        canonicalLength(entry) !== row.canonicalBytes
      ) {
        return invalid;
      }
      entries.push(entry);
    }
    const verified = yield* Effect.promise(() => verifyChainWithHistory(entries));
    return verified.ok ? null : invalid;
  });
}

export const mirrorPageProgram = (
  actor: DataActor,
  page: MirrorPageRequest,
  storage: DurableObjectStorage,
  cache: StateCache,
): Effect.Effect<MirrorPageValue, DataRejectedError, ChainStore | AuditStore | StorageMeter> =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    const sql = storage.sql;
    const state = readMirrorState(sql);
    if (state === null) {
      return yield* rejectData({ kind: "mirror-state", reason: "not-mirror" });
    }
    yield* ensureStorageAdmitsGrowth;
    const stagedPage = yield* staged(() =>
      stageMirrorPage({
        storage,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(sql),
        state,
        sequence: page.sequence,
        lines: page.lines,
        nowMs: Date.now(),
        maxRows: MAX_EXPORT_PAGE_ROWS,
        maxBytes: MAX_EXPORT_PAGE_BYTES + MAX_MIRROR_PAGE_SLACK_BYTES,
      }),
    );
    if (stagedPage instanceof MirrorPageRefusedError) {
      return yield* refuse(stagedPage);
    }
    if (stagedPage.kind === "staged") {
      return { nextSequence: stagedPage.nextSequence };
    }
    // The trailer page: the staged chain's content, then the swap (the
    // permit is held across the verification's awaits — nothing else runs)
    const invalid = yield* verifyStagedChain(sql);
    if (invalid !== null) {
      yield* Effect.sync(() => discardMirrorStaging(storage, PROJECT_DO_TABLES));
      return yield* refuse(invalid);
    }
    const commit = yield* staged(() =>
      commitMirrorReplica({ storage, tables: PROJECT_DO_TABLES, state, nowMs: Date.now() }),
    );
    if (commit instanceof MirrorPageRefusedError) {
      return yield* refuse(commit);
    }
    // The chain and the audit log were replaced: the derived memory is
    // discarded and the audit-head column extended to the end (the same
    // convergence as a restore — chain-do.ts opsRestore)
    const audit = yield* AuditStore;
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
