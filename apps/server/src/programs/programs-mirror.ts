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
import type { DataActor, DataRejectedError } from "../data.package/index.ts";
import { rejectData, requireMemberState, roleAtLeast } from "../data.package/index.ts";
import type { ChainStore, StateCache } from "../do/chain-store.ts";
import { verifyStagedAuditHeads } from "../do/do-mirror-audit-verify.ts";
import { commitMirrorReplica, type MirrorCommit } from "../do/do-mirror-commit.ts";
import {
  discardMirrorStaging,
  markMirror,
  MirrorPageRefusedError,
  readMirrorState,
  remarkMirror,
  stagedChainRows,
  unmarkMirror,
} from "../do/do-mirror-state.ts";
import { stageMirrorPage } from "../do/do-mirror.ts";
import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../do/do-schema.ts";
import { readWatermarks } from "../do/do-snapshot.ts";
import {
  MAX_EXPORT_PAGE_BYTES,
  MAX_EXPORT_PAGE_ROWS,
  MAX_MIRROR_PAGE_SLACK_BYTES,
} from "../policy.ts";
import { ensureStorageAdmitsGrowth, StorageMeter } from "../storage-guard.ts";

export type MirrorSyncPosition = Omit<MirrorCommit, "ownAuditRows">;

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

export interface MirrorPageValue {
  readonly nextSequence: number;
  readonly committed?: MirrorCommit;
}

export interface MirrorPageRequest {
  readonly sequence: number;
  readonly lines: readonly string[];
  readonly sourceMutationSeq: number;
}

function statusOf(sql: SqlStorage, role: Role): MirrorStatusValue {
  const marks = readWatermarks(sql);
  const admin = roleAtLeast(role, "admin");
  const head = {
    chainHeadSeq: marks.chainHeadSeq,
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
    remarkMirror(storage, PROJECT_DO_TABLES, sourceOrigin, yield* Clock.currentTimeMillis);
  }
  return statusOf(sql, "owner");
});

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

const refuse = (refusal: MirrorPageRefusedError): DataRejectedError =>
  rejectData({ kind: "mirror-sync-rejected", reason: refusal.reason });

const decodeEntryJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown));
const decodeChainEntry = Schema.decodeUnknownEffect(ChainEntrySchema);

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

const verifyStagedChain = Effect.fn("programs-mirror.verifyStagedChain")(function* (
  sql: SqlStorage,
): Effect.fn.Return<void, MirrorPageRefusedError> {
  const rows = yield* stagedChainRows(sql);
  const invalid = new MirrorPageRefusedError({ reason: "chain-invalid" });
  const entries: ChainEntry[] = [];
  for (const row of rows) {
    const entry = yield* decodeEntry(row.entryJson);
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
  const audit = yield* AuditStore;
  while ((yield* audit.ensureHeadCurrent) === "more-remains") {}
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
  const discardAndRefuse = (refusal: MirrorPageRefusedError) =>
    Effect.andThen(
      Effect.sync(() => discardMirrorStaging(storage, PROJECT_DO_TABLES)),
      refuse(refusal),
    );
  yield* verifyStagedChain(sql).pipe(Effect.catchTag("MirrorPageRefused", discardAndRefuse));
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
  yield* Effect.sync(() => {
    cache.chain = null;
    cache.current = null;
    audit.resetSeqCacheSync();
  });
  while ((yield* audit.ensureHeadCurrent) === "more-remains") {}
  return { nextSequence: 0, committed: commit };
});
