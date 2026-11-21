import type { UserId } from "@maruhi/core";
import { Clock, Effect, Option, Schema } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, DataRejectedError } from "../data.package/index.ts";
import { dataEvent, DataStore, rejectData, requireMemberState } from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import type { ChainStore } from "../do/chain-store.ts";
import { readMirrorState } from "../do/do-mirror.ts";
import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "../do/do-schema.ts";
import {
  decodeExportCursor,
  encodeExportCursor,
  type ExportCursorState,
  type ExportPageResult,
  exportSnapshotPage,
} from "../do/do-snapshot-export.ts";
import { MAX_EXPORT_PAGE_BYTES, MAX_EXPORT_PAGE_ROWS, MAX_EXPORTS_PER_WINDOW } from "../policy.ts";
import type { StorageMeter } from "../storage-guard.ts";
import { observeStorageLevel } from "../storage-guard.ts";

export interface ExportPageValue {
  readonly lines: readonly string[];
  readonly next: string | null;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq: number;
    readonly mutationSeq: number;
    readonly mirrorOf?: string;
  };
}

export const exportPageProgram = Effect.fn("programs-export.exportPageProgram")(function* (
  actor: DataActor,
  cursorText: string | null,
  sql: SqlStorage,
  doIdHex: string,
  cache: StateCache,
): Effect.fn.Return<
  ExportPageValue,
  DataRejectedError,
  ChainStore | DataStore | AuditStore | StorageMeter
> {
  const { state } = yield* requireMemberState(actor.userId, "owner", cache);
  const nowMs = yield* Clock.currentTimeMillis;
  const cursor = yield* continuationOf(cursorText, sql, actor.userId);
  const exportedSeq =
    cursor === null
      ? yield* openExport(actor, state.headSeq, state.headHashHex, sql, nowMs)
      : cursor.exportedSeq;
  const { page, mirrorOf } = yield* Effect.sync(() => ({
    page: exportSnapshotPage({
      sql,
      tables: PROJECT_DO_TABLES,
      schemaVersion: readProjectDoSchemaVersion(sql),
      doIdHex,
      takenAtMs: nowMs,
      cursor,
      exportedSeq,
      maxRows: MAX_EXPORT_PAGE_ROWS,
      maxBytes: MAX_EXPORT_PAGE_BYTES,
    }),
    mirrorOf: readMirrorState(sql)?.sourceOrigin ?? null,
  }));
  if (page.kind === "changed") {
    return yield* rejectData({ kind: "export-changed" });
  }
  return pageValue(page, mirrorOf);
});

function continuationOf(
  cursorText: string | null,
  sql: SqlStorage,
  userId: UserId,
): Effect.Effect<ExportCursorState | null, DataRejectedError> {
  if (cursorText === null) {
    return Effect.succeed(null);
  }
  const cursor = decodeExportCursor(cursorText);
  return cursor !== null && exportRowBinds(sql, cursor, userId)
    ? Effect.succeed(cursor)
    : rejectData({ kind: "export-changed" });
}

function pageValue(
  page: Extract<ExportPageResult, { kind: "page" }>,
  mirrorOf: string | null,
): ExportPageValue {
  return {
    lines: page.lines,
    next: page.next === null ? null : encodeExportCursor(page.next),
    head: {
      chainHeadSeq: page.marks.chainHeadSeq,
      chainHeadHashHex: page.marks.chainHeadHashHex ?? "",
      auditMaxSeq: page.auditMaxSeq,
      mutationSeq: page.marks.mutationSeq,
      ...(mirrorOf === null ? {} : { mirrorOf }),
    },
  };
}

const openExport = Effect.fn("programs-export.openExport")(function* (
  actor: DataActor,
  chainHeadSeq: number,
  chainHeadHashHex: string,
  sql: SqlStorage,
  nowMs: number,
): Effect.fn.Return<number, DataRejectedError, DataStore | AuditStore | StorageMeter> {
  const store = yield* DataStore;
  const audit = yield* AuditStore;
  const window = yield* store.checkLeaseWindow("exported", MAX_EXPORTS_PER_WINDOW, nowMs);
  if (!window.allowed) {
    return yield* rejectData({
      kind: "export-rate-limited",
      retryAfterSeconds: window.retryAfterSeconds,
    });
  }
  const exportedSeq = yield* Effect.sync(() => {
    store.recordLeaseWindowUse("exported", nowMs);
    audit.appendSync(
      dataEvent(actor, nowMs, {
        event: "project.exported",
        payload: { chainHeadSeq, chainHeadHashHex },
      }),
    );
    return lastAuditSeq(sql);
  });
  while (
    (yield* observeStorageLevel) !== "reject" &&
    (yield* audit.ensureHeadCurrent) === "more-remains"
  ) {}
  return exportedSeq;
});

function lastAuditSeq(sql: SqlStorage): number {
  return Number(sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").one()["m"]);
}

const exportRowPayload = Schema.Struct({
  chainHeadSeq: Schema.Number,
  chainHeadHashHex: Schema.NullOr(Schema.String),
});
const decodeExportRowPayload = Schema.decodeUnknownOption(Schema.fromJsonString(exportRowPayload));

function exportRowBinds(sql: SqlStorage, cursor: ExportCursorState, userId: UserId): boolean {
  const row = sql
    .exec(
      "SELECT event, actor_user_id, payload FROM audit_events WHERE seq = ?",
      cursor.exportedSeq,
    )
    .toArray()[0];
  if (row === undefined || row["event"] !== "project.exported" || row["actor_user_id"] !== userId) {
    return false;
  }
  const head = Option.getOrNull(decodeExportRowPayload(String(row["payload"])));
  return (
    head !== null &&
    head.chainHeadSeq === cursor.marks.chainHeadSeq &&
    head.chainHeadHashHex === cursor.marks.chainHeadHashHex
  );
}

export interface ExportMembersValue {
  readonly members: readonly UserId[];
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
}

export const exportMembersProgram = (
  actor: DataActor,
  cache: StateCache,
): Effect.Effect<ExportMembersValue, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(actor.userId, "owner", cache), ({ state }) => ({
    members: [...state.members.values()].map((member) => member.userId).toSorted(),
    chainHeadSeq: state.headSeq,
    chainHeadHashHex: state.headHashHex,
  }));
