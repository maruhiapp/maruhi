// Project export programs (AUTH_SPEC §11-6 — PF3, docs/notes/pf3-design.md).
//
// - page: chain role owner (the strongest read — every member's wraps and
//   the class-2 audit rows travel). The first page consumes the
//   per-project export window, appends `project.exported` (class 2 —
//   the exported log records its own export) and takes the watermarks;
//   every later page re-reads them and refuses with export-changed when
//   the project moved (the client starts over). The lines are the
//   evacuation's (do-snapshot.ts) — nothing is decrypted or re-encoded
// - members: the current chain members' user ids (the identities
//   companion joins them with D1 on the worker side)
//
// Both run under the DO's permit synchronously (one page = one
// synchronous read; no permit across awaits).

import { Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type { DataActor, DataRejectedError } from "../data/data-plane.ts";
import { dataEvent, rejectData, requireMemberState } from "../data/data-plane.ts";
import { DataStore } from "../data/data-store.ts";
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
} from "../do/do-snapshot.ts";
import { MAX_EXPORT_PAGE_BYTES, MAX_EXPORT_PAGE_ROWS, MAX_EXPORTS_PER_WINDOW } from "../policy.ts";

/** One page as the worker returns it (the wire shape of api-schema's ExportPageSchema). */
export interface ExportPageValue {
  readonly lines: readonly string[];
  /** null = the last page. */
  readonly next: string | null;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq: number;
    readonly mutationSeq: number;
    /** The source this project is marked as a mirror of (read with the marks — ruling J revision, round 5); absent on a writable project. */
    readonly mirrorOf?: string;
  };
}

export const exportPageProgram = (
  actor: DataActor,
  cursorText: string | null,
  sql: SqlStorage,
  doIdHex: string,
  cache: StateCache,
): Effect.Effect<ExportPageValue, DataRejectedError, ChainStore | DataStore | AuditStore> =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "owner", cache);
    const nowMs = Date.now();
    const cursor = yield* continuationOf(cursorText, sql, actor.userId);
    const exportedSeq =
      cursor === null
        ? yield* openExport(actor, state.headSeq, state.headHashHex, sql, nowMs)
        : cursor.exportedSeq;
    // The mark is read in the same synchronous call as the page's marks:
    // "marked at the last page, marks unchanged since the first" then
    // says by construction that no write landed after the export
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

/**
 * The cursor of a continuation (null = the first page). A cursor this
 * server did not produce is treated like a changed project (the client
 * starts over), and a continuation is served only to the owner whose
 * export it is: the audit row the cursor names must be theirs and still
 * say what the cursor says (ruling D revision) — another owner continuing
 * a cursor would take pages without a row of their own and outside their
 * window.
 */
function continuationOf(
  cursorText: string | null,
  sql: SqlStorage,
  userId: string,
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
      // An initialized project always has a head (requireMemberState passed)
      chainHeadHashHex: page.marks.chainHeadHashHex ?? "",
      auditMaxSeq: page.auditMaxSeq,
      mutationSeq: page.marks.mutationSeq,
      ...(mirrorOf === null ? {} : { mirrorOf }),
    },
  };
}

/**
 * The first page: the window (judged after authorization), then the audit
 * row before the marks are read, so the exported log carries the row of
 * its own export (ruling F); then the cumulative-hash column is brought to
 * the mark, so the trailer always carries the audit head the restore
 * recomputes (bounded extension, run to convergence like a restore).
 * Returns the seq of the export's row (the cursor binds it).
 */
const openExport = (
  actor: DataActor,
  chainHeadSeq: number,
  chainHeadHashHex: string,
  sql: SqlStorage,
  nowMs: number,
): Effect.Effect<number, DataRejectedError, DataStore | AuditStore> =>
  Effect.gen(function* () {
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
        dataEvent(actor, nowMs, "project.exported", {
          payload: { chainHeadSeq, chainHeadHashHex },
        }),
      );
      return lastAuditSeq(sql);
    });
    while ((yield* audit.ensureHeadCurrent) === "more-remains") {
      // Each call makes progress (the bounded contract of audit-store.ts)
    }
    return exportedSeq;
  });

function lastAuditSeq(sql: SqlStorage): number {
  return Number(sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").one()["m"]);
}

/** Whether the cursor's `project.exported` row exists, is the requester's, and names the cursor's head (within the exported bound). */
function exportRowBinds(sql: SqlStorage, cursor: ExportCursorState, userId: string): boolean {
  const row = sql
    .exec(
      "SELECT event, actor_user_id, payload FROM audit_events WHERE seq = ?",
      cursor.exportedSeq,
    )
    .toArray()[0];
  if (row === undefined || row["event"] !== "project.exported" || row["actor_user_id"] !== userId) {
    return false;
  }
  let payload: unknown;
  try {
    payload = JSON.parse(String(row["payload"]));
  } catch {
    return false;
  }
  if (typeof payload !== "object" || payload === null) {
    return false;
  }
  const head = payload as { chainHeadSeq?: unknown; chainHeadHashHex?: unknown };
  return (
    head.chainHeadSeq === cursor.marks.chainHeadSeq &&
    head.chainHeadHashHex === cursor.marks.chainHeadHashHex
  );
}

/** The members of the companion and the chain head they were read at (the companion is bound to it — ruling H revision). */
export interface ExportMembersValue {
  readonly members: readonly string[];
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
}

/** The current members' user ids (owner only — the identities companion of an export), with the chain head. */
export const exportMembersProgram = (
  actor: DataActor,
  cache: StateCache,
): Effect.Effect<ExportMembersValue, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(actor.userId, "owner", cache), ({ state }) => ({
    members: [...state.members.keys()].toSorted(),
    chainHeadSeq: state.headSeq,
    chainHeadHashHex: state.headHashHex,
  }));
