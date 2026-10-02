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

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type { ChainStore } from "./chain-store.ts";
import type { DataActor, DataRejectedError } from "./data-plane.ts";
import { dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { PROJECT_DO_TABLES, readProjectDoSchemaVersion } from "./do-schema.ts";
import { decodeExportCursor, encodeExportCursor, exportSnapshotPage } from "./do-snapshot.ts";
import { MAX_EXPORT_PAGE_BYTES, MAX_EXPORT_PAGE_ROWS, MAX_EXPORTS_PER_WINDOW } from "./policy.ts";

/** One page as the worker returns it (the wire shape of api-schema's ExportPageSchema). */
export interface ExportPageValue {
  readonly lines: readonly string[];
  /** null = the last page. */
  readonly next: string | null;
  readonly head: {
    readonly chainHeadSeq: number;
    readonly chainHeadHashHex: string;
    readonly auditMaxSeq: number;
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
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const nowMs = Date.now();
    // A cursor this server did not produce is treated like a changed
    // project: the client starts over from the first page
    const cursor = cursorText === null ? null : decodeExportCursor(cursorText);
    if (cursorText !== null && cursor === null) {
      return yield* rejectData({ kind: "export-changed" });
    }
    if (cursor === null) {
      // The first page: the window (judged after authorization), then the
      // audit row before the marks are read, so the exported log carries
      // the row of its own export (ruling F)
      const window = yield* store.checkLeaseWindow("exported", MAX_EXPORTS_PER_WINDOW, nowMs);
      if (!window.allowed) {
        return yield* rejectData({
          kind: "export-rate-limited",
          retryAfterSeconds: window.retryAfterSeconds,
        });
      }
      yield* Effect.sync(() => {
        store.recordLeaseWindowUse("exported", nowMs);
        audit.appendSync(
          dataEvent(actor, nowMs, "project.exported", {
            payload: { chainHeadSeq: state.headSeq, chainHeadHashHex: state.headHashHex },
          }),
        );
      });
    }
    const page = yield* Effect.sync(() =>
      exportSnapshotPage({
        sql,
        tables: PROJECT_DO_TABLES,
        schemaVersion: readProjectDoSchemaVersion(sql),
        doIdHex,
        takenAtMs: nowMs,
        cursor,
        maxRows: MAX_EXPORT_PAGE_ROWS,
        maxBytes: MAX_EXPORT_PAGE_BYTES,
      }),
    );
    if (page.kind === "changed") {
      return yield* rejectData({ kind: "export-changed" });
    }
    return {
      lines: page.lines,
      next: page.next === null ? null : encodeExportCursor(page.next),
      head: {
        chainHeadSeq: page.marks.chainHeadSeq,
        // An initialized project always has a head (requireMemberState passed)
        chainHeadHashHex: page.marks.chainHeadHashHex ?? "",
        auditMaxSeq: page.marks.auditMaxSeq,
      },
    };
  });

/** The current members' user ids (owner only — the identities companion of an export). */
export const exportMembersProgram = (
  actor: DataActor,
  cache: StateCache,
): Effect.Effect<readonly string[], DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(actor.userId, "owner", cache), ({ state }) =>
    [...state.members.keys()].toSorted(),
  );
