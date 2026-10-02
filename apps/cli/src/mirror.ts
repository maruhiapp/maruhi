// `maruhi mirror sync` / `status` (AUTH_SPEC §11-7 — PF2,
// docs/notes/pf2-design.md rulings D / H): a member replicates the project
// from the server to a mirror by paging the owner's export and uploading
// the pages in order; the mirror commits when the page carrying the
// trailer arrives, and only if the replica extends what it already holds.
//
// Two sessions take part: the server's (the export needs the owner role)
// and the mirror's (the pages need admin or above there). From a cron
// they are MARUHI_TOKEN / MARUHI_TOKEN_ORIGIN and MARUHI_MIRROR_TOKEN.
//
// TCB discipline: what is reported is heads and counts, cross-checked
// against the verified view of the server (the same note as `project
// export`); row content never reaches the output.

import type { MirrorStatus, MirrorSyncRecord } from "@maruhi/api-schema";
import { ExportChangedError } from "@maruhi/api-schema";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/** How many times a changed project restarts the replication before giving up. */
const MAX_RESTARTS = 3;
/** The bound on pages of one replication (far above any project the storage guard admits). */
const MAX_PAGES = 100_000;

export interface MirrorSyncInput {
  /** The server (the source of the export). */
  readonly source: MaruhiClient;
  /** The mirror (the destination of the pages). */
  readonly mirror: MaruhiClient;
  readonly projectId: string;
  readonly verified: VerifiedProject;
}

export type MirrorSyncResult =
  | {
      readonly kind: "replicated";
      readonly pages: number;
      readonly lines: number;
      readonly restarts: number;
      readonly committed: MirrorSyncRecord;
      /** The mirror's status before the replication (the previous position). */
      readonly before: MirrorStatus;
    }
  /** The source's three marks are the last replication's: nothing to upload (ruling H revision). */
  | { readonly kind: "current"; readonly before: MirrorStatus };

export function mirrorStatusOp(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
}): Effect.Effect<MirrorStatus, CliError> {
  return input.client.mirror
    .status({ params: { projectId: input.projectId } })
    .pipe(Effect.mapError(toCliError));
}

type Attempt =
  | {
      readonly kind: "done";
      readonly pages: number;
      readonly lines: number;
      readonly committed: MirrorSyncRecord;
    }
  | { readonly kind: "changed" };

/** One pass over the export's pages into the mirror; "changed" = the project moved (the caller restarts at sequence 0). */
function replicateOnce(input: MirrorSyncInput): Effect.Effect<Attempt, CliError> {
  return Effect.gen(function* () {
    const params = { projectId: input.projectId };
    let cursor: string | undefined;
    let sequence = 0;
    let lines = 0;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      const exported = yield* input.source.export
        .page({ params, query: cursor === undefined ? {} : { cursor } })
        .pipe(
          Effect.catch((error) =>
            error instanceof ExportChangedError
              ? Effect.succeed(null)
              : Effect.fail(toCliError(error)),
          ),
        );
      if (exported === null) {
        return { kind: "changed" } as const;
      }
      const uploaded = yield* input.mirror.mirror
        .pages({
          params,
          payload: {
            sequence,
            lines: exported.lines,
            // The source's counter rides with every page; the mirror records
            // the trailer page's with the replica (the no-change check)
            ...(exported.head.mutationSeq === undefined
              ? {}
              : { sourceMutationSeq: exported.head.mutationSeq }),
          },
        })
        .pipe(Effect.mapError(toCliError));
      lines += exported.lines.length;
      cursor = exported.next;
      if (cursor === undefined) {
        if (uploaded.committed === undefined) {
          return yield* Effect.fail(
            cliError(
              "The mirror staged the last page without committing it (the export ended without a trailer line). Re-run `maruhi mirror sync`; if it persists, check that the server and the mirror versions match",
            ),
          );
        }
        return { kind: "done", pages: page + 1, lines, committed: uploaded.committed } as const;
      }
      if (uploaded.committed !== undefined) {
        return yield* Effect.fail(
          cliError(
            "The mirror committed the replica before the export's last page (a trailer line arrived early). This does not happen with an honest server and mirror — investigate before relying on either",
          ),
        );
      }
      sequence = uploaded.nextSequence;
    }
    return yield* Effect.fail(
      cliError(
        `The server kept returning more pages past the ${MAX_PAGES}-page bound — stopping. This does not happen with an honest server; investigate the server if it persists`,
      ),
    );
  });
}

/** Replicates the whole project (restarting when it changes) into a mirror that is marked. */
export function mirrorSyncOp(input: MirrorSyncInput): Effect.Effect<MirrorSyncResult, CliError> {
  return Effect.gen(function* () {
    const before = yield* mirrorStatusOp({ client: input.mirror, projectId: input.projectId });
    if (!before.mirror) {
      return yield* Effect.fail(
        cliError(
          "The project is not marked as a mirror on that server (its writes are open). An owner marks it with `maruhi mirror mark --server <mirror url> --source <server url>` first",
        ),
      );
    }
    // Nothing to upload when the source's chain head, audit seq and
    // attestation mark are the ones the last replication brought (the
    // source's status, read with the owner's session — the three marks are
    // shown to admins and owners). A cron then costs one read, not an export
    if (yield* sourceUnchanged(input, before)) {
      return { kind: "current", before } as const;
    }
    let restarts = 0;
    let attempt = yield* replicateOnce(input);
    while (attempt.kind === "changed" && restarts < MAX_RESTARTS) {
      restarts += 1;
      attempt = yield* replicateOnce(input);
    }
    if (attempt.kind === "changed") {
      return yield* Effect.fail(toCliError(new ExportChangedError({ reason: "project-changed" })));
    }
    const { pages, lines, committed } = attempt;
    return { kind: "replicated", pages, lines, committed, restarts, before } as const;
  });
}

/**
 * Whether the source's marks equal the last replication's: the chain head
 * (content-bound), the audit seq (the reads) and the mutation counter
 * (every write, attestations included — it is what the export's own
 * consistency relies on). The mirror must also still hold that head (a
 * mirror whose record says "current" while its head is older is caught —
 * ruling H revision, round 3). A source that does not answer the status
 * fails the sync (the export would fail the same way).
 */
function sourceUnchanged(
  input: MirrorSyncInput,
  before: MirrorStatus,
): Effect.Effect<boolean, CliError> {
  const last = before.lastSync;
  if (last === undefined || last.mutationSeq === undefined) {
    return Effect.succeed(false);
  }
  return input.source.mirror.status({ params: { projectId: input.projectId } }).pipe(
    Effect.map(
      (source) =>
        source.head.chainHeadHashHex === last.chainHeadHashHex &&
        before.head.chainHeadHashHex === last.chainHeadHashHex &&
        source.head.auditMaxSeq === last.auditMaxSeq &&
        source.head.mutationSeq === last.mutationSeq,
    ),
    Effect.mapError(toCliError),
  );
}

/** How a head stands against the verified view of the server (the same cross-check as `project export`). */
function headNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string {
  if (head.chainHeadHashHex === verified.state.headHashHex) {
    return "in sync with the verified view";
  }
  if (head.chainHeadSeq < verified.state.headSeq) {
    return verified.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex
      ? `behind the verified view by ${countNoun(verified.state.headSeq - head.chainHeadSeq, "chain entry")} (seq ${head.chainHeadSeq} of ${verified.state.headSeq})`
      : `on a different chain (its seq ${head.chainHeadSeq} is not the verified view's entry) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  if (head.chainHeadSeq === verified.state.headSeq) {
    return `a different chain at the same height as the verified view (head ${verified.state.headHashHex}) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  return `ahead of the verified view (seq ${head.chainHeadSeq} > ${verified.state.headSeq}) — a write landed on the server after this sync, or the mirror was promoted and written to; re-run \`maruhi project verify\``;
}

function describeLastSync(status: MirrorStatus): string {
  return status.lastSync === undefined
    ? "No replication recorded since the mark (the replication history is shown to admins and owners)"
    : `Last replication: chain head seq=${status.lastSync.chainHeadSeq}, audit seq=${status.lastSync.auditMaxSeq}, at ${formatUtcMinutes(status.lastSync.atMs)} (UTC)`;
}

/** The report of a replication (heads and counts only). */
export function describeMirrorSync(
  result: MirrorSyncResult,
  verified: VerifiedProject,
  mirrorOrigin: string,
): string[] {
  if (result.kind === "current") {
    return [
      `Mirror ${mirrorOrigin} is current for project ${verified.projectId} (chain head seq=${result.before.head.chainHeadSeq}, head ${result.before.head.chainHeadHashHex}): the server's chain head, audit seq and mutation counter are the ones the last replication brought — nothing uploaded`,
      describeLastSync(result.before),
    ];
  }
  const { committed } = result;
  const restarted =
    result.restarts === 0
      ? ""
      : ` (restarted ${countNoun(result.restarts, "time")} because the project changed while it was being exported)`;
  const own =
    committed.ownAuditRows === undefined
      ? ""
      : `; ${countNoun(committed.ownAuditRows, "audit row")} of the mirror's own (the reads and leases it served) re-appended after the replica's`;
  return [
    `Replicated project ${verified.projectId} to ${mirrorOrigin}: chain head seq=${committed.chainHeadSeq} (${headNote(committed, verified)}); audit seq=${committed.auditMaxSeq}; ${countNoun(result.pages, "page")}, ${countNoun(result.lines, "line")}${restarted}${own}`,
    `Before this run: ${describeLastSync(result.before)}`,
  ];
}

/** The two heads side by side (`maruhi mirror status`); without the server's view (it did not answer) the mirror's head stands alone. */
export function describeMirrorStatus(
  status: MirrorStatus,
  verified: VerifiedProject | null,
  mirrorOrigin: string,
): string[] {
  const mirrorHead =
    verified === null
      ? `chain head seq=${status.head.chainHeadSeq} (head ${status.head.chainHeadHashHex}; the server did not answer, so it is not compared with a verified view)`
      : `chain head seq=${status.head.chainHeadSeq} — ${headNote(status.head, verified)}`;
  if (!status.mirror) {
    return [
      `${mirrorOrigin}: the project is not marked as a mirror there (its ${mirrorHead}). An owner marks it with \`maruhi mirror mark --server ${mirrorOrigin} --source <server url>\``,
    ];
  }
  const inProgress =
    status.nextSequence === undefined
      ? []
      : [`A replication is in progress (the next page is sequence ${status.nextSequence})`];
  return [
    `Mirror ${mirrorOrigin} of ${status.sourceOrigin ?? "an unknown source"} (marked ${status.markedAtMs === undefined ? "at an unknown time" : `${formatUtcMinutes(status.markedAtMs)} UTC`})`,
    verified === null
      ? "Server: unreachable (no verified view)"
      : `Server: chain head seq=${verified.state.headSeq} (the verified view)`,
    `Mirror: ${mirrorHead}${status.head.auditMaxSeq === undefined ? "" : `; audit seq=${status.head.auditMaxSeq}`}`,
    describeLastSync(status),
    ...inProgress,
  ];
}
