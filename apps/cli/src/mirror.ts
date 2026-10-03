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
import { CliError, cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

/** How many times a changed project restarts the replication before giving up. */
const MAX_RESTARTS = 3;
/** The bound on pages of one replication (far above any project the storage guard admits). */
const MAX_PAGES = 100_000;

export interface MirrorSyncInput<R = never> {
  /** The server (the source of the export). */
  readonly source: MaruhiClient;
  /** The mirror (its status). */
  readonly mirror: MaruhiClient;
  /**
   * The client the pages go through (the mirror under the body bound on
   * its headers — a full page on a slow uplink is not "did not answer");
   * defaults to `mirror`. Opened by the caller; used on the replicating
   * path only (ruling H revision, round 5).
   */
  readonly pages?: MaruhiClient;
  readonly projectId: string;
  /** The server's origin: the mirror's recorded source must be it, else the sync is refused (`force` overrides — ruling H revision, round 6). */
  readonly sourceOrigin: string;
  /** The mirror's origin: a server that is itself a mirror of another origin, or a frozen former primary that already synced back, is no source for it (`force` overrides — ruling H revision, round 8). */
  readonly mirrorOrigin: string;
  readonly force?: boolean;
  /**
   * The local floor's chain head (null = none): a source whose reported
   * head is behind it is never "current" — the replicating path's floor
   * check decides, with its evidence (ruling H revision, round 5).
   */
  readonly floorHead: { readonly seq: number; readonly hashHex: string } | null;
  /**
   * The server's verified view, built only when something is uploaded
   * (ruling H revision, round 4): a "current" tick costs the two status
   * reads and no chain download.
   */
  readonly verified: Effect.Effect<VerifiedProject, CliError, R>;
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
      /** The server's verified view the replica is compared with: the one taken before the export, or taken again after the commit when the replica's head is past it (ruling H revision, round 9). */
      readonly verified: VerifiedProject;
      /** The view taken before the export (the one the replica cannot honestly be behind). */
      readonly viewBefore: VerifiedProject;
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
function replicateOnce(input: MirrorSyncInput<unknown>): Effect.Effect<Attempt, CliError> {
  return Effect.gen(function* () {
    const params = { projectId: input.projectId };
    const pages = input.pages ?? input.mirror;
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
      const uploaded = yield* pages.mirror
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
export function mirrorSyncOp<R>(
  input: MirrorSyncInput<R>,
): Effect.Effect<MirrorSyncResult, CliError, R> {
  return Effect.gen(function* () {
    const before = yield* markedMirrorStatus(input);
    const source = yield* starSource(input);
    const verdict = yield* syncVerdict(input, before, source);
    if (verdict === "current") {
      return { kind: "current", before } as const;
    }
    const replicated = yield* replicateWithRestarts(input, verdict.verified);
    return { kind: "replicated", ...replicated, before } as const;
  });
}

/** The mirror's status: it must be marked, and marked as a mirror of the server the sync exports from (H-15). */
function markedMirrorStatus(
  input: MirrorSyncInput<unknown>,
): Effect.Effect<MirrorStatus, CliError> {
  return Effect.gen(function* () {
    const before = yield* mirrorStatusOp({ client: input.mirror, projectId: input.projectId });
    if (!before.mirror) {
      return yield* Effect.fail(
        cliError(
          "The project is not marked as a mirror on that server (its writes are open). An owner marks it with `maruhi mirror mark --server <mirror url> --source <server url>` first",
        ),
      );
    }
    // A cron left at the former primary after a failover elsewhere would
    // export a frozen copy into a mirror of another source (an equal-head
    // replica commits): the recorded source must be this server
    if (
      before.sourceOrigin !== undefined &&
      before.sourceOrigin !== input.sourceOrigin &&
      input.force !== true
    ) {
      return yield* Effect.fail(
        cliError(
          `The mirror holds this project as a mirror of ${before.sourceOrigin}, not of ${input.sourceOrigin}: sync from that server, re-point the mirror at this one (\`maruhi mirror mark --source ${input.sourceOrigin}\`), or pass --force to replicate from here anyway`,
        ),
      );
    }
    return before;
  });
}

/**
 * The server's own mark (its status, read with the owner's session): mirrors
 * sync from the primary — a star (AUTH_SPEC §11-7). A server that is itself
 * a mirror of another origin is refused before anything is exported (a
 * replica of it would commit once and be refused after its next sync, when
 * its own rows are renumbered). A server frozen as a mirror of this mirror
 * (the planned failover's last sync, or a sibling re-pointed here) goes
 * through. `force` overrides (ruling H revision, rounds 8 and 9).
 */
function starSource(input: MirrorSyncInput<unknown>): Effect.Effect<MirrorStatus, CliError> {
  return Effect.gen(function* () {
    const source = yield* input.source.mirror
      .status({ params: { projectId: input.projectId } })
      .pipe(Effect.mapError(toCliError));
    if (!source.mirror || input.force === true || source.sourceOrigin === undefined) {
      return source;
    }
    if (source.sourceOrigin !== input.mirrorOrigin) {
      return yield* Effect.fail(
        cliError(
          `The server ${input.sourceOrigin} holds this project as a mirror of ${source.sourceOrigin}: mirrors sync from the primary (a mirror's own audit rows are renumbered at every replication, so a replica taken from it is refused by this mirror after the next one). Sync from ${source.sourceOrigin} (\`maruhi mirror sync --server ${source.sourceOrigin} --mirror ${input.mirrorOrigin}\`, after re-pointing the mirror at it with \`maruhi mirror mark --server ${input.mirrorOrigin} --source ${source.sourceOrigin}\`), or pass --force to replicate from here anyway`,
        ),
      );
    }
    // A server frozen for this mirror is a source whatever it replicated
    // from it before (ruling H revision, round 9): the pair stays
    // consistent — this mirror's rows up to its position travel in the
    // server's log verbatim, and its own rows are carried by row id. The
    // renumbering hurts a third mirror of that server only, which the
    // refusal above covers
    return source;
  });
}

/**
 * Nothing to upload when the source's chain head, audit seq and mutation
 * counter are the ones the last replication brought (the source's status,
 * read with the owner's session — the marks are shown to admins and
 * owners). A cron then costs the status reads, not an export. A floor
 * below the source's head cannot be checked from the two statuses: the
 * verdict then waits for the view, whose floor check proves the floor's
 * entry is on the source's chain (H-14); the view is handed on to the
 * replication otherwise.
 */
function syncVerdict<R>(
  input: MirrorSyncInput<R>,
  before: MirrorStatus,
  source: MirrorStatus,
): Effect.Effect<"current" | { readonly verified: VerifiedProject }, CliError, R> {
  return Effect.gen(function* () {
    const unchanged = sourceUnchanged(input, before, source);
    if (unchanged === "current") {
      return "current";
    }
    const verified = yield* input.verified;
    return unchanged === "current-if-floor-on-chain" &&
      verified.state.headHashHex === before.lastSync?.chainHeadHashHex
      ? "current"
      : { verified };
  });
}

/** The passes over the export (restarting when the project changed, the view rebuilt before each — H-13). */
function replicateWithRestarts<R>(
  input: MirrorSyncInput<R>,
  firstView: VerifiedProject,
): Effect.Effect<
  {
    readonly pages: number;
    readonly lines: number;
    readonly restarts: number;
    readonly committed: MirrorSyncRecord;
    readonly verified: VerifiedProject;
    readonly viewBefore: VerifiedProject;
  },
  CliError,
  R
> {
  return Effect.gen(function* () {
    let viewBefore = firstView;
    let restarts = 0;
    let attempt = yield* replicateOnce(input);
    while (attempt.kind === "changed" && restarts < MAX_RESTARTS) {
      restarts += 1;
      viewBefore = yield* input.verified;
      attempt = yield* replicateOnce(input);
    }
    if (attempt.kind === "changed") {
      // The export's own renderer names `project export`; this is a sync
      // (round 11)
      return yield* Effect.fail(
        cliError(
          `The project changed on ${input.sourceOrigin} while it was being exported, ${countNoun(MAX_RESTARTS + 1, "time")} in a row: re-run \`maruhi mirror sync\` when the writes settle (the mirror keeps the replication in progress, which the next run restarts at sequence 0)`,
        ),
      );
    }
    const { pages, lines, committed } = attempt;
    // A replica past the view taken before the export is the one honest
    // race (a write landed in between) — or a server that serves one chain
    // and exports another: the view is taken again, and its floor check
    // (against the floor the first view advanced) proves it extends the
    // first; the replica must be on it (ruling H revision, round 9)
    const verified =
      committed.chainHeadSeq > viewBefore.state.headSeq
        ? yield* input.verified.pipe(
            // The strongest evidence gets the most specific report (round
            // 10) — and a server that merely stopped answering, or refused
            // the session, is not one that failed verification (round 11)
            Effect.mapError((error) => secondViewFailure(error, committed, viewBefore)),
          )
        : viewBefore;
    return { pages, lines, committed, restarts, verified, viewBefore };
  });
}

/** What the failure of the view taken after the commit means for the replica the mirror now holds (its flags are kept). */
function secondViewFailure(
  error: CliError,
  committed: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  viewBefore: VerifiedProject,
): CliError {
  const replica = `the replica the mirror now holds (chain seq ${committed.chainHeadSeq}, head ${committed.chainHeadHashHex}) is past the view taken before the export (seq ${viewBefore.state.headSeq})`;
  const message =
    error.unreachable === true
      ? `The server stopped answering after the commit (${error.message}): ${replica} and could not be checked against a second view. Verify the server (\`maruhi project verify\`) before promoting the mirror`
      : error.evidence === true
        ? `The mirror now holds a replica at chain seq ${committed.chainHeadSeq} (head ${committed.chainHeadHashHex}), past the view taken before the export (seq ${viewBefore.state.headSeq}), and the server failed verification right after exporting it: ${error.message}. Do not promote the mirror; run \`maruhi project verify\` against the server`
        : `The server could not be verified again after the commit (${error.message}): ${replica} and was not checked against a second view. Re-run \`maruhi mirror sync\`, or \`maruhi project verify\` against the server, before promoting the mirror`;
  return new CliError({
    message,
    ...(error.evidence === undefined ? {} : { evidence: error.evidence }),
    ...(error.unreachable === undefined ? {} : { unreachable: error.unreachable }),
  });
}

/** The fork evidence a mirror's reported head carries against the verified view (`maruhi mirror status` fails on it — round 11); null = none. */
export function statusEvidence(status: MirrorStatus, verified: VerifiedProject): string | null {
  return forkNote(status.head, verified);
}

/** Whether a head is an entry of a verified chain (its head, or an earlier entry). */
export function headOnChain(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  chain: VerifiedProject,
): boolean {
  return head.chainHeadSeq === chain.state.headSeq
    ? head.chainHeadHashHex === chain.state.headHashHex
    : head.chainHeadSeq < chain.state.headSeq &&
        chain.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex;
}

/**
 * Why a committed replica fails the sync (null = it stands): behind the
 * view taken before the export is a rollback at the server, never a race
 * (the view precedes every export); past the view taken again after the
 * commit, the server exported entries it no longer serves; off either
 * view's chain is a fork. Only an equivocating server produces any of
 * them, so a cron must see exit 1 (ruling H revision, rounds 8 and 9).
 */
export function replicaVerdict(
  committed: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  viewBefore: VerifiedProject,
  verified: VerifiedProject,
): string | null {
  if (committed.chainHeadSeq < viewBefore.state.headSeq) {
    return `behind the verified view taken before the export (seq ${committed.chainHeadSeq} of ${viewBefore.state.headSeq}): the server exported a chain shorter than the one it served — a rollback at the server, not a race (CRYPTO_SPEC §6.3); do not promote the mirror and run \`maruhi project verify\``;
  }
  if (committed.chainHeadSeq > verified.state.headSeq) {
    return `ahead of the verified view taken after the commit (seq ${committed.chainHeadSeq} > ${verified.state.headSeq}): the server exported entries it no longer serves — a rollback at the server, not a race (CRYPTO_SPEC §6.3); do not promote the mirror and run \`maruhi project verify\``;
  }
  return headOnChain(committed, verified) ? null : (forkNote(committed, verified) ?? null);
}

type Unchanged = "changed" | "current" | "current-if-floor-on-chain";

function sourceUnchanged(
  input: MirrorSyncInput<unknown>,
  before: MirrorStatus,
  source: MirrorStatus,
): Unchanged {
  // A source behind this machine's floor (rebuilt from a backup taken
  // at the last synced head) is not current: the replicating path's
  // floor check says so with evidence (H-11). A floor below the
  // source's head is checked by the view before the verdict (H-14)
  if (!marksUnchanged(before, source) || floorAhead(input.floorHead, source.head)) {
    return "changed";
  }
  return input.floorHead !== null && input.floorHead.seq < source.head.chainHeadSeq
    ? "current-if-floor-on-chain"
    : "current";
}

/** The three marks the last replication brought are the source's current ones, and the mirror still holds that head. */
function marksUnchanged(before: MirrorStatus, source: MirrorStatus): boolean {
  const last = before.lastSync;
  if (last === undefined || last.mutationSeq === undefined) {
    return false;
  }
  return (
    source.head.chainHeadHashHex === last.chainHeadHashHex &&
    before.head.chainHeadHashHex === last.chainHeadHashHex &&
    source.head.auditMaxSeq === last.auditMaxSeq &&
    source.head.mutationSeq === last.mutationSeq
  );
}

function floorAhead(
  floor: MirrorSyncInput<unknown>["floorHead"],
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
): boolean {
  return (
    floor !== null &&
    (floor.seq > head.chainHeadSeq ||
      (floor.seq === head.chainHeadSeq && floor.hashHex !== head.chainHeadHashHex))
  );
}

/** How a head stands against the verified view of the server (the same cross-check as `project export`). */
function headNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string {
  const fork = forkNote(head, verified);
  if (fork !== null) {
    return fork;
  }
  if (head.chainHeadHashHex === verified.state.headHashHex) {
    return "in sync with the verified view";
  }
  if (head.chainHeadSeq < verified.state.headSeq) {
    return `behind the verified view by ${countNoun(verified.state.headSeq - head.chainHeadSeq, "chain entry")} (seq ${head.chainHeadSeq} of ${verified.state.headSeq})`;
  }
  return `ahead of the verified view (seq ${head.chainHeadSeq} > ${verified.state.headSeq}) — the mirror was promoted and written to, the server rolled back, the mirror's recorded source is not this server, or a replication was forced from another server; run \`maruhi project verify\``;
}

/**
 * A head that is not on the verified view's chain and not past it: the
 * view and the head are both signature-verified, so only an equivocating
 * server produces this (never an honest race — "behind" and "ahead" are
 * those). A sync whose replica shows it fails after the commit (ruling H
 * revision, round 8: a cron must notice). null = no fork evidence.
 */
function forkNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string | null {
  if (head.chainHeadHashHex === verified.state.headHashHex) {
    return null;
  }
  if (head.chainHeadSeq < verified.state.headSeq) {
    return verified.history.entryHashAt(head.chainHeadSeq) === head.chainHeadHashHex
      ? null
      : `on a different chain (its seq ${head.chainHeadSeq} is not the verified view's entry) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  if (head.chainHeadSeq === verified.state.headSeq) {
    return `a different chain at the same height as the verified view (head ${verified.state.headHashHex}) — evidence of a fork (CRYPTO_SPEC §6.3); do not promote it and run \`maruhi project verify\``;
  }
  return null;
}

/** The sync's own note on the committed head: on the sync path an "ahead" past the view taken after the commit has one cause (rounds 11 and 12 — the replica and the view are of the same server). */
function syncHeadNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string {
  return head.chainHeadSeq > verified.state.headSeq && forkNote(head, verified) === null
    ? `ahead of the verified view taken after the commit (seq ${head.chainHeadSeq} > ${verified.state.headSeq}) — the server exported entries it no longer serves (a rollback at the server)`
    : headNote(head, verified);
}

function describeLastSync(status: MirrorStatus): string {
  return status.lastSync === undefined
    ? "No replication recorded since the mark (the replication history is shown to admins and owners)"
    : `Last replication: chain head seq=${status.lastSync.chainHeadSeq}, audit seq=${status.lastSync.auditMaxSeq}, at ${formatUtcMinutes(status.lastSync.atMs)} (UTC)`;
}

/** The report of a replication (heads and counts only). */
export function describeMirrorSync(
  result: MirrorSyncResult,
  projectId: string,
  mirrorOrigin: string,
): string[] {
  if (result.kind === "current") {
    return [
      `Mirror ${mirrorOrigin} is current for project ${projectId} (chain head seq=${result.before.head.chainHeadSeq}, head ${result.before.head.chainHeadHashHex}): the server's chain head, audit seq and mutation counter are the ones the last replication brought — nothing uploaded`,
      describeLastSync(result.before),
    ];
  }
  const { committed, verified } = result;
  const restarted =
    result.restarts === 0
      ? ""
      : ` (restarted ${countNoun(result.restarts, "time")} because the project changed while it was being exported)`;
  const own =
    committed.ownAuditRows === undefined
      ? ""
      : `; ${countNoun(committed.ownAuditRows, "audit row")} of the mirror's own (the reads and leases it served) re-appended after the replica's`;
  return [
    `Replicated project ${projectId} to ${mirrorOrigin}: chain head seq=${committed.chainHeadSeq} (${syncHeadNote(committed, verified)}); audit seq=${committed.auditMaxSeq}; ${countNoun(result.pages, "page")}, ${countNoun(result.lines, "line")}${restarted}${own}`,
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
