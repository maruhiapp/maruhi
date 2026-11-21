import type { MirrorStatus, MirrorSyncRecord } from "@maruhi/api-schema";
import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { BODY_TIMEOUT, makeApiClient, type MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { type CliServices, openSession } from "../context.ts";
import { countNoun } from "../display.ts";
import { CliError, cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { FloorStore } from "../floor.ts";
import { CliIo } from "../io.ts";
import { forkNote, headNote, headOnChain } from "./mirror-heads.ts";
import {
  describeLastSync,
  openMirrorTarget,
  readMirrorStatus,
  verifiedViewOf,
} from "./mirror-target.ts";

const MAX_RESTARTS = 3;

const MAX_PAGES = 100_000;

interface MirrorSyncInput<R = never> {
  readonly source: MaruhiClient;
  readonly mirror: MaruhiClient;
  readonly pages?: MaruhiClient;
  readonly projectId: ProjectId;
  readonly sourceOrigin: string;
  readonly mirrorOrigin: string;
  readonly force?: boolean;
  readonly floorHead: { readonly seq: number; readonly hashHex: string } | null;
  readonly verified: Effect.Effect<VerifiedProject, CliError, R>;
}

type MirrorSyncResult =
  | {
      readonly kind: "replicated";
      readonly pages: number;
      readonly lines: number;
      readonly restarts: number;
      readonly committed: MirrorSyncRecord;
      readonly before: MirrorStatus;
      readonly verified: VerifiedProject;
      readonly viewBefore: VerifiedProject;
    }
  | { readonly kind: "current"; readonly before: MirrorStatus };

export const mirrorSyncOp = Effect.fn("mirror-sync.mirrorSyncOp")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const target = yield* openMirrorTarget(flags);
  const source = yield* openSession(flags.server);
  const pages = yield* makeApiClient({
    baseUrl: target.mirrorOrigin,
    token: target.mirror.session.token,
    timeout: BODY_TIMEOUT,
  });
  const floor = yield* (yield* FloorStore).load(target.projectId);
  const result = yield* replicateProject({
    source: source.client,
    mirror: target.mirror.client,
    pages,
    projectId: target.projectId,
    sourceOrigin: source.origin,
    mirrorOrigin: target.mirrorOrigin,
    ...(flags.force === true ? { force: true } : {}),
    floorHead: floor.floor?.chainHead ?? null,
    verified: verifiedViewOf(source, target.projectId),
  });
  for (const line of describeMirrorSync(result, target.projectId, target.mirrorOrigin)) {
    yield* io.log(line);
  }
  const verdict =
    result.kind === "replicated"
      ? replicaVerdict(result.committed, result.viewBefore, result.verified)
      : null;
  if (verdict !== null) {
    return yield* Effect.fail(
      cliError(
        `The replica ${target.mirrorOrigin} now holds is ${verdict} — against ${source.origin} and against the mirror`,
      ),
    );
  }
});

type Attempt =
  | {
      readonly kind: "done";
      readonly pages: number;
      readonly lines: number;
      readonly committed: MirrorSyncRecord;
    }
  | { readonly kind: "changed" };

const replicateOnce = Effect.fn("mirror-sync.replicateOnce")(function* (
  input: MirrorSyncInput<unknown>,
): Effect.fn.Return<Attempt, CliError> {
  const params = { projectId: input.projectId };
  const pages = input.pages ?? input.mirror;
  let cursor: string | undefined;
  let sequence = 0;
  let lines = 0;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const exported = yield* input.source.export
      .page({ params, query: cursor === undefined ? {} : { cursor } })
      .pipe(
        Effect.catchTag(
          "ExportChanged",
          () => Effect.succeed(null),
          (error) => Effect.fail(toCliError(error)),
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
          sourceMutationSeq: exported.head.mutationSeq,
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

const replicateProject = Effect.fn("mirror-sync.replicateProject")(function* <R>(
  input: MirrorSyncInput<R>,
): Effect.fn.Return<MirrorSyncResult, CliError, R> {
  const before = yield* markedMirrorStatus(input);
  const source = yield* starSource(input);
  const verdict = yield* syncVerdict(input, before, source);
  if (verdict === "current") {
    return { kind: "current", before } as const;
  }
  const replicated = yield* replicateWithRestarts(input, verdict.verified);
  return { kind: "replicated", ...replicated, before } as const;
});

const markedMirrorStatus = Effect.fn("mirror-sync.markedMirrorStatus")(function* (
  input: MirrorSyncInput<unknown>,
): Effect.fn.Return<MirrorStatus, CliError> {
  const before = yield* readMirrorStatus({ client: input.mirror, projectId: input.projectId });
  if (!before.mirror) {
    return yield* Effect.fail(
      cliError(
        "The project is not marked as a mirror on that server (its writes are open). An owner marks it with `maruhi mirror mark --server <mirror url> --source <server url>` first",
      ),
    );
  }
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

const starSource = Effect.fn("mirror-sync.starSource")(function* (
  input: MirrorSyncInput<unknown>,
): Effect.fn.Return<MirrorStatus, CliError> {
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
  return source;
});

const syncVerdict = Effect.fn("mirror-sync.syncVerdict")(function* <R>(
  input: MirrorSyncInput<R>,
  before: MirrorStatus,
  source: MirrorStatus,
): Effect.fn.Return<"current" | { readonly verified: VerifiedProject }, CliError, R> {
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

const replicateWithRestarts = Effect.fn("mirror-sync.replicateWithRestarts")(function* <R>(
  input: MirrorSyncInput<R>,
  firstView: VerifiedProject,
): Effect.fn.Return<
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
  let viewBefore = firstView;
  let restarts = 0;
  let attempt = yield* replicateOnce(input);
  while (attempt.kind === "changed" && restarts < MAX_RESTARTS) {
    restarts += 1;
    viewBefore = yield* input.verified;
    attempt = yield* replicateOnce(input);
  }
  if (attempt.kind === "changed") {
    return yield* Effect.fail(
      cliError(
        `The project changed on ${input.sourceOrigin} while it was being exported, ${countNoun(MAX_RESTARTS + 1, "time")} in a row: re-run \`maruhi mirror sync\` when the writes settle (the mirror keeps the replication in progress, which the next run restarts at sequence 0)`,
      ),
    );
  }
  const { pages, lines, committed } = attempt;
  const verified =
    committed.chainHeadSeq > viewBefore.state.headSeq
      ? yield* input.verified.pipe(
          Effect.mapError((error) => secondViewFailure(error, committed, viewBefore)),
        )
      : viewBefore;
  return { pages, lines, committed, restarts, verified, viewBefore };
});

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

function replicaVerdict(
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
  if (!marksUnchanged(before, source) || floorAhead(input.floorHead, source.head)) {
    return "changed";
  }
  return input.floorHead !== null && input.floorHead.seq < source.head.chainHeadSeq
    ? "current-if-floor-on-chain"
    : "current";
}

function marksUnchanged(before: MirrorStatus, source: MirrorStatus): boolean {
  const last = before.lastSync;
  if (last === undefined) {
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

function syncHeadNote(
  head: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  verified: VerifiedProject,
): string {
  return head.chainHeadSeq > verified.state.headSeq && forkNote(head, verified) === null
    ? `ahead of the verified view taken after the commit (seq ${head.chainHeadSeq} > ${verified.state.headSeq}) — the server exported entries it no longer serves (a rollback at the server)`
    : headNote(head, verified);
}

function describeMirrorSync(
  result: MirrorSyncResult,
  projectId: ProjectId,
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
