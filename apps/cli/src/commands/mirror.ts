// `maruhi mirror` (discipline: see commands/index.ts).

import { type MirrorStatus } from "@maruhi/api-schema";
import { type ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import { Command } from "effect/cli";

import { loadCliConfig } from "../config.ts";
import type { CliServices, SessionContext } from "../context.ts";
import { CliError, cliError, evidenceError, usageError } from "../errors.ts";
import { FloorStore } from "../floor.ts";
import { CliIo } from "../io.ts";
import {
  describeMirrorStatus,
  describeMirrorSync,
  mirrorStatusOp,
  mirrorSyncOp,
  replicaVerdict,
  statusEvidence,
} from "../mirror.ts";
import { noteServerDisclosure } from "../server-disclosure.ts";
import { projectFlags, singleFlag, singleValued } from "./flags.ts";
import { sameDeployment } from "./mirror-core.ts";
import { mirrorMark, mirrorPromote } from "./mirror-write.ts";

/** `maruhi mirror sync` / `status`: the server (session + export) and the mirror (its own session + the pages). */
export const mirrorStatusConfig = {
  ...projectFlags(),
  mirror: singleValued("mirror", "Mirror URL (default: the `mirror` setting)"),
};

export const mirrorSyncConfig = {
  ...mirrorStatusConfig,
  force: singleFlag(
    "force",
    "Replicate even though the mirror is marked as a mirror of another server",
  ),
};

/** Validating a config key passed as a positional (**the given value itself never appears in the error**). */
/* -------------------------------------------------------------------------- */
/* Mirrors (PF2 — AUTH_SPEC §11-7; the operations live in mirror.ts)          */
/* -------------------------------------------------------------------------- */

/** The mirror's session and the project of `mirror sync` / `status` (the server session is opened separately). */
const openMirrorTarget = Effect.fn("commands-mirror.openMirrorTarget")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}) {
  const { openSession, resolveMirrorOrigin, resolveProjectId } = yield* Effect.promise(
    () => import("../context.ts"),
  );
  const { resolveServerOrigin } = yield* Effect.promise(() => import("../session.ts"));

  const config = yield* loadCliConfig;
  const projectId = yield* resolveProjectId(flags.project, config);
  const serverOrigin = yield* resolveServerOrigin(flags.server, config);
  const mirrorOrigin = yield* resolveMirrorOrigin(flags.mirror, config);
  if (mirrorOrigin === null) {
    return yield* Effect.fail(
      cliError(
        "No mirror URL. Pass --mirror <url> or set it with `maruhi config set mirror <url>`",
      ),
    );
  }
  // By string here (a cron's "current" tick stays the status reads
  // — H-9); the mark, where a self-mirror would be created, and the
  // promotion compare deployments by server key fingerprint (C-13)
  if (mirrorOrigin === serverOrigin) {
    return yield* Effect.fail(
      usageError("The mirror URL is the server URL itself (pass the mirror deployment's URL)"),
    );
  }
  const mirror = yield* openSession(mirrorOrigin, "mirror");
  return { mirror, mirrorOrigin, serverOrigin, projectId };
});

/** The server's verified view (the same keyless prologue as `project export`). */
const verifiedServerView = Effect.fn("commands-mirror.verifiedServerView")(function* (
  serverFlag: string | undefined,
  projectId: ProjectId,
) {
  const { openSession } = yield* Effect.promise(() => import("../context.ts"));

  const source = yield* openSession(serverFlag);
  const verified = yield* verifiedViewOf(source, projectId);
  return { source, verified };
});

/**
 * The server's verified view from an open session: the same keyless
 * prologue as `project verify` — the floor check, the invite anchor and
 * the head gossip, which advances the local floor to the verified head
 * once every check passes (ruling H revision, round 7: a sync whose view
 * left the floor behind took the view on every tick, forever).
 */
const verifiedViewOf = Effect.fn("commands-mirror.verifiedViewOf")(function* (
  source: SessionContext,
  projectId: ProjectId,
) {
  const { syncProject } = yield* Effect.promise(() => import("../chain-sync.ts"));
  const { checkInviteAnchor, loadCheckedFloor, reconcileGossip } = yield* Effect.promise(
    () => import("../context.ts"),
  );

  const synced = yield* syncProject(source.client, projectId);
  const checked = yield* loadCheckedFloor(projectId, synced, syncProject(source.client, projectId));
  yield* checkInviteAnchor(projectId, checked.verified);
  const verified = yield* reconcileGossip(
    projectId,
    checked.verified,
    syncProject(source.client, projectId),
  );
  yield* noteServerDisclosure(verified);
  return verified;
});

/**
 * `maruhi mirror sync`: the export's pages uploaded to the mirror in
 * order. The two sessions are opened first (the server's for the export,
 * the mirror's for the pages); the server's chain is fetched and verified
 * only when something is uploaded — a cron's "current" tick is the two
 * status reads (ruling H revision, round 4).
 */
const mirrorSyncCommand = Effect.fn("commands-mirror.mirrorSyncCommand")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const { BODY_TIMEOUT, makeApiClient } = yield* Effect.promise(() => import("../api.ts"));
  const { openSession } = yield* Effect.promise(() => import("../context.ts"));

  const io = yield* CliIo;
  const target = yield* openMirrorTarget(flags);
  const source = yield* openSession(flags.server);
  // The pages go through the mirror under the body bound on their
  // headers (a full page on a slow uplink is not "did not answer" — H-10);
  // the status reads keep the usual bound (H-12)
  const pages = yield* makeApiClient({
    baseUrl: target.mirrorOrigin,
    token: target.mirror.session.token,
    timeout: BODY_TIMEOUT,
  });
  const floor = yield* (yield* FloorStore).load(target.projectId);
  const result = yield* mirrorSyncOp({
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
  // A replica behind the view taken before the export, past the one
  // taken after the commit, or off either's chain is evidence against
  // the server, reported above; the sync fails so a cron notices (ruling
  // H revision, rounds 8 and 9)
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

/**
 * `maruhi mirror status`: the server's verified head and the mirror's,
 * side by side. The one command for "is my mirror usable" must answer
 * while the server is down: a server that does not answer leaves the
 * mirror's head alone on the report (announced), any other failure of the
 * server side fails as usual.
 */
const mirrorStatusCommand = Effect.fn("commands-mirror.mirrorStatusCommand")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const target = yield* openMirrorTarget(flags);
  const status = yield* mirrorStatusOp({
    client: target.mirror.client,
    projectId: target.projectId,
  });
  const verified = yield* verifiedServerView(flags.server, target.projectId).pipe(
    Effect.map((view) => view.verified),
    Effect.catch((error: CliError) =>
      error.unreachable === true
        ? Effect.gen(function* () {
            yield* io.logError(`${error.message}. Reporting the mirror's head alone`);
            return null;
          })
        : Effect.fail(error),
    ),
  );
  for (const line of describeMirrorStatus(status, verified, target.mirrorOrigin)) {
    yield* io.log(line);
  }
  // Fork evidence fails the status as it fails the sync (round 11): a
  // cron or a member's "is my mirror usable" must not read it as fine
  const evidence = verified === null ? null : statusEvidence(status, verified);
  if (evidence !== null) {
    // A recorded source that is this server under another hostname is
    // this server (the fingerprints decide, on the failing path only — round 13)
    const recordedElsewhere =
      status.mirror &&
      status.sourceOrigin !== undefined &&
      status.sourceOrigin !== target.serverOrigin &&
      !(yield* sameDeployment(status.sourceOrigin, target.serverOrigin));
    return yield* Effect.fail(
      evidenceError(
        statusEvidenceText(
          status,
          target.mirrorOrigin,
          target.serverOrigin,
          evidence,
          recordedElsewhere,
        ),
      ),
    );
  }
});

/**
 * The status's fork evidence attributed to the state it was seen in (round
 * 12): a copy that is not marked (promoted and written to) diverging from
 * the server is two writable copies, a copy marked for another source was
 * judged against a server that is not its source, a marked mirror of this
 * server holds fork evidence against it.
 */
function statusEvidenceText(
  status: MirrorStatus,
  mirrorOrigin: string,
  serverOrigin: string,
  evidence: string,
  recordedElsewhere: boolean,
): string {
  if (!status.mirror) {
    return `${mirrorOrigin} is not marked as a mirror (promoted, or never marked) and holds a chain head that is ${evidence} of ${serverOrigin}: two writable copies have diverged (a split brain). Decide which chain is the project's with \`maruhi project verify\` against both, and mark or export the other away`;
  }
  if (recordedElsewhere && status.sourceOrigin !== undefined) {
    return `${mirrorOrigin} is a mirror of ${status.sourceOrigin}, not of ${serverOrigin}, and holds a chain head that is ${evidence} of ${serverOrigin}: the comparison is against a server that is not its source — run the status against ${status.sourceOrigin} (\`maruhi mirror status --server ${status.sourceOrigin} --mirror ${mirrorOrigin}\`)`;
  }
  return `The mirror ${mirrorOrigin} holds a chain head that is ${evidence} — against ${serverOrigin} and against the mirror`;
}

export function makeMirrorCommands() {
  const mirrorSync = Command.make("sync", mirrorSyncConfig, (values) =>
    mirrorSyncCommand(values),
  ).pipe(
    Command.withDescription(
      "Replicate the project from the server to the mirror (the export's pages uploaded in order; the mirror accepts only a replica that extends what it holds). From a cron: MARUHI_TOKEN / MARUHI_TOKEN_ORIGIN for the server, MARUHI_MIRROR_TOKEN for the mirror",
    ),
  );

  const mirrorStatus = Command.make("status", mirrorStatusConfig, (values) =>
    mirrorStatusCommand(values),
  ).pipe(
    Command.withDescription(
      "Show the server's verified chain head and the mirror's side by side, with the last replication",
    ),
  );

  const mirror = Command.make("mirror").pipe(
    Command.withDescription(
      "Manage a read replica of the project in another deployment (sync / status / mark / promote)",
    ),
    Command.withSubcommands([mirrorSync, mirrorStatus, mirrorMark, mirrorPromote]),
  );

  return mirror;
}
