// `maruhi mirror status` (AUTH_SPEC §11-7): the server's verified chain
// head and the mirror's, side by side, with the last replication. The
// status fails on fork evidence in the mirror's head, as the sync does.
//
// TCB discipline: the same as mirror-sync.ts's — heads and counts only.

import type { MirrorStatus } from "@maruhi/api-schema";
import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { type CliServices, openSession } from "../context.ts";
import { formatUtcMinutes } from "../display.ts";
import { type CliError, evidenceError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { sameDeployment } from "./mirror-deployment.ts";
import { forkNote, headNote } from "./mirror-heads.ts";
import {
  describeLastSync,
  openMirrorTarget,
  readMirrorStatus,
  verifiedViewOf,
} from "./mirror-target.ts";

/** The server's verified view (the same keyless prologue as `project export`). */
const verifiedServerView = Effect.fn("mirror-status.verifiedServerView")(function* (
  serverFlag: string | undefined,
  projectId: ProjectId,
) {
  const source = yield* openSession(serverFlag);
  const verified = yield* verifiedViewOf(source, projectId);
  return { source, verified };
});

/**
 * `maruhi mirror status`: the server's verified head and the mirror's,
 * side by side. The one command for "is my mirror usable" must answer
 * while the server is down: a server that does not answer leaves the
 * mirror's head alone on the report (announced), any other failure of the
 * server side fails as usual.
 */
export const mirrorStatusOp = Effect.fn("mirror-status.mirrorStatusOp")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly mirror?: string | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const target = yield* openMirrorTarget(flags);
  const status = yield* readMirrorStatus({
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

/** The fork evidence a mirror's reported head carries against the verified view (`maruhi mirror status` fails on it — round 11); null = none. */
function statusEvidence(status: MirrorStatus, verified: VerifiedProject): string | null {
  return forkNote(status.head, verified);
}

/** The two heads side by side (`maruhi mirror status`); without the server's view (it did not answer) the mirror's head stands alone. */
function describeMirrorStatus(
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
    `Mirror ${mirrorOrigin} of ${status.sourceOrigin ?? "an unknown source"} (marked ${status.markedAtMs === undefined ? "at an unknown time" : formatUtcMinutes(status.markedAtMs)})`,
    verified === null
      ? "Server: unreachable (no verified view)"
      : `Server: chain head seq=${verified.state.headSeq} (the verified view)`,
    `Mirror: ${mirrorHead}${status.head.auditMaxSeq === undefined ? "" : `; audit seq=${status.head.auditMaxSeq}`}`,
    describeLastSync(status),
    ...inProgress,
  ];
}
