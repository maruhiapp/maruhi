// `maruhi mirror mark` (AUTH_SPEC §11-7 — ruling C revision): the owner
// marks the project read-only on the mirror deployment (--server) as a
// mirror of --source. A source that is this deployment is refused; then
// the source's chain and mark are read, and a mark no sync could follow is
// refused unless --force (ensureMarkable).

import type { MirrorStatus } from "@maruhi/api-schema";
import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { syncProject, type VerifiedProject } from "../chain-sync.ts";
import {
  type CliServices,
  openSession,
  openSessionWith,
  resolveProjectId,
  type SessionContext,
} from "../context.ts";
import { countNoun } from "../display.ts";
import { type CliError, cliError, usageError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { normalizeHttpOrigin } from "../session.ts";
import { sameDeployment } from "./mirror-deployment.ts";
import { headOnChain } from "./mirror-heads.ts";

/** `maruhi mirror mark --server <mirror> --source <server>`: the owner marks the project read-only there. */
export const mirrorMarkOp = Effect.fn("mirror-mark.mirrorMarkOp")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly source?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  if (flags.source === undefined) {
    return yield* Effect.fail(
      usageError("mirror mark requires --source <url> (the deployment this project mirrors)"),
    );
  }
  const sourceOrigin = yield* normalizeHttpOrigin(flags.source, "the --source URL");
  const context = yield* openSession(flags.server);
  if (yield* sameDeployment(sourceOrigin, context.origin)) {
    return yield* Effect.fail(
      usageError(
        sourceOrigin === context.origin
          ? "--source is the server itself (run this against the mirror deployment with --server <mirror url>)"
          : "--source publishes this server's key fingerprint: it is this deployment under another hostname (run this against the mirror deployment with --server <mirror url>), or another deployment sharing one SERVER_ENC_KEY_IKM — one key per deployment; generate a distinct IKM for the mirror first",
      ),
    );
  }
  const projectId = yield* resolveProjectId(flags.project, context.config);
  // A project whose chain is not part of the source's (a former primary
  // that advanced past the fork) can never be synced: every replica is
  // refused as not an extension, and there is no way out but another
  // promotion. Refused here, before the mark (ruling C revision, round 3)
  yield* ensureMarkable(context, sourceOrigin, projectId, flags.force === true);
  yield* context.client.mirror
    .mark({ params: { projectId }, payload: { sourceOrigin } })
    .pipe(Effect.mapError(toCliError));
  yield* io.log(
    `Marked project ${projectId} on ${context.origin} as a mirror of ${sourceOrigin}: it refuses writes from now on and serves reads and leases. Keep it current with \`maruhi mirror sync --server ${sourceOrigin} --mirror ${context.origin}\`; members fall back to it with \`maruhi config set mirror ${context.origin}\``,
  );
});

/**
 * The mark's precondition: the two chains are one chain — the project's
 * head here is an entry of the source's verified chain (equal, or behind
 * it), or the source's head is an entry of this project's (this project
 * is ahead: the planned failover's freeze, whose last sync brings the
 * difference over — ruling C revision, round 8). Only a fork is refused.
 * Both views are plain verified chains (no floor: the floor is per
 * project, and a mirror behind the local floor is the normal state of the
 * copy about to be synced). The source's view needs a session there;
 * without one, or when the source does not answer, the mark proceeds with
 * a warning (the first sync tells).
 */
const ensureMarkable = Effect.fn("mirror-mark.ensureMarkable")(function* (
  context: SessionContext,
  sourceOrigin: string,
  projectId: ProjectId,
  forced: boolean,
): Effect.fn.Return<void, CliError, CliServices> {
  const here = yield* syncProject(context.client, projectId);
  // Each read stands alone (round 10): a transient failure of the mark's
  // read does not discard the chain already read, nor the other way round
  const source = yield* openSessionWith(context.config, sourceOrigin, "server").pipe(
    Effect.flatMap((session) =>
      Effect.all(
        {
          view: syncProject(session.client, projectId).pipe(
            Effect.catch(sourceUnread("chain", "this project's chain is part of it")),
          ),
          mark: session.client.mirror
            .status({ params: { projectId } })
            .pipe(
              Effect.mapError(toCliError),
              Effect.catch(sourceUnread("mark", "it is a primary, or frozen for this project")),
            ),
        },
        // Concurrently: a source that does not answer costs one bound, not two (round 12)
        { concurrency: 2 },
      ),
    ),
    Effect.catch(
      sourceUnread("chain and mark", "this project's chain is part of it and that it is a primary"),
    ),
  );
  const verdict = source === null ? null : markRefusal(context, sourceOrigin, here, source);
  if (verdict === null) {
    return;
  }
  if (verdict.kind === "note") {
    yield* logNote(verdict.text);
    return;
  }
  // A source frozen for this deployment under another hostname (C-13):
  // the star instruction would be refused as a self-mark, so the way out
  // is the mark under that name (round 11)
  const body =
    verdict.star !== undefined && (yield* sameDeployment(verdict.star, context.origin))
      ? `${sourceOrigin} holds this project as a mirror of ${verdict.star}, which publishes this server's key fingerprint: that is this deployment under the name the freeze used — run the mark with \`--server ${verdict.star}\`; if it is another deployment sharing one SERVER_ENC_KEY_IKM, that is the misconfiguration to fix first (one key per deployment)`
      : verdict.body;
  // --force marks anyway, but says what it overrides (round 10) — without
  // the refusal's own escape clause (round 11)
  if (!forced) {
    return yield* Effect.fail(cliError(`${body}${verdict.escape}`));
  }
  yield* logWarning(`marking with --force. ${body}`);
});

/** The mark proceeds without the check a failed read of the source would feed, with a warning. */
function sourceUnread(
  what: string,
  check: string,
): (error: CliError) => Effect.Effect<null, never, CliServices> {
  return (error) =>
    Effect.as(
      logWarning(
        `the source's ${what} could not be read (${error.message}); marking without the check that ${check} — the first \`maruhi mirror sync\` tells`,
      ),
      null,
    );
}

/** A refusal's text, with its "pass --force" clause apart: the clause is printed on the refusing path only (round 11). */
export interface Refusal {
  readonly body: string;
  readonly escape: string;
  /** What `--force` does instead of the body's remedy, when the remedy is dead after the override (round 12); the body otherwise. */
  readonly forced?: string | undefined;
}

type MarkVerdict =
  | { readonly kind: "note"; readonly text: string }
  | (Refusal & {
      readonly kind: "refusal";
      /** The third origin the source is a mirror of (the star refusal). */
      readonly star?: string | undefined;
    })
  | null;

/** What the mark's guard says about the source: a refusal, a note to print, or nothing. */
function markRefusal(
  context: SessionContext,
  sourceOrigin: string,
  here: VerifiedProject,
  source: { readonly view: VerifiedProject | null; readonly mark: MirrorStatus | null },
): MarkVerdict {
  // The source's own mark decides whether the sync the mark leads to can
  // run at all (ruling C revision, round 9): a mirror of a third origin
  // is no source (the star), and a writable source takes no page
  if (source.mark?.mirror === true && source.mark.sourceOrigin !== context.origin) {
    return {
      kind: "refusal",
      body: `${sourceOrigin} holds this project as a mirror of ${source.mark.sourceOrigin ?? "another deployment"}: mirrors sync from the primary, so this project is marked against it (\`maruhi mirror mark --server ${context.origin} --source ${source.mark.sourceOrigin ?? "<primary url>"}\`)`,
      escape: `, or pass --force to mark it against ${sourceOrigin} anyway`,
      star: source.mark.sourceOrigin,
    };
  }
  if (source.view === null) {
    // The chain could not be read, but the mark alone tells that the
    // source is frozen for this deployment: the undo note stands (round 11)
    return source.mark?.mirror === true
      ? {
          kind: "note",
          text: `${sourceOrigin} is frozen as a mirror of this deployment, so after this mark neither copy accepts writes: promote one of them`,
        }
      : null;
  }
  return markChainVerdict(context, sourceOrigin, here, source.view, source.mark);
}

/** The chain relation's verdict: one chain in either direction passes (with the note the mark's state earns), a fork is refused. */
function markChainVerdict(
  context: SessionContext,
  sourceOrigin: string,
  here: VerifiedProject,
  view: VerifiedProject,
  mark: MirrorStatus | null,
): MarkVerdict {
  const source = { view, mark };
  if (headOnChain(headOfView(here), view)) {
    // Equal to or behind a source frozen for this project: two frozen
    // copies and no primary — the undo of a planned failover (round 10)
    return source.mark?.mirror === true
      ? {
          kind: "note",
          text: `${sourceOrigin} is frozen as a mirror of this deployment, so after this mark neither copy accepts writes: promote one (\`maruhi mirror promote --server ${sourceOrigin}\`, or this one after a sync from it)`,
        }
      : null;
  }
  const ahead = countNoun(here.state.headSeq - view.state.headSeq, "chain entry");
  if (!headOnChain(headOfView(view), here)) {
    return {
      kind: "refusal",
      body: `This project's chain (seq ${here.state.headSeq}, head ${here.state.headHashHex}) and ${sourceOrigin}'s (seq ${view.state.headSeq}, head ${view.state.headHashHex}) are not one chain: neither head is an entry of the other. Marked as a mirror it could never be synced (every replica would be refused as not an extension). It was written to after the fork — export it away`,
      escape: ", or pass --force to mark it anyway",
    };
  }
  if (source.mark !== null && !source.mark.mirror) {
    return {
      kind: "refusal",
      body: `${sourceOrigin} holds this project writable, and this project holds ${ahead} it lacks (seq ${here.state.headSeq} against ${view.state.headSeq}): no sync brings them into a writable deployment (a replication writes into a marked mirror only). If this project is the primary, mark ${sourceOrigin} as a mirror of it instead (\`maruhi mirror mark --server ${sourceOrigin} --source ${context.origin}\`) and sync from here; if ${sourceOrigin} is the primary, those entries were written here after the fork — export them away`,
      escape: ". --force marks anyway and abandons them",
    };
  }
  // The mark unread: the sync below presumes a source frozen for this
  // project, so the note says what holds otherwise (round 11)
  const unread =
    source.mark === null
      ? ` — if ${sourceOrigin} is frozen for this project; if it holds the project writable, the mark goes the other way round (\`maruhi mirror mark --server ${sourceOrigin} --source ${context.origin}\`)`
      : "";
  return {
    kind: "note",
    text: `this project holds ${ahead} that ${sourceOrigin} lacks (seq ${here.state.headSeq} against ${view.state.headSeq}): after the mark, bring them over with \`maruhi mirror sync --server ${context.origin} --mirror ${sourceOrigin}\` before promoting ${sourceOrigin} (the planned failover's last sync)${unread}`,
  };
}

function headOfView(view: VerifiedProject): {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
} {
  return { chainHeadSeq: view.state.headSeq, chainHeadHashHex: view.state.headHashHex };
}
