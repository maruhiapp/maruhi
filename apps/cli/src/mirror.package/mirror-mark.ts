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
  yield* ensureMarkable(context, sourceOrigin, projectId, flags.force === true);
  yield* context.client.mirror
    .mark({ params: { projectId }, payload: { sourceOrigin } })
    .pipe(Effect.mapError(toCliError));
  yield* io.log(
    `Marked project ${projectId} on ${context.origin} as a mirror of ${sourceOrigin}: it refuses writes from now on and serves reads and leases. Keep it current with \`maruhi mirror sync --server ${sourceOrigin} --mirror ${context.origin}\`; members fall back to it with \`maruhi config set mirror ${context.origin}\``,
  );
});

const ensureMarkable = Effect.fn("mirror-mark.ensureMarkable")(function* (
  context: SessionContext,
  sourceOrigin: string,
  projectId: ProjectId,
  forced: boolean,
): Effect.fn.Return<void, CliError, CliServices> {
  const here = yield* syncProject(context.client, projectId);
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
  const body =
    verdict.star !== undefined && (yield* sameDeployment(verdict.star, context.origin))
      ? `${sourceOrigin} holds this project as a mirror of ${verdict.star}, which publishes this server's key fingerprint: that is this deployment under the name the freeze used — run the mark with \`--server ${verdict.star}\`; if it is another deployment sharing one SERVER_ENC_KEY_IKM, that is the misconfiguration to fix first (one key per deployment)`
      : verdict.body;
  if (!forced) {
    return yield* Effect.fail(cliError(`${body}${verdict.escape}`));
  }
  yield* logWarning(`marking with --force. ${body}`);
});

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

export interface Refusal {
  readonly body: string;
  readonly escape: string;
  readonly forced?: string | undefined;
}

type MarkVerdict =
  | { readonly kind: "note"; readonly text: string }
  | (Refusal & {
      readonly kind: "refusal";
      readonly star?: string | undefined;
    })
  | null;

function markRefusal(
  context: SessionContext,
  sourceOrigin: string,
  here: VerifiedProject,
  source: { readonly view: VerifiedProject | null; readonly mark: MirrorStatus | null },
): MarkVerdict {
  if (source.mark?.mirror === true && source.mark.sourceOrigin !== context.origin) {
    return {
      kind: "refusal",
      body: `${sourceOrigin} holds this project as a mirror of ${source.mark.sourceOrigin ?? "another deployment"}: mirrors sync from the primary, so this project is marked against it (\`maruhi mirror mark --server ${context.origin} --source ${source.mark.sourceOrigin ?? "<primary url>"}\`)`,
      escape: `, or pass --force to mark it against ${sourceOrigin} anyway`,
      star: source.mark.sourceOrigin,
    };
  }
  if (source.view === null) {
    return source.mark?.mirror === true
      ? {
          kind: "note",
          text: `${sourceOrigin} is frozen as a mirror of this deployment, so after this mark neither copy accepts writes: promote one of them`,
        }
      : null;
  }
  return markChainVerdict(context, sourceOrigin, here, source.view, source.mark);
}

function markChainVerdict(
  context: SessionContext,
  sourceOrigin: string,
  here: VerifiedProject,
  view: VerifiedProject,
  mark: MirrorStatus | null,
): MarkVerdict {
  const source = { view, mark };
  if (headOnChain(headOfView(here), view)) {
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
