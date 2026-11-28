import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import { makeApiClient, type MaruhiClient } from "../api.ts";
import { syncProject, type VerifiedProject } from "../chain-sync.ts";
import type { CliServices } from "../cli.ts";
import type { CliConfig as MaruhiCliConfig } from "../config.ts";
import { openSession, openSessionWith, resolveProjectId, type SessionContext } from "../context.ts";
import { countNoun, displayText } from "../display.ts";
import { type CliError, cliError } from "../errors.ts";
import { isNoAnswer, toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logWarning } from "../notice.ts";
import { PROMOTE_PROBE_TIMEOUT, sameDeployment } from "./mirror-deployment.ts";
import { headOnChain } from "./mirror-heads.ts";
import type { Refusal } from "./mirror-mark.ts";

export const mirrorPromoteOp = Effect.fn("mirror-promote.mirrorPromoteOp")(function* (flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const context = yield* openSession(flags.server);
  const projectId = yield* resolveProjectId(flags.project, context.config);
  const status = yield* context.client.mirror
    .status({ params: { projectId } })
    .pipe(Effect.mapError(toCliError));
  const guard =
    status.sourceOrigin !== undefined
      ? yield* promotionGuard(context, projectId, status.sourceOrigin, status, flags.force === true)
      : { leftBehind: null, mirrorChain: null };
  const { leftBehind, mirrorChain } = guard;
  yield* context.client.mirror.unmark({ params: { projectId } }).pipe(Effect.mapError(toCliError));
  yield* io.log(
    `Promoted project ${projectId} on ${context.origin}: it accepts writes again. Members point at it with \`maruhi config set server ${context.origin}\`. A former primary that comes back is a stale server: it can never be replicated over this chain — mark it as a mirror of this one while its chain has not advanced past the fork, otherwise export it away`,
  );
  if (leftBehind !== null) {
    yield* io.log(leftBehind);
  }
  for (const line of yield* keyFollowUps(context.client, context.origin, projectId, mirrorChain)) {
    yield* io.log(line);
  }
});

const promotionGuard = Effect.fn("mirror-promote.promotionGuard")(function* (
  context: SessionContext,
  projectId: ProjectId,
  sourceOrigin: string,
  status: {
    readonly head: SourceHead;
    readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
  },
  forced: boolean,
): Effect.fn.Return<
  { readonly leftBehind: string | null; readonly mirrorChain: VerifiedProject | null },
  CliError,
  CliServices
> {
  const source = yield* sourceState(context.config, sourceOrigin, projectId, context.origin);
  const frozenAt =
    typeof source === "string" ? null : "frozenAt" in source ? source.frozenAt : null;
  const mirrorChain =
    frozenAt !== null && frozenAt.chainHeadSeq < status.head.chainHeadSeq
      ? yield* syncProject(context.client, projectId)
      : null;
  const refusal = promotionRefusal(source, sourceOrigin, status.head, context.origin, mirrorChain);
  if (refusal !== null) {
    if (!forced) {
      return yield* Effect.fail(cliError(`${refusal.body}${refusal.escape}`));
    }
    yield* logWarning(`promoting with --force. ${refusal.forced ?? refusal.body}`);
  }
  return {
    leftBehind: frozenAt === null ? null : rowsLeftBehind(frozenAt, sourceOrigin, status),
    mirrorChain,
  };
});

function rowsLeftBehind(
  frozenAt: SourceHead,
  sourceOrigin: string,
  mirror: {
    readonly head: SourceHead;
    readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
  },
): string | null {
  if (frozenAt.auditMaxSeq === undefined) {
    return null;
  }
  const keep = `a promoted copy takes no page, so they can never be brought over — keep them with \`maruhi project export --server ${sourceOrigin}\``;
  const counted =
    frozenAt.lastSync !== undefined
      ? frozenAt.auditMaxSeq - frozenAt.lastSync.auditMaxSeq
      : mirror.lastSync !== undefined && frozenAt.chainHeadHashHex === mirror.head.chainHeadHashHex
        ? frozenAt.auditMaxSeq - mirror.lastSync.auditMaxSeq
        : null;
  if (counted === null) {
    return `The audit rows the frozen source ${sourceOrigin} wrote since the last replication (the reads and leases it served) cannot be counted from here: ${keep}`;
  }
  return counted > 0
    ? `${countNoun(counted, "audit row")} stay on the frozen source ${sourceOrigin} (the reads and leases it served since the last replication): ${keep}`
    : null;
}

function promotionRefusal(
  source: SourceState,
  sourceOrigin: string,
  mirrorHead: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  thisOrigin: string,
  mirrorChain: VerifiedProject | null,
): Refusal | null {
  if (source === "writable") {
    return {
      body: `The source ${sourceOrigin} still answers and holds this project writable: promoting ${thisOrigin} now leaves two writable copies (a split brain). The planned order: mark the source as a mirror of ${thisOrigin} (\`maruhi mirror mark --server ${sourceOrigin} --source ${thisOrigin}\` — it freezes), bring its last writes over (\`maruhi mirror sync --server ${sourceOrigin} --mirror ${thisOrigin}\`), then promote; or take the source down`,
      escape: ". Pass --force to promote anyway",
      forced: `The source ${sourceOrigin} still answers and holds this project writable: two writable copies from now on (a split brain) until one is marked as a mirror of the other — the source as a mirror of ${thisOrigin} (\`maruhi mirror mark --server ${sourceOrigin} --source ${thisOrigin}\`) while it has taken no write, else this copy as a mirror of the source and a sync from it; writes both take meanwhile fork the project`,
    };
  }
  if (source === "answers") {
    return {
      body: `The source ${sourceOrigin} still answers, and its mark could not be read from this machine (no session for it here, or it refused the read): promoting ${thisOrigin} now may leave two writable copies (a split brain). Log in there (\`maruhi login --server ${sourceOrigin}\`) so the promotion can read whether it is frozen, follow the planned order (mark the source as a mirror of ${thisOrigin}, one last \`maruhi mirror sync\`, then promote)`,
      escape: ", or pass --force to promote anyway",
      forced: `The source ${sourceOrigin} still answers, and its mark could not be read from this machine: two writable copies may exist from now on (a split brain) — check its mark there, and mark it as a mirror of ${thisOrigin} or take it down`,
    };
  }
  if (source === "gone") {
    return null;
  }
  if ("frozenAt" in source) {
    return frozenRefusal(source.frozenAt, sourceOrigin, mirrorHead, thisOrigin, mirrorChain);
  }
  return source.sameKey
    ? {
        body: `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}, which publishes this server's key fingerprint. If that is this deployment under another hostname, promote it under that name (\`maruhi mirror promote --server ${source.movedTo}\` — the source is frozen for it); if it is another deployment sharing one SERVER_ENC_KEY_IKM, that is the misconfiguration to fix first (one key per deployment)`,
        escape: "; or pass --force to promote anyway",
        forced: `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}, which publishes this server's key fingerprint. If that is this deployment under another hostname, nothing is lost: the source is frozen for a name of this deployment, and members may use either; if it is another deployment sharing one SERVER_ENC_KEY_IKM, two writable copies exist from now on — fix the shared key, then mark one as a mirror of the other`,
      }
    : {
        body: `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}, not of ${thisOrigin}: the project's primary moved there, and promoting this copy would leave two writable copies (a split brain). Re-point this mirror at it (\`maruhi mirror mark --server ${thisOrigin} --source ${source.movedTo}\`) and sync from there`,
        escape: "; or pass --force to promote anyway",
        forced: `The source ${sourceOrigin} holds this project as a mirror of ${source.movedTo}: two writable copies from now on, this one and the primary at ${source.movedTo} (a split brain). Mark this copy as a mirror of it (\`maruhi mirror mark --server ${thisOrigin} --source ${source.movedTo}\`) while it has taken no write, and sync from there`,
      };
}

function frozenRefusal(
  frozenAt: SourceHead,
  sourceOrigin: string,
  mirrorHead: { readonly chainHeadSeq: number; readonly chainHeadHashHex: string },
  thisOrigin: string,
  mirrorChain: VerifiedProject | null,
): Refusal | null {
  if (frozenAt.chainHeadHashHex === mirrorHead.chainHeadHashHex) {
    return null;
  }
  if (frozenAt.chainHeadSeq <= mirrorHead.chainHeadSeq) {
    return frozenAt.chainHeadSeq < mirrorHead.chainHeadSeq &&
      mirrorChain !== null &&
      headOnChain(frozenAt, mirrorChain)
      ? null
      : {
          body: `The source ${sourceOrigin} is frozen at chain seq ${frozenAt.chainHeadSeq} (head ${frozenAt.chainHeadHashHex}), which is not an entry of this mirror's chain (seq ${mirrorHead.chainHeadSeq}, head ${mirrorHead.chainHeadHashHex}): the two copies forked, and a promotion would bury the fork. Run \`maruhi project verify\` against both and decide which chain is the project's`,
          escape: "; --force promotes this copy anyway",
        };
  }
  return {
    body: `The source ${sourceOrigin} is frozen at chain seq ${frozenAt.chainHeadSeq} (head ${frozenAt.chainHeadHashHex}) but this mirror holds seq ${mirrorHead.chainHeadSeq} (head ${mirrorHead.chainHeadHashHex}): its last writes have not been brought over. Run \`maruhi mirror sync --server ${sourceOrigin} --mirror ${thisOrigin}\` first`,
    escape: "; or pass --force to promote without them",
    forced: `promoting without the chain entries ${sourceOrigin} holds past seq ${mirrorHead.chainHeadSeq} (its head is seq ${frozenAt.chainHeadSeq}): a promoted copy takes no page, so they are unreachable from ${thisOrigin} from now on — keep them with \`maruhi project export --server ${sourceOrigin}\``,
  };
}

interface SourceHead {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq?: number | undefined;
  readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
}

type SourceState =
  | { readonly frozenAt: SourceHead }
  | "writable"
  | "answers"
  | "gone"
  | { readonly movedTo: string; readonly sameKey: boolean };

const sourceState = Effect.fn("mirror-promote.sourceState")(function* (
  config: MaruhiCliConfig,
  sourceOrigin: string,
  projectId: ProjectId,
  thisOrigin: string,
): Effect.fn.Return<SourceState, never, CliServices> {
  const marked = yield* openSessionWith(config, sourceOrigin, "server").pipe(
    Effect.flatMap((source) =>
      source.client.mirror.status({ params: { projectId } }).pipe(
        Effect.flatMap((status): Effect.Effect<SourceState | null, never, CliServices> => {
          if (!status.mirror) {
            return Effect.succeed("writable");
          }
          if (status.sourceOrigin === undefined) {
            return Effect.succeed(null);
          }
          const movedTo = status.sourceOrigin;
          if (movedTo === thisOrigin) {
            return Effect.succeed({
              frozenAt: {
                ...status.head,
                ...(status.lastSync === undefined ? {} : { lastSync: status.lastSync }),
              },
            });
          }
          return Effect.map(sameDeployment(movedTo, thisOrigin), (same) => ({
            movedTo,
            sameKey: same,
          }));
        }),
      ),
    ),
    Effect.orElseSucceed(() => null),
  );
  if (marked !== null) {
    return marked;
  }
  return (yield* sourceAnswers(sourceOrigin)) ? "answers" : "gone";
});

const keyFollowUps = Effect.fn("mirror-promote.keyFollowUps")(function* (
  client: MaruhiClient,
  origin: string,
  projectId: ProjectId,
  prefetched: VerifiedProject | null = null,
): Effect.fn.Return<readonly string[], CliError, CliServices> {
  const verified = prefetched ?? (yield* syncProject(client, projectId));
  const own = yield* client.auth.authConfig({}).pipe(
    Effect.map((config) => config.serverKeyFingerprintHex ?? null),
    Effect.orElseSucceed(() => null),
  );
  const lines: string[] = [];
  for (const grant of [...verified.state.serverGrants.values()].toSorted((a, b) =>
    a.serverKeyFingerprintHex < b.serverKeyFingerprintHex ? -1 : 1,
  )) {
    if (grant.serverKeyFingerprintHex === own) {
      continue;
    }
    lines.push(
      `Another server key is granted on this chain: ${grant.serverKeyFingerprintHex} (environments ${grant.scopeEnvironmentIds.map(displayText).join(", ")}). If that deployment was compromised rather than lost, revoke it (\`maruhi server revoke --fingerprint ${grant.serverKeyFingerprintHex}\`) and rotate those environments (\`maruhi env rotate\`) — the promotion retires nothing`,
    );
  }
  if (own !== null && !verified.state.serverGrants.has(own)) {
    lines.push(
      `This deployment's server key (${own}) is not granted on the chain: CI leases are not issued here until an owner runs \`maruhi server grant --server ${origin}\``,
    );
  }
  return lines;
});

const sourceAnswers = Effect.fn("mirror-promote.sourceAnswers")(function* (
  sourceOrigin: string,
): Effect.fn.Return<boolean, never, HttpClient.HttpClient> {
  const client = yield* makeApiClient({ baseUrl: sourceOrigin, timeout: PROMOTE_PROBE_TIMEOUT });
  return yield* client.auth.authConfig({}).pipe(
    Effect.map(() => true),
    Effect.catch((error) => Effect.succeed(!isNoAnswer(error))),
  );
});
