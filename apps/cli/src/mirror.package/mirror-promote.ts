// `maruhi mirror promote` (AUTH_SPEC §11-7 — ruling C revision): the owner
// unmarks the project on the mirror deployment (--server), which accepts
// writes again. The guard first reads what the source holds (sourceState)
// and, unless --force, refuses a promotion that may leave two writable
// copies or would bury the frozen source's last writes or a fork. The
// message then names the server keys to check (keyFollowUps).

import type { ProjectId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import { makeApiClient, type MaruhiClient } from "../api.ts";
import { syncProject, type VerifiedProject } from "../chain-sync.ts";
import type { CliConfig as MaruhiCliConfig } from "../config.ts";
import {
  type CliServices,
  openSession,
  openSessionWith,
  resolveProjectId,
  type SessionContext,
} from "../context.ts";
import { countNoun, displayText } from "../display.ts";
import { type CliError, cliError } from "../errors.ts";
import { isNoAnswer, toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logWarning } from "../notice.ts";
import { PROMOTE_PROBE_TIMEOUT, sameDeployment } from "./mirror-deployment.ts";
import { headOnChain } from "./mirror-heads.ts";
import type { Refusal } from "./mirror-mark.ts";

/**
 * `maruhi mirror promote --server <mirror>`: the owner unmarks the mirror;
 * it accepts writes again. The source is probed first (its public
 * `/auth/config`): a source that still answers means two writable copies
 * after the promotion, so it is refused unless `--force` (ruling C
 * revision — a split brain is an owner's explicit decision).
 */
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

/**
 * The promotion's guard on what the source holds: fails with the refusal,
 * else says what stays on a frozen source and hands on the mirror's chain
 * when the guard fetched it (a frozen source behind this mirror is judged
 * on it — a strict prefix holds nothing the mirror lacks, anything else is
 * a fork; ruling C revision, round 8).
 */
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
    // --force promotes anyway, but says what it abandons (round 9),
    // without the refusal's own escape clause (round 10)
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

/**
 * What stays on the frozen source after the promotion (ruling C revision,
 * rounds 8 and 9): its audit rows past the mirror's last replication —
 * counted only when the frozen head is the mirror's and a replication is
 * recorded (positions of one log; a re-point clears the record), else
 * said to be uncountable from here. null = nothing to say (none, or the
 * source's marks are not shown to this session).
 */
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
  // A source that synced back from this mirror holds this mirror's log
  // followed by its own rows: its own record counts them exactly (round
  // 10); otherwise the mirror's record counts, at the same head only
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

/**
 * Why a promotion is refused for what the source holds (null = it goes
 * through): a writable source and an unread mark are split brains, a
 * frozen source whose head the mirror lacks loses its last writes (round
 * 7), a source frozen for another origin moved; `--force` skips all four.
 */
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

/**
 * Why a promotion over a frozen source is refused (null = it goes through):
 * the planned order's last sync did not happen — the source holds chain
 * entries this mirror lacks, which a promotion makes unreachable forever
 * (ruling C revision, round 7); or the source, behind the mirror (restored
 * from an older backup, then frozen), is not on the mirror's chain — a
 * fork, which no sync repairs (round 8). A source behind the mirror on its
 * chain holds nothing the mirror lacks.
 */
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
    // At the mirror's height with another hash, or behind it and not on
    // its chain: a fork (round 10 — the same height was sent to a sync
    // the mirror refuses)
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

/** The frozen source's head as its status reports it (the audit seq to admins and owners only). */
interface SourceHead {
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly auditMaxSeq?: number | undefined;
  /** The source's own last replication (from this mirror, after a sync back — shown to admins and owners). */
  readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
}

/** What the source holds; `movedTo` = it is a mirror of another deployment (the primary moved there). */
type SourceState =
  | { readonly frozenAt: SourceHead }
  | "writable"
  | "answers"
  | "gone"
  | { readonly movedTo: string; readonly sameKey: boolean };

/**
 * What the source holds (ruling C revision, round 3): `frozen` = it is
 * already a mirror of **this** deployment — by server key fingerprint, so
 * a deployment under another hostname is still this one (round 5) — the
 * honest path, promoted without a probe; `movedTo` = it is a mirror of
 * another deployment (the primary moved there; promoting this copy is a
 * split brain — round 4); `writable` = its mark says it holds the project
 * as a primary; `answers` = its mark could not be read (no session for it
 * here, or a refusal) but its public `/auth/config` answers (any HTTP
 * answer counts); `gone` = nothing answers.
 */
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
          // A fingerprint match never lifts the guard (it is self-reported
          // and shared by deployments cloned from one secrets set — round
          // 6); it only names the honest way out
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

/**
 * After a promotion: the other server keys the chain grants (each with
 * the environments its grant covers — the one to revoke and rotate if that
 * deployment was compromised), and whether this deployment's own key is
 * granted (CI leases need it). From the verified chain and this server's
 * public key; never a guess at a fingerprint (ruling F revision, round 3).
 */
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

/** Whether the source deployment answers its public auth config within the probe's bound (an error of any kind = it does not). */
const sourceAnswers = Effect.fn("mirror-promote.sourceAnswers")(function* (
  sourceOrigin: string,
): Effect.fn.Return<boolean, never, HttpClient.HttpClient> {
  const client = yield* makeApiClient({ baseUrl: sourceOrigin, timeout: PROMOTE_PROBE_TIMEOUT });
  return yield* client.auth.authConfig({}).pipe(
    Effect.map(() => true),
    // Any HTTP answer counts, even an error; only no answer at all does not
    Effect.catch((error) => Effect.succeed(!isNoAnswer(error))),
  );
});
