// `maruhi mirror mark` / `maruhi mirror promote` (discipline: see commands/index.ts).

import { type MirrorStatus } from "@maruhi/api-schema";
import { Effect } from "effect";
import { Command } from "effect/cli";
import { type HttpClient } from "effect/http";

import { type MaruhiClient, makeApiClient } from "../api.ts";
import { type VerifiedProject, syncProject } from "../chain-sync.ts";
import { type CliConfig as MaruhiCliConfig } from "../config.ts";
import {
  type CliServices,
  type SessionContext,
  openSession,
  openSessionWith,
  resolveProjectId,
} from "../context.ts";
import { countNoun, displayText } from "../display.ts";
import { CliError, cliError, usageError } from "../errors.ts";
import { isNoAnswer, toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { headOnChain } from "../mirror.ts";
import { logNote, logWarning } from "../notice.ts";
import { normalizeHttpOrigin } from "../session.ts";
import { projectFlags, singleFlag, singleValued } from "./flags.ts";
import { PROMOTE_PROBE_TIMEOUT, sameDeployment } from "./mirror-core.ts";

/** `maruhi mirror mark`: --server is the mirror deployment, --source the deployment it mirrors. */
export const mirrorMarkConfig = {
  ...projectFlags(),
  source: singleValued("source", "URL of the deployment this project mirrors (required)"),
  force: singleFlag(
    "force",
    "Mark even though this project's chain is not part of the source's (a mirror that can never be synced)",
  ),
};

export const mirrorPromoteConfig = {
  ...projectFlags(),
  force: singleFlag(
    "force",
    "Promote even though the source still answers (two writable copies of the project — a split you accept)",
  ),
};

/** `maruhi mirror mark --server <mirror> --source <server>`: the owner marks the project read-only there. */
function mirrorMarkCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly source?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

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
function ensureMarkable(
  context: SessionContext,
  sourceOrigin: string,
  projectId: string,
  forced: boolean,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
        sourceUnread(
          "chain and mark",
          "this project's chain is part of it and that it is a primary",
        ),
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
}

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
interface Refusal {
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
  if (onChain(headOfView(here), view)) {
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
  if (!onChain(headOfView(view), here)) {
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

const onChain = headOnChain;

/**
 * `maruhi mirror promote --server <mirror>`: the owner unmarks the mirror;
 * it accepts writes again. The source is probed first (its public
 * `/auth/config`): a source that still answers means two writable copies
 * after the promotion, so it is refused unless `--force` (ruling C
 * revision — a split brain is an owner's explicit decision).
 */
function mirrorPromoteCommand(flags: {
  readonly server?: string | undefined;
  readonly project?: string | undefined;
  readonly force?: boolean | undefined;
}): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openSession(flags.server);
    const projectId = yield* resolveProjectId(flags.project, context.config);
    const status = yield* context.client.mirror
      .status({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    const guard =
      status.sourceOrigin !== undefined
        ? yield* promotionGuard(
            context,
            projectId,
            status.sourceOrigin,
            status,
            flags.force === true,
          )
        : { leftBehind: null, mirrorChain: null };
    const { leftBehind, mirrorChain } = guard;
    yield* context.client.mirror
      .unmark({ params: { projectId } })
      .pipe(Effect.mapError(toCliError));
    yield* io.log(
      `Promoted project ${projectId} on ${context.origin}: it accepts writes again. Members point at it with \`maruhi config set server ${context.origin}\`. A former primary that comes back is a stale server: it can never be replicated over this chain — mark it as a mirror of this one while its chain has not advanced past the fork, otherwise export it away`,
    );
    if (leftBehind !== null) {
      yield* io.log(leftBehind);
    }
    for (const line of yield* keyFollowUps(
      context.client,
      context.origin,
      projectId,
      mirrorChain,
    )) {
      yield* io.log(line);
    }
  });
}

/**
 * The promotion's guard on what the source holds: fails with the refusal,
 * else says what stays on a frozen source and hands on the mirror's chain
 * when the guard fetched it (a frozen source behind this mirror is judged
 * on it — a strict prefix holds nothing the mirror lacks, anything else is
 * a fork; ruling C revision, round 8).
 */
function promotionGuard(
  context: SessionContext,
  projectId: string,
  sourceOrigin: string,
  status: {
    readonly head: SourceHead;
    readonly lastSync?: { readonly auditMaxSeq: number } | undefined;
  },
  forced: boolean,
): Effect.Effect<
  { readonly leftBehind: string | null; readonly mirrorChain: VerifiedProject | null },
  CliError,
  CliServices
> {
  return Effect.gen(function* () {
    const source = yield* sourceState(context.config, sourceOrigin, projectId, context.origin);
    const frozenAt =
      typeof source === "string" ? null : "frozenAt" in source ? source.frozenAt : null;
    const mirrorChain =
      frozenAt !== null && frozenAt.chainHeadSeq < status.head.chainHeadSeq
        ? yield* syncProject(context.client, projectId)
        : null;
    const refusal = promotionRefusal(
      source,
      sourceOrigin,
      status.head,
      context.origin,
      mirrorChain,
    );
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
}

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
      onChain(frozenAt, mirrorChain)
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
function sourceState(
  config: MaruhiCliConfig,
  sourceOrigin: string,
  projectId: string,
  thisOrigin: string,
): Effect.Effect<SourceState, never, CliServices> {
  return Effect.gen(function* () {
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
}

/**
 * After a promotion: the other server keys the chain grants (each with
 * the environments its grant covers — the one to revoke and rotate if that
 * deployment was compromised), and whether this deployment's own key is
 * granted (CI leases need it). From the verified chain and this server's
 * public key; never a guess at a fingerprint (ruling F revision, round 3).
 */
function keyFollowUps(
  client: MaruhiClient,
  origin: string,
  projectId: string,
  prefetched: VerifiedProject | null = null,
): Effect.Effect<readonly string[], CliError, CliServices> {
  return Effect.gen(function* () {
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
        `Another server key is granted on this chain: ${grant.serverKeyFingerprintHex} (environments ${grant.scopeEnvironmentIds.map(displayText).join(", ")}). If that deployment was compromised rather than lost, revoke it (\`maruhi server revoke ${grant.serverKeyFingerprintHex}\`) and rotate those environments (\`maruhi env rotate\`) — the promotion retires nothing`,
      );
    }
    if (own !== null && !verified.state.serverGrants.has(own)) {
      lines.push(
        `This deployment's server key (${own}) is not granted on the chain: CI leases are not issued here until an owner runs \`maruhi server grant --server ${origin}\``,
      );
    }
    return lines;
  });
}

/** Whether the source deployment answers its public auth config within the probe's bound (an error of any kind = it does not). */
function sourceAnswers(sourceOrigin: string): Effect.Effect<boolean, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* makeApiClient({ baseUrl: sourceOrigin, timeout: PROMOTE_PROBE_TIMEOUT });
    return yield* client.auth.authConfig({}).pipe(
      Effect.map(() => true),
      // Any HTTP answer counts, even an error; only no answer at all does not
      Effect.catch((error) => Effect.succeed(!isNoAnswer(error))),
    );
  });
}

export const mirrorMark = Command.make("mark", mirrorMarkConfig, (values) =>
  mirrorMarkCommand(values),
).pipe(
  Command.withDescription(
    "Mark the project on this server (--server names the mirror deployment) as a read-only mirror of --source; writes are refused there from then on (owner only)",
  ),
);

export const mirrorPromote = Command.make("promote", mirrorPromoteConfig, (values) =>
  mirrorPromoteCommand(values),
).pipe(
  Command.withDescription(
    "Remove the mirror mark on this server (--server names the mirror deployment): the project accepts writes again and becomes the primary (owner only)",
  ),
);
