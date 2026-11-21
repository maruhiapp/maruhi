import type { UserId } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import { Clock, Effect, Stdio } from "effect";

import {
  type ProposalView,
  describeInnerOperation,
  parseProposalExpiry,
} from "../approval-rules.ts";
import type { ProposalInput, ProposedSummary } from "../approval.package/index.ts";
import { ConfigStore, type IdentityBacking, identityBackingOf, loadCliConfig } from "../config.ts";
import type { CliServices, CommonFlags, EnvironmentContext, ProjectContext } from "../context.ts";
import { countNoun, displayText, formatUtcMinutes } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { GITHUB_LOGIN } from "../invite-link.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { Keychain, tokenEntryName } from "../keychain.ts";
import type { MemberAddSummary, RoleChangeFulfilment } from "../member.package/index.ts";
import { logNote, logWarning } from "../notice.ts";
import { reportRotation } from "../rotation-report.ts";
import type { SweepOutcome } from "../rotation-sweep.ts";
import {
  decidePushSync,
  loadPushSyncConfig,
  type PushSyncDecision,
  type PushSyncSetup,
  syncAfterPush,
} from "../sync.package/index.ts";
import { normalizeHttpOrigin, openEnvironment } from "./lazy.ts";

const RUN_TERMINATOR_HINT =
  ". Write the command to run after `--` (example: `maruhi run -- printenv MY_VAR`)";

export const commandAfterTerminator = Effect.fn("commands-shared.commandAfterTerminator")(
  function* (
    parsed: readonly string[],
  ): Effect.fn.Return<readonly string[], CliError, Stdio.Stdio> {
    const stdio = yield* Stdio.Stdio;
    const argv = yield* stdio.args;
    const terminator = argv.indexOf("--");
    const stray = terminator < 0 ? parsed.length : parsed.length - (argv.length - terminator - 1);
    if (stray > 0) {
      return yield* Effect.fail(
        usageError(
          `Unexpected extra arguments (${stray}; contents not shown — they may contain plaintext values). \`maruhi run\` takes no positional arguments before \`--\`${RUN_TERMINATOR_HINT}`,
        ),
      );
    }
    return parsed;
  },
);

export const noteMirrorSession = Effect.fn("commands-shared.noteMirrorSession")(function* (
  raw: string,
): Effect.fn.Return<void, CliError, CliServices> {
  const origin = yield* normalizeHttpOrigin(raw, "the mirror URL", {
    fix: "mirror in your config",
  });
  const keychain = yield* Keychain;
  if ((yield* keychain.get(tokenEntryName(origin))) === null) {
    yield* logWarning(
      `no session for ${origin} is stored: run \`maruhi login --server ${origin}\` now, while the server is up — a fallback read uses the mirror's own credential, and a login is not possible once the server is the reason you need the mirror. Rehearse it with \`maruhi pull --server ${origin}\``,
    );
  }
});

export function parseGithubLoginFlag(
  flagName: string,
  value: string | undefined,
): Effect.Effect<string | null, CliError> {
  if (value === undefined) {
    return Effect.succeed(null);
  }
  return GITHUB_LOGIN.test(value)
    ? Effect.succeed(value)
    : Effect.fail(
        usageError(
          `${flagName} must be a GitHub login (1 to 39 letters, digits, or hyphens; no leading, trailing, or doubled hyphen)`,
        ),
      );
}

export const loadIdentityBacking: Effect.Effect<IdentityBacking, CliError, ConfigStore> =
  Effect.gen(function* () {
    return identityBackingOf(yield* loadCliConfig);
  });

function warnOutOfScopeMandates(outOfScope: readonly string[]): Effect.Effect<void, never, CliIo> {
  if (outOfScope.length === 0) {
    return Effect.void;
  }
  const one = outOfScope.length === 1;
  return logWarning(
    `${countNoun(outOfScope.length, "environment")} with a pending rotation mandate ${one ? "is" : "are"} outside your scope and cannot be rotated by you (${outOfScope.map(displayText).join(", ")}) — a member whose scope includes ${one ? "it" : "them"} converges ${one ? "it" : "them"} with \`maruhi env rotate <environment> --new-epoch --reason <text>\``,
  );
}

export const proposeCheckpointRefresh = Effect.fn("commands-shared.proposeCheckpointRefresh")(
  function* (
    context: Pick<ProjectContext, "client" | "verified" | "session">,
    options: { readonly afterWrite: boolean },
  ): Effect.fn.Return<void, never, CliServices> {
    const { ANCHOR_REFRESH_PROPOSAL, checkpointProposal } = yield* Effect.promise(() =>
      import("../checkpoint.package/index.ts").then((m) => ({
        ANCHOR_REFRESH_PROPOSAL: m.ANCHOR_REFRESH_PROPOSAL,
        checkpointProposal: m.checkpointProposal,
      })),
    );
    const proposal = yield* checkpointProposal({
      client: context.client,
      verified: context.verified,
      signerUserId: context.session.userId,
      nowMs: yield* Clock.currentTimeMillis,
      afterWrite: options.afterWrite,
    });
    if (proposal === null) {
      return;
    }
    yield* logNote(options.afterWrite ? `${proposal}. ${ANCHOR_REFRESH_PROPOSAL}` : proposal);
  },
);

interface WriteSync {
  readonly setup: PushSyncSetup;
  readonly decision: PushSyncDecision;
}

export function decideWriteSync(
  setup: PushSyncSetup | null,
  context: EnvironmentContext,
  name: string,
): Effect.Effect<WriteSync | null, CliError> {
  return setup === null
    ? Effect.succeed(null)
    : Effect.map(
        decidePushSync(setup, {
          projectId: context.projectId,
          environmentId: context.environmentId,
          name,
        }),
        (decision) => ({ setup, decision }),
      );
}

export const openWriteEnvironment = Effect.fn("commands-shared.openWriteEnvironment")(function* (
  values: CommonFlags & {
    readonly config?: string | undefined;
    readonly "no-sync": boolean;
    readonly name: string;
  },
): Effect.fn.Return<
  { readonly context: EnvironmentContext; readonly sync: WriteSync | null },
  CliError,
  CliServices
> {
  const setup = yield* loadPushSyncConfig({ config: values.config, noSync: values["no-sync"] });
  const context = yield* openEnvironment(values);
  return { context, sync: yield* decideWriteSync(setup, context, values.name) };
});

export const finishWrite = Effect.fn("commands-shared.finishWrite")(function* (
  context: EnvironmentContext,
  sync: WriteSync | null,
): Effect.fn.Return<void, CliError, CliServices> {
  yield* proposeCheckpointRefresh(context, { afterWrite: true });
  if (sync !== null) {
    yield* syncAfterPush({ context, ...sync });
  }
});

export const proposalInputOf = Effect.fn("commands-shared.proposalInputOf")(function* (
  expires: string | undefined,
): Effect.fn.Return<ProposalInput, CliError> {
  const parsed = parseProposalExpiry(expires);
  if (!parsed.ok) {
    return yield* Effect.fail(usageError(parsed.message));
  }
  const nowMs = yield* Clock.currentTimeMillis;
  return { nowMs, expiresAtMs: nowMs + parsed.lifetimeMs };
});

export function describeNeeded(view: ProposalView): string {
  if (view.needed === null) {
    return "the policy is off, so it cannot be approved (withdraw it)";
  }
  const more = view.needed + 1;
  return `needs ${countNoun(more, "more owner approval")} (${view.votes} of ${view.required} recounted so far)`;
}

export const reportProposed = Effect.fn("commands-shared.reportProposed")(function* (
  io: CliIoShape,
  proposal: ProposedSummary,
): Effect.fn.Return<number, never, CliIo> {
  const view = proposal.view;
  const id = view.proposal.proposalHashHex;
  if (proposal.kind === "proposed") {
    yield* io.log(
      `Proposed ${describeInnerOperation(view.proposal.inner)} (proposal ${id.slice(0, 12)}…, seq=${view.proposal.proposalSeq}; expires ${formatUtcMinutes(view.proposal.expiresAtMs)}) — the four-eyes policy requires approval, so nothing has been applied yet`,
    );
  } else {
    yield* io.log(
      `The same operation is already proposed (proposal ${id.slice(0, 12)}…, seq=${view.proposal.proposalSeq}, by ${displayText(view.proposal.proposerUserId)}; expires ${formatUtcMinutes(view.proposal.expiresAtMs)}) — nothing new was proposed and nothing has been applied`,
    );
  }
  yield* io.log(`  proposal id: ${id}`);
  yield* io.log(
    `  ${describeNeeded(view)}. Another owner runs \`maruhi approval approve ${id.slice(0, 12)}\`; the approver whose approval completes it runs the follow-up rotation / key distribution (CRYPTO_SPEC §7). \`maruhi approval list\` shows the status`,
  );
  return 0;
});

export const reportSweepOutcome = Effect.fn("commands-shared.reportSweepOutcome")(function* (
  sweep: SweepOutcome & {
    readonly skippedDeleted: readonly string[];
    readonly outOfScope?: readonly string[];
  },
  options: { readonly rerunCommand: string; readonly alreadyRotatedBasis: string },
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  yield* warnOutOfScopeMandates(sweep.outOfScope ?? []);
  if (sweep.skippedDeleted.length > 0) {
    yield* io.log(
      `Skipped deleted environments (delete_environment on the verified chain): ${sweep.skippedDeleted.join(", ")}`,
    );
  }
  if (sweep.alreadyRotated.length > 0) {
    yield* io.log(
      `Already rotated (epoch newer than ${options.alreadyRotatedBasis}, no incomplete re-encryption confirmed): ${sweep.alreadyRotated.join(", ")}`,
    );
  }
  let exitCode = 0;
  for (const item of sweep.rotated) {
    const code = yield* reportRotation(item.environmentId, item.summary, item.forcedNewEpoch);
    if (code !== 0) {
      exitCode = 1;
    }
  }
  for (const failure of sweep.failed) {
    yield* logWarning(
      `rotation of environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${options.rerunCommand} to resume (an environment deleted on the verified chain is never rotated, so this one is live)`,
    );
    exitCode = 1;
  }
  if (sweep.rotated.some((item) => item.summary.mode === "rotated")) {
    const { ANCHOR_STALE_AFTER_ROTATION } = yield* Effect.promise(() =>
      import("../checkpoint.package/index.ts").then((m) => ({
        ANCHOR_STALE_AFTER_ROTATION: m.ANCHOR_STALE_AFTER_ROTATION,
      })),
    );
    yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
  }
  return exitCode;
});

export const reportMemberAdd = Effect.fn("commands-shared.reportMemberAdd")(function* (
  io: CliIoShape,
  summary: Pick<MemberAddSummary, "registered" | "alreadyRegistered" | "repaired" | "failed"> & {
    readonly targetUserId: UserId;
    readonly role: Role | null;
  },
): Effect.fn.Return<number, CliError, CliIo> {
  const repaired =
    summary.repaired > 0 ? `, ${countNoun(summary.repaired, "old-key wrap")} repaired` : "";
  yield* io.log(
    `Added member ${displayText(summary.targetUserId)}${summary.role === null ? "" : ` (role=${summary.role})`}. Backfill: ${summary.registered} newly registered, ${summary.alreadyRegistered} already registered${repaired}`,
  );
  if (summary.failed.length === 0) {
    yield* io.log(
      "Done: DEK wraps for every environment in the member's scope × every epoch were distributed to the new member (CRYPTO_SPEC §7). Have the new member run `maruhi pull` and confirm they can decrypt",
    );
    return 0;
  }
  for (const failure of summary.failed) {
    yield* logWarning(
      `backfill for environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run \`maruhi member add\` to resume (409 converges as already-registered)`,
    );
  }
  return 1;
});

export const reportRoleChangeFulfilment = Effect.fn("commands-shared.reportRoleChangeFulfilment")(
  function* (
    io: CliIoShape,
    summary: RoleChangeFulfilment,
    rerunCommand: string,
  ): Effect.fn.Return<number, CliError, CliServices> {
    const backfillCode = yield* reportScopeBackfill(io, summary, rerunCommand);
    if (summary.sweep === null) {
      yield* io.log(
        backfillCode === 0
          ? "Done: the role / scope was changed (no rotation mandate)"
          : "The role / scope was changed, but the backfill is incomplete",
      );
      return backfillCode;
    }
    yield* reportChangeRoleMandates(io, summary);
    const sweepCode = yield* reportSweepOutcome(summary.sweep, {
      rerunCommand,
      alreadyRotatedBasis: "the mandate entry",
    });
    const exitCode = backfillCode === 0 && sweepCode === 0 ? 0 : 1;
    if (exitCode === 0) {
      yield* io.log("Done: the change and the rotation of the affected environments completed");
    }
    return exitCode;
  },
);

const reportScopeBackfill = Effect.fn("commands-shared.reportScopeBackfill")(function* (
  io: CliIoShape,
  summary: RoleChangeFulfilment,
  rerunCommand: string,
): Effect.fn.Return<number, never, CliIo> {
  if (summary.widenedOutOfScopeEnvironmentIds.length > 0) {
    yield* logWarning(
      `${countNoun(summary.widenedOutOfScopeEnvironmentIds.length, "environment")} widened earlier for this member (${summary.widenedOutOfScopeEnvironmentIds.map(displayText).join(", ")}) ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "is" : "are"} outside your scope, so you cannot backfill ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "it" : "them"} — a member whose scope includes ${summary.widenedOutOfScopeEnvironmentIds.length === 1 ? "it" : "them"} re-runs \`maruhi member change-role\` with the member's current scope to resume`,
    );
  }
  if (summary.backfill === null) {
    return 0;
  }
  yield* io.log(
    `${countNoun(summary.widenedEnvironmentIds.length, "environment")} added to the member's scope (${summary.widenedEnvironmentIds.map(displayText).join(", ")}) — backfilled every epoch's DEK to the target (AUTH_SPEC §12-6): ${summary.backfill.registered} newly registered, ${summary.backfill.alreadyRegistered} already registered`,
  );
  for (const failure of summary.backfill.failed) {
    yield* logWarning(
      `backfill for environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${rerunCommand} to resume (409 converges as already-registered)`,
    );
  }
  return summary.backfill.failed.length === 0 ? 0 : 1;
});

const reportChangeRoleMandates = Effect.fn("commands-shared.reportChangeRoleMandates")(function* (
  io: CliIoShape,
  summary: RoleChangeFulfilment,
): Effect.fn.Return<void, never> {
  if (summary.demoted) {
    yield* io.log(
      "Demotion below member forces a rotation of every environment in the target's scope (CRYPTO_SPEC §7 — epoch-anchor soundness)",
    );
  }
  if (summary.narrowedEnvironmentIds.length > 0) {
    yield* io.log(
      `Scope narrowed by ${countNoun(summary.narrowedEnvironmentIds.length, "environment")} (${summary.narrowedEnvironmentIds.map(displayText).join(", ")}) — forcing a rotation of those environments (CRYPTO_SPEC §7 — the target keeps their old DEKs)`,
    );
  }
});
