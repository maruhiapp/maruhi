// Helpers shared across command groups (discipline: see commands/index.ts).
// A leaf: of the other commands/ files it imports only lazy.ts, itself a leaf.

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

// P-6: the heavy implementation graph (context / api / session and the op
// modules) is imported lazily inside the bodies that use it, so that
// parsing / help / version never pay its module cost. `import()` inside an
// `Effect.promise` resolves only when the command handler actually runs.
// Each load reads its names off the module inside the `.then` — the only
// shape fallow credits per export (pinned by test/lazy-imports.test.ts).
// Every context.ts and session.ts function the commands call is wrapped
// once in lazy.ts, as are the two rotation helpers several commands share
// (reportRotationChecklist, sweepRotateFor), so a command imports them from
// there and calls them directly. That parsing, help and version load none
// of context / api / session / chain-sync is checked on the running CLI by
// test/startup-loads.test.ts.

/** The guidance attached to a run that forgot `--` (there is exactly one way to pass the run target). */
const RUN_TERMINATOR_HINT =
  ". Write the command to run after `--` (example: `maruhi run -- printenv MY_VAR`)";

/**
 * Settles the command list `maruhi run` executes (**only what follows
 * `--`**). The parser merges the positional arguments before and after
 * `--` into one array (measured: upstream's `parseArgs` produces
 * `[...result.arguments, ...afterEndOfOptions]`). So on the declaration
 * alone, `maruhi run stray -- printenv` would disguise as running `stray`.
 * As the implementation of ADR-0016 decision 8 (`--` is required, judged
 * by reading `Stdio.args`), it also checks **that the count after `--`
 * matches**.
 *
 * The count is derived from **the array the parser resolved and argv's
 * position** (never a copy of the declaration — it would silently drift
 * when a value-taking flag is added). The contents never appear in
 * diagnostics.
 */
export const commandAfterTerminator = Effect.fn("commands-shared.commandAfterTerminator")(
  function* (
    parsed: readonly string[],
  ): Effect.fn.Return<readonly string[], CliError, Stdio.Stdio> {
    const stdio = yield* Stdio.Stdio;
    const argv = yield* stdio.args;
    const terminator = argv.indexOf("--");
    // On the no-`--` branch, the variadic arguments stay as extra
    // positional arguments (`--env prod`'s `prod` was eaten as the flag's
    // value)
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

/**
 * After `config set mirror`: a fallback that needs a login while the server
 * is down is no fallback (ruling E revision), so the member is told now when
 * no session for the mirror is in the keychain.
 */
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

/** Format check of the flag taking a GitHub login (`--github` / `--from`) (unspecified = null). */
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

/** The backing-source setting (CRYPTO_SPEC §6.5 — unset = github-signing-keys). */
export const loadIdentityBacking: Effect.Effect<IdentityBacking, CliError, ConfigStore> =
  Effect.gen(function* () {
    return identityBackingOf(yield* loadCliConfig);
  });

/**
 * §7: a duty environment outside the performer's scope cannot be rotated
 * — a note, not a failure (the always-on warning keeps displaying it, and
 * an env rotate by a member whose scope covers it converges it).
 */
function warnOutOfScopeMandates(outOfScope: readonly string[]): Effect.Effect<void, never, CliIo> {
  if (outOfScope.length === 0) {
    return Effect.void;
  }
  const one = outOfScope.length === 1;
  return logWarning(
    `${countNoun(outOfScope.length, "environment")} with a pending rotation mandate ${one ? "is" : "are"} outside your scope and cannot be rotated by you (${outOfScope.map(displayText).join(", ")}) — a member whose scope includes ${one ? "it" : "them"} converges ${one ? "it" : "them"} with \`maruhi env rotate <environment> --new-epoch --reason <text>\``,
  );
}

/**
 * The proposal of issuance trigger (iii) (CRYPTO_SPEC §6.3): when a pull /
 * push success detects staleness of the baseline checkpoint (over 7 days,
 * or never issued = over 7 days since genesis), emit the proposal **as a
 * 1-line Note**. A failed proposal judgment never overturns the command
 * body's success (the proposal is a SHOULD attachment). On push, the
 * anchor-update proposal is bundled into the end of the same line (DP5
 * ruling C — never split into 2 lines).
 */
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

/** A value write's sync, decided before the write is sent: the sync config, and what it means for the written variable. */
interface WriteSync {
  readonly setup: PushSyncSetup;
  readonly decision: PushSyncDecision;
}

/**
 * Decides a value write's sync before the write is sent (push, var
 * rollback, var rotate): null when no sync config was read (none at the
 * default path, or --no-sync). A disagreement with an explicitly given
 * config's `project` is a misspelling (2), and the write is not sent.
 */
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

/**
 * Opens the environment a value write goes to (push, var rollback), with
 * its sync. The sync config is read first, **before any network**, so a
 * broken file or an explicitly given other project's config is never
 * found behind the write (same as SY2 stage 2 2b's ruling B), and the
 * sync is decided before the write is sent (decideWriteSync).
 */
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

/**
 * After a successful value write (push, var rollback, var rotate):
 * issuance trigger (iii) (CRYPTO_SPEC §6.3), which detects the baseline
 * checkpoint's staleness (proposeCheckpointRefresh — the anchor-update
 * proposal rides the same route; the ruling is docs/notes/session-35.md),
 * then the decided sync: applied directly to the targets carrying
 * `onPush`, or CI launched. A failed sync stays a warning and the exit
 * code stays the write's (only the evidence fails — sync-push.ts).
 */
export const finishWrite = Effect.fn("commands-shared.finishWrite")(function* (
  context: EnvironmentContext,
  sync: WriteSync | null,
): Effect.fn.Return<void, CliError, CliServices> {
  yield* proposeCheckpointRefresh(context, { afterWrite: true });
  if (sync !== null) {
    yield* syncAfterPush({ context, ...sync });
  }
});

/**
 * Four-eyes (K6-K): `--expires <duration>` → the proposal's expiry and
 * clock. Never read on an operation the policy doesn't target, but a
 * malformed format drops as usage (2) before any communication.
 */
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

/** The wording of a proposal's remaining vote count ("needs N more owner approval(s)" — ruling P8). */
export function describeNeeded(view: ProposalView): string {
  if (view.needed === null) {
    return "the policy is off, so it cannot be approved (withdraw it)";
  }
  const more = view.needed + 1;
  return `needs ${countNoun(more, "more owner approval")} (${view.votes} of ${view.required} recounted so far)`;
}

/**
 * Reporting that it was proposed (or was already proposed) (K6-A — a
 * shape never mistaken for "appended"). States that nothing was applied
 * and who does what next.
 */
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

/**
 * Reporting the sweep result (the §7 all-environment scan) and deriving
 * the exit code (shared by server revoke / member remove / change-role).
 * `alreadyRotatedBasis` phrases "past which point an epoch was confirmed
 * rotated" (revoke = the revocation, member = the duty entry). The report
 * shape and §7's "never silently skip a failed rotate" discipline are
 * kept in one place — held twice, only one would get fixed.
 */
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
    // §7: never silently skip a rotate refusal of an environment
    // believed active (never make selective rotation blocking by a
    // malicious server invisible)
    yield* logWarning(
      `rotation of environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${options.rerunCommand} to resume (an environment deleted on the verified chain is never rotated, so this one is live)`,
    );
    exitCode = 1;
  }
  if (sweep.rotated.some((item) => item.summary.mode === "rotated")) {
    // The anchor-update proposal — emitted as one line across the whole sweep
    const { ANCHOR_STALE_AFTER_ROTATION } = yield* Effect.promise(() =>
      import("../checkpoint.package/index.ts").then((m) => ({
        ANCHOR_STALE_AFTER_ROTATION: m.ANCHOR_STALE_AFTER_ROTATION,
      })),
    );
    yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
  }
  return exitCode;
});

/** member add's result report and exit code (a backfill failure = a partial completion). */
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

/** Reporting change-role's post-application stage (shared by the direct append and the approver's fulfillment [approval approve]). */
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

/** Reporting change-role's widening backfill (a failure = a partial completion → 1). */
const reportScopeBackfill = Effect.fn("commands-shared.reportScopeBackfill")(function* (
  io: CliIoShape,
  summary: RoleChangeFulfilment,
  rerunCommand: string,
): Effect.fn.Return<number, never, CliIo> {
  // The note of the widenings remaining outside scope is emitted even
  // when no backfill exists within my scope (Cursor Bugbot's catch: the
  // main path is a listed admin re-running after someone else's
  // widening)
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

/** The explanation line of change-role's duties (demotion / narrowing) (the sweep report's preamble). */
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
