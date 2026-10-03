// Helpers shared across command groups (discipline: see commands/index.ts). A leaf: nothing here imports another commands/ file.

import { type EnvironmentId } from "@maruhi/core";
import { Effect, Stdio } from "effect";

import {
  type ProposalView,
  describeInnerOperation,
  parseProposalExpiry,
} from "../approval-rules.ts";
import { type ProposalInput, type ProposedSummary } from "../approval.ts";
import {
  ANCHOR_REFRESH_PROPOSAL,
  ANCHOR_STALE_AFTER_ROTATION,
  checkpointProposal,
} from "../checkpoint.ts";
import { ConfigStore, type IdentityBacking, identityBackingOf } from "../config.ts";
import { type CliServices, type ProjectContext } from "../context.ts";
import { countNoun, displayText, formatUtcMinutes } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { GITHUB_LOGIN } from "../invite-link.ts";
import { CliIo, type CliIoShape } from "../io.ts";
import { Keychain, tokenEntryName } from "../keychain.ts";
import { logNote, logWarning } from "../notice.ts";
import { reportRotation } from "../rotation-report.ts";
import { type SweepOutcome } from "../rotation-sweep.ts";
import { normalizeHttpOrigin } from "../session.ts";

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
export function commandAfterTerminator(
  parsed: readonly string[],
): Effect.Effect<readonly string[], CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
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
  });
}

/** The environment ID's shape (the wording for the --env flag. The given value itself never appears in the error). */
export const ENV_FLAG_SHAPE_MESSAGE =
  "Invalid environment ID for --env (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -)";

/**
 * After `config set mirror`: a fallback that needs a login while the server
 * is down is no fallback (ruling E revision), so the member is told now when
 * no session for the mirror is in the keychain.
 */
export function noteMirrorSession(raw: string): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
}

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
    const store = yield* ConfigStore;
    return identityBackingOf(yield* store.load);
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
export function proposeCheckpointRefresh(
  context: Pick<ProjectContext, "client" | "verified" | "session">,
  options: { readonly includeAnchor: boolean },
): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const proposal = yield* checkpointProposal({
      client: context.client,
      verified: context.verified,
      signerUserId: context.session.userId,
      nowMs: Date.now(),
    });
    if (proposal === null) {
      return;
    }
    yield* logNote(options.includeAnchor ? `${proposal}. ${ANCHOR_REFRESH_PROPOSAL}` : proposal);
  }).pipe(Effect.catch(() => Effect.void));
}

/** `maruhi server grant --environments <ids> [--lease-policy <file>]` (§9 / §12-6). */
/**
 * Four-eyes (K6-K): `--expires <duration>` → the proposal's expiry and
 * clock. Never read on an operation the policy doesn't target, but a
 * malformed format drops as usage (2) before any communication.
 */
export function proposalInputOf(
  expires: string | undefined,
): Effect.Effect<ProposalInput, CliError> {
  const parsed = parseProposalExpiry(expires);
  if (!parsed.ok) {
    return Effect.fail(usageError(parsed.message));
  }
  const nowMs = Date.now();
  return Effect.succeed({ nowMs, expiresAtMs: nowMs + parsed.lifetimeMs });
}

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
export function reportProposed(
  io: CliIoShape,
  proposal: ProposedSummary,
): Effect.Effect<number, never, CliIo> {
  return Effect.gen(function* () {
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
}

/**
 * Reporting the sweep result (the §7 all-environment scan) and deriving
 * the exit code (shared by server revoke / member remove / change-role).
 * `alreadyRotatedBasis` phrases "past which point an epoch was confirmed
 * rotated" (revoke = the revocation, member = the duty entry). The report
 * shape and §7's "never silently skip a failed rotate" discipline are
 * kept in one place — held twice, only one would get fixed.
 */
export function reportSweepOutcome(
  sweep: SweepOutcome & {
    readonly skippedDeleted: readonly string[];
    readonly outOfScope?: readonly string[];
  },
  options: { readonly rerunCommand: string; readonly alreadyRotatedBasis: string },
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* warnOutOfScopeMandates(sweep.outOfScope ?? []);
    if (sweep.skippedDeleted.length > 0) {
      yield* io.log(
        `Skipped deleted environments (signed deletion statements verified): ${sweep.skippedDeleted.join(", ")}`,
      );
    }
    if (sweep.alreadyRotated.length > 0) {
      yield* io.log(
        `Already rotated (epoch newer than ${options.alreadyRotatedBasis}, no incomplete re-encryption confirmed): ${sweep.alreadyRotated.join(", ")}`,
      );
    }
    let exitCode = 0;
    for (const item of sweep.rotated) {
      const code = yield* reportRotation(
        item.environmentId as EnvironmentId,
        item.summary,
        item.forcedNewEpoch,
      );
      if (code !== 0) {
        exitCode = 1;
      }
    }
    for (const failure of sweep.failed) {
      // §7: never silently skip a rotate refusal of an environment
      // believed active (never make selective rotation blocking by a
      // malicious server invisible)
      yield* logWarning(
        `rotation of environment ${displayText(failure.environmentId)} failed: ${failure.message} — resolve the cause and re-run ${options.rerunCommand} to resume (if the environment was deleted, check for a verified deletion statement)`,
      );
      exitCode = 1;
    }
    if (sweep.rotated.some((item) => item.summary.mode === "rotated")) {
      // The anchor-update proposal — emitted as one line across the whole sweep
      yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
    }
    return exitCode;
  });
}
