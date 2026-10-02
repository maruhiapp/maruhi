// `maruhi rotation list|dismiss` (AUDIT_SPEC §4.1 / §6 / §7).
//
// - list: fetches and displays the server's derived view
//   (currently active rotation.recommended − resolved). Display
//   names are not trusted to the server's declaration; they are
//   resolved from the verified meta statements (a deleted
//   variable's tombstone — §4.2's "deleted keeps the last active
//   name") (AUDIT_SPEC §7's TCB discipline). An environment that
//   cannot be resolved (a verified deletion etc.) is displayed as
//   its identifier
// - dismiss: the withdrawal operation (the server generates
//   rotation.dismissed — admin). A flag is also resolved by
//   rotating the upstream credential + push (no re-encryption
//   marker needed) (§4.1-5) — dismiss is the explicit declaration
//   "accept the risk without rotating", and the only resolution
//   path for a deleted variable (which cannot be pushed)
//
// The flag set is only non-secret metadata (identifiers, basis
// kinds, targets); plaintext values and key material never pass
// through this module.

import type { RotationProposal } from "@maruhi/api-schema";
import { RotationFlagNotFoundError } from "@maruhi/api-schema";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { CliServices, ProjectContextBase } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import { countNoun, displayText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import {
  DAY_MS,
  describeDue,
  DUE_SOON_DAYS,
  type DueRow,
  type DueRows,
  dueRowsFor,
  type MaxAgeCandidate,
} from "./max-age.ts";
import { logNote } from "./notice.ts";
import {
  configNamesProject,
  DEFAULT_ROTATE_CONFIG_PATH,
  loadRotateConfigIfPresent,
  type RotateConfig,
  ruleFor,
} from "./rotate-config.ts";
import { pullVerifiedEnvironmentMetadata, type VerifiedEnvironmentMetadata } from "./values.ts";

/** One flag of the derived view (the received form of api-schema's RotationFlagSchema). */
interface RotationFlagView {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  /**
   * AUDIT_SPEC §3.3's trigger (2026-09-14 ES. `revoke_device` is
   * 2026-09-19 DK K3's device-revocation variant — a mechanical
   * follow of the wire type. The CLI's 5th sweep kind is K4).
   */
  readonly trigger: "remove_member" | "change_role" | "revoke_server" | "revoke_device";
  /** The restore that re-opened a resolved flag (AUDIT_SPEC §4.1-5 / §7 — 2026-09-27 VH). */
  readonly reopenedByVersion?: number;
}

/** Fetches the flag view (the shared entry of display, count reporting, and dismiss-target resolution). */
function fetchRotationFlags(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly RotationFlagView[], CliError> {
  return client.rotation.flags({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.flags),
  );
}

/** Fetches the pending sealed proposals addressed to the caller (member or above — the server filters by scope; PF7b). */
export function fetchRotationProposals(
  client: MaruhiClient,
  projectId: string,
): Effect.Effect<readonly RotationProposal[], CliError> {
  return client.rotation.proposals({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.proposals),
  );
}

/** The variable-name resolution result (only verified-statement-derived — unresolvable = null). */
export type NameIndex = ReadonlyMap<string, string>;

/** One variable's verified state: its display name, and whether its live statement is a tombstone. */
export interface VariableState {
  readonly name: string;
  readonly deleted: boolean;
}

export type StateIndex = ReadonlyMap<string, VariableState>;

/**
 * For each environment appearing in the list, fetches the verified
 * metadata (active + tombstone) and builds a variableId → state index. An
 * environment whose fetch/verification fails (a verified deletion etc.)
 * has no index = degrades to identifier display (with a warning — the
 * display is SHOULD and does not stop the listing itself).
 */
/** One environment's verified metadata, or null with a note (the display is SHOULD — a failure never stops the listing). */
function verifiedMetadataOrNote(
  context: ProjectContextBase,
  environmentId: string,
  consequence: string,
): Effect.Effect<VerifiedEnvironmentMetadata | null, never, CliServices> {
  return Effect.gen(function* () {
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return yield* pullVerifiedEnvironmentMetadata({
      client: context.client,
      verified: context.verified,
      environmentId,
      resync: context.resync,
      floor: floorHandle,
    });
  }).pipe(
    Effect.catch((error) =>
      Effect.gen(function* () {
        yield* logNote(
          `could not fetch verified metadata for environment ${displayText(environmentId)} (${error.message}) — ${consequence}`,
        );
        return null;
      }),
    ),
  );
}

export function resolveVariableStates(
  context: ProjectContextBase,
  environmentIds: readonly string[],
): Effect.Effect<ReadonlyMap<string, StateIndex>, never, CliServices> {
  return Effect.gen(function* () {
    const byEnvironment = new Map<string, StateIndex>();
    for (const environmentId of environmentIds) {
      const metadata = yield* verifiedMetadataOrNote(
        context,
        environmentId,
        "variables are shown by identifier only",
      );
      if (metadata === null) {
        continue;
      }
      const states = new Map<string, VariableState>();
      for (const statement of metadata.variables) {
        states.set(statement.variableId, { name: statement.name, deleted: false });
      }
      for (const tombstone of metadata.tombstones) {
        states.set(tombstone.variableId, { name: tombstone.name, deleted: true });
      }
      byEnvironment.set(environmentId, states);
    }
    return byEnvironment;
  });
}

/**
 * The values whose schema declares a max age (layout v3 — CRYPTO_SPEC §4.2)
 * and whose latest push is past it, or within `windowDays` of it (PF6 R9 /
 * PF7a — max-age.ts). The max age comes from the verified statements; the
 * push time is the history's server-declared `pushedAtMs` (advisory). A
 * declared variable with no value has no age.
 */
function expiringValues(
  context: ProjectContextBase,
  nowMs: number,
  windowDays: number,
): Effect.Effect<DueRows, never, CliServices> {
  return Effect.gen(function* () {
    const rows: DueRow[] = [];
    const unreadable: string[] = [];
    for (const environmentId of [...context.verified.state.environments.keys()].toSorted()) {
      const metadata = yield* verifiedMetadataOrNote(
        context,
        environmentId,
        "its expiring values are not listed",
      );
      if (metadata === null) {
        continue;
      }
      const candidates: MaxAgeCandidate[] = [];
      for (const statement of metadata.variables) {
        const maxAgeDays = statement.schema?.maxAgeDays ?? null;
        if (maxAgeDays !== null && statement.status === "active") {
          candidates.push({ variableId: statement.variableId, name: statement.name, maxAgeDays });
        }
      }
      const due = yield* dueRowsFor({
        client: context.client,
        projectId: context.projectId,
        environmentId,
        candidates,
        nowMs,
        windowDays,
      });
      rows.push(...due.rows);
      unreadable.push(...due.unreadable.map((name) => `${environmentId}/${name}`));
    }
    return {
      rows: rows.toSorted((a, b) => a.dueAtMs - b.dueAtMs || a.name.localeCompare(b.name)),
      unreadable,
    };
  });
}

/** Prints the expiring values (nothing when none — the section exists only when there is something to do). Returns the rows for `--fail-on-due`. */
function reportExpiringValues(
  context: ProjectContextBase,
  config: RotateConfig | null,
  nowMs: number,
  windowDays: number,
): Effect.Effect<DueRows, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const due = yield* expiringValues(context, nowMs, Math.max(windowDays, DUE_SOON_DAYS));
    const { rows } = due;
    if (rows.length === 0) {
      return due;
    }
    const expired = rows.filter((row) => row.dueAtMs <= nowMs).length;
    const soon = rows.length - expired;
    const horizon = Math.max(windowDays, DUE_SOON_DAYS);
    const parts = [
      ...(expired === 0 ? [] : [`${countNoun(expired, "value")} past the declared max age`]),
      ...(soon === 0 ? [] : [`${countNoun(soon, "value")} due within ${horizon} days`]),
    ];
    yield* io.log(
      `Expiring values: ${parts.join(", ")} (the max age is declared with \`maruhi schema set --max-age\`; the push time is server-declared)`,
    );
    for (const row of rows) {
      const next = rotationAction({
        environmentId: row.environmentId,
        variableId: row.variableId,
        state: { name: row.name, deleted: false },
        config,
      });
      yield* io.log(
        `  [${row.dueAtMs <= nowMs ? "expired" : "due"}] ${displayText(row.environmentId)} ${displayText(row.name)}: max age ${row.maxAgeDays}d, pushed ${formatUtcDate(row.pushedAtMs)}, ${describeDue(row, nowMs)} — next: ${next}`,
      );
    }
    return due;
  });
}

/**
 * The variableId → display name index per environment (the name-only view
 * of {@link resolveVariableStates}). Shared with `maruhi audit`'s
 * display-name resolution (same TCB discipline — AUDIT_SPEC §7).
 */
export function resolveNames(
  context: ProjectContextBase,
  environmentIds: readonly string[],
): Effect.Effect<ReadonlyMap<string, NameIndex>, never, CliServices> {
  return Effect.map(resolveVariableStates(context, environmentIds), (byEnvironment) => {
    const names = new Map<string, NameIndex>();
    for (const [environmentId, states] of byEnvironment) {
      names.set(
        environmentId,
        new Map([...states].map(([variableId, state]) => [variableId, state.name])),
      );
    }
    return names;
  });
}

/**
 * The rotation config the checklist consults (PF6 R3): the default path in
 * the working directory, when it exists and names this project. A broken
 * file is a note, never a failure (the checklist is guidance).
 */
function checklistConfig(projectId: string): Effect.Effect<RotateConfig | null, never, CliIo> {
  return loadRotateConfigIfPresent(DEFAULT_ROTATE_CONFIG_PATH).pipe(
    Effect.flatMap((config) =>
      Effect.gen(function* () {
        if (config === null) {
          return null;
        }
        if (!configNamesProject(config, projectId)) {
          yield* logNote(
            `the rotation config ${displayText(DEFAULT_ROTATE_CONFIG_PATH)} belongs to a different project, so it was not consulted`,
          );
          return null;
        }
        return config;
      }),
    ),
    Effect.catch((error) =>
      Effect.gen(function* () {
        yield* logNote(`${error.message} — the checklist names no connector`);
        return null;
      }),
    ),
  );
}

/**
 * The next action for one flagged pair (PF6 R3 — the concrete form of
 * ADR-0014 decision 3 "human error is guarded by mechanisms"): the exact
 * command when a connector covers the variable, the by-hand route
 * otherwise, and the dismissal for a deleted variable (it cannot be
 * pushed).
 */
export function rotationAction(input: {
  readonly environmentId: string;
  readonly variableId: string;
  readonly state: VariableState | undefined;
  readonly config: RotateConfig | null;
}): string {
  const env = displayText(input.environmentId);
  if (input.state === undefined) {
    return `rotate at the issuer; the variable could not be resolved here — see \`maruhi rotation list\``;
  }
  const name = displayText(input.state.name);
  if (input.state.deleted) {
    return `deleted — rotate at the issuer, then \`maruhi rotation dismiss ${displayText(input.variableId)} --env ${env}\` (a deleted variable cannot be pushed)`;
  }
  const rule = input.config === null ? null : ruleFor(input.config, input.state.name);
  if (rule !== null) {
    return `\`maruhi var rotate ${displayText(rule.primary)} --env ${env}\` (${rule.rule.connector} connector in ${DEFAULT_ROTATE_CONFIG_PATH})`;
  }
  return `rotate at the issuer, then \`maruhi push ${name} --env ${env}\` (runbooks: https://maruhi.app/docs/rotation)`;
}

function describeTarget(flag: RotationFlagView): string {
  if (flag.targetUserId !== undefined) {
    // The change_role variant (demotion / scope shrinking —
    // AUDIT_SPEC §4.1) is not a deletion, so distinguish it by
    // trigger
    const prefix =
      flag.trigger === "change_role"
        ? "member (role/scope changed)"
        : flag.trigger === "revoke_device"
          ? "member (device revoked)"
          : "member";
    return `${prefix}:${displayText(flag.targetUserId)}`;
  }
  if (flag.targetServerKeyFingerprintHex !== undefined) {
    return `server:${flag.targetServerKeyFingerprintHex}`;
  }
  return "unknown";
}

function describeBasis(basis: "read" | "readable"): string {
  return basis === "read" ? "read (confirmed fetch)" : "readable (fetch was possible)";
}

/**
 * The exit code `maruhi rotation list` uses to say "something is due" under
 * `--fail-on-due` / `--fail-on-flags` (PF7a S-B). Distinct from 1 (the check
 * itself failed) so a CI cron can tell a due credential from an outage.
 */
const ROTATION_DUE_EXIT_CODE = 3;

/** The options of `maruhi rotation list` (the fail-on switches are the CI-cron shape — PF7a). */
export interface RotationListOptions {
  readonly nowMs?: number | undefined;
  /** Exit {@link ROTATION_DUE_EXIT_CODE} when a value is past its max age (or within `dueWithinDays` of it). */
  readonly failOnDue?: boolean | undefined;
  /** How many days ahead `--fail-on-due` looks (0 = past due only; the listing always shows the 14-day window). */
  readonly dueWithinDays?: number | undefined;
  /** Exit {@link ROTATION_DUE_EXIT_CODE} when any rotation flag is active. */
  readonly failOnFlags?: boolean | undefined;
  /** Exit {@link ROTATION_DUE_EXIT_CODE} while a sealed proposal minted by a CI job awaits a member (PF7b — A-9). */
  readonly failOnPending?: boolean | undefined;
}

interface VerdictInput {
  readonly options: RotationListOptions;
  readonly flagCount: number;
  readonly due: readonly DueRow[];
  readonly pending: PendingProposals;
  readonly nowMs: number;
}

/** `--fail-on-flags`: the active flags. */
function flagsReason(input: VerdictInput): string | null {
  return input.options.failOnFlags === true && input.flagCount > 0
    ? `${countNoun(input.flagCount, "rotation flag")} active`
    : null;
}

/** `--fail-on-due`: the values past their max age, or due within the window. */
function dueReason(input: VerdictInput): string | null {
  const windowDays = input.options.dueWithinDays ?? 0;
  const dueRows = input.due.filter((row) => row.dueAtMs - input.nowMs <= windowDays * DAY_MS);
  if (input.options.failOnDue !== true || dueRows.length === 0) {
    return null;
  }
  const when =
    windowDays === 0 ? "past the declared max age" : `due within ${countNoun(windowDays, "day")}`;
  return `${countNoun(dueRows.length, "value")} ${when} (${dueRows.map((row) => displayText(row.name)).join(", ")})`;
}

/** `--fail-on-pending`: the sealed proposals awaiting a member (and how many expire within the window). */
function pendingReason(input: VerdictInput): string | null {
  if (input.options.failOnPending !== true || input.pending.count === 0) {
    return null;
  }
  const windowDays = input.options.dueWithinDays ?? 0;
  const expiring = input.pending.expiresAtMs.filter(
    (expiresAtMs) => expiresAtMs - input.nowMs <= windowDays * DAY_MS,
  ).length;
  const soon =
    windowDays > 0 && expiring > 0
      ? ` (${expiring} expiring within ${countNoun(windowDays, "day")})`
      : "";
  return `${countNoun(input.pending.count, "sealed proposal")} awaiting a member${soon}`;
}

/** The fail-on verdict: which switch fired, in the order they are reported. */
function dueVerdict(input: VerdictInput): string | null {
  const reasons = [flagsReason(input), dueReason(input), pendingReason(input)].filter(
    (reason) => reason !== null,
  );
  return reasons.length === 0 ? null : reasons.join("; ");
}

/** What the pending-proposal line found (the count and the expiries — a verdict input of `--fail-on-pending`). */
interface PendingProposals {
  readonly count: number;
  readonly expiresAtMs: readonly number[];
  /** Why the list is unknown (a reader's token, or a failed read) — `--fail-on-pending` cannot pass on it. */
  readonly unknown: string | null;
}

const NO_PENDING: PendingProposals = { count: 0, expiresAtMs: [], unknown: null };

/** `maruhi rotation list`: displays the currently active flags (all members — class 1). */
/**
 * The pending sealed proposals (PF7b — CRYPTO_SPEC §5.3), one line: a
 * member or above sees the count and the command; a reader is never a
 * recipient and asks nothing. A failed read is a note (the listing is
 * SHOULD and does not stop).
 */
function reportPendingProposals(
  context: ProjectContextBase,
): Effect.Effect<PendingProposals, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const self = context.verified.state.members.get(context.session.userId);
    if (self === undefined || self.role === "reader") {
      return { ...NO_PENDING, unknown: "the proposals are listed to members and above only" };
    }
    const proposals = yield* fetchRotationProposals(context.client, context.projectId).pipe(
      Effect.catch((error) =>
        Effect.map(
          logNote(
            `could not read the pending sealed proposals (${error.message}) — they are not shown`,
          ),
          () => error.message,
        ),
      ),
    );
    if (typeof proposals === "string") {
      return { ...NO_PENDING, unknown: `they could not be read (${proposals})` };
    }
    if (proposals.length === 0) {
      return NO_PENDING;
    }
    yield* io.log(
      `Pending sealed proposals: ${countNoun(proposals.length, "proposal")} minted by CI jobs await a member (\`maruhi rotation proposals\` lists them; \`maruhi rotation accept <id>\` pushes one)`,
    );
    return {
      count: proposals.length,
      expiresAtMs: proposals.map((proposal) => proposal.expiresAtMs),
      unknown: null,
    };
  });
}

export function rotationListOp(
  context: ProjectContextBase,
  options: RotationListOptions = {},
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const nowMs = options.nowMs ?? Date.now();
    const windowDays = options.dueWithinDays ?? 0;
    const config = yield* checklistConfig(context.projectId);
    const flags = yield* fetchRotationFlags(context.client, context.projectId);
    // The fail-on verdict closes the listing (after everything was shown)
    const conclude = (due: DueRows, pending: PendingProposals) =>
      Effect.gen(function* () {
        // A check cannot pass on an age it could not read: that is a
        // failed check (exit 1), not "nothing is due" (exit 0) and not
        // "something is due" (exit 3)
        if (options.failOnDue === true && due.unreadable.length > 0) {
          return yield* Effect.fail(
            cliError(
              `Cannot judge --fail-on-due: the history of ${countNoun(due.unreadable.length, "value")} could not be read (${due.unreadable.map(displayText).join(", ")}); the check did not run to completion`,
            ),
          );
        }
        if (options.failOnPending === true && pending.unknown !== null) {
          return yield* Effect.fail(
            cliError(
              `Cannot judge --fail-on-pending: ${pending.unknown}; the check did not run to completion (run it with a member's token)`,
            ),
          );
        }
        const verdict = dueVerdict({
          options,
          flagCount: flags.length,
          due: due.rows,
          pending,
          nowMs,
        });
        if (verdict === null) {
          return 0;
        }
        yield* io.logError(
          `Rotation due (exit ${ROTATION_DUE_EXIT_CODE}): ${verdict}. Rotate and push the new values, or run \`maruhi rotation dismiss\` for a flag you accept`,
        );
        return ROTATION_DUE_EXIT_CODE;
      });
    if (flags.length === 0) {
      yield* io.log("No rotation flags are currently active");
      const due = yield* reportExpiringValues(context, config, nowMs, windowDays);
      const pending = yield* reportPendingProposals(context);
      return yield* conclude(due, pending);
    }
    const environmentIds = [...new Set(flags.map((flag) => flag.environmentId))].toSorted();
    const states = yield* resolveVariableStates(context, environmentIds);
    yield* io.log(
      `Rotation flags: ${countNoun(flags.length, "active flag")} (upstream credential rotation recommended — AUDIT_SPEC §4.1)`,
    );
    for (const environmentId of environmentIds) {
      yield* io.log(`Environment ${displayText(environmentId)}:`);
      const index = states.get(environmentId);
      // Display order is detection time → (for the same time
      // within one sweep) a stable sort by variableId. The audit
      // seq does not go on the wire (AUDIT_SPEC §7 — non-leakage
      // of the ordinal)
      const rows = flags
        .filter((flag) => flag.environmentId === environmentId)
        .toSorted(
          (a, b) =>
            a.recommendedAtMs - b.recommendedAtMs || a.variableId.localeCompare(b.variableId),
        );
      for (const flag of rows) {
        const state = index?.get(flag.variableId);
        const label =
          state === undefined
            ? displayText(flag.variableId)
            : `${displayText(state.name)} (${displayText(flag.variableId)})`;
        // A re-opened flag says why it came back (a rollback restored a
        // value from before the flag — AUDIT_SPEC §4.1-5)
        const reopened =
          flag.reopenedByVersion === undefined
            ? ""
            : `\treopened by the rollback in version ${flag.reopenedByVersion}`;
        yield* io.log(
          `  ${label}\tbasis=${describeBasis(flag.basis)}\ttarget=${describeTarget(flag)}\ttrigger seq=${flag.triggerChainSeq}${reopened}`,
        );
        yield* io.log(
          `    next: ${rotationAction({ environmentId, variableId: flag.variableId, state, config })}`,
        );
      }
    }
    yield* io.log(
      "To resolve: rotate the upstream credential and save the new value with `maruhi push` after the environment's mandated rotation (a value pushed before it is still under a key the former holder has; the re-encryption alone does not resolve a flag, and rolling back to a value they could read re-opens it). For pairs that cannot be pushed (e.g. deleted variables), dismiss the flag with `maruhi rotation dismiss` as an explicit acceptance of risk (admin)",
    );
    const due = yield* reportExpiringValues(context, config, nowMs, windowDays);
    const pending = yield* reportPendingProposals(context);
    return yield* conclude(due, pending);
  });
}

/** The result of dismiss's target resolution. */
interface DismissTargets {
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}

/**
 * `--all`'s target resolution: folds the currently active flags
 * (with `--env`, only that environment) into pairs (multiple
 * flags of the same pair — e.g. re-deletion — count as one
 * pair).
 */
function resolveAllTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly environmentId: string | null;
}): Effect.Effect<DismissTargets, CliError> {
  return Effect.gen(function* () {
    const flags = yield* fetchRotationFlags(input.client, input.projectId);
    const scoped =
      input.environmentId === null
        ? flags
        : flags.filter((flag) => flag.environmentId === input.environmentId);
    const seen = new Set<string>();
    const targets: { environmentId: string; variableId: string }[] = [];
    for (const flag of scoped) {
      const key = `${flag.environmentId} ${flag.variableId}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      targets.push({ environmentId: flag.environmentId, variableId: flag.variableId });
    }
    if (targets.length === 0) {
      return yield* Effect.fail(
        cliError(
          input.environmentId === null
            ? "No rotation flags are currently active (nothing to dismiss)"
            : "No rotation flags are currently active in the specified environment (nothing to dismiss)",
        ),
      );
    }
    return { targets };
  });
}

/** The dismiss request's form (the part settled **without communication** — decided from the arguments alone). */
export type DismissRequest =
  | { readonly kind: "all"; readonly environmentId: string | null }
  | { readonly kind: "single"; readonly environmentId: string; readonly variableId: string };

/**
 * Interprets `maruhi rotation dismiss`'s request. Checks needing
 * no network (a contradiction between `--all` and a variable id,
 * a missing target) fail here — placed after the prior sync, the
 * guidance would hide behind a connection error and waste a
 * round trip.
 */
export function parseDismissRequest(input: {
  readonly all: boolean;
  readonly environmentId: string | null;
  readonly variableId: string | null;
}): Effect.Effect<DismissRequest, CliError> {
  if (input.all) {
    if (input.variableId !== null) {
      return Effect.fail(
        cliError("--all cannot be combined with a variableId (use one or the other)"),
      );
    }
    return Effect.succeed({ kind: "all", environmentId: input.environmentId });
  }
  if (input.environmentId === null || input.variableId === null) {
    return Effect.fail(
      cliError(
        "Specify what to dismiss: `maruhi rotation dismiss <variableId> --env <environmentId>` (or --all for every flag)",
      ),
    );
  }
  return Effect.succeed({
    kind: "single",
    environmentId: input.environmentId,
    variableId: input.variableId,
  });
}

/**
 * `maruhi rotation dismiss`'s target resolution: `--all` is
 * every currently active flag (with `--env`, only that
 * environment); an individual spec is the single pair (--env,
 * variableId).
 */
export function resolveDismissTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly request: DismissRequest;
}): Effect.Effect<DismissTargets, CliError> {
  if (input.request.kind === "all") {
    return resolveAllTargets({
      client: input.client,
      projectId: input.projectId,
      environmentId: input.request.environmentId,
    });
  }
  const { environmentId, variableId } = input.request;
  return Effect.succeed({ targets: [{ environmentId, variableId }] });
}

/** `maruhi rotation dismiss`: executes the withdrawal (admin — the server checks the authority). */
export function rotationDismissOp(input: {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly targets: readonly { readonly environmentId: string; readonly variableId: string }[];
}): Effect.Effect<number, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    yield* input.client.rotation
      .dismiss({ params: { projectId: input.projectId }, payload: { targets: input.targets } })
      .pipe(
        Effect.catch((error) =>
          Effect.fail(
            error instanceof RotationFlagNotFoundError
              ? cliError(
                  `No active flag for variable ${displayText(error.variableId)} in environment ${displayText(error.environmentId)} (the dismissal was aborted as a whole — check the current targets with \`maruhi rotation list\`)`,
                )
              : toCliError(error),
          ),
        ),
      );
    yield* io.log(
      `Dismissed ${countNoun(input.targets.length, "rotation flag")} (rotation.dismissed — recorded in the audit log)`,
    );
    return 0;
  });
}

/** Who lost access (the subject the checklist is about). */
export type ChecklistTarget =
  | {
      readonly kind: "member";
      readonly userId: string;
      /** Only flags of this trigger (a role change / device revocation leaves the member's other flags out). */
      readonly trigger?: RotationFlagView["trigger"] | undefined;
    }
  | { readonly kind: "server"; readonly fingerprintHex: string };

function targetsFlag(target: ChecklistTarget, flag: RotationFlagView): boolean {
  if (target.kind === "server") {
    return flag.targetServerKeyFingerprintHex === target.fingerprintHex;
  }
  return (
    flag.targetUserId === target.userId &&
    (target.trigger === undefined || flag.trigger === target.trigger)
  );
}

/**
 * The checklist at remove / revoke / narrowing completion (PF6 R3 — the
 * leaver checklist; formerly the flag-count report of ruling B2). Lists
 * the currently active flags addressed to the target (the removed user_id
 * / the revoked server-key FP) with the next action per variable: the
 * exact `maruhi var rotate` command when `maruhi.rotate.json` covers it,
 * the by-hand route otherwise. Confirmed fetches come first. A fetch
 * failure does not change the command's outcome (a SHOULD display).
 */
export function reportRotationChecklist(input: {
  readonly context: ProjectContextBase;
  readonly target: ChecklistTarget;
}): Effect.Effect<void, never, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { context } = input;
    const flags = yield* fetchRotationFlags(context.client, context.projectId).pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logNote(
            `failed to fetch rotation flags (${error.message}) — check with \`maruhi rotation list\``,
          );
          return null;
        }),
      ),
    );
    if (flags === null) {
      return;
    }
    const targeted = flags.filter((flag) => targetsFlag(input.target, flag));
    if (targeted.length === 0) {
      return;
    }
    const environmentIds = [...new Set(targeted.map((flag) => flag.environmentId))].toSorted();
    const states = yield* resolveVariableStates(context, environmentIds);
    const config = yield* checklistConfig(context.projectId);
    const who =
      input.target.kind === "server" ? "the revoked server key" : "the party that lost access";
    yield* io.log(
      `Rotation checklist: ${countNoun(targeted.length, "variable")} ${who} could read (encryption cannot revoke already-read values — rotate each upstream credential, AUDIT_SPEC §4.1):`,
    );
    for (const environmentId of environmentIds) {
      const index = states.get(environmentId);
      // Confirmed fetches first (the certain exposure), then by name
      const rows = targeted
        .filter((flag) => flag.environmentId === environmentId)
        .toSorted((a, b) => {
          if (a.basis !== b.basis) {
            return a.basis === "read" ? -1 : 1;
          }
          const nameA = index?.get(a.variableId)?.name ?? a.variableId;
          const nameB = index?.get(b.variableId)?.name ?? b.variableId;
          return nameA.localeCompare(nameB) || a.variableId.localeCompare(b.variableId);
        });
      for (const flag of rows) {
        const state = index?.get(flag.variableId);
        const label = state === undefined ? displayText(flag.variableId) : displayText(state.name);
        yield* io.log(
          `  [${flag.basis === "read" ? "read" : "readable"}] ${displayText(environmentId)} ${label}: ${rotationAction({ environmentId, variableId: flag.variableId, state, config })}`,
        );
      }
    }
    yield* io.log(
      "A fresh value pushed after the environment's rotation resolves a flag; `maruhi rotation list` shows what remains",
    );
  });
}
