import type { RotationProposal } from "@maruhi/api-schema";
import { type EnvironmentId, type ProjectId, type UserId, type VariableId } from "@maruhi/core";
import { Clock, Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { CliServices } from "../cli.ts";
import {
  configNamesProject,
  DEFAULT_ROTATE_CONFIG_PATH,
  loadRotateConfigIfPresent,
  type RotateConfig,
  ruleFor,
} from "../connector.package/index.ts";
import type { ProjectContextBase } from "../context.ts";
import { floorHandleFor } from "../context.ts";
import { chainDeletedEnvironments, chainEnvironmentIds } from "../deks.ts";
import { countNoun, displayText, formatUtcDate } from "../display.ts";
import { cliError, type CliError, evidenceError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import {
  DAY_MS,
  describeDue,
  DUE_SOON_DAYS,
  type DueRow,
  type DueRows,
  dueRowsFor,
  type MaxAgeCandidate,
} from "../max-age.ts";
import { logNote } from "../notice.ts";
import { pullVerifiedEnvironmentMetadata, type VerifiedEnvironmentMetadata } from "../values.ts";

interface RotationFlagView {
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly basis: "read" | "readable";
  readonly targetUserId?: UserId;
  readonly targetServerKeyFingerprintHex?: string;
  readonly recommendedAtMs: number;
  readonly triggerChainSeq: number;
  readonly trigger: "remove_member" | "change_role" | "revoke_server" | "revoke_device";
  readonly reopenedByVersion?: number;
}

function fetchRotationFlags(
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.Effect<readonly RotationFlagView[], CliError> {
  return client.rotation.flags({ params: { projectId } }).pipe(
    Effect.mapError(toCliError),
    Effect.map((response) =>
      response.flags.map((flag) => {
        const { targetUserId, ...rest } = flag;
        return {
          ...rest,
          ...(targetUserId === undefined ? {} : { targetUserId }),
        };
      }),
    ),
  );
}

export function flaggedVariablesOf(
  client: MaruhiClient,
  projectId: ProjectId,
  environmentId: EnvironmentId,
): Effect.Effect<ReadonlySet<string>, CliError> {
  return Effect.map(
    fetchRotationFlags(client, projectId),
    (flags) =>
      new Set(
        flags.filter((flag) => flag.environmentId === environmentId).map((flag) => flag.variableId),
      ),
  );
}

export const fetchRotationProposals = Effect.fn("rotation.fetchRotationProposals")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<readonly RotationProposal[], CliError> {
  const { proposals } = yield* context.client.rotation
    .proposals({ params: { projectId: context.projectId } })
    .pipe(Effect.mapError(toCliError));
  for (const proposal of proposals) {
    const deletedAtSeq =
      context.verified.state.environments.get(proposal.environmentId)?.deletedAtSeq ?? null;
    if (deletedAtSeq !== null) {
      return yield* Effect.fail(
        evidenceError(
          `The server listed sealed proposal ${proposal.proposalId} for environment ${displayText(proposal.environmentId)}, which is deleted on the verified chain (delete_environment at seq ${deletedAtSeq}) — an unauthorized resurrection (a deleted environment's proposals are deleted with it). No proposal was opened or resolved`,
        ),
      );
    }
  }
  return proposals;
});

export type NameIndex = ReadonlyMap<string, string>;

export interface VariableState {
  readonly name: string;
  readonly deleted: boolean;
}

export type StateIndex = ReadonlyMap<string, VariableState>;

const verifiedMetadataOrNote: (
  context: ProjectContextBase,
  environmentId: EnvironmentId,
  consequence: string,
) => Effect.Effect<VerifiedEnvironmentMetadata | null, never, CliServices> = Effect.fn(
  "rotation.verifiedMetadataOrNote",
)(
  function* (context: ProjectContextBase, environmentId: EnvironmentId, _consequence: string) {
    const floorHandle = yield* floorHandleFor(context, environmentId);
    return yield* pullVerifiedEnvironmentMetadata({
      client: context.client,
      verified: context.verified,
      environmentId,
      resync: context.resync,
      floor: floorHandle,
    });
  },
  (effect, context, environmentId, consequence) =>
    effect.pipe(
      Effect.catch((error) =>
        Effect.gen(function* () {
          yield* logNote(
            `could not fetch verified metadata for environment ${displayText(environmentId)} (${error.message}) — ${consequence}`,
          );
          return null;
        }),
      ),
    ),
);

export const resolveVariableStates = Effect.fn("rotation.resolveVariableStates")(function* (
  context: ProjectContextBase,
  environmentIds: readonly EnvironmentId[],
): Effect.fn.Return<ReadonlyMap<string, StateIndex>, never, CliServices> {
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

function environmentsToWalk(context: ProjectContextBase): readonly EnvironmentId[] {
  const deleted = chainDeletedEnvironments(context.verified);
  return chainEnvironmentIds(context.verified)
    .toSorted()
    .filter((environmentId) => !deleted.has(environmentId));
}

const expiringValues = Effect.fn("rotation.expiringValues")(function* (
  context: ProjectContextBase,
  nowMs: number,
  windowDays: number,
): Effect.fn.Return<DueRows, never, CliServices> {
  const rows: DueRow[] = [];
  const unreadable: string[] = [];
  const unreadableEnvironments: string[] = [];
  for (const environmentId of environmentsToWalk(context)) {
    const metadata = yield* verifiedMetadataOrNote(
      context,
      environmentId,
      "its expiring values are not listed",
    );
    if (metadata === null) {
      unreadableEnvironments.push(environmentId);
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
    unreadableEnvironments,
  };
});

const reportExpiringValues = Effect.fn("rotation.reportExpiringValues")(function* (
  context: ProjectContextBase,
  config: RotateConfig | null,
  nowMs: number,
  windowDays: number,
): Effect.fn.Return<DueRows, never, CliServices> {
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

export function resolveNames(
  context: ProjectContextBase,
  environmentIds: readonly EnvironmentId[],
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

function checklistConfig(projectId: ProjectId): Effect.Effect<RotateConfig | null, never, CliIo> {
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

export function rotationAction(input: {
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
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

const ROTATION_DUE_EXIT_CODE = 3;

interface RotationListOptions {
  readonly failOnDue?: boolean | undefined;
  readonly dueWithinDays?: number | undefined;
  readonly failOnFlags?: boolean | undefined;
  readonly failOnPending?: boolean | undefined;
}

interface VerdictInput {
  readonly options: RotationListOptions;
  readonly flagCount: number | null;
  readonly due: readonly DueRow[];
  readonly pending: PendingProposals;
  readonly nowMs: number;
}

function flagsReason(input: VerdictInput): string | null {
  return input.options.failOnFlags === true && input.flagCount !== null && input.flagCount > 0
    ? `${countNoun(input.flagCount, "rotation flag")} active`
    : null;
}

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

function dueVerdict(input: VerdictInput): string | null {
  const reasons = [flagsReason(input), dueReason(input), pendingReason(input)].filter(
    (reason) => reason !== null,
  );
  return reasons.length === 0 ? null : reasons.join("; ");
}

interface PendingProposals {
  readonly count: number;
  readonly expiresAtMs: readonly number[];
  readonly unknown: string | null;
}

const NO_PENDING: PendingProposals = { count: 0, expiresAtMs: [], unknown: null };

const reportPendingProposals = Effect.fn("rotation.reportPendingProposals")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<PendingProposals, never, CliServices> {
  const io = yield* CliIo;
  const self = context.verified.state.members.get(context.session.userId);
  if (self === undefined || self.role === "reader") {
    return {
      ...NO_PENDING,
      unknown: "the proposals are listed to members and above only (run it with a member's token)",
    };
  }
  const partial =
    self.scope.kind === "all"
      ? null
      : `only the environments in your scope are listed (${self.scope.environmentIds.map(displayText).join(", ")}); run it with a member whose scope covers every environment`;
  const proposals = yield* fetchRotationProposals(context).pipe(
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
    return { ...NO_PENDING, unknown: partial };
  }
  yield* io.log(
    `Pending sealed proposals: ${countNoun(proposals.length, "proposal")} minted by CI jobs await a member (\`maruhi rotation proposals\` lists them; \`maruhi rotation accept <id>\` pushes one)`,
  );
  return {
    count: proposals.length,
    expiresAtMs: proposals.map((proposal) => proposal.expiresAtMs),
    unknown: partial,
  };
});

function unknownParts(
  options: RotationListOptions,
  due: DueRows,
  pending: PendingProposals,
  flags: readonly unknown[] | string,
): readonly string[] {
  return [
    ...(options.failOnFlags === true && typeof flags === "string"
      ? [`the rotation flags could not be read (${flags})`]
      : []),
    ...(options.failOnDue === true ? dueUnknownParts(due) : []),
    ...(options.failOnPending === true && pending.unknown !== null
      ? [`the pending proposals are unknown: ${pending.unknown}`]
      : []),
  ];
}

function dueUnknownParts(due: DueRows): readonly string[] {
  return [
    ...(due.unreadable.length === 0
      ? []
      : [
          `the history of ${countNoun(due.unreadable.length, "value")} could not be read (${due.unreadable.map(displayText).join(", ")})`,
        ]),
    ...(due.unreadableEnvironments.length === 0
      ? []
      : [
          `the expiring values of ${countNoun(due.unreadableEnvironments.length, "environment")} could not be listed (${due.unreadableEnvironments.map(displayText).join(", ")})`,
        ]),
  ];
}

const concludeListing = Effect.fn("rotation.concludeListing")(function* (input: {
  readonly options: RotationListOptions;
  readonly flags: readonly unknown[] | string;
  readonly nowMs: number;
  readonly due: DueRows;
  readonly pending: PendingProposals;
}): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  const { options, flags, due, pending } = input;
  const unknown = unknownParts(options, due, pending, flags);
  const verdict = dueVerdict({
    options,
    flagCount: typeof flags === "string" ? null : flags.length,
    due: due.rows,
    pending,
    nowMs: input.nowMs,
  });
  if (verdict !== null) {
    yield* io.logError(
      `Rotation due (exit ${ROTATION_DUE_EXIT_CODE}): ${verdict}${unknown.length === 0 ? "" : `; also ${unknown.join("; ")}`}. Rotate and push the new values, or run \`maruhi rotation dismiss\` for a flag you accept`,
    );
    return ROTATION_DUE_EXIT_CODE;
  }
  if (unknown.length > 0) {
    return yield* Effect.fail(
      cliError(`Cannot judge the check: ${unknown.join("; ")}; it did not run to completion`),
    );
  }
  return 0;
});

const printFlagRows = Effect.fn("rotation.printFlagRows")(function* (input: {
  readonly flags: readonly RotationFlagView[];
  readonly environmentIds: readonly EnvironmentId[];
  readonly states: ReadonlyMap<string, StateIndex>;
  readonly config: RotateConfig | null;
}): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  for (const environmentId of input.environmentIds) {
    yield* io.log(`Environment ${displayText(environmentId)}:`);
    const index = input.states.get(environmentId);
    const rows = input.flags
      .filter((flag) => flag.environmentId === environmentId)
      .toSorted(
        (a, b) => a.recommendedAtMs - b.recommendedAtMs || a.variableId.localeCompare(b.variableId),
      );
    for (const flag of rows) {
      const state = index?.get(flag.variableId);
      const label =
        state === undefined
          ? displayText(flag.variableId)
          : `${displayText(state.name)} (${displayText(flag.variableId)})`;
      const reopened =
        flag.reopenedByVersion === undefined
          ? ""
          : `\treopened by the rollback in version ${flag.reopenedByVersion}`;
      yield* io.log(
        `  ${label}\tbasis=${describeBasis(flag.basis)}\ttarget=${describeTarget(flag)}\ttrigger seq=${flag.triggerChainSeq}${reopened}`,
      );
      yield* io.log(
        `    next: ${rotationAction({ environmentId, variableId: flag.variableId, state, config: input.config })}`,
      );
    }
  }
});

export const rotationListOp = Effect.fn("rotation.rotationListOp")(function* (
  context: ProjectContextBase,
  options: RotationListOptions = {},
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const nowMs = yield* Clock.currentTimeMillis;
  const windowDays = options.dueWithinDays ?? 0;
  const config = yield* checklistConfig(context.projectId);
  const flags = yield* fetchRotationFlags(context.client, context.projectId).pipe(
    Effect.catch((error) =>
      Effect.as(
        logNote(`could not read the rotation flags (${error.message}) — they are not shown`),
        error.message,
      ),
    ),
  );
  const conclude = (due: DueRows, pending: PendingProposals) =>
    concludeListing({ options, flags, nowMs, due, pending });
  if (typeof flags === "string" || flags.length === 0) {
    if (typeof flags !== "string") {
      yield* io.log("No rotation flags are currently active");
    }
    const due = yield* reportExpiringValues(context, config, nowMs, windowDays);
    const pending = yield* reportPendingProposals(context);
    return yield* conclude(due, pending);
  }
  const environmentIds = [...new Set(flags.map((flag) => flag.environmentId))].toSorted();
  const states = yield* resolveVariableStates(context, environmentIds);
  yield* io.log(
    `Rotation flags: ${countNoun(flags.length, "active flag")} (upstream credential rotation recommended — AUDIT_SPEC §4.1)`,
  );
  yield* printFlagRows({ flags, environmentIds, states, config });
  yield* io.log(
    "To resolve: rotate the upstream credential and save the new value with `maruhi push` after the environment's mandated rotation (a value pushed before it is still under a key the former holder has; the re-encryption alone does not resolve a flag, and rolling back to a value they could read re-opens it). For pairs that cannot be pushed (e.g. deleted variables), dismiss the flag with `maruhi rotation dismiss` as an explicit acceptance of risk (admin)",
  );
  const due = yield* reportExpiringValues(context, config, nowMs, windowDays);
  const pending = yield* reportPendingProposals(context);
  return yield* conclude(due, pending);
});

interface DismissTargets {
  readonly targets: readonly {
    readonly environmentId: EnvironmentId;
    readonly variableId: VariableId;
  }[];
}

const resolveAllTargets = Effect.fn("rotation.resolveAllTargets")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId | null;
}): Effect.fn.Return<DismissTargets, CliError> {
  const flags = yield* fetchRotationFlags(input.client, input.projectId);
  const scoped =
    input.environmentId === null
      ? flags
      : flags.filter((flag) => flag.environmentId === input.environmentId);
  const seen = new Set<string>();
  const targets: { environmentId: EnvironmentId; variableId: VariableId }[] = [];
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

export type DismissRequest =
  | { readonly kind: "all"; readonly environmentId: EnvironmentId | null }
  | {
      readonly kind: "single";
      readonly environmentId: EnvironmentId;
      readonly variableId: VariableId;
    };

export function parseDismissRequest(input: {
  readonly all: boolean;
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
}): Effect.Effect<DismissRequest, CliError> {
  if (input.all) {
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

export function resolveDismissTargets(input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
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

export const rotationDismissOp = Effect.fn("rotation.rotationDismissOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly targets: readonly {
    readonly environmentId: EnvironmentId;
    readonly variableId: VariableId;
  }[];
}): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  yield* input.client.rotation
    .dismiss({ params: { projectId: input.projectId }, payload: { targets: input.targets } })
    .pipe(
      Effect.catchTag(
        "RotationFlagNotFound",
        (error) =>
          Effect.fail(
            cliError(
              `No active flag for variable ${displayText(error.variableId)} in environment ${displayText(error.environmentId)} (the dismissal was aborted as a whole — check the current targets with \`maruhi rotation list\`)`,
            ),
          ),
        (error) => Effect.fail(toCliError(error)),
      ),
    );
  yield* io.log(
    `Dismissed ${countNoun(input.targets.length, "rotation flag")} (rotation.dismissed — recorded in the audit log)`,
  );
  return 0;
});

type ChecklistTarget =
  | {
      readonly kind: "member";
      readonly userId: UserId;
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

export const reportRotationChecklist = Effect.fn("rotation.reportRotationChecklist")(
  function* (input: {
    readonly context: ProjectContextBase;
    readonly target: ChecklistTarget;
  }): Effect.fn.Return<void, never, CliServices> {
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
  },
);
