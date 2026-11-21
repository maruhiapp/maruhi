import { type EnvironmentId, type UserId } from "@maruhi/core";
import { Clock, Effect, Redacted } from "effect";
import type { HttpClient } from "effect/http";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import type { DekRecipient } from "../deks.ts";
import { countNoun, decodeValueText, displayText, logWarnings } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { type DeclaredVariable, pullVariables, toDeclaredVariables } from "../pull.ts";
import { enforceDeclaredPresence, ProcessRunner } from "../run.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "../values.ts";
import type { SyncTarget, TargetDriver } from "./sync-config.ts";
import {
  buildInvocations,
  checkValueConstraints,
  scrubVendorOutput,
  type SyncWrite,
} from "./sync-exec.ts";
import { runBatch } from "./sync-http-run.ts";
import {
  buildBatches,
  checkIntegrationToken,
  DEFAULT_HTTP_RETRY,
  type HttpRetryPolicy,
  type IntegrationToken,
  resolveOptions,
} from "./sync-http.ts";
import {
  loadReceipt,
  type LoadedReceipt,
  receiptVariableName,
  receiptVersionWarning,
  storeReceipt,
  type SyncReceipt,
} from "./sync-receipt.ts";

type PlanEntry =
  | { readonly action: "add"; readonly name: string; readonly version: number }
  | {
      readonly action: "update";
      readonly name: string;
      readonly version: number;
      readonly previousVersion: number;
    }
  | { readonly action: "unchanged"; readonly name: string; readonly version: number }
  | { readonly action: "delete"; readonly name: string; readonly previousVersion: number }
  | {
      readonly action: "blocked";
      readonly name: string;
      readonly version: number;
      readonly reason: string;
    };

interface SyncPlan {
  readonly entries: readonly PlanEntry[];
  readonly declaredRequired: readonly DeclaredVariable[];
  readonly requiredNotSelected: readonly string[];
}

export interface SourceVariable {
  readonly name: string;
  readonly version: number;
  readonly byteLength: number;
  readonly required: boolean;
}

const GCM_TAG_BYTES = 16;

function byName<T extends { readonly name: string }>(entries: readonly T[]): Map<string, T> {
  return new Map(entries.map((entry) => [entry.name, entry] as const));
}

export function sourceVariablesOf(
  variables: readonly {
    readonly name: string;
    readonly version: number;
    readonly required: boolean;
    readonly value: Redacted.Redacted<Uint8Array>;
  }[],
): readonly SourceVariable[] {
  return variables.map((variable) => ({
    name: variable.name,
    version: variable.version,
    byteLength: Redacted.value(variable.value).byteLength,
    required: variable.required,
  }));
}

function sourceFromVerified(
  variables: VerifiedEnvironmentPull["variables"],
): readonly SourceVariable[] {
  return variables.map((variable) => ({
    name: variable.name,
    version: variable.version,
    byteLength: Math.max(0, variable.ciphertextHex.length / 2 - GCM_TAG_BYTES),
    required: variable.schema?.required ?? false,
  }));
}

export function writesOf(
  variables: readonly { readonly name: string; readonly value: Redacted.Redacted<Uint8Array> }[],
): ReadonlyMap<string, SyncWrite> {
  return byName(variables.map((variable) => ({ name: variable.name, value: variable.value })));
}

function driverLabel(driver: TargetDriver): string {
  return driver.kind === "exec" ? `the ${driver.spec.command} CLI` : driver.spec.label;
}

function selectNames(
  target: SyncTarget,
  source: ReadonlyMap<string, SourceVariable>,
  declared: ReadonlyMap<string, DeclaredVariable>,
): Effect.Effect<readonly string[], CliError> {
  if (target.variables === "all") {
    const excluded = new Set(target.exclude);
    return Effect.succeed([...source.keys()].filter((name) => !excluded.has(name)).toSorted());
  }
  const missing = target.variables.filter((name) => !source.has(name) && !declared.has(name));
  if (missing.length > 0) {
    return Effect.fail(
      cliError(
        `The target lists variables that do not exist in environment ${displayText(target.environment)}: ${missing.map(displayText).join(", ")}. Push them first, or remove them from the target's variables in the sync config`,
      ),
    );
  }
  return Effect.succeed([...target.variables].toSorted());
}

function classifyVariable(
  driver: TargetDriver,
  variable: SourceVariable,
  previousVersion: number | undefined,
): PlanEntry {
  const { name, version } = variable;
  const { constraints } = driver.spec;
  if (constraints.name !== null && !constraints.name.regex.test(name)) {
    return {
      action: "blocked",
      name,
      version,
      reason: `a name ${driverLabel(driver)} cannot store as is: ${constraints.name.rule}`,
    };
  }
  if (constraints.nonEmpty && variable.byteLength === 0) {
    return {
      action: "blocked",
      name,
      version,
      reason: `empty value (${driverLabel(driver)} reads an empty stdin as no value)`,
    };
  }
  if (constraints.maxBytes !== null && variable.byteLength > constraints.maxBytes) {
    return {
      action: "blocked",
      name,
      version,
      reason: `${variable.byteLength} bytes, above the ${constraints.maxBytes}-byte limit for ${driverLabel(driver)}`,
    };
  }
  if (previousVersion === undefined) {
    return { action: "add", name, version };
  }
  if (previousVersion === version) {
    return { action: "unchanged", name, version };
  }
  return { action: "update", name, version, previousVersion };
}

function compareByName(a: { readonly name: string }, b: { readonly name: string }): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

export const computePlan = Effect.fn("sync-plan.computePlan")(function* (input: {
  readonly target: SyncTarget;
  readonly source: readonly SourceVariable[];
  readonly declared: readonly DeclaredVariable[];
  readonly receipt: SyncReceipt | null;
}): Effect.fn.Return<SyncPlan, CliError> {
  const source = byName(input.source);
  const declared = byName(input.declared);
  const selected = yield* selectNames(input.target, source, declared);
  const selectedSet = new Set(selected);
  const previous = input.receipt?.variables ?? {};
  const current = selected.flatMap((name) => {
    const variable = source.get(name);
    if (variable === undefined) {
      return [];
    }
    const previousVersion = Object.hasOwn(previous, name) ? previous[name] : undefined;
    return [classifyVariable(input.target.driver, variable, previousVersion)];
  });
  const deleted = Object.keys(previous)
    .filter((name) => !selectedSet.has(name) || !source.has(name))
    .map((name): PlanEntry => ({
      action: "delete",
      name,
      previousVersion: previous[name] as number,
    }));
  const declaredRequired = selected.flatMap((name) => {
    const statement = declared.get(name);
    return statement !== undefined && statement.required ? [statement] : [];
  });
  const requiredNotSelected = [...source.values()]
    .filter((variable) => variable.required && !selectedSet.has(variable.name))
    .map((variable) => variable.name)
    .toSorted();
  return {
    entries: [...current, ...deleted].toSorted(compareByName),
    declaredRequired,
    requiredNotSelected,
  };
});

function countOf(plan: SyncPlan, action: PlanEntry["action"]): number {
  return plan.entries.filter((entry) => entry.action === action).length;
}

function planLine(entry: PlanEntry): string {
  const name = displayText(entry.name);
  switch (entry.action) {
    case "add":
      return `+ ${name}\tversion ${entry.version} (new)`;
    case "update":
      return `~ ${name}\tversion ${entry.previousVersion} -> ${entry.version}`;
    case "unchanged":
      return `= ${name}\tversion ${entry.version} (unchanged)`;
    case "delete":
      return `- ${name}\t(no longer synced; last delivered version ${entry.previousVersion})`;
    case "blocked":
      return `! ${name}\tversion ${entry.version} (cannot be synced: ${entry.reason})`;
  }
}

function describeDestination(target: SyncTarget): string {
  const shown = target.driver.spec.describeOptions.flatMap((option) => {
    const value = target.options[option];
    return typeof value === "string" ? [displayText(value)] : [];
  });
  return `${[target.preset.id, ...shown].join(" ")} via ${target.driver.kind}`;
}

interface PlanDisplay {
  readonly showUnchanged: boolean;
}

const FULL_PLAN: PlanDisplay = { showUnchanged: true };

const reportPlan = Effect.fn("sync-plan.reportPlan")(function* (
  target: SyncTarget,
  plan: SyncPlan,
  receipt: SyncReceipt | null | "none-in-ci",
  display: PlanDisplay,
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  yield* io.log(
    `Sync plan for target ${displayText(target.name)} (environment ${displayText(target.environment)} -> ${describeDestination(target)}): ${countOf(plan, "add")} to add, ${countOf(plan, "update")} to update, ${countOf(plan, "delete")} to delete, ${countOf(plan, "unchanged")} unchanged, ${countOf(plan, "blocked")} blocked`,
  );
  yield* io.log(
    receipt === "none-in-ci"
      ? "Last delivery: not tracked in CI (no receipt — every selected variable is written again, and nothing is deleted)"
      : receipt === null
        ? "Last delivery: none (no receipt yet — every selected variable is new to this target)"
        : `Last delivery: ${displayText(receipt.syncedAt)} (receipt ${displayText(receiptVariableName(target.name))})`,
  );
  for (const entry of plan.entries) {
    if (entry.action === "unchanged" && !display.showUnchanged) {
      continue;
    }
    yield* io.log(planLine(entry));
  }
});

interface SyncContextInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly target: SyncTarget;
  readonly sourceFloor: FloorHandle;
  readonly receiptsEnvironment: EnvironmentId;
  readonly receiptsFloor: FloorHandle;
}

const loadTargetReceipt = Effect.fn("sync-plan.loadTargetReceipt")(function* (
  input: SyncContextInput,
): Effect.fn.Return<LoadedReceipt, CliError, CliIo> {
  const loaded = yield* loadReceipt({
    client: input.client,
    verified: input.verified,
    environmentId: input.receiptsEnvironment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.receiptsFloor,
    target: input.target.name,
    preset: input.target.preset.id,
  });
  yield* logWarnings(loaded.warnings);
  return loaded;
});

export const reviewPlan = Effect.fn("sync-plan.reviewPlan")(function* (
  target: SyncTarget,
  plan: SyncPlan,
  receipt:
    | {
        readonly kind: "loaded";
        readonly loaded: LoadedReceipt;
        readonly environmentId: EnvironmentId;
      }
    | { readonly kind: "none-in-ci" },
  display: PlanDisplay = FULL_PLAN,
): Effect.fn.Return<void, CliError, CliIo> {
  yield* reportPlan(
    target,
    plan,
    receipt.kind === "none-in-ci" ? "none-in-ci" : receipt.loaded.receipt,
    display,
  );
  if (plan.requiredNotSelected.length > 0) {
    yield* logWarning(
      `required variables are not part of this target: ${plan.requiredNotSelected.map(displayText).join(", ")}. The target's runtime will not receive them (add them to the target's variables in the sync config if it needs them)`,
    );
  }
  yield* enforceDeclaredPresence(plan.declaredRequired, "Nothing was sent");
  if (receipt.kind === "loaded") {
    const warning = receiptVersionWarning({
      target: target.name,
      environmentId: receipt.environmentId,
      variableVersion: receipt.loaded.variableVersion,
    });
    if (warning !== null) {
      yield* logWarning(warning);
    }
  }
  const blocked = plan.entries.filter((entry) => entry.action === "blocked");
  if (blocked.length > 0) {
    return yield* Effect.fail(
      cliError(
        `${countNoun(blocked.length, "variable")} cannot be synced with this driver (marked ! above): ${blocked.map((entry) => displayText(entry.name)).join(", ")}. Leave them out of the target, rename them, or push values ${driverLabel(target.driver)} can carry (each line above says which). Nothing was sent`,
      ),
    );
  }
});

export const syncPlanOp = Effect.fn("sync-plan.syncPlanOp")(function* (
  input: SyncContextInput,
): Effect.fn.Return<void, CliError, CliIo> {
  const loaded = yield* loadTargetReceipt(input);
  const pulled = yield* pullVerifiedEnvironment({
    client: input.client,
    verified: loaded.verified,
    environmentId: input.target.environment,
    resync: input.resync,
    floor: input.sourceFloor,
  });
  yield* logWarnings(pulled.warnings);
  const source = sourceFromVerified(pulled.variables);
  const plan = yield* computePlan({
    target: input.target,
    source,
    declared: toDeclaredVariables(pulled.declared),
    receipt: loaded.receipt,
  });
  yield* reviewPlan(input.target, plan, {
    kind: "loaded",
    loaded,
    environmentId: input.receiptsEnvironment,
  });
  if (input.target.production) {
    yield* logNote(
      `target ${displayText(input.target.name)} is a production target: \`maruhi sync apply ${displayText(input.target.name)}\` needs --yes`,
    );
  }
});

interface SyncApplyInput extends SyncContextInput {
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
  readonly yes: boolean;
  readonly tokenFloor: FloorHandle | null;
  readonly httpRetry?: HttpRetryPolicy;
  readonly display?: PlanDisplay;
}

interface ApplyWork {
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
  readonly versions: ReadonlyMap<string, number>;
}

export const prepareWork = Effect.fn("sync-plan.prepareWork")(function* (
  target: SyncTarget,
  plan: SyncPlan,
  values: ReadonlyMap<string, SyncWrite>,
): Effect.fn.Return<ApplyWork, CliError> {
  const writes: SyncWrite[] = [];
  const versions = new Map<string, number>();
  for (const entry of plan.entries) {
    if (entry.action !== "add" && entry.action !== "update") {
      continue;
    }
    const write = values.get(entry.name);
    if (write === undefined) {
      return yield* Effect.fail(
        cliError("The plan names a variable that was not pulled (internal inconsistency)"),
      );
    }
    const plaintext = Redacted.value(write.value);
    if (decodeValueText(plaintext) === null) {
      return yield* Effect.fail(
        cliError(
          `The value of variable ${displayText(write.name)} is not valid UTF-8 (${driverLabel(target.driver)} takes text). Nothing was sent`,
        ),
      );
    }
    const problem = checkValueConstraints(
      { constraints: target.driver.spec.constraints, label: driverLabel(target.driver) },
      write.name,
      plaintext,
    );
    if (problem !== null) {
      return yield* Effect.fail(cliError(`${problem.message}. Nothing was sent`));
    }
    writes.push(write);
    versions.set(entry.name, entry.version);
  }
  const deletes = plan.entries.flatMap((entry) => (entry.action === "delete" ? [entry.name] : []));
  return { writes, deletes, versions };
});

interface DriverResult {
  readonly written: readonly string[];
  readonly deleted: readonly string[];
  readonly failure: {
    readonly names: readonly string[];
    readonly kind: "write" | "delete";
    readonly what: string;
    readonly detail: string | null;
    readonly output: readonly string[];
  } | null;
}

const runInvocations = Effect.fn("sync-plan.runInvocations")(function* (
  driver: Extract<TargetDriver, { kind: "exec" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
): Effect.fn.Return<DriverResult, never, ProcessRunner> {
  const runner = yield* ProcessRunner;
  const invocations = buildInvocations({
    preset: driver.spec,
    command: driver.command,
    cwd: driver.cwd,
    options,
    writes: work.writes,
    deletes: work.deletes,
  });
  const written: string[] = [];
  const deleted: string[] = [];
  const deleteSet = new Set(work.deletes);
  for (const invocation of invocations) {
    const outcome = yield* runner
      .exec(invocation)
      .pipe(Effect.catch((error: CliError) => Effect.succeed({ startFailure: error.message })));
    if ("startFailure" in outcome) {
      return {
        written,
        deleted,
        failure: {
          names: invocation.names,
          kind: invocation.kind,
          what: `${displayText(driver.command)} could not be started`,
          detail: displayText(outcome.startFailure),
          output: [],
        },
      };
    }
    if (outcome.exitCode !== 0) {
      return {
        written,
        deleted,
        failure: {
          names: invocation.names,
          kind: invocation.kind,
          what: `${displayText(driver.command)} exited with code ${outcome.exitCode}`,
          detail: null,
          output: scrubVendorOutput(outcome.output, work.writes),
        },
      };
    }
    for (const name of invocation.names) {
      (deleteSet.has(name) ? deleted : written).push(name);
    }
  }
  return { written, deleted, failure: null };
});

const runBatches = Effect.fn("sync-plan.runBatches")(function* (
  driver: Extract<TargetDriver, { kind: "http" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
  token: IntegrationToken,
  retry: HttpRetryPolicy,
): Effect.fn.Return<DriverResult, CliError, HttpClient.HttpClient> {
  const batches = buildBatches({
    preset: driver.spec,
    writes: work.writes,
    deletes: work.deletes,
  });
  const target = {
    preset: driver.spec,
    options: resolveOptions(driver.spec, options),
    token,
    retry,
  };
  const written: string[] = [];
  const deleted: string[] = [];
  const deleteSet = new Set(work.deletes);
  for (const batch of batches) {
    const result = yield* runBatch(target, batch);
    for (const name of result.delivered) {
      (deleteSet.has(name) ? deleted : written).push(name);
    }
    if (result.failure !== null) {
      return {
        written,
        deleted,
        failure: {
          names: result.failure.names,
          kind: batch.kind,
          what: result.failure.what,
          detail: null,
          output: result.failure.lines,
        },
      };
    }
  }
  return { written, deleted, failure: null };
});

interface RunDriverInput {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  readonly token: IntegrationToken | null;
  readonly httpRetry: HttpRetryPolicy;
}

export const runDriver = Effect.fn("sync-plan.runDriver")(function* (
  input: RunDriverInput,
): Effect.fn.Return<DriverResult, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const { driver } = input.target;
  if (driver.kind === "exec") {
    yield* io.log(`Running ${displayText(driver.command)} in ${displayText(driver.cwd)}`);
    return yield* runInvocations(driver, input.target.options, input.work);
  }
  if (input.token === null) {
    return yield* Effect.fail(
      cliError("The http driver needs the integration token (internal inconsistency)"),
    );
  }
  yield* io.log(
    `Sending to ${driver.spec.host} with the token from variable ${displayText(driver.token.name)} in environment ${displayText(driver.token.environment)}`,
  );
  return yield* runBatches(driver, input.target.options, input.work, input.token, input.httpRetry);
});

export function integrationTokenOf(
  token: { readonly environment: EnvironmentId; readonly name: string },
  variables: readonly { readonly name: string; readonly value: Redacted.Redacted<Uint8Array> }[],
): Effect.Effect<IntegrationToken, CliError> {
  const variable = variables.find((entry) => entry.name === token.name);
  if (variable === undefined) {
    return Effect.fail(
      cliError(
        `The token variable ${displayText(token.name)} does not exist in environment ${displayText(token.environment)}. Push the vendor's token there with \`maruhi push ${displayText(token.name)} --env ${displayText(token.environment)}\` (the token on stdin, without a trailing newline), or fix the target's token in the sync config`,
      ),
    );
  }
  const checked = checkIntegrationToken(token.name, Redacted.value(variable.value));
  return typeof checked === "string"
    ? Effect.succeed(Redacted.make(checked, { label: "integration-token" }))
    : Effect.fail(checked);
}

const fetchIntegrationToken = Effect.fn("sync-plan.fetchIntegrationToken")(function* (
  input: SyncApplyInput,
  driver: Extract<TargetDriver, { kind: "http" }>,
  verified: VerifiedProject,
): Effect.fn.Return<
  { readonly token: IntegrationToken; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  if (input.tokenFloor === null) {
    return yield* Effect.fail(
      cliError("No floor handle for the token environment (internal inconsistency)"),
    );
  }
  const pulled = yield* pullVariables({
    client: input.client,
    verified,
    environmentId: driver.token.environment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.tokenFloor,
    select: (name) => name === driver.token.name,
  });
  yield* logWarnings(pulled.warnings);
  const token = yield* integrationTokenOf(driver.token, pulled.variables);
  return { token, verified: pulled.verified };
});

function nextReceipt(input: {
  readonly target: SyncTarget;
  readonly previous: SyncReceipt | null;
  readonly result: DriverResult;
  readonly versions: ReadonlyMap<string, number>;
  readonly syncedAt: string;
}): SyncReceipt {
  const variables: Record<string, number> = Object.assign(
    Object.create(null) as Record<string, number>,
    input.previous?.variables ?? {},
  );
  for (const name of input.result.deleted) {
    delete variables[name];
  }
  for (const name of input.result.written) {
    variables[name] = input.versions.get(name) as number;
  }
  return {
    version: 1,
    target: input.target.name,
    preset: input.target.preset.id,
    syncedAt: input.syncedAt,
    variables,
  };
}

function sameVariables(a: SyncReceipt | null, b: SyncReceipt): boolean {
  if (a === null) {
    return Object.keys(b.variables).length === 0;
  }
  const left = Object.entries(a.variables).toSorted();
  const right = Object.entries(b.variables).toSorted();
  return JSON.stringify(left) === JSON.stringify(right);
}

function saveReceipt(
  input: SyncApplyInput,
  loaded: LoadedReceipt,
  receipt: SyncReceipt,
): Effect.Effect<number | null, never, CliIo> {
  if (sameVariables(loaded.receipt, receipt)) {
    return Effect.succeed(null);
  }
  return storeReceipt({
    client: input.client,
    verified: loaded.verified,
    environmentId: input.receiptsEnvironment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.receiptsFloor,
    writerUserId: input.writerUserId,
    signingKey: input.signingKey,
    receipt,
  }).pipe(
    Effect.flatMap((stored) => Effect.as(logWarnings(stored.warnings), stored.version)),
    Effect.catch((error: CliError) =>
      Effect.as(
        logWarning(
          `the target was updated, but the receipt could not be saved (${error.message}). The next \`maruhi sync plan\` will show the delivered variables as pending; applying again overwrites them with the same versions`,
        ),
        null,
      ),
    ),
  );
}

function driverFailureMessage(
  input: {
    readonly target: SyncTarget;
    readonly work: ApplyWork;
    readonly receiptsEnvironment: string | null;
    readonly next: string;
  },
  result: DriverResult,
  failure: NonNullable<DriverResult["failure"]>,
): string {
  const failed = new Set(failure.names);
  const notAttempted = input.work.deletes.filter(
    (name) => !result.deleted.includes(name) && !failed.has(name),
  );
  const pendingHint =
    notAttempted.length === 0
      ? ""
      : ` Resetting the receipt also forgets the deletions not attempted yet, so remove these at the target yourself first: ${notAttempted.map(displayText).join(", ")}.`;
  const deleteHint =
    failure.kind === "delete" && input.receiptsEnvironment !== null
      ? ` If the variable was already removed at the target (for example in its dashboard), reset the receipt with \`maruhi var rm ${displayText(receiptVariableName(input.target.name))} --env ${displayText(input.receiptsEnvironment)}\` and apply again (the next apply rewrites every variable of the target once).${pendingHint}`
      : "";
  const outputHint =
    failure.output.length === 0 ? "" : " Its output is shown above with values filtered out.";
  const detail = failure.detail === null ? "" : ` ${failure.detail}.`;
  return `${failure.what} while ${failure.kind === "write" ? "writing" : "deleting"} ${failure.names.map(displayText).join(", ")} (delivered before that: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted).${detail}${outputHint}${deleteHint} Fix the cause, then ${input.next}`;
}

export const failDriver = Effect.fn("sync-plan.failDriver")(function* (input: {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  readonly result: DriverResult;
  readonly receiptsEnvironment: string | null;
  readonly next: string;
}): Effect.fn.Return<never, CliError, CliIo> {
  const io = yield* CliIo;
  const { target, result } = input;
  if (result.failure === null) {
    return yield* Effect.fail(
      cliError("failDriver called without a failure (internal inconsistency)"),
    );
  }
  const prefix = target.driver.kind === "exec" ? target.driver.command : target.driver.spec.host;
  for (const line of result.failure.output) {
    yield* io.logError(`  ${displayText(prefix)}: ${line}`);
  }
  return yield* Effect.fail(cliError(driverFailureMessage(input, result, result.failure)));
});

const reportApply = Effect.fn("sync-plan.reportApply")(function* (
  input: SyncApplyInput,
  work: ApplyWork,
  result: DriverResult,
  receiptVersion: number | null,
): Effect.fn.Return<void, CliError, CliIo> {
  const io = yield* CliIo;
  const targetName = displayText(input.target.name);
  if (result.failure !== null) {
    return yield* failDriver({
      target: input.target,
      work,
      result,
      receiptsEnvironment: input.receiptsEnvironment,
      next: `run \`maruhi sync plan ${targetName}\` to see what is left`,
    });
  }
  const saved =
    receiptVersion === null
      ? ""
      : `. Receipt saved as version ${receiptVersion} of ${displayText(receiptVariableName(input.target.name))} in environment ${displayText(input.receiptsEnvironment)}`;
  yield* io.log(
    `Applied to target ${targetName}: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted${saved}`,
  );
});

export function requireProductionConsent(
  target: SyncTarget,
  yes: boolean,
  command: string,
): Effect.Effect<void, CliError> {
  if (target.production && !yes) {
    return Effect.fail(
      cliError(
        `Target ${displayText(target.name)} is a production target, so apply needs an explicit --yes. Review the plan above, then re-run \`${command} ${displayText(target.name)} --yes\`. Nothing was sent`,
      ),
    );
  }
  return Effect.void;
}

export const syncApplyOp = Effect.fn("sync-plan.syncApplyOp")(function* (
  input: SyncApplyInput,
): Effect.fn.Return<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const loaded = yield* loadTargetReceipt(input);
  const meta = yield* pullVerifiedEnvironment({
    client: input.client,
    verified: loaded.verified,
    environmentId: input.target.environment,
    resync: input.resync,
    floor: input.sourceFloor,
  });
  const plan = yield* computePlan({
    target: input.target,
    source: sourceFromVerified(meta.variables),
    declared: toDeclaredVariables(meta.declared),
    receipt: loaded.receipt,
  });
  yield* reviewPlan(
    input.target,
    plan,
    { kind: "loaded", loaded, environmentId: input.receiptsEnvironment },
    input.display ?? FULL_PLAN,
  );
  const writeNames = new Set(
    plan.entries
      .filter((entry) => entry.action === "add" || entry.action === "update")
      .map((entry) => entry.name),
  );
  const pulled = yield* pullVariables({
    client: input.client,
    verified: meta.verified,
    environmentId: input.target.environment,
    recipient: input.recipient,
    resync: input.resync,
    floor: input.sourceFloor,
    select: (name) => writeNames.has(name),
  });
  yield* logWarnings(pulled.warnings);
  const work = yield* prepareWork(input.target, plan, writesOf(pulled.variables));
  if (work.writes.length === 0 && work.deletes.length === 0) {
    yield* io.log(
      "Nothing to apply: the target already has every selected variable at its current version",
    );
    return;
  }
  yield* requireProductionConsent(input.target, input.yes, "maruhi sync apply");
  let verified = pulled.verified;
  let token: IntegrationToken | null = null;
  if (input.target.driver.kind === "http") {
    const fetched = yield* fetchIntegrationToken(input, input.target.driver, verified);
    token = fetched.token;
    verified = fetched.verified;
  }
  const result = yield* runDriver({
    target: input.target,
    work,
    token,
    httpRetry: input.httpRetry ?? DEFAULT_HTTP_RETRY,
  });
  const syncedAtMs = yield* Clock.currentTimeMillis;
  const receipt = nextReceipt({
    target: input.target,
    previous: loaded.receipt,
    result,
    versions: work.versions,
    syncedAt: new Date(syncedAtMs).toISOString(),
  });
  const receiptVersion = yield* saveReceipt(input, { ...loaded, verified }, receipt);
  yield* reportApply(input, work, result, receiptVersion);
});
