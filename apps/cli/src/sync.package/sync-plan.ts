// `maruhi sync plan` / `maruhi sync apply` (the table of "the sync's
// final form" in integration-options.md §3: driver × repository config
// × receipt × plan / apply. The http driver and the receipt-less CI
// path [sync-ci.ts] ride the same core [{@link runDriver}]).
//
// plan = shows "the difference between the receipt (the versions
// delivered last time) and maruhi's current versions" by name and
// version only. The target is **never read back** (one-way —
// ADR-0014. A Vercel sensitive value cannot be read back, so the
// receipt is the only matching material — supplement 13 W2). plan never
// decrypts the source's values (stops at verifying the value signatures
// — values.ts's pullVerifiedEnvironment) and never touches the vendor
// API. apply decrypts (pull.ts), then for the exec driver writes once
// to the vendor CLI's stdin (sync-exec.ts), or for the http driver puts
// them in the vendor API's request body (sync-http.ts). Values never
// appear on stdout / stderr / in an error's wording.
//
// production's default is plan only (supplement 14 M4): apply to a
// target treated as production requires `--yes`. No dedicated gate for
// an agent environment is built (supplement 9 — the same treatment as
// `run`).
//
// Completeness (supplement 14 M5): when a variable declared required
// has no value, stop without carrying anything under the same rule as
// `run`'s presence fail-fast. When a required active variable is left
// out of the target's selection, warn (missing at the destination is a
// contract violation, but choosing what to carry is the config's
// responsibility).

import type { EnvironmentId } from "@maruhi/core";
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

/** One line of a plan. `blocked` = apply would refuse it (reason names only the variable). */
export type PlanEntry =
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

/** A computed plan for one target. */
export interface SyncPlan {
  readonly entries: readonly PlanEntry[];
  /** Selected variables that have only a required declaration and no value (apply carries nothing). */
  readonly declaredRequired: readonly DeclaredVariable[];
  /** Names among the required active variables that fell outside the target's selection (warned). */
  readonly requiredNotSelected: readonly string[];
}

/** One variable of the sync source (plan derives the plaintext length from the ciphertext's length — never decrypts). */
export interface SourceVariable {
  readonly name: string;
  readonly version: number;
  /** The plaintext's byte length (plan = ciphertext length − 16-byte GCM tag, apply = measured). */
  readonly byteLength: number;
  /** The required declaration (layout v1 = false). */
  readonly required: boolean;
}

const GCM_TAG_BYTES = 16;

function byName<T extends { readonly name: string }>(entries: readonly T[]): Map<string, T> {
  return new Map(entries.map((entry) => [entry.name, entry] as const));
}

/** Decrypted variables → plan material (apply / ci sync). The plaintext length is measured. */
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
    // Reason for unwrapping: measuring the plaintext length (the product
    // is only the length). The same value as the plan stage's estimate
    // from the ciphertext length, but apply judges on the byte string it
    // actually sends
    byteLength: Redacted.value(variable.value).byteLength,
    required: variable.required,
  }));
}

/** Verified metadata → plan material. From ciphertext = ct || tag (16
 * bytes), derives only the plaintext length (never decrypts — shared by
 * plan / apply). */
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

/** Decrypted variables → write material indexable by name (the values stay wrapped). */
export function writesOf(
  variables: readonly { readonly name: string; readonly value: Redacted.Redacted<Uint8Array> }[],
): ReadonlyMap<string, SyncWrite> {
  return byName(variables.map((variable) => ({ name: variable.name, value: variable.value })));
}

/** The driver's label for wording ("the vercel CLI" / "the Vercel API"). */
function driverLabel(driver: TargetDriver): string {
  return driver.kind === "exec" ? `the ${driver.spec.command} CLI` : driver.spec.label;
}

/**
 * Resolves which variables the target carries: the explicit list, or every
 * active variable minus `exclude`. Names in an explicit list that exist
 * neither as an active nor as a declared variable are a hard error (the
 * config and the environment disagree — nothing is synced).
 */
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

/** One variable's plan line (the name / size / emptiness constraints here; the content constraints at apply). */
function classifyVariable(
  driver: TargetDriver,
  variable: SourceVariable,
  previousVersion: number | undefined,
): PlanEntry {
  const { name, version } = variable;
  const { constraints } = driver.spec;
  // The name rule needs no plaintext = judgeable in plan (apply's
  // checkValueConstraints remains as the defense line). The reason
  // wording carries only the name and the rule
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

/**
 * Computes the plan: receipt versions vs current versions, names only.
 * `blocked` entries come from the driver's name / size / emptiness
 * constraints (content constraints need the plaintext and are checked at
 * apply). A receipt-only name is a `delete` even when the driver could not
 * store it today: the delete carries no value, and the vendor reports a name
 * it cannot address.
 */
export function computePlan(input: {
  readonly target: SyncTarget;
  readonly source: readonly SourceVariable[];
  readonly declared: readonly DeclaredVariable[];
  readonly receipt: SyncReceipt | null;
}): Effect.Effect<SyncPlan, CliError> {
  return Effect.gen(function* () {
    const source = byName(input.source);
    const declared = byName(input.declared);
    const selected = yield* selectNames(input.target, source, declared);
    const selectedSet = new Set(selected);
    const previous = input.receipt?.variables ?? {};
    // Declared-only (no value) has nothing to carry: when required it is
    // material for enforceDeclaredPresence to stop; when optional it is
    // not put on the plan
    const current = selected.flatMap((name) => {
      const variable = source.get(name);
      if (variable === undefined) {
        return [];
      }
      const previousVersion = Object.hasOwn(previous, name) ? previous[name] : undefined;
      return [classifyVariable(input.target.driver, variable, previousVersion)];
    });
    // Names in the receipt that are no longer carried (left the selection / disappeared from maruhi) = deletes
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
}

function countOf(plan: SyncPlan, action: PlanEntry["action"]): number {
  return plan.entries.filter((entry) => entry.action === action).length;
}

/** Rendering one line (symbol + name + version. A value never lands). */
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

/**
 * The destination's description (for the header line): the preset id,
 * the option values of the "destination's label" the preset declared
 * via `describeOptions` (only the strings that are set, in declaration
 * order), and the driver. Neither values nor secrets land (the
 * declaration has only non-secret option names).
 */
function describeDestination(target: SyncTarget): string {
  const shown = target.driver.spec.describeOptions.flatMap((option) => {
    const value = target.options[option];
    return typeof value === "string" ? [displayText(value)] : [];
  });
  return `${[target.preset.id, ...shown].join(" ")} via ${target.driver.kind}`;
}

/** The choice of plan rendering (the apply right after a push omits the unchanged lines). */
interface PlanDisplay {
  /** Whether the `=` lines are shown (default true. The header's counts always cover all). */
  readonly showUnchanged: boolean;
}

const FULL_PLAN: PlanDisplay = { showUnchanged: true };

/** Prints the plan to stdout (the command's output — names and versions only). */
function reportPlan(
  target: SyncTarget,
  plan: SyncPlan,
  receipt: SyncReceipt | null | "none-in-ci",
  display: PlanDisplay,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
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
}

/** Everything a plan or apply needs from the project context. */
export interface SyncContextInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly recipient: DekRecipient;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly target: SyncTarget;
  readonly sourceFloor: FloorHandle;
  readonly receiptsEnvironment: EnvironmentId;
  readonly receiptsFloor: FloorHandle;
}

/** The prologue shared by plan / apply: read the receipt (warnings flow here). */
function loadTargetReceipt(input: SyncContextInput): Effect.Effect<LoadedReceipt, CliError, CliIo> {
  return Effect.gen(function* () {
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
}

/**
 * The epilogue shared by plan / apply: emits the plan, flows the
 * contract's advisories, warns on the receipt nearing its cap, and
 * fails when even one blocked entry exists (apply sends nothing).
 * CI (no receipt) passes through the same stage with
 * `receipt: "none-in-ci"`.
 */
export function reviewPlan(
  target: SyncTarget,
  plan: SyncPlan,
  receipt:
    | { readonly kind: "loaded"; readonly loaded: LoadedReceipt; readonly environmentId: string }
    | { readonly kind: "none-in-ci" },
  display: PlanDisplay = FULL_PLAN,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
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
    // A selection containing a variable with only a required declaration and no value = nothing is carried (the same rule as run)
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
}

/**
 * `maruhi sync plan <target>`: receipt + verified names and versions of the
 * source environment. The source values are not decrypted, and the vendor
 * API is not contacted.
 */
export function syncPlanOp(input: SyncContextInput): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const loaded = yield* loadTargetReceipt(input);
    const pulled = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: loaded.verified,
      environmentId: input.target.environment as EnvironmentId,
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
}

/** apply's input (plan's, plus the signing key and `--yes`). */
export interface SyncApplyInput extends SyncContextInput {
  readonly writerUserId: string;
  readonly signingKey: CryptoKey;
  /** The explicit consent for apply to a production target (supplement 14 M4). */
  readonly yes: boolean;
  /** The floor of the integration token's environment (only for the http driver. exec is null). */
  readonly tokenFloor: FloorHandle | null;
  /** The vendor API's retry (the default is production tuning. Tests shorten it). */
  readonly httpRetry?: HttpRetryPolicy;
  /** The plan's rendering (the apply right after a push omits unchanged). */
  readonly display?: PlanDisplay;
}

/** What apply sends (built from the plan's add / update / delete). */
export interface ApplyWork {
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
  /** The version of each variable written (the coordinate recorded in the receipt). */
  readonly versions: ReadonlyMap<string, number>;
}

/**
 * Turns the plan into writes and deletes, checking every value's content
 * constraints first (UTF-8, emptiness, size, trailing newline). One
 * refused value means nothing is sent.
 */
export function prepareWork(
  target: SyncTarget,
  plan: SyncPlan,
  values: ReadonlyMap<string, SyncWrite>,
): Effect.Effect<ApplyWork, CliError> {
  return Effect.gen(function* () {
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
      // Reason for unwrapping: the input of the constraint check before sending (the product is only a boolean and a variable name)
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
    const deletes = plan.entries.flatMap((entry) =>
      entry.action === "delete" ? [entry.name] : [],
    );
    return { writes, deletes, versions };
  });
}

/** The driver's run result (the material for advancing only the succeeded names to the receipt). */
export interface DriverResult {
  readonly written: readonly string[];
  readonly deleted: readonly string[];
  /** The failed invocation (null when none). */
  readonly failure: {
    readonly names: readonly string[];
    readonly kind: "write" | "delete";
    /** What failed (the executable name and exit code / the API's name). Carries no value. */
    readonly what: string;
    /**
     * maruhi's own explanation (the start failure's reason and guidance
     * — a complete sentence). Not the vendor's output, so it does not go
     * on `output` (failDriver shows output as the vendor's speech, with
     * an executable-name / hostname prefix).
     */
    readonly detail: string | null;
    /** The scrubbed fragments of output / responses (the vendor's speech. Empty when none). */
    readonly output: readonly string[];
  } | null;
}

/**
 * Runs the vendor processes in order and stops at the first failure. What
 * succeeded before it is reported so the receipt can record it. A process
 * that cannot be started (the CLI is not installed, or the cwd is gone) is
 * that invocation's failure too — like the http driver's runBatch, so a
 * typed error never drops the names delivered by the invocations before it.
 */
function runInvocations(
  driver: Extract<TargetDriver, { kind: "exec" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
): Effect.Effect<DriverResult, never, ProcessRunner> {
  return Effect.gen(function* () {
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
      // A start failure (a typed error — live.ts's execStartFailure) is
      // also folded into this invocation's failure: aborting the whole
      // generator here would leave the names delivered by the earlier
      // invocations unfurled into written / deleted and absent from the
      // receipt (the same shape as http's runBatch)
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
            // The start failure's wording is maruhi's own (carries no
            // value). A process that never ran has no output, so it
            // travels on detail rather than the vendor-output slot
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
            // The vendor's output is untrusted: scrub the values, neutralize control characters, keep only the tail
            output: scrubVendorOutput(outcome.output, work.writes),
          },
        };
      }
      // A JSON batch mixes writes and deletes (null) — split by name
      for (const name of invocation.names) {
        (deleteSet.has(name) ? deleted : written).push(name);
      }
    }
    return { written, deleted, failure: null };
  });
}

/** Sending to the vendor API (in batch order. Stops at the first failure and returns what was delivered). */
function runBatches(
  driver: Extract<TargetDriver, { kind: "http" }>,
  options: SyncTarget["options"],
  work: ApplyWork,
  token: IntegrationToken,
  retry: HttpRetryPolicy,
): Effect.Effect<DriverResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
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
            // What happened (refused / an unconfirmed response / a
            // failed send / a failed listing / never sent) is
            // distinguished by runBatch as the failure's author — never
            // attach "refused" to a retry-exhausted attempt
            what: result.failure.what,
            detail: null,
            output: result.failure.lines,
          },
        };
      }
    }
    return { written, deleted, failure: null };
  });
}

/** What running the driver needs (exec = processes, http = the token + communication). */
export interface RunDriverInput {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  /** The http driver's integration token (null for exec). */
  readonly token: IntegrationToken | null;
  readonly httpRetry: HttpRetryPolicy;
}

/**
 * Runs the target's driver over the prepared work: the installed vendor CLI
 * (values on stdin) or the vendor API (values in the request body). Prints
 * one line naming where the plaintext goes before sending anything.
 */
export function runDriver(
  input: RunDriverInput,
): Effect.Effect<DriverResult, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { driver } = input.target;
    if (driver.kind === "exec") {
      // Leave in the output which executable receives it and where (the
      // config's command / cwd changes the plaintext's destination, so
      // make it visible on the terminal and in CI logs, not only in the
      // diff)
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
    return yield* runBatches(
      driver,
      input.target.options,
      input.work,
      input.token,
      input.httpRetry,
    );
  });
}

/** Extracts the integration token from the decrypted variables (with a check). */
export function integrationTokenOf(
  token: { readonly environment: string; readonly name: string },
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
  // Reason for unwrapping: checking the token's shape (is it header-safe). The product is Redacted again
  const checked = checkIntegrationToken(token.name, Redacted.value(variable.value));
  return typeof checked === "string"
    ? Effect.succeed(Redacted.make(checked, { label: "integration-token" }))
    : Effect.fail(checked);
}

/** Fetching the integration token (locally: verifies the token environment and decrypts just that one variable). */
function fetchIntegrationToken(
  input: SyncApplyInput,
  driver: Extract<TargetDriver, { kind: "http" }>,
  verified: VerifiedProject,
): Effect.Effect<
  { readonly token: IntegrationToken; readonly verified: VerifiedProject },
  CliError,
  CliIo
> {
  return Effect.gen(function* () {
    if (input.tokenFloor === null) {
      return yield* Effect.fail(
        cliError("No floor handle for the token environment (internal inconsistency)"),
      );
    }
    const pulled = yield* pullVariables({
      client: input.client,
      verified,
      environmentId: driver.token.environment as EnvironmentId,
      recipient: input.recipient,
      resync: input.resync,
      floor: input.tokenFloor,
      select: (name) => name === driver.token.name,
    });
    yield* logWarnings(pulled.warnings);
    const token = yield* integrationTokenOf(driver.token, pulled.variables);
    return { token, verified: pulled.verified };
  });
}

/** The receipt's next content (layers only the succeeded writes / deletes over the previous). */
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
    // No receipt yet and nothing delivered (the first invocation failed) = nothing to write
    return Object.keys(b.variables).length === 0;
  }
  const left = Object.entries(a.variables).toSorted();
  const right = Object.entries(b.variables).toSorted();
  return JSON.stringify(left) === JSON.stringify(right);
}

/**
 * Saves the receipt when its variables changed. Returns the new version, or
 * null when nothing was written (unchanged, or the write failed — a warning,
 * because the target is already updated and the next apply is idempotent).
 */
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

/** The driver failure's body (a pure function — failDriver turns it into a typed error as-is). */
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
  // A delete's failure can take the shape "it was already removed at
  // the destination" (the destination is never read back, so the name
  // keeps being deleted from the receipt). Recovery is rebuilding the
  // receipt — but rebuilding also forgets the **deletions not attempted
  // yet**, so name them and say to remove them at the destination by
  // hand first
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
  // When there is not a single output line, never say "shown above"
  // (some CLIs fail with empty output, and a process that could not
  // start has none)
  const outputHint =
    failure.output.length === 0 ? "" : " Its output is shown above with values filtered out.";
  // maruhi's own explanation (the start failure's reason and guidance) is spoken as the body's continuation
  const detail = failure.detail === null ? "" : ` ${failure.detail}.`;
  return `${failure.what} while ${failure.kind === "write" ? "writing" : "deleting"} ${failure.names.map(displayText).join(", ")} (delivered before that: ${countNoun(result.written.length, "variable")} written, ${result.deleted.length} deleted).${detail}${outputHint}${deleteHint} Fix the cause, then ${input.next}`;
}

/** Reporting the driver's failure (a typed error with the scrubbed output attached). */
export function failDriver(input: {
  readonly target: SyncTarget;
  readonly work: ApplyWork;
  readonly result: DriverResult;
  /** The environment attached to the receipt-rebuild guidance (CI = null: no receipt). */
  readonly receiptsEnvironment: string | null;
  /** The means to see what is left (locally = plan, CI = re-run). */
  readonly next: string;
}): Effect.Effect<never, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const { target, result } = input;
    if (result.failure === null) {
      return yield* Effect.fail(
        cliError("failDriver called without a failure (internal inconsistency)"),
      );
    }
    // output is the vendor's speech, so it is shown with an executable-name / hostname prefix
    const prefix = target.driver.kind === "exec" ? target.driver.command : target.driver.spec.host;
    for (const line of result.failure.output) {
      yield* io.logError(`  ${displayText(prefix)}: ${line}`);
    }
    return yield* Effect.fail(cliError(driverFailureMessage(input, result, result.failure)));
  });
}

/** Reporting the run's result (a failure is a typed error with the scrubbed output attached). */
function reportApply(
  input: SyncApplyInput,
  work: ApplyWork,
  result: DriverResult,
  receiptVersion: number | null,
): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
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
}

/** apply to a production target needs `--yes` (supplement 14 M4). */
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

/**
 * `maruhi sync apply <target>`: plan, then write the changed variables to
 * the target through its driver, then record what landed in the receipt.
 */
export function syncApplyOp(
  input: SyncApplyInput,
): Effect.Effect<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const loaded = yield* loadTargetReceipt(input);
    // The plan is built from metadata only (never decrypts — the same
    // path as sync plan). To never build a plaintext in memory of a
    // variable outside the selection or outside the required-warning
    // target, the values are taken in a second pull select-narrowed to
    // "only the add / update entries actually being sent"
    const meta = yield* pullVerifiedEnvironment({
      client: input.client,
      verified: loaded.verified,
      environmentId: input.target.environment as EnvironmentId,
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
    // apply decrypts (the same path as run — pull.ts). The plaintext
    // stays in Redacted all the way to the driver's body / stdin
    // assembly
    const writeNames = new Set(
      plan.entries
        .filter((entry) => entry.action === "add" || entry.action === "update")
        .map((entry) => entry.name),
    );
    const pulled = yield* pullVariables({
      client: input.client,
      verified: meta.verified,
      environmentId: input.target.environment as EnvironmentId,
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
    // The integration token is fetched just before sending (a path that ends without sending never decrypts it)
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
    // The receipt advances only by "what was actually delivered". Even
    // on a failed run the delivered part is recorded, so the next plan
    // shows only the remainder
    const syncedAtMs = yield* Clock.currentTimeMillis;
    const receipt = nextReceipt({
      target: input.target,
      previous: loaded.receipt,
      result,
      versions: work.versions,
      syncedAt: new Date(syncedAtMs).toISOString(),
    });
    // The receipt's push starts from the view that may have advanced via
    // the pulls of the sync source (and the token environment) (the view
    // at loadReceipt can be stale)
    const receiptVersion = yield* saveReceipt(input, { ...loaded, verified }, receipt);
    yield* reportApply(input, work, result, receiptVersion);
  });
}
