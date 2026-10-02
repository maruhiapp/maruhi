// `maruhi var rotate <NAME> [--finalize]` (PF6 — ROADMAP "minimal upstream
// rotation" R2; docs/notes/pf6-design.md rulings R2–R6).
//
//   - rotate: pull the verified environment, decrypt the current credential
//     (and the admin inputs the rule names — from this environment or
//     another the member can decrypt), ask the connector to create a new
//     credential at the issuer, and push it as an ordinary signed new
//     version (a fresh value after the environment's mandated rotation
//     resolves the rotation flag — AUDIT_SPEC §4.1-5). The old credential
//     stays valid at the issuer: the dual-credential grace period
//   - finalize: read the previous version as a verified ancestor of the
//     latest (the rollback's evidence rule — var-history.ts), and ask the
//     connector to invalidate the credential it held. No state file: the
//     value history is the rotation state
//
// Plaintext lives only in memory as Redacted and is never displayed; the
// report carries the issuer-side identifiers (a key id, a role, a token id)
// and the version numbers. A connector that invalidates the current
// credential as part of the rotation (an in-place database password) asks
// for confirmation first (`--yes` for scripts). Finalizing asks the same way.

import type { EnvironmentId } from "@maruhi/core";
import { Context, Effect, Redacted, Stdio } from "effect";

import type { CliServices, EnvironmentContext } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import { environmentKeysFor } from "./deks.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";
import { decryptVerifiedValue } from "./pull.ts";
import { type PushedVersion, pushVariable } from "./push.ts";
import { type InputRefs, type RotateConfig, type RotateRule, ruleFor } from "./rotate-config.ts";
import {
  companionsOf,
  ConnectorError,
  type CredentialValues,
  describeFinalize,
  type FinalizeOutcome,
  finalizeCredential,
  planRotation,
  type RotateDeps,
  type RotateInputs,
  rotateCredential,
  type RotationOutcome,
} from "./rotate-connector.ts";
import { requireEnvironmentInScope } from "./scope.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "./values.ts";
import { verifiedAncestorValues } from "./var-history.ts";

/**
 * Test seams (absent in production): where the issuer APIs are and what the
 * clock says. Provided by the test layer through {@link RotateSeams}.
 */
export interface RotateSeamsShape {
  readonly fetch?: typeof fetch;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly awsIamBase?: string;
  readonly cloudflareBase?: string;
}

export class RotateSeams extends Context.Reference<RotateSeamsShape | null>("cli/RotateSeams", {
  defaultValue: (): RotateSeamsShape | null => null,
}) {}

/** The connector dependencies of one run: production defaults overridden by the test seams. */
export function rotateDeps(seams: RotateSeamsShape | null, sql: RotateDeps["sql"]): RotateDeps {
  return {
    fetch: seams?.fetch ?? globalThis.fetch,
    now: seams?.now ?? (() => Date.now()),
    randomBytes: seams?.randomBytes ?? ((length) => crypto.getRandomValues(new Uint8Array(length))),
    sql,
    awsIamBase: seams?.awsIamBase,
    cloudflareBase: seams?.cloudflareBase,
  };
}

export interface VarRotateInput {
  readonly context: EnvironmentContext;
  readonly config: RotateConfig;
  readonly configPath: string;
  /** The variable named on the command line (the rule's variable, or an AWS rule's key id companion). */
  readonly name: string;
  /** true = skip the confirmation of an invalidating step (the only non-interactive path). */
  readonly yes: boolean;
  readonly deps: RotateDeps;
}

export interface VarRotateResult {
  /** The rule's variable (the secret access key for an AWS rule). */
  readonly primary: string;
  readonly connector: RotateRule["connector"];
  /** Every version pushed, in push order (companions first). */
  readonly pushed: readonly { readonly name: string; readonly version: PushedVersion }[];
  readonly facts: readonly string[];
  readonly previous: string;
  readonly warnings: readonly string[];
}

export interface VarFinalizeInput extends VarRotateInput {
  /** The version that held the credential to invalidate (null = the one before the latest). */
  readonly previousVersion: number | null;
}

export interface VarFinalizeResult {
  readonly primary: string;
  readonly connector: RotateRule["connector"];
  readonly outcome: FinalizeOutcome;
  readonly previousVersion: number;
  readonly latestVersion: number;
  readonly warnings: readonly string[];
}

interface ResolvedTarget {
  readonly primary: string;
  readonly rule: RotateRule;
}

function resolveRule(input: VarRotateInput): Effect.Effect<ResolvedTarget, CliError> {
  const resolved = ruleFor(input.config, input.name.normalize("NFC"));
  if (resolved === null) {
    return Effect.fail(
      cliError(
        `No rotation rule for ${displayText(input.name)} in ${displayText(input.configPath)}. Add one (see the Rotation page in the docs), or rotate the credential at the issuer and push the new value with \`maruhi push ${displayText(input.name)}\``,
      ),
    );
  }
  return Effect.succeed(resolved);
}

/** The decrypted values of one environment by name (the pull's view and wraps are reused for the keys). */
function decryptedByName(
  context: EnvironmentContext,
  environmentId: string,
  pulled: VerifiedEnvironmentPull,
): Effect.Effect<ReadonlyMap<string, Redacted.Redacted<Uint8Array>>, CliError> {
  return Effect.gen(function* () {
    const keys = yield* environmentKeysFor({
      client: context.client,
      verified: pulled.verified,
      environmentId,
      recipient: context.recipient,
      prefetched: pulled.deks,
    });
    const byName = new Map<string, Redacted.Redacted<Uint8Array>>();
    for (const variable of pulled.variables) {
      byName.set(
        variable.name,
        yield* decryptVerifiedValue({
          verified: pulled.verified,
          environmentId,
          variable,
          deksByEpoch: keys.deksByEpoch,
          chainEpoch: keys.currentEpoch,
        }),
      );
    }
    return byName;
  });
}

/** Pulls and decrypts another environment the rule points at for an admin input (scope checked first — §6.3). */
function pullOtherEnvironment(
  context: EnvironmentContext,
  environmentId: string,
): Effect.Effect<ReadonlyMap<string, Redacted.Redacted<Uint8Array>>, CliError, CliServices> {
  return Effect.gen(function* () {
    yield* requireEnvironmentInScope({
      verified: context.verified,
      userId: context.session.userId,
      environmentId,
      operation: "read the admin credential from",
    });
    const floor = yield* floorHandleFor(context, environmentId);
    const pulled = yield* pullVerifiedEnvironment({
      client: context.client,
      verified: context.verified,
      environmentId: environmentId as EnvironmentId,
      resync: context.resync,
      floor,
    });
    return yield* decryptedByName(context, environmentId, pulled);
  });
}

/**
 * The admin inputs a rule names, decrypted (this environment's from the
 * pull already made; another environment's through its own verified pull).
 * A missing input stops the command before anything is sent.
 */
function resolveInputs(
  context: EnvironmentContext,
  refs: InputRefs,
  local: ReadonlyMap<string, Redacted.Redacted<Uint8Array>>,
  primary: string,
): Effect.Effect<RotateInputs, CliError, CliServices> {
  return Effect.gen(function* () {
    const inputs: Record<string, Uint8Array> = {};
    const others = new Map<string, ReadonlyMap<string, Redacted.Redacted<Uint8Array>>>();
    for (const [inputName, ref] of Object.entries(refs)) {
      let source = local;
      if (ref.environment !== null && ref.environment !== context.environmentId) {
        const cached = others.get(ref.environment);
        if (cached === undefined) {
          const pulled = yield* pullOtherEnvironment(context, ref.environment);
          others.set(ref.environment, pulled);
          source = pulled;
        } else {
          source = cached;
        }
      }
      const value = source.get(ref.name);
      if (value === undefined) {
        const where =
          ref.environment === null || ref.environment === context.environmentId
            ? "this environment"
            : `environment ${displayText(ref.environment)}`;
        return yield* Effect.fail(
          cliError(
            `The rotation rule for ${displayText(primary)} names variable ${displayText(ref.name)} in ${where} as its ${inputName}, but it has no value there. Set it with \`maruhi push\`, or fix the rule. Nothing was sent to the issuer`,
          ),
        );
      }
      // Reason for unwrapping: the connector consumes the admin credential in
      // memory to call the issuer's API (integration-options.md §4 R2). It is
      // never displayed, written, or sent anywhere but the issuer
      inputs[inputName] = Redacted.value(value);
    }
    return inputs;
  });
}

/** The rule's credential as currently stored: the primary and every companion, decrypted. */
function currentCredential(
  target: ResolvedTarget,
  local: ReadonlyMap<string, Redacted.Redacted<Uint8Array>>,
): Effect.Effect<CredentialValues, CliError> {
  return Effect.gen(function* () {
    const primary = local.get(target.primary);
    if (primary === undefined) {
      return yield* Effect.fail(
        cliError(
          `Variable ${displayText(target.primary)} has no value in this environment (a rotation replaces an existing credential; push the first value with \`maruhi push ${displayText(target.primary)}\`)`,
        ),
      );
    }
    const companions: Record<string, Uint8Array> = {};
    for (const [companion, variable] of Object.entries(companionsOf(target.rule))) {
      const value = local.get(variable);
      if (value === undefined) {
        return yield* Effect.fail(
          cliError(
            `Variable ${displayText(variable)} (the ${companion} the rule for ${displayText(target.primary)} names) has no value in this environment`,
          ),
        );
      }
      companions[companion] = Redacted.value(value);
    }
    return { primary: Redacted.value(primary), companions };
  });
}

function connectorFailure(error: unknown): CliError {
  if (error instanceof ConnectorError) {
    return cliError(error.message);
  }
  return cliError(error instanceof Error ? error.message : "the connector failed");
}

/** Confirms an invalidating step: `--yes`, or a y/N prompt at a terminal; non-interactive without --yes refuses. */
function ensureConfirmed(input: {
  readonly facts: readonly string[];
  readonly prompt: string;
  readonly refusal: string;
  readonly yes: boolean;
}): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    if (input.yes) {
      yield* Effect.forEach(input.facts, io.logError, { discard: true });
      return;
    }
    const stdio = yield* Stdio.Stdio;
    const interactive = (yield* stdio.stdinIsTerminal) && (yield* stdio.stdoutIsTerminal);
    if (!interactive) {
      return yield* Effect.fail(cliError(input.refusal));
    }
    yield* Effect.forEach(input.facts, io.logError, { discard: true });
    const answer = yield* io.promptLine({ prompt: input.prompt });
    if (!["y", "yes"].includes(answer.trim().toLowerCase())) {
      return yield* Effect.fail(cliError("Aborted: nothing was sent to the issuer"));
    }
  });
}

function pushOne(
  context: EnvironmentContext,
  pulled: VerifiedEnvironmentPull,
  name: string,
  bytes: Uint8Array,
): Effect.Effect<PushedVersion, CliError> {
  return pushVariable({
    client: context.client,
    environmentId: context.environmentId as EnvironmentId,
    recipient: context.recipient,
    name,
    value: Redacted.make(bytes, { label: "variable-value" }),
    verified: pulled.verified,
    resync: context.resync,
    writerUserId: context.session.userId,
    signingKey: context.masterKeys.sigKeyPair.privateKey,
    floor: context.floorHandle,
  });
}

/** Pushes the new credential: companions first (the AWS key id), then the primary. A failure says what already exists at the issuer. */
function pushOutcome(
  context: EnvironmentContext,
  pulled: VerifiedEnvironmentPull,
  target: ResolvedTarget,
  outcome: RotationOutcome,
): Effect.Effect<VarRotateResult["pushed"], CliError> {
  return Effect.gen(function* () {
    const pushed: { readonly name: string; readonly version: PushedVersion }[] = [];
    const planned: { readonly name: string; readonly bytes: Uint8Array }[] = [];
    for (const [companion, variable] of Object.entries(companionsOf(target.rule))) {
      const bytes = outcome.values.companions[companion];
      if (bytes !== undefined) {
        planned.push({ name: variable, bytes });
      }
    }
    planned.push({ name: target.primary, bytes: outcome.values.primary });
    for (const item of planned) {
      const version = yield* pushOne(context, pulled, item.name, item.bytes).pipe(
        Effect.mapError((error) =>
          cliError(
            `The issuer accepted the rotation (${outcome.facts.join("; ")}) but storing ${displayText(item.name)} failed: ${error.message}. ${pushed.length === 0 ? "Nothing was stored" : `Stored so far: ${pushed.map((entry) => displayText(entry.name)).join(", ")}`}. The new credential exists at the issuer and is held only by this process — resolve the cause and re-run the rotation (the next run reclaims or supersedes it), or revoke it at the issuer`,
          ),
        ),
      );
      pushed.push({ name: item.name, version });
    }
    return pushed;
  });
}

/** `maruhi var rotate <NAME>`: a new credential at the issuer, pushed as a new version; the old one stays valid until finalized. */
export function varRotateOp(
  input: VarRotateInput,
): Effect.Effect<VarRotateResult, CliError, CliServices> {
  return Effect.gen(function* () {
    const { context } = input;
    const target = yield* resolveRule(input);
    const pulled = yield* pullVerifiedEnvironment({
      client: context.client,
      verified: context.verified,
      environmentId: context.environmentId as EnvironmentId,
      resync: context.resync,
      floor: context.floorHandle,
    });
    const local = yield* decryptedByName(context, context.environmentId, pulled);
    const current = yield* currentCredential(target, local);
    const inputs = yield* resolveInputs(context, target.rule.inputs, local, target.primary);
    const plan = yield* Effect.try({
      try: () => planRotation(target.rule, current),
      catch: connectorFailure,
    });
    if (plan.immediate) {
      yield* ensureConfirmed({
        facts: [
          `Rotating ${displayText(target.primary)} will ${plan.description}. Consumers holding the current value stop working until the new one is deployed`,
        ],
        prompt: "Proceed with the rotation? [y/N]: ",
        refusal: `Refusing to rotate ${displayText(target.primary)} in a non-interactive environment without --yes: this rule's rotation invalidates the current credential at once (${plan.description}). Re-run with --yes to accept that explicitly`,
        yes: input.yes,
      });
    }
    const outcome = yield* Effect.tryPromise({
      try: () => rotateCredential(target.rule, current, inputs, input.deps),
      catch: connectorFailure,
    });
    const pushed = yield* pushOutcome(context, pulled, target, outcome);
    return {
      primary: target.primary,
      connector: target.rule.connector,
      pushed,
      facts: outcome.facts,
      previous: outcome.previous,
      warnings: [
        ...pulled.warnings,
        ...outcome.warnings,
        ...pushed.flatMap((entry) => entry.version.warnings),
      ],
    };
  });
}

/** `maruhi var rotate <NAME> --finalize`: invalidates the credential the previous version held. */
export function varFinalizeOp(
  input: VarFinalizeInput,
): Effect.Effect<VarFinalizeResult, CliError, CliServices> {
  return Effect.gen(function* () {
    const { context } = input;
    const target = yield* resolveRule(input);
    const base = {
      client: context.client,
      verified: context.verified,
      environmentId: context.environmentId as EnvironmentId,
      resync: context.resync,
      floor: context.floorHandle,
      recipient: context.recipient,
    };
    const primary = yield* verifiedAncestorValues({
      ...base,
      name: target.primary,
      toVersion: input.previousVersion,
    });
    const previousCompanions: Record<string, Uint8Array> = {};
    const currentCompanions: Record<string, Uint8Array> = {};
    const warnings = [...primary.warnings];
    for (const [companion, variable] of Object.entries(companionsOf(target.rule))) {
      // A companion's previous version is its own version before the latest
      // (the two variables are pushed together, so they move in step)
      const values = yield* verifiedAncestorValues({
        ...base,
        name: variable,
        toVersion: null,
      }).pipe(
        Effect.catch((error) =>
          // A companion with a single version: the previous credential's
          // companion is then the current one (nothing moved)
          error.message.includes("no previous version")
            ? verifiedAncestorValues({ ...base, name: variable, toVersion: 1 }).pipe(
                Effect.catch(() => Effect.fail(error)),
              )
            : Effect.fail(error),
        ),
      );
      previousCompanions[companion] = Redacted.value(values.ancestor);
      currentCompanions[companion] = Redacted.value(values.latest);
      warnings.push(...values.warnings);
    }
    const previous: CredentialValues = {
      primary: Redacted.value(primary.ancestor),
      companions: previousCompanions,
    };
    const current: CredentialValues = {
      primary: Redacted.value(primary.latest),
      companions: currentCompanions,
    };
    // The admin inputs come from the current environment state (a fresh
    // verified pull — the credential in use now authenticates a self-rotation)
    const pulled = yield* pullVerifiedEnvironment(base);
    const local = yield* decryptedByName(context, context.environmentId, pulled);
    const inputs = yield* resolveInputs(context, target.rule.inputs, local, target.primary);
    yield* ensureConfirmed({
      facts: [
        `Finalizing the rotation of ${displayText(target.primary)} will ${describeFinalize(target.rule)} (the credential of version ${primary.ancestorVersion}; version ${primary.latestVersion} is current). Anything still using the previous credential stops working`,
      ],
      prompt: "Proceed? [y/N]: ",
      refusal: `Refusing to finalize the rotation of ${displayText(target.primary)} in a non-interactive environment without --yes (it invalidates the previous credential at the issuer). Re-run with --yes to accept that explicitly`,
      yes: input.yes,
    });
    const outcome = yield* Effect.tryPromise({
      try: () => finalizeCredential(target.rule, previous, current, inputs, input.deps),
      catch: connectorFailure,
    });
    return {
      primary: target.primary,
      connector: target.rule.connector,
      outcome,
      previousVersion: primary.ancestorVersion,
      latestVersion: primary.latestVersion,
      warnings,
    };
  });
}

/** The report lines of a rotation (the command prints them; values never appear). */
export function describeRotation(result: VarRotateResult, environmentId: string): string[] {
  const versions = result.pushed
    .map(
      (entry) =>
        `${displayText(entry.name)} version=${entry.version.version}, epoch=${entry.version.epoch}`,
    )
    .join("; ");
  const lines = [
    `Rotated ${displayText(result.primary)} in environment ${displayText(environmentId)} with the ${result.connector} connector (${versions})`,
    ...result.facts.map((fact) => `  ${fact}`),
    `Previous credential: ${result.previous}`,
  ];
  if (!result.previous.includes("nothing to finalize")) {
    lines.push(
      `Deploy the new value (${countNoun(result.pushed.length, "variable")} pushed — sync targets with onPush were synced), then run \`maruhi var rotate ${displayText(result.primary)} --finalize\` to invalidate the previous credential`,
    );
  }
  return lines;
}

export function describeFinalization(result: VarFinalizeResult, environmentId: string): string[] {
  const head =
    result.outcome.kind === "finalized"
      ? `Finalized the rotation of ${displayText(result.primary)} in environment ${displayText(environmentId)} (${result.connector}): the credential of version ${result.previousVersion} is invalidated; version ${result.latestVersion} stays current`
      : result.outcome.kind === "already"
        ? `The previous credential of ${displayText(result.primary)} (version ${result.previousVersion}) was already invalidated at the issuer`
        : `Nothing to finalize for ${displayText(result.primary)} (version ${result.previousVersion} → ${result.latestVersion})`;
  return [head, ...result.outcome.facts.map((fact) => `  ${fact}`)];
}

/** Logs the warnings a rotation collected (a connection test that failed is one). */
export function logRotationWarnings(
  warnings: readonly string[],
): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(warnings, (warning) => logWarning(warning), { discard: true });
}
