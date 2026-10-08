// Syncing right after `maruhi push` (the "who carries it" row of
// the "sync's final form" table in integration-options.md §3: only
// a human can change a value → at the change's moment the writer's
// CLI is present → either the writer's CLI syncs directly, or it
// launches CI via `gh workflow run`. Supplement 4 N1 / supplement
// 7 P1).
//
// When a sync-config target has `onPush`, as the push's **cleanup**
// after acceptance:
// - `"apply"`: calls the existing `syncApplyOp` (sync-plan.ts —
//   decrypt → the driver's stdin / API body → receipt) as-is.
//   Since plan is the diff between the receipt and the current
//   version, what gets written is only the variables pushed now
//   (plus anything missed last time). A production target is
//   refused at the config stage (sync-config.ts — only a human's
//   `--yes`-ed `maruhi sync apply` writes production)
// - `"workflow"`: hits `gh workflow run <file> -f target=<name>`
//   with the writer's `gh` (the user's own GitHub auth) and lets
//   CI (`maruhi ci sync`) carry it. The writer does not hold the
//   sync target's token (P1). **Neither values nor variable names
//   ride**: argv is only the config-derived target name and the
//   workflow's name; the values are fetched from maruhi by CI.
//   Only the launch's acceptance is reported — the result is not
//   awaited (one-way). The receipt cannot advance because CI
//   cannot write it (docs "In CI", 3rd point)
//
// This is cleanup, not part of push (same discipline as ruling D
// of 2b): communication, authority, conflict, and vendor / gh
// failures stay warnings and never change push's exit code — the
// mark of unsynced work is the receipt's lag itself (the next
// `maruhi sync plan` shows it pending), and the next apply or CI
// picks it up. Only **evidence** (`CliError.evidence`) passes
// through as a failure (asCleanupOutcome — errors.ts). push's own
// report and the checkpoint / anchor proposals come out before
// here.
//
// Where the config lives (ruling B): an explicit `--config`, or
// the default path under cwd (`maruhi.sync.json`). The default
// path is used silently, so it is only used for a config that
// names `project` (sync-config.ts requires `project` for
// `onPush`), and does nothing if it names a different project
// than the push target (note). A mismatch with an explicit
// `--config` is a write-up error — stops before the push (ruling
// B of 2b). `--no-sync` performs push alone without reading the
// config (supplement 14 M8 — one `maruhi sync apply` at the tail
// of consecutive pushes).
//
// A target the default-path config **names an executable for**
// (exec's `command` / `workflow.command`) is not run: the project
// ID is public information in a public repository, and a config
// planted on a fork must not get to name "that ID + an arbitrary
// program" and receive the writer's plaintext on stdin merely by
// cwd. Only the preset's default executables (`vercel` /
// `wrangler` / `gh` on PATH) run from the default path.
//
// There is no dedicated gate for agent environments (supplement 9
// — `sync` is treated like `run`). What appears in the output is
// only the target name, the workflow name, counts, versions, and
// variable names (displayText).

import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import { type CliServices, type EnvironmentContext, floorHandleFor } from "../context.ts";
import { displayText } from "../display.ts";
import { asCleanupOutcome, type CliError, usageError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { environmentIdOf } from "../ids.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { type ExecInput, ProcessRunner } from "../run.ts";
import {
  DEFAULT_SYNC_CONFIG_PATH,
  loadSyncConfig,
  loadSyncConfigIfPresent,
  type OnPush,
  type SyncConfig,
  type SyncTarget,
} from "./sync-config.ts";
import { GH_ENV, scrubVendorOutput } from "./sync-exec.ts";
import { syncApplyOp } from "./sync-plan.ts";

/** The sync config `maruhi push` found, and how. */
export interface PushSyncSetup {
  readonly config: SyncConfig;
  readonly path: string;
  /** Whether it was made explicit via `--config` (true), or the cwd default path was silently read (false). */
  readonly explicit: boolean;
}

/**
 * Reads the sync config before the push touches the network: the explicit
 * `--config` must exist; the default path is optional. `--no-sync` reads
 * nothing (the push behaves as if no config existed) and cannot be combined
 * with `--config`.
 */
export const loadPushSyncConfig = Effect.fn("sync-push.loadPushSyncConfig")(function* (input: {
  readonly config: string | undefined;
  readonly noSync: boolean;
}): Effect.fn.Return<PushSyncSetup | null, CliError> {
  if (input.noSync) {
    if (input.config !== undefined) {
      // Do not silently allow the shape that avoids reading the pointed-at config
      return yield* Effect.fail(
        usageError("--no-sync and --config cannot be combined (drop one of them)"),
      );
    }
    return null;
  }
  if (input.config !== undefined) {
    const config = yield* loadSyncConfig(input.config);
    return { config, path: input.config, explicit: true };
  }
  const config = yield* loadSyncConfigIfPresent(DEFAULT_SYNC_CONFIG_PATH);
  return config === null ? null : { config, path: DEFAULT_SYNC_CONFIG_PATH, explicit: false };
});

/** What the cleanup will do (decided before the push, so a usage error stops it). */
export type PushSyncDecision =
  /** The default-path config belongs to a different project (does nothing — note). */
  | { readonly kind: "other-project" }
  /** There is no `onPush` target carrying this variable from the push's environment. */
  | { readonly kind: "none" }
  | {
      readonly kind: "targets";
      readonly targets: readonly SyncTarget[];
      /**
       * Targets for which the default-path config **names an
       * executable** (exec's `command` / `workflow.command`).
       * From a config merely found in cwd, never build the shape
       * that hands plaintext to a program the config names: say
       * it does not sync in a note, and run it only under an
       * explicit `--config` (the act of the user pointing at
       * that file)
       */
      readonly namesCommand: readonly SyncTarget[];
    };

/** Whether the target carries this variable (an explicit list / `"all"` − exclude). */
function targetCarries(target: SyncTarget, name: string): boolean {
  return target.variables === "all"
    ? !target.exclude.includes(name)
    : target.variables.includes(name);
}

/**
 * Decides the cleanup from the resolved project, environment, and variable
 * name. An explicit config that belongs to another project is a usage error
 * (before the push); the default config is then simply not used.
 */
export function decidePushSync(
  setup: PushSyncSetup,
  input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly name: string;
  },
): Effect.Effect<PushSyncDecision, CliError> {
  const { config } = setup;
  const onPush = [...config.targets.values()].filter((target) => target.onPush !== null);
  if (onPush.length === 0) {
    // A config of manual sync only: unrelated to push (its
    // `project` is not collated either — a config is obliged to
    // name `project` only when it has `onPush`)
    return Effect.succeed({ kind: "none" });
  }
  if (config.projectId !== undefined && config.projectId !== input.projectId) {
    if (setup.explicit) {
      return Effect.fail(
        usageError(
          "The sync config belongs to a different project (its `project` does not match the project being pushed to)",
        ),
      );
    }
    return Effect.succeed({ kind: "other-project" });
  }
  const selected = onPush.filter(
    (target) => target.environment === input.environmentId && targetCarries(target, input.name),
  );
  if (selected.length === 0) {
    return Effect.succeed({ kind: "none" });
  }
  const namesCommand = setup.explicit ? [] : selected.filter(namesCommandToRun);
  return Effect.succeed({
    kind: "targets",
    targets: selected.filter((target) => !namesCommand.includes(target)),
    namesCommand,
  });
}

/**
 * The target names the program to run (the config wrote an exec `command` or
 * a `workflow.command` — decided at parse time, sync-config.ts): the preset's
 * default is looked up on PATH, a named one is whatever the file says, even
 * when it spells the default. Only an explicitly passed config may do that
 * after a push.
 */
function namesCommandToRun(target: SyncTarget): boolean {
  const onPush = target.onPush;
  if (onPush?.kind === "workflow") {
    return onPush.namedCommand;
  }
  return target.driver.kind === "exec" && target.driver.namedCommand;
}

/** gh's exit code 4 = authentication is needed (exitAuth in cli/cli internal/ghcmd/cmd.go). */
const GH_EXIT_AUTH = 4;

/**
 * The `gh workflow run` invocation for one target: the workflow file, the
 * target name as the only input, and `--ref` when the config pins one. No
 * value and no variable name is on the command line — CI reads the values
 * from maruhi. Stdin is empty.
 */
function buildWorkflowDispatch(
  target: SyncTarget,
  onPush: Extract<OnPush, { kind: "workflow" }>,
): ExecInput {
  return {
    command: [
      onPush.command,
      "workflow",
      "run",
      onPush.file,
      "-f",
      `target=${target.name}`,
      ...(onPush.ref === undefined ? [] : ["--ref", onPush.ref]),
    ],
    cwd: onPush.cwd,
    extraEnv: GH_ENV,
    stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
  };
}

/** The recovery guidance (common to direct-apply and CI-launch failures). */
function recoveryHint(target: SyncTarget): string {
  return `The next \`maruhi sync plan ${displayText(target.name)}\` shows the pushed variable as pending; \`maruhi sync apply ${displayText(target.name)}\` or CI delivers it`;
}

/** CI launch: hits `gh workflow run` and reports only the acceptance (exit code 0). */
const triggerWorkflow = Effect.fn("sync-push.triggerWorkflow")(function* (
  target: SyncTarget,
  onPush: Extract<OnPush, { kind: "workflow" }>,
): Effect.fn.Return<void, CliError, CliIo | ProcessRunner> {
  const io = yield* CliIo;
  const runner = yield* ProcessRunner;
  const invocation = buildWorkflowDispatch(target, onPush);
  const name = displayText(target.name);
  const file = displayText(onPush.file);
  const outcome = yield* runner.exec(invocation);
  if (outcome.exitCode === 0) {
    yield* io.log(
      `Triggered workflow ${file} for target ${name} (\`gh workflow run\` in ${displayText(onPush.cwd)}). CI applies it with \`maruhi ci sync\` and keeps no receipt, so the next local \`maruhi sync plan ${name}\` still shows the pushed variable as pending`,
    );
    return;
  }
  if (outcome.exitCode === GH_EXIT_AUTH) {
    yield* logWarning(
      `the push is done, but workflow ${file} was not triggered for target ${name}: gh is not signed in (run \`gh auth login\`, or trigger the workflow yourself). ${recoveryHint(target)}`,
    );
    return;
  }
  // gh's output is not trusted: there should be no values, but the discipline of scrub-then-truncate is the same
  for (const line of scrubVendorOutput(outcome.output, [])) {
    yield* io.logError(`  ${displayText(onPush.command)}: ${line}`);
  }
  yield* logWarning(
    `the push is done, but workflow ${file} was not triggered for target ${name} (${displayText(onPush.command)} exited with code ${outcome.exitCode}; its output is shown above). Check that the workflow exists on the branch gh dispatches to and has a workflow_dispatch trigger with a "target" input, then trigger it yourself or let the next push retry. ${recoveryHint(target)}`,
  );
});

/**
 * A ledger holding exactly one floor handle per environment for
 * one push (never open two handles on the same environment — the
 * same discipline as `openSyncTarget`, so that when several
 * targets share one token environment, the second does not start
 * from the floor's pre-push snapshot).
 */
function floorLedger(
  context: EnvironmentContext,
): (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, never, CliServices> {
  const handles = new Map<string, FloorHandle>([[context.environmentId, context.floorHandle]]);
  return (environmentId) =>
    Effect.gen(function* () {
      const known = handles.get(environmentId);
      if (known !== undefined) {
        return known;
      }
      const handle = yield* floorHandleFor(context, environmentId);
      handles.set(environmentId, handle);
      return handle;
    });
}

/** Direct apply: the existing apply as-is (unchanged rows are skipped). */
const applyTarget = Effect.fn("sync-push.applyTarget")(function* (
  context: EnvironmentContext,
  setup: PushSyncSetup,
  target: SyncTarget,
  floorOf: (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, never, CliServices>,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  yield* io.log(
    `Syncing target ${displayText(target.name)} after the push (onPush in ${displayText(setup.path)})`,
  );
  // One floor handle per environment (the sync source = the
  // push destination gets push's handle; the receipt
  // environment and the unified token's environment get the
  // same one the ledger returns)
  const receiptsFloor = yield* floorOf(environmentIdOf(setup.config.receiptsEnvironment));
  const tokenFloor =
    target.driver.kind !== "http"
      ? null
      : yield* floorOf(environmentIdOf(target.driver.token.environment));
  yield* syncApplyOp({
    client: context.client,
    verified: context.verified,
    recipient: context.recipient,
    resync: context.resync,
    target,
    // The push's environment = the sync source: passes push's advanced floor handle as-is
    sourceFloor: context.floorHandle,
    receiptsEnvironment: setup.config.receiptsEnvironment,
    receiptsFloor,
    writerUserId: context.session.userId,
    signingKey: context.masterKeys.sigKeyPair.privateKey,
    // A production target cannot become "apply" at the config
    // stage (sync-config.ts). Even if reached,
    // requireProductionConsent stops it and it becomes a
    // warning
    yes: false,
    tokenFloor,
    display: { showUnchanged: false },
  });
});

/**
 * Runs the sync each `onPush` target asked for, after the push was reported.
 * A failure on one target is a warning (the push is done; the receipt lag is
 * the mark, and the next apply or CI run delivers it) and the remaining
 * targets are still processed. Only evidence fails the command.
 */
export const syncAfterPush = Effect.fn("sync-push.syncAfterPush")(function* (input: {
  readonly context: EnvironmentContext;
  readonly setup: PushSyncSetup;
  readonly decision: PushSyncDecision;
}): Effect.fn.Return<void, CliError, CliServices> {
  const { context, setup, decision } = input;
  if (decision.kind === "other-project") {
    yield* logNote(
      `the sync config ${displayText(setup.path)} belongs to a different project, so nothing was synced after the push`,
    );
    return;
  }
  if (decision.kind === "none") {
    if (setup.explicit) {
      yield* logNote(
        `no target in the sync config copies this variable from environment ${displayText(context.environmentId)} on push, so nothing was synced (set "onPush" on a target to sync it after every push)`,
      );
    }
    return;
  }
  for (const target of decision.namesCommand) {
    yield* logNote(
      `target ${displayText(target.name)} names the program to run (its command in ${displayText(setup.path)}), and a config found in the working directory does not start one after a push. Run \`maruhi sync apply ${displayText(target.name)}\` now, or pass --config ${displayText(setup.path)} on the next push`,
    );
  }
  const floorOf = floorLedger(context);
  for (const target of decision.targets) {
    const onPush = target.onPush;
    if (onPush === null) {
      continue;
    }
    const attempt = yield* asCleanupOutcome(
      onPush.kind === "apply"
        ? applyTarget(context, setup, target, floorOf)
        : triggerWorkflow(target, onPush),
    );
    if (attempt.kind === "failed") {
      yield* logWarning(
        `the push is done, but target ${displayText(target.name)} could not be synced (${attempt.error.message}). ${recoveryHint(target)}`,
      );
    }
  }
});
