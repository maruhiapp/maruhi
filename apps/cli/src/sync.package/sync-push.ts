import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import type { CliServices, EnvironmentContext } from "../context.ts";
import { displayText } from "../display.ts";
import { asCleanupOutcome, type CliError, usageError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
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

export interface PushSyncSetup {
  readonly config: SyncConfig;
  readonly path: string;
  readonly explicit: boolean;
}

export const loadPushSyncConfig = Effect.fn("sync-push.loadPushSyncConfig")(function* (input: {
  readonly config: string | undefined;
  readonly noSync: boolean;
}): Effect.fn.Return<PushSyncSetup | null, CliError> {
  if (input.noSync) {
    return null;
  }
  if (input.config !== undefined) {
    const config = yield* loadSyncConfig(input.config);
    return { config, path: input.config, explicit: true };
  }
  const config = yield* loadSyncConfigIfPresent(DEFAULT_SYNC_CONFIG_PATH);
  return config === null ? null : { config, path: DEFAULT_SYNC_CONFIG_PATH, explicit: false };
});

export type PushSyncDecision =
  | { readonly kind: "other-project" }
  | { readonly kind: "none" }
  | {
      readonly kind: "targets";
      readonly targets: readonly SyncTarget[];
      readonly namesCommand: readonly SyncTarget[];
    };

function targetCarries(target: SyncTarget, name: string): boolean {
  return target.variables === "all"
    ? !target.exclude.includes(name)
    : target.variables.includes(name);
}

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

function namesCommandToRun(target: SyncTarget): boolean {
  const onPush = target.onPush;
  if (onPush?.kind === "workflow") {
    return onPush.namedCommand;
  }
  return target.driver.kind === "exec" && target.driver.namedCommand;
}

const GH_EXIT_AUTH = 4;

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

function recoveryHint(target: SyncTarget): string {
  return `The next \`maruhi sync plan ${displayText(target.name)}\` shows the pushed variable as pending; \`maruhi sync apply ${displayText(target.name)}\` or CI delivers it`;
}

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
  for (const line of scrubVendorOutput(outcome.output, [])) {
    yield* io.logError(`  ${displayText(onPush.command)}: ${line}`);
  }
  yield* logWarning(
    `the push is done, but workflow ${file} was not triggered for target ${name} (${displayText(onPush.command)} exited with code ${outcome.exitCode}; its output is shown above). Check that the workflow exists on the branch gh dispatches to and has a workflow_dispatch trigger with a "target" input, then trigger it yourself or let the next push retry. ${recoveryHint(target)}`,
  );
});

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
      const { floorHandleFor } = yield* Effect.promise(() =>
        import("../context.ts").then((m) => ({ floorHandleFor: m.floorHandleFor })),
      );
      const handle = yield* floorHandleFor(context, environmentId);
      handles.set(environmentId, handle);
      return handle;
    });
}

const applyTarget = Effect.fn("sync-push.applyTarget")(function* (
  context: EnvironmentContext,
  setup: PushSyncSetup,
  target: SyncTarget,
  floorOf: (environmentId: EnvironmentId) => Effect.Effect<FloorHandle, never, CliServices>,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const { syncApplyOp } = yield* Effect.promise(() =>
    import("./sync-plan.ts").then((m) => ({ syncApplyOp: m.syncApplyOp })),
  );
  yield* io.log(
    `Syncing target ${displayText(target.name)} after the push (onPush in ${displayText(setup.path)})`,
  );
  const receiptsFloor = yield* floorOf(setup.config.receiptsEnvironment);
  const tokenFloor =
    target.driver.kind !== "http" ? null : yield* floorOf(target.driver.token.environment);
  yield* syncApplyOp({
    client: context.client,
    verified: context.verified,
    recipient: context.recipient,
    resync: context.resync,
    target,
    sourceFloor: context.floorHandle,
    receiptsEnvironment: setup.config.receiptsEnvironment,
    receiptsFloor,
    writerUserId: context.session.userId,
    signingKey: context.masterKeys.sigKeyPair.privateKey,
    yes: false,
    tokenFloor,
    display: { showUnchanged: false },
  });
});

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
