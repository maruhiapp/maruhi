// `maruhi sync` (discipline: see commands/index.ts).

import { type ProjectId, ProjectIdSchema } from "@maruhi/core";
import { Effect } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import {
  NonBlank,
  projectFlags,
  singleFlag,
  singleValued,
  singleValuedAs,
} from "../commands/flags.ts";
import { CliError, usageError } from "../errors.ts";
import {
  DEFAULT_SYNC_CONFIG_PATH,
  checkConfigProject,
  loadSyncConfig,
  requireSyncTarget,
} from "./sync-config.ts";
import { syncInitOp } from "./sync-init.ts";

/**
 * The declarations of `maruhi sync plan` / `apply` (SY2 stage 1). The
 * environment is decided not by a flag but by the repository config (the
 * `maruhi.sync.json` targets), so there is no `--env`. `--project` exists
 * but is checked against the config's `project` when present.
 */
const syncTargetArgument = () =>
  Argument.String("target").pipe(
    Argument.withDescription("Target name from the sync config (a key under `targets`)"),
    Argument.withSchema(NonBlank),
  );

const syncCommonFlags = () => ({
  ...projectFlags(),
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository (default: ${DEFAULT_SYNC_CONFIG_PATH})`,
  ),
});

/** @public */
export const syncPlanConfig = {
  ...syncCommonFlags(),
  target: syncTargetArgument(),
};

/** @public */
export const syncApplyConfig = {
  ...syncCommonFlags(),
  yes: singleFlag(
    "yes",
    "Apply to a production target (without it, a production target only shows the plan)",
  ),
  target: syncTargetArgument(),
};

/**
 * `maruhi sync init <target>`'s declaration (SY2 stage 2 — ruling F):
 * touches neither network nor files; assembles the config JSON from the
 * flags and prints it to stdout.
 * @public
 */
export const syncInitConfig = {
  preset: singleValued(
    "preset",
    "Deploy target kind: vercel, cloudflare-workers, netlify, or github-actions (required)",
  ),
  driver: singleValued(
    "driver",
    "How to reach the target: exec (the installed vendor CLI; default when the preset has one; the only driver for github-actions) or http (the vendor API with a token stored in maruhi; the only driver for netlify)",
  ),
  env: singleValued("env", "maruhi environment ID to copy from (required)"),
  receipts: singleValued(
    "receipts",
    "maruhi environment ID that stores the receipts (required; create it with `maruhi env create`)",
  ),
  project: singleValuedAs("project", "Project ID to pin the config to (optional)", ProjectIdSchema),
  variables: singleValued("variables", 'Comma-separated variable names to copy (default: "all")'),
  exclude: singleValued(
    "exclude",
    'Comma-separated names to leave out (only with the default "all")',
  ),
  production: singleFlag(
    "production",
    "Mark the target as production (apply then needs --yes; the default follows the preset)",
  ),
  cwd: singleValued(
    "cwd",
    "exec driver: directory to run the vendor CLI in, relative to the config",
  ),
  command: singleValued(
    "command",
    "exec driver: path of the installed vendor CLI (default: on PATH)",
  ),
  "token-env": singleValued(
    "token-env",
    "http driver: maruhi environment ID that holds the vendor's token",
  ),
  "token-name": singleValued(
    "token-name",
    "http driver: name of the maruhi variable that holds the vendor's token",
  ),
  "on-push": singleValued(
    "on-push",
    "Sync after every `maruhi push` to the environment: apply (from this machine) or workflow (trigger the repository's workflow with gh so CI syncs); needs --project",
  ),
  workflow: singleValued(
    "workflow",
    "With --on-push workflow: the workflow file that runs `maruhi ci sync` (for example maruhi-sync.yml)",
  ),
  option: Flag.String("option").pipe(
    Flag.withDescription(
      "Preset option as key=value (repeatable; for example environment=production, name=my-worker)",
    ),
    Flag.withSchema(NonBlank),
    Flag.atMost(64),
  ),
  target: syncTargetArgument(),
};

/** `maruhi sync init`'s required flags (a misspelling = 2). */
function requireInitFlag(value: string | undefined, flag: string): Effect.Effect<string, CliError> {
  return value === undefined
    ? Effect.fail(usageError(`sync init requires ${flag} (pass --preset, --env, and --receipts)`))
    : Effect.succeed(value);
}

/**
 * The command body. Since the handler can only return `Effect<void>`
 * (`Command.runWith` discards the value), the child process's exit code is
 * carried out via `onExitCode`.
 */
/**
 * `maruhi sync`'s shared prologue: config → target → project (matching
 * the config's `project` against the flag) → the floor handles of the
 * sync-source / receipt environments. The config is read exactly once
 * here. The project prologue happens once (never compare two verified
 * views that disagree by opening two environments separately — same
 * reason as env diff).
 */
const openSyncTarget = Effect.fn("sync-command.openSyncTarget")(function* (values: {
  readonly server: string | undefined;
  readonly project: ProjectId | undefined;
  readonly config: string | undefined;
  readonly target: string;
}) {
  const { floorHandleFor, openProject } = yield* Effect.promise(() => import("../context.ts"));

  // The config is read before any network (a broken file's detection is never placed behind a round trip)
  const config = yield* loadSyncConfig(values.config ?? DEFAULT_SYNC_CONFIG_PATH);
  const target = yield* requireSyncTarget(config, values.target);
  yield* checkConfigProject(config, values.project);
  const context = yield* openProject({
    server: values.server,
    project: values.project ?? config.projectId,
  });
  const sourceFloor = yield* floorHandleFor(context, target.environment);
  const receiptsFloor = yield* floorHandleFor(context, config.receiptsEnvironment);
  // The http driver's integration-token environment. When it equals
  // the sync-source / receipt environment, **the same floor handle** is
  // used (holding two handles on one environment would leave the
  // receipt's push unaware of the floor the token's pull advanced)
  const tokenFloor =
    target.driver.kind !== "http"
      ? null
      : target.driver.token.environment === target.environment
        ? sourceFloor
        : target.driver.token.environment === config.receiptsEnvironment
          ? receiptsFloor
          : yield* floorHandleFor(context, target.driver.token.environment);
  return { config, target, context, sourceFloor, receiptsFloor, tokenFloor };
});

/** @public */
export function makeSyncCommands() {
  const syncPlan = Command.make(
    "plan",
    syncPlanConfig,
    Effect.fn("sync-command.syncPlan")(function* (values) {
      const { syncPlanOp } = yield* Effect.promise(() => import("./sync-plan.ts"));

      const opened = yield* openSyncTarget(values);
      yield* syncPlanOp({
        client: opened.context.client,
        verified: opened.context.verified,
        recipient: opened.context.recipient,
        resync: opened.context.resync,
        target: opened.target,
        sourceFloor: opened.sourceFloor,
        receiptsEnvironment: opened.config.receiptsEnvironment,
        receiptsFloor: opened.receiptsFloor,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Show which variables an apply would write to or delete from a deploy target, by name and version (the values are not decrypted, and nothing is read back from the target)",
    ),
  );

  const syncApply = Command.make(
    "apply",
    syncApplyConfig,
    Effect.fn("sync-command.syncApply")(function* (values) {
      const { syncApplyOp } = yield* Effect.promise(() => import("./sync-plan.ts"));

      const opened = yield* openSyncTarget(values);
      yield* syncApplyOp({
        client: opened.context.client,
        verified: opened.context.verified,
        recipient: opened.context.recipient,
        resync: opened.context.resync,
        target: opened.target,
        sourceFloor: opened.sourceFloor,
        receiptsEnvironment: opened.config.receiptsEnvironment,
        receiptsFloor: opened.receiptsFloor,
        // The receipt's signature (§4.1): writer = my internal user_id, key = the master sig key
        writerUserId: opened.context.session.userId,
        signingKey: opened.context.masterKeys.sigKeyPair.privateKey,
        yes: values.yes,
        tokenFloor: opened.tokenFloor,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Decrypt the target's variables in memory and write the changed ones to the deploy target through its driver (the installed vendor CLI on stdin, or the vendor API with a token stored in maruhi), then record what was delivered in the receipt. A production target needs --yes",
    ),
  );

  const syncInit = Command.make(
    "init",
    syncInitConfig,
    Effect.fn("sync-command.syncInit")(function* (values) {
      const preset = yield* requireInitFlag(values.preset, "--preset");
      const environment = yield* requireInitFlag(values.env, "--env");
      const receipts = yield* requireInitFlag(values.receipts, "--receipts");
      yield* syncInitOp({
        target: values.target,
        preset,
        driver: values.driver,
        environment,
        receipts,
        project: values.project,
        variables: values.variables,
        exclude: values.exclude,
        production: values.production,
        cwd: values.cwd,
        command: values.command,
        tokenEnvironment: values["token-env"],
        tokenName: values["token-name"],
        onPush: values["on-push"],
        workflow: values.workflow,
        options: values.option,
      });
    }),
  ).pipe(
    Command.withDescription(
      "Print a sync config for one deploy target as JSON to stdout (commit it as maruhi.sync.json). Reads nothing and contacts no server",
    ),
  );

  const sync = Command.make("sync").pipe(
    Command.withDescription(
      "Copy variables to deploy targets (init / plan / apply) through the installed vendor CLI or the vendor API. Targets are declared in the sync config committed in the repository",
    ),
    Command.withSubcommands([syncInit, syncPlan, syncApply]),
  );

  return sync;
}
