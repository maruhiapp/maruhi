// `maruhi var` (discipline: see commands/index.ts).

import { Clock, Effect } from "effect";
import { Argument, Command, Flag } from "effect/cli";

import type { CliServices } from "../context.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import {
  DEFAULT_ROTATE_CONFIG_PATH,
  loadRotateConfig,
  configNamesProject as rotateConfigNamesProject,
} from "../rotate-config.ts";
import {
  DEFAULT_SYNC_CONFIG_PATH,
  type PushSyncSetup,
  decidePushSync,
  loadPushSyncConfig,
  syncAfterPush,
} from "../sync.package/index.ts";
import type { VarFinalizeInput, VarRotateInput } from "../var-rotate.ts";
import { NonBlank, commonFlags, singleFlag, singleValued } from "./flags.ts";
import { proposeCheckpointRefresh } from "./shared.ts";

/** `maruhi var rm <NAME>` (deleting a variable — AUTH_SPEC §12-5). */
export const varRmConfig = {
  ...commonFlags(),
  force: singleFlag(
    "force",
    "Skip the interactive confirmation (the only non-interactive path; deletion is permanent)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name to delete (declared or active)"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var history <NAME>` (the version history — AUTH_SPEC §12-7, 2026-09-27 VH). */
export const varHistoryConfig = {
  ...commonFlags(),
  json: singleFlag(
    "json",
    "Print the history as JSON (server-declared metadata: version, epoch, writer, time, lineage, flag count)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name whose version history to show"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var rollback <NAME> --to <VERSION>` (restoring an old value as a new version — VH). */
export const varRollbackConfig = {
  ...commonFlags(),
  to: Flag.Int("to").pipe(
    Flag.withDescription(
      "The version whose value to restore (see `maruhi var history`); pushed as a new version",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  force: singleFlag("force", "Skip the interactive confirmation (the only non-interactive path)"),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the rollback (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the rollback (the default sync config is not read)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription("Variable name to roll back"),
    Argument.withSchema(NonBlank),
  ),
};

/** `maruhi var rotate <NAME> [--finalize]` (upstream rotation through a connector — PF6). */
export const varRotateConfig = {
  ...commonFlags(),
  finalize: singleFlag(
    "finalize",
    "Invalidate the credential the previous version held (after the new value is deployed) instead of rotating",
  ),
  previous: Flag.Int("previous").pipe(
    Flag.withDescription(
      "With --finalize: the version that held the credential to invalidate (default: the one before the current version)",
    ),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  ),
  yes: singleFlag(
    "yes",
    "Skip the confirmation of a step that invalidates a credential (the only non-interactive path)",
  ),
  "rotate-config": singleValued(
    "rotate-config",
    `Path to the rotation config naming the connector and admin credential of each variable (default: ${DEFAULT_ROTATE_CONFIG_PATH} in the working directory)`,
  ),
  config: singleValued(
    "config",
    `Path to the sync config whose "onPush" targets are synced after the rotation (default: ${DEFAULT_SYNC_CONFIG_PATH} in the working directory, when it exists and names this project)`,
  ),
  "no-sync": singleFlag(
    "no-sync",
    "Skip the sync after the rotation (the default sync config is not read)",
  ),
  name: Argument.String("name").pipe(
    Argument.withDescription(
      "Variable name to rotate (the rule's variable, or the access key id an AWS rule pairs with it)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** `--previous` rides only with `--finalize` and names a version (checked before any network). */
function checkPreviousFlag(values: {
  readonly previous: number | undefined;
  readonly finalize: boolean;
}): Effect.Effect<void, CliError> {
  if (values.previous === undefined) {
    return Effect.void;
  }
  if (!values.finalize) {
    return Effect.fail(usageError("--previous applies to --finalize only"));
  }
  return values.previous < 1
    ? Effect.fail(usageError("--previous must be a positive version number"))
    : Effect.void;
}

/** `maruhi var rotate <name> --finalize`: invalidates the previous credential and reports. */
const runVarFinalize = Effect.fn("commands-var.runVarFinalize")(function* (
  input: VarFinalizeInput,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const { describeFinalization, logRotationWarnings, varFinalizeOp } = yield* Effect.promise(() =>
    import("../var-rotate.ts").then(
      ({ describeFinalization, logRotationWarnings, varFinalizeOp }) => ({
        describeFinalization,
        logRotationWarnings,
        varFinalizeOp,
      }),
    ),
  );
  const result = yield* varFinalizeOp(input);
  yield* logRotationWarnings(result.warnings);
  for (const line of describeFinalization(result, input.context.environmentId)) {
    yield* io.log(line);
  }
});

/** `maruhi var rotate <name>`: the rotation, its report, the checkpoint proposal, and the onPush sync. */
const runVarRotate = Effect.fn("commands-var.runVarRotate")(function* (
  input: VarRotateInput,
  syncSetup: PushSyncSetup | null,
): Effect.fn.Return<void, CliError, CliServices> {
  const io = yield* CliIo;
  const { describeRotation, logRotationWarnings, varRotateOp } = yield* Effect.promise(() =>
    import("../var-rotate.ts").then(({ describeRotation, logRotationWarnings, varRotateOp }) => ({
      describeRotation,
      logRotationWarnings,
      varRotateOp,
    })),
  );
  const { context } = input;
  const syncDecision =
    syncSetup === null
      ? null
      : yield* decidePushSync(syncSetup, {
          projectId: context.projectId,
          environmentId: context.environmentId,
          name: input.name,
        });
  const result = yield* varRotateOp(input);
  yield* logRotationWarnings(result.warnings);
  const nowMs = yield* Clock.currentTimeMillis;
  for (const line of describeRotation(result, context.environmentId, nowMs)) {
    yield* io.log(line);
  }
  yield* proposeCheckpointRefresh(context, { includeAnchor: true });
  if (syncSetup !== null && syncDecision !== null) {
    yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
  }
});

export function makeVarCommands() {
  const varRm = Command.make(
    "rm",
    varRmConfig,
    Effect.fn("commands-var.varRm")(function* (values) {
      const io = yield* CliIo;
      const { openEnvironment } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openEnvironment }) => ({ openEnvironment })),
      );
      const { varRmOp } = yield* Effect.promise(() =>
        import("../var-rm.ts").then(({ varRmOp }) => ({ varRmOp })),
      );
      const context = yield* openEnvironment(values);
      const summary = yield* varRmOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        force: values.force,
        resync: context.resync,
        floor: context.floorHandle,
        authorUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(summary.warnings);
      const consequence =
        summary.previousStatus === "active"
          ? "its value (every stored version) was deleted"
          : "it had no value (declared only)";
      yield* io.log(
        `Deleted ${displayText(values.name)} (${consequence}; metaVersion=${summary.metaVersion}). Deletion is terminal — the variable cannot be restored, though the name can be reused by a new variable`,
      );
    }),
  ).pipe(
    Command.withDescription(
      "Delete a variable and all of its values permanently (asks for confirmation unless --force). Works for declared and active variables",
    ),
  );

  const varHistory = Command.make(
    "history",
    varHistoryConfig,
    Effect.fn("commands-var.varHistory")(function* (values) {
      const io = yield* CliIo;
      const { openMetadataEnvironment } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openMetadataEnvironment }) => ({
          openMetadataEnvironment,
        })),
      );
      const { formatVarHistory, varHistoryJson, varHistoryOp } = yield* Effect.promise(() =>
        import("../var-history.ts").then(({ formatVarHistory, varHistoryJson, varHistoryOp }) => ({
          formatVarHistory,
          varHistoryJson,
          varHistoryOp,
        })),
      );
      // Metadata only (§12-7): keyless, scope-agnostic, no value is read —
      // the agent gate does not apply (zero values — the permissive side)
      const context = yield* openMetadataEnvironment(values);
      const result = yield* varHistoryOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        name: values.name,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(result.warnings);
      if (values.json) {
        yield* io.log(varHistoryJson(result, context.environmentId));
        return;
      }
      for (const line of formatVarHistory(result, context.environmentId)) {
        yield* io.log(line);
      }
    }),
  ).pipe(
    Command.withDescription(
      "Show a variable's version history (metadata only: version, epoch, writer, time, rollbacks, rotation-flag exposure — never a value)",
    ),
  );

  const varRollback = Command.make(
    "rollback",
    varRollbackConfig,
    Effect.fn("commands-var.varRollback")(function* (values) {
      const io = yield* CliIo;
      const { openEnvironment } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openEnvironment }) => ({ openEnvironment })),
      );
      const { varRollbackOp } = yield* Effect.promise(() =>
        import("../var-history.ts").then(({ varRollbackOp }) => ({ varRollbackOp })),
      );
      const toVersion = values.to;
      if (toVersion === undefined || toVersion < 1) {
        return yield* Effect.fail(
          usageError(
            "--to <version> is required and must be a positive version number (see `maruhi var history <name>`)",
          ),
        );
      }
      // The sync config is read before any network (same order as push)
      const syncSetup = yield* loadPushSyncConfig({
        config: values.config,
        noSync: values["no-sync"],
      });
      const context = yield* openEnvironment(values);
      const syncDecision =
        syncSetup === null
          ? null
          : yield* decidePushSync(syncSetup, {
              projectId: context.projectId,
              environmentId: context.environmentId,
              name: values.name,
            });
      const result = yield* varRollbackOp({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        name: values.name,
        toVersion,
        force: values.force,
        resync: context.resync,
        floor: context.floorHandle,
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
      });
      yield* logWarnings(result.warnings);
      yield* io.log(
        `Rolled back ${displayText(result.name)} to the value of version ${result.toVersion} (new version=${result.pushed.version}, epoch=${result.pushed.epoch}; was version ${result.fromVersion})`,
      );
      if (result.flagsIfCurrent > 0) {
        yield* logNote(
          `The restored value was readable by the subject of ${countNoun(result.flagsIfCurrent, "rotation flag")} — see \`maruhi rotation list\``,
        );
      }
      yield* proposeCheckpointRefresh(context, { includeAnchor: true });
      if (syncSetup !== null && syncDecision !== null) {
        yield* syncAfterPush({ context, setup: syncSetup, decision: syncDecision });
      }
    }),
  ).pipe(
    Command.withDescription(
      "Restore a previous version's value as a new version (verifies the old version against the latest first; asks for confirmation unless --force). Never displays the value",
    ),
  );

  const varRotate = Command.make(
    "rotate",
    varRotateConfig,
    Effect.fn("commands-var.varRotate")(function* (values) {
      const { openEnvironment } = yield* Effect.promise(() =>
        import("../context.ts").then(({ openEnvironment }) => ({ openEnvironment })),
      );
      yield* checkPreviousFlag(values);
      // Both configs are read before any network: a broken or absent rotation
      // config is a usage problem, not something to find after a pull
      const rotateConfigPath = values["rotate-config"] ?? DEFAULT_ROTATE_CONFIG_PATH;
      const rotateConfig = yield* loadRotateConfig(rotateConfigPath);
      const syncSetup = values.finalize
        ? null
        : yield* loadPushSyncConfig({ config: values.config, noSync: values["no-sync"] });
      const context = yield* openEnvironment(values);
      if (!rotateConfigNamesProject(rotateConfig, context.projectId)) {
        return yield* Effect.fail(
          usageError(
            `The rotation config ${displayText(rotateConfigPath)} belongs to a different project (its \`project\` does not match)`,
          ),
        );
      }
      const shared = {
        context,
        config: rotateConfig,
        configPath: rotateConfigPath,
        name: values.name,
        yes: values.yes,
      };
      if (values.finalize) {
        return yield* runVarFinalize({ ...shared, previousVersion: values.previous ?? null });
      }
      yield* runVarRotate(shared, syncSetup);
    }),
  ).pipe(
    Command.withDescription(
      "Create a new credential at the issuer through the rule's connector and push it as a new version; the previous credential stays valid until --finalize. Never displays a value",
    ),
  );

  const varGroup = Command.make("var").pipe(
    Command.withDescription(
      "Manage variables (rm, history, rollback, rotate). push / pull / run operate on values directly",
    ),
    Command.withSubcommands([varRm, varHistory, varRollback, varRotate]),
  );

  return varGroup;
}
