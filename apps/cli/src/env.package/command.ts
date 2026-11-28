import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import {
  environmentIdArgument,
  invalidFlagCombination,
  NonBlank,
  projectFlags,
  singleFlag,
  singleValued,
} from "../commands/flags.ts";
import {
  commitVerifiedHead,
  floorHandleFor,
  loadMasterKeys,
  openEnvironment,
  openMetadataEnvironmentPair,
  openMetadataProject,
  openProject,
} from "../commands/lazy.ts";
import type { CliServices, CommonFlags } from "../context.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { reportRotation } from "../rotation-report.ts";
import {
  loadSyncConfig,
  advanceReceiptsAfterRotation,
  checkRotateConfigProject,
} from "../sync.package/index.ts";

/** @public */
export const envCreateConfig = {
  ...projectFlags(),
  name: singleValued("name", "Display name (defaults to the environment ID)"),
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

/** @public */
export const envRotateConfig = {
  ...projectFlags(),
  reason: singleValued(
    "reason",
    "Rotation reason (required when creating a new epoch; recorded on the chain)",
  ),
  "new-epoch": singleFlag(
    "new-epoch",
    "Always create a new epoch, even when incomplete re-encryption could be resumed instead",
  ),
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository; when given, the receipts of the targets synced from this environment advance to the re-encrypted versions (no default: without it, receipts are left alone)`,
  ),
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

/** @public */
export const envDiffConfig = {
  ...projectFlags(),
  "environment-id": environmentIdArgument("environment-id", "First environment ID to compare"),
  "other-environment-id": environmentIdArgument(
    "other-environment-id",
    "Second environment ID to compare",
  ),
};

/** @public */
export const envRenameConfig = {
  ...projectFlags(),
  "environment-id": environmentIdArgument(
    "environment-id",
    "ID of the environment to rename (the ID itself never changes)",
  ),
  "new-name": Argument.String("new-name").pipe(
    Argument.withDescription(
      "New display name (NFC-normalized; unique among the environments that are not deleted)",
    ),
    Argument.withSchema(NonBlank),
  ),
};

/** @public */
export const envListConfig = {
  ...projectFlags(),
  all: singleFlag("all", "Also list deleted environments (recorded on the project chain)"),
  json: singleFlag(
    "json",
    "Print the environments as JSON (ID, name, status, current epoch, whether your scope covers it)",
  ),
};

/** @public */
export const envRmConfig = {
  ...projectFlags(),
  force: singleFlag(
    "force",
    "Skip the interactive confirmation (the only non-interactive path; deletion is permanent)",
  ),
  "environment-id": environmentIdArgument("environment-id", "ID of the environment to delete"),
};

const envCreateCommand = Effect.fn("env-command.envCreateCommand")(function* (
  flags: CommonFlags & { readonly name?: string | undefined },
  environmentId: EnvironmentId,
): Effect.fn.Return<void, CliError, CliServices> {
  const { envCreateOp } = yield* Effect.promise(() =>
    import("./env-create.ts").then((m) => ({ envCreateOp: m.envCreateOp })),
  );

  const io = yield* CliIo;
  const context = yield* openProject(flags);
  const floor = yield* floorHandleFor(context, environmentId);
  const created = yield* envCreateOp({
    client: context.client,
    verified: context.verified,
    environmentId,
    name: flags.name ?? environmentId,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    resync: context.resync,
    floor,
  });
  yield* io.log(
    `Created environment ${environmentId} (epoch=${created.currentEpoch}, DEK wrapped for ${countNoun(created.memberCount, "current member")})`,
  );
});

const envRotateCommand = Effect.fn("env-command.envRotateCommand")(function* (
  flags: CommonFlags & {
    readonly reason?: string | undefined;
    readonly newEpoch?: boolean | undefined;
    readonly config?: string | undefined;
  },
  environmentId: EnvironmentId,
): Effect.fn.Return<number, CliError, CliServices> {
  const { ANCHOR_STALE_AFTER_ROTATION } = yield* Effect.promise(() =>
    import("../checkpoint.package/index.ts").then((m) => ({
      ANCHOR_STALE_AFTER_ROTATION: m.ANCHOR_STALE_AFTER_ROTATION,
    })),
  );
  const { envRotateOp } = yield* Effect.promise(() =>
    import("./env-rotate.ts").then((m) => ({ envRotateOp: m.envRotateOp })),
  );

  const syncConfig = flags.config === undefined ? null : yield* loadSyncConfig(flags.config);
  const context = yield* openEnvironment(
    { ...flags, env: environmentId },
    { quietMandateWarning: true },
  );
  if (syncConfig !== null) {
    yield* checkRotateConfigProject(syncConfig, context.projectId);
  }
  const summary = yield* envRotateOp({
    client: context.client,
    verified: context.verified,
    environmentId,
    recipient: context.recipient,
    reason: flags.reason,
    forceNewEpoch: flags.newEpoch === true,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
    resync: context.resync,
    floor: context.floorHandle,
  });
  const code = yield* reportRotation(
    environmentId,
    summary,
    flags.newEpoch === true || flags.reason !== undefined,
  );
  if (summary.mode === "rotated") {
    yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
  }
  if (syncConfig !== null) {
    const receiptsFloor =
      syncConfig.receiptsEnvironment === environmentId
        ? context.floorHandle
        : yield* floorHandleFor(context, syncConfig.receiptsEnvironment);
    yield* advanceReceiptsAfterRotation({
      client: context.client,
      verified: context.verified,
      recipient: context.recipient,
      resync: context.resync,
      config: syncConfig,
      environmentId,
      written: summary.written,
      receiptsFloor,
      writerUserId: context.session.userId,
      signingKey: context.masterKeys.sigKeyPair.privateKey,
    });
  }
  return code;
});

const envRenameCommand = Effect.fn("env-command.envRenameCommand")(function* (
  flags: CommonFlags,
  environmentId: EnvironmentId,
  newName: string,
): Effect.fn.Return<void, CliError, CliServices> {
  const { envRenameOp } = yield* Effect.promise(() =>
    import("./env-rename.ts").then((m) => ({ envRenameOp: m.envRenameOp })),
  );

  const io = yield* CliIo;
  const context = yield* openEnvironment({ ...flags, env: environmentId });
  const renamed = yield* envRenameOp({
    client: context.client,
    verified: context.verified,
    environmentId,
    newName,
    resync: context.resync,
    floor: context.floorHandle,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
  });
  yield* logWarnings(renamed.warnings);
  yield* io.log(
    `Renamed environment ${environmentId} from ${displayText(renamed.previousName)} to ${displayText(renamed.name)} (metaVersion=${renamed.metaVersion})`,
  );
});

const envRmCommand = Effect.fn("env-command.envRmCommand")(function* (
  flags: CommonFlags & { readonly force: boolean },
  environmentId: EnvironmentId,
): Effect.fn.Return<void, CliError, CliServices> {
  const { envRmOp } = yield* Effect.promise(() =>
    import("./env-rm.ts").then((m) => ({ envRmOp: m.envRmOp })),
  );

  const io = yield* CliIo;
  const context = yield* openEnvironment({ ...flags, env: environmentId });
  const deleted = yield* envRmOp({
    client: context.client,
    verified: context.verified,
    environmentId,
    force: flags.force,
    resync: context.resync,
    floor: context.floorHandle,
    signerUserId: context.session.userId,
    signingKeyPair: context.masterKeys.sigKeyPair,
  });
  yield* logWarnings(deleted.warnings);
  yield* io.log(
    `Deleted environment ${environmentId} (${displayText(deleted.name)}; delete_environment at chain seq ${deleted.deletedAtSeq}). Its variables, values and DEK wraps are gone; a signed deletion record remains on the project chain, and the ID ${environmentId} can never be reused`,
  );
});

const envListCommand = Effect.fn("env-command.envListCommand")(function* (
  flags: CommonFlags & { readonly all: boolean; readonly json: boolean },
): Effect.fn.Return<void, CliError, CliServices> {
  const { envListJson, envListOp, formatEnvListRow, shownEnvironmentRows } = yield* Effect.promise(
    () =>
      import("./env-list.ts").then((m) => ({
        envListJson: m.envListJson,
        envListOp: m.envListOp,
        formatEnvListRow: m.formatEnvListRow,
        shownEnvironmentRows: m.shownEnvironmentRows,
      })),
  );

  const io = yield* CliIo;
  const context = yield* openMetadataProject(flags);
  const keys = yield* loadMasterKeys(context.session).pipe(Effect.orElseSucceed(() => null));
  const list = yield* envListOp({
    client: context.client,
    verified: context.verified,
    resync: context.resync,
    userId: context.session.userId,
    ownKeyFingerprintHex: keys?.fingerprintHex ?? null,
  });
  if (list.memberBasisReason !== null) {
    yield* logNote(
      `${list.memberBasisReason}, so in-scope shows your member scope (no device cap is applied)`,
    );
  }
  if (flags.json) {
    yield* io.log(envListJson(list, flags.all));
    return;
  }
  const rows = shownEnvironmentRows(list, flags.all);
  yield* io.log(`Environments (${rows.length}) — verified chain head seq=${list.headSeq}:`);
  for (const row of rows) {
    yield* io.log(`  ${formatEnvListRow(row)}`);
  }
  const hidden = list.rows.length - rows.length;
  if (hidden > 0) {
    yield* logNote(`${countNoun(hidden, "deleted environment")} not shown (--all lists them)`);
  }
});

const envDiffCommand = Effect.fn("env-command.envDiffCommand")(function* (
  flags: CommonFlags,
  environmentId: EnvironmentId,
  otherEnvironmentId: EnvironmentId,
): Effect.fn.Return<void, CliError, CliServices> {
  const { envDiffOp, reportEnvironmentDiff } = yield* Effect.promise(() =>
    import("./env-diff.ts").then((m) => ({
      envDiffOp: m.envDiffOp,
      reportEnvironmentDiff: m.reportEnvironmentDiff,
    })),
  );

  const context = yield* openMetadataEnvironmentPair(flags, environmentId, otherEnvironmentId);
  const diff = yield* envDiffOp({
    client: context.client,
    verified: context.verified,
    resync: context.resync,
    first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
    second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
    commitHead: (verified) => commitVerifiedHead(context.projectId, verified),
  });
  yield* reportEnvironmentDiff(diff);
});

/** @public */
export function makeEnvCommands(onExitCode: (code: number) => void) {
  const envCreate = Command.make(
    "create",
    envCreateConfig,
    Effect.fn("env-command.envCreate")(function* (values) {
      yield* envCreateCommand(values, values["environment-id"]);
    }),
  ).pipe(Command.withDescription("Create an environment"));

  const envRotate = Command.make(
    "rotate",
    envRotateConfig,
    Effect.fn("env-command.envRotate")(function* (values) {
      const { reason, "new-epoch": newEpoch, config: syncConfig, ...flags } = values;
      onExitCode(
        yield* envRotateCommand(
          { ...flags, reason, newEpoch, config: syncConfig },
          values["environment-id"],
        ),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Rotate the environment's epoch DEK, or resume an incomplete re-encryption",
    ),
    Command.validate((values) =>
      values["new-epoch"] && values.reason === undefined
        ? invalidFlagCombination(
            "Specify the rotation reason with --reason (it is recorded on the chain's rotate_epoch entry and cannot be rewritten later)",
          )
        : Effect.void,
    ),
  );

  const envDiff = Command.make(
    "diff",
    envDiffConfig,
    Effect.fn("env-command.envDiff")(function* (values) {
      const environmentId = values["environment-id"];
      const otherEnvironmentId = values["other-environment-id"];
      if (otherEnvironmentId === environmentId) {
        return yield* Effect.fail(
          usageError(
            "The same environment ID was written twice. Specify two different environments to compare",
          ),
        );
      }
      yield* envDiffCommand(values, environmentId, otherEnvironmentId);
    }),
  ).pipe(
    Command.withDescription(
      "Compare the variable-name sets of two environments (names only; no values)",
    ),
  );

  const envRename = Command.make(
    "rename",
    envRenameConfig,
    Effect.fn("env-command.envRename")(function* (values) {
      yield* envRenameCommand(values, values["environment-id"], values["new-name"]);
    }),
  ).pipe(
    Command.withDescription(
      "Rename an environment's display name (the environment ID and every value stay as they are)",
    ),
  );

  const envList = Command.make(
    "list",
    envListConfig,
    Effect.fn("env-command.envList")(function* (values) {
      yield* envListCommand(values);
    }),
  ).pipe(
    Command.withDescription(
      "List the project's environments (ID, display name, status, current epoch, and whether your scope covers it; deleted ones only with --all)",
    ),
  );

  const envRm = Command.make(
    "rm",
    envRmConfig,
    Effect.fn("env-command.envRm")(function* (values) {
      yield* envRmCommand(values, values["environment-id"]);
    }),
  ).pipe(
    Command.withDescription(
      "Delete an environment permanently (admin or owner; asks for confirmation unless --force). Its variables, every stored value version and its DEK wraps are deleted immediately; only its signed delete_environment entry on the project chain remains, and the environment ID can never be reused",
    ),
  );

  const env = Command.make("env").pipe(
    Command.withDescription("Manage environments (create / list / rename / rm / rotate / diff)"),
    Command.withSubcommands([envCreate, envList, envRename, envRm, envRotate, envDiff]),
  );

  return env;
}
