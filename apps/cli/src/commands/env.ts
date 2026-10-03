// `maruhi env` (discipline: see commands/index.ts).

import { type EnvironmentId, isEnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import { Argument, Command } from "effect/cli";

import { ANCHOR_STALE_AFTER_ROTATION } from "../checkpoint.ts";
import {
  type CliServices,
  type CommonFlags,
  commitVerifiedHead,
  floorHandleFor,
  openEnvironment,
  openMetadataEnvironmentPair,
  openProject,
} from "../context.ts";
import { countNoun } from "../display.ts";
import { envCreateOp } from "../env-create.ts";
import { envDiffOp, reportEnvironmentDiff } from "../env-diff.ts";
import { envRotateOp } from "../env-rotate.ts";
import { CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { reportRotation } from "../rotation-report.ts";
import { loadSyncConfig } from "../sync-config.ts";
import { advanceReceiptsAfterRotation, checkRotateConfigProject } from "../sync-rotate.ts";
import { NonBlank, projectFlags, singleFlag, singleValued } from "./flags.ts";

/** The environment ID positional (shared by env's subcommands. The key is the spelling typed). */
const environmentIdArgument = (name: string, description: string) =>
  Argument.String(name).pipe(Argument.withDescription(description), Argument.withSchema(NonBlank));

export const envCreateConfig = {
  ...projectFlags(),
  name: singleValued("name", "Display name (defaults to the environment ID)"),
  // The key is **the spelling typed** (specOf uses it as the diagnostic name as-is)
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

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
  // The sync receipt advances only when given (no implicit discovery of
  // the default path — rotate can be run from outside a repository and the
  // config is cwd-dependent)
  config: singleValued(
    "config",
    `Path to the sync config committed in the repository; when given, the receipts of the targets synced from this environment advance to the re-encrypted versions (no default: without it, receipts are left alone)`,
  ),
  "environment-id": environmentIdArgument("environment-id", "Environment ID (e.g. dev / prod)"),
};

export const envDiffConfig = {
  ...projectFlags(),
  "environment-id": environmentIdArgument("environment-id", "First environment ID to compare"),
  // Declared **required** since it is a diff-only subcommand (a missing one is MissingArgument)
  "other-environment-id": environmentIdArgument(
    "other-environment-id",
    "Second environment ID to compare",
  ),
};

/**
 * `maruhi env create <id>`'s body (the composite request — §12-4).
 */
function envCreateCommand(
  flags: CommonFlags & { readonly name?: string | undefined },
  environmentId: string,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
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
      // The member count is the size of **the wrap set actually
      // registered** (when rebuilt under a CAS retry, it may disagree with
      // the run-start view's member count)
      `Created environment ${environmentId} (epoch=${created.currentEpoch}, DEK wrapped for ${countNoun(created.memberCount, "current member")})`,
    );
  });
}

/** Format validation of an environment ID passed as a positional (**the given value itself never appears in the error**). */
function requireEnvironmentId(
  value: string,
  example: string,
): Effect.Effect<EnvironmentId, CliError> {
  return isEnvironmentId(value)
    ? Effect.succeed(value)
    : Effect.fail(
        usageError(
          `Invalid environment ID (must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or -. Example: ${example})`,
        ),
      );
}

/** `maruhi env rotate <id> [--reason <text>] [--new-epoch]` (§7 / §12-4). */
function envRotateCommand(
  flags: CommonFlags & {
    readonly reason?: string | undefined;
    readonly newEpoch?: boolean | undefined;
    readonly config?: string | undefined;
  },
  environmentId: EnvironmentId,
): Effect.Effect<number, CliError, CliServices> {
  return Effect.gen(function* () {
    // The sync config (M1) is read **before any network**: detecting a
    // broken file or another project's config is never placed behind the
    // epoch advance (failing after advancing would make the rotation look
    // failed over a cleanup omission)
    const syncConfig = flags.config === undefined ? null : yield* loadSyncConfig(flags.config);
    // Opened as an environment context to use the environment floor (§6.3)
    // (the environment is fixed by the positional). Being a convergent
    // command, the always-on warning of unconverged duties is suppressed
    // (this command's own rotation report conveys the same fact —
    // context.ts's OpenProjectOptions)
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
      // Unspecified (undefined) and an empty string are passed as
      // **distinct values**: an empty `--reason` is dropped by the
      // declaration (NonBlank) with exit 2, so an undefined reaching here
      // is only a run **without `--reason` itself** (env-rotate's
      // checkReasonLength stays as a defense line)
      reason: flags.reason,
      forceNewEpoch: flags.newEpoch === true,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
      floor: context.floorHandle,
    });
    // "Was a new epoch requested" is fixed by the launch-time flag
    // (--reason is required only on the path that creates a new epoch —
    // env-rotate.ts's requireReason)
    const code = yield* reportRotation(
      environmentId,
      summary,
      flags.newEpoch === true || flags.reason !== undefined,
    );
    if (summary.mode === "rotated") {
      // The anchor-update proposal (CRYPTO_SPEC §6.3 (b)): an advanced
      // epoch = the committed anchor's epoch floor went stale. Emitted
      // **before** the cleanup: even when the cleanup fails on evidence,
      // the fact the epoch advanced and the anchor's staleness do not
      // change
      yield* logNote(ANCHOR_STALE_AFTER_ROTATION);
    }
    if (syncConfig !== null) {
      // Cleanup: the receipt advances to the new version only for the
      // accepted re-encryptions. A failure stays a warning and the exit
      // code remains the rotation's report (sync-rotate.ts). When the
      // receipt environment is the rotated environment itself, the same
      // floor handle is reused (never open two handles on one
      // environment)
      const receiptsFloor =
        syncConfig.receiptsEnvironment === environmentId
          ? context.floorHandle
          : yield* floorHandleFor(context, syncConfig.receiptsEnvironment);
      yield* advanceReceiptsAfterRotation({
        client: context.client,
        // The rotation advanced the chain: the cleanup starts from the
        // resynced verified view (checked to be an extension of
        // openEnvironment's view). A resync communication failure is
        // folded into a warning inside the cleanup
        verified: context.verified,
        recipient: context.recipient,
        resync: context.resync,
        config: syncConfig,
        environmentId,
        written: summary.written,
        receiptsFloor,
        writerUserId: context.session.userId,
        signingKey: context.masterKeys.sigKeyPair.privateKey,
        now: () => new Date(),
      });
    }
    return code;
  });
}

/**
 * `maruhi env diff <a> <b>`: compares the two environments' **variable
 * name sets** (values are neither fetched nor decrypted). A difference
 * leaves the exit code 0: "a difference exists" is a **report content** of
 * a successful run, not a run failure — mixing it into 1 would make it
 * indistinguishable from a verification failure / floor violation (=
 * evidence of a malicious server) or a communication failure.
 */
function envDiffCommand(
  flags: CommonFlags,
  environmentId: EnvironmentId,
  otherEnvironmentId: EnvironmentId,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    // The prologue (chain sync + §6.3 verification) runs exactly once. The
    // master key is not required (nothing is decrypted — context.ts's
    // openMetadataProjectWith)
    const context = yield* openMetadataEnvironmentPair(flags, environmentId, otherEnvironmentId);
    const diff = yield* envDiffOp({
      client: context.client,
      verified: context.verified,
      resync: context.resync,
      first: { environmentId: context.first.environmentId, floor: context.first.floorHandle },
      second: { environmentId: context.second.environmentId, floor: context.second.floorHandle },
      // No environment-level meta floor is built (no values were read),
      // but the **chain floor's head** advances the same as pull / push.
      // Recording happens per pull (envDiffOp)
      commitHead: (verified) => commitVerifiedHead(context.projectId, verified),
    });
    yield* reportEnvironmentDiff(diff);
  });
}

export function makeEnvCommands(onExitCode: (code: number) => void) {
  const envCreate = Command.make("create", envCreateConfig, (values) =>
    Effect.gen(function* () {
      // The format is an additional check after the declaration (NonBlank). Seen before the network
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env create dev`",
      );
      yield* envCreateCommand(values, environmentId);
    }),
  ).pipe(Command.withDescription("Create an environment"));

  const envRotate = Command.make("rotate", envRotateConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env rotate dev`",
      );
      const { reason, "new-epoch": newEpoch, config: syncConfig, ...flags } = values;
      onExitCode(
        yield* envRotateCommand({ ...flags, reason, newEpoch, config: syncConfig }, environmentId),
      );
    }),
  ).pipe(
    Command.withDescription(
      "Rotate the environment's epoch DEK, or resume an incomplete re-encryption",
    ),
  );

  const envDiff = Command.make("diff", envDiffConfig, (values) =>
    Effect.gen(function* () {
      const environmentId = yield* requireEnvironmentId(
        values["environment-id"],
        "`maruhi env diff dev prod`",
      );
      const otherEnvironmentId = yield* requireEnvironmentId(
        values["other-environment-id"],
        "`maruhi env diff dev prod`",
      );
      if (otherEnvironmentId === environmentId) {
        // Comparing an environment with itself is always empty = the
        // request itself is a misspelling. The given values are not shown
        // (a positional could carry a value)
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

  // The nested subcommands remove the need to hand-write the refusal of
  // "an option that does not apply to that operation"
  const env = Command.make("env").pipe(
    Command.withDescription("Manage environments (create / rotate / diff)"),
    Command.withSubcommands([envCreate, envRotate, envDiff]),
  );

  return env;
}
