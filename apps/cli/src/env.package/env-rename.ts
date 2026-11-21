import { EnvironmentConflictError } from "@maruhi/api-schema";
import { Effect } from "effect";

import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { rejectIntentOnServerRejection } from "../floor-check.ts";
import type { ManifestFloor } from "../floor.ts";
import {
  confirmAcceptedMetaMutation,
  confirmsIssuedStatement,
  issueManifestWithIntent,
} from "../meta-confirm.ts";
import { retryOnConflict } from "../retry.ts";
import {
  type EnvironmentMetaInput,
  type EnvironmentMetaState,
  isEnvironmentMetaConflict,
  normalizeEnvironmentName,
  requireEnvironmentMetaAuthor,
  resolveEnvironmentMeta,
  signNextEnvironmentStatement,
} from "./env-meta.ts";

const MAX_ATTEMPTS = 5;

interface EnvRenameSummary {
  readonly previousName: string;
  readonly name: string;
  readonly metaVersion: number;
  readonly warnings: readonly string[];
}

const resolveRenameTarget = Effect.fn("env-rename.resolveRenameTarget")(function* (
  input: EnvironmentMetaInput,
  verified: EnvironmentMetaInput["verified"],
  name: string,
): Effect.fn.Return<EnvironmentMetaState, CliError> {
  const state = yield* resolveEnvironmentMeta(input, verified);
  if (state.environment.name === name) {
    return yield* Effect.fail(
      cliError(
        `Environment ${input.environmentId} is already named ${displayText(name)}. Nothing was changed by this run`,
      ),
    );
  }
  return state;
});

interface AcceptedRename {
  readonly state: EnvironmentMetaState;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly selfManifest: ManifestFloor;
  readonly intentId: string;
}

type RenameAttemptError =
  | CliError
  | Effect.Error<ReturnType<EnvironmentMetaInput["client"]["environments"]["rename"]>>;

const attemptRename = Effect.fn("env-rename.attemptRename")(function* (
  input: EnvironmentMetaInput,
  state: EnvironmentMetaState,
  name: string,
): Effect.fn.Return<AcceptedRename, RenameAttemptError> {
  const signingKey = input.signingKeyPair.privateKey;
  const signed = yield* signNextEnvironmentStatement({
    state,
    environmentId: input.environmentId,
    name,
    authorUserId: input.signerUserId,
    signingKey,
  });
  const { manifest, intentId } = yield* issueManifestWithIntent({
    verified: state.verified,
    environmentId: input.environmentId,
    epoch: state.currentEpoch,
    previous: state.manifestBase.previous,
    entries: state.manifestBase.entries,
    envMeta: { metaVersion: signed.metaVersion, sigHashHex: signed.metaSigHashHex },
    issuerUserId: input.signerUserId,
    signingKey,
    floor: input.floor,
    variableId: null,
  });
  yield* input.client.environments
    .rename({
      params: { projectId: state.verified.projectId, environmentId: input.environmentId },
      payload: { statement: signed.statement, manifest: manifest.manifest },
    })
    .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
  return {
    state,
    metaVersion: signed.metaVersion,
    metaSigHashHex: signed.metaSigHashHex,
    selfManifest: {
      manifestVersion: manifest.manifestVersion,
      epoch: manifest.epoch,
      manifestSigHashHex: manifest.manifestSigHashHex,
    },
    intentId,
  };
});

function renameRefusal(error: RenameAttemptError, name: string): CliError | null {
  if (error instanceof EnvironmentConflictError && error.reason === "duplicate-name") {
    return cliError(
      `Another environment in this project is already named ${displayText(name)} (display names are unique among the environments that are not deleted). Choose a different name`,
    );
  }
  return null;
}

export const envRenameOp = Effect.fn("env-rename.envRenameOp")(function* (
  input: EnvironmentMetaInput & { readonly newName: string },
): Effect.fn.Return<EnvRenameSummary, CliError> {
  const name = yield* normalizeEnvironmentName(input.newName);
  yield* requireEnvironmentMetaAuthor(input, {
    minimumRole: "member",
    operation: "rename an environment",
    forbidden:
      "A reader cannot rename environments (an environment rename requires the member role or above — AUTH_SPEC §12-3)",
  });
  const initial = yield* resolveRenameTarget(input, input.verified, name);
  const accepted = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) =>
      attemptRename(input, state, name).pipe(
        Effect.mapError((error) => renameRefusal(error, name) ?? error),
      ),
    classify: (error) => (isEnvironmentMetaConflict(error) ? "re-resolve" : null),
    recover: (state) => resolveRenameTarget(input, state.verified, name),
    exhaustedMessage: `The rename conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  });
  yield* confirmAcceptedMetaMutation(input, accepted, "environment rename", (metadata, issued) =>
    confirmsIssuedStatement(metadata.environment, issued),
  );
  return {
    previousName: accepted.state.environment.name,
    name,
    metaVersion: accepted.metaVersion,
    warnings: accepted.state.warnings,
  };
});
