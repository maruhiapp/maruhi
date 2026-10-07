// `maruhi env rename <environment-id> <new-name>` — renaming an environment
// (AUTH_SPEC §12-4 → the §12-5 meta rules).
//
// Only the display name changes: the environment ID is the crypto context
// (CRYPTO_SPEC §3) and never changes, so no value is re-encrypted. The
// request bundles the rename statement (metaVersion + 1, prev chained to
// the verified current statement, declared head = the last verified head)
// with the next manifest (manifestVersion + 1 — the meta set is unchanged
// and envMeta copies the new statement's signed-bytes hash; CRYPTO_SPEC
// §4.3). The server decides the metaVersion CAS and the manifestVersion CAS
// in one transaction; a 409 on either refetches, re-verifies and re-signs
// both (§12-5).
//
// Rides the existing meta-operation discipline: 3-F (journal-before-send —
// issueManifestWithIntent) + 1-E′ (effect confirmation against the verified
// distribution — confirmMetaMutation). The confirmation pull itself joins
// the new environment statement and manifest into the floor.

import { EnvironmentConflictError } from "@maruhi/api-schema";
import { Effect } from "effect";

import { displayText } from "./display.ts";
import {
  type EnvironmentMetaInput,
  type EnvironmentMetaState,
  isEnvironmentMetaConflict,
  normalizeEnvironmentName,
  requireEnvironmentMetaAuthor,
  resolveEnvironmentMeta,
  signNextEnvironmentStatement,
} from "./env-meta.ts";
import { cliError, type CliError } from "./errors.ts";
import { rejectIntentOnServerRejection } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import {
  confirmAcceptedMetaMutation,
  confirmsIssuedStatement,
  issueManifestWithIntent,
} from "./meta-confirm.ts";
import { retryOnConflict } from "./retry.ts";

const MAX_ATTEMPTS = 5;

interface EnvRenameSummary {
  readonly previousName: string;
  readonly name: string;
  readonly metaVersion: number;
  readonly warnings: readonly string[];
}

/** Resolves the verified current statement and refuses a rename that would change nothing. */
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

/** One attempt's failure channel: own failures plus the environments.rename endpoint's declared errors. */
type RenameAttemptError =
  | CliError
  | Effect.Error<ReturnType<EnvironmentMetaInput["client"]["environments"]["rename"]>>;

/** One attempt (sign the statement and the manifest, journal the intent, send). */
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
  // The meta set is unchanged; envMeta copies the new statement (§4.3).
  // The 3-F intent is persisted before sending
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

/** The rename refusals that have a more precise reading than the generic rendering. */
function renameRefusal(error: RenameAttemptError, name: string): CliError | null {
  if (error instanceof EnvironmentConflictError && error.reason === "duplicate-name") {
    return cliError(
      `Another environment in this project is already named ${displayText(name)} (display names are unique among the environments that are not deleted). Choose a different name`,
    );
  }
  return null;
}

/**
 * Renames an environment (AUTH_SPEC §12-4): a signed rename statement +
 * the next manifest, retried on a metaVersion / manifestVersion CAS conflict
 * with both re-signed over a re-verified view (§12-5), and confirmed against
 * the verified distribution (1-E′ — §12-10 (3)) before success is reported.
 */
export const envRenameOp = Effect.fn("env-rename.envRenameOp")(function* (
  input: EnvironmentMetaInput & { readonly newName: string },
): Effect.fn.Return<EnvRenameSummary, CliError> {
  // Normalization's agent is the client before signing (§4.2 / §12-1)
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
    // A concurrent meta operation re-resolves (refetch → verify → re-sign
    // both the statement and the manifest — §12-5). A concurrent rename to
    // the same name surfaces as the determinate "already named" error, and
    // a concurrent deletion as the pull's refusal
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
