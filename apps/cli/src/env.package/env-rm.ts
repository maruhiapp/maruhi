import { ChainHeadConflictError } from "@maruhi/api-schema";
import { Effect, Stdio } from "effect";

import { signEntryAtHead } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { confirmPermanentDeletion, noteConcurrentRename } from "../deletion-confirm.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { rejectIntentOnServerRejection } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { retryOnConflict } from "../retry.ts";
import { flaggedVariablesOf } from "../rotation.ts";
import { deletedEnvironmentMessage } from "../scope.ts";
import {
  type EnvironmentMetaInput,
  type EnvironmentMetaState,
  requireEnvironmentMetaAuthor,
  resolveEnvironmentMeta,
} from "./env-meta.ts";

const MAX_ATTEMPTS = 5;

interface EnvRmSummary {
  readonly name: string;
  readonly deletedAtSeq: number;
  readonly warnings: readonly string[];
}

const resolveDeletionTarget = Effect.fn("env-rm.resolveDeletionTarget")(function* (
  input: EnvironmentMetaInput,
  verified: VerifiedProject,
): Effect.fn.Return<EnvironmentMetaState, CliError> {
  const deletedAtSeq = verified.state.environments.get(input.environmentId)?.deletedAtSeq ?? null;
  if (deletedAtSeq !== null) {
    return yield* Effect.fail(
      cliError(
        `${deletedEnvironmentMessage(input.environmentId, deletedAtSeq)}. Nothing was changed by this run`,
      ),
    );
  }
  return yield* resolveEnvironmentMeta(input, verified);
});

const recordVariableNames = Effect.fn("env-rm.recordVariableNames")(function* (
  input: EnvironmentMetaInput,
  state: EnvironmentMetaState,
): Effect.fn.Return<void, never, CliIo> {
  if (state.variableNames.length === 0) {
    return;
  }
  const io = yield* CliIo;
  const flagged = yield* flaggedVariablesOf(
    input.client,
    state.verified.projectId,
    input.environmentId,
  ).pipe(
    Effect.catch((error) =>
      Effect.as(
        logNote(
          `could not read the rotation flags (${error.message}) — check \`maruhi rotation list\` before deleting`,
        ),
        null,
      ),
    ),
  );
  yield* io.logError(
    `Variables of environment ${input.environmentId} by their verified names (after the deletion none of these names can be verified again, so a rotation flag on one of them shows only its variable ID):`,
  );
  for (const variable of state.variableNames) {
    const notes = [
      ...(variable.deleted ? ["deleted earlier"] : []),
      ...(flagged?.has(variable.variableId) === true ? ["rotation flag open"] : []),
    ];
    yield* io.logError(
      `  ${displayText(variable.name)} (${displayText(variable.variableId)})${notes.length === 0 ? "" : ` — ${notes.join(", ")}`}`,
    );
  }
  if (flagged !== null && flagged.size > 0) {
    yield* io.logError(
      "The open rotation flags outlive the deletion: the upstream credentials behind them still need rotating, and the flags close only by dismissal — keep this list of names",
    );
  }
});

function ensureDeletionConfirmed(
  input: EnvironmentMetaInput & { readonly force: boolean },
  state: EnvironmentMetaState,
): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return confirmPermanentDeletion(input.force, {
    label: `environment ${input.environmentId} (${displayText(state.environment.name)})`,
    consequence:
      "every variable in it, every stored value version and every wrapped DEK is deleted immediately and cannot be recovered; only its signed deletion record remains",
    irreversibility: "the environment cannot be restored and its ID can never be reused",
    refusalReason: "deletion is terminal and destroys every value stored in the environment",
    typedNoun: "environment ID",
    mismatchNoun: "ID",
    expected: input.environmentId,
  });
}

interface AcceptedDeletion {
  readonly state: EnvironmentMetaState;
  readonly seq: number;
  readonly signatureHex: string;
  readonly intentId: string;
}

type DeletionAttemptError =
  | CliError
  | Effect.Error<ReturnType<EnvironmentMetaInput["client"]["environments"]["remove"]>>;

const attemptDeletion = Effect.fn("env-rm.attemptDeletion")(function* (
  input: EnvironmentMetaInput,
  state: EnvironmentMetaState,
): Effect.fn.Return<AcceptedDeletion, DeletionAttemptError> {
  const entry = yield* signEntryAtHead({
    verified: state.verified,
    signerUserId: input.signerUserId,
    operation: { op: "delete_environment", payload: { environmentId: input.environmentId } },
    signingKeyPair: input.signingKeyPair,
  });
  if (entry.op !== "delete_environment") {
    return yield* Effect.fail(cliError("Failed to sign the delete_environment entry"));
  }
  const declaredHead = {
    seq: state.verified.state.headSeq,
    hashHex: state.verified.state.headHashHex,
  };
  const intentId = yield* input.floor.appendIntent({
    op: "delete_environment",
    environmentId: input.environmentId,
    declaredHead,
  });
  yield* input.client.environments
    .remove({
      params: { projectId: state.verified.projectId, environmentId: input.environmentId },
      payload: { parentHeadHashHex: declaredHead.hashHex, entry },
    })
    .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
  return { state, seq: entry.seq, signatureHex: entry.signatureHex, intentId };
});

const confirmDeletion = Effect.fn("env-rm.confirmDeletion")(function* (
  input: EnvironmentMetaInput,
  accepted: AcceptedDeletion,
): Effect.fn.Return<void, CliError> {
  const view = yield* resyncExtended(input.resync, accepted.state.verified).pipe(
    Effect.mapError((error) =>
      cliError(
        `The environment deletion was accepted (2xx), but the chain sync for the post-acceptance confirmation failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}. Re-run any command against this project after restoring connectivity; the recorded intent will be reconciled against the chain`,
      ),
    ),
  );
  const landed = view.entries[accepted.seq - 1];
  const confirmed =
    landed !== undefined &&
    landed.op === "delete_environment" &&
    landed.signatureHex === accepted.signatureHex &&
    view.state.environments.get(input.environmentId)?.deletedAtSeq === accepted.seq;
  if (!confirmed) {
    return yield* Effect.fail(
      cliError(
        `The environment deletion was accepted (2xx), but the verified chain does not carry this run's delete_environment entry at seq ${accepted.seq}. The server response contradicts the chain — treating the environment deletion as unconfirmed (AUTH_SPEC §12-10 (3)); re-run \`maruhi env rm\` after investigating the server`,
      ),
    );
  }
  yield* Effect.ignore(input.floor.resolveIntent(accepted.intentId, "accepted"));
});

export const envRmOp = Effect.fn("env-rm.envRmOp")(function* (
  input: EnvironmentMetaInput & { readonly force: boolean },
): Effect.fn.Return<EnvRmSummary, CliError, CliIo | Stdio.Stdio> {
  yield* requireEnvironmentMetaAuthor(input, {
    minimumRole: "admin",
    operation: "delete an environment",
    forbidden:
      "Only admins and owners can delete environments (an environment deletion requires the admin role or above — AUTH_SPEC §12-3)",
  });
  const initial = yield* resolveDeletionTarget(input, input.verified);
  yield* recordVariableNames(input, initial);
  yield* ensureDeletionConfirmed(input, initial);
  const accepted = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) => attemptDeletion(input, state),
    classify: (error) => (error instanceof ChainHeadConflictError ? "re-resolve" : null),
    recover: (state) =>
      resyncExtended(input.resync, state.verified).pipe(
        Effect.flatMap((fresh) => resolveDeletionTarget(input, fresh)),
        Effect.tap((next) =>
          noteConcurrentRename({
            subject: `Environment ${input.environmentId}`,
            seenName: initial.environment.name,
            currentName: next.environment.name,
          }),
        ),
      ),
    exhaustedMessage: `The deletion conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  }).pipe(Effect.mapError((error) => (error instanceof Error ? toCliError(error) : error)));
  yield* confirmDeletion(input, accepted);
  return {
    name: accepted.state.environment.name,
    deletedAtSeq: accepted.seq,
    warnings: accepted.state.warnings,
  };
});
