// `maruhi env rm <environment-id>` — deleting an environment (AUTH_SPEC
// §12-4's deletion composite; CRYPTO_SPEC §6.2 `delete_environment` — admin
// or above with the environment in the signing device's scope).
//
// The request carries the signed `delete_environment` chain entry appended
// onto the verified head (parent-head CAS). The server appends it and
// deletes the environment's variables, versions (ciphertexts), DEK wraps,
// variable and environment statements, manifest and checkpoint value
// snapshot in the same transaction. The chain entry is the deletion's
// record: every client that verifies the chain treats the environment as
// deleted and refuses any distribution of it (a server that hides the
// deletion must roll the chain back; one that serves the environment as live
// is refused — §6.3), and the ID can never be reused (§6.2).
//
// Deletion is terminal and destroys every value, so it is gated by the same
// explicit confirmation as `maruhi var rm` (deletion-confirm.ts: retyping
// the environment ID interactively, or --force).
//
// Journal-before-send (3-F — §6.3's recording discipline (ii)): an intent
// (op delete_environment, the environment, the declared head) is appended
// before sending, so a lost response or a crash leaves the duty to confirm;
// the next run's prologue reconciles it against the chain slot after the
// declared head (context.ts).
//
// Effect confirmation (1-E′ — §12-10 (3)): a 2xx is a transport fact; the
// deletion counts as done only once a chain sync shows this run's own
// entry on the verified chain.

import { ChainHeadConflictError } from "@maruhi/api-schema";
import { Effect, Stdio } from "effect";

import { signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { deletedEnvironmentMessage } from "./deks.ts";
import { confirmPermanentDeletion, noteConcurrentRename } from "./deletion-confirm.ts";
import { displayText } from "./display.ts";
import {
  type EnvironmentMetaInput,
  type EnvironmentMetaState,
  requireEnvironmentMetaAuthor,
  resolveEnvironmentMeta,
} from "./env-meta.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { rejectIntentOnServerRejection } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { retryOnConflict } from "./retry.ts";

const MAX_ATTEMPTS = 5;

interface EnvRmSummary {
  /** The deleted environment's last verified display name. */
  readonly name: string;
  /** The chain seq of this run's delete_environment entry. */
  readonly deletedAtSeq: number;
  readonly warnings: readonly string[];
}

/**
 * Resolves the deletion target on a verified view: an environment the
 * chain already shows as deleted is a typed error (deletion is terminal —
 * the desired state holds, but this run's precondition does not);
 * otherwise the verified current statement (its name drives the
 * confirmation).
 */
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

/** The explicit confirmation (fail-closed): retyping the environment ID, or --force. */
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
  /** This run's delete_environment entry (seq = the declared head + 1). */
  readonly seq: number;
  readonly signatureHex: string;
  readonly intentId: string;
}

/** One attempt's failure channel: own failures plus the environments.remove endpoint's declared errors. */
type DeletionAttemptError =
  | CliError
  | Effect.Error<ReturnType<EnvironmentMetaInput["client"]["environments"]["remove"]>>;

/** One attempt (sign the entry at the verified head, record the intent, send). */
const attemptDeletion = Effect.fn("env-rm.attemptDeletion")(function* (
  input: EnvironmentMetaInput,
  state: EnvironmentMetaState,
): Effect.fn.Return<AcceptedDeletion, DeletionAttemptError> {
  const entry = yield* signEntryAtHead({
    verified: state.verified,
    signerUserId: input.signerUserId,
    operation: { op: "delete_environment", payload: { environmentId: input.environmentId } },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the delete_environment entry",
  });
  if (entry.op !== "delete_environment") {
    return yield* Effect.fail(cliError("Failed to sign the delete_environment entry"));
  }
  const declaredHead = {
    seq: state.verified.state.headSeq,
    hashHex: state.verified.state.headHashHex,
  };
  // journal-before-send (3-F): if persisting the intent fails, nothing is
  // sent (fail-closed)
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
    .pipe(
      // A refusal with the server's own error body (CAS 409 included) =
      // the effect did not occur (settled) — close the intent
      Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)),
    );
  return { state, seq: entry.seq, signatureHex: entry.signatureHex, intentId };
});

/**
 * Effect confirmation (1-E′ — §12-10 (3)): a chain sync must show this
 * run's own entry — the delete_environment at its seq — on the verified
 * chain.
 */
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
  // An intent left open is the safe direction (the next run's
  // reconciliation redoes the same decision)
  yield* Effect.ignore(input.floor.resolveIntent(accepted.intentId, "accepted"));
});

/**
 * Deletes an environment (AUTH_SPEC §12-4): an admin-signed
 * `delete_environment` chain entry at the verified head, gated by an
 * explicit confirmation (interactive ID re-entry, or --force), retried on a
 * chain-head CAS conflict over a re-synced view (the head moved — including
 * a concurrent deletion, which then surfaces as "already deleted"), and
 * confirmed against the verified chain before success is reported (1-E′ —
 * §12-10 (3)).
 */
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
  // The confirmation happens exactly once, before signing, sending and the
  // retry loop. It binds the environment ID, which is never reused (§6.2),
  // so a re-resolution after a conflict cannot land on another environment
  yield* ensureDeletionConfirmed(input, initial);
  const accepted = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) => attemptDeletion(input, state),
    classify: (error) => (error instanceof ChainHeadConflictError ? "re-resolve" : null),
    // The head moved: re-sync → re-verify → re-sign at the new head (the
    // entry's prev is signed). A concurrent deletion surfaces as the
    // determinate "already deleted" error; a concurrent rename re-resolves
    // the name, saying so when it differs from the one the confirmation
    // showed
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
