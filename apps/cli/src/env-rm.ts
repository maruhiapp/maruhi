// `maruhi env rm <environment-id>` — deleting an environment (AUTH_SPEC
// §12-4 → the §12-5 meta rules; admin or above — §12-3).
//
// The request carries only the signed deletion statement: status deleted,
// name = the immediately preceding active name (CRYPTO_SPEC §4.2 — the
// server refuses any other name with 422 payload-mismatch), metaVersion + 1
// with prev chained to the verified current statement. **No manifest is
// re-issued** (§12-4): the server deletes the environment's variables,
// versions (ciphertexts), DEK wraps, variable statements (tombstones
// included), manifests and checkpoint value snapshot immediately, so no
// distribution channel remains for them; the environment row stays as a
// tombstone whose deletion statement keeps being distributed in the
// environment list (the detection material for a denied or silently
// revived deletion). The ID can never be reused (CRYPTO_SPEC §6.2 — the
// chain does not observe deletion).
//
// Deletion is terminal and destroys every value, so it is gated by the same
// explicit confirmation as `maruhi var rm` (deletion-confirm.ts: retyping
// the environment ID interactively, or --force).
//
// Effect confirmation (1-E′ — §12-10 (3)): a 2xx is a transport fact; the
// deletion counts as done only once the environment list distributes a
// verified deletion statement at or past the issued one. There is no 3-F
// intent: an intent records a manifest coordinate to reconcile on a later
// pull, and a deleted environment has neither a manifest nor a pull — a
// lost response is settled by re-running, which finds the verified
// tombstone and reports the environment as already deleted.

import { PayloadMismatchError } from "@maruhi/api-schema";
import { Effect, Stdio } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { confirmPermanentDeletion, noteConcurrentRename } from "./deletion-confirm.ts";
import { displayText } from "./display.ts";
import {
  type EnvironmentMetaInput,
  type EnvironmentMetaState,
  isEnvironmentMetaConflict,
  requireEnvironmentMetaAuthor,
  resolveEnvironmentMeta,
  signNextEnvironmentStatement,
} from "./env-meta.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedEnvironmentStatement } from "./floor-check.ts";
import { CliIo } from "./io.ts";
import { confirmsIssuedStatement } from "./meta-confirm.ts";
import { retryOnConflict } from "./retry.ts";
import { verifyEnvironmentTombstone } from "./values-verify.ts";

const MAX_ATTEMPTS = 5;

interface EnvRmSummary {
  /** The deleted environment's last active name (kept by the deletion statement — §4.2). */
  readonly name: string;
  readonly metaVersion: number;
  readonly warnings: readonly string[];
}

/**
 * The verified deletion statement the environment list distributes for this
 * environment (the highest metaVersion when several verify), or null when
 * none is listed. A listed deletion statement that fails verification is a
 * refusal, never silently treated as "not deleted".
 */
const listedEnvironmentTombstone = Effect.fn("env-rm.listedEnvironmentTombstone")(function* (
  input: EnvironmentMetaInput,
  verified: VerifiedProject,
): Effect.fn.Return<VerifiedEnvironmentStatement | null, CliError> {
  const listed = yield* input.client.environments
    .list({ params: { projectId: verified.projectId } })
    .pipe(Effect.mapError(toCliError));
  let latest: VerifiedEnvironmentStatement | null = null;
  for (const entry of listed.environments) {
    if (entry.environmentId !== input.environmentId) {
      continue;
    }
    const outcome = yield* Effect.promise(() =>
      verifyEnvironmentTombstone(verified, input.environmentId, entry.statement),
    );
    if (outcome === null) {
      continue;
    }
    if (outcome.kind === "future") {
      return yield* Effect.fail(
        cliError(
          `The deletion statement listed for environment ${input.environmentId} declares a chain head this run has not verified yet. Re-run the command to resync`,
        ),
      );
    }
    if (outcome.kind === "rejected") {
      return yield* Effect.fail(
        outcome.evidence ? evidenceError(outcome.message) : cliError(outcome.message),
      );
    }
    if (latest === null || outcome.value.metaVersion > latest.metaVersion) {
      latest = outcome.value;
    }
  }
  return latest;
});

/** Resolves the deletion target: an already-deleted environment is a typed error, otherwise the verified current statement. */
const resolveDeletionTarget = Effect.fn("env-rm.resolveDeletionTarget")(function* (
  input: EnvironmentMetaInput,
  verified: VerifiedProject,
): Effect.fn.Return<EnvironmentMetaState, CliError> {
  const tombstone = yield* listedEnvironmentTombstone(input, verified);
  if (tombstone !== null) {
    // Deletion is terminal (§4.2) — the desired state holds, but this
    // run's precondition (it deletes the environment) does not
    return yield* Effect.fail(
      cliError(
        `Environment ${input.environmentId} (${displayText(tombstone.name)}) is already deleted (deletion is terminal — a deleted environment cannot be restored). Nothing was changed by this run`,
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
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

/** One attempt's failure channel: own failures plus the environments.remove endpoint's declared errors. */
type DeletionAttemptError =
  | CliError
  | Effect.Error<ReturnType<EnvironmentMetaInput["client"]["environments"]["remove"]>>;

/** One attempt (sign the deletion statement, send). */
const attemptDeletion = Effect.fn("env-rm.attemptDeletion")(function* (
  input: EnvironmentMetaInput,
  state: EnvironmentMetaState,
): Effect.fn.Return<AcceptedDeletion, DeletionAttemptError> {
  const signed = yield* signNextEnvironmentStatement({
    state,
    environmentId: input.environmentId,
    // name keeps the last active name as-is (§4.2 — deletion never empties it)
    name: state.environment.name,
    status: "deleted",
    authorUserId: input.signerUserId,
    signingKey: input.signingKeyPair.privateKey,
  });
  yield* input.client.environments.remove({
    params: { projectId: state.verified.projectId, environmentId: input.environmentId },
    payload: { statement: signed.statement },
  });
  return { state, metaVersion: signed.metaVersion, metaSigHashHex: signed.metaSigHashHex };
});

/**
 * The deletion refusal the generic rendering would misdescribe:
 * payload-mismatch here is about the statement, not a value's AAD — the
 * server stores a different active name than the one signed (§4.2). The
 * server judges it after the metaVersion CAS (§12-5's check order), so it is
 * never a concurrent rename (that is a 409, retried): the statement was
 * signed over the verified current state and the server disagrees — a hard
 * stop, not retried.
 */
function deletionRefusal(
  input: EnvironmentMetaInput,
  error: DeletionAttemptError,
): CliError | null {
  return error instanceof PayloadMismatchError
    ? cliError(
        `The server refused the deletion statement: its ${displayText(error.field)} does not match environment ${input.environmentId}'s current state (payload-mismatch — a deletion must keep the last active name). It was signed over the verified current state, so the server disagrees with what it distributes — investigate the server before retrying`,
      )
    : null;
}

/**
 * Effect confirmation (1-E′ — §12-10 (3)): the environment list must
 * distribute a verified deletion statement at or past the issued one.
 */
const confirmDeletion = Effect.fn("env-rm.confirmDeletion")(function* (
  input: EnvironmentMetaInput,
  accepted: AcceptedDeletion,
): Effect.fn.Return<void, CliError> {
  const tombstone = yield* listedEnvironmentTombstone(input, accepted.state.verified).pipe(
    Effect.mapError((error) =>
      cliError(
        `The environment deletion was accepted (2xx), but the post-acceptance confirmation against the verified environment list failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}`,
      ),
    ),
  );
  if (tombstone === null || !confirmsIssuedStatement(tombstone, accepted)) {
    return yield* Effect.fail(
      cliError(
        `The environment deletion was accepted (2xx), but the environment list does not distribute a verified deletion statement at the issued metaVersion ${accepted.metaVersion} or later. Treating the environment deletion as unconfirmed (AUTH_SPEC §12-10 (3)) — re-run \`maruhi env rm\` after investigating the server`,
      ),
    );
  }
});

/**
 * Deletes an environment (AUTH_SPEC §12-4): an admin-signed deletion
 * statement (status deleted, the last active name, metaVersion + 1), gated
 * by an explicit confirmation (interactive ID re-entry, or --force),
 * retried on a metaVersion CAS conflict over a re-verified view (§12-5), and
 * confirmed against the verified environment list before success is
 * reported (1-E′ — §12-10 (3)).
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
    attempt: (state) =>
      attemptDeletion(input, state).pipe(
        Effect.mapError((error) => deletionRefusal(input, error) ?? error),
      ),
    classify: (error) => (isEnvironmentMetaConflict(error) ? "re-resolve" : null),
    // A concurrent meta operation (a rename) re-resolves: refetch → verify
    // → re-sign with the then-current name (§12-5), saying so when the
    // name differs from the one the confirmation showed. Losing to a
    // concurrent deletion surfaces as the determinate "already deleted"
    // error
    recover: (state) =>
      resolveDeletionTarget(input, state.verified).pipe(
        Effect.tap((next) =>
          noteConcurrentRename({
            subject: `Environment ${input.environmentId}`,
            seenName: initial.environment.name,
            currentName: next.environment.name,
          }),
        ),
      ),
    exhaustedMessage: `The deletion conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  });
  yield* confirmDeletion(input, accepted);
  return {
    name: accepted.state.environment.name,
    metaVersion: accepted.metaVersion,
    warnings: accepted.state.warnings,
  };
});
