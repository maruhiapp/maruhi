// The push operation's input / state and the CAS-retry state machine
// (AUTH_SPEC §12-5's retry procedure): the initial resolution + DEK
// fetch, the winner adoption after a VersionConflict, the re-resolution
// after a VariableConflict, and the epoch re-derivation after an
// EpochConflict.

import {
  ActivationRequiredError,
  EpochConflictError,
  ManifestVersionConflictError,
  MetaVersionConflictError,
  VariableConflictError,
  VersionConflictError,
} from "@maruhi/api-schema";
import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import { Effect, type Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { type DekRecipient, environmentKeysFor } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import { resolveTarget, type PushTarget } from "./push-resolve.ts";
import { winnerInconsistency } from "./push-winner.ts";
import { type ManifestIssueBase, pullVerifiedEnvironment } from "./values.ts";

type PushConflict =
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict" }
  | { readonly kind: "variable-conflict" };

/**
 * One attempt's concrete failure channel: CliError (own failures and the
 * crypto bridge's wrapped kinds re-mapped at the crypto sites) plus the
 * variables endpoints' declared error unions (the raw types —
 * classifyPushConflict discriminates them on the retryOnConflict side).
 */
export type PushAttemptError =
  | CliError
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["create"]>>
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["activate"]>>
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["push"]>>;

/** The retryable classification of CAS conflicts (§12-5). Anything else is null (a terminal error). */
export function classifyPushConflict(error: PushAttemptError): PushConflict | null {
  if (error instanceof VersionConflictError) {
    return { kind: "version-conflict", currentVersion: error.currentVersion };
  }
  if (error instanceof EpochConflictError) {
    return { kind: "epoch-conflict" };
  }
  if (
    error instanceof VariableConflictError ||
    error instanceof MetaVersionConflictError ||
    error instanceof ManifestVersionConflictError ||
    error instanceof ActivationRequiredError
  ) {
    // A create's name conflict / metaVersion conflict (concurrent creation,
    // concurrent rename) / manifestVersion conflict (a concurrent meta
    // operation — §12-5 (6)) is re-resolved from the name (§12-5's retry =
    // re-fetch → verify → re-sign both the statement and the manifest. An
    // ID conflict effectively never happens with random IDs).
    // ActivationRequired (a normal push hit a declared variable — §12-5) is
    // not a resync but a switch-to-activation signal: the re-resolution sees
    // the declared variable and switches to the activation composite
    // (design doc §3 row S3)
    return { kind: "variable-conflict" };
  }
  return null;
}

export interface PushInput {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  readonly name: string;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly verified: VerifiedProject;
  /** The resync (full chain re-verification). The caller runs it through resyncExtended's extension check. */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The writer of the value signature (my internal user_id) and the master sig key (§4.1). */
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
  /** The local floor (§6.3 — the check and commit of internal pulls, and the variable-floor advance after acceptance). */
  readonly floor: FloorHandle;
  /**
   * A rollback (`maruhi var rollback` — 2026-09-27 VH): the value is version
   * `sameValueAs`'s plaintext, restored into this existing variable. The push
   * declares the lineage (AUTH_SPEC §12-5), and every attempt — including a
   * conflict retry that re-resolves the name — must land as a normal push to
   * exactly this variable: a concurrent delete / rename / re-create never
   * turns a rollback into a creation or a push elsewhere. It also lands only
   * on top of the exact version the user confirmed rolling back from
   * (`fromVersion` + its signed-bytes hash): a concurrent push by another
   * member is never silently overwritten with the restored value — the
   * rollback is refused and the user re-runs it against the new state.
   */
  readonly restore?: {
    readonly variableId: VariableId;
    readonly sameValueAs: number;
    readonly fromVersion: number;
    readonly fromSignedBytesHashHex: string;
  };
}

export interface PushState {
  readonly verified: VerifiedProject;
  readonly epoch: number;
  readonly deks: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly target: PushTarget;
  /** create / activate paths only: the issuing material of the bundled manifest (reresolveTarget re-fetches it). */
  readonly issueBase: ManifestIssueBase | null;
  readonly warnings: readonly string[];
}

export const initialState = Effect.fn("push-state.initialState")(function* (
  input: PushInput,
): Effect.fn.Return<PushState, CliError> {
  const resolved = yield* resolveTarget(input);
  const verified = resolved.verified;
  // The current epoch (the chain-derived value — §6.2; a push against an
  // uncreated environment stops here) and the DEK set are derived together
  // from the same verified view (deks.ts's environmentKeysFor). The DEK is
  // fetched exactly once per path (session-11 ruling 3's double-fetch
  // elimination): for an existing variable the bundled share of the
  // value-carrying pull (prefetched) is verified and unwrapped / for a
  // creation, listMine
  const keys = yield* environmentKeysFor({
    client: input.client,
    verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: resolved.deks,
  });
  return {
    verified,
    epoch: keys.currentEpoch,
    deks: keys.deksByEpoch,
    target: resolved.target,
    issueBase: resolved.issueBase,
    warnings: resolved.warnings,
  };
});

/** Re-fetches the DEK set only when the epoch changed (or is first seen) (the cached semantics). */
function refreshEpochState(
  input: PushInput,
  state: PushState,
  verified: VerifiedProject,
): Effect.Effect<Pick<PushState, "verified" | "epoch" | "deks">, CliError> {
  return Effect.map(
    environmentKeysFor({
      client: input.client,
      verified,
      environmentId: input.environmentId,
      recipient: input.recipient,
      cached: state.deks,
    }),
    (keys) => ({ verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch }),
  );
}

/**
 * The winner re-fetch after a 409 VersionConflict (§12-5's retry
 * procedure): re-fetch the bulk pull, identify the winner by its stable
 * id, verify it, and re-point prev at its signed-bytes hash. The 409
 * response is never asked for the winner's hash.
 */
const adoptConflictWinner = Effect.fn("push-state.adoptConflictWinner")(function* (
  input: PushInput,
  state: PushState,
  currentVersion: number,
): Effect.fn.Return<PushState, CliError> {
  const pulled = yield* pullVerifiedEnvironment({
    client: input.client,
    verified: state.verified,
    environmentId: input.environmentId,
    resync: input.resync,
    floor: input.floor,
  });
  const winner = pulled.variables.find(
    (variable) => variable.variableId === state.target.variableId,
  );
  if (winner === undefined) {
    return yield* Effect.fail(
      cliError(
        `The version-conflict winner (variable ${state.target.variableId}) is missing from the re-fetched pull (a concurrent deletion by another member, or an inconsistent server response)`,
      ),
    );
  }
  const inconsistency = winnerInconsistency(
    state.target.variableId,
    state.target.kind === "push" ? state.target.latest : null,
    winner,
    currentVersion,
  );
  if (inconsistency !== null) {
    return yield* Effect.fail(cliError(inconsistency));
  }
  const refreshed = yield* refreshEpochState(input, state, pulled.verified);
  return {
    ...refreshed,
    target: { kind: "push", variableId: state.target.variableId, latest: winner },
    // Adopting the winner = a push to an existing variable (meta state unchanged — no manifest issued)
    issueBase: null,
    warnings: [...state.warnings, ...pulled.warnings],
  };
});

const reresolveTarget = Effect.fn("push-state.reresolveTarget")(function* (
  input: PushInput,
  state: PushState,
): Effect.fn.Return<PushState, CliError> {
  const resolved = yield* resolveTarget({ ...input, verified: state.verified });
  // The re-resolution's DEK prefers the on-hand set of a known epoch and
  // is re-fetched only when the epoch advanced (refreshEpochState).
  // resolved.deks is for the first resolution only — don't redo the
  // unwrapping on the rare path of a conflict retry
  const refreshed = yield* refreshEpochState(input, state, resolved.verified);
  return {
    ...refreshed,
    target: resolved.target,
    issueBase: resolved.issueBase,
    warnings: [...state.warnings, ...resolved.warnings],
  };
});

/**
 * Recovery from a conflict (the domain-specific part of §12-5's retry
 * procedure). Runs as retryOnConflict's recover — and also after the last
 * attempt (surfacing the terminal errors: equivocation evidence and
 * contradictions between the server response and the chain).
 */
export function nextState(
  input: PushInput,
  state: PushState,
  outcome: PushConflict,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      // A VersionConflict on the create path means "a concurrent creation
      // happened"; on the activate path it means "a value version 1 landed
      // first via a concurrent activation" (my send was not stored). Both
      // are re-resolved from the name (a variable the re-resolution sees as
      // active enters the normal push path — the winner is verified via a
      // value-carrying pull)
      if (state.target.kind !== "push") {
        return reresolveTarget(input, state);
      }
      return adoptConflictWinner(input, state, outcome.currentVersion);
    case "epoch-conflict":
      // The epoch's source of truth is the chain (§6.3). Resync with the
      // extension check and use the derived value, and get the
      // commitment-verified DEK of the new epoch. prev stays the verified
      // predecessor hash (the value has not changed — if it had, the next
      // attempt becomes a VersionConflict and enters the procedure above)
      return Effect.gen(function* () {
        const verified = yield* resyncExtended(input.resync, state.verified);
        // The current epoch and DEKs are derived together from the same
        // resync view (no re-fetch when the on-hand verified set already
        // has the current epoch — environmentKeysFor's cached)
        const keys = yield* environmentKeysFor({
          client: input.client,
          verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          cached: state.deks,
        });
        if (keys.currentEpoch === state.epoch) {
          // If the chain-derived epoch is unchanged after resyncing, the
          // server's EpochConflict claim contradicts the chain (a retry
          // cannot resolve it)
          return yield* Effect.fail(
            cliError(
              `The server reported an epoch conflict, but the chain-derived current epoch is still ${keys.currentEpoch} (the server response contradicts the chain)`,
            ),
          );
        }
        return { ...state, verified, epoch: keys.currentEpoch, deks: keys.deksByEpoch };
      });
    case "variable-conflict":
      return reresolveTarget(input, state);
  }
}
