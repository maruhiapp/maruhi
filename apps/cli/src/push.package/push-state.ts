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

import type { MaruhiClient } from "../api.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { type DekRecipient, environmentKeysFor } from "../deks.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle } from "../floor-check.ts";
import { type ManifestIssueBase, pullVerifiedEnvironment } from "../values.ts";
import { resolveTarget, type PushTarget } from "./push-resolve.ts";
import { winnerInconsistency } from "./push-winner.ts";

type PushConflict =
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict" }
  | { readonly kind: "variable-conflict" };

export type PushAttemptError =
  | CliError
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["create"]>>
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["activate"]>>
  | Effect.Error<ReturnType<PushInput["client"]["variables"]["push"]>>;

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
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
  readonly floor: FloorHandle;
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
  readonly issueBase: ManifestIssueBase | null;
  readonly warnings: readonly string[];
}

export const initialState = Effect.fn("push-state.initialState")(function* (
  input: PushInput,
): Effect.fn.Return<PushState, CliError> {
  const resolved = yield* resolveTarget(input);
  const verified = resolved.verified;
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
    issueBase: null,
    warnings: [...state.warnings, ...pulled.warnings],
  };
});

const reresolveTarget = Effect.fn("push-state.reresolveTarget")(function* (
  input: PushInput,
  state: PushState,
): Effect.fn.Return<PushState, CliError> {
  const resolved = yield* resolveTarget({ ...input, verified: state.verified });
  const refreshed = yield* refreshEpochState(input, state, resolved.verified);
  return {
    ...refreshed,
    target: resolved.target,
    issueBase: resolved.issueBase,
    warnings: [...state.warnings, ...resolved.warnings],
  };
});

export function nextState(
  input: PushInput,
  state: PushState,
  outcome: PushConflict,
): Effect.Effect<PushState, CliError> {
  switch (outcome.kind) {
    case "version-conflict":
      if (state.target.kind !== "push") {
        return reresolveTarget(input, state);
      }
      return adoptConflictWinner(input, state, outcome.currentVersion);
    case "epoch-conflict":
      return Effect.gen(function* () {
        const verified = yield* resyncExtended(input.resync, state.verified);
        const keys = yield* environmentKeysFor({
          client: input.client,
          verified,
          environmentId: input.environmentId,
          recipient: input.recipient,
          cached: state.deks,
        });
        if (keys.currentEpoch === state.epoch) {
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
