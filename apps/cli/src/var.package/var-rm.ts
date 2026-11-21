import { ManifestVersionConflictError, MetaVersionConflictError } from "@maruhi/api-schema";
import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect, Stdio } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { confirmPermanentDeletion, noteConcurrentRename } from "../deletion-confirm.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { FloorHandle, VerifiedVariableStatement } from "../floor-check.ts";
import { rejectIntentOnServerRejection } from "../floor-check.ts";
import { CliIo } from "../io.ts";
import {
  confirmAcceptedMetaMutation,
  confirmsIssuedStatement,
  issueManifestWithIntent,
} from "../meta-confirm.ts";
import { signStatementAndHash } from "../meta-statement.ts";
import { retryOnConflict } from "../retry.ts";
import {
  signDeleteStatementV3,
  requireVerifiedEnvironment,
  resolveSchemaTarget,
  type SchemaSetState,
  type SchemaTargetKey,
} from "../schema.package/index.ts";

const MAX_ATTEMPTS = 5;

interface VarRmInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly force: boolean;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}

interface VarRmSummary {
  readonly variableId: VariableId;
  readonly metaVersion: number;
  readonly previousStatus: "active" | "declared";
  readonly warnings: readonly string[];
}

const resolveDeletionTarget = Effect.fn("var-rm.resolveDeletionTarget")(function* (
  input: VarRmInput,
  verified: VerifiedProject,
  key: SchemaTargetKey,
  name: string,
): Effect.fn.Return<SchemaSetState & { readonly target: VerifiedVariableStatement }, CliError> {
  const state = yield* resolveSchemaTarget(input, verified, key);
  const target = state.target;
  if (target !== null) {
    return { ...state, target };
  }
  const isKeyed = (tombstone: { readonly name: string; readonly variableId: VariableId }) =>
    typeof key === "string" ? tombstone.name === key : tombstone.variableId === key.variableId;
  if (state.tombstones.some(isKeyed)) {
    return yield* Effect.fail(
      cliError(
        `Variable ${displayText(name)} is already deleted (deletion is terminal — a deleted variable cannot be restored). Nothing was changed by this run`,
      ),
    );
  }
  return yield* Effect.fail(
    cliError(`Variable ${displayText(name)} does not exist in this environment`),
  );
});

function ensureDeletionConfirmed(
  input: VarRmInput,
  target: VerifiedVariableStatement,
  name: string,
): Effect.Effect<void, CliError, CliIo | Stdio.Stdio> {
  return confirmPermanentDeletion(input.force, {
    label: displayText(name),
    consequence:
      target.status === "active"
        ? "its value (every stored version) is deleted immediately and cannot be recovered"
        : "the declaration (no value was set) is removed",
    irreversibility: "the variable cannot be restored",
    refusalReason:
      "deletion is terminal and, for a variable with a value, destroys every stored version",
    typedNoun: "variable name",
    mismatchNoun: "name",
    expected: name,
  });
}

interface AcceptedDeletion {
  readonly variableId: VariableId;
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
  readonly previousStatus: "active" | "declared";
  readonly selfManifest: {
    readonly manifestVersion: number;
    readonly epoch: number;
    readonly manifestSigHashHex: string;
  };
  readonly intentId: string;
  readonly state: SchemaSetState;
}

const signDeleteStatementV1 = Effect.fn("var-rm.signDeleteStatementV1")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly target: VerifiedVariableStatement;
  readonly authorUserId: UserId;
  readonly signingKey: CryptoKey;
}) {
  const context = {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    target: { kind: "variable", variableId: input.target.variableId },
    name: input.target.name,
    status: "deleted",
    metaVersion: input.target.metaVersion + 1,
    prevMetaSigHashHex: input.target.metaSigHashHex,
    authorUserId: input.authorUserId,
    chainHeadHashHex: input.verified.state.headHashHex,
    chainHeadSeq: input.verified.state.headSeq,
  } as const;
  const signed = yield* signStatementAndHash(context, input.signingKey);
  return {
    statement: {
      suite: context.suite,
      environmentId: context.environmentId,
      variableId: context.target.variableId,
      name: context.name,
      status: context.status,
      metaVersion: context.metaVersion,
      prevMetaSigHashHex: context.prevMetaSigHashHex,
      chainHeadHashHex: context.chainHeadHashHex,
      chainHeadSeq: context.chainHeadSeq,
      signatureHex: signed.signatureHex,
    },
    metaSigHashHex: signed.metaSigHashHex,
  };
});

type DeletionAttemptError =
  | CliError
  | Effect.Error<ReturnType<VarRmInput["client"]["variables"]["remove"]>>;

const attemptDeletion = Effect.fn("var-rm.attemptDeletion")(function* (
  input: VarRmInput,
  state: SchemaSetState & { readonly target: VerifiedVariableStatement },
): Effect.fn.Return<AcceptedDeletion, DeletionAttemptError> {
  const target = state.target;
  const environment = yield* requireVerifiedEnvironment(state, input.environmentId);
  if (target.status !== "active" && target.status !== "declared") {
    return yield* Effect.fail(
      cliError("The resolved deletion target is not a live variable (internal inconsistency)"),
    );
  }
  const previousStatus = target.status;
  const signed =
    target.schema !== null
      ? yield* signDeleteStatementV3({
          verified: state.verified,
          environmentId: input.environmentId,
          variableId: target.variableId,
          name: target.name,
          schema: target.schema,
          prev: { metaVersion: target.metaVersion, metaSigHashHex: target.metaSigHashHex },
          authorUserId: input.authorUserId,
          signingKey: input.signingKey,
        })
      : yield* signDeleteStatementV1({
          verified: state.verified,
          environmentId: input.environmentId,
          target,
          authorUserId: input.authorUserId,
          signingKey: input.signingKey,
        });
  const { manifest, intentId } = yield* issueManifestWithIntent({
    verified: state.verified,
    environmentId: input.environmentId,
    epoch: environment.currentEpoch,
    previous: state.manifestBase.previous,
    entries: [
      ...state.manifestBase.entries.filter((entry) => entry.variableId !== target.variableId),
      {
        variableId: target.variableId,
        status: "deleted" as const,
        metaVersion: target.metaVersion + 1,
        metaSigHashHex: signed.metaSigHashHex,
      },
    ],
    envMeta: state.manifestBase.envMeta,
    issuerUserId: input.authorUserId,
    signingKey: input.signingKey,
    floor: input.floor,
    variableId: target.variableId,
  });
  yield* input.client.variables
    .remove({
      params: {
        projectId: state.verified.projectId,
        environmentId: input.environmentId,
        variableId: target.variableId,
      },
      payload: { statement: signed.statement, manifest: manifest.manifest },
    })
    .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
  return {
    variableId: target.variableId,
    metaVersion: target.metaVersion + 1,
    metaSigHashHex: signed.metaSigHashHex,
    previousStatus,
    selfManifest: {
      manifestVersion: manifest.manifestVersion,
      epoch: manifest.epoch,
      manifestSigHashHex: manifest.manifestSigHashHex,
    },
    intentId,
    state,
  };
});

type DeletionConflict = { readonly kind: "re-resolve" };

function classifyDeletionConflict(error: DeletionAttemptError): DeletionConflict | null {
  if (error instanceof MetaVersionConflictError || error instanceof ManifestVersionConflictError) {
    return { kind: "re-resolve" };
  }
  return null;
}

export const varRmOp = Effect.fn("var-rm.varRmOp")(function* (
  input: VarRmInput,
): Effect.fn.Return<VarRmSummary, CliError, CliIo | Stdio.Stdio> {
  const name = input.name.normalize("NFC");
  const initial = yield* resolveDeletionTarget(input, input.verified, name, name);
  yield* ensureDeletionConfirmed(input, initial.target, name);
  const confirmed = { variableId: initial.target.variableId };
  const accepted = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) => attemptDeletion(input, state),
    classify: classifyDeletionConflict,
    recover: (state) =>
      resolveDeletionTarget(input, state.verified, confirmed, name).pipe(
        Effect.tap((next) =>
          noteConcurrentRename({
            subject: "The variable you confirmed",
            seenName: name,
            currentName: next.target.name,
          }),
        ),
      ),
    exhaustedMessage: `The deletion conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  });
  yield* confirmAcceptedMetaMutation(input, accepted, "variable deletion", (metadata, issued) =>
    metadata.tombstones.some(
      (tombstone) =>
        tombstone.variableId === accepted.variableId && confirmsIssuedStatement(tombstone, issued),
    ),
  );
  yield* input.floor
    .commitPush(
      accepted.variableId,
      {
        status: "deleted",
        metaVersion: accepted.metaVersion,
        metaSigHashHex: accepted.metaSigHashHex,
      },
      {
        seq: accepted.state.verified.state.headSeq,
        hashHex: accepted.state.verified.state.headHashHex,
      },
    )
    .pipe(Effect.mapError((error) => cliError(`The deletion was accepted, but ${error.message}`)));
  return {
    variableId: accepted.variableId,
    metaVersion: accepted.metaVersion,
    previousStatus: accepted.previousStatus,
    warnings: accepted.state.warnings,
  };
});
