import { type EnvironmentId, type UserId, type VariableId, cryptoEffect } from "@maruhi/core";
import {
  computeValueSignedBytesHash,
  encodeHex,
  encryptVariable,
  signValue,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { rejectIntentOnServerRejection } from "../floor-check.ts";
import type { ManifestFloor, VariableFloor } from "../floor.ts";
import type { ManifestDigestEntry } from "../manifest.ts";
import { confirmMetaMutation, issueManifestWithIntent } from "../meta-confirm.ts";
import { signCreateStatement } from "../meta-statement.ts";
import { decryptVerifiedValue } from "../pull.ts";
import { retryOnConflict } from "../retry.ts";
import { signContinuationStatementV3 } from "../schema.package/index.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import type { ManifestIssueBase } from "../values.ts";
import { nextVersionOf, prevHashOf } from "./push-resolve.ts";
import {
  classifyPushConflict,
  initialState,
  nextState,
  type PushAttemptError,
  type PushInput,
  type PushState,
} from "./push-state.ts";

const MAX_ATTEMPTS = 5;

export function normalizeStdinValue(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0 && bytes[bytes.length - 1] === 0x0a) {
    const end = bytes.length > 1 && bytes[bytes.length - 2] === 0x0d ? -2 : -1;
    return bytes.slice(0, end);
  }
  return bytes;
}

export interface PushedVersion {
  readonly variableId: VariableId;
  readonly version: number;
  readonly epoch: number;
  readonly warnings: readonly string[];
}

export function encryptAndSignPayload(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly epoch: number;
  readonly version: number;
  readonly prevValueSigHashHex: string;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly value: Redacted.Redacted<Uint8Array>;
  readonly writerUserId: UserId;
  readonly signingKey: CryptoKey;
}) {
  const context = {
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
  };
  return Effect.gen(function* () {
    const encrypted = yield* cryptoEffect(() =>
      encryptVariable({
        dek: Redacted.value(input.dek),
        context,
        plaintext: Redacted.value(input.value),
      }),
    ).pipe(Effect.mapError(() => cliError("Failed to encrypt the value")));
    const nonceHex = encodeHex(encrypted.nonce);
    const ciphertextHex = encodeHex(encrypted.ciphertext);
    const signatureContext = {
      suite: SUITE_ID,
      ...context,
      nonceHex,
      ciphertextHex,
      prevValueSigHashHex: input.prevValueSigHashHex,
      writerUserId: input.writerUserId,
      chainHeadHashHex: input.verified.state.headHashHex,
      chainHeadSeq: input.verified.state.headSeq,
    } as const;
    const signature = yield* cryptoEffect(() =>
      signValue({ context: signatureContext, signingKey: input.signingKey }),
    ).pipe(Effect.mapError(() => cliError("Failed to create the value signature")));
    const signedBytesHash = yield* cryptoEffect(() =>
      computeValueSignedBytesHash(signatureContext),
    ).pipe(
      Effect.mapError(() => cliError("Failed to compute the value-signature signed-bytes hash")),
    );
    return {
      payload: {
        suite: SUITE_ID,
        aad: context,
        nonceHex,
        ciphertextHex,
        prevValueSigHashHex: input.prevValueSigHashHex,
        chainHeadHashHex: input.verified.state.headHashHex,
        chainHeadSeq: input.verified.state.headSeq,
        signatureHex: signature,
      },
      signedBytesHashHex: signedBytesHash,
    } as const;
  });
}

interface AcceptedPush {
  readonly accepted: {
    readonly variableId: VariableId;
    readonly version: number;
    readonly epoch: number;
  };
  readonly floorVariable: VariableFloor;
  readonly selfManifest: ManifestFloor | null;
  readonly intentId: string | null;
  readonly state: PushState;
}

function ensureRestoreTarget(input: PushInput, state: PushState): Effect.Effect<void, CliError> {
  const restore = input.restore;
  if (restore === undefined) {
    return Effect.void;
  }
  const target = state.target;
  if (target.kind !== "push" || target.variableId !== restore.variableId) {
    return Effect.fail(
      cliError(
        `The rollback target ${displayText(input.name)} no longer resolves to the variable whose history was verified (a concurrent delete, rename, or re-creation). Nothing was pushed — re-run the command`,
      ),
    );
  }
  if (
    target.latest.version !== restore.fromVersion ||
    target.latest.signedBytesHashHex !== restore.fromSignedBytesHashHex
  ) {
    return Effect.fail(
      cliError(
        `${displayText(input.name)} changed while the rollback was being prepared (the latest is now version ${target.latest.version}, not the confirmed version ${restore.fromVersion}). Nothing was pushed — check \`maruhi var history\` and re-run the command`,
      ),
    );
  }
  return Effect.void;
}

export function sameRedactedBytes(
  a: Redacted.Redacted<Uint8Array>,
  b: Redacted.Redacted<Uint8Array>,
): boolean {
  const [left, right] = [a, b].map(Redacted.value);
  return (
    left !== undefined &&
    right !== undefined &&
    left.length === right.length &&
    left.every((byte, index) => byte === right[index])
  );
}

function lineageOf(
  input: PushInput,
  state: PushState,
  latest: VerifiedPulledValue,
): Effect.Effect<number | undefined, CliError> {
  if (input.restore !== undefined) {
    return Effect.succeed(input.restore.sameValueAs);
  }
  if (!state.deks.has(latest.epoch)) {
    return Effect.succeed(undefined);
  }
  return Effect.map(
    decryptVerifiedValue({
      verified: state.verified,
      environmentId: input.environmentId,
      variable: latest,
      deksByEpoch: state.deks,
      chainEpoch: state.epoch,
    }),
    (current) => (sameRedactedBytes(current, input.value) ? latest.version : undefined),
  );
}

function withLineage<T>(value: T, sameValueAs: number | undefined) {
  return sameValueAs === undefined ? { value } : { value, sameValueAs };
}

function issueVariableManifest(
  input: PushInput,
  state: PushState,
  issueBase: ManifestIssueBase,
  variableId: VariableId,
  entries: readonly ManifestDigestEntry[],
): ReturnType<typeof issueManifestWithIntent> {
  return issueManifestWithIntent({
    verified: state.verified,
    environmentId: input.environmentId,
    epoch: state.epoch,
    previous: issueBase.previous,
    entries,
    envMeta: issueBase.envMeta,
    issuerUserId: input.writerUserId,
    signingKey: input.signingKey,
    floor: input.floor,
    variableId,
  });
}

const attemptOnce = Effect.fn("push.attemptOnce")(function* (
  input: PushInput,
  state: PushState,
): Effect.fn.Return<AcceptedPush, PushAttemptError> {
  yield* ensureRestoreTarget(input, state);
  const dek = state.deks.get(state.epoch);
  if (dek === undefined) {
    return yield* Effect.fail(
      cliError(
        `No DEK for the current epoch ${state.epoch} is registered for you (possibly awaiting a re-wrap after a rotation)`,
      ),
    );
  }
  const version = nextVersionOf(state.target);
  const signed = yield* encryptAndSignPayload({
    verified: state.verified,
    environmentId: input.environmentId,
    variableId: state.target.variableId,
    epoch: state.epoch,
    version,
    prevValueSigHashHex: prevHashOf(state.target),
    dek,
    value: input.value,
    writerUserId: input.writerUserId,
    signingKey: input.signingKey,
  });
  const valueFloor = {
    status: "active",
    version,
    epoch: state.epoch,
    valueSigHashHex: signed.signedBytesHashHex,
  } as const;
  const params = { projectId: state.verified.projectId, environmentId: input.environmentId };
  if (state.target.kind === "create") {
    const target = state.target;
    const issueBase = state.issueBase;
    if (issueBase === null) {
      return yield* Effect.fail(
        cliError(
          `Variable ${target.variableId} resolved as a creation without manifest material (internal inconsistency)`,
        ),
      );
    }
    const created = yield* signCreateStatement({
      verified: state.verified,
      environmentId: input.environmentId,
      target: { kind: "variable", variableId: target.variableId },
      name: input.name,
      authorUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    if (issueBase.entries.some((entry) => entry.variableId === target.variableId)) {
      return yield* Effect.fail(
        cliError(
          `Variable ${target.variableId} resolved as a creation but already exists in the verified statement set (internal inconsistency)`,
        ),
      );
    }
    const { manifest, intentId } = yield* issueVariableManifest(
      input,
      state,
      issueBase,
      target.variableId,
      [
        ...issueBase.entries,
        {
          variableId: target.variableId,
          status: "active" as const,
          metaVersion: 1,
          metaSigHashHex: created.metaSigHashHex,
        },
      ],
    );
    const accepted = yield* input.client.variables
      .create({
        params,
        payload: {
          statement: created.statement,
          value: signed.payload,
          manifest: manifest.manifest,
        },
      })
      .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
    return {
      accepted,
      floorVariable: { ...valueFloor, metaVersion: 1, metaSigHashHex: created.metaSigHashHex },
      selfManifest: {
        manifestVersion: manifest.manifestVersion,
        epoch: manifest.epoch,
        manifestSigHashHex: manifest.manifestSigHashHex,
      },
      intentId,
      state,
    };
  }
  if (state.target.kind === "activate") {
    const target = state.target;
    const issueBase = state.issueBase;
    if (issueBase === null) {
      return yield* Effect.fail(
        cliError(
          `Variable ${target.variableId} resolved as an activation without manifest material (internal inconsistency)`,
        ),
      );
    }
    const activation = yield* signContinuationStatementV3({
      verified: state.verified,
      environmentId: input.environmentId,
      variableId: target.variableId,
      name: target.prev.name,
      schema: target.prev.schema,
      status: "active",
      prev: {
        metaVersion: target.prev.metaVersion,
        metaSigHashHex: target.prev.metaSigHashHex,
      },
      authorUserId: input.writerUserId,
      signingKey: input.signingKey,
    });
    const previousEntry = issueBase.entries.find((entry) => entry.variableId === target.variableId);
    if (previousEntry === undefined || previousEntry.status !== "declared") {
      return yield* Effect.fail(
        cliError(
          `Variable ${target.variableId} resolved as an activation but its declared entry is missing from the verified statement set (internal inconsistency)`,
        ),
      );
    }
    const { manifest, intentId } = yield* issueVariableManifest(
      input,
      state,
      issueBase,
      target.variableId,
      [
        ...issueBase.entries.filter((entry) => entry.variableId !== target.variableId),
        {
          variableId: target.variableId,
          status: "active" as const,
          metaVersion: target.prev.metaVersion + 1,
          metaSigHashHex: activation.metaSigHashHex,
        },
      ],
    );
    const accepted = yield* input.client.variables
      .activate({
        params: { ...params, variableId: target.variableId },
        payload: {
          value: signed.payload,
          statement: activation.statement,
          manifest: manifest.manifest,
        },
      })
      .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
    return {
      accepted,
      floorVariable: {
        ...valueFloor,
        metaVersion: target.prev.metaVersion + 1,
        metaSigHashHex: activation.metaSigHashHex,
      },
      selfManifest: {
        manifestVersion: manifest.manifestVersion,
        epoch: manifest.epoch,
        manifestSigHashHex: manifest.manifestSigHashHex,
      },
      intentId,
      state,
    };
  }
  const latest = state.target.latest;
  const sameValueAs = yield* lineageOf(input, state, latest);
  const accepted = yield* input.client.variables.push({
    params: { ...params, variableId: state.target.variableId },
    payload: withLineage(signed.payload, sameValueAs),
  });
  return {
    accepted,
    floorVariable: {
      ...valueFloor,
      metaVersion: latest.metaVersion,
      metaSigHashHex: latest.metaSignedBytesHashHex,
    },
    selfManifest: null,
    intentId: null,
    state,
  };
});

function confirmPushMetaMutation(input: {
  readonly push: PushInput;
  readonly accepted: AcceptedPush;
  readonly selfManifest: ManifestFloor;
}): Effect.Effect<void, CliError> {
  const target = input.accepted.state.target;
  const variableId = target.variableId;
  const issued = input.accepted.floorVariable;
  const statementConfirms = (statement: {
    readonly metaVersion: number;
    readonly metaSigHashHex: string;
  }) =>
    statement.metaVersion > issued.metaVersion ||
    (statement.metaVersion === issued.metaVersion &&
      statement.metaSigHashHex === issued.metaSigHashHex);
  return confirmMetaMutation({
    client: input.push.client,
    verified: input.accepted.state.verified,
    environmentId: input.push.environmentId,
    resync: input.push.resync,
    floor: input.push.floor,
    selfManifest: input.selfManifest,
    intentId: input.accepted.intentId,
    describe: target.kind === "activate" ? "variable activation" : "variable creation",
    effectVisible: (metadata) =>
      target.kind === "create"
        ? metadata.variables.some((statement) => statement.variableId === variableId) ||
          metadata.tombstones.some((tombstone) => tombstone.variableId === variableId)
        : metadata.variables.some(
            (statement) => statement.variableId === variableId && statementConfirms(statement),
          ) ||
          metadata.tombstones.some(
            (tombstone) => tombstone.variableId === variableId && statementConfirms(tombstone),
          ),
  });
}

export const pushVariable = Effect.fn("push.pushVariable")(function* (
  input: PushInput,
): Effect.fn.Return<PushedVersion, CliError> {
  const normalized: PushInput = { ...input, name: input.name.normalize("NFC") };
  const initial = yield* initialState(normalized);
  const outcome = yield* retryOnConflict(initial, {
    maxAttempts: MAX_ATTEMPTS,
    attempt: (state) => attemptOnce(normalized, state),
    classify: classifyPushConflict,
    recover: (state, conflict) => nextState(normalized, state, conflict),
    exhaustedMessage: `The push conflict did not resolve (after ${MAX_ATTEMPTS} attempts). Wait a moment and re-run the command`,
  });
  const acceptedState = outcome.state;
  if (outcome.selfManifest !== null) {
    yield* confirmPushMetaMutation({
      push: normalized,
      accepted: outcome,
      selfManifest: outcome.selfManifest,
    });
  }
  yield* input.floor
    .commitPush(acceptedState.target.variableId, outcome.floorVariable, {
      seq: acceptedState.verified.state.headSeq,
      hashHex: acceptedState.verified.state.headHashHex,
    })
    .pipe(Effect.mapError((error) => cliError(`The push was accepted, but ${error.message}`)));
  const floorVariable = outcome.floorVariable;
  if (floorVariable.status !== "active") {
    return yield* Effect.fail(
      cliError("The accepted push produced a non-active floor record (internal inconsistency)"),
    );
  }
  const local = {
    variableId: acceptedState.target.variableId,
    version: floorVariable.version,
    epoch: floorVariable.epoch,
  };
  const echo = outcome.accepted;
  if (
    echo.variableId !== local.variableId ||
    echo.version !== local.version ||
    echo.epoch !== local.epoch
  ) {
    return yield* Effect.fail(
      cliError(
        `The push was accepted and recorded locally as ${displayText(local.variableId)} version=${local.version} epoch=${local.epoch}, but the server's response echoes different coordinates (${displayText(echo.variableId)} version=${echo.version} epoch=${echo.epoch}). The locally signed values are authoritative — verify the server with \`maruhi pull\``,
      ),
    );
  }
  return { ...local, warnings: acceptedState.warnings };
});
