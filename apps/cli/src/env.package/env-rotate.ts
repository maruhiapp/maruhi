import { cryptoEffect, type EnvironmentId, type ProjectId } from "@maruhi/core";
import { computeDekCommitment, generateDek, SUITE_ID } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { issueCheckpoint } from "../checkpoint.package/index.ts";
import { environmentKeysFor } from "../deks.ts";
import { ownDeviceBySigningKey } from "../device-key.ts";
import { countNoun, displayText, logWarnings } from "../display.ts";
import { CliError, cliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import type { ManifestDigestEntry } from "../manifest.ts";
import { logWarning } from "../notice.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import { pullVerifiedEnvironment, type VerifiedEnvironmentPull } from "../values.ts";
import {
  nothingDecryptable,
  decryptForRotation,
  ensureRotationIsUseful,
} from "./env-rotate-decrypt.ts";
import { reencryptContext, reencryptCurrentValues } from "./env-rotate-pass.ts";
import { appendRotation, type RotateValuesConflictError } from "./env-rotate-send.ts";
import { ensureRotatable, type RotateInput, dedupeWarnings } from "./env-rotate-shared.ts";

const MAX_REASON_BYTES = 1024;

export interface RotationSummary {
  readonly mode: "rotated" | "resumed" | "up-to-date";
  readonly previousEpoch: number;
  readonly epoch: number;
  readonly reencrypted: number;
  readonly alreadyCurrent: number;
  readonly remaining: number;
  readonly remainingExact: boolean;
  readonly failure: string | null;
  readonly written: readonly ReencryptedVariable[];
  readonly warnings: readonly string[];
}

export interface ReencryptedVariable {
  readonly name: string;
  readonly version: number;
}

function checkReasonLength(reason: string | undefined): Effect.Effect<string | null, CliError> {
  if (reason === undefined) {
    return Effect.succeed(null);
  }
  const trimmed = reason.trim();
  if (trimmed.length === 0) {
    return Effect.fail(
      usageError(
        "--reason is empty. Specify the rotation reason (an unset shell variable may have expanded to an empty value). To only resume incomplete re-encryption without recording a reason, run without --reason",
      ),
    );
  }
  const bytes = new TextEncoder().encode(trimmed).length;
  if (bytes > MAX_REASON_BYTES) {
    return Effect.fail(
      usageError(
        `--reason is too long (${bytes} bytes). Free-form strings in chain entries are limited to ${MAX_REASON_BYTES} UTF-8 bytes (CRYPTO_SPEC §6.1)`,
      ),
    );
  }
  return Effect.succeed(trimmed);
}

function requireReason(reason: string | null): Effect.Effect<string> {
  return reason === null
    ? Effect.die(new Error("the rotate path was taken without a rotation reason"))
    : Effect.succeed(reason);
}

export function envRotateOp(input: RotateInput): Effect.Effect<RotationSummary, CliError, CliIo> {
  return rotateAttempt(input, 1);
}

const MAX_VALUES_CONFLICT_ATTEMPTS = 3;

function rotateAttempt(
  input: RotateInput,
  attempt: number,
): Effect.Effect<RotationSummary, CliError, CliIo> {
  return Effect.suspend(() => {
    const warnings: string[] = [];
    return rotateWithWarnings(input, warnings).pipe(
      Effect.tapError(() => logWarnings(dedupeWarnings(warnings))),
      Effect.catchTag("RotateValuesConflictError", (error) =>
        Effect.gen(function* () {
          if (attempt < MAX_VALUES_CONFLICT_ATTEMPTS) {
            const io = yield* CliIo;
            yield* io.log(
              `A concurrent push advanced environment ${input.environmentId}'s values — re-pulling and retrying the rotation (attempt ${attempt + 1} of ${MAX_VALUES_CONFLICT_ATTEMPTS})`,
            );
            return yield* rotateAttempt(input, attempt + 1);
          }
          return yield* Effect.fail(cliError(error.message));
        }),
      ),
    );
  });
}

const resumeReencryption = Effect.fn("env-rotate.resumeReencryption")(function* (input: {
  readonly input: RotateInput;
  readonly pulled: { readonly verified: VerifiedProject };
  readonly keys: { readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>> };
  readonly currentEpoch: number;
  readonly stale: readonly VerifiedPulledValue[];
  readonly reason: string | null;
  readonly anyDecryptable: boolean;
  readonly warnings: string[];
}): Effect.fn.Return<RotationSummary, CliError, CliIo> {
  const { currentEpoch, stale, warnings } = input;
  const environmentId = input.input.environmentId;
  const member = yield* ensureRotatable(
    input.pulled.verified,
    environmentId,
    input.input.signerUserId,
    input.input.signingKeyPair,
  );
  const dek = input.keys.deksByEpoch.get(currentEpoch);
  if (dek === undefined) {
    return yield* Effect.fail(
      cliError(
        input.anyDecryptable
          ? `The DEK for current epoch ${currentEpoch} is not registered for you (possibly awaiting a re-wrap by the rotation's executor). Cannot resume the incomplete re-encryption — wait for the re-wrap, or if revocation takes priority, run with --new-epoch (only values you can open move to the new epoch; the rest are reported as incomplete)`
          : `The DEK for current epoch ${currentEpoch} is not registered for you (possibly awaiting a re-wrap by the rotation's executor). You cannot open any current value, so advancing the epoch with --new-epoch would re-encrypt nothing — wait for a re-wrap addressed to you, or have a member holding wraps for that epoch run this`,
      ),
    );
  }
  const switched =
    input.reason === null
      ? "Resuming this re-encryption (no new epoch will be created)"
      : "**The requested rotation will not be performed**; switching to resuming this re-encryption (no new epoch is created, and since this path appends no chain entry, --reason is not recorded either)";
  yield* logWarning(
    `after the rotation to epoch ${currentEpoch}, environment ${environmentId} still has ${countNoun(stale.length, "variable")} with incomplete re-encryption. ${switched}. If a new epoch is strictly required (e.g. after removing a departed member), run with --new-epoch — this also counters responses that fake an incomplete state to suppress rotations`,
  );
  const targets = yield* decryptForRotation({
    verified: input.pulled.verified,
    environmentId,
    values: stale,
    deksByEpoch: input.keys.deksByEpoch,
    chainEpoch: currentEpoch,
    warnings,
  });
  const outcome =
    targets.length === 0
      ? {
          reencrypted: 0,
          alreadyCurrent: 0,
          remaining: stale.length,
          remainingExact: true,
          failure: nothingDecryptable(stale.length),
          written: [],
        }
      : yield* reencryptCurrentValues({
          context: reencryptContext(
            input.input,
            yield* ownDeviceBySigningKey(input.pulled.verified, member, input.input.signingKeyPair),
            {
              epoch: currentEpoch,
              dek,
              deksByEpoch: input.keys.deksByEpoch,
            },
          ),
          view: input.pulled.verified,
          targets,
          sink: warnings,
        });
  if (outcome.remaining === 0 && outcome.failure === null) {
    yield* issuePostRotationCheckpoint(input.input, input.pulled.verified, warnings);
  }
  return {
    mode: "resumed",
    previousEpoch: currentEpoch,
    epoch: currentEpoch,
    reencrypted: outcome.reencrypted,
    alreadyCurrent: outcome.alreadyCurrent,
    remaining: outcome.remaining,
    remainingExact: outcome.remainingExact,
    failure: outcome.failure,
    written: outcome.written,
    warnings: dedupeWarnings(warnings),
  };
});

function rotateSituationWarnings(input: RotateInput, floorless: boolean): readonly string[] {
  const warnings: string[] = [];
  if (floorless) {
    warnings.push(
      `This environment has no local floor yet, so variables the server keeps omitting from responses (ones that exist but never appear in listings) are not covered by re-encryption, and the omission cannot be detected (omission detection in CRYPTO_SPEC §6.3 presumes a floor). For revocation-purpose rotations, re-run from a machine that has a floor and confirm the variable listing for ${displayText(input.environmentId)} matches`,
    );
  }
  return warnings;
}

function rotatePathOf(input: {
  readonly staleCount: number;
  readonly reason: string | null;
  readonly forceNewEpoch: boolean;
}): "resume" | "up-to-date" | "rotate" {
  if (input.forceNewEpoch) {
    return "rotate";
  }
  if (input.staleCount > 0) {
    return "resume";
  }
  return input.reason === null ? "up-to-date" : "rotate";
}

function manifestBaseOf(pulled: VerifiedEnvironmentPull): {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
} {
  return {
    previous: {
      manifestVersion: pulled.manifest.manifestVersion,
      signedBytesHashHex: pulled.manifest.signedBytesHashHex,
    },
    entries: [
      ...pulled.variables.map((value) => ({
        variableId: value.variableId,
        status: "active" as const,
        metaVersion: value.metaVersion,
        metaSigHashHex: value.metaSignedBytesHashHex,
      })),
      ...pulled.declared.map((statement) => ({
        variableId: statement.variableId,
        status: "declared" as const,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...pulled.tombstones.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    envMeta: {
      metaVersion: pulled.environment.metaVersion,
      sigHashHex: pulled.environment.metaSigHashHex,
    },
  };
}

const rotateWithWarnings = Effect.fn("env-rotate.rotateWithWarnings")(function* (
  input: RotateInput,
  warnings: string[],
): Effect.fn.Return<RotationSummary, CliError | RotateValuesConflictError, CliIo> {
  const io = yield* CliIo;
  const reason = yield* checkReasonLength(input.reason);
  yield* ensureRotatable(
    input.verified,
    input.environmentId,
    input.signerUserId,
    input.signingKeyPair,
  );
  const floorless = input.floor.current() === null;

  const pulled = yield* pullVerifiedEnvironment({
    client: input.client,
    verified: input.verified,
    environmentId: input.environmentId,
    resync: input.resync,
    floor: input.floor,
  });
  warnings.push(...pulled.warnings, ...rotateSituationWarnings(input, floorless));
  const keys = yield* environmentKeysFor({
    client: input.client,
    verified: pulled.verified,
    environmentId: input.environmentId,
    recipient: input.recipient,
    prefetched: pulled.deks,
  });
  const currentEpoch = keys.currentEpoch;
  const stale = pulled.variables.filter((value) => value.epoch < currentEpoch);
  const path = rotatePathOf({
    staleCount: stale.length,
    reason,
    forceNewEpoch: input.forceNewEpoch,
  });

  if (path === "resume") {
    return yield* resumeReencryption({
      input,
      pulled,
      keys,
      currentEpoch,
      stale,
      reason,
      anyDecryptable: pulled.variables.some((value) => keys.deksByEpoch.has(value.epoch)),
      warnings,
    });
  }

  if (path === "up-to-date") {
    return {
      mode: "up-to-date",
      previousEpoch: currentEpoch,
      epoch: currentEpoch,
      reencrypted: 0,
      alreadyCurrent: 0,
      remaining: 0,
      remainingExact: true,
      failure: null,
      written: [],
      warnings: dedupeWarnings(warnings),
    };
  }

  const entryReason = yield* requireReason(reason);
  const newEpoch = currentEpoch + 1;
  const member = yield* ensureRotatable(
    pulled.verified,
    input.environmentId,
    input.signerUserId,
    input.signingKeyPair,
  );
  const targets = yield* decryptForRotation({
    verified: pulled.verified,
    environmentId: input.environmentId,
    values: pulled.variables,
    deksByEpoch: keys.deksByEpoch,
    chainEpoch: currentEpoch,
    warnings,
  });
  yield* ensureRotationIsUseful(targets.length, pulled.variables.length);
  const dek = Redacted.make(generateDek(), { label: "dek" });
  const dekCommitmentHex = yield* computeRotationCommitmentHex({
    projectId: pulled.verified.projectId,
    environmentId: input.environmentId,
    newEpoch,
    dek,
  });
  yield* io.log(
    `Rotating environment ${input.environmentId} (epoch ${currentEpoch} → ${newEpoch}, ${countNoun(targets.length, "variable")} targeted)`,
  );
  const rotated = yield* appendRotation({
    ...input,
    baseline: pulled.verified,
    member,
    reason: entryReason,
    newEpoch,
    dek,
    dekCommitmentHex,
    manifestBase: manifestBaseOf(pulled),
    checkpointValues: pulled.variables.map((value) => ({
      variableId: value.variableId,
      version: value.version,
      valueSigHashHex: value.signedBytesHashHex,
    })),
  });
  yield* io.log(
    `rotate_epoch accepted (epoch=${newEpoch}, new DEK wrapped for ${countNoun(rotated.memberCount, "current member")})`,
  );
  if (rotated.floorWarning !== null) {
    warnings.push(rotated.floorWarning);
  }
  const deksByEpoch = new Map<number, Redacted.Redacted<Uint8Array>>(keys.deksByEpoch);
  deksByEpoch.set(newEpoch, dek);
  const outcome = yield* reencryptCurrentValues({
    context: reencryptContext(
      input,
      yield* ownDeviceBySigningKey(pulled.verified, rotated.member, input.signingKeyPair),
      {
        epoch: newEpoch,
        dek,
        deksByEpoch,
      },
    ),
    view: rotated.view,
    targets,
    sink: warnings,
  });
  if (outcome.remaining === 0 && outcome.failure === null) {
    yield* issuePostRotationCheckpoint(input, rotated.view, warnings);
  }
  return {
    mode: "rotated",
    previousEpoch: currentEpoch,
    epoch: newEpoch,
    reencrypted: outcome.reencrypted,
    alreadyCurrent: outcome.alreadyCurrent,
    remaining: outcome.remaining,
    remainingExact: outcome.remainingExact,
    failure: outcome.failure,
    written: outcome.written,
    warnings: dedupeWarnings(warnings),
  };
});

function computeRotationCommitmentHex(input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly newEpoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
}): Effect.Effect<string, CliError> {
  return cryptoEffect(() =>
    computeDekCommitment({
      context: {
        suite: SUITE_ID,
        projectId: input.projectId,
        environmentId: input.environmentId,
        epoch: input.newEpoch,
      },
      dek: Redacted.value(input.dek),
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the DEK commitment")));
}

const issuePostRotationCheckpoint = Effect.fn("env-rotate.issuePostRotationCheckpoint")(function* (
  input: RotateInput,
  view: VerifiedProject,
  warnings: string[],
): Effect.fn.Return<void, never, CliIo> {
  const io = yield* CliIo;
  yield* issueCheckpoint({
    client: input.client,
    verified: view,
    resync: input.resync,
    environmentIds: [input.environmentId],
    signerUserId: input.signerUserId,
    signingKeyPair: input.signingKeyPair,
    floorFor: () => Effect.succeed(input.floor),
  }).pipe(
    Effect.tap((issued) =>
      Effect.gen(function* () {
        warnings.push(...issued.warnings);
        yield* io.log(
          issued.environmentIds.length === 0
            ? `Environment ${input.environmentId} matches its latest checkpoint, so the post-rotation periodic checkpoint has nothing to notarize${issued.attestedAuditHead ? " (issued for the audit head only)" : ""} — CRYPTO_SPEC §6.3 (i)`
            : `Issued the post-rotation periodic checkpoint for environment ${input.environmentId}${issued.attestedAuditHead ? " (audit head attested)" : ""} — CRYPTO_SPEC §6.3 (i)`,
        );
      }),
    ),
    Effect.catch((error) =>
      Effect.sync(() => {
        warnings.push(
          `The post-rotation periodic checkpoint could not be issued (${error.message}). The boundary checkpoint from the rotation still holds; run \`maruhi project checkpoint\` to notarize the re-encrypted state (CRYPTO_SPEC §6.3 (i))`,
        );
      }),
    ),
  );
});
