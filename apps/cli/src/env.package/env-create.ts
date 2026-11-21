import { cryptoEffect, type EnvironmentId, type UserId } from "@maruhi/core";
import type { ChainEntry, ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { computeDekCommitment, generateDek, SUITE_ID } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "../api.ts";
import { signEntryAtHead } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { buildWrapCompleteSet, requireWritingMember } from "../dek-wrap.ts";
import { cliError, type CliError } from "../errors.ts";
import { type FloorHandle, rejectIntentOnServerRejection } from "../floor-check.ts";
import type { ManifestFloor } from "../floor.ts";
import { signNextManifest } from "../manifest.ts";
import { signCreateStatement } from "../meta-statement.ts";
import { retryOnConflict } from "../retry.ts";
import { signBoundaryCheckpoint } from "./boundary-checkpoint.ts";
import {
  classifyCompositeConflict,
  type CompositeState,
  compositeExhaustedMessage,
  recoverComposite,
} from "./composite-retry.ts";
import { normalizeEnvironmentName } from "./env-meta.ts";

const MAX_ATTEMPTS = 5;

const ensureCreatable = Effect.fn("env-create.ensureCreatable")(function* (
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  signerUserId: UserId,
  signingKeyPair: SigningKeyPair,
): Effect.fn.Return<ChainMember, CliError> {
  const { member } = yield* requireWritingMember({
    verified,
    environmentId,
    target: "new",
    signerUserId,
    signingKeyPair,
    operation: "create an environment",
    forbidden:
      "A reader cannot create environments (create_environment requires the member role or above — CRYPTO_SPEC §6.2)",
    outOfScope:
      "Only members whose environment scope is `all` can create environments (a listed scope cannot contain an environment that does not exist yet — CRYPTO_SPEC §6.2). Ask an owner or an all-scope admin to create it, or to widen your scope to all",
  });
  if (verified.state.environments.has(environmentId)) {
    return yield* Effect.fail(
      cliError(
        `Environment ID ${environmentId} is already used on the chain (a create_environment entry was observed — IDs of deleted environments cannot be reused either). Use a different ID`,
      ),
    );
  }
  return member;
});

const signCreateEntry = Effect.fn("env-create.signCreateEntry")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly dekCommitmentHex: string;
  readonly member: ChainMember;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.fn.Return<ChainEntry & { readonly op: "create_environment" }, CliError> {
  const signed = yield* signEntryAtHead({
    verified: input.verified,
    signerUserId: input.member.userId,
    operation: {
      op: "create_environment",
      payload: {
        environmentId: input.environmentId,
        dekCommitmentHex: input.dekCommitmentHex,
      },
    },
    signingKeyPair: input.signingKeyPair,
  });
  if (signed.op !== "create_environment") {
    return yield* Effect.fail(cliError("Failed to sign the create_environment entry"));
  }
  return signed;
});

interface AcceptedCreation {
  readonly state: CompositeState;
  readonly manifest: ManifestFloor;
  readonly metaSigHashHex: string;
  readonly intentId: string;
}

export const envCreateOp = Effect.fn("env-create.envCreateOp")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly name: string;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}): Effect.fn.Return<{ readonly currentEpoch: number; readonly memberCount: number }, CliError> {
  const member = yield* ensureCreatable(
    input.verified,
    input.environmentId,
    input.signerUserId,
    input.signingKeyPair,
  );
  const name = yield* normalizeEnvironmentName(input.name);
  const dek = Redacted.make(generateDek(), { label: "dek" });
  const commitment = yield* cryptoEffect(() =>
    computeDekCommitment({
      context: {
        suite: SUITE_ID,
        projectId: input.verified.projectId,
        environmentId: input.environmentId,
        epoch: 1,
      },
      dek: Redacted.value(dek),
    }),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the DEK commitment")));
  const buildWraps = (verified: VerifiedProject) =>
    buildWrapCompleteSet({
      verified,
      environmentId: input.environmentId,
      epoch: 1,
      dek,
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
    });
  const deks = yield* buildWraps(input.verified);

  const accepted = yield* retryOnConflict(
    { verified: input.verified, member, deks },
    {
      maxAttempts: MAX_ATTEMPTS,
      attempt: (state) => attemptCreate(input, state, { name, commitmentHex: commitment }),
      classify: classifyCompositeConflict,
      recover: (state) =>
        recoverComposite(state, {
          resync: input.resync,
          environmentId: input.environmentId,
          recheck: (resynced) =>
            ensureCreatable(
              resynced,
              input.environmentId,
              input.signerUserId,
              input.signingKeyPair,
            ),
          buildWraps,
        }),
      exhaustedMessage: compositeExhaustedMessage("The environment creation", MAX_ATTEMPTS),
    },
  );
  yield* confirmCreation(input, accepted, commitment);
  return { currentEpoch: 1, memberCount: accepted.state.deks.length };
});

type EnvironmentsCreateError = Effect.Error<ReturnType<MaruhiClient["environments"]["create"]>>;

const attemptCreate = Effect.fn("env-create.attemptCreate")(function* (
  input: {
    readonly client: MaruhiClient;
    readonly environmentId: EnvironmentId;
    readonly signerUserId: UserId;
    readonly signingKeyPair: SigningKeyPair;
    readonly floor: FloorHandle;
  },
  state: CompositeState,
  material: { readonly name: string; readonly commitmentHex: string },
): Effect.fn.Return<AcceptedCreation, CliError | EnvironmentsCreateError> {
  const entry = yield* signCreateEntry({
    verified: state.verified,
    environmentId: input.environmentId,
    dekCommitmentHex: material.commitmentHex,
    member: state.member,
    signingKeyPair: input.signingKeyPair,
  });
  const { statement, metaSigHashHex } = yield* signCreateStatement({
    verified: state.verified,
    environmentId: input.environmentId,
    target: { kind: "environment" },
    name: material.name,
    authorUserId: input.signerUserId,
    signingKey: input.signingKeyPair.privateKey,
  });
  const signedManifest = yield* signNextManifest({
    verified: state.verified,
    environmentId: input.environmentId,
    epoch: 1,
    previous: null,
    entries: [],
    envMeta: { metaVersion: 1, sigHashHex: metaSigHashHex },
    issuerUserId: input.signerUserId,
    signingKey: input.signingKeyPair.privateKey,
    chainHead: {
      seq: state.verified.state.headSeq,
      hashHex: state.verified.state.headHashHex,
    },
  });
  const manifest = signedManifest.manifest;
  if (manifest.manifestVersion !== 1 || manifest.prevManifestSigHashHex !== "") {
    return yield* Effect.fail(cliError("Failed to sign the environment manifest"));
  }
  const checkpoint = yield* signBoundaryCheckpoint({
    compositeEntry: entry,
    environmentId: input.environmentId,
    epoch: 1,
    manifestVersion: 1,
    manifestSigHashHex: signedManifest.manifestSigHashHex,
    values: [],
    verified: state.verified,
    member: state.member,
    deviceFingerprintHex: entry.actor.keyFingerprintHex,
    signingKey: input.signingKeyPair.privateKey,
  });
  const intentId = yield* input.floor.appendIntent({
    op: "create_environment",
    environmentId: input.environmentId,
    epoch: 1,
    dekCommitmentHex: material.commitmentHex,
    variableId: null,
    manifestVersion: 1,
    manifestSigHashHex: signedManifest.manifestSigHashHex,
    declaredHead: {
      seq: state.verified.state.headSeq,
      hashHex: state.verified.state.headHashHex,
    },
  });
  yield* input.client.environments
    .create({
      params: { projectId: state.verified.projectId },
      payload: {
        parentHeadHashHex: state.verified.state.headHashHex,
        entry,
        statement,
        deks: state.deks,
        manifest: {
          ...manifest,
          manifestVersion: 1,
          prevManifestSigHashHex: "",
        },
        checkpoint,
      },
    })
    .pipe(Effect.tapError(rejectIntentOnServerRejection(input.floor, intentId)));
  return {
    state,
    manifest: {
      manifestVersion: 1,
      epoch: 1,
      manifestSigHashHex: signedManifest.manifestSigHashHex,
    },
    metaSigHashHex,
    intentId,
  };
});

const confirmCreation = Effect.fn("env-create.confirmCreation")(function* (
  input: {
    readonly environmentId: EnvironmentId;
    readonly resync: Effect.Effect<VerifiedProject, CliError>;
    readonly floor: FloorHandle;
  },
  accepted: AcceptedCreation,
  commitmentHex: string,
): Effect.fn.Return<void, CliError> {
  const view = yield* resyncExtended(input.resync, accepted.state.verified).pipe(
    Effect.mapError((error) =>
      cliError(
        `The environment creation was accepted (2xx), but the chain sync for the post-acceptance confirmation failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}. Environment ${input.environmentId} may already exist — re-run any command against this project after restoring connectivity; the recorded intent will be reconciled against the chain`,
      ),
    ),
  );
  const environment = view.state.environments.get(input.environmentId);
  if (environment === undefined || environment.dekCommitments.get(1) !== commitmentHex) {
    return yield* Effect.fail(
      cliError(
        `The environment creation was accepted (2xx), but the verified chain does not show this run's create_environment entry for ${input.environmentId} (the epoch-1 DEK commitment does not match the generated DEK's). The server response contradicts the chain — treating the creation as unconfirmed (AUTH_SPEC §12-10 (3))`,
      ),
    );
  }
  yield* input.floor
    .commitPull(
      {
        pullEpoch: 1,
        observedEpoch: 1,
        metaVersion: 1,
        metaSigHashHex: accepted.metaSigHashHex,
        manifest: accepted.manifest,
        variables: {},
      },
      { seq: view.state.headSeq, hashHex: view.state.headHashHex },
    )
    .pipe(
      Effect.mapError((error) =>
        cliError(`The environment was created and confirmed on the chain, but ${error.message}`),
      ),
    );
  yield* Effect.ignore(input.floor.resolveIntent(accepted.intentId, "accepted"));
});
