import type { DistributedEnvironmentManifest, EnvironmentManifest } from "@maruhi/api-schema";
import {
  CryptoEnvManifestInvalidError,
  cryptoEffect,
  type EnvironmentId,
  type UserId,
} from "@maruhi/core";
import type { EnvManifestContext, VariablesDigestEntry } from "@maruhi/crypto";
import {
  computeEnvManifestSignedBytesHash,
  computeVariablesDigest,
  signEnvManifest,
  SUITE_ID,
  verifyDistributedEnvManifest,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { cryptoErrorKind } from "./crypto-error-kind.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import type { ManifestFloor } from "./floor.ts";

export interface VerifiedManifest {
  readonly manifestVersion: number;
  readonly epoch: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  readonly signedBytesHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly issuerUserId: UserId;
  readonly issuerKeyFingerprintHex: string;
}

export type ManifestDigestEntry = VariablesDigestEntry;

interface SignManifestInput {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly issuerUserId: UserId;
  readonly signingKey: CryptoKey;
  readonly chainHead: { readonly seq: number; readonly hashHex: string };
}

export interface SignedManifest {
  readonly manifest: EnvironmentManifest;
  readonly manifestSigHashHex: string;
  readonly manifestVersion: number;
  readonly epoch: number;
}

export const signNextManifest = Effect.fn("manifest.signNextManifest")(function* (
  input: SignManifestInput,
): Effect.fn.Return<SignedManifest, CliError> {
  const digest = yield* cryptoEffect(() => computeVariablesDigest(SUITE_ID, input.entries)).pipe(
    Effect.mapError(() => cliError("Failed to compute the manifest variables digest")),
  );
  const context: EnvManifestContext = {
    suite: SUITE_ID,
    projectId: input.verified.projectId,
    environmentId: input.environmentId,
    epoch: input.epoch,
    manifestVersion: (input.previous?.manifestVersion ?? 0) + 1,
    variablesDigestHex: digest,
    envMetaVersion: input.envMeta.metaVersion,
    envMetaSigHashHex: input.envMeta.sigHashHex,
    prevManifestSigHashHex: input.previous?.signedBytesHashHex ?? "",
    issuerUserId: input.issuerUserId,
    chainHeadHashHex: input.chainHead.hashHex,
    chainHeadSeq: input.chainHead.seq,
  };
  const signature = yield* cryptoEffect(() =>
    signEnvManifest({ context, signingKey: input.signingKey }),
  ).pipe(Effect.mapError(() => cliError("Failed to sign the environment manifest")));
  const hash = yield* cryptoEffect(() => computeEnvManifestSignedBytesHash(context)).pipe(
    Effect.mapError(() => cliError("Failed to compute the manifest signed-bytes hash")),
  );
  return {
    manifest: {
      suite: SUITE_ID,
      environmentId: context.environmentId,
      epoch: context.epoch,
      manifestVersion: context.manifestVersion,
      variablesDigestHex: context.variablesDigestHex,
      envMetaVersion: context.envMetaVersion,
      envMetaSigHashHex: context.envMetaSigHashHex,
      prevManifestSigHashHex: context.prevManifestSigHashHex,
      chainHeadHashHex: context.chainHeadHashHex,
      chainHeadSeq: context.chainHeadSeq,
      signatureHex: signature,
    },
    manifestSigHashHex: hash,
    manifestVersion: context.manifestVersion,
    epoch: context.epoch,
  };
});

export type ManifestVerifyOutcome =
  | { readonly kind: "ok"; readonly value: VerifiedManifest }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string };

export async function verifyDistributedManifest(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly floorManifest?: ManifestFloor | null;
}): Promise<ManifestVerifyOutcome> {
  const manifest = input.manifest;
  if (manifest.environmentId !== input.environmentId) {
    return {
      kind: "rejected",
      message: `The environment manifest's coordinates do not match the requested environment ${input.environmentId} (possible transplantation)`,
    };
  }
  const floorManifest = input.floorManifest ?? null;
  const predecessor =
    floorManifest !== null && manifest.manifestVersion === floorManifest.manifestVersion + 1
      ? {
          signedBytesHashHex: floorManifest.manifestSigHashHex,
          epoch: floorManifest.epoch,
        }
      : undefined;
  return Effect.runPromise(
    cryptoEffect(() =>
      verifyDistributedEnvManifest({
        history: input.verified.history,
        context: {
          suite: manifest.suite,
          projectId: input.verified.projectId,
          environmentId: input.environmentId,
          epoch: manifest.epoch,
          manifestVersion: manifest.manifestVersion,
          variablesDigestHex: manifest.variablesDigestHex,
          envMetaVersion: manifest.envMetaVersion,
          envMetaSigHashHex: manifest.envMetaSigHashHex,
          prevManifestSigHashHex: manifest.prevManifestSigHashHex,
          issuerUserId: manifest.issuerUserId,
          chainHeadHashHex: manifest.chainHeadHashHex,
          chainHeadSeq: manifest.chainHeadSeq,
        },
        issuerKeyFingerprintHex: manifest.issuerKeyFingerprintHex,
        signatureHex: manifest.signatureHex,
        entries: input.entries,
        envMeta: { metaVersion: input.envMeta.metaVersion, sigHashHex: input.envMeta.sigHashHex },
        ...(predecessor === undefined ? {} : { predecessor }),
      }),
    ).pipe(
      Effect.match({
        onSuccess: (value): ManifestVerifyOutcome => ({
          kind: "ok",
          value: {
            manifestVersion: manifest.manifestVersion,
            epoch: manifest.epoch,
            variablesDigestHex: manifest.variablesDigestHex,
            envMetaVersion: manifest.envMetaVersion,
            envMetaSigHashHex: manifest.envMetaSigHashHex,
            prevManifestSigHashHex: manifest.prevManifestSigHashHex,
            signedBytesHashHex: value.signedBytesHashHex,
            chainHeadSeq: manifest.chainHeadSeq,
            chainHeadHashHex: manifest.chainHeadHashHex,
            signatureHex: manifest.signatureHex,
            issuerUserId: manifest.issuerUserId,
            issuerKeyFingerprintHex: manifest.issuerKeyFingerprintHex,
          },
        }),
        onFailure: (error): ManifestVerifyOutcome => {
          if (error instanceof CryptoEnvManifestInvalidError) {
            const unknownSigner = error.reason === "issuer-unknown";
            if (
              error.reason === "chain-head-future" ||
              (unknownSigner && manifest.chainHeadSeq > input.verified.history.headSeq)
            ) {
              return { kind: "future" };
            }
            if (predecessor !== undefined && error.reason === "prev-hash-mismatch") {
              return {
                kind: "rejected",
                message: [
                  `Environment ${input.environmentId}'s manifest (manifestVersion ${manifest.manifestVersion}) declares a prev that does not match the verified predecessor recorded in the local floor (evidence of a diverged manifest chain — CRYPTO_SPEC §4.3 rule (1))`,
                  `  floor record (previously verified): manifestVersion=${floorManifest?.manifestVersion ?? 0} manifest_signed_bytes_hash=${predecessor.signedBytesHashHex}`,
                  `  this distribution: prevManifestSigHashHex=${manifest.prevManifestSigHashHex}`,
                  `    declared head: seq=${manifest.chainHeadSeq} hash=${manifest.chainHeadHashHex}`,
                  `    issuer signature: issuer=${displayText(manifest.issuerUserId)} fp=${manifest.issuerKeyFingerprintHex}`,
                  `    signature=${manifest.signatureHex}`,
                  "  Preserve this output and the local floor log, and present them to the project administrators",
                ].join("\n"),
              };
            }
            return {
              kind: "rejected",
              message: `Verification of environment ${input.environmentId}'s manifest failed (reason=${error.reason}). Statements may have been omitted, injected or replaced by the server (CRYPTO_SPEC §4.3)`,
            };
          }
          return {
            kind: "rejected",
            message: `Verification of environment ${input.environmentId}'s manifest failed (reason=${cryptoErrorKind(error)})`,
          };
        },
      }),
    ),
  );
}
