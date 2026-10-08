// The CLI's shared implementation of issuing and verifying the
// environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-5).
//
// Issuance (env create / rotate / push's variable creation): the
// same discipline as meta-statement.ts — the wire is derived
// mechanically from "the signed context" (an independent literal is
// never re-enumerated, because a one-field discrepancy becomes a
// silent verification failure). Verification (both pull modes, the
// lease response): digest recomputation from the verified statement
// set (tombstones included), epoch consistency, and signature /
// authorization time are delegated to @maruhi/crypto's
// verifyDistributedEnvManifest (the single implementation shared
// with the server — §4.3).
//
// **Missing manifest = uniform refusal** (§6.3 — the "warn if
// uninitialized" branch is a relaxation path an attacker can
// choose, so it does not exist). Required on the wire since
// 0.28-draft: the schema refuses the omission at decode — the
// same verdict as a dropped environment statement.

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

/**
 * The evidence material of a verified manifest (§14.2-5's
 * self-containedness — the comparison target of the floor's
 * manifest extension, the next manifestVersion's prev, and
 * equivocation evidence).
 */
export interface VerifiedManifest {
  readonly manifestVersion: number;
  /** The current epoch at issuance time (§4.3's freshness anchor — the material of floor rule (c)'s manifest application). */
  readonly epoch: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  readonly prevManifestSigHashHex: string;
  /** The self-computed signed-bytes hash (floor rule (b)'s comparison target, the basis of the next prev). */
  readonly signedBytesHashHex: string;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly signatureHex: string;
  readonly issuerUserId: UserId;
  readonly issuerKeyFingerprintHex: string;
}

/** The input of variables_digest (the latest form of verified statements — tombstones included, §4.3). */
export type ManifestDigestEntry = VariablesDigestEntry;

/** Issuance input: the previous manifest (none = env create's v1) and the post-issuance meta state. */
interface SignManifestInput {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  /** The current epoch at issuance time (rotate compound = new_epoch; otherwise = the verified view's current epoch). */
  readonly epoch: number;
  /** The verified previous manifest (null = no stored manifest → manifestVersion 1). */
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  /** Every variable entry of the post-issuance meta state (tombstones included — §4.3 (3)'s recomputation target). */
  readonly entries: readonly ManifestDigestEntry[];
  /** The latest form of the post-issuance environment meta statement. */
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly issuerUserId: UserId;
  readonly signingKey: CryptoKey;
  /**
   * The declared head. Compound (env create / rotate) = the current
   * head before the append (§12-4); meta operation = the last
   * verified chain head. If the verified view advances on a CAS
   * retry, the caller rebuilds it (each attempt is signed — same
   * convention as meta-statement.ts).
   */
  readonly chainHead: { readonly seq: number; readonly hashHex: string };
}

export interface SignedManifest {
  readonly manifest: EnvironmentManifest;
  /** The self-computed hash that, once accepted, becomes the local floor's manifest record (§6.3). */
  readonly manifestSigHashHex: string;
  /** The signed manifestVersion / epoch (for floor records and display). */
  readonly manifestVersion: number;
  readonly epoch: number;
}

/**
 * Issues the next environment manifest (CRYPTO_SPEC §4.3): computes the
 * canonical variables digest from the post-operation statement set, signs the
 * context, and derives the wire manifest mechanically from that very context
 * so the signed bytes and the wire can never drift apart.
 */
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
    // The wire is entirely derived from the signed context (this
    // module's reason to exist. suite is a Literal — the context
    // is built with SUITE_ID inside)
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

/** The distributed manifest's verification result (future = the entry to bounded re-sync — values.ts's shared convention). */
export type ManifestVerifyOutcome =
  | { readonly kind: "ok"; readonly value: VerifiedManifest }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string };

/**
 * Verifies one distributed environment manifest against the verified chain
 * history and the **verified** statement set (CRYPTO_SPEC §4.3 / §6.3):
 * signature / head binding / head-time authorization, epoch integrity
 * (composite issuance included), env-meta binding and the digest
 * recomputation — all through the single shared implementation in
 * @maruhi/crypto. Coordinates are rebuilt from expected values, never from
 * wire claims (§6.3-5).
 *
 * **Adjacent-version prev-chain verification (CRYPTO_SPEC §4.3
 * verification rule (1) — session-31 §3)**: when the floor holds a
 * manifest record and the distributed version is immediately after
 * the floor's (pulled.manifestVersion = floor.manifestVersion + 1),
 * the floor IS the previous manifest, so the floor's signed-bytes
 * hash is passed to the shared verifier as the predecessor and
 * `prevManifestSigHashHex` is strictly verified. A version gap of 2
 * or more cannot check the actual identity of intermediate
 * predecessors, per latest-only's known constraint (§14.3 — not
 * falsely claimed as checked). Same-version and regression are the
 * floor checks' job (rules (a)(b)). Floorless paths (first sync,
 * lease — the workload is a floorless first-sync class §14.3-3)
 * pass floor = null as before.
 */
export async function verifyDistributedManifest(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  /** The local floor's manifest record (the predecessor of adjacent-prev verification — null = no floor). */
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
        // Only an adjacent version gets the floor-derived predecessor
        // (above). Otherwise it follows latest-only's known constraint —
        // detecting cross-session regression, same-version difference,
        // and forward injection is the floor's manifest extension's job
        // (floor-check.ts's rules (a)(b)(c))
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
              // An adjacent-prev mismatch is a contradiction against the
              // floor (the verified previous manifest) = evidence of a fork
              // in the manifest chain. Include material presentable to a
              // third party (both hashes, the issuer, the declared head)
              // (session-31 §3)
              return {
                kind: "rejected",
                message: [
                  `Environment ${input.environmentId}'s manifest (manifestVersion ${manifest.manifestVersion}) declares a prev that does not match the verified predecessor recorded in the local floor (evidence of a diverged manifest chain — CRYPTO_SPEC §4.3 rule (1))`,
                  `  floor record (previously verified): manifestVersion=${floorManifest?.manifestVersion ?? 0} manifest_signed_bytes_hash=${predecessor.signedBytesHashHex}`,
                  `  this distribution: prevManifestSigHashHex=${manifest.prevManifestSigHashHex}`,
                  `    declared head: seq=${manifest.chainHeadSeq} hash=${manifest.chainHeadHashHex}`,
                  // user_id is a length-constrained free-form string on the wire — neutralize before showing on the terminal
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
