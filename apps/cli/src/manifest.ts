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
// choose, so it does not exist).

import type { DistributedEnvironmentManifest, EnvironmentManifest } from "@maruhi/api-schema";
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
  readonly issuerUserId: string;
  readonly issuerKeyFingerprintHex: string;
}

/** The input of variables_digest (the latest form of verified statements — tombstones included, §4.3). */
export type ManifestDigestEntry = VariablesDigestEntry;

/** Issuance input: the previous manifest (none = env create's v1) and the post-issuance meta state. */
export interface SignManifestInput {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
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
  readonly issuerUserId: string;
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
export function signNextManifest(
  input: SignManifestInput,
): Effect.Effect<SignedManifest, CliError> {
  return Effect.gen(function* () {
    const digest = yield* Effect.tryPromise({
      try: () => computeVariablesDigest(SUITE_ID, input.entries),
      catch: () => cliError("Failed to compute the manifest variables digest"),
    });
    if (!digest.ok) {
      return yield* Effect.fail(cliError("Failed to compute the manifest variables digest"));
    }
    const context: EnvManifestContext = {
      suite: SUITE_ID,
      projectId: input.verified.projectId,
      environmentId: input.environmentId,
      epoch: input.epoch,
      manifestVersion: (input.previous?.manifestVersion ?? 0) + 1,
      variablesDigestHex: digest.value,
      envMetaVersion: input.envMeta.metaVersion,
      envMetaSigHashHex: input.envMeta.sigHashHex,
      prevManifestSigHashHex: input.previous?.signedBytesHashHex ?? "",
      issuerUserId: input.issuerUserId,
      chainHeadHashHex: input.chainHead.hashHex,
      chainHeadSeq: input.chainHead.seq,
    };
    const signature = yield* Effect.tryPromise({
      try: () => signEnvManifest({ context, signingKey: input.signingKey }),
      catch: () => cliError("Failed to sign the environment manifest"),
    });
    if (!signature.ok) {
      return yield* Effect.fail(cliError("Failed to sign the environment manifest"));
    }
    const hash = yield* Effect.tryPromise({
      try: () => computeEnvManifestSignedBytesHash(context),
      catch: () => cliError("Failed to compute the manifest signed-bytes hash"),
    });
    if (!hash.ok) {
      return yield* Effect.fail(cliError("Failed to compute the manifest signed-bytes hash"));
    }
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
        signatureHex: signature.value,
      },
      manifestSigHashHex: hash.value,
      manifestVersion: context.manifestVersion,
      epoch: context.epoch,
    };
  });
}

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
  readonly environmentId: string;
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
  const result = await verifyDistributedEnvManifest({
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
  });
  if (result.ok) {
    return {
      kind: "ok",
      value: {
        manifestVersion: manifest.manifestVersion,
        epoch: manifest.epoch,
        variablesDigestHex: manifest.variablesDigestHex,
        envMetaVersion: manifest.envMetaVersion,
        envMetaSigHashHex: manifest.envMetaSigHashHex,
        prevManifestSigHashHex: manifest.prevManifestSigHashHex,
        signedBytesHashHex: result.value.signedBytesHashHex,
        chainHeadSeq: manifest.chainHeadSeq,
        chainHeadHashHex: manifest.chainHeadHashHex,
        signatureHex: manifest.signatureHex,
        issuerUserId: manifest.issuerUserId,
        issuerKeyFingerprintHex: manifest.issuerKeyFingerprintHex,
      },
    };
  }
  const error = result.error;
  if (error.kind === "EnvManifestInvalid") {
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
    message: `Verification of environment ${input.environmentId}'s manifest failed (reason=${error.kind})`,
  };
}

/** The uniform refusal message for a missing manifest (§6.3). */
export function missingManifestMessage(environmentId: string): string {
  return (
    `The server did not distribute an environment manifest for ${environmentId}. ` +
    "A missing manifest is treated as manifest suppression (statement omission cannot be ruled out — CRYPTO_SPEC §6.3) and the response is rejected"
  );
}
