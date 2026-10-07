// Shared resolution and signing for the operations on an environment —
// `maruhi env rename` (env-rename.ts) and `maruhi env rm` (env-rm.ts). A
// rename signs the environment's next meta statement under §12-5's meta
// rules (AUTH_SPEC §12-4): metaVersion + 1, prev chained to the verified
// current statement, the last verified chain head declared; a metaVersion
// CAS conflict (409) refetches, re-verifies and re-signs. A deletion is a
// chain entry (CRYPTO_SPEC §6.2 delete_environment) and shares only the
// verified resolution and the pre-signing permission check.
//
// The current statement comes only from a verified metadata-only pull
// (§12-7 — no values are fetched and no `var.read` is recorded): the
// environment statement, every variable statement and tombstone, and the
// manifest are verified against the chain and the local floor before
// anything is signed (CRYPTO_SPEC §6.3). The manifest's digest consistency
// is what gives the meta statement its freshness anchor (§4.2 / §4.3).

import { ManifestVersionConflictError, MetaVersionConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { SigningKeyPair } from "@maruhi/crypto";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { requireWritingMember } from "./dek-wrap.ts";
import { requireChainEnvironment } from "./deks.ts";
import { usageError, type CliError } from "./errors.ts";
import type { FloorHandle, VerifiedEnvironmentStatement } from "./floor-check.ts";
import { signStatementAndHash } from "./meta-statement.ts";
import {
  type ManifestIssueBase,
  manifestIssueBaseOf,
  pullVerifiedEnvironmentMetadata,
} from "./values.ts";

/** The display-name cap of a meta statement (§12-8 — the wire Schema's limit, in UTF-16 code units). */
const MAX_NAME_LENGTH = 256;

/**
 * The display-name rule shared by `env create --name` and `env rename`:
 * NFC-normalized by the client before signing (§4.2 / §12-1 — the server
 * only checks), and within the §12-8 length cap. The given name is not
 * echoed in the refusal (a positional could carry anything).
 */
export function normalizeEnvironmentName(raw: string): Effect.Effect<string, CliError> {
  const name = raw.normalize("NFC");
  return name.length === 0 || name.length > MAX_NAME_LENGTH
    ? Effect.fail(
        usageError(
          `The environment display name must be 1 to ${MAX_NAME_LENGTH} characters long (after NFC normalization)`,
        ),
      )
    : Effect.succeed(name);
}

/** The inputs every environment meta operation shares. */
export interface EnvironmentMetaInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the metadata pull's check and commit). */
  readonly floor: FloorHandle;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
}

/** The verified current state an environment meta operation signs over. */
export interface EnvironmentMetaState {
  /** The view used for verification (may have advanced via the pull's bounded resync). */
  readonly verified: VerifiedProject;
  /** The verified current (active) environment statement. */
  readonly environment: VerifiedEnvironmentStatement;
  /** The previous manifest and the current meta set (rename's manifest issuance material). */
  readonly manifestBase: ManifestIssueBase;
  /** The chain-derived current epoch (the next manifest's epoch — §4.3). */
  readonly currentEpoch: number;
  readonly warnings: readonly string[];
}

/**
 * The pre-signing permission check on the verified chain (the server's 403
 * is not waited for): the signing device's effective role and scope
 * (rename = member — §12-3 / CRYPTO_SPEC §4.2; deletion = admin —
 * CRYPTO_SPEC §6.2 delete_environment).
 */
export function requireEnvironmentMetaAuthor(
  input: EnvironmentMetaInput,
  requirement: {
    readonly minimumRole: "member" | "admin";
    readonly operation: string;
    readonly forbidden: string;
  },
): Effect.Effect<void, CliError> {
  return Effect.asVoid(
    requireWritingMember({
      verified: input.verified,
      environmentId: input.environmentId,
      target: "existing",
      signerUserId: input.signerUserId,
      signingKeyPair: input.signingKeyPair,
      ...requirement,
    }),
  );
}

/** Resolves the verified current environment statement and the manifest issuance material. */
export const resolveEnvironmentMeta = Effect.fn("env-meta.resolveEnvironmentMeta")(function* (
  input: EnvironmentMetaInput,
  verified: VerifiedProject,
): Effect.fn.Return<EnvironmentMetaState, CliError> {
  const metadata = yield* pullVerifiedEnvironmentMetadata({
    client: input.client,
    verified,
    environmentId: input.environmentId,
    resync: input.resync,
    floor: input.floor,
  });
  const chainEnvironment = yield* requireChainEnvironment(metadata.verified, input.environmentId);
  return {
    verified: metadata.verified,
    environment: metadata.environment,
    manifestBase: manifestIssueBaseOf(metadata),
    currentEpoch: chainEnvironment.currentEpoch,
    warnings: metadata.warnings,
  };
});

/**
 * Signs the environment's next meta statement (metaVersion + 1, prev = the
 * verified current statement's signed-bytes hash, declared head = the last
 * verified head) and derives the wire statement mechanically from the very
 * context that was signed (meta-statement.ts's discipline).
 */
export const signNextEnvironmentStatement = Effect.fn("env-meta.signNextEnvironmentStatement")(
  function* (input: {
    readonly state: EnvironmentMetaState;
    readonly environmentId: string;
    /** The NFC-normalized name. */
    readonly name: string;
    readonly authorUserId: string;
    readonly signingKey: CryptoKey;
  }) {
    const context = {
      suite: SUITE_ID,
      projectId: input.state.verified.projectId,
      environmentId: input.environmentId,
      target: { kind: "environment" },
      name: input.name,
      // An environment statement is always active (a deletion is the chain
      // op delete_environment — CRYPTO_SPEC §4.2 / §6.2)
      status: "active",
      metaVersion: input.state.environment.metaVersion + 1,
      prevMetaSigHashHex: input.state.environment.metaSigHashHex,
      authorUserId: input.authorUserId,
      chainHeadHashHex: input.state.verified.state.headHashHex,
      chainHeadSeq: input.state.verified.state.headSeq,
    } as const;
    const signed = yield* signStatementAndHash(context, input.signingKey);
    return {
      statement: {
        suite: context.suite,
        environmentId: context.environmentId,
        name: context.name,
        status: context.status,
        metaVersion: context.metaVersion,
        prevMetaSigHashHex: context.prevMetaSigHashHex,
        chainHeadHashHex: context.chainHeadHashHex,
        chainHeadSeq: context.chainHeadSeq,
        signatureHex: signed.signatureHex,
      },
      metaVersion: context.metaVersion,
      metaSigHashHex: signed.metaSigHashHex,
    };
  },
);

/** The retryable CAS conflicts of an environment meta operation (§12-5 — refetch, re-verify, re-sign). */
export function isEnvironmentMetaConflict(error: unknown): boolean {
  return error instanceof MetaVersionConflictError || error instanceof ManifestVersionConflictError;
}
