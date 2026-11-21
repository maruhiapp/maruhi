import { ManifestVersionConflictError, MetaVersionConflictError } from "@maruhi/api-schema";
import { type EnvironmentId, type UserId } from "@maruhi/core";
import type { SigningKeyPair } from "@maruhi/crypto";
import { SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { requireWritingMember } from "../dek-wrap.ts";
import { requireChainEnvironment } from "../deks.ts";
import { usageError, type CliError } from "../errors.ts";
import type { FloorHandle, VerifiedEnvironmentStatement } from "../floor-check.ts";
import { signStatementAndHash } from "../meta-statement.ts";
import {
  type ManifestIssueBase,
  manifestIssueBaseOf,
  pullVerifiedEnvironmentMetadata,
} from "../values.ts";

const MAX_NAME_LENGTH = 256;

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

export interface EnvironmentMetaInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
}

export interface EnvironmentMetaState {
  readonly verified: VerifiedProject;
  readonly environment: VerifiedEnvironmentStatement;
  readonly manifestBase: ManifestIssueBase;
  readonly currentEpoch: number;
  readonly variableNames: readonly VerifiedVariableName[];
  readonly warnings: readonly string[];
}

export interface VerifiedVariableName {
  readonly variableId: string;
  readonly name: string;
  readonly deleted: boolean;
}

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
    variableNames: [
      ...metadata.variables.map(({ variableId, name }) => ({ variableId, name, deleted: false })),
      ...metadata.tombstones.map(({ variableId, name }) => ({ variableId, name, deleted: true })),
    ],
    warnings: metadata.warnings,
  };
});

export const signNextEnvironmentStatement = Effect.fn("env-meta.signNextEnvironmentStatement")(
  function* (input: {
    readonly state: EnvironmentMetaState;
    readonly environmentId: EnvironmentId;
    readonly name: string;
    readonly authorUserId: UserId;
    readonly signingKey: CryptoKey;
  }) {
    const context = {
      suite: SUITE_ID,
      projectId: input.state.verified.projectId,
      environmentId: input.environmentId,
      target: { kind: "environment" },
      name: input.name,
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

export function isEnvironmentMetaConflict(error: unknown): boolean {
  return error instanceof MetaVersionConflictError || error instanceof ManifestVersionConflictError;
}
