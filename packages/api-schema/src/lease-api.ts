import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { ChainEntrySchema } from "./chain.ts";
import { PulledVariableSchema } from "./data-api.ts";
import {
  BoundedUserId,
  CheckpointValueSnapshotSchema,
  DistributedEnvironmentMetaStatementSchema,
  DistributedVariableMetaStatementSchema,
  LeasedDekSchema,
  RequiredDistributedEnvironmentManifestSchema,
} from "./data.ts";
import {
  LeaseRateLimitedError,
  LeaseUnauthorizedError,
  LeaseUnavailableError,
  ProjectNotFoundError,
  RotationProposalRejectedError,
  SetupIncompleteError,
} from "./errors.package/index.ts";
import { EncPubHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { RotationProposalInputSchema, RotationProposalReceiptSchema } from "./rotation-api.ts";
import { strictPayload } from "./strict.ts";

const OidcTokenSchema = Schema.String.check(
  Schema.isMaxLength(16 * 1024),
  Schema.isPattern(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, {
    description: "compact JWS (three base64url segments)",
  }),
);

export const LeaseRequestSchema = Schema.Struct({
  oidcToken: OidcTokenSchema,
  ephemeralPubHex: EncPubHex,
});

export const LeaseResponseSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  currentEpoch: PositiveInt,
  chain: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  statement: DistributedEnvironmentMetaStatementSchema,
  variables: Schema.Array(PulledVariableSchema),
  deletedVariables: Schema.Array(DistributedVariableMetaStatementSchema),
  declaredVariables: Schema.optionalKey(Schema.Array(DistributedVariableMetaStatementSchema)),
  leases: Schema.Array(LeasedDekSchema),
  manifest: RequiredDistributedEnvironmentManifestSchema,
  checkpointSnapshot: Schema.optionalKey(CheckpointValueSnapshotSchema),
});

export const RotationProposalRequestSchema = Schema.Struct({
  ...LeaseRequestSchema.fields,
  proposal: RotationProposalInputSchema,
});

export const RotationPreflightRequestSchema = Schema.Struct({
  ...LeaseRequestSchema.fields,
  variables: Schema.Array(
    Schema.Struct({ variableId: VariableIdSchema, baseVersion: PositiveInt }),
  ).check(Schema.isMinLength(1), Schema.isMaxLength(8)),
  recipients: Schema.Array(Schema.Struct({ userId: BoundedUserId, encPubHex: EncPubHex })).check(
    Schema.isMaxLength(10_000),
  ),
});

export const RotationPreflightResultSchema = Schema.Struct({ ok: Schema.Literal(true) });

export const leaseGroup = HttpApiGroup.make("lease")
  .add(
    HttpApiEndpoint.post(
      "propose",
      "/projects/:projectId/environments/:environmentId/rotation-proposals",
      {
        params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
        payload: strictPayload(RotationProposalRequestSchema),
        success: RotationProposalReceiptSchema,
        error: [
          LeaseUnauthorizedError,
          ProjectNotFoundError,
          LeaseRateLimitedError,
          LeaseUnavailableError,
          SetupIncompleteError,
          RotationProposalRejectedError,
        ],
      },
    ),
  )
  .add(
    HttpApiEndpoint.post(
      "preflight",
      "/projects/:projectId/environments/:environmentId/rotation-proposals/preflight",
      {
        params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
        payload: strictPayload(RotationPreflightRequestSchema),
        success: RotationPreflightResultSchema,
        error: [
          LeaseUnauthorizedError,
          ProjectNotFoundError,
          LeaseRateLimitedError,
          LeaseUnavailableError,
          SetupIncompleteError,
          RotationProposalRejectedError,
        ],
      },
    ),
  )
  .add(
    HttpApiEndpoint.post("issue", "/projects/:projectId/environments/:environmentId/lease", {
      params: { projectId: ProjectIdSchema, environmentId: EnvironmentIdSchema },
      payload: strictPayload(LeaseRequestSchema),
      success: LeaseResponseSchema,
      error: [
        LeaseUnauthorizedError,
        ProjectNotFoundError,
        LeaseRateLimitedError,
        LeaseUnavailableError,
        SetupIncompleteError,
      ],
    }),
  );
