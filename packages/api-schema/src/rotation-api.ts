import {
  EnvironmentIdSchema,
  ProjectIdSchema,
  ROTATION_CONNECTORS,
  UserIdSchema,
  VariableIdSchema,
} from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import { BoundedUserId } from "./data.ts";
import {
  DataLimitExceededError,
  ForbiddenError,
  ProjectNotFoundError,
  RotationFlagNotFoundError,
  RotationProposalNotFoundError,
  RotationProposalRejectedError,
} from "./errors.package/index.ts";
import {
  EncPubHex,
  hexString,
  HpkeEncHex,
  KeyFingerprintHex,
  PositiveInt,
  Sha256Hex,
} from "./hex.ts";
import { strictPayload } from "./strict.ts";

export const RotationFlagBasisSchema = Schema.Literals(["read", "readable"]);

export const RotationFlagTriggerSchema = Schema.Literals([
  "remove_member",
  "change_role",
  "revoke_server",
  "revoke_device",
]);

export const RotationFlagSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
  basis: RotationFlagBasisSchema,
  targetUserId: Schema.optionalKey(UserIdSchema),
  targetServerKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  recommendedAtMs: Schema.Number,
  triggerChainSeq: PositiveInt,
  trigger: RotationFlagTriggerSchema,
  reopenedByVersion: Schema.optionalKey(PositiveInt),
});

export const RotationFlagListSchema = Schema.Struct({
  flags: Schema.Array(RotationFlagSchema),
});

export const RotationDismissTargetSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
});

export const ProposalIdSchema = hexString(16);

export const RotationConnectorSchema = Schema.Literals(ROTATION_CONNECTORS);

const ProposalFactSchema = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(256),
  Schema.isPattern(/^\P{Cc}*$/u, { description: "no control characters" }),
);

const SealedValueCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){17,65536}$/, {
    description: "lowercase hex HPKE ciphertext (17 to 65536 bytes incl. tag)",
  }),
);

export const SealedValueWrapSchema = Schema.Struct({
  recipientUserId: BoundedUserId,
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: SealedValueCiphertextHex,
});

export type SealedValueWrap = typeof SealedValueWrapSchema.Type;

export const ProposedVariableSchema = Schema.Struct({
  variableId: VariableIdSchema,
  baseVersion: PositiveInt,
  wraps: Schema.Array(SealedValueWrapSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(10_000),
  ),
});

export const RotationProposalInputSchema = Schema.Struct({
  proposalId: ProposalIdSchema,
  connector: RotationConnectorSchema,
  facts: Schema.Array(ProposalFactSchema).check(Schema.isMaxLength(16)),
  expiresInDays: Schema.Number.check(
    Schema.isInt(),
    Schema.isGreaterThanOrEqualTo(1),
    Schema.isLessThanOrEqualTo(30),
  ),
  variables: Schema.Array(ProposedVariableSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(8),
  ),
});

export type RotationProposalInput = typeof RotationProposalInputSchema.Type;

export const RotationProposalReceiptSchema = Schema.Struct({
  proposalId: ProposalIdSchema,
  expiresAtMs: Schema.Number,
});

export const RotationProposalSchema = Schema.Struct({
  proposalId: ProposalIdSchema,
  environmentId: EnvironmentIdSchema,
  connector: RotationConnectorSchema,
  facts: Schema.Array(ProposalFactSchema),
  claimsDigestHex: Sha256Hex,
  grantChainSeq: PositiveInt,
  createdAtMs: Schema.Number,
  expiresAtMs: Schema.Number,
  variables: Schema.Array(
    Schema.Struct({
      variableId: VariableIdSchema,
      baseVersion: PositiveInt,
      wraps: Schema.Array(SealedValueWrapSchema),
    }),
  ),
});

export type RotationProposal = typeof RotationProposalSchema.Type;

export const RotationProposalListSchema = Schema.Struct({
  proposals: Schema.Array(RotationProposalSchema),
});

export const RotationProposalResolutionSchema = Schema.Struct({
  outcome: Schema.Literals(["accepted", "rejected"]),
  versions: Schema.optionalKey(
    Schema.Array(Schema.Struct({ variableId: VariableIdSchema, version: PositiveInt })).check(
      Schema.isMaxLength(8),
    ),
  ),
});

export type RotationProposalResolution = typeof RotationProposalResolutionSchema.Type;

export const rotationGroup = HttpApiGroup.make("rotation")
  .add(
    HttpApiEndpoint.get("flags", "/projects/:projectId/rotation/flags", {
      params: { projectId: ProjectIdSchema },
      success: RotationFlagListSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("dismiss", "/projects/:projectId/rotation/dismissals", {
      params: { projectId: ProjectIdSchema },
      payload: Schema.Struct({
        targets: Schema.Array(RotationDismissTargetSchema).check(Schema.isMinLength(1)),
      }),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        ForbiddenError,
        RotationFlagNotFoundError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("proposals", "/projects/:projectId/rotation/proposals", {
      params: { projectId: ProjectIdSchema },
      success: RotationProposalListSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post(
      "resolveProposal",
      "/projects/:projectId/rotation/proposals/:proposalId/resolution",
      {
        params: { projectId: ProjectIdSchema, proposalId: ProposalIdSchema },
        payload: strictPayload(RotationProposalResolutionSchema),
        success: HttpApiSchema.NoContent,
        error: [
          ProjectNotFoundError,
          ForbiddenError,
          RotationProposalNotFoundError,
          RotationProposalRejectedError,
        ],
      },
    ).middleware(AuthMiddleware),
  );
