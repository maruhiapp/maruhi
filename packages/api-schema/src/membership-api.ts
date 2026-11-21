import { OrgIdSchema, ProjectIdSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import {
  HttpApi,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiSchema,
} from "effect/http-api";

import { auditGroup } from "./audit-api.ts";
import { authGroup } from "./auth-api.ts";
import { authCliGroup } from "./auth-cli-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import { ChainEntrySchema, RoleSchema } from "./chain.ts";
import { deksGroup, environmentsGroup, schemaPolicyGroup, variablesGroup } from "./data-api.ts";
import { devicesGroup } from "./devices-api.ts";
import {
  AttestationRateLimitedError,
  AttestationRegressionError,
  AttestationRejectedError,
  AuditHeadNotReadyError,
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CheckpointStateMismatchError,
  CompositeRequiredError,
  DataLimitExceededError,
  DeviceLimitError,
  ForbiddenError,
  ProjectAlreadyInitializedError,
  ProjectLimitError,
  ProjectNotFoundError,
  ProposalLimitError,
} from "./errors.package/index.ts";
import { exportGroup } from "./export-api.ts";
import { HeadAttestationSignatureHex, KeyFingerprintHex, PositiveInt, Sha256Hex } from "./hex.ts";
import { invitesGroup } from "./invites-api.ts";
import { keyWrapsGroup } from "./key-wraps-api.ts";
import { leaseGroup } from "./lease-api.ts";
import { mirrorGroup } from "./mirror-api.ts";
import { rotationGroup } from "./rotation-api.ts";
import { assertSessionCapabilityClassified } from "./session-capability.ts";
import { assertSecurityCriticalPayloadsStrict, strictPayload } from "./strict.ts";

export const ChainHeadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
});

export const HeadAttestationSubmissionSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

export const DistributedHeadAttestationSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  attesterUserId: UserIdSchema,
  attesterKeyFingerprintHex: KeyFingerprintHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: HeadAttestationSignatureHex,
});

export const ChainSnapshotSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  entries: Schema.Array(ChainEntrySchema),
  headSeq: PositiveInt,
  headHashHex: Sha256Hex,
  attestations: Schema.Array(DistributedHeadAttestationSchema),
});

export const ProjectMembershipSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  role: RoleSchema,
});

export const ProjectListSchema = Schema.Struct({
  projects: Schema.Array(ProjectMembershipSchema),
  nextAfter: Schema.optionalKey(ProjectIdSchema),
});

export const membershipGroup = HttpApiGroup.make("membership")
  .add(
    HttpApiEndpoint.post("init", "/projects", {
      payload: strictPayload(Schema.Struct({ orgId: OrgIdSchema, entry: ChainEntrySchema })),
      success: ChainHeadSchema,
      error: [
        ProjectAlreadyInitializedError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ForbiddenError,
        ProjectLimitError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("list", "/projects", {
      query: { after: Schema.optionalKey(ProjectIdSchema) },
      success: ProjectListSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("get", "/projects/:projectId/chain", {
      params: { projectId: ProjectIdSchema },
      success: ChainSnapshotSchema,
      error: [ProjectNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("append", "/projects/:projectId/chain/entries", {
      params: { projectId: ProjectIdSchema },
      payload: strictPayload(
        Schema.Struct({
          parentHeadHashHex: Sha256Hex,
          entry: ChainEntrySchema,
        }),
      ),
      success: ChainHeadSchema,
      error: [
        ProjectNotFoundError,
        ChainHeadConflictError,
        ChainEntryInvalidError,
        ChainEntryTooLargeError,
        ChainCapacityExceededError,
        CheckpointStateMismatchError,
        AuditHeadNotReadyError,
        CompositeRequiredError,
        ProposalLimitError,
        DeviceLimitError,
        ForbiddenError,
        DataLimitExceededError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.put("attest", "/projects/:projectId/head-attestation", {
      params: { projectId: ProjectIdSchema },
      payload: strictPayload(HeadAttestationSubmissionSchema),
      success: HttpApiSchema.NoContent,
      error: [
        ProjectNotFoundError,
        AttestationRegressionError,
        AttestationRejectedError,
        AttestationRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  );

export const maruhiApi = HttpApi.make("maruhi")
  .add(membershipGroup)
  .add(authGroup)
  .add(authCliGroup)
  .add(environmentsGroup)
  .add(variablesGroup)
  .add(deksGroup)
  .add(schemaPolicyGroup)
  .add(invitesGroup)
  .add(keyWrapsGroup)
  .add(devicesGroup)
  .add(rotationGroup)
  .add(auditGroup)
  .add(exportGroup)
  .add(mirrorGroup)
  .add(leaseGroup)
  .middleware(HttpApiMiddleware.ProblemDetails)
  .annotate(HttpApi.RedactedNames, {
    query: ["code", "state", "signup_code", "vsig"],
    headers: ["authorization", "cookie", "set-cookie"],
  });

assertSecurityCriticalPayloadsStrict(maruhiApi);

assertSessionCapabilityClassified(maruhiApi);
