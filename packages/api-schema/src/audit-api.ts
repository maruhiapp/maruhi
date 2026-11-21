import { OrgIdSchema, ProjectIdSchema, UserIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/http-api";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  AuditHeadNotReadyError,
  DataLimitExceededError,
  ForbiddenError,
  ProjectNotFoundError,
} from "./errors.package/index.ts";
import { hexPattern, hexString, KeyFingerprintHex, PositiveInt } from "./hex.ts";

export const MAX_AUDIT_EVENTS_PAGE_LIMIT = 200;

export const DEFAULT_AUDIT_EVENTS_PAGE_LIMIT = 50;

const ROW_ID_BYTES = 16;

export const AUDIT_ROW_ID_PATTERN = hexPattern(ROW_ID_BYTES);

const RowIdHex = hexString(ROW_ID_BYTES);

export const AuditActorSchema = Schema.Struct({
  type: Schema.Literals(["user", "server", "system"]),
  userId: Schema.optionalKey(UserIdSchema),
  keyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  apiTokenId: Schema.optionalKey(Schema.String),
});

export const AuditEventSchema = Schema.Struct({
  id: RowIdHex,
  seq: Schema.optionalKey(PositiveInt),
  serverTs: Schema.Number,
  clientTs: Schema.optionalKey(Schema.Number),
  event: Schema.String,
  actor: AuditActorSchema,
  targetUserId: Schema.optionalKey(UserIdSchema),
  targetKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  environmentId: Schema.optionalKey(Schema.String),
  variableId: Schema.optionalKey(Schema.String),
  epoch: Schema.optionalKey(PositiveInt),
  version: Schema.optionalKey(PositiveInt),
  chainSeq: Schema.optionalKey(PositiveInt),
  orgId: Schema.optionalKey(OrgIdSchema),
  projectId: Schema.optionalKey(Schema.String),
  payload: Schema.optionalKey(Schema.JsonObject),
});

export const AuditEventsPageSchema = Schema.Struct({
  events: Schema.Array(AuditEventSchema),
});

export const AuditHeadSchema = Schema.Struct({
  auditHeadHashHex: Schema.String.check(
    Schema.isPattern(/^(?:[0-9a-f]{64})?$/, {
      description: "empty string or 64 lowercase hex digits",
    }),
  ),
});

const PageLimitFromString = Schema.NumberFromString.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_AUDIT_EVENTS_PAGE_LIMIT),
);

const EventNameFilter = Schema.String.check(Schema.isMaxLength(64));
const UserIdFilter = UserIdSchema.check(Schema.isMaxLength(1024));
const IdFilter = Schema.String.check(Schema.isMaxLength(64));

const pageQuery = {
  before: Schema.optionalKey(RowIdHex),
  limit: Schema.optionalKey(PageLimitFromString),
};

export const auditGroup = HttpApiGroup.make("audit")
  .add(
    HttpApiEndpoint.get("events", "/projects/:projectId/audit/events", {
      params: { projectId: ProjectIdSchema },
      query: {
        ...pageQuery,
        event: Schema.optionalKey(EventNameFilter),
        eventPrefix: Schema.optionalKey(EventNameFilter),
        chainSeqPresent: Schema.optionalKey(Schema.Literal("true")),
        actorUserId: Schema.optionalKey(UserIdFilter),
        targetUserId: Schema.optionalKey(UserIdFilter),
        variableId: Schema.optionalKey(IdFilter),
        environmentId: Schema.optionalKey(IdFilter),
      },
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("invites", "/projects/:projectId/audit/invites", {
      params: { projectId: ProjectIdSchema },
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("self", "/auth/audit/events", {
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("auditHead", "/projects/:projectId/audit-head", {
      params: { projectId: ProjectIdSchema },
      success: AuditHeadSchema,
      error: [ProjectNotFoundError, ForbiddenError, AuditHeadNotReadyError, DataLimitExceededError],
    }).middleware(AuthMiddleware),
  );
