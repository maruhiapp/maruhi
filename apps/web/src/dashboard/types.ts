import type {
  AuditEventSchema,
  AuditEventsPageSchema,
  ChainEntrySchema,
  ChainSnapshotSchema,
  DeviceListSchema,
  DeviceSummarySchema,
  EnvironmentListSchema,
  EnvironmentMetadataPullSchema,
  EnvironmentSummarySchema,
  ForbiddenReasonSchema,
  InvitationListSchema,
  InvitationSummarySchema,
  InviteStatusSchema,
  MeSchema,
  ProjectListSchema,
  RoleSchema,
  RotationFlagListSchema,
  RotationFlagSchema,
  TokenListSchema,
  TokenSummarySchema,
} from "@maruhi/api-schema";

export type Me = typeof MeSchema.Type;
export type ProjectList = typeof ProjectListSchema.Type;
export type ChainSnapshot = typeof ChainSnapshotSchema.Type;
export type ChainEntry = typeof ChainEntrySchema.Type;
export type ChainRole = typeof RoleSchema.Type;
export type EnvironmentSummary = typeof EnvironmentSummarySchema.Type;
export type EnvironmentMetadataPull = typeof EnvironmentMetadataPullSchema.Type;
export type AuditEvent = typeof AuditEventSchema.Type;
export type RotationFlag = typeof RotationFlagSchema.Type;
export type ForbiddenReason = typeof ForbiddenReasonSchema.Type;

export type AuditEventsPage = typeof AuditEventsPageSchema.Type;

export type EnvironmentList = typeof EnvironmentListSchema.Type;

export type RotationFlagList = typeof RotationFlagListSchema.Type;

export type InvitationSummary = typeof InvitationSummarySchema.Type;

export type InviteStatus = typeof InviteStatusSchema.Type;

export type InvitationList = typeof InvitationListSchema.Type;

export type TokenSummary = typeof TokenSummarySchema.Type;

export type TokenList = typeof TokenListSchema.Type;

export type DeviceSummary = typeof DeviceSummarySchema.Type;

export type DeviceList = typeof DeviceListSchema.Type;
