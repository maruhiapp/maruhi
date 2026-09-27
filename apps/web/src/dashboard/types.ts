// The wire types the dashboard consumes (ruling BR —
// docs/notes/session-43.md).
//
// Restricted to **type-only imports** from api-schema: the types stay
// bound to the single definition (the HttpApi Schema) while no
// Effect / Schema executable code enters the bundle (= the TCB)
// (verbatimModuleSyntax guarantees build-time erasure).
// Runtime Schema validation is intentionally skipped — every display
// is as reported by the server and the web implements no validation
// (ADR-0018 amendment 2, item 4). Defense against shape breakage is
// satisfied by optional access at the display layer.
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
/** The closed enumeration of 403 reasons (ruling CC — renaming a compared literal is caught by the type). */
export type ForbiddenReason = typeof ForbiddenReasonSchema.Type;

/** `{ events }` page shape shared by every audit read endpoint (AUDIT_SPEC §7). */
export type AuditEventsPage = typeof AuditEventsPageSchema.Type;

/** `{ environments }` shape of the environment listing (AUTH_SPEC §12-4). */
export type EnvironmentList = typeof EnvironmentListSchema.Type;

/** `{ flags }` shape of the rotation-flag view (AUDIT_SPEC §7). */
export type RotationFlagList = typeof RotationFlagListSchema.Type;

/** One invitation row of the S8 management listing (AUTH_SPEC §15-2). */
export type InvitationSummary = typeof InvitationSummarySchema.Type;

/** The closed enumeration of stored invite states (AUTH_SPEC §15-1 — used as the key for display colors). */
export type InviteStatus = typeof InviteStatusSchema.Type;

/** `{ invitations }` shape of the invite listing (AUTH_SPEC §15-2). */
export type InvitationList = typeof InvitationListSchema.Type;

/** One token row of the S9 self-inventory listing (AUTH_SPEC §6). */
export type TokenSummary = typeof TokenSummarySchema.Type;

/** `{ tokens }` shape of the token listing (AUTH_SPEC §6). */
export type TokenList = typeof TokenListSchema.Type;

/** One device-registry row of the S11 listing (AUTH_SPEC §13-11 — advisory, server-reported). */
export type DeviceSummary = typeof DeviceSummarySchema.Type;

/** `{ devices }` shape of the device registry listing (AUTH_SPEC §13-11). */
export type DeviceList = typeof DeviceListSchema.Type;
