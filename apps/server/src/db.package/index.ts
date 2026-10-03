// The public surface of db.package (the ImportLint boundary).
//
// Only the repository services' Context tags, the shape types consumers
// need, and the construction functions are re-exported from here.
// Drizzle table definitions (schema.ts) and query types never leave the
// boundary (ADR-0006).

export {
  D1AuditRepo,
  type D1StoredAuditEventRow,
  INVITE_AUDIT_EVENTS,
  LOGIN_FAILED_WINDOW_LIMIT,
  LOGIN_FAILED_WINDOW_MS,
} from "./audit.ts";
export { type DeviceAddRequestRecord, type DeviceRecord, DeviceRepo } from "./devices.ts";
export {
  classifyImportedProject,
  type ImportClassification,
  type ImportedIdentity,
  type ImportProvisionResult,
  provisionImportedProject,
} from "./import.ts";
export {
  APPROVAL_LIMIT,
  HANDOFF_REQUEST_LIMIT,
  KEY_BLOB_FETCH_LIMIT,
  KeyWrapRepo,
  type KeyWrapRepoShape,
} from "./key-wraps.ts";
export {
  type OpsBackupAttempt,
  type OpsCounterMetric,
  OpsRepo,
  type OpsRepoShape,
  opsWindowStart,
} from "./ops.ts";
export {
  CliFlowRepo,
  type DbServices,
  FlowSigningKeyRepo,
  IdentityRepo,
  INVITE_ISSUE_WINDOW_LIMIT,
  INVITE_TTL_MS,
  InviteRepo,
  isUniqueConflict,
  makeDbServices,
  MAX_CONCURRENT_CLI_FLOWS,
  MAX_PENDING_INVITES_PER_PROJECT,
  OrgRepo,
  ProjectRepo,
  RECOVERY_FETCH_LIMIT,
  RecoveryRepo,
  SessionRepo,
  type SessionRepoShape,
  TokenRepo,
  type TokenRepoShape,
} from "./repos.ts";
