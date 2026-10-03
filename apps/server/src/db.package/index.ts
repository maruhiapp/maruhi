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
export { CliFlowRepo, MAX_CONCURRENT_CLI_FLOWS } from "./cli-flows.ts";
export { FlowSigningKeyRepo } from "./flow-signing-keys.ts";
export { IdentityRepo } from "./identities.ts";
export {
  INVITE_ISSUE_WINDOW_LIMIT,
  INVITE_TTL_MS,
  InviteRepo,
  MAX_PENDING_INVITES_PER_PROJECT,
} from "./invites.ts";
export { OrgRepo } from "./orgs.ts";
export { ProjectRepo } from "./projects.ts";
export { RECOVERY_FETCH_LIMIT, RecoveryRepo } from "./recovery.ts";
export { type DbServices, isUniqueConflict, makeDbServices } from "./repos.ts";
export { SessionRepo, type SessionRepoShape } from "./sessions.ts";
export { TokenRepo, type TokenRepoShape } from "./tokens.ts";
