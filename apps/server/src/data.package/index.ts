// The public surface of data.package (the ImportLint boundary).
//
// Only the data plane's shared vocabulary is re-exported from here: the
// RPC-boundary types (data-plane.ts), the authorization guards, the
// rejection vocabulary, the audit events, the storage service, the
// statement / manifest / value verifiers, and the HTTP adapters. The
// store's query modules (data-store-*.ts) and row types never leave the
// boundary.

export { dataEvent, dekRecipientTarget } from "./data-events.ts";
export {
  currentEpochOf,
  deviceOf,
  ensureDevicePermission,
  type InitializedChain,
  loadInitializedChain,
  type MemberWithDevice,
  requireEnvironmentAccess,
  requireMemberState,
  requireRole,
  requireRoleInScope,
  roleAtLeast,
  withSigningDevice,
} from "./data-guards.ts";
export {
  callProjectData,
  checkAadCoordinates,
  checkManifestCoordinates,
  checkStatementCoordinates,
  checkValueSize,
  dataRejectionError,
  noContent,
  requireProjectChainAdmin,
  toManifestInput,
  toMetaStatementInput,
  toValueInput,
  toWireValue,
  toWireVariable,
  unwrapDataOutcome,
} from "./data-http.ts";
export {
  type DataActor,
  type DekRecipientClass,
  type DekRecipientPosition,
  type DekWrapInput,
  type DekWrapRefInput,
  type EnvironmentListValue,
  type EnvironmentMetadataPullValue,
  type EnvironmentPullValue,
  type EnvironmentSummaryValue,
  type EnvManifestInput,
  type MetaStatementInput,
  type MetaStatementStatusInput,
  optionalCheckpointSnapshot,
  projectIdOf,
  type PulledVariableValue,
  type RecipientDekValue,
  type SchemaPolicy,
  type ValueInput,
  type VariableVersionValue,
  type WireMetaStatement,
  type WireSuite,
} from "./data-plane.ts";
export {
  type AttestationRejectReason,
  type DataOutcome,
  DataRejectedError,
  type DataRejection,
  type MirrorSyncRejectReason,
  rejectData,
  type RotationProposalRejectReason,
} from "./data-rejection.ts";
export {
  type CheckpointValueEntryRow,
  DataStore,
  dataStoreLayer,
  type DataStoreShape,
  type DataWriteOps,
  type StaleWrapRef,
  type StoredHeadAttestation,
  type StoredProposal,
  type StoredProposalVariable,
  type StoredVersionMeta,
  type VariableRow,
} from "./data-store.ts";
export {
  acceptEnvManifest,
  acceptEnvManifestForCreation,
  acceptManifestForMetaOp,
  manifestDigestEntries,
  storedEnvMeta,
} from "./verify-manifest.ts";
export {
  acceptMetaStatement,
  ensureDescriptionPolicy,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
  ensureSupportedLayout,
  type MetaOperation,
  statementLayoutVersion,
} from "./verify-meta.ts";
export { ensureValueCas, ensureValueSignature } from "./verify-value.ts";
