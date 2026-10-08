// Typed errors of the data-plane API (AUTH_SPEC §12).
//
// As with the chain API, errors carry only identifiers and counters (no
// plaintext values or key material). EnvironmentNotFound /
// VariableNotFound are returned only to chain-derived members (the
// project's own existence concealment §11-2 takes precedence — §12-3).

import { Schema } from "effect";
import { EnvironmentIdSchema, VariableIdSchema } from "@maruhi/core";

/** 404: no active environment under this id (returned to chain members only). */
export class EnvironmentNotFoundError extends Schema.TaggedError<EnvironmentNotFoundError>()(
  "EnvironmentNotFound",
  { environmentId: EnvironmentIdSchema },
  { httpApiStatus: 404 },
) {}

/** 404: no active variable under this id (returned to chain members only). */
export class VariableNotFoundError extends Schema.TaggedError<VariableNotFoundError>()(
  "VariableNotFound",
  { variableId: VariableIdSchema },
  { httpApiStatus: 404 },
) {}

/**
 * Reason codes for a 409 on variable creation or rename (AUTH_SPEC §12-1):
 * `exists` = the id is in use, `retired` = the id was used before (tombstone)
 * and may not be reused, `duplicate-name` = the display name is taken within
 * the uniqueness scope.
 */
export const ResourceConflictReasonSchema = Schema.Literals([
  "exists",
  "retired",
  "duplicate-name",
]);

/**
 * Reason codes for a 409 on environment creation or rename. Only the display
 * name remains a data-plane check: id uniqueness (`exists` / `retired`) was
 * absorbed into the chain consensus rule `duplicate-environment`
 * (ChainEntryInvalid — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4).
 */
export const EnvironmentConflictReasonSchema = Schema.Literals(["duplicate-name"]);

/** 409: the environment display name conflicts (AUTH_SPEC §12-1 / §12-4). */
export class EnvironmentConflictError extends Schema.TaggedError<EnvironmentConflictError>()(
  "EnvironmentConflict",
  { environmentId: EnvironmentIdSchema, reason: EnvironmentConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/** 409: the variable id or display name conflicts (AUTH_SPEC §12-1 / §12-5). */
export class VariableConflictError extends Schema.TaggedError<VariableConflictError>()(
  "VariableConflict",
  { variableId: VariableIdSchema, reason: ResourceConflictReasonSchema },
  { httpApiStatus: 409 },
) {}

/**
 * 409: push CAS failure (AUTH_SPEC §12-5) — the declared AAD version is not
 * `currentVersion + 1`. The client re-encrypts under the next version and
 * retries (the version is part of the AAD, so the server cannot renumber).
 */
export class VersionConflictError extends Schema.TaggedError<VersionConflictError>()(
  "VersionConflict",
  { currentVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 409: the declared AAD epoch is not the current chain epoch (AUTH_SPEC
 * §12-5). After a rotation the client fetches the new DEK, re-encrypts and
 * retries under `currentEpoch`.
 */
export class EpochConflictError extends Schema.TaggedError<EpochConflictError>()(
  "EpochConflict",
  { currentEpoch: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: a declared AAD component does not match the storage coordinates named
 * by the request (AUTH_SPEC §12-2). `field` names the mismatching component.
 */
export class PayloadMismatchError extends Schema.TaggedError<PayloadMismatchError>()(
  "PayloadMismatch",
  { field: Schema.String },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on a value push / create (AUTH_SPEC §12-5 =
 * the server-side verification of CRYPTO_SPEC §4.1 / §6.4):
 *
 * - `signature-invalid` — Ed25519 verification failed on a valid-format
 *   signature
 * - `chain-head-unknown` — the signature is valid but the declared seq
 *   does not exist on the server's own chain, or does not match the
 *   stored hash at that seq
 * - `chain-head-state-mismatch` — the head is known but the key / role /
 *   environment / epoch at that head does not match, or prev does not
 *   match the stored predecessor
 *
 * Check order: broken signature → unknown head → state mismatch. Only
 * the spec's three reasons — a fourth would be a wire change.
 */
export const ValueSignatureRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
]);

/**
 * 422: the value write signature (CRYPTO_SPEC §4.1) was rejected. Carries a
 * reason code only — never signature bytes, hashes or ciphertext fragments.
 */
export class ValueSignatureRejectedError extends Schema.TaggedError<ValueSignatureRejectedError>()(
  "ValueSignatureRejected",
  { reason: ValueSignatureRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on a metadata statement (CRYPTO_SPEC §4.2 /
 * AUTH_SPEC §12-5): the three value-signature reasons (session-12 §6-7 —
 * shared vocabulary; state-mismatch covers membership and key binding
 * at the head, role, the shape of prev / mismatch with the stored
 * predecessor, a re-statement after deletion, and the active →
 * declared transition) plus two layout reasons the spec names
 * explicitly:
 *
 * - `layout-regression` — a v1 successor to a variable whose preceding
 *   statement is v3 (layout monotonicity — CRYPTO_SPEC §4.2; blocks a
 *   silent loss of the schema fields via rename and bypassing
 *   schema-locked)
 * - `unsupported-layout` — the declared layoutVersion is outside this
 *   server's supported range ({1, 3} — the retired layout 2 included).
 *   The normal case of "old server × new client"; not collapsed into
 *   invalid signature
 *   (a failure indistinguishable from tampering) (ruling CR — the
 *   honest failure mode of "server update required")
 */
export const MetaStatementRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
  "layout-regression",
  "unsupported-layout",
]);

/**
 * 422: a metadata statement (CRYPTO_SPEC §4.2) was rejected. Carries a
 * reason code only — never signature bytes or hashes.
 */
export class MetaStatementRejectedError extends Schema.TaggedError<MetaStatementRejectedError>()(
  "MetaStatementRejected",
  { reason: MetaStatementRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 from the project schema policy (AUTH_SPEC §12-11 /
 * §12-5):
 *
 * - `schema-required` — in a locked project, a variable creation
 *   (metaVersion 1) does not satisfy layoutVersion 3 and non-empty
 *   varType (a one-time check at creation — a later schema reissuance
 *   can still downgrade)
 */
export const SchemaPolicyRejectReasonSchema = Schema.Literals(["schema-required"]);

/** 422: the request violates the project's schema policy (AUTH_SPEC §12-11). */
export class SchemaPolicyRejectedError extends Schema.TaggedError<SchemaPolicyRejectedError>()(
  "SchemaPolicyRejected",
  { reason: SchemaPolicyRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 422: a plain value push targeted a declared variable (AUTH_SPEC §12-5).
 * The first value of a declared variable must arrive through the activation
 * composite (value version 1 + status-active statement + manifest).
 */
export class ActivationRequiredError extends Schema.TaggedError<ActivationRequiredError>()(
  "ActivationRequired",
  { variableId: VariableIdSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on the schema `description` field (AUTH_SPEC §12-8):
 * `too-long` = over 1024 code points; `control-characters` = control
 * characters (including newlines — pinned to a single line so ANSI
 * escapes and newline spoofing are rejected at acceptance). NFC
 * normalization is not required (it is not an identifier and is not
 * used for comparison — a deliberate difference from name).
 */
export const SchemaDescriptionRejectReasonSchema = Schema.Literals([
  "too-long",
  "control-characters",
]);

/** 422: the schema description violates the §12-8 acceptance policy. */
export class SchemaDescriptionRejectedError extends Schema.TaggedError<SchemaDescriptionRejectedError>()(
  "SchemaDescriptionRejected",
  { reason: SchemaDescriptionRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on an environment manifest (AUTH_SPEC §12-5 =
 * CRYPTO_SPEC §4.3): shares the existing three vocabularies (signature
 * and head family) and adds manifest-specific reasons —
 *
 * - `manifest-digest-mismatch` — the declared values do not match the
 *   variablesDigestHex / envMetaVersion / envMetaSigHashHex the server
 *   recomputed from the post-acceptance meta state (all variable
 *   statements after applying the bundled statement + the environment
 *   meta statement) (§12-5 (7))
 * - `manifest-epoch-mismatch` — epoch consistency failed (§12-5 (4):
 *   the current epoch at the declared head — for the bundled portion
 *   of a rotate / create composite, the state after applying the
 *   bundled entry)
 * - `checkpoint-binding-mismatch` / `checkpoint-equivocation` /
 *   `checkpoint-regressed` — checkpoint binding (CRYPTO_SPEC §4.3 (2):
 *   must exactly match the (environment_id, manifest_version) tuple on
 *   the verified chain / coexisting differing tuples at the same
 *   coordinates = evidence of equivocation / failure of non-regression
 *   against the latest checkpoint baseline [§6.3 consistency rule 1])
 */
export const ManifestRejectReasonSchema = Schema.Literals([
  "signature-invalid",
  "chain-head-unknown",
  "chain-head-state-mismatch",
  "manifest-digest-mismatch",
  "manifest-epoch-mismatch",
  "checkpoint-binding-mismatch",
  "checkpoint-equivocation",
  "checkpoint-regressed",
]);

/**
 * 422: the environment manifest (CRYPTO_SPEC §4.3) was rejected. Carries a
 * reason code only — never signature bytes, hashes or digests.
 */
export class ManifestRejectedError extends Schema.TaggedError<ManifestRejectedError>()(
  "ManifestRejected",
  { reason: ManifestRejectReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * Reason codes for a 422 on a `checkpoint` entry's acceptance-time state
 * matching (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2; shared by both paths —
 * the boundary-bundled case [§12-4 — the matching baseline is the
 * composite's post-application stored state] and the standalone case
 * [generic chain append — acceptance time = the pre-application stored
 * state]):
 *
 * - `manifest-mismatch` — the tuple's (manifest_version,
 *   manifest_sig_hash) does not match the environment's **latest**
 *   manifest at acceptance time (covers both a stale issuer view and
 *   notarizing a nonexistent earlier manifest_version — a malicious
 *   member jamming checkpoint-regressed)
 * - `values-digest-mismatch` — the tuple's values_digest does not match
 *   a recomputation from the acceptance-time stored state (the latest
 *   version of every active variable and its value_signed_bytes hash).
 *   Can legitimately happen when a concurrent push lands after the
 *   declared head was fixed — the client re-pulls and retries with a
 *   bound (§12-4 / §16-2)
 * - `audit-head-unknown` — a non-empty audit_head_hash does not exist
 *   in the stored cumulative hash sequence (AUDIT_SPEC §5.1) (refusing
 *   a forged notarization)
 * - `audit-head-stale` — the occurrence position precedes the mirror
 *   row (chain.checkpointed) of the immediately previous checkpoint
 *   (whether or not it notarized) (the CRYPTO_SPEC §6.4 position floor;
 *   not applied on the first checkpoint where no previous exists.
 *   Refuses an issuance that did not re-obtain the attestation after a
 *   CAS conflict — the client refetches the attestation too and
 *   retries)
 *
 * A tuple for a deleted environment is not a mismatch: since environment
 * deletion moved onto the chain it fails chain verification itself
 * (ChainEntryInvalid `environment-deleted` — CRYPTO_SPEC §6.2, 2026-10-07)
 */
export const CheckpointMismatchReasonSchema = Schema.Literals([
  "manifest-mismatch",
  "values-digest-mismatch",
  "audit-head-unknown",
  "audit-head-stale",
]);

/**
 * 422: a `checkpoint` entry's attested content does not match the
 * acceptance-time stored state (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2).
 */
export class CheckpointStateMismatchError extends Schema.TaggedError<CheckpointStateMismatchError>()(
  "CheckpointStateMismatch",
  { reason: CheckpointMismatchReasonSchema },
  { httpApiStatus: 422 },
) {}

/**
 * 503: the audit-head derived column (AUDIT_SPEC §5.1 lazy
 * materialization) has not reached MAX(seq) within this call's bounded
 * extension budget (AUTH_SPEC §16-2). Retryable: expansion progress is
 * already stored server-side, and every retry makes progress. Shared by
 * every path that reads the audit head (GET /audit-head, standalone
 * checkpoint acceptance, non-empty notarization in a boundary
 * composite). **The body is empty**: carrying a remaining row count or
 * progress would disclose ordinal information about the audit row
 * count (AUDIT_SPEC §7 non-leakage of counts).
 */
export class AuditHeadNotReadyError extends Schema.TaggedError<AuditHeadNotReadyError>()(
  "AuditHeadNotReady",
  {},
  { httpApiStatus: 503 },
) {}

/**
 * 409: manifestVersion CAS failure (AUTH_SPEC §12-5 (6)) — the manifest's
 * declared manifestVersion is not `currentManifestVersion + 1`. Carries
 * the latest manifestVersion **number only** (the discipline of not
 * carrying the winner's hash is the same as the metaVersion CAS —
 * §12-5). A retry re-signs **both** the statement and the manifest.
 */
export class ManifestVersionConflictError extends Schema.TaggedError<ManifestVersionConflictError>()(
  "ManifestVersionConflict",
  { currentManifestVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 409: metaVersion CAS failure (AUTH_SPEC §12-5) — the statement's declared
 * metaVersion is not `currentMetaVersion + 1`. Carries the latest
 * metaVersion **number only** (never the winner's signed-bytes hash —
 * the client refetches and verifies the winner and computes prev
 * itself; the §12-5 409 discipline).
 */
export class MetaVersionConflictError extends Schema.TaggedError<MetaVersionConflictError>()(
  "MetaVersionConflict",
  { currentMetaVersion: Schema.Number },
  { httpApiStatus: 409 },
) {}

/**
 * 422: the statement's display name is not in NFC normal form (AUTH_SPEC
 * §12-1). Normalization is the signing client's responsibility — the
 * server only checks and never normalizes (compatibility with
 * byte-exact signatures — CRYPTO_SPEC §4.2).
 */
export class NameNotNfcError extends Schema.TaggedError<NameNotNfcError>()(
  "NameNotNfc",
  {},
  { httpApiStatus: 422 },
) {}

/** 413: the value ciphertext exceeds the §12-8 acceptance policy (64 KiB). */
export class ValueTooLargeError extends Schema.TaggedError<ValueTooLargeError>()(
  "ValueTooLarge",
  { limitBytes: Schema.Number },
  { httpApiStatus: 413 },
) {}

/** Resources bounded by the §12-8 count / cumulative-size acceptance policy. */
export const DataLimitResourceSchema = Schema.Literals([
  "environments",
  "environment-rows",
  "variables",
  "variable-rows",
  "versions",
  // metaVersion rows / variable (environment). Applies the same value
  // (1,000) as §12-8's "versions / variable" to rename / delete
  // statement rows too (blocks DO-storage bloat from unlimited rename
  // spam)
  "meta-versions",
  "project-ciphertext-bytes",
  "dek-wraps-per-request",
  "dek-wrap-rows",
  // Enumeration cap for dismissal targets (the AUDIT_SPEC §7 dismiss operation)
  "rotation-dismissals-per-request",
  // DO total-storage guard (§12-8): when the project DO's measured
  // SQLite size (databaseSize) reaches the refusal threshold (drafted
  // 9 GB), content-growing surfaces (value push, variable / environment
  // creation, rename, DEK registration, add_member / grant_server) are
  // refused. limit = the refusal threshold in bytes. Reads, deletions,
  // revocations, and rotations keep being accepted under refusal (the
  // same section's explicit enumeration)
  "project-storage-bytes",
]);

/**
 * 422: accepting the request would exceed a §12-8 count / size limit.
 *
 * `project-storage-bytes` (the DO storage guard) is the one resource whose
 * `limit` is a threshold on **measured** storage rather than on a count the
 * request adds to: freeing space (deleting environments / variables / wraps —
 * all still accepted) is the way back under it.
 */
export class DataLimitExceededError extends Schema.TaggedError<DataLimitExceededError>()(
  "DataLimitExceeded",
  { resource: DataLimitResourceSchema, limit: Schema.Number },
  { httpApiStatus: 422 },
) {}
