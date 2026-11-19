// The types crossing the data plane's RPC boundary (AUTH_SPEC §12): the
// inputs the worker hands the project DO and the values it returns (only
// plain objects safe for structured clone), and projectIdOf, which mints
// the project id from the stored chain's genesis hash (CRYPTO_SPEC §6.4).
// The rejection vocabulary is data-rejection.ts, the authorization guards
// data-guards.ts, and the audit events of a data operation data-events.ts.

import type {
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
} from "@maruhi/api-schema";
import type { AuditActor, EnvironmentId, ProjectId, UserId, VariableId } from "@maruhi/core";
import { decodeProjectId } from "@maruhi/core";
import type { KeyFingerprintHex } from "@maruhi/crypto";

/**
 * The genesis hash of the loaded chain IS the project id (§6.4): the
 * mint of a stored-chain derived coordinate. Shared by every program /
 * DO method that names the project.
 */
export function projectIdOf(chain: { readonly genesisHashHex: string }): ProjectId {
  return decodeProjectId(chain.genesisHashHex);
}

/**
 * The audit actor of a data operation (AUDIT_SPEC §2). The worker builds
 * it from the authenticated principal via auditActorOf (@maruhi/core —
 * the mapping's only implementation).
 * It carries no key FP — most data operations involve no signature. The
 * only exception that does is DEK wrap registration (CRYPTO_SPEC §5.1),
 * whose signer FP is taken not by the worker but by the DO from the
 * chain-derived member and recorded on the dek.registered event.
 */
export type DataActor = AuditActor;

/**
 * The suite identifier (CRYPTO_SPEC §2 design principle 4). Since the wire
 * pins it via the Schema Literal, the types at the RPC boundary and the
 * stored rows express it as this same literal (AUTH_SPEC §12-2).
 */
export type WireSuite = "maruhi/v1";

/**
 * The recipient class of a DEK wrap (AUTH_SPEC §12-6): member = a current
 * member on the chain; server = the server key of a valid grant_server.
 */
export type DekRecipientClass = "member" | "server";

/**
 * A wrap's recipient, typed by its class (the api-schema wire union): the
 * recipientUserId position holds a member's user id for class member, and
 * the server key FP for class server — the same substitution as the HPKE
 * info / §5.1 signed target (CRYPTO_SPEC §9). Narrowing on recipientClass
 * narrows the id's brand with it.
 */
export type DekRecipientPosition =
  | { readonly recipientClass: "member"; readonly recipientUserId: UserId }
  | { readonly recipientClass: "server"; readonly recipientUserId: KeyFingerprintHex };

/**
 * A DEK wrapped to one recipient (AUTH_SPEC §12-6; structurally identical
 * to the wire form). signatureHex is the registration signature
 * (CRYPTO_SPEC §5.1) — the signer matches the API calling principal
 * exactly (§12-6), so no signer ID rides the wire or the RPC boundary.
 */
export type DekWrapInput = DekRecipientPosition & {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
};

/**
 * A reference to a stored wrap (the deletion unit of the §12-6 repair
 * path). `recipientEncPubHex` is on the device axis (2026-09-19 DK —
 * slots are per device).
 */
export type DekWrapRefInput = DekRecipientPosition & {
  readonly epoch: number;
  readonly recipientEncPubHex: string;
};

/**
 * The fields every wire request statement carries past the coordinate check
 * (variable and environment, every lifecycle and layout): api-schema's
 * self-describing statement form without the coordinates (already matched
 * against the URL — checkStatementCoordinates) and the distribution-only
 * author fields. Every request statement form of api-schema is assignable to
 * it, and the statement types below derive from it, so the RPC-boundary
 * statement cannot drift from the wire contract. The one converter
 * (toMetaStatementInput) copies the stored-input fields by explicit name and
 * regroups the WireSchemaField set under `schema`, so the wire-declared
 * coordinates the runtime request still carries never reach the DO (§12-5).
 */
export type WireMetaStatement = Omit<
  DistributedVariableMetaStatement,
  "environmentId" | "variableId" | "authorUserId" | "authorKeyFingerprintHex"
>;

/**
 * A statement's lifecycle state (CRYPTO_SPEC §4.2). declared is limited
 * to variables on layout v3 (environment meta and the v1 layout stay
 * two-valued — the wire Schema enforces it, and the DO side accepts all
 * three values as the storage / verification type).
 */
export type MetaStatementStatusInput = WireMetaStatement["status"];

/** The closed set of varType (CRYPTO_SPEC §4.2 — `""` = unspecified). */
export type MetaVarTypeInput = Exclude<WireMetaStatement["varType"], undefined>;

/**
 * The layout-v3 schema fields (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2), nested
 * out of the flat wire form. varType / required / description are a set
 * (present together on v3); required rides as the wire's boolean (the mapping
 * onto the signed "true" / "false" strings happens in the one place that
 * verifies — verify-meta.ts). maxAgeDays (PF6 R9 expiring values) stays
 * optional only as the wire arrives: a v3 statement without it is refused by
 * verify-meta.ts as 422 payload-mismatch, and every stored row carries it.
 */
export type MetaVariableSchemaInput = Required<
  Pick<WireMetaStatement, "varType" | "required" | "description">
> &
  Pick<WireMetaStatement, "maxAgeDays">;

/** The flat wire fields that the stored input regroups under `schema`. */
export type WireSchemaField = keyof MetaVariableSchemaInput;

/**
 * The stored input of a metadata statement (CRYPTO_SPEC §4.2 / AUTH_SPEC
 * §12-5): the wire statement with the layout-v3 schema fields nested under
 * `schema` (always present when layoutVersion is explicit — the wire
 * shape). The coordinates (environment / variable) have already been
 * checked by the worker for a match against the URL and the statement's
 * declared values; the DO reconstructs the signed target from the
 * storage coordinates (§12-5 — it is never assembled from the wire's
 * declared values). Since author = the calling principal is the
 * contract, no author ID / FP is carried here (the DO takes it from the
 * chain-derived member at acceptance time).
 *
 * Fields (inherited from the wire statement):
 * - prevMetaSigHashHex: SHA-256 of the previous statement's signed_bytes
 *   (empty string for metaVersion 1).
 * - layoutVersion: the wire's layoutVersion (§12-2 — omitted = 1; the wire
 *   Schema only admits an explicit value of 2 or above). A layout outside
 *   the supported range ({1, 3} — the retired 2 included) is refused by the
 *   acceptance check ahead of signature verification with a 422
 *   `unsupported-layout` (ruling CR).
 * - chainHeadHashHex / chainHeadSeq: the chain head the author last verified
 *   at signing time (the §4.2 authorization-time binding).
 * - signatureHex: the statement signature (Ed25519 — CRYPTO_SPEC §4.2).
 */
export type MetaStatementInput = Omit<WireMetaStatement, WireSchemaField> & {
  readonly schema?: MetaVariableSchemaInput;
};

/**
 * The distributed environment metadata statement (an environment statement
 * is always active — deletion is the chain op delete_environment, §4.2 /
 * §6.2). Derived from api-schema's DistributedEnvironmentMetaStatement, with
 * authorKeyFingerprintHex re-typed to crypto's branded KeyFingerprintHex: the
 * wire carries a plain lowercase-hex string, the server value carries the
 * chain-derived fingerprint (the user_id + key FP at acceptance time are
 * returned as-is — verifiability of a past statement by a since-deleted
 * author, §12-2). name / chainHead* / signatureHex / prevMetaSigHashHex
 * follow the wire definitions (name NFC-checked by the server, the signature
 * block Ed25519 — §4.2).
 */
export type DistributedMetaStatementValue = Omit<
  DistributedEnvironmentMetaStatement,
  "authorKeyFingerprintHex"
> & {
  readonly authorKeyFingerprintHex: KeyFingerprintHex;
};

/**
 * The distributed form of a variable statement (with variableId and the
 * three-valued status). The layout-v3 carried fields exist as a complete set
 * only on v3 stored rows (no new field is added to a v1 distribution —
 * §12-2). Derived from api-schema's DistributedVariableMetaStatement with the
 * same author-fingerprint re-typing as DistributedMetaStatementValue.
 */
export type DistributedVariableMetaStatementValue = Omit<
  DistributedVariableMetaStatement,
  "authorKeyFingerprintHex"
> & {
  readonly authorKeyFingerprintHex: KeyFingerprintHex;
};

/**
 * The stored input of an environment manifest (CRYPTO_SPEC §4.3 /
 * AUTH_SPEC §12-5). The coordinate (environment) has already been
 * checked by the worker for a match against the URL; the DO reconstructs
 * the signed target from the storage coordinate (§12-5 — it is never
 * assembled from the wire's declared values). Since issuer = the calling
 * principal is the contract, no issuer ID / FP is carried here (the DO
 * takes it from the chain-derived member at acceptance time).
 */
export interface EnvManifestInput {
  readonly suite: WireSuite;
  /** The current epoch at issuance time (at the declared head) — §4.3's freshness anchor. */
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly variablesDigestHex: string;
  readonly envMetaVersion: number;
  readonly envMetaSigHashHex: string;
  /** SHA-256 of the previous manifest's signed_bytes (empty string for manifestVersion 1). */
  readonly prevManifestSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** The manifest signature (Ed25519 — CRYPTO_SPEC §4.3). */
  readonly signatureHex: string;
}

/**
 * The distributed environment manifest (structurally identical to
 * DistributedEnvironmentManifest). Returns the stored signature block and
 * the issuer (the user_id + chain-derived key FP at acceptance time)
 * as-is (verifiability of a past manifest by a since-deleted issuer —
 * §12-2).
 */
export interface DistributedEnvManifestValue extends EnvManifestInput {
  readonly environmentId: EnvironmentId;
  readonly issuerUserId: UserId;
  readonly issuerKeyFingerprintHex: KeyFingerprintHex;
}

/**
 * The stored input of a variable value. Of the AAD components, the
 * coordinates (project / environment / variable) have already been
 * checked by the worker for a match against the URL (§12-2). The DO
 * verifies the state-dependent epoch / version and the value signature
 * (§12-5 = CRYPTO_SPEC §4.1 / §6.4).
 * Since writer = the calling principal is the contract, no writer ID / FP
 * is carried here (the DO takes it from the chain-derived member at
 * acceptance time).
 */
export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** SHA-256 of the previous version's value_signed_bytes (empty string for version 1). */
  readonly prevValueSigHashHex: string;
  /** The chain head the writer last verified at signing time (the §4.1 authorization-time binding). */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** The value's write signature (Ed25519 — CRYPTO_SPEC §4.1). */
  readonly signatureHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  /** The latest environment meta statement (always active — a deleted environment is not listed; its deletion is a chain entry). */
  readonly statement: DistributedMetaStatementValue;
}

export interface VariableVersionValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly epoch: number;
}

/**
 * One variable of a bulk pull (§12-7). Distributes the stored signature
 * block and the writer (the user_id + chain-derived key FP at acceptance
 * time) — not re-derived from the current member set (so that a past
 * value by a since-deleted writer is still verifiable under the keys of
 * that time in the chain history). The server-recomputed signed_bytes
 * hash is not distributed (a verifier recomputes it themselves).
 */
export interface PulledVariableValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly writerUserId: UserId;
  readonly writerKeyFingerprintHex: KeyFingerprintHex;
}

/**
 * The distributed wrap (structurally identical to RecipientDek). Carries
 * the signature and the signer information (the user_id + key FP of the
 * chain-derived member at registration acceptance) to enable the
 * client's verification at distribution time (CRYPTO_SPEC §5.1).
 */
export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  /**
   * The recipient's device key (the enc public key — the device axis of
   * AUTH_SPEC §12-6; 2026-09-19 DK). Since wraps to multiple devices of
   * the same person appear side by side in one response, the recipient
   * opens only the row of its own device key (an open failure is not
   * mistaken for a poisoned wrap).
   */
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: UserId;
  readonly signerKeyFingerprintHex: KeyFingerprintHex;
}

/** One entry of the checkpoint-time value snapshot (the distributed form — §12-7). */
export interface CheckpointSnapshotEntryValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly valueSigHashHex: string;
}

/**
 * The distributed checkpoint-time value snapshot (structurally identical
 * to api-schema's CheckpointValueSnapshot — §12-7 / §14-2).
 * The supply is the very rows atomically stored at checkpoint acceptance
 * (§16-2 — never reconstructed). chainSeq / entryHashHex are the
 * position of the stored corresponding checkpoint (on the client side an
 * advisory locator — the verification basis is chain-derived).
 */
export interface CheckpointSnapshotValue {
  readonly chainSeq: number;
  readonly entryHashHex: string;
  readonly values: readonly CheckpointSnapshotEntryValue[];
}

/**
 * The omittable verification-material field of a value-bearing response
 * (§12-7 / §14-2): bundled when a stored row exists for the latest
 * checkpoint covering this environment, otherwise the key itself is
 * absent (the optionalKey wire shape — legitimately absent on an
 * environment without a baseline). Shared by the response assembly of
 * pull and lease (the branch is not duplicated in each program). The
 * manifest is not omittable — a created environment always has one
 * (§12-4; required on the wire since 0.28-draft).
 */
export function optionalCheckpointSnapshot(checkpointSnapshot: CheckpointSnapshotValue | null): {
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
} {
  return checkpointSnapshot === null ? {} : { checkpointSnapshot };
}

export interface EnvironmentPullValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  /** The environment's own latest meta statement (the bundled verification material of §12-7). */
  readonly statement: DistributedMetaStatementValue;
  /** The latest statement + latest version of each active variable. */
  readonly variables: readonly (PulledVariableValue & {
    readonly statement: DistributedVariableMetaStatementValue;
  })[];
  /** The deleted statements of deleted variables (kept being stored and distributed — §12-5). */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /**
   * The latest statements of declared variables (§12-7 — no value or
   * version exists. Input for the manifest digest recomputation).
   * Omitted for an environment with no declared variable (same shape as
   * the wire's optionalKey).
   */
  readonly declaredVariables?: readonly DistributedVariableMetaStatementValue[];
  readonly deks: readonly RecipientDekValue[];
  /** The schemaPolicy advisory bundle (§12-7 / §12-11 — always present). */
  readonly schemaPolicy: SchemaPolicy;
  /**
   * The latest environment manifest (§12-7). Required — a created
   * environment always has a stored row (environment creation bundles
   * manifest_version 1, and every meta operation / rotate re-issues
   * it), so a missing row is an invariant violation = defect, never an
   * omission (0.28-draft; on the client side absence = unconditional
   * rejection §6.3).
   */
  readonly manifest: DistributedEnvManifestValue;
  /**
   * The checkpoint-time value snapshot enumeration (§12-7).
   * Always bundled when a stored row exists for the latest checkpoint
   * that contains an entry of the environment (client rule 2 rejects
   * "basis present + enumeration absent" — CRYPTO_SPEC §6.3).
   * undefined only for an environment with no basis checkpoint.
   */
  readonly checkpointSnapshot?: CheckpointSnapshotValue;
}

/**
 * The metadata-only mode's response (§12-7): carries no values
 * (ciphertexts) and no DEKs. Only the §6.3 meta-verification material
 * (environment + latest statements of active variables + tombstones).
 * var.read is not recorded (AUDIT_SPEC §3.3).
 */
export interface EnvironmentMetadataPullValue {
  readonly environmentId: EnvironmentId;
  readonly currentEpoch: number;
  /** The environment's own latest meta statement. */
  readonly statement: DistributedMetaStatementValue;
  /**
   * The latest statements of every non-deleted variable (no values
   * attached). The statements of declared variables also appear here
   * (§12-7 — status carries the discrimination).
   */
  readonly variables: readonly DistributedVariableMetaStatementValue[];
  /** The deleted statements of deleted variables (§12-5). */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  /**
   * The latest environment manifest (meta verification completeness is
   * at the same level in this mode — §12-7). Required, same as the
   * with-values pull.
   */
  readonly manifest: DistributedEnvManifestValue;
  /** The schemaPolicy advisory bundle (§12-7 / §12-11 — always present). */
  readonly schemaPolicy: SchemaPolicy;
}

/** The RPC value of the environment list (§12-4 + the schemaPolicy advisory bundle — §12-7). */
export interface EnvironmentListValue {
  readonly environments: readonly EnvironmentSummaryValue[];
  readonly schemaPolicy: SchemaPolicy;
}

/**
 * A project's schema policy (AUTH_SPEC §12-11 — default enabled). The
 * acceptance decision reads the policy at acceptance time (inside the
 * project DO's serialization).
 */
export type SchemaPolicy = "enabled" | "locked";
