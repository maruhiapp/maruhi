// Wire representation of the data plane (AUTH_SPEC §12-2 = the
// concretization of CRYPTO_SPEC §10).
//
// The API boundary invariant (CRYPTO_SPEC §10): variable values are
// represented only as EncryptedPayload. Do not put any type representing
// a plaintext value, DEK, or secret key in this file.
//
// The server cannot cryptographically verify AAD (E2EE). The Schema
// checks only the transport shape (hex format, fixed lengths); matching
// the declared AAD to the storage coordinates is the handler / DO
// acceptance check, and enforcing context binding is carried by
// decryption failure (pinned by the crypto test vectors).

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";

import {
  EncPubHex,
  hexString,
  HpkeEncHex,
  KeyFingerprintHex,
  ManifestSignatureHex,
  MetaSignatureHex,
  PositiveInt,
  Sha256Hex,
  ValueSignatureHex,
  WrapSignatureHex,
} from "./hex.ts";

/**
 * Suite identifier (CRYPTO_SPEC §2 design principle 4: every persistent
 * data structure has one). The v1 API pins it as a Literal (binding
 * suite and epoch = the shape of a v2 migration is deferred until the
 * v2 design — AUTH_SPEC §12-2).
 */
const SuiteSchema = Schema.Literal("maruhi/v1");

const NonceHex = hexString(12);
// Wrapped DEK = 32-byte DEK + 16-byte GCM tag (CRYPTO_SPEC §5)
const WrappedDekCiphertextHex = hexString(48);
// prev_value_sig_hash_hex: empty string at version 1, 64 hex chars
// afterwards (§4.1). The binding to version (1 ⇔ empty) is checked by
// the server / client signature verification (prev-shape-mismatch) as a
// state-independent verification rule — the Schema covers wire shape
// only
const PrevValueSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

// AES-256-GCM ct || tag: lowercase hex of 16+ bytes including the tag
// (even length)
const ValueCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,}$/, {
    description: "lowercase hex AES-GCM ciphertext (>= 16 bytes incl. tag)",
  }),
);

/**
 * Wire limit of the internal user_id: aligned to the chain consensus
 * rule's free-string limit (CRYPTO_SPEC §6.1's 1024 bytes). A narrower
 * limit could make a legitimate member on the chain unrepresentable.
 * The chain.ts side is deliberately unbounded (§6.1 — verifyChain
 * checks the limit).
 */
export const BoundedUserId = Schema.String.check(
  Schema.isMinLength(1),
  // The limit counts UTF-8 bytes (isMaxLength counts UTF-16 code units).
  Schema.makeFilter((s: string) =>
    new TextEncoder().encode(s).length <= 1024
      ? undefined
      : { path: [], issue: "at most 1024 UTF-8 bytes" },
  ),
);

/** Declared AAD components of a variable ciphertext (CRYPTO_SPEC §4). */
export const VariableAadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  epoch: PositiveInt,
  variableId: VariableIdSchema,
  version: PositiveInt,
});

/**
 * An encrypted variable value on the wire (AUTH_SPEC §12-2): the only shape a
 * secret value ever takes across the API boundary (CRYPTO_SPEC §10).
 *
 * A value (CRYPTO_SPEC §4.1 = implementation PR-2 of the session-12
 * spec) carries the writer's write-signature block: the prev chain
 * (prevValueSigHashHex), the chain-head binding at acceptance
 * (chainHeadHashHex + chainHeadSeq), and the Ed25519 signature
 * (signatureHex). For push / create the contract is writer = calling
 * principal (§12-5), so the writer's ID / FP / signed-bytes hash are
 * not on the wire.
 */
export const EncryptedPayloadSchema = Schema.Struct({
  suite: SuiteSchema,
  aad: VariableAadSchema,
  nonceHex: NonceHex,
  ciphertextHex: ValueCiphertextHex,
  prevValueSigHashHex: PrevValueSigHashHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ValueSignatureHex,
});

/** An encrypted variable value on the wire. */
export type EncryptedPayload = typeof EncryptedPayloadSchema.Type;

/**
 * A distributed (pulled) variable value (AUTH_SPEC §12-2 / §12-7): the stored
 * payload plus the verification material — the writer's user id and key
 * fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history (CRYPTO_SPEC §6.3); a writer removed since then
 * stays verifiable through the chain's key history. The server-computed
 * signed-bytes hash is NOT distributed — verifiers recompute it themselves.
 */
export const DistributedEncryptedPayloadSchema = Schema.Struct({
  ...EncryptedPayloadSchema.fields,
  writerUserId: BoundedUserId,
  writerKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed variable value with its writer identity. */
export type DistributedEncryptedPayload = typeof DistributedEncryptedPayloadSchema.Type;

/**
 * One row of a variable's version history (AUTH_SPEC §12-7 — 2026-09-27 VH,
 * docs/notes/vh-design.md ruling V3). **Metadata only and server-declared**:
 * no ciphertext travels, so the value signature cannot be verified from this
 * row and clients must not base a write on it (rollback verifies its target
 * through the value range instead).
 *
 * - `pushedAtMs`: the acceptance time of the push
 * - `sameValueAs`: the writer's lineage declaration (§12-5 — this version's
 *   plaintext equals that version's). `version − 1` = a re-encryption, older =
 *   a rollback. Absent = a fresh value
 * - `flagsIfCurrent`: the number of non-dismissed rotation-needed flags on the
 *   pair that are effective while this version's value is the live one
 *   (AUDIT_SPEC §4.1 procedure 5's lineage derivation — computed server-side
 *   because it compares audit seqs, which never go on the wire)
 */
export const VariableVersionHistoryEntrySchema = Schema.Struct({
  version: PositiveInt,
  epoch: PositiveInt,
  writerUserId: BoundedUserId,
  writerKeyFingerprintHex: KeyFingerprintHex,
  pushedAtMs: Schema.Number,
  sameValueAs: Schema.optionalKey(PositiveInt),
  flagsIfCurrent: Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(0)),
});

/** A version-history row (metadata only — server-declared). */
export type VariableVersionHistoryEntry = typeof VariableVersionHistoryEntrySchema.Type;

// ---------------------------------------------------------------------------
// Metadata statements (CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2).
// The author's Ed25519 signature binds the name ↔ ID correspondence and
// the authenticity of the active / deleted state. name is already
// NFC-normalized (§12-1 — the actor that normalizes is the client
// before signing; the server only checks, it does not normalize). The
// 256-character length cap is a §12-8 acceptance policy (unlike values
// there is no dedicated verification layer, so the Schema enforces it —
// the former ResourceNameSchema).
// ---------------------------------------------------------------------------

/** Whether it is in NFC is checked not by the Schema but by the server's 422 (NameNotNfc). */
const StatementNameSchema = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256));

const MetaStatementStatusSchema = Schema.Literals(["active", "deleted"]);
// Layout v2 of variable statements adds a third state, declared
// (CRYPTO_SPEC §4.2 — declared, value not yet set; environment meta and
// the v1 layout keep the traditional two values)
const VariableMetaStatementStatusSchema = Schema.Literals(["active", "deleted", "declared"]);
// metaVersion 1 is creation-only (status active, empty prev), so the
// rename / delete request forms are pinned to metaVersion >= 2 (the
// narrowed structs below)
const MetaVersionAtLeast2 = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(2));
const PrevMetaSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const varMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

const envMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

// The three lifecycle forms (creation = metaVersion 1, active, empty
// prev / rename = active / deletion = deleted). Pin the request's wire
// form per operation so "deleted at creation" or "active at deletion"
// is refused by the Schema (400), not by a server check
const creationLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
};
const renameLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
const deleteLifecycleFields = {
  status: Schema.Literal("deleted"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
// The distribution side carries every lifecycle (the self-describing
// form of a stored statement)
const anyLifecycleFields = {
  status: MetaStatementStatusSchema,
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
};

// ---------------------------------------------------------------------------
// Layout v2 of variable meta statements (CRYPTO_SPEC §4.2 / AUTH_SPEC
// §12-2). A v1 statement keeps the traditional field set (layoutVersion
// and all 4 schema fields absent — strict acceptance enforces this);
// v2 carries layoutVersion and the schema fields. Environment meta
// statements are out of scope (stay v1).
// ---------------------------------------------------------------------------

/**
 * The closed set of varType (CRYPTO_SPEC §4.2 — `""` = unspecified; no
 * validation DSL, enum, or default is introduced — ruling CT).
 * Closed-set membership is decided by Schema validation (400 — §12-5).
 */
export const MetaVarTypeSchema = Schema.Literals(["", "string", "number", "boolean", "url"]);

/**
 * The wire layoutVersion (AUTH_SPEC §12-2): **an integer with no pinned
 * upper bound**. v1 is expressed by the field being absent (omitted =
 * 1), so an explicit value is 2 or higher. Checking the supported range
 * (currently {1, 2}) is done not by the Schema but by the acceptance
 * check before signature verification; an excess surfaces as a typed
 * 422 "unsupported layout" (an honest failure mode that does not
 * conflate it with a Schema 400 = a failure indistinguishable from
 * tampering — CRYPTO_SPEC §4.2).
 */
const MetaLayoutVersionSchema = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(2),
);

/**
 * Layout v3's max age (CRYPTO_SPEC §4.2 — PF6 R9 "expiring values"): the
 * number of days after a value's push within which it should be replaced,
 * 1..3650, or null = no declaration. The wire carries the field **iff the
 * layout is 3** (present with null for "none"; absent on v2) — the
 * coupling is an acceptance check (422 payload-mismatch), not a Schema
 * 400, so the two layouts share one wire shape.
 */
export const MetaMaxAgeDaysSchema = Schema.NullOr(
  Schema.Number.check(
    Schema.isInt(),
    Schema.isGreaterThanOrEqualTo(1),
    Schema.isLessThanOrEqualTo(3650),
  ),
);

// The schema fields (all required in v2 — fail-closed so the omitted
// interpretation of required is not dispersed into client
// implementations; CRYPTO_SPEC §4.2). The description limit (1024 code
// points) and character class (reject control characters) are a §12-8
// acceptance check (422), not checked in the Schema (deliberately a
// different category from the display-name 400). maxAgeDays is layout
// v3's field (present iff layoutVersion is 3 — acceptance-checked)
const varMetaV2Fields = {
  layoutVersion: MetaLayoutVersionSchema,
  varType: MetaVarTypeSchema,
  required: Schema.Boolean,
  description: Schema.String,
  maxAgeDays: Schema.optionalKey(MetaMaxAgeDaysSchema),
};

/** The statement bundled with variable creation (metaVersion 1 — AUTH_SPEC §12-5). */
export const CreateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
});

/** Layout-v2 value-carrying creation statement (status active, with schema fields). */
export const CreateVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
  ...varMetaV2Fields,
});

/**
 * The statement of a declaration (declared creation — §12-5):
 * metaVersion 1 with no value. The sole exception to "a variable
 * without a value does not exist", and layout-v2 only (CRYPTO_SPEC
 * §4.2 — ruling CS). A creation's status is only active (value bundled)
 * or declared (no value) — creating a deleted one is structurally
 * refused by the wire form.
 */
export const DeclareVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literal("declared"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
  ...varMetaV2Fields,
});

/** The statement of a variable rename (metaVersion CAS — §12-5). */
export const RenameVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
});

/**
 * Layout-v2 rename / schema-reissuance statement (§12-5 — the
 * acceptance rule is identical to a rename). status keeps the current
 * state (a schema reissuance or rename stays active, or stays declared
 * — a state transition cannot happen in this form: if status does not
 * match the immediately preceding statement it is 422
 * payload-mismatch. declared → active goes only through the activation
 * composite; active → declared is forbidden — CRYPTO_SPEC §4.2).
 */
export const RenameVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literals(["active", "declared"]),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
  ...varMetaV2Fields,
});

/**
 * The statement of an activation (declared → active — §12-5): a
 * status-active, metaVersion + 1 v2 statement bundled into the
 * composite with the first value push.
 */
export const ActivateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
  ...varMetaV2Fields,
});

/** The statement of a variable deletion (status deleted; name is the immediately preceding active name — §4.2). */
export const DeleteVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
});

/**
 * Layout-v2 deletion statement (deleting a v2 variable is always v2 —
 * layout monotonicity). The schema fields and layout must keep the
 * immediately preceding statement's values unchanged (same convention
 * as name — a mismatch is 422 payload-mismatch; §12-5).
 */
export const DeleteVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
  ...varMetaV2Fields,
});

/** The statement bundled in an environment-creation composite request (§12-4). */
export const CreateEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...creationLifecycleFields,
});

/** The statement of an environment rename (§12-4 → the §12-5 meta rules). */
export const RenameEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...renameLifecycleFields,
});

/** The statement of an environment deletion (admin at declared-head time — §12-3). */
export const DeleteEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...deleteLifecycleFields,
});

/**
 * A distributed variable metadata statement (AUTH_SPEC §12-2 / §12-7): the
 * stored statement plus the verification material — the author's user id and
 * key fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history (CRYPTO_SPEC §6.3); an author removed since then
 * stays verifiable through the chain's key history. Name-returning responses
 * carry statements instead of bare name snapshots (§12-2) — clients must not
 * trust a name that did not pass statement verification.
 */
export const DistributedVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  // The variable-side distribution carries 3 states (declared is layout v2 only — CRYPTO_SPEC §4.2)
  status: VariableMetaStatementStatusSchema,
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
  // Layout-v2 carriage fields (§12-2): on a v1 statement's distribution
  // **all 4 fields are absent** (new fields are never added to a v1
  // distribution); on v2 all 4 fields are present. The server's stored
  // row (already accepted) guarantees the presence binding
  layoutVersion: Schema.optionalKey(MetaLayoutVersionSchema),
  varType: Schema.optionalKey(MetaVarTypeSchema),
  required: Schema.optionalKey(Schema.Boolean),
  description: Schema.optionalKey(Schema.String),
  // Layout v3 (PF6 R9): present (null = no declaration) iff layoutVersion is 3
  maxAgeDays: Schema.optionalKey(MetaMaxAgeDaysSchema),
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed variable metadata statement with its author identity. */
export type DistributedVariableMetaStatement = typeof DistributedVariableMetaStatementSchema.Type;

/** A distributed environment metadata statement (same shape, env kind). */
export const DistributedEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...anyLifecycleFields,
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed environment metadata statement with its author identity. */
export type DistributedEnvironmentMetaStatement =
  typeof DistributedEnvironmentMetaStatementSchema.Type;

// ---------------------------------------------------------------------------
// Environment manifest (CRYPTO_SPEC §4.3 / AUTH_SPEC §12-2).
// The actor of an operation that changes meta state signs the full
// picture of the environment's meta state (the digest of all variable
// statements — tombstones included — plus the environment meta
// statement) with the current epoch at issuance baked in. The meta
// layer's freshness anchor (the counterpart of the values' §4.1 epoch
// consistency).
// ---------------------------------------------------------------------------

const PrevManifestSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const manifestBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  /** Current epoch at issuance (at the declared head) — the meta layer's freshness anchor (§4.3). */
  epoch: PositiveInt,
  /** Canonical digest of all variable statements (tombstones included) (§4.3). */
  variablesDigestHex: Sha256Hex,
  envMetaVersion: PositiveInt,
  envMetaSigHashHex: Sha256Hex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ManifestSignatureHex,
};

/**
 * The manifest bundled in an environment-creation composite request
 * (§12-4): the wire form pins manifestVersion 1, empty variable set,
 * empty prev (the grounds that a manifest-uninitialized state cannot
 * structurally exist on a new environment — CRYPTO_SPEC §6.3).
 */
export const CreateEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: Schema.Literal(1),
  prevManifestSigHashHex: Schema.Literal(""),
});

/**
 * The manifest bundled into meta operations (variable create / rename /
 * delete, environment rename) and the rotate composite (the §12-5 (6)
 * manifestVersion CAS = declared == latest + 1). manifestVersion 1 is
 * also accepted: the first meta operation / rotate of an environment
 * created before manifests were introduced issues v1 from no stored
 * manifest (= latest 0) (the migration procedure — session-27 §14
 * PR-M1).
 */
export const EnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
});

/** An environment manifest (issuance form — the contract is issuer = calling principal §12-5 (1)). */
export type EnvironmentManifest = typeof EnvironmentManifestSchema.Type;

/**
 * A distributed environment manifest (AUTH_SPEC §12-2 / §12-7): the stored
 * latest manifest plus the verification material — the issuer's user id and
 * key fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history and the distributed statement set (CRYPTO_SPEC
 * §4.3 / §6.3 — digest recomputation and epoch consistency). **Absence =
 * unconditional refusal** (§6.3 — there is no warning-downgrade branch
 * for "uninitialized"). It is optional on the wire only during the
 * transitional state until environments created before manifests were
 * introduced finish migrating (the server bundles it whenever a stored
 * row exists).
 */
export const DistributedEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
  issuerUserId: BoundedUserId,
  issuerKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed environment manifest with its issuer identity. */
export type DistributedEnvironmentManifest = typeof DistributedEnvironmentManifestSchema.Type;

// ---------------------------------------------------------------------------
// Enumeration of the checkpoint-time value snapshots (AUTH_SPEC §12-7 /
// §14-2 — PR-M3). The enumeration the server atomically stored at
// checkpoint acceptance (§16-2) is bundled into value-bearing
// responses, as material for the client's checkpoint consistency and
// rule 2 (value non-regression — CRYPTO_SPEC §6.3). metadata-only pull
// is out of scope (it carries no values).
// ---------------------------------------------------------------------------

/**
 * One entry of the checkpoint-time value snapshot (AUTH_SPEC §12-7): one
 * active variable's latest version at checkpoint acceptance and the SHA-256
 * of that version's `value_signed_bytes` (CRYPTO_SPEC §4.1 / §6.2).
 */
export const CheckpointValueSnapshotEntrySchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: PositiveInt,
  valueSigHashHex: Sha256Hex,
});

/** One checkpoint-time snapshot entry (variable id / version / value-sig hash). */
export type CheckpointValueSnapshotEntry = typeof CheckpointValueSnapshotEntrySchema.Type;

/**
 * The checkpoint-time value snapshot bundled into value-bearing responses
 * (bulk pull §12-7 / lease §14-2): the enumeration the server stored at
 * checkpoint acceptance, plus the checkpoint's chain position. The position
 * is an **advisory locator only** (CRYPTO_SPEC §1 principle 6 — session-36 ruling S):
 * the verification baseline is always the client's own chain-derived latest
 * covering checkpoint (§6.3), and the locator merely routes the §6.3-2-style
 * two-way classification (declared seq beyond the verified head = possibly
 * stale view → one bounded re-sync on the pull path; at or below it = the
 * baseline is settled, any mismatch is hard evidence).
 */
export const CheckpointValueSnapshotSchema = Schema.Struct({
  /** Chain seq of the checkpoint entry the enumeration was stored for. */
  chainSeq: PositiveInt,
  /** Entry hash of that checkpoint entry (cross-checked against the chain). */
  entryHashHex: Sha256Hex,
  values: Schema.Array(CheckpointValueSnapshotEntrySchema),
});

/** The checkpoint-time value snapshot of one environment (§12-7 / §14-2). */
export type CheckpointValueSnapshot = typeof CheckpointValueSnapshotSchema.Type;

/**
 * The project's schema policy (AUTH_SPEC §12-11 — the enablement gate
 * and schema-locked; default disabled): disabled = refuse new
 * adoption of layout v2 / enabled = accept v2 (schema fields
 * optional) / locked = enabled + require layoutVersion 2 and non-empty
 * varType on variable creation. A write acceptance policy; not placed
 * on the chain (nor an input to verification rules — distribution is
 * advisory).
 */
export const SchemaPolicySchema = Schema.Literals(["disabled", "enabled", "locked"]);

/** The project's schema policy (AUTH_SPEC §12-11). */
export type SchemaPolicy = typeof SchemaPolicySchema.Type;

/**
 * Recipient class of a DEK wrap (AUTH_SPEC §12-6): member = a current
 * member on the chain (identified by user_id + enc public key), server
 * = the server key of a valid grant_server (identified by FP + enc
 * public key — it has no user_id). Defaults to member (same shape as
 * the wire before recipient classes were introduced).
 */
const DekRecipientClassSchema = Schema.Literals(["member", "server"]);

/**
 * One HPKE-wrapped epoch DEK for one recipient (AUTH_SPEC §12-6). The
 * recipient is identified by both user id and encryption public key; the
 * server requires both to match the chain-derived member exactly.
 * `signatureHex` is the per-wrap registration signature (CRYPTO_SPEC §5.1);
 * the signer must be the calling principal, so the wire carries no signer id.
 *
 * For recipient class server, the recipientUserId position carries the
 * **server key FP (32 lowercase hex chars)** — the same substitution as
 * the recipient_user_id position in HPKE info / the §5.1 signed payload
 * (CRYPTO_SPEC §9). Identification requires both the FP and the enc
 * public key to exactly match the chain-derived valid grant_server
 * payload.
 *
 * The recipientUserId limit is aligned to the chain consensus rule's
 * free-string limit (CRYPTO_SPEC §6.1's 1024 bytes) — the add_member
 * target is not validated more narrowly than this, so a narrower limit
 * could make a wrap for a legitimate member on the chain
 * unregistrable.
 */
export const WrappedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  recipientClass: Schema.optionalKey(DekRecipientClassSchema),
  recipientUserId: BoundedUserId,
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
});

/** One HPKE-wrapped epoch DEK for one recipient. */
export type WrappedDek = typeof WrappedDekSchema.Type;

/**
 * A wrap distributed to its recipient (the recipient is the caller — §12-6).
 * Carries the registration signature and the signer identity (user id + key
 * fingerprint at acceptance time) so the client can verify attribution
 * against the chain history (CRYPTO_SPEC §5.1).
 */
export const RecipientDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  /**
   * The recipient device key this wrap was sealed to (the AUTH_SPEC §12-6
   * device axis — 2026-09-19 DK K3). A member's wraps for all of its devices travel in one
   * response, so the recipient opens only the rows sealed to the key it holds
   * (an open failure on another device's row is not a poisoned wrap).
   */
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
  signerUserId: BoundedUserId,
  signerKeyFingerprintHex: KeyFingerprintHex,
});

/** A wrap distributed to its recipient. */
export type RecipientDek = typeof RecipientDekSchema.Type;

/**
 * Reference naming one stored wrap — the unit of the admin-only deletion in
 * the §12-6 repair path (delete a poisoned wrap, then re-register the missing
 * one through the append path). A row of recipient class server carries
 * the server key FP in the recipientUserId position (same convention as
 * WrappedDekSchema).
 */
export const DekWrapRefSchema = Schema.Struct({
  epoch: PositiveInt,
  recipientClass: Schema.optionalKey(DekRecipientClassSchema),
  recipientUserId: BoundedUserId,
  /**
   * The recipient device key of the slot (the AUTH_SPEC §12-6 device
   * axis — 2026-09-19 DK K3: slots are per device).
   */
  recipientEncPubHex: EncPubHex,
});

/** Reference naming one stored wrap (§12-6 repair path). */
export type DekWrapRef = typeof DekWrapRefSchema.Type;

/**
 * One leased epoch DEK (CRYPTO_SPEC §9.1 / AUTH_SPEC §14-2): the server
 * opened its own server-addressed wrap and re-sealed the DEK to the
 * workload's ephemeral public key.
 *
 * Deliberately **not** a `RecipientDek`: a lease wrap is server-generated,
 * response-scoped and never persisted (§9.1), so it carries no §5.1
 * registration signature and no signer identity — those describe a wrap a
 * chain member registered, which a lease wrap never is. Keeping the two wire
 * types apart stops a lease response from being mistaken for distributable
 * wrap material.
 */
export const LeasedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
});

/** One leased epoch DEK, sealed to the workload's ephemeral key. */
export type LeasedDek = typeof LeasedDekSchema.Type;
