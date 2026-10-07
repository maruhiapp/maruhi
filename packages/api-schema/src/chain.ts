// Wire representation of the membership log (CRYPTO_SPEC §6).
//
// The fields match @maruhi/crypto's ChainEntry structurally, so a decoded
// value can be passed to verifyChain unchanged (no repacking layer on the
// server side).
//
// The verification authority is verifyChain (§6.3 / §6.4). The Schema
// checks only the transport shape: fixed-length hex is checked here
// because it can be rejected cheaply and precisely, but the free-string
// size limits (the §6.1 consensus rules) are deliberately not duplicated
// into the Schema — a limit violation should be reported consistently as
// verifyChain's `invalid-payload` (a reason code pinned by test vectors),
// so that a Schema 400 does not become a second refusal path.

import { EnvironmentIdSchema, UserIdSchema } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";
import { Schema } from "effect";

import { KeyFingerprintHex, PublicKeyHex, Sha256Hex, SignatureHex } from "./hex.ts";

/** Chain role (CRYPTO_SPEC §6.2). */
export const RoleSchema = Schema.Literals(["owner", "admin", "member", "reader"]);

/** Entry actor: internal user id + key fingerprint only (CRYPTO_SPEC §6.1). */
export const ChainActorSchema = Schema.Struct({
  // userId is deliberately unbounded (verifyChain checks the §6.1 free-string limit)
  userId: UserIdSchema,
  keyFingerprintHex: KeyFingerprintHex,
});

const entryBaseFields = {
  suite: Schema.String,
  seq: Schema.Number,
  prevHashHex: Sha256Hex,
  actor: ChainActorSchema,
  timestampMs: Schema.Number,
  signatureHex: SignatureHex,
};

/** Member scope kind (CRYPTO_SPEC §6.2 — 2026-09-14 ES). */
export const ScopeKindSchema = Schema.Literals(["all", "listed"]);

/**
 * The two trailing scope fields of `add_member` / `change_role` (CRYPTO_SPEC
 * §6.2). The wire carries the structured list of environment_ids in
 * as-signed order (canonicalization = nested LP lives on the crypto side).
 * `all` ⇒ empty list, at most 256 entries, no duplicates are consensus
 * rules that verifyChain checks as `invalid-payload` (not duplicated into
 * the Schema, per the policy in the header comment)
 */
const scopePayloadFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(Schema.String),
};

const GenesisPayloadSchema = Schema.Struct({ encPubHex: PublicKeyHex, sigPubHex: PublicKeyHex });

const AddMemberPayloadSchema = Schema.Struct({
  targetUserId: UserIdSchema,
  encPubHex: PublicKeyHex,
  sigPubHex: PublicKeyHex,
  role: RoleSchema,
  ...scopePayloadFields,
});

const RemoveMemberPayloadSchema = Schema.Struct({ targetUserId: UserIdSchema });

const ChangeRolePayloadSchema = Schema.Struct({
  targetUserId: UserIdSchema,
  newRole: RoleSchema,
  ...scopePayloadFields,
});

const GenesisEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("genesis"),
  payload: GenesisPayloadSchema,
});

const AddMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("add_member"),
  payload: AddMemberPayloadSchema,
});

const RemoveMemberEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("remove_member"),
  payload: RemoveMemberPayloadSchema,
});

const ChangeRoleEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("change_role"),
  payload: ChangeRolePayloadSchema,
});

/**
 * `create_environment` entry (CRYPTO_SPEC §6.2): carries the
 * epoch-1 DEK commitment (§5.2). Submitted only through the composite
 * environment-creation endpoint (AUTH_SPEC §12-4) — the generic append
 * rejects it (§6). Exported for that endpoint's payload schema.
 *
 * environmentId is checked with the §12-1 acceptance-policy format
 * (EnvironmentIdSchema): compositing moved ID carriage from the old
 * payload into the chain entry, and the entry carries no URL coordinate,
 * so this is the only wire acceptance point (the format is not a
 * consensus rule — chain verification only requires the §6.1 bounded
 * string. Accepting a loosely-formatted ID would create an environment
 * unreachable from the follow-up endpoints that take a URL param —
 * rotate / rename / delete / pull — and would also break §7's
 * all-environment rotation obligation).
 */
const CreateEnvironmentPayloadSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  dekCommitmentHex: Sha256Hex,
});

export const CreateEnvironmentEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("create_environment"),
  payload: CreateEnvironmentPayloadSchema,
});

/**
 * `rotate_epoch` entry: carries the new-epoch DEK commitment (§5.2).
 * Submitted only through the composite rotation endpoint
 * (AUTH_SPEC §12-4). Exported for that endpoint's payload schema.
 */
const RotateEpochPayloadSchema = Schema.Struct({
  // Same acceptance-policy format as create_environment (it is the target
  // of the URL-coordinate match check — §12-4 — but the wire side is
  // pinned to the same format so no asymmetry is introduced)
  environmentId: EnvironmentIdSchema,
  newEpoch: Schema.Number,
  reason: Schema.String,
  dekCommitmentHex: Sha256Hex,
});

export const RotateEpochEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("rotate_epoch"),
  payload: RotateEpochPayloadSchema,
});

/**
 * One exact-match claim constraint of a grant_server lease policy element
 * (CRYPTO_SPEC §6.2). The size limits (8 elements / 8 constraints / 1024
 * bytes per string) are consensus rules checked by verifyChain (not
 * duplicated into the Schema — the policy in the header comment).
 */
const LeaseClaimConstraintSchema = Schema.Struct({
  claimName: Schema.String,
  claimValue: Schema.String,
});

/** One issuer element of a grant_server lease policy (CRYPTO_SPEC §6.2 / §9.1). */
const LeasePolicyIssuerSchema = Schema.Struct({
  issuerUrl: Schema.String,
  audience: Schema.String,
  claimConstraints: Schema.Array(LeaseClaimConstraintSchema),
});

const GrantServerPayloadSchema = Schema.Struct({
  serverEncPubHex: PublicKeyHex,
  serverKeyFingerprintHex: KeyFingerprintHex,
  scopeEnvironmentIds: Schema.Array(Schema.String),
  // The wire carries the structured list in as-signed order
  // (canonicalization = the 3-level nested LP lives on the crypto side —
  // order is part of the signed payload, so it is kept as an array rather
  // than an object)
  leasePolicy: Schema.Array(LeasePolicyIssuerSchema),
});

const GrantServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("grant_server"),
  payload: GrantServerPayloadSchema,
});

const RevokeServerPayloadSchema = Schema.Struct({ serverKeyFingerprintHex: KeyFingerprintHex });

const RevokeServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_server"),
  payload: RevokeServerPayloadSchema,
});

/**
 * One environment tuple of a `checkpoint` payload (CRYPTO_SPEC §6.2).
 * environmentId uses the same acceptance-policy format as create/rotate.
 * The numeric ranges of epoch / manifestVersion, duplicate
 * environment_ids, and audit_head's "empty or 64 hex" are consensus rules
 * checked by verifyChain (not duplicated into the Schema, per the header
 * policy; only fixed-length hex is checked here).
 */
const CheckpointEnvironmentEntrySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  epoch: Schema.Number,
  manifestVersion: Schema.Number,
  manifestSigHashHex: Sha256Hex,
  valuesDigestHex: Sha256Hex,
});

/**
 * `checkpoint` entry (CRYPTO_SPEC §6.2): the issuer's attestation of its
 * verified data-layer view. Boundary checkpoints are submitted only through
 * the composite create/rotate endpoints (AUTH_SPEC §12-4);
 * standalone (periodic) checkpoints flow through the generic append with
 * acceptance-time content matching (AUTH_SPEC §16-2). Exported for
 * the composite payload schemas (data-api.ts).
 */
const CheckpointPayloadSchema = Schema.Struct({
  // The wire carries the structured list in as-signed order
  // (canonicalization = nested LP lives on the crypto side — order is
  // part of the signed payload, so it is kept as an array; same shape as
  // grant_server)
  environments: Schema.Array(CheckpointEnvironmentEntrySchema),
  // Empty string = no audit-head notarization (§6.2). The "empty or 64
  // hex" check is consolidated into the consensus rule (verifyChain)
  auditHeadHashHex: Schema.String,
});

export const CheckpointEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("checkpoint"),
  payload: CheckpointPayloadSchema,
});

// ---------------------------------------------------------------------------
// Four-eyes (CRYPTO_SPEC §6.2 — 2026-09-14 PF1)

/** Operations a four-eyes policy may name (CRYPTO_SPEC §6.2 — the closed target set). */
const ApprovalTargetOpSchema = Schema.Literals([
  "grant_server",
  "revoke_server",
  "remove_member",
  "change_role",
  "add_member",
  "set_approval_policy",
]);

/**
 * `set_approval_policy` payload: ops is an as-signed-order array
 * (canonicalization = nested LP lives on the crypto side). The
 * required_approvals "0 or at least 2" rule and the closed-set check on
 * ops are consensus rules (verifyChain) — here only the closed-set
 * literals are held as a type (so the wire type matches the crypto type)
 */
const SetApprovalPolicyPayloadSchema = Schema.Struct({
  ops: Schema.Array(ApprovalTargetOpSchema),
  requiredApprovals: Schema.Number,
});

const SetApprovalPolicyEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("set_approval_policy"),
  payload: SetApprovalPolicyPayloadSchema,
});

/**
 * `add_device` payload (CRYPTO_SPEC §6.2 — 2026-09-19 DK): the actor's new
 * device key and its cap. The scope pair reuses the member-scope fields (same
 * encoding and structure rules — verifyChain checks them as `invalid-payload`).
 */
const AddDevicePayloadSchema = Schema.Struct({
  encPubHex: PublicKeyHex,
  sigPubHex: PublicKeyHex,
  roleCap: RoleSchema,
  ...scopePayloadFields,
});

/**
 * `revoke_device` payload (CRYPTO_SPEC §6.2 — 2026-09-19 DK): the target and the
 * fingerprints of that member's devices to revoke, carried as-signed (the nested
 * length-prefixed canonical form is computed by the crypto layer). 1..256 entries
 * and no duplicates are consensus rules (`invalid-payload`), not Schema checks.
 */
const RevokeDevicePayloadSchema = Schema.Struct({
  targetUserId: UserIdSchema,
  deviceFingerprintsHex: Schema.Array(KeyFingerprintHex),
});

/**
 * An operation carried inside a `propose` entry (CRYPTO_SPEC §6.2): any
 * non-approval operation as `{ op, payload }` — structured on the wire, the
 * `inner_payload_lp_hex` canonical form is computed by the crypto layer.
 * `propose` / `approve` / `withdraw` are not members (nesting a proposal
 * is invalid at the structure stage).
 */
const ProposableOperationSchema = Schema.Union([
  Schema.Struct({ op: Schema.Literal("genesis"), payload: GenesisPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("add_member"), payload: AddMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("remove_member"), payload: RemoveMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("change_role"), payload: ChangeRolePayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("create_environment"),
    payload: CreateEnvironmentPayloadSchema,
  }),
  Schema.Struct({ op: Schema.Literal("rotate_epoch"), payload: RotateEpochPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("grant_server"), payload: GrantServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_server"), payload: RevokeServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("checkpoint"), payload: CheckpointPayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("set_approval_policy"),
    payload: SetApprovalPolicyPayloadSchema,
  }),
  // The two device-key ops (2026-09-19 DK) can structurally be inner ops,
  // but they can never be policy targets (`approval-not-required` —
  // CRYPTO_SPEC §6.2 "relationship to four-eyes"; verifyChain decides)
  Schema.Struct({ op: Schema.Literal("add_device"), payload: AddDevicePayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_device"), payload: RevokeDevicePayloadSchema }),
]);

const ProposeEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("propose"),
  payload: Schema.Struct({
    inner: ProposableOperationSchema,
    // A non-negative safe integer is a consensus rule (verifyChain's invalid-payload)
    expiresAtMs: Schema.Number,
  }),
});

/** `approve` / `withdraw` payload: the `propose` entry hash (CRYPTO_SPEC §6.2). */
const ProposalRefPayloadSchema = Schema.Struct({ proposalHashHex: Sha256Hex });

const ApproveEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("approve"),
  payload: ProposalRefPayloadSchema,
});

const WithdrawEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("withdraw"),
  payload: ProposalRefPayloadSchema,
});

const AddDeviceEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("add_device"),
  payload: AddDevicePayloadSchema,
});

const RevokeDeviceEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_device"),
  payload: RevokeDevicePayloadSchema,
});

/** Wire schema for one signed chain entry, discriminated by `op` (CRYPTO_SPEC §6.1). */
export const ChainEntrySchema = Schema.Union([
  GenesisEntrySchema,
  AddMemberEntrySchema,
  RemoveMemberEntrySchema,
  ChangeRoleEntrySchema,
  CreateEnvironmentEntrySchema,
  RotateEpochEntrySchema,
  GrantServerEntrySchema,
  RevokeServerEntrySchema,
  CheckpointEntrySchema,
  SetApprovalPolicyEntrySchema,
  ProposeEntrySchema,
  ApproveEntrySchema,
  WithdrawEntrySchema,
  // Device keys (CRYPTO_SPEC §6.2 — 2026-09-19 DK)
  AddDeviceEntrySchema,
  RevokeDeviceEntrySchema,
]);

// Static check that a decoded value can be passed unchanged to
// @maruhi/crypto's ChainEntry. (If the wire type diverges from the crypto
// type, this fails to compile)
type WireChainEntry = typeof ChainEntrySchema.Type;
type WireIsChainEntry = WireChainEntry extends ChainEntry ? true : never;
const wireIsChainEntry: WireIsChainEntry = true;
void wireIsChainEntry;
type WireProposable = typeof ProposableOperationSchema.Type;
type WireIsProposable = WireProposable extends ProposableOperation ? true : never;
const wireIsProposable: WireIsProposable = true;
void wireIsProposable;
