import { EnvironmentIdSchema, KeyFingerprintHexSchema, UserIdSchema } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";
import { Schema } from "effect";

import { PublicKeyHex, Sha256Hex, SignatureHex } from "./hex.ts";

export const RoleSchema = Schema.Literals(["owner", "admin", "member", "reader"]);

export const ChainActorSchema = Schema.Struct({
  userId: UserIdSchema,
  keyFingerprintHex: KeyFingerprintHexSchema,
});

const entryBaseFields = {
  suite: Schema.String,
  seq: Schema.Number,
  prevHashHex: Sha256Hex,
  actor: ChainActorSchema,
  timestampMs: Schema.Number,
  signatureHex: SignatureHex,
};

export const ScopeKindSchema = Schema.Literals(["all", "listed"]);

const scopePayloadFields = {
  scopeKind: ScopeKindSchema,
  scopeEnvironmentIds: Schema.Array(EnvironmentIdSchema),
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

const CreateEnvironmentPayloadSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  dekCommitmentHex: Sha256Hex,
});

export const CreateEnvironmentEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("create_environment"),
  payload: CreateEnvironmentPayloadSchema,
});

const DeleteEnvironmentPayloadSchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
});

export const DeleteEnvironmentEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("delete_environment"),
  payload: DeleteEnvironmentPayloadSchema,
});

const RotateEpochPayloadSchema = Schema.Struct({
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

const LeaseClaimConstraintSchema = Schema.Struct({
  claimName: Schema.String,
  claimValue: Schema.String,
});

const LeasePolicyIssuerSchema = Schema.Struct({
  issuerUrl: Schema.String,
  audience: Schema.String,
  claimConstraints: Schema.Array(LeaseClaimConstraintSchema),
});

const GrantServerPayloadSchema = Schema.Struct({
  serverEncPubHex: PublicKeyHex,
  serverKeyFingerprintHex: KeyFingerprintHexSchema,
  scopeEnvironmentIds: Schema.Array(EnvironmentIdSchema),
  leasePolicy: Schema.Array(LeasePolicyIssuerSchema),
});

const GrantServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("grant_server"),
  payload: GrantServerPayloadSchema,
});

const RevokeServerPayloadSchema = Schema.Struct({
  serverKeyFingerprintHex: KeyFingerprintHexSchema,
});

const RevokeServerEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("revoke_server"),
  payload: RevokeServerPayloadSchema,
});

const CheckpointEnvironmentEntrySchema = Schema.Struct({
  environmentId: EnvironmentIdSchema,
  epoch: Schema.Number,
  manifestVersion: Schema.Number,
  manifestSigHashHex: Sha256Hex,
  valuesDigestHex: Sha256Hex,
});

const CheckpointPayloadSchema = Schema.Struct({
  environments: Schema.Array(CheckpointEnvironmentEntrySchema),
  auditHeadHashHex: Schema.String,
});

export const CheckpointEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("checkpoint"),
  payload: CheckpointPayloadSchema,
});

const ApprovalTargetOpSchema = Schema.Literals([
  "grant_server",
  "revoke_server",
  "remove_member",
  "change_role",
  "add_member",
  "set_approval_policy",
]);

const SetApprovalPolicyPayloadSchema = Schema.Struct({
  ops: Schema.Array(ApprovalTargetOpSchema),
  requiredApprovals: Schema.Number,
});

const SetApprovalPolicyEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("set_approval_policy"),
  payload: SetApprovalPolicyPayloadSchema,
});

const AddDevicePayloadSchema = Schema.Struct({
  encPubHex: PublicKeyHex,
  sigPubHex: PublicKeyHex,
  roleCap: RoleSchema,
  ...scopePayloadFields,
});

const RevokeDevicePayloadSchema = Schema.Struct({
  targetUserId: UserIdSchema,
  deviceFingerprintsHex: Schema.Array(KeyFingerprintHexSchema),
});

const ProposableOperationSchema = Schema.Union([
  Schema.Struct({ op: Schema.Literal("genesis"), payload: GenesisPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("add_member"), payload: AddMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("remove_member"), payload: RemoveMemberPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("change_role"), payload: ChangeRolePayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("create_environment"),
    payload: CreateEnvironmentPayloadSchema,
  }),
  Schema.Struct({
    op: Schema.Literal("delete_environment"),
    payload: DeleteEnvironmentPayloadSchema,
  }),
  Schema.Struct({ op: Schema.Literal("rotate_epoch"), payload: RotateEpochPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("grant_server"), payload: GrantServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_server"), payload: RevokeServerPayloadSchema }),
  Schema.Struct({ op: Schema.Literal("checkpoint"), payload: CheckpointPayloadSchema }),
  Schema.Struct({
    op: Schema.Literal("set_approval_policy"),
    payload: SetApprovalPolicyPayloadSchema,
  }),
  Schema.Struct({ op: Schema.Literal("add_device"), payload: AddDevicePayloadSchema }),
  Schema.Struct({ op: Schema.Literal("revoke_device"), payload: RevokeDevicePayloadSchema }),
]);

const ProposeEntrySchema = Schema.Struct({
  ...entryBaseFields,
  op: Schema.Literal("propose"),
  payload: Schema.Struct({
    inner: ProposableOperationSchema,
    expiresAtMs: Schema.Number,
  }),
});

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

export const ChainEntrySchema = Schema.Union([
  GenesisEntrySchema,
  AddMemberEntrySchema,
  RemoveMemberEntrySchema,
  ChangeRoleEntrySchema,
  CreateEnvironmentEntrySchema,
  DeleteEnvironmentEntrySchema,
  RotateEpochEntrySchema,
  GrantServerEntrySchema,
  RevokeServerEntrySchema,
  CheckpointEntrySchema,
  SetApprovalPolicyEntrySchema,
  ProposeEntrySchema,
  ApproveEntrySchema,
  WithdrawEntrySchema,
  AddDeviceEntrySchema,
  RevokeDeviceEntrySchema,
]);

type WireChainEntry = typeof ChainEntrySchema.Type;
type WireIsChainEntry = WireChainEntry extends ChainEntry ? true : never;
const wireIsChainEntry: WireIsChainEntry = true;
void wireIsChainEntry;
type WireProposable = typeof ProposableOperationSchema.Type;
type WireIsProposable = WireProposable extends ProposableOperation ? true : never;
const wireIsProposable: WireIsProposable = true;
void wireIsProposable;
