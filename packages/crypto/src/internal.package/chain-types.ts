import type { ChainDevice } from "./chain-device.ts";
import type { MemberScope, ScopePayloadFields } from "./member-scope.ts";

export type Role = "owner" | "admin" | "member" | "reader";

export type ChainOp =
  | "genesis"
  | "add_member"
  | "remove_member"
  | "change_role"
  | "create_environment"
  | "delete_environment"
  | "rotate_epoch"
  | "grant_server"
  | "revoke_server"
  | "checkpoint"
  | "set_approval_policy"
  | "propose"
  | "approve"
  | "withdraw"
  | "add_device"
  | "revoke_device";

export type ApprovalTargetOp =
  | "grant_server"
  | "revoke_server"
  | "remove_member"
  | "change_role"
  | "add_member"
  | "set_approval_policy";

export const APPROVAL_TARGET_OPS: readonly ApprovalTargetOp[] = [
  "grant_server",
  "revoke_server",
  "remove_member",
  "change_role",
  "add_member",
  "set_approval_policy",
];

declare const userIdBrand: unique symbol;

export type UserId = string & { readonly [userIdBrand]: "UserId" };

declare const keyFingerprintBrand: unique symbol;

export type KeyFingerprintHex = string & { readonly [keyFingerprintBrand]: "KeyFingerprintHex" };

declare const projectIdBrand: unique symbol;

export type ProjectId = string & { readonly [projectIdBrand]: "ProjectId" };

declare const environmentIdBrand: unique symbol;

export type EnvironmentId = string & { readonly [environmentIdBrand]: "EnvironmentId" };

declare const variableIdBrand: unique symbol;

export type VariableId = string & { readonly [variableIdBrand]: "VariableId" };

export interface ChainActor {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

export interface GenesisPayload {
  readonly encPubHex: string;
  readonly sigPubHex: string;
}

export interface AddMemberPayload extends ScopePayloadFields {
  readonly targetUserId: UserId;
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly role: Role;
}

export interface RemoveMemberPayload {
  readonly targetUserId: UserId;
}

export interface ChangeRolePayload extends ScopePayloadFields {
  readonly targetUserId: UserId;
  readonly newRole: Role;
}

export interface CreateEnvironmentPayload {
  readonly environmentId: EnvironmentId;
  readonly dekCommitmentHex: string;
}

export interface DeleteEnvironmentPayload {
  readonly environmentId: EnvironmentId;
}

export interface RotateEpochPayload {
  readonly environmentId: EnvironmentId;
  readonly newEpoch: number;
  readonly reason: string;
  readonly dekCommitmentHex: string;
}

export interface LeaseClaimConstraint {
  readonly claimName: string;
  readonly claimValue: string;
}

export interface LeasePolicyIssuer {
  readonly issuerUrl: string;
  readonly audience: string;
  readonly claimConstraints: readonly LeaseClaimConstraint[];
}

export interface GrantServerPayload {
  readonly serverEncPubHex: string;
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}

export interface RevokeServerPayload {
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
}

export interface CheckpointEnvironmentEntry {
  readonly environmentId: EnvironmentId;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

export interface CheckpointPayload {
  readonly environments: readonly CheckpointEnvironmentEntry[];
  readonly auditHeadHashHex: string;
}

export interface SetApprovalPolicyPayload {
  readonly ops: readonly ApprovalTargetOp[];
  readonly requiredApprovals: number;
}

export type ProposableOperation = Exclude<
  ChainOperation,
  { readonly op: "propose" | "approve" | "withdraw" }
>;

export interface ProposePayload {
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
}

export interface ApprovePayload {
  readonly proposalHashHex: string;
}

export interface WithdrawPayload {
  readonly proposalHashHex: string;
}

export interface AddDevicePayload extends ScopePayloadFields {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly roleCap: Role;
}

export interface RevokeDevicePayload {
  readonly targetUserId: UserId;
  readonly deviceFingerprintsHex: readonly KeyFingerprintHex[];
}

export type ChainOperation =
  | { readonly op: "genesis"; readonly payload: GenesisPayload }
  | { readonly op: "add_member"; readonly payload: AddMemberPayload }
  | { readonly op: "remove_member"; readonly payload: RemoveMemberPayload }
  | { readonly op: "change_role"; readonly payload: ChangeRolePayload }
  | { readonly op: "create_environment"; readonly payload: CreateEnvironmentPayload }
  | { readonly op: "delete_environment"; readonly payload: DeleteEnvironmentPayload }
  | { readonly op: "rotate_epoch"; readonly payload: RotateEpochPayload }
  | { readonly op: "grant_server"; readonly payload: GrantServerPayload }
  | { readonly op: "revoke_server"; readonly payload: RevokeServerPayload }
  | { readonly op: "checkpoint"; readonly payload: CheckpointPayload }
  | { readonly op: "set_approval_policy"; readonly payload: SetApprovalPolicyPayload }
  | { readonly op: "propose"; readonly payload: ProposePayload }
  | { readonly op: "approve"; readonly payload: ApprovePayload }
  | { readonly op: "withdraw"; readonly payload: WithdrawPayload }
  | { readonly op: "add_device"; readonly payload: AddDevicePayload }
  | { readonly op: "revoke_device"; readonly payload: RevokeDevicePayload };

export type UnsignedChainEntry = ChainOperation & {
  readonly suite: string;
  readonly seq: number;
  readonly prevHashHex: string;
  readonly actor: ChainActor;
  readonly timestampMs: number;
};

export type ChainEntry = UnsignedChainEntry & { readonly signatureHex: string };

export interface ChainMember {
  readonly userId: UserId;
  readonly role: Role;
  readonly scope: MemberScope;
  readonly devices: ReadonlyMap<string, ChainDevice>;
}

export interface ApprovalPolicy {
  readonly ops: readonly ApprovalTargetOp[];
  readonly requiredApprovals: number;
}

export interface ApprovalVote {
  readonly userId: UserId;
  readonly keyFingerprintHex: KeyFingerprintHex;
}

export interface PendingProposal {
  readonly proposalSeq: number;
  readonly proposalHashHex: string;
  readonly proposerUserId: UserId;
  readonly proposerKeyFingerprintHex: KeyFingerprintHex;
  readonly proposerRoleAtProposal: Role;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: readonly ApprovalVote[];
}

export interface ServerGrant {
  readonly serverKeyFingerprintHex: KeyFingerprintHex;
  readonly serverEncPubHex: string;
  readonly grantSeq: number;
  readonly scopeEnvironmentIds: readonly EnvironmentId[];
  readonly leasePolicy: readonly LeasePolicyIssuer[];
}

export interface EnvironmentChainState {
  readonly currentEpoch: number;
  readonly createdAtSeq: number;
  readonly deletedAtSeq: number | null;
  readonly epochStartSeqs: ReadonlyMap<number, number>;
  readonly dekCommitments: ReadonlyMap<number, string>;
}

export interface EnvironmentCheckpointState {
  readonly seq: number;
  readonly epoch: number;
  readonly manifestVersion: number;
  readonly manifestSigHashHex: string;
  readonly valuesDigestHex: string;
}

export interface ChainState {
  readonly members: ReadonlyMap<UserId, ChainMember>;
  readonly serverGrants: ReadonlyMap<KeyFingerprintHex, ServerGrant>;
  readonly environments: ReadonlyMap<EnvironmentId, EnvironmentChainState>;
  readonly checkpoints: ReadonlyMap<EnvironmentId, EnvironmentCheckpointState>;
  readonly approvalPolicy: ApprovalPolicy | null;
  readonly pendingProposals: ReadonlyMap<string, PendingProposal>;
  readonly namedServerKeys: ReadonlyMap<string, KeyFingerprintHex>;
  readonly headSeq: number;
  readonly headHashHex: string;
}
