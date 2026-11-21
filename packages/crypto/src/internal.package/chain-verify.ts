import { concatBytes, decodeHex, encodeHex, utf8Encode } from "./bytes.ts";
import { canonicalChainSignedBytes, computeChainEntryHash } from "./chain-canonical.ts";
import {
  type ChainDevice,
  type EffectivePermission,
  FIRST_DEVICE_CAP,
  ROLE_RANK,
  capWithinCap,
  effectivePermissionOf,
  soleDeviceOf,
} from "./chain-device.ts";
import { ChainHistoryBuilder, type ChainHistoryIndex } from "./chain-history.ts";
import {
  APPROVAL_TARGET_OPS,
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  type ChainEntry,
  type ChainMember,
  type ChainState,
  type CheckpointEnvironmentEntry,
  type EnvironmentChainState,
  type EnvironmentCheckpointState,
  type EnvironmentId,
  type KeyFingerprintHex,
  type PendingProposal,
  type ProposableOperation,
  type Role,
  type ServerGrant,
  type UserId,
} from "./chain-types.ts";
import type { ChainInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  ALL_SCOPE,
  type EnvironmentSet,
  MAX_SCOPE_ENVIRONMENTS,
  memberScopeOf,
  scopeAsEnvironmentSet,
  scopeContainsEnvironmentSet,
  scopeIncludesEnvironment,
  scopeShapeOk,
  scopeWithout,
  symmetricDifferenceEnvironmentSets,
  unionEnvironmentSets,
} from "./member-scope.ts";
import { SUITE_ID } from "./suite.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];
const FINGERPRINT_BYTES = 16;
const SIGNATURE_BYTES = 64;
const SHA256_BYTES = 32;
const MAX_FIELD_BYTES = 1024;
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
const MIN_ACTIVE_REQUIRED_APPROVALS = 2;
const MAX_REVOKE_DEVICE_FINGERPRINTS = 256;

interface MutableEnvironmentState {
  currentEpoch: number;
  readonly createdAtSeq: number;
  deletedAtSeq: number | null;
  readonly epochStartSeqs: Map<number, number>;
  readonly dekCommitments: Map<number, string>;
}

interface MutablePendingProposal {
  readonly proposalSeq: number;
  readonly proposalHashHex: string;
  readonly proposerUserId: UserId;
  readonly proposerKeyFingerprintHex: KeyFingerprintHex;
  readonly proposerRoleAtProposal: Role;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: ApprovalVote[];
}

interface MutableChainState {
  readonly members: Map<string, ChainMember>;
  readonly serverGrants: Map<string, ServerGrant>;
  readonly environments: Map<string, MutableEnvironmentState>;
  readonly checkpoints: Map<string, EnvironmentCheckpointState>;
  readonly memberEncPubs: Set<string>;
  readonly memberSigPubs: Set<string>;
  readonly namedServerKeys: Map<string, KeyFingerprintHex>;
  approvalPolicy: ApprovalPolicy | null;
  readonly pendingProposals: Map<string, MutablePendingProposal>;
}

interface ActorContext {
  readonly userId: UserId;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

interface AppliedOperation {
  readonly operation: ProposableOperation;
  readonly actorUserId: string;
}

function withinFieldBytes(value: string): boolean {
  return value.length <= MAX_FIELD_BYTES && utf8Encode(value).length <= MAX_FIELD_BYTES;
}

function isBoundedId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && withinFieldBytes(value);
}

function isHexOfLength(value: unknown, bytes: number): boolean {
  if (typeof value !== "string" || value.length !== bytes * 2) {
    return false;
  }
  const decoded = decodeHex(value);
  return decoded !== null && decoded.length === bytes;
}

function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

export function isApprovalTargetOp(value: unknown): value is ApprovalTargetOp {
  return typeof value === "string" && (APPROVAL_TARGET_OPS as readonly string[]).includes(value);
}

function atLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

async function userFingerprintHex(
  encPubHex: string,
  sigPubHex: string,
): Promise<KeyFingerprintHex> {
  const enc = decodeHex(encPubHex) ?? new Uint8Array(0);
  const sig = decodeHex(sigPubHex) ?? new Uint8Array(0);
  const digest = await sha256(concatBytes(enc, sig));
  return encodeHex(digest.slice(0, FINGERPRINT_BYTES)) as KeyFingerprintHex;
}

function checkFraming(
  entry: ChainEntry,
  expectedSeq: number,
  expectedPrevHash: string,
): ChainInvalidReason | null {
  if (entry.suite !== SUITE_ID) {
    return "bad-suite";
  }
  if (entry.seq !== expectedSeq) {
    return "bad-seq";
  }
  if ((expectedSeq === 1) !== (entry.op === "genesis")) {
    return "bad-genesis";
  }
  if (entry.prevHashHex !== expectedPrevHash) {
    return "bad-prev-hash";
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function checkPayloadShape(entry: ChainEntry): ChainInvalidReason | null {
  if (!Number.isSafeInteger(entry.timestampMs) || entry.timestampMs < 0) {
    return "invalid-payload";
  }
  if (
    !isRecord(entry.actor) ||
    !isBoundedId(entry.actor.userId) ||
    !isHexOfLength(entry.actor.keyFingerprintHex, FINGERPRINT_BYTES)
  ) {
    return "invalid-payload";
  }
  if (!isHexOfLength(entry.signatureHex, SIGNATURE_BYTES)) {
    return "invalid-payload";
  }
  return operationShapeOk(entry.op, entry.payload) ? null : "invalid-payload";
}

function shapeGenesis(p: { encPubHex: unknown; sigPubHex: unknown }): boolean {
  return isHexOfLength(p.encPubHex, 32) && isHexOfLength(p.sigPubHex, 32);
}

function shapeScope(p: { scopeKind: unknown; scopeEnvironmentIds: unknown }): boolean {
  return scopeShapeOk(p.scopeKind, p.scopeEnvironmentIds, isBoundedId);
}

function shapeAddMember(p: {
  targetUserId: unknown;
  encPubHex: unknown;
  sigPubHex: unknown;
  role: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return isBoundedId(p.targetUserId) && shapeGenesis(p) && isRole(p.role) && shapeScope(p);
}

function shapeChangeRole(p: {
  targetUserId: unknown;
  newRole: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return isBoundedId(p.targetUserId) && isRole(p.newRole) && shapeScope(p);
}

function shapeCreateEnvironment(p: { environmentId: unknown; dekCommitmentHex: unknown }): boolean {
  return isBoundedId(p.environmentId) && isHexOfLength(p.dekCommitmentHex, SHA256_BYTES);
}

function shapeRotateEpoch(p: {
  environmentId: unknown;
  newEpoch: unknown;
  reason: unknown;
  dekCommitmentHex: unknown;
}): boolean {
  return (
    isBoundedId(p.environmentId) &&
    Number.isSafeInteger(p.newEpoch) &&
    (p.newEpoch as number) >= 1 &&
    typeof p.reason === "string" &&
    withinFieldBytes(p.reason) &&
    isHexOfLength(p.dekCommitmentHex, SHA256_BYTES)
  );
}

function shapeLeaseClaimConstraint(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.claimName) &&
    typeof value.claimValue === "string" &&
    withinFieldBytes(value.claimValue)
  );
}

function shapeLeasePolicyIssuer(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.issuerUrl) &&
    isBoundedId(value.audience) &&
    Array.isArray(value.claimConstraints) &&
    value.claimConstraints.length <= MAX_LEASE_CLAIM_CONSTRAINTS &&
    value.claimConstraints.every((constraint) => shapeLeaseClaimConstraint(constraint))
  );
}

function shapeGrantServer(p: {
  serverEncPubHex: unknown;
  serverKeyFingerprintHex: unknown;
  scopeEnvironmentIds: unknown;
  leasePolicy: unknown;
}): boolean {
  return (
    isHexOfLength(p.serverEncPubHex, 32) &&
    isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES) &&
    Array.isArray(p.scopeEnvironmentIds) &&
    p.scopeEnvironmentIds.length <= MAX_SCOPE_ENVIRONMENTS &&
    p.scopeEnvironmentIds.every((id) => isBoundedId(id)) &&
    Array.isArray(p.leasePolicy) &&
    p.leasePolicy.length <= MAX_LEASE_POLICY_ISSUERS &&
    p.leasePolicy.every((element) => shapeLeasePolicyIssuer(element))
  );
}

function shapeCheckpointEnvironment(value: unknown): boolean {
  if (!isRecord(value)) {
    return false;
  }
  return (
    isBoundedId(value.environmentId) &&
    Number.isSafeInteger(value.epoch) &&
    (value.epoch as number) >= 1 &&
    Number.isSafeInteger(value.manifestVersion) &&
    (value.manifestVersion as number) >= 1 &&
    isHexOfLength(value.manifestSigHashHex, SHA256_BYTES) &&
    isHexOfLength(value.valuesDigestHex, SHA256_BYTES)
  );
}

function shapeCheckpoint(p: { environments: unknown; auditHeadHashHex: unknown }): boolean {
  if (!Array.isArray(p.environments)) {
    return false;
  }
  if (!p.environments.every((entry) => shapeCheckpointEnvironment(entry))) {
    return false;
  }
  const ids = new Set<string>();
  for (const entry of p.environments as readonly { environmentId: string }[]) {
    if (ids.has(entry.environmentId)) {
      return false;
    }
    ids.add(entry.environmentId);
  }
  return p.auditHeadHashHex === "" || isHexOfLength(p.auditHeadHashHex, SHA256_BYTES);
}

function shapeSetApprovalPolicy(p: { ops: unknown; requiredApprovals: unknown }): boolean {
  return (
    Array.isArray(p.ops) &&
    p.ops.every((op) => isApprovalTargetOp(op)) &&
    Number.isSafeInteger(p.requiredApprovals) &&
    ((p.requiredApprovals as number) === 0 ||
      (p.requiredApprovals as number) >= MIN_ACTIVE_REQUIRED_APPROVALS)
  );
}

function shapePropose(p: { inner: unknown; expiresAtMs: unknown }): boolean {
  if (!isRecord(p.inner) || !isProposableOp(p.inner.op)) {
    return false;
  }
  return (
    operationShapeOk(p.inner.op, p.inner.payload) &&
    Number.isSafeInteger(p.expiresAtMs) &&
    (p.expiresAtMs as number) >= 0
  );
}

function shapeProposalRef(p: { proposalHashHex: unknown }): boolean {
  return isHexOfLength(p.proposalHashHex, SHA256_BYTES);
}

function shapeAddDevice(p: {
  encPubHex: unknown;
  sigPubHex: unknown;
  roleCap: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return shapeGenesis(p) && isRole(p.roleCap) && shapeScope(p);
}

function shapeRevokeDevice(p: { targetUserId: unknown; deviceFingerprintsHex: unknown }): boolean {
  if (!isBoundedId(p.targetUserId) || !Array.isArray(p.deviceFingerprintsHex)) {
    return false;
  }
  const fps = p.deviceFingerprintsHex;
  if (fps.length < 1 || fps.length > MAX_REVOKE_DEVICE_FINGERPRINTS) {
    return false;
  }
  if (!fps.every((fp) => isHexOfLength(fp, FINGERPRINT_BYTES))) {
    return false;
  }
  return new Set(fps as readonly string[]).size === fps.length;
}

const PAYLOAD_SHAPES: {
  readonly [K in ChainEntry["op"]]: (payload: Extract<ChainEntry, { op: K }>["payload"]) => boolean;
} = {
  genesis: shapeGenesis,
  add_member: shapeAddMember,
  remove_member: (p) => isBoundedId(p.targetUserId),
  change_role: shapeChangeRole,
  create_environment: shapeCreateEnvironment,
  delete_environment: (p) => isBoundedId(p.environmentId),
  rotate_epoch: shapeRotateEpoch,
  grant_server: shapeGrantServer,
  revoke_server: (p) => isHexOfLength(p.serverKeyFingerprintHex, FINGERPRINT_BYTES),
  checkpoint: shapeCheckpoint,
  set_approval_policy: shapeSetApprovalPolicy,
  propose: shapePropose,
  approve: shapeProposalRef,
  withdraw: shapeProposalRef,
  add_device: shapeAddDevice,
  revoke_device: shapeRevokeDevice,
};

const APPROVAL_OPS: readonly string[] = ["propose", "approve", "withdraw"];

function isKnownOp(op: unknown): op is ChainEntry["op"] {
  return typeof op === "string" && Object.hasOwn(PAYLOAD_SHAPES, op);
}

function isProposableOp(op: unknown): op is ProposableOperation["op"] {
  return isKnownOp(op) && !APPROVAL_OPS.includes(op);
}

function operationShapeOk(op: unknown, payload: unknown): boolean {
  if (!isKnownOp(op) || !isRecord(payload)) {
    return false;
  }
  return PAYLOAD_SHAPES[op](payload as never);
}

async function resolveActorSigPub(
  entry: ChainEntry,
  state: MutableChainState,
): Promise<{ readonly sigPubHex: string } | { readonly reason: ChainInvalidReason }> {
  if (entry.op === "genesis") {
    const fp = await userFingerprintHex(entry.payload.encPubHex, entry.payload.sigPubHex);
    if (fp !== entry.actor.keyFingerprintHex) {
      return { reason: "actor-key-mismatch" };
    }
    return { sigPubHex: entry.payload.sigPubHex };
  }
  const record = state.members.get(entry.actor.userId);
  if (record === undefined) {
    return { reason: "actor-not-member" };
  }
  const device = record.devices.get(entry.actor.keyFingerprintHex);
  if (device === undefined) {
    return { reason: "actor-key-mismatch" };
  }
  return { sigPubHex: device.sigPubHex };
}

async function verifyEntrySignature(entry: ChainEntry, sigPubHex: string): Promise<boolean> {
  const signature = decodeHex(entry.signatureHex);
  const publicKeyBytes = decodeHex(sigPubHex);
  if (signature === null || signature.length !== SIGNATURE_BYTES || publicKeyBytes === null) {
    return false;
  }
  try {
    const signedBytes = canonicalChainSignedBytes(entry);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes as BufferSource,
      "Ed25519",
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signature as BufferSource,
      signedBytes as BufferSource,
    );
  } catch {
    return false;
  }
}

function ownersCount(state: MutableChainState): number {
  let count = 0;
  for (const member of state.members.values()) {
    if (member.role === "owner") {
      count += 1;
    }
  }
  return count;
}

function actorContextOf(member: ChainMember, device: ChainDevice): ActorContext {
  return { userId: member.userId, device, permission: effectivePermissionOf(member, device) };
}

function indexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.add(device.encPubHex);
  state.memberSigPubs.add(device.sigPubHex);
}

function unindexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.delete(device.encPubHex);
  state.memberSigPubs.delete(device.sigPubHex);
}

function registersTakenKey(
  state: MutableChainState,
  keys: { readonly encPubHex: string; readonly sigPubHex: string },
): boolean {
  return (
    state.memberEncPubs.has(keys.encPubHex) ||
    state.memberSigPubs.has(keys.sigPubHex) ||
    state.namedServerKeys.has(keys.encPubHex)
  );
}

function firstDeviceOf(
  keys: { readonly encPubHex: string; readonly sigPubHex: string },
  keyFingerprintHex: KeyFingerprintHex,
  addedSeq: number,
): ChainDevice {
  return {
    ...FIRST_DEVICE_CAP,
    encPubHex: keys.encPubHex,
    sigPubHex: keys.sigPubHex,
    keyFingerprintHex,
    addedSeq,
  };
}

function permissionChangeEnvironments(
  operation: Extract<ProposableOperation, { op: "add_member" | "change_role" | "remove_member" }>,
  target: ChainMember | undefined,
): EnvironmentSet {
  const current = scopeAsEnvironmentSet(target?.scope ?? ALL_SCOPE);
  if (operation.op === "remove_member") {
    return current;
  }
  const next = scopeAsEnvironmentSet(memberScopeOf(operation.payload));
  if (operation.op === "add_member") {
    return next;
  }
  return target?.role === operation.payload.newRole
    ? symmetricDifferenceEnvironmentSets(current, next)
    : unionEnvironmentSets(current, next);
}

export function isApprovalTarget(
  operation: ProposableOperation,
  policy: ApprovalPolicy | null,
): boolean {
  if (policy === null) {
    return false;
  }
  if (operation.op === "set_approval_policy" || establishesOwner(operation)) {
    return true;
  }
  return isApprovalTargetOp(operation.op) && policy.ops.includes(operation.op);
}

function establishesOwner(operation: ProposableOperation): boolean {
  return (
    (operation.op === "add_member" && operation.payload.role === "owner") ||
    (operation.op === "change_role" && operation.payload.newRole === "owner")
  );
}

export function approvalSignersOf(pending: PendingProposal): readonly ApprovalVote[] {
  const proposer: readonly ApprovalVote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

function voteDevice(state: MutableChainState, signer: ApprovalVote): ChainDevice | undefined {
  return state.members.get(signer.userId)?.devices.get(signer.keyFingerprintHex);
}

export function ownerVotersOf(
  members: ReadonlyMap<string, ChainMember>,
  signers: readonly ApprovalVote[],
): ReadonlySet<UserId> {
  const voters = new Set<UserId>();
  for (const signer of signers) {
    const member = members.get(signer.userId);
    const device = member?.devices.get(signer.keyFingerprintHex);
    if (
      member !== undefined &&
      device !== undefined &&
      effectivePermissionOf(member, device).role === "owner"
    ) {
      voters.add(signer.userId);
    }
  }
  return voters;
}

function countOwnerVotes(state: MutableChainState, signers: readonly ApprovalVote[]): number {
  return ownerVotersOf(state.members, signers).size;
}

function quorumReachableAfter(
  operation: ProposableOperation,
  state: MutableChainState,
  target: ChainMember | undefined,
): boolean {
  const required =
    operation.op === "set_approval_policy"
      ? operation.payload.requiredApprovals
      : (state.approvalPolicy?.requiredApprovals ?? 0);
  return required === 0 || ownersCount(state) - ownersRemovedBy(operation, target) >= required;
}

function ownersRemovedBy(operation: ProposableOperation, target: ChainMember | undefined): number {
  if (target?.role !== "owner") {
    return 0;
  }
  if (operation.op === "remove_member") {
    return 1;
  }
  return operation.op === "change_role" && operation.payload.newRole !== "owner" ? 1 : 0;
}

function checkpointRoleReason(
  auditHeadHashHex: string,
  actorRole: Role,
): ChainInvalidReason | null {
  if (!atLeast(actorRole, "member")) {
    return "insufficient-role";
  }
  if (auditHeadHashHex !== "" && !atLeast(actorRole, "admin")) {
    return "checkpoint-audit-role-insufficient";
  }
  return null;
}

function requireRole(actual: Role, minimum: Role): ChainInvalidReason | null {
  return atLeast(actual, minimum) ? null : "insufficient-role";
}

function addMemberRoleReason(grantedRole: Role, actorRole: Role): ChainInvalidReason | null {
  return requireRole(actorRole, atLeast(grantedRole, "admin") ? "owner" : "admin");
}

const ROLE_RULES: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    actor: ActorContext,
  ) => ChainInvalidReason | null;
} = {
  genesis: () => null,
  add_member: (operation, actor) =>
    addMemberRoleReason(operation.payload.role, actor.permission.role),
  remove_member: (_operation, actor) => requireRole(actor.permission.role, "admin"),
  change_role: (_operation, actor) => requireRole(actor.permission.role, "admin"),
  create_environment: (_operation, actor) => requireRole(actor.permission.role, "member"),
  delete_environment: (_operation, actor) => requireRole(actor.permission.role, "admin"),
  rotate_epoch: (_operation, actor) => requireRole(actor.permission.role, "member"),
  checkpoint: (operation, actor) =>
    checkpointRoleReason(operation.payload.auditHeadHashHex, actor.permission.role),
  grant_server: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  revoke_server: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  set_approval_policy: (_operation, actor) => requireRole(actor.permission.role, "owner"),
  add_device: () => null,
  revoke_device: () => null,
};

function roleReason(
  operation: ProposableOperation,
  actor: ActorContext,
): ChainInvalidReason | null {
  return ROLE_RULES[operation.op](operation as never, actor);
}

function targetRoleReason(
  operation: Extract<
    ProposableOperation,
    { op: "remove_member" | "change_role" | "revoke_device" }
  >,
  actor: ActorContext,
  target: ChainMember,
): ChainInvalidReason | null {
  if (atLeast(target.role, "admin") && actor.permission.role !== "owner") {
    return "insufficient-role";
  }
  if (
    operation.op === "change_role" &&
    atLeast(operation.payload.newRole, "admin") &&
    actor.permission.role !== "owner"
  ) {
    return "insufficient-role";
  }
  return null;
}

function isDeletedEnvironment(state: MutableChainState, environmentId: string): boolean {
  return (state.environments.get(environmentId)?.deletedAtSeq ?? null) !== null;
}

function liveEnvironmentReason(
  state: MutableChainState,
  environmentId: string,
): ChainInvalidReason | null {
  if (!state.environments.has(environmentId)) {
    return "unknown-environment";
  }
  return isDeletedEnvironment(state, environmentId) ? "environment-deleted" : null;
}

function scopeEnvironmentsReason(
  payload: { readonly scopeEnvironmentIds: readonly string[] },
  state: MutableChainState,
): ChainInvalidReason | null {
  const ids = payload.scopeEnvironmentIds;
  if (ids.some((environmentId) => !state.environments.has(environmentId))) {
    return "unknown-environment";
  }
  return ids.some((environmentId) => isDeletedEnvironment(state, environmentId))
    ? "environment-deleted"
    : null;
}

function scopeRoleReason(role: Role, scopeKind: string): ChainInvalidReason | null {
  return role === "owner" && scopeKind !== "all" ? "scope-role-mismatch" : null;
}

function memberScopeReason(
  operation: Extract<ProposableOperation, { op: "add_member" | "change_role" }>,
  establishedRole: Role,
  actor: ActorContext,
  target: ChainMember | undefined,
  state: MutableChainState,
): ChainInvalidReason | null {
  return (
    scopeEnvironmentsReason(operation.payload, state) ??
    scopeRoleReason(establishedRole, operation.payload.scopeKind) ??
    (scopeContainsEnvironmentSet(
      actor.permission.scope,
      permissionChangeEnvironments(operation, target),
    )
      ? null
      : "scope-not-contained")
  );
}

function resolveTargetedOp(
  operation: Extract<ProposableOperation, { op: "remove_member" | "change_role" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainMember | ChainInvalidReason {
  const target = state.members.get(operation.payload.targetUserId);
  if (target === undefined) {
    return "unknown-target";
  }
  const role = targetRoleReason(operation, actor, target);
  if (role !== null) {
    return role;
  }
  if (ownersRemovedBy(operation, target) === 1 && ownersCount(state) === 1) {
    return "last-owner-protected";
  }
  return target;
}

function addMemberReason(
  operation: Extract<ProposableOperation, { op: "add_member" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  if (state.members.has(p.targetUserId)) {
    return "duplicate-member";
  }
  if (registersTakenKey(state, p)) {
    return "duplicate-member-key";
  }
  return memberScopeReason(operation, p.role, actor, undefined, state);
}

function changeRoleReason(
  operation: Extract<ProposableOperation, { op: "change_role" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const target = resolveTargetedOp(operation, actor, state);
  if (typeof target === "string") {
    return target;
  }
  return (
    memberScopeReason(operation, operation.payload.newRole, actor, target, state) ??
    (quorumReachableAfter(operation, state, target) ? null : "approval-quorum-unreachable")
  );
}

function removeMemberReason(
  operation: Extract<ProposableOperation, { op: "remove_member" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const target = resolveTargetedOp(operation, actor, state);
  if (typeof target === "string") {
    return target;
  }
  if (
    !scopeContainsEnvironmentSet(
      actor.permission.scope,
      permissionChangeEnvironments(operation, target),
    )
  ) {
    return "scope-not-contained";
  }
  return quorumReachableAfter(operation, state, target) ? null : "approval-quorum-unreachable";
}

function addDeviceReason(
  operation: Extract<ProposableOperation, { op: "add_device" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  if (registersTakenKey(state, p)) {
    return "duplicate-member-key";
  }
  return (
    scopeEnvironmentsReason(p, state) ??
    (capWithinCap({ roleCap: p.roleCap, scope: memberScopeOf(p) }, actor.device)
      ? null
      : "device-cap-exceeded")
  );
}

function revokeDeviceReason(
  operation: Extract<ProposableOperation, { op: "revoke_device" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target === undefined) {
    return "unknown-target";
  }
  if (p.deviceFingerprintsHex.some((fp) => !target.devices.has(fp))) {
    return "unknown-device";
  }
  const self = target.userId === actor.userId;
  if (!self) {
    const role =
      requireRole(actor.permission.role, "admin") ?? targetRoleReason(operation, actor, target);
    if (role !== null) {
      return role;
    }
  }
  if (target.devices.size - p.deviceFingerprintsHex.length < 1) {
    return "last-device-protected";
  }
  if (
    !self &&
    !scopeContainsEnvironmentSet(actor.permission.scope, scopeAsEnvironmentSet(target.scope))
  ) {
    return "scope-not-contained";
  }
  return null;
}

async function grantServerReason(
  operation: Extract<ProposableOperation, { op: "grant_server" }>,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  const p = operation.payload;
  const encPub = decodeHex(p.serverEncPubHex) ?? new Uint8Array(0);
  const digest = await sha256(encPub);
  if (encodeHex(digest.slice(0, FINGERPRINT_BYTES)) !== p.serverKeyFingerprintHex) {
    return "invalid-payload";
  }
  if (p.scopeEnvironmentIds.some((environmentId) => isDeletedEnvironment(state, environmentId))) {
    return "environment-deleted";
  }
  const existing = state.serverGrants.get(p.serverKeyFingerprintHex);
  if (existing !== undefined) {
    const newScope = new Set(p.scopeEnvironmentIds);
    if (existing.scopeEnvironmentIds.some((id) => !newScope.has(id))) {
      return "grant-scope-narrowed";
    }
  }
  return state.memberEncPubs.has(p.serverEncPubHex) ? "duplicate-server-key" : null;
}

function createEnvironmentReason(
  operation: Extract<ProposableOperation, { op: "create_environment" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  if (state.environments.has(operation.payload.environmentId)) {
    return "duplicate-environment";
  }
  return scopeIncludesEnvironment(actor.permission.scope, operation.payload.environmentId)
    ? null
    : "environment-out-of-scope";
}

function rotateEpochReason(
  operation: Extract<ProposableOperation, { op: "rotate_epoch" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  const environment = state.environments.get(p.environmentId);
  if (environment === undefined) {
    return "unknown-environment";
  }
  if (environment.deletedAtSeq !== null) {
    return "environment-deleted";
  }
  if (!scopeIncludesEnvironment(actor.permission.scope, p.environmentId)) {
    return "environment-out-of-scope";
  }
  return p.newEpoch === environment.currentEpoch + 1 ? null : "epoch-out-of-sequence";
}

function deleteEnvironmentReason(
  operation: Extract<ProposableOperation, { op: "delete_environment" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const environmentId = operation.payload.environmentId;
  return (
    liveEnvironmentReason(state, environmentId) ??
    (scopeIncludesEnvironment(actor.permission.scope, environmentId)
      ? null
      : "environment-out-of-scope")
  );
}

function checkpointReason(
  environments: readonly CheckpointEnvironmentEntry[],
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const stage = (
    rejected: (tuple: CheckpointEnvironmentEntry) => boolean,
    reason: ChainInvalidReason,
  ): ChainInvalidReason | null => (environments.some(rejected) ? reason : null);
  return (
    stage((tuple) => !state.environments.has(tuple.environmentId), "unknown-environment") ??
    stage((tuple) => isDeletedEnvironment(state, tuple.environmentId), "environment-deleted") ??
    stage(
      (tuple) => !scopeIncludesEnvironment(actor.permission.scope, tuple.environmentId),
      "environment-out-of-scope",
    ) ??
    stage(
      (tuple) => state.environments.get(tuple.environmentId)?.currentEpoch !== tuple.epoch,
      "checkpoint-epoch-mismatch",
    ) ??
    stage((tuple) => {
      const prior = state.checkpoints.get(tuple.environmentId);
      return prior !== undefined && tuple.manifestVersion < prior.manifestVersion;
    }, "checkpoint-regression")
  );
}

const CONSENSUS_RULES: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    actor: ActorContext,
    state: MutableChainState,
  ) => ChainInvalidReason | null | Promise<ChainInvalidReason | null>;
} = {
  genesis: () => null,
  add_member: addMemberReason,
  change_role: changeRoleReason,
  remove_member: removeMemberReason,
  grant_server: (operation, _actor, state) => grantServerReason(operation, state),
  revoke_server: (operation, _actor, state) =>
    state.serverGrants.has(operation.payload.serverKeyFingerprintHex)
      ? null
      : "unknown-server-grant",
  create_environment: createEnvironmentReason,
  delete_environment: deleteEnvironmentReason,
  rotate_epoch: rotateEpochReason,
  checkpoint: (operation, actor, state) =>
    checkpointReason(operation.payload.environments, actor, state),
  set_approval_policy: (operation, _actor, state) =>
    quorumReachableAfter(operation, state, undefined) ? null : "approval-quorum-unreachable",
  add_device: addDeviceReason,
  revoke_device: revokeDeviceReason,
};

async function consensusReason(
  operation: ProposableOperation,
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  return CONSENSUS_RULES[operation.op](operation as never, actor, state);
}

const INITIAL_EPOCH = 1;

function applyGenesis(
  entry: ChainEntry & { readonly op: "genesis" },
  state: MutableChainState,
): void {
  const device = firstDeviceOf(entry.payload, entry.actor.keyFingerprintHex, entry.seq);
  state.members.set(entry.actor.userId, {
    userId: entry.actor.userId,
    role: "owner",
    scope: ALL_SCOPE,
    devices: new Map([[device.keyFingerprintHex, device]]),
  });
  indexDeviceKeys(state, device);
}

async function applyAddMember(
  operation: Extract<ProposableOperation, { op: "add_member" }>,
  state: MutableChainState,
  seq: number,
): Promise<void> {
  const p = operation.payload;
  const device = firstDeviceOf(p, await userFingerprintHex(p.encPubHex, p.sigPubHex), seq);
  state.members.set(p.targetUserId, {
    userId: p.targetUserId,
    role: p.role,
    scope: memberScopeOf(p),
    devices: new Map([[device.keyFingerprintHex, device]]),
  });
  indexDeviceKeys(state, device);
}

async function applyAddDevice(
  operation: Extract<ProposableOperation, { op: "add_device" }>,
  state: MutableChainState,
  seq: number,
  actorUserId: string,
): Promise<void> {
  const p = operation.payload;
  const member = state.members.get(actorUserId);
  if (member === undefined) {
    return;
  }
  const device: ChainDevice = {
    keyFingerprintHex: await userFingerprintHex(p.encPubHex, p.sigPubHex),
    encPubHex: p.encPubHex,
    sigPubHex: p.sigPubHex,
    roleCap: p.roleCap,
    scope: memberScopeOf(p),
    addedSeq: seq,
  };
  state.members.set(member.userId, {
    ...member,
    devices: new Map([...member.devices, [device.keyFingerprintHex, device]]),
  });
  indexDeviceKeys(state, device);
}

function applyRevokeDevice(
  operation: Extract<ProposableOperation, { op: "revoke_device" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target === undefined) {
    return;
  }
  const devices = new Map(target.devices);
  for (const fp of p.deviceFingerprintsHex) {
    const device = devices.get(fp);
    if (device !== undefined) {
      devices.delete(fp);
      unindexDeviceKeys(state, device);
    }
  }
  state.members.set(target.userId, { ...target, devices });
}

function applyChangeRole(
  operation: Extract<ProposableOperation, { op: "change_role" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  const target = state.members.get(p.targetUserId);
  if (target !== undefined) {
    state.members.set(target.userId, { ...target, role: p.newRole, scope: memberScopeOf(p) });
  }
}

function applyRemoveMember(
  operation: Extract<ProposableOperation, { op: "remove_member" }>,
  state: MutableChainState,
): void {
  const target = state.members.get(operation.payload.targetUserId);
  if (target !== undefined) {
    state.members.delete(target.userId);
    for (const device of target.devices.values()) {
      unindexDeviceKeys(state, device);
    }
  }
}

function applyGrantServer(
  operation: Extract<ProposableOperation, { op: "grant_server" }>,
  state: MutableChainState,
  seq: number,
): void {
  const p = operation.payload;
  state.namedServerKeys.set(p.serverEncPubHex, p.serverKeyFingerprintHex);
  state.serverGrants.set(p.serverKeyFingerprintHex, {
    serverKeyFingerprintHex: p.serverKeyFingerprintHex,
    serverEncPubHex: p.serverEncPubHex,
    grantSeq: seq,
    scopeEnvironmentIds: [...p.scopeEnvironmentIds],
    leasePolicy: p.leasePolicy.map((element) => ({
      issuerUrl: element.issuerUrl,
      audience: element.audience,
      claimConstraints: element.claimConstraints.map((constraint) => ({ ...constraint })),
    })),
  });
}

function applyCreateEnvironment(
  operation: Extract<ProposableOperation, { op: "create_environment" }>,
  state: MutableChainState,
  seq: number,
): void {
  state.environments.set(operation.payload.environmentId, {
    currentEpoch: INITIAL_EPOCH,
    createdAtSeq: seq,
    deletedAtSeq: null,
    epochStartSeqs: new Map([[INITIAL_EPOCH, seq]]),
    dekCommitments: new Map([[INITIAL_EPOCH, operation.payload.dekCommitmentHex]]),
  });
}

function applyDeleteEnvironment(
  operation: Extract<ProposableOperation, { op: "delete_environment" }>,
  state: MutableChainState,
  seq: number,
): void {
  const environmentId = operation.payload.environmentId;
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    return;
  }
  environment.deletedAtSeq = seq;
  for (const member of state.members.values()) {
    const devices = new Map<string, ChainDevice>();
    for (const [fingerprintHex, device] of member.devices) {
      devices.set(fingerprintHex, { ...device, scope: scopeWithout(device.scope, environmentId) });
    }
    state.members.set(member.userId, {
      ...member,
      scope: scopeWithout(member.scope, environmentId),
      devices,
    });
  }
  for (const grant of state.serverGrants.values()) {
    state.serverGrants.set(grant.serverKeyFingerprintHex, {
      ...grant,
      scopeEnvironmentIds: grant.scopeEnvironmentIds.filter((id) => id !== environmentId),
    });
  }
  state.checkpoints.delete(environmentId);
}

function applyRotateEpoch(
  operation: Extract<ProposableOperation, { op: "rotate_epoch" }>,
  state: MutableChainState,
  seq: number,
): void {
  const p = operation.payload;
  const environment = state.environments.get(p.environmentId);
  if (environment !== undefined) {
    environment.currentEpoch = p.newEpoch;
    environment.epochStartSeqs.set(p.newEpoch, seq);
    environment.dekCommitments.set(p.newEpoch, p.dekCommitmentHex);
  }
}

function applyCheckpoint(
  operation: Extract<ProposableOperation, { op: "checkpoint" }>,
  state: MutableChainState,
  seq: number,
): void {
  for (const tuple of operation.payload.environments) {
    state.checkpoints.set(tuple.environmentId, {
      seq,
      epoch: tuple.epoch,
      manifestVersion: tuple.manifestVersion,
      manifestSigHashHex: tuple.manifestSigHashHex,
      valuesDigestHex: tuple.valuesDigestHex,
    });
  }
}

function applySetApprovalPolicy(
  operation: Extract<ProposableOperation, { op: "set_approval_policy" }>,
  state: MutableChainState,
): void {
  const p = operation.payload;
  state.approvalPolicy =
    p.requiredApprovals === 0
      ? null
      : { ops: [...new Set(p.ops)], requiredApprovals: p.requiredApprovals };
}

const OPERATION_APPLIERS: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    state: MutableChainState,
    seq: number,
    actorUserId: string,
  ) => void | Promise<void>;
} = {
  genesis: () => undefined,
  add_member: applyAddMember,
  change_role: applyChangeRole,
  remove_member: applyRemoveMember,
  grant_server: applyGrantServer,
  revoke_server: (operation, state) => {
    state.serverGrants.delete(operation.payload.serverKeyFingerprintHex);
  },
  create_environment: applyCreateEnvironment,
  delete_environment: applyDeleteEnvironment,
  rotate_epoch: applyRotateEpoch,
  checkpoint: applyCheckpoint,
  set_approval_policy: applySetApprovalPolicy,
  add_device: applyAddDevice,
  revoke_device: applyRevokeDevice,
};

async function applyOperation(
  operation: ProposableOperation,
  state: MutableChainState,
  seq: number,
  actorUserId: string,
): Promise<void> {
  await OPERATION_APPLIERS[operation.op](operation as never, state, seq, actorUserId);
}

async function evaluateDirect(
  operation: ProposableOperation,
  actor: ActorContext,
  state: MutableChainState,
  seq: number,
): Promise<ChainInvalidReason | AppliedOperation> {
  const role = roleReason(operation, actor);
  if (role !== null) {
    return role;
  }
  if (isApprovalTarget(operation, state.approvalPolicy)) {
    return "approval-required";
  }
  const reason = await consensusReason(operation, actor, state);
  if (reason !== null) {
    return reason;
  }
  await applyOperation(operation, state, seq, actor.userId);
  return { operation, actorUserId: actor.userId };
}

async function evaluatePropose(
  entry: ChainEntry & { readonly op: "propose" },
  entryHashHex: string,
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  const inner = entry.payload.inner;
  const role = roleReason(inner, actor);
  if (role !== null) {
    return role;
  }
  if (!isApprovalTarget(inner, state.approvalPolicy)) {
    return "approval-not-required";
  }
  const reason = await consensusReason(inner, actor, state);
  if (reason !== null) {
    return reason;
  }
  state.pendingProposals.set(entryHashHex, {
    proposalSeq: entry.seq,
    proposalHashHex: entryHashHex,
    proposerUserId: actor.userId,
    proposerKeyFingerprintHex: actor.device.keyFingerprintHex,
    proposerRoleAtProposal: actor.permission.role,
    inner,
    expiresAtMs: entry.payload.expiresAtMs,
    approvals: [],
  });
  return null;
}

async function evaluateApprove(
  entry: ChainEntry & { readonly op: "approve" },
  actor: ActorContext,
  state: MutableChainState,
): Promise<ChainInvalidReason | AppliedOperation | null> {
  if (actor.permission.role !== "owner") {
    return "insufficient-role";
  }
  const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
  if (pending === undefined) {
    return "unknown-proposal";
  }
  const reason = approveVoteReason(entry, actor, pending, state);
  if (reason !== null) {
    return reason;
  }
  const signature: ApprovalVote = {
    userId: actor.userId,
    keyFingerprintHex: actor.device.keyFingerprintHex,
  };
  const required = state.approvalPolicy?.requiredApprovals ?? Number.POSITIVE_INFINITY;
  if (countOwnerVotes(state, [...approvalSignersOf(pending), signature]) < required) {
    pending.approvals.push(signature);
    return null;
  }
  return completeProposal(pending, state, entry.seq);
}

function approveVoteReason(
  entry: ChainEntry & { readonly op: "approve" },
  actor: ActorContext,
  pending: MutablePendingProposal,
  state: MutableChainState,
): ChainInvalidReason | null {
  const live = approvalSignersOf(pending).some(
    (signer) => signer.userId === actor.userId && voteDevice(state, signer) !== undefined,
  );
  if (live) {
    return "duplicate-approval";
  }
  if (!isApprovalTarget(pending.inner, state.approvalPolicy)) {
    return "approval-not-required";
  }
  return entry.timestampMs > pending.expiresAtMs ? "proposal-expired" : null;
}

async function completeProposal(
  pending: MutablePendingProposal,
  state: MutableChainState,
  seq: number,
): Promise<ChainInvalidReason | AppliedOperation> {
  const proposer = state.members.get(pending.proposerUserId);
  const device = proposer?.devices.get(pending.proposerKeyFingerprintHex);
  if (proposer === undefined || device === undefined) {
    return "proposal-void";
  }
  const actor = actorContextOf(proposer, device);
  if (roleReason(pending.inner, actor) !== null) {
    return "proposal-void";
  }
  const reason = await consensusReason(pending.inner, actor, state);
  if (reason !== null) {
    return reason;
  }
  await applyOperation(pending.inner, state, seq, proposer.userId);
  state.pendingProposals.delete(pending.proposalHashHex);
  return { operation: pending.inner, actorUserId: proposer.userId };
}

function evaluateWithdraw(
  entry: ChainEntry & { readonly op: "withdraw" },
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
  if (actor.permission.role !== "owner" && pending?.proposerUserId !== actor.userId) {
    return "insufficient-role";
  }
  if (pending === undefined) {
    return "unknown-proposal";
  }
  state.pendingProposals.delete(pending.proposalHashHex);
  return null;
}

async function evaluateEntry(
  entry: ChainEntry,
  entryHashHex: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | AppliedOperation | null> {
  if (entry.op === "genesis") {
    applyGenesis(entry, state);
    return { operation: entry, actorUserId: entry.actor.userId };
  }
  const member = state.members.get(entry.actor.userId);
  if (member === undefined) {
    return "actor-not-member";
  }
  const device = member.devices.get(entry.actor.keyFingerprintHex);
  if (device === undefined) {
    return "actor-key-mismatch";
  }
  const actor = actorContextOf(member, device);
  switch (entry.op) {
    case "propose":
      return evaluatePropose(entry, entryHashHex, actor, state);
    case "approve":
      return evaluateApprove(entry, actor, state);
    case "withdraw":
      return evaluateWithdraw(entry, actor, state);
    default:
      return evaluateDirect(entry, actor, state, entry.seq);
  }
}

function recordTenureStartOf(
  history: ChainHistoryBuilder,
  state: MutableChainState,
  userId: string,
  seq: number,
): void {
  const member = state.members.get(userId);
  const device = member === undefined ? undefined : soleDeviceOf(member);
  if (member !== undefined && device !== undefined) {
    history.recordTenureStart(userId, seq, device, member.role, member.scope);
  }
}

function recordDeviceAddedOf(
  history: ChainHistoryBuilder,
  state: MutableChainState,
  actorUserId: string,
  encPubHex: string,
): void {
  for (const device of state.members.get(actorUserId)?.devices.values() ?? []) {
    if (device.encPubHex === encPubHex) {
      history.recordDeviceAdded(actorUserId, device);
      return;
    }
  }
}

const HISTORY_RECORDERS: {
  readonly [K in ProposableOperation["op"]]: (
    history: ChainHistoryBuilder,
    operation: Extract<ProposableOperation, { op: K }>,
    seq: number,
    state: MutableChainState,
    actorUserId: string,
  ) => void;
} = {
  genesis: (history: ChainHistoryBuilder, _operation, seq, state, actorUserId) =>
    recordTenureStartOf(history, state, actorUserId, seq),
  add_member: (history: ChainHistoryBuilder, operation, seq, state) =>
    recordTenureStartOf(history, state, operation.payload.targetUserId, seq),
  change_role: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordRoleChange(
      operation.payload.targetUserId,
      seq,
      operation.payload.newRole,
      memberScopeOf(operation.payload),
    ),
  remove_member: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordTenureEnd(operation.payload.targetUserId, seq),
  create_environment: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordEnvironmentCreated(operation.payload.environmentId, seq),
  delete_environment: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordEnvironmentDeleted(operation.payload.environmentId, seq),
  rotate_epoch: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordEpochRotated(operation.payload.environmentId, operation.payload.newEpoch, seq),
  checkpoint: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordCheckpoint(seq, operation.payload.environments),
  grant_server: () => undefined,
  revoke_server: () => undefined,
  set_approval_policy: () => undefined,
  add_device: (history: ChainHistoryBuilder, operation, _seq, state, actorUserId) =>
    recordDeviceAddedOf(history, state, actorUserId, operation.payload.encPubHex),
  revoke_device: (history: ChainHistoryBuilder, operation, seq) =>
    history.recordDevicesRevoked(
      operation.payload.targetUserId,
      seq,
      operation.payload.deviceFingerprintsHex,
    ),
};

function recordHistory(
  history: ChainHistoryBuilder,
  applied: AppliedOperation,
  seq: number,
  state: MutableChainState,
): void {
  HISTORY_RECORDERS[applied.operation.op](
    history,
    applied.operation as never,
    seq,
    state,
    applied.actorUserId,
  );
}

async function checkEntryBeforeApply(
  entry: ChainEntry,
  seq: number,
  prevHash: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  if (!isRecord(entry)) {
    return "invalid-payload";
  }
  const framing = checkFraming(entry, seq, prevHash);
  if (framing !== null) {
    return framing;
  }
  const shape = checkPayloadShape(entry);
  if (shape !== null) {
    return shape;
  }
  const actor = await resolveActorSigPub(entry, state);
  if ("reason" in actor) {
    return actor.reason;
  }
  if (!(await verifyEntrySignature(entry, actor.sigPubHex))) {
    return "bad-signature";
  }
  return null;
}

function freezePendingProposals(
  pending: ReadonlyMap<string, MutablePendingProposal>,
): ReadonlyMap<string, PendingProposal> {
  const frozen = new Map<string, PendingProposal>();
  for (const [hash, proposal] of pending) {
    frozen.set(hash, { ...proposal, approvals: proposal.approvals.map((vote) => ({ ...vote })) });
  }
  return frozen;
}

function sealChainState(
  state: MutableChainState,
  headSeq: number,
  headHashHex: string,
): ChainState {
  const members = new Map<UserId, ChainMember>();
  for (const [userId, member] of state.members) {
    members.set(userId as UserId, member);
  }
  const serverGrants = new Map<KeyFingerprintHex, ServerGrant>();
  for (const [fingerprint, grant] of state.serverGrants) {
    serverGrants.set(fingerprint as KeyFingerprintHex, grant);
  }
  const environments = new Map<EnvironmentId, EnvironmentChainState>();
  for (const [environmentId, environment] of state.environments) {
    environments.set(environmentId as EnvironmentId, environment);
  }
  const checkpoints = new Map<EnvironmentId, EnvironmentCheckpointState>();
  for (const [environmentId, checkpoint] of state.checkpoints) {
    checkpoints.set(environmentId as EnvironmentId, checkpoint);
  }
  return {
    members,
    serverGrants,
    environments,
    checkpoints,
    approvalPolicy: state.approvalPolicy,
    pendingProposals: freezePendingProposals(state.pendingProposals),
    namedServerKeys: new Map(state.namedServerKeys),
    headSeq,
    headHashHex,
  };
}

async function verifyChainCore(
  entries: readonly ChainEntry[],
  history: ChainHistoryBuilder | null,
): Promise<CryptoResult<ChainState>> {
  if (entries.length === 0) {
    return { ok: false, error: { kind: "ChainInvalid", seq: 0, reason: "empty-chain" } };
  }
  const state: MutableChainState = {
    members: new Map(),
    serverGrants: new Map(),
    environments: new Map(),
    checkpoints: new Map(),
    memberEncPubs: new Set(),
    memberSigPubs: new Set(),
    namedServerKeys: new Map(),
    approvalPolicy: null,
    pendingProposals: new Map(),
  };
  let prevHash = GENESIS_PREV_HASH;
  let seq = 0;
  const fail = (reason: ChainInvalidReason) =>
    ({ ok: false, error: { kind: "ChainInvalid", seq, reason } }) as const;

  for (const [index, entry] of entries.entries()) {
    seq = index + 1;
    const rejected = await checkEntryBeforeApply(entry, seq, prevHash, state);
    if (rejected !== null) {
      return fail(rejected);
    }
    const entryHashHex = await computeChainEntryHash(entry);
    const evaluated = await evaluateEntry(entry, entryHashHex, state);
    if (typeof evaluated === "string") {
      return fail(evaluated);
    }
    if (history !== null && evaluated !== null) {
      recordHistory(history, evaluated, seq, state);
    }
    prevHash = entryHashHex;
    history?.recordEntryHash(prevHash);
  }

  return { ok: true, value: sealChainState(state, entries.length, prevHash) };
}

export async function verifyChain(
  entries: readonly ChainEntry[],
): Promise<CryptoResult<ChainState>> {
  return verifyChainCore(entries, null);
}

export async function verifyChainWithHistory(
  entries: readonly ChainEntry[],
): Promise<CryptoResult<{ readonly state: ChainState; readonly history: ChainHistoryIndex }>> {
  const builder = new ChainHistoryBuilder();
  const result = await verifyChainCore(entries, builder);
  if (!result.ok) {
    return result;
  }
  return { ok: true, value: { state: result.value, history: builder.build() } };
}
