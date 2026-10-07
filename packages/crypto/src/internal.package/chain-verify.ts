// CRYPTO_SPEC §6.3: client verification — verify prev_hash continuity,
// Ed25519 signatures, and the §6.2 role / scope / four-eyes rules on every
// entry, and derive from the verified chain the current member set (with
// role + scope), the active grant_server set, observed epochs, and the
// four-eyes policy and pending proposals.
//
// Verification order (corresponds to the expected_reason of the
// authorization test vectors):
//   1. Framing (suite / seq / genesis position / prev_hash)
//   2. Payload structure check (hex length, role value, numeric ranges,
//      scope structure, inner op shape)
//      → invalid-payload
//   3. Actor resolution (is the actor a current member / does the declared
//      FP match a registered key)
//      → actor-not-member / actor-key-mismatch
//   4. Signature verification (actor's registered sig public key) → bad-signature
//   5. Authorization + state transition (role rules → four-eyes → target
//      existence, last-owner protection, scope …)
//
// 2026-09-14 ES + PF1: the authorization stage is split into three phases —
// "role rules / consensus rules / apply" — and direct append, propose
// (pre-check of the inner op), and approve (apply on reaching quorum) share
// the same phase functions. Principle 1 (containment of the environment set
// whose permissions change) and principle 2 (the owner vote count of the
// signer set S) are each expressed by a single derivation function
// (permissionChangeEnvironments / countOwnerVotes), not a per-op if-list.
//
// 2026-09-19 DK (device keys — §6.2 "device keys"): members hold a set of
// device keys, and actor resolution picks a device by (user_id, FP). The
// authorization subject ActorContext carries the **effective permission of
// the signing device** (effectivePermissionOf — chain-device.ts); the role
// rules, principle 1, environment-targeting ops, and the four-eyes votes are
// all judged against it (the person's (role, scope) is never used directly).

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
  type EnvironmentCheckpointState,
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
  symmetricDifferenceEnvironmentSets,
  unionEnvironmentSets,
} from "./member-scope.ts";
import { SUITE_ID } from "./suite.ts";

const GENESIS_PREV_HASH = "0".repeat(64);
const ROLES: readonly Role[] = ["owner", "admin", "member", "reader"];
const FINGERPRINT_BYTES = 16;
const SIGNATURE_BYTES = 64;
const SHA256_BYTES = 32;
// Field size limit (CRYPTO_SPEC §6.1): a consensus rule of chain validity.
// Guards the verifying client against resource consumption (availability)
// via oversized payloads
const MAX_FIELD_BYTES = 1024;
// lease_policy limits (CRYPTO_SPEC §6.2): 8 elements, 8 claim constraints
// per element (each string bounded by MAX_FIELD_BYTES). A consensus rule
// chosen so the normalized size of a spec-conformant grant_server entry
// stays mathematically below the §6.4 acceptance-policy limit
const MAX_LEASE_POLICY_ISSUERS = 8;
const MAX_LEASE_CLAIM_CONSTRAINTS = 8;
// Required approvals for four-eyes (§6.2): 0 = off, otherwise 2 or more
const MIN_ACTIVE_REQUIRED_APPROVALS = 2;
// FP list limit for revoke_device (§6.2 — at least 1 element, at most 256, no duplicates)
const MAX_REVOKE_DEVICE_FINGERPRINTS = 256;

interface MutableEnvironmentState {
  currentEpoch: number;
  readonly createdAtSeq: number;
  readonly epochStartSeqs: Map<number, number>;
  readonly dekCommitments: Map<number, string>;
}

/** Pending proposal (the §6.2 verification state). approvals holds the accepted approve signatures (user_id, key FP), ordered. */
interface MutablePendingProposal {
  readonly proposalSeq: number;
  readonly proposalHashHex: string;
  readonly proposerUserId: UserId;
  readonly proposerKeyFingerprintHex: string;
  readonly proposerRoleAtProposal: Role;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: ApprovalVote[];
}

interface MutableChainState {
  readonly members: Map<string, ChainMember>;
  readonly serverGrants: Map<string, ServerGrant>;
  // Environment set (derived from §6.2 create_environment). The chain never
  // observes an environment deletion (deletion is a data-plane operation),
  // so this map is itself "every ID used across history" and the
  // duplicate-environment check needs no extra index
  readonly environments: Map<string, MutableEnvironmentState>;
  // Latest checkpoint tuple per environment (derived state of §6.2
  // checkpoint — the comparison target for checkpoint-regression and the
  // basis for §6.3 checkpoint consistency)
  readonly checkpoints: Map<string, EnvironmentCheckpointState>;
  // Index of the enc / sig public keys of **every device key** in the
  // current member set (member-key uniqueness — §6.2; extended to device
  // sets by 2026-09-19 DK). Since the rule itself makes "each key belongs to
  // at most one device" an invariant, the Set deletions in remove_member /
  // revoke_device never erase another device's keys (sound).
  // The hex values are normalized by the §6.1 shape check (decodeHex =
  // lowercase only), so string equality = byte equality
  readonly memberEncPubs: Set<string>;
  readonly memberSigPubs: Set<string>;
  // Four-eyes (§6.2): the current policy (null = off) and pending proposals
  // (proposal entry hash → proposal)
  approvalPolicy: ApprovalPolicy | null;
  readonly pendingProposals: Map<string, MutablePendingProposal>;
}

/**
 * The authorization subject (the actor of a direct append, or the proposer
 * at proposal-apply time): the person (user_id), the signing device, and
 * that device's effective permission (§6.2 — the person's (role, scope)
 * lives on ChainMember, but only the branded EffectivePermission is passed
 * to the checks).
 */
interface ActorContext {
  readonly userId: UserId;
  readonly device: ChainDevice;
  readonly permission: EffectivePermission;
}

/** An applied op (to be recorded in the history index) and its attributed subject. */
interface AppliedOperation {
  readonly operation: ProposableOperation;
  readonly actorUserId: string;
}

// Each shape-check predicate takes an `unknown` and inspects the runtime
// type, so it never throws even when the actual runtime input (a cast of
// server-distributed JSON) diverges from what the TS types claim (malicious
// chain data always lands on invalid-payload — verification is never
// aborted by a throw)

function withinFieldBytes(value: string): boolean {
  // UTF-8 byte count >= code-unit count, so the cheap `length` rejects
  // first and only the remaining candidates are confirmed by a real encode
  // (avoids allocating huge strings)
  return value.length <= MAX_FIELD_BYTES && utf8Encode(value).length <= MAX_FIELD_BYTES;
}

/** Free-form string field (IDs, reason, …) that is non-empty and at most MAX_FIELD_BYTES in UTF-8 */
function isBoundedId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && withinFieldBytes(value);
}

function isHexOfLength(value: unknown, bytes: number): boolean {
  // Strings of the wrong length are rejected in O(1) before decodeHex
  // (regex scan + allocation) runs — fail-fast against CPU/memory burn on
  // huge hex strings
  if (typeof value !== "string" || value.length !== bytes * 2) {
    return false;
  }
  const decoded = decodeHex(value);
  return decoded !== null && decoded.length === bytes;
}

function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

function isApprovalTargetOp(value: unknown): value is ApprovalTargetOp {
  return typeof value === "string" && (APPROVAL_TARGET_OPS as readonly string[]).includes(value);
}

function atLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

async function userFingerprintHex(encPubHex: string, sigPubHex: string): Promise<string> {
  // Hex shape already verified before the call (32B each). FP = SHA-256(enc || sig)[:16]
  const enc = decodeHex(encPubHex) ?? new Uint8Array(0);
  const sig = decodeHex(sigPubHex) ?? new Uint8Array(0);
  const digest = await sha256(concatBytes(enc, sig));
  return encodeHex(digest.slice(0, FINGERPRINT_BYTES));
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
  // actor FP (16B) and signature (64B) are fixed-length hex per §6.1. The
  // exact-length check fails fast so huge hex strings never reach decodeHex
  // or normalization
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

/** The two scope fields (the §6.2 structure rule — precedes authorization). */
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
  // dek_commitment_hex is lowercase hex, 64 chars (a §6.2 consensus rule;
  // the format check belongs to the payload-structure stage, before
  // authorization)
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

/**
 * Shape of one lease_policy constraint (§6.2). claim_name is an identifier
 * (non-empty); claim_value is a data position (may be the empty string,
 * like rotate_epoch's reason — an OIDC claim value can be empty). Both are
 * subject to the §6.1 1024-byte limit
 */
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
    // lease_policy (§6.2): only structure is a consensus rule (evaluation
    // semantics are AUTH_SPEC §14). A missing leasePolicy lands on
    // invalid-payload here
    Array.isArray(p.leasePolicy) &&
    p.leasePolicy.length <= MAX_LEASE_POLICY_ISSUERS &&
    p.leasePolicy.every((element) => shapeLeasePolicyIssuer(element))
  );
}

/**
 * Structure check of a checkpoint payload (§6.2). Besides hex lengths and
 * numeric ranges, **rejecting duplicate environment_ids** also belongs to
 * the structure stage (the spec's "payload structure check" — allowing two
 * entries for the same environment would make the §6.3 basis and the
 * checkpoint-regression comparison target nondeterministic). No consensus
 * limit on the number of environment entries (§6.2 — size is bounded by
 * the server acceptance policy [§6.4's 1 MiB])
 */
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
  // audit_head_hash is either the empty string (no notarization) or lowercase hex, 64 chars
  return p.auditHeadHashHex === "" || isHexOfLength(p.auditHeadHashHex, SHA256_BYTES);
}

/**
 * Structure of set_approval_policy (§6.2): ops may only contain elements
 * of the closed set of targetable ops (duplicates are treated as a set,
 * like grant_server's scope — not rejected at the structure stage);
 * required_approvals is 0 (off) or a safe integer >= 2
 */
function shapeSetApprovalPolicy(p: { ops: unknown; requiredApprovals: unknown }): boolean {
  return (
    Array.isArray(p.ops) &&
    p.ops.every((op) => isApprovalTargetOp(op)) &&
    Number.isSafeInteger(p.requiredApprovals) &&
    ((p.requiredApprovals as number) === 0 ||
      (p.requiredApprovals as number) >= MIN_ACTIVE_REQUIRED_APPROVALS)
  );
}

/**
 * Structure of propose (§6.2): the inner op is a known op other than
 * propose / approve / withdraw, and the inner payload satisfies that op's
 * shape table (nesting is one level — a proposal cannot nest, since nested
 * proposals are never a policy target, so it is rejected at the structure
 * stage and there is no recursive shape check). expires_at_ms is a
 * non-negative safe integer
 */
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

/**
 * Structure of add_device (§6.2 — 2026-09-19 DK): public keys are
 * lowercase hex, 64 chars; role_cap is a value of the role table; the two
 * scope fields follow the same structure rule as environment scope (`all`
 * ⇒ empty list, at most 256, no duplicates; an empty `listed` list is
 * valid)
 */
function shapeAddDevice(p: {
  encPubHex: unknown;
  sigPubHex: unknown;
  roleCap: unknown;
  scopeKind: unknown;
  scopeEnvironmentIds: unknown;
}): boolean {
  return shapeGenesis(p) && isRole(p.roleCap) && shapeScope(p);
}

/**
 * Structure of revoke_device (§6.2 — 2026-09-19 DK): target user_id plus a
 * list of FPs (lowercase hex, 32 chars; at least 1 element, at most 256,
 * no duplicates. Order is signed over, but verification treats it as a
 * set)
 */
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

// Per-op payload shape predicates (the §6.1 / §6.2 structure checks).
// Table lookup instead of branching, so the type (an exhaustive Record)
// prevents a missed check when an op is added
const PAYLOAD_SHAPES: {
  readonly [K in ChainEntry["op"]]: (payload: Extract<ChainEntry, { op: K }>["payload"]) => boolean;
} = {
  genesis: shapeGenesis,
  add_member: shapeAddMember,
  remove_member: (p) => isBoundedId(p.targetUserId),
  change_role: shapeChangeRole,
  create_environment: shapeCreateEnvironment,
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
  // Unknown ops are rejected by membership **before** the table lookup:
  // the TS type claims op is exhaustive, but the input is a cast of
  // server-distributed JSON and may diverge. Calling PAYLOAD_SHAPES[op]
  // unchecked would throw a TypeError, violating the public verifier's
  // contract of "malformed input returns invalid-payload, never throws".
  // Object.hasOwn correctly rejects prototype-derived names like
  // "__proto__" / "toString" as not own properties
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

/** Resolves the actor's registered sig public key (hex). genesis is self-describing via its payload */
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
  // The declared FP picks a currently-valid device (§6.2 — revoked devices and unregistered keys are actor-key-mismatch)
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
    // Normalization must happen inside this try (do not hoist it out in a
    // refactor): exceptions the encoder throws on oversized fields etc. are
    // confined here to bad-signature, preserving verifyChain's "never throw
    // on untrusted input" contract. The computeChainEntryHash in the loop
    // is reached only after the same fields encoded successfully here
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

/** A subject carrying the signing device's effective permission (§6.2 — effectivePermissionOf is the single computation point). */
function actorContextOf(member: ChainMember, device: ChainDevice): ActorContext {
  return { userId: member.userId, device, permission: effectivePermissionOf(member, device) };
}

/** Adds/removes a device's keys on the index of every device key in the current member set (member-key uniqueness — §6.2). */
function indexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.add(device.encPubHex);
  state.memberSigPubs.add(device.sigPubHex);
}

function unindexDeviceKeys(state: MutableChainState, device: ChainDevice): void {
  state.memberEncPubs.delete(device.encPubHex);
  state.memberSigPubs.delete(device.sigPubHex);
}

/** The first device key (genesis / add_member — cap is structurally (owner, all)). */
function firstDeviceOf(
  keys: { readonly encPubHex: string; readonly sigPubHex: string },
  keyFingerprintHex: string,
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

// ---------------------------------------------------------------------------
// Derivation functions for principle 1 / principle 2

/**
 * Principle 1 (§6.2): the environment set whose permissions an op
 * changes. Derived from the role table, not an enumeration — add_member =
 * the new scope; change_role = old ∪ new if the role changes, the
 * symmetric difference if only the scope changes; remove_member = the
 * current scope. `all` is treated as U (includes future environments) —
 * the set algebra lives in member-scope.ts. The caller has already
 * confirmed the target exists (absence fails earlier on unknown-target —
 * treated here as U, fail-closed)
 */
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

/**
 * Four-eyes target determination (§6.2 — a single predicate shared by
 * propose / approve / direct-append rejection): the policy is active and
 * the op is either listed in ops or an always-target (set_approval_policy
 * itself, and add_member / change_role establishing the owner role —
 * policy monotonicity (a))
 */
function isApprovalTarget(operation: ProposableOperation, policy: ApprovalPolicy | null): boolean {
  if (policy === null) {
    return false;
  }
  if (operation.op === "set_approval_policy" || establishesOwner(operation)) {
    return true;
  }
  // Only ops of the closed set can be listed in ops (already
  // structure-checked). Unlisted ops (create / rotate / checkpoint /
  // genesis) can never be policy targets
  return isApprovalTargetOp(operation.op) && policy.ops.includes(operation.op);
}

/** add_member / change_role establishing the owner role (the always-targets of policy monotonicity (a)). */
function establishesOwner(operation: ProposableOperation): boolean {
  return (
    (operation.op === "add_member" && operation.payload.role === "owner") ||
    (operation.op === "change_role" && operation.payload.newRole === "owner")
  );
}

/**
 * Principle 2 (§6.2): a proposal's signer set S = {the proposer, if they
 * proposed as an owner} ∪ {the actors of accepted approves}. Elements are
 * (user_id, key FP at signing time) — votes are signatures made under the
 * owner role, so a proposal signature by a proposer acting as admin does
 * not enter S (same after a later promotion to owner; post-promotion they
 * can append an approve — 2026-09-15 ruling ②)
 */
function signersOf(pending: MutablePendingProposal): readonly ApprovalVote[] {
  const proposer: readonly ApprovalVote[] =
    pending.proposerRoleAtProposal === "owner"
      ? [{ userId: pending.proposerUserId, keyFingerprintHex: pending.proposerKeyFingerprintHex }]
      : [];
  return [...proposer, ...pending.approvals];
}

/**
 * Whether the vote's device is **now** a valid device of that person
 * (§6.2 "the device vocabulary of an approve vote" — 2026-09-19 DK).
 * Votes by revoked devices, by removed members, and old votes by a person
 * re-added under a different key are not live (the same person
 * re-registering the same FP via add_device revives the vote —
 * revocation is not monotonic)
 */
function voteDevice(state: MutableChainState, signer: ApprovalVote): ChainDevice | undefined {
  return state.members.get(signer.userId)?.devices.get(signer.keyFingerprintHex);
}

/**
 * Principle 2 (§6.2): of the signer set S, the count of distinct user_ids
 * whose FP is **currently a valid device of a current owner and whose
 * device's effective role is owner** (another device of the same person
 * is still one vote). Votes by voters demoted or removed after the
 * proposal are not counted and do not revive if re-added under a
 * different key (the judgment state is "the state before this entry
 * applies" — 2026-09-15 ruling ⑤)
 */
function countOwnerVotes(state: MutableChainState, signers: readonly ApprovalVote[]): number {
  const voters = new Set<string>();
  for (const signer of signers) {
    const member = state.members.get(signer.userId);
    const device = voteDevice(state, signer);
    if (
      member !== undefined &&
      device !== undefined &&
      effectivePermissionOf(member, device).role === "owner"
    ) {
      voters.add(signer.userId);
    }
  }
  return voters.size;
}

/**
 * Reachability invariant (§6.2 — policy monotonicity (b), a
 * generalization of last-owner-protected): an op is invalid if the owner
 * count after applying it would fall below the required_approvals of the
 * post-apply policy. set_approval_policy (the policy side changes) and
 * owner-reducing remove_member / change_role (the owner-count side
 * changes) are judged by the same single predicate
 */
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

/** The number of people an op removes from the owner set (removing an owner, demoting from owner = 1). */
function ownersRemovedBy(operation: ProposableOperation, target: ChainMember | undefined): number {
  if (target?.role !== "owner") {
    return 0;
  }
  if (operation.op === "remove_member") {
    return 1;
  }
  return operation.op === "change_role" && operation.payload.newRole !== "owner" ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Role rules (head of the authorization stage — the part independent of target existence)

/**
 * The role rule for checkpoint (§6.2): member or above; only admin or
 * above may notarize a non-empty audit head (obtaining an audit-head
 * attestation is itself limited to effective-permission admin —
 * AUTH_SPEC §16-2)
 */
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

/** Role rule for add_member: admin or above. Granting the admin / owner roles is owner-only. */
function addMemberRoleReason(grantedRole: Role, actorRole: Role): ChainInvalidReason | null {
  return requireRole(actorRole, atLeast(grantedRole, "admin") ? "owner" : "admin");
}

/**
 * The part of an op's role rule determined by the actor alone (the §6.2
 * permission list — the actor's role is the signing device's effective
 * role). The part that depends on the target member's role (remove /
 * change targeting an admin / owner is owner-only) is checked by
 * targetRoleReason after target resolution (unknown-target). add_device
 * is role-agnostic, and revoke_device's role rule is target-dependent
 * (any role if self), so it lives on the consensus-rule side
 * (revokeDeviceReason). The exhaustive Record prevents a missed rule via
 * the type when an op is added
 */
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

// ---------------------------------------------------------------------------
// Consensus rules (after role rules and approval-required; do not mutate state)

/** Existence of each environment_id in a scope (§6.2 — `unknown-environment`). */
function scopeEnvironmentsReason(
  payload: { readonly scopeEnvironmentIds: readonly string[] },
  state: MutableChainState,
): ChainInvalidReason | null {
  for (const environmentId of payload.scopeEnvironmentIds) {
    if (!state.environments.has(environmentId)) {
      return "unknown-environment";
    }
  }
  return null;
}

/** add_member / change_role establishing an owner only allow scope = all (§6.2 — `scope-role-mismatch`). */
function scopeRoleReason(role: Role, scopeKind: string): ChainInvalidReason | null {
  return role === "owner" && scopeKind !== "all" ? "scope-role-mismatch" : null;
}

/**
 * The scope check sequence shared by add_member / change_role (§6.2 —
 * fixed order): unknown-environment → scope-role-mismatch →
 * scope-not-contained (principle 1 — containment of the environment set
 * whose permissions change)
 */
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

/**
 * The shared front half of remove_member / change_role (§6.2 — fixed
 * order): target existence (`unknown-target`) → target-dependent role
 * rule (changes involving an admin / owner are owner-only) → last-owner
 * protection (an op that reduces owners while a single owner remains —
 * `last-owner-protected`)
 */
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
  // Check order (§6.2; fixed by the vectors): duplicate-member →
  // duplicate-member-key → unknown-environment → scope-role-mismatch →
  // scope-not-contained
  if (state.members.has(p.targetUserId)) {
    return "duplicate-member";
  }
  // Member-key uniqueness (§6.2): reject an add whose enc or sig matches
  // a same-kind key of the current member set. The check is per individual
  // key (not per FP — a sockpuppet reusing only one of the two keys is
  // still rejected). The prohibition covers only the current member set;
  // re-adding a removed member's same keys (the same person returning) is
  // not rejected
  if (state.memberEncPubs.has(p.encPubHex) || state.memberSigPubs.has(p.sigPubHex)) {
    return "duplicate-member-key";
  }
  return memberScopeReason(operation, p.role, actor, undefined, state);
}

function changeRoleReason(
  operation: Extract<ProposableOperation, { op: "change_role" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  // Check order (§6.2): unknown-target → (target-dependent role rules) →
  // last-owner-protected → unknown-environment → scope-role-mismatch →
  // scope-not-contained → approval-quorum-unreachable
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
  // Check order (§6.2): unknown-target → (target-dependent role rules) →
  // last-owner-protected → scope-not-contained →
  // approval-quorum-unreachable
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

/**
 * Consensus rules for add_device (§6.2 — 2026-09-19 DK). Check order
 * (fixed by the vectors): no role rule → duplicate-member-key (every
 * device key of the current member set) → unknown-environment →
 * device-cap-exceeded (principle D2 — the new device's cap <= the signing
 * device's **own** cap; effective permissions are not compared)
 */
function addDeviceReason(
  operation: Extract<ProposableOperation, { op: "add_device" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const p = operation.payload;
  if (state.memberEncPubs.has(p.encPubHex) || state.memberSigPubs.has(p.sigPubHex)) {
    return "duplicate-member-key";
  }
  return (
    scopeEnvironmentsReason(p, state) ??
    (capWithinCap({ roleCap: p.roleCap, scope: memberScopeOf(p) }, actor.device)
      ? null
      : "device-cap-exceeded")
  );
}

/**
 * Consensus rules for revoke_device (§6.2 — 2026-09-19 DK). Check order
 * (fixed by the vectors): unknown-target → unknown-device (each FP is a
 * currently-valid device of the target) → target-dependent role rule
 * (any role if self; same as remove_member if other) →
 * last-device-protected (zero devices after revocation) →
 * scope-not-contained (others only — the target **person's** scope ⊆ the
 * actor's effective scope; principle 1)
 */
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
  // FPs are duplicate-free by the structure stage, so list length = number of devices revoked
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
  // Authorization-stage check order (§6.2; fixed by the vectors): role
  // rule → re-grant rule (§6.3) → server-key duplication. FP consistency
  // is the payload's own self-consistency (§9) and is checked right after
  // role (its historical position kept).
  // Server-key FP = SHA-256(server_enc_pub)[:16] (enc key only; §9 /
  // vector definition)
  const encPub = decodeHex(p.serverEncPubHex) ?? new Uint8Array(0);
  const digest = await sha256(encPub);
  if (encodeHex(digest.slice(0, FINGERPRINT_BYTES)) !== p.serverKeyFingerprintHex) {
    return "invalid-payload";
  }
  // Two-layer judgment for re-granting the same server key (owner
  // ruling): the disclosure scope accepts only scope widening (old ⊆
  // new). Allowing a narrowing would let one bypass revoke_server +
  // rotate_epoch (the §7 all-environment rotation duty) and end up
  // "thinking disclosure was stopped", so narrowing must always go
  // through the revocation path. Widening only adds undisclosed
  // environments and is harmless.
  // lease_policy, on the other hand, is freely revisable (including
  // narrowing or full deletion): the policy is an ACL on the lease path
  // (§9.1) and does not change the server's known DEK set (§6.3 — judged
  // independently per field)
  const existing = state.serverGrants.get(p.serverKeyFingerprintHex);
  if (existing !== undefined) {
    const newScope = new Set(p.scopeEnvironmentIds);
    if (existing.scopeEnvironmentIds.some((id) => !newScope.has(id))) {
      return "grant-scope-narrowed";
    }
  }
  // Server-key uniqueness (§6.2): a grant whose server enc public key
  // matches a current member's enc public key is rejected (the
  // recipient-class-crossing version of "key → subject" reverse-lookup
  // uniqueness). The reverse direction (reusing an active grant's server
  // key in add_member) remains explicitly out of scope in the spec (the
  // "note" of §6.2 member-key uniqueness)
  return state.memberEncPubs.has(p.serverEncPubHex) ? "duplicate-server-key" : null;
}

function createEnvironmentReason(
  operation: Extract<ProposableOperation, { op: "create_environment" }>,
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  // Check order (§6.2): duplicate-environment → environment-out-of-scope.
  // environment_id is unique across the whole chain history. The chain
  // never observes an environment deletion (deletion is a data-plane
  // operation), so the environments map is never shrunk, and recreating a
  // deleted environment ID is also rejected here (a consensus-rule
  // escalation of the ID-reuse ban). Since a new environment_id cannot be
  // inside a `listed` scope (no prior scoping to a not-yet-existing
  // environment), environment creation is only possible for a scope = all
  // actor — judged by the same single predicate
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
  // Check order (§6.2; fixed by the vectors): unknown-environment →
  // environment-out-of-scope → epoch ordering. The op is invalid unless a
  // create_environment for that environment_id precedes it (there is no
  // "initial value 1 if unobserved" default fallback)
  const environment = state.environments.get(p.environmentId);
  if (environment === undefined) {
    return "unknown-environment";
  }
  if (!scopeIncludesEnvironment(actor.permission.scope, p.environmentId)) {
    return "environment-out-of-scope";
  }
  // The epoch is a per-environment counter, always +1 (owner ruling,
  // option 3). Rollback (new values encrypted under an old DEK still held
  // by removed members), duplicates, and jumps (a DoS where one
  // member-permission signature jumps to the safe-integer ceiling and
  // disables all future rotations) are all rejected
  return p.newEpoch === environment.currentEpoch + 1 ? null : "epoch-out-of-sequence";
}

/**
 * Consensus rules for checkpoint (§6.2). Check order (fixed by the
 * vectors): unknown-environment → environment-out-of-scope →
 * checkpoint-epoch-mismatch → checkpoint-regression. Across multiple
 * environment entries, **every entry is scanned per check stage**
 * (stage-wise — session-33 ruling C; fixed by
 * authz-checkpoint-unknown-precedes-epoch). The epoch must strictly
 * equal the current epoch "as of the entry (before this entry applies)" —
 * since a checkpoint itself does not move the epoch, even a boundary
 * checkpoint (the compound H+2 — AUTH_SPEC §12-4) naturally matches the
 * state after the bundled entry (H+1) applies. Tuple contents (manifest,
 * values, audit head) cannot be verified here (§6.2's "format is a
 * consensus rule, content belongs to the reconciliation side" — server
 * §6.4 / client §6.3).
 */
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
    stage(
      (tuple) => !scopeIncludesEnvironment(actor.permission.scope, tuple.environmentId),
      "environment-out-of-scope",
    ) ??
    stage(
      (tuple) => state.environments.get(tuple.environmentId)?.currentEpoch !== tuple.epoch,
      "checkpoint-epoch-mismatch",
    ) ??
    // Non-regression allows equality (after a rotation boundary, a
    // periodic checkpoint following re-encryption legitimately
    // re-notarizes the same manifest_version with a new values_digest —
    // §6.3)
    stage((tuple) => {
      const prior = state.checkpoints.get(tuple.environmentId);
      return prior !== undefined && tuple.manifestVersion < prior.manifestVersion;
    }, "checkpoint-regression")
  );
}

// Per-op consensus rules (the remainder of each op's §6.2 check
// sequence, after role rules and approval-required). Shared by direct
// append, propose (pre-check of the inner op), and approve (re-check at
// apply time). Does not mutate state (application is applyOperation).
// The exhaustive Record prevents a missed rule via the type when an op
// is added
const CONSENSUS_RULES: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    actor: ActorContext,
    state: MutableChainState,
  ) => ChainInvalidReason | null | Promise<ChainInvalidReason | null>;
} = {
  // genesis is only a seq-1 direct append (fixed by framing). It is
  // unreachable as an inner op — never a policy target, it fails earlier
  // on approval-not-required
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

// ---------------------------------------------------------------------------
// State transitions (applying ops that passed the consensus rules)

// An environment's initial epoch (the value right after create_environment — CRYPTO_SPEC §3 / §6.2)
const INITIAL_EPOCH = 1;

function applyGenesis(
  entry: ChainEntry & { readonly op: "genesis" },
  state: MutableChainState,
): void {
  // The genesis key = the first device (cap is structurally (owner, all); the FP was already matched in resolveActorSigPub)
  const device = firstDeviceOf(entry.payload, entry.actor.keyFingerprintHex, entry.seq);
  state.members.set(entry.actor.userId, {
    userId: entry.actor.userId,
    role: "owner",
    // The creator's scope is structurally all (§6.2 — genesis carries no scope in its payload)
    scope: ALL_SCOPE,
    devices: new Map([[device.keyFingerprintHex, device]]),
  });
  // The member set is empty at genesis, so key duplication cannot arise
  // structurally (§6.2). The owner's key is still indexed as the
  // comparison target for later add_member / add_device
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

/** add_device: adds a new device to the actor's own device set (target = actor — §6.2). */
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

/** revoke_device: removes the listed devices from the target's device set (and from the key index). */
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
    // Full replacement with the new (role, scope) (§6.2)
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
    // remove_member ends all of the target's devices at once (§6.2)
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
  state.serverGrants.set(p.serverKeyFingerprintHex, {
    serverKeyFingerprintHex: p.serverKeyFingerprintHex,
    serverEncPubHex: p.serverEncPubHex,
    // On re-grant the entry that established the active grant is
    // replaced, so seq also advances (the origin of AUDIT_SPEC §3.5's
    // grant_chain_seq — the 9 → 10 advance is fixed by the valid_appends
    // `regrant-lease-policy-revised` vector in chain-entries.json)
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
    epochStartSeqs: new Map([[INITIAL_EPOCH, seq]]),
    dekCommitments: new Map([[INITIAL_EPOCH, operation.payload.dekCommitmentHex]]),
  });
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
  // required_approvals = 0 means off (§6.2 — same as a policy never
  // having been established). ops is a set (duplicates are not rejected
  // at the structure stage — same as grant_server's scope), so it is
  // deduplicated for storage
  state.approvalPolicy =
    p.requiredApprovals === 0
      ? null
      : { ops: [...new Set(p.ops)], requiredApprovals: p.requiredApprovals };
}

// Per-op state transitions (applying ops that passed the consensus
// rules). The exhaustive Record prevents a missed application via the
// type when an op is added. seq is the applying entry's seq (for a
// proposal-mediated apply, the seq of the approve entry that reached
// quorum — the inclusive convention). actorUserId is the attributed
// subject (add_device's target = the actor itself)
const OPERATION_APPLIERS: {
  readonly [K in ProposableOperation["op"]]: (
    operation: Extract<ProposableOperation, { op: K }>,
    state: MutableChainState,
    seq: number,
    actorUserId: string,
  ) => void | Promise<void>;
} = {
  // genesis as a direct append is applyGenesis (needs the actor). Unreachable as an inner op
  genesis: () => undefined,
  add_member: applyAddMember,
  change_role: applyChangeRole,
  remove_member: applyRemoveMember,
  grant_server: applyGrantServer,
  revoke_server: (operation, state) => {
    state.serverGrants.delete(operation.payload.serverKeyFingerprintHex);
  },
  create_environment: applyCreateEnvironment,
  rotate_epoch: applyRotateEpoch,
  checkpoint: applyCheckpoint,
  set_approval_policy: applySetApprovalPolicy,
  add_device: applyAddDevice,
  revoke_device: applyRevokeDevice,
};

/** Applies an op that passed the consensus rules to the state. */
async function applyOperation(
  operation: ProposableOperation,
  state: MutableChainState,
  seq: number,
  actorUserId: string,
): Promise<void> {
  await OPERATION_APPLIERS[operation.op](operation as never, state, seq, actorUserId);
}

// ---------------------------------------------------------------------------
// Entry evaluation (direct append / propose / approve / withdraw)

/**
 * Direct append (§6.2): role rules → approval-required (a policy target
 * has S = {actor} and cannot reach quorum — derived from principle 2) →
 * consensus rules → apply
 */
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

/**
 * propose (§6.2): role rules (of the inner op) → approval-not-required
 * (policy off / op not a target) → the inner op's consensus rules (except
 * approval-required — S is still being gathered). A passing proposal is
 * recorded in pending (identifier = the proposal entry's entry_hash)
 */
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

/**
 * approve (§6.2): role rules (owner) → unknown-proposal →
 * duplicate-approval (actor is already in S) → approval-not-required
 * (not a target under the current policy) → proposal-expired → if the
 * vote count = |S ∩ current owners| (principle 2) reaches required:
 * proposal-void (proposer membership, key FP, inner op's role) → the
 * inner op's consensus rules (state at apply time) → apply (actor = the
 * proposer, seq = this approve). If it does not reach quorum, the vote
 * is recorded and that is all
 */
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
  // S ∪ {this actor's (user_id, current key FP)} (principle 2).
  // approveVoteReason already confirmed the policy is active (non-null)
  // — if it were somehow null, fall to the side that cannot reach quorum
  const signature: ApprovalVote = {
    userId: actor.userId,
    keyFingerprintHex: actor.device.keyFingerprintHex,
  };
  const required = state.approvalPolicy?.requiredApprovals ?? Number.POSITIVE_INFINITY;
  if (countOwnerVotes(state, [...signersOf(pending), signature]) < required) {
    pending.approvals.push(signature);
    return null;
  }
  return completeProposal(pending, state, entry.seq);
}

/**
 * approve pre-vote checks (the §6.2 order): duplicate-approval (the
 * actor's user_id already holds a **live** vote in S — the vote's device
 * is currently a valid device of that person. An owner's proposal is 1
 * vote, so self-approval is a duplicate. Re-voting from another device
 * of the same person is also a duplicate [distinct is by user_id —
 * 2026-09-19 DK]. Votes by revoked devices and old votes by a voter
 * re-added under a different key are not live, so they may vote again)
 * → approval-not-required (not a target under the current policy —
 * including policy off) → proposal-expired (timestamp_ms >
 * expires_at_ms — the only place this spec uses timestamp as a
 * consensus rule)
 */
function approveVoteReason(
  entry: ChainEntry & { readonly op: "approve" },
  actor: ActorContext,
  pending: MutablePendingProposal,
  state: MutableChainState,
): ChainInvalidReason | null {
  const live = signersOf(pending).some(
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

/**
 * Apply-on-quorum (§6.2): re-check, against the state at apply time, the
 * proposer (membership, the proposing device still valid, the inner op's
 * role [the proposing device's effective role] — `proposal-void`) and
 * the inner op's consensus rules; on success, apply with the proposer
 * as actor. A failed approve is an invalid entry and the proposal stays
 * in pending (closed by withdraw)
 */
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
  // The applied inner op's actor is treated as the proposer (recorded for membership/attribution)
  return { operation: pending.inner, actorUserId: proposer.userId };
}

function evaluateWithdraw(
  entry: ChainEntry & { readonly op: "withdraw" },
  actor: ActorContext,
  state: MutableChainState,
): ChainInvalidReason | null {
  const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
  // A non-owner satisfies the role only when they are "the proposer of
  // the referenced pending proposal" (they cannot be the proposer of an
  // unknown proposal, so the role rule fails first — fixed by the
  // vectors)
  if (actor.permission.role !== "owner" && pending?.proposerUserId !== actor.userId) {
    return "insufficient-role";
  }
  if (pending === undefined) {
    return "unknown-proposal";
  }
  state.pendingProposals.delete(pending.proposalHashHex);
  return null;
}

/**
 * Authorization + state transition (verification stage 5). Returns: a
 * rejection reason, or the applied op (recorded in the history index —
 * propose / withdraw / an approve short of quorum entail no state
 * transition and yield null)
 */
async function evaluateEntry(
  entry: ChainEntry,
  entryHashHex: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | AppliedOperation | null> {
  if (entry.op === "genesis") {
    applyGenesis(entry, state);
    return { operation: entry, actorUserId: entry.actor.userId };
  }
  // The actor's existence and device were already confirmed by resolveActorSigPub
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

// ---------------------------------------------------------------------------
// Recording into the history index

/** Records tenure start by pulling the target member's first device from the applied state (one device at tenure start). */
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

/** Records the device added by add_device (identified by enc public key), pulled from the applied state. */
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

// Per-op history recording (an exhaustive Record — the type prevents a
// missed record when an op is added). Tenure start, end, and (role,
// scope) changes all use the applying entry's own seq as the boundary
// (the §6.3 inclusive convention — fixed by vectors in
// value-signature.json; a proposal-mediated apply uses the seq of the
// approve entry that reached quorum). grant_server / revoke_server /
// set_approval_policy have no state recorded in the history index
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

/**
 * Pre-apply single-entry checks (in verification-stage order: framing →
 * payload structure → actor resolution → signature). null = pass.
 * Authorization + state transition is then checked by evaluateEntry.
 */
async function checkEntryBeforeApply(
  entry: ChainEntry,
  seq: number,
  prevHash: string,
  state: MutableChainState,
): Promise<ChainInvalidReason | null> {
  // Does not throw even on crafted data where the array slot itself is null / a non-object
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
    // entry_hash is computed only after signature verification has
    // successfully normalized the same fields. It is needed before apply
    // as a propose identifier (§6.2), so it is computed here
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

  return {
    ok: true,
    value: {
      members: state.members,
      serverGrants: state.serverGrants,
      environments: state.environments,
      checkpoints: state.checkpoints,
      approvalPolicy: state.approvalPolicy,
      pendingProposals: freezePendingProposals(state.pendingProposals),
      headSeq: entries.length,
      headHashHex: prevHash,
    },
  };
}

/**
 * Verifies a full membership chain (CRYPTO_SPEC §6.3): framing, payload
 * shape, actor identity, Ed25519 signatures and the §6.2 role / scope /
 * four-eyes rules — and derives the resulting state (current members with
 * roles and scopes, active server grants, observed environment epochs, the
 * approval policy and pending proposals, chain head).
 *
 * Verification is fail-fast: the returned error carries the failing entry's
 * `seq` and a machine-readable reason.
 *
 * Entries are treated as untrusted input (chains are distributed by the
 * server): every field is re-validated at runtime regardless of the static
 * types, so malformed data yields `invalid-payload` instead of throwing.
 */
export async function verifyChain(
  entries: readonly ChainEntry[],
): Promise<CryptoResult<ChainState>> {
  return verifyChainCore(entries, null);
}

/**
 * `verifyChain` plus the per-snapshot history index (CRYPTO_SPEC §6.3 /
 * §4.1 — the input of the declared-head-time value verification). The index
 * is built inside the same verification loop, so it can only exist for a
 * chain that passed full verification, and per-value checks never re-verify
 * chain signatures (session-14 ruling A).
 */
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
