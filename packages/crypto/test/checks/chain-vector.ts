// Helpers that convert the chain-entries.json vectors into @maruhi/crypto
// typed entries.

import {
  type ApprovalPolicy,
  type ApprovalTargetOp,
  type ApprovalVote,
  canonicalChainPayloadBytes,
  type ChainDevice,
  type ChainEntry,
  type ChainMember,
  type ChainOperation,
  type MemberScope,
  type PendingProposal,
  type ProposableOperation,
  type Role,
  type ScopeKind,
  type ServerGrant,
  soleDeviceOf,
} from "../../src/index.ts";
import { importSigningKeyPair, importSigningPublicKey } from "../../src/index.ts";
import chainVectors from "../../test-vectors/chain-entries.json" with { type: "json" };
import { testUserId } from "../support/fixture.ts";
import { fromHex, toHex } from "./support.ts";

export interface VectorEntry {
  readonly seq: number;
  readonly suite: string;
  readonly prev_hash_hex: string;
  readonly op: string;
  readonly actor: { readonly user_id: string; readonly key_fingerprint_hex: string };
  readonly payload: Readonly<Record<string, unknown>>;
  readonly timestamp_ms: number;
  readonly payload_bytes_hex: string;
  readonly signed_bytes_hex: string;
  readonly signature_hex: string;
  readonly entry_bytes_hex: string;
  readonly entry_hash_hex: string;
}

interface VectorNegative {
  readonly name: string;
  readonly kind?: string;
  readonly base_seq?: number;
  readonly payload?: Readonly<Record<string, unknown>>;
  readonly signed_bytes_hex?: string;
  readonly signature_hex?: string;
  readonly verify_key_hex?: string;
  readonly claimed_prev_hash_hex?: string;
  readonly expected_prev_hash_hex?: string;
  readonly entry?: VectorEntry;
  readonly expected_reason?: string;
  /** Prerequisite chain for an authorization negative (an extended_chains key; unset = the canonical chain). */
  readonly chain?: string;
  readonly must_fail: boolean;
}

/** Vector representation of a grant_server payload / derived-state lease_policy (§6.2). */
interface VectorLeasePolicyIssuer {
  readonly issuer_url: string;
  readonly audience: string;
  readonly claim_constraints: readonly {
    readonly claim_name: string;
    readonly claim_value: string;
  }[];
}

interface VectorServerGrant {
  readonly server_key_fingerprint_hex: string;
  readonly server_enc_pub_hex: string;
  readonly scope_environments: readonly string[];
  readonly lease_policy: readonly VectorLeasePolicyIssuer[];
  /** seq of the entry that established the active grant (advances on re-grant — §6.3 / AUDIT_SPEC §3.5). */
  readonly grant_seq: number;
}

/** Expected latest checkpoint per environment after acceptance (§6.2 checkpoint). */
export interface VectorCheckpointState {
  readonly seq: number;
  readonly epoch: string;
  readonly manifest_version: string;
  readonly manifest_sig_hash_hex: string;
  readonly values_digest_hex: string;
}

/** Expected scope (all / listed). */
interface VectorScope {
  readonly kind: string;
  readonly environments?: readonly string[];
}

/** Expected state of a single device (FP → cap + added seq — the §6.2 verification state. 2026-09-19 DK). */
export interface VectorDeviceState {
  readonly role_cap: string;
  readonly scope: VectorScope;
  readonly added_seq: number;
}

/**
 * Expected member state (role + scope — the §6.2 verification state.
 * 2026-09-14 ES). Omitting `devices` means "only the first key (cap (owner,
 * all))" (convention 28 — existing expectations are unchanged)
 */
export interface VectorMemberState {
  readonly role: string;
  readonly scope: VectorScope;
  readonly devices?: Readonly<Record<string, VectorDeviceState>>;
}

/** Expected four-eyes policy (null = off). */
export interface VectorApprovalPolicy {
  readonly ops: readonly string[];
  readonly required_approvals: string;
}

/** Expected pending proposals (proposal entry hash → proposal). */
export interface VectorPendingProposal {
  readonly proposal_seq: number;
  readonly proposer_user_id: string;
  readonly proposer_key_fingerprint_hex: string;
  readonly proposer_role_at_proposal: string;
  readonly inner_op: string;
  readonly inner_payload: Readonly<Record<string, unknown>>;
  readonly expires_at_ms: string;
  /** Signatures of accepted approve votes (user_id, key FP) — 2026-09-15 ruling (5) (key binding of votes). */
  readonly approvals: readonly { readonly user_id: string; readonly key_fingerprint_hex: string }[];
}

interface VectorValidAppend {
  readonly name: string;
  readonly entry: VectorEntry;
  /** Attach point (an extended_chains key; unset = the canonical chain up to entry.seq - 1). */
  readonly chain?: string;
  readonly expected_members: Readonly<Record<string, VectorMemberState>>;
  readonly expected_policy?: VectorApprovalPolicy | null;
  readonly expected_pending?: Readonly<Record<string, VectorPendingProposal>>;
  /** Current epoch per environment after acceptance (§6.2 environment lifecycle). */
  readonly expected_environments: Readonly<Record<string, string>>;
  /** Active grant set after acceptance (§6.2 two-layer re-grant). */
  readonly expected_server_grants: readonly VectorServerGrant[];
  /** Latest checkpoint per environment after acceptance (valid appends of checkpoint only). */
  readonly expected_checkpoints?: Readonly<Record<string, VectorCheckpointState>>;
  readonly note?: string;
}

/** Derived chain appended onto a mid-canonical-chain head (the prerequisite state for authorization negatives). */
interface VectorExtendedChain {
  readonly description: string;
  readonly base_seq: number;
  readonly entries: readonly VectorEntry[];
  readonly expected_members: Readonly<Record<string, VectorMemberState>>;
  /** Keys used only by the derived chain (re-added new keys, second devices — same shape as the top-level keys). */
  readonly keys?: Readonly<Record<string, VectorKey>>;
  /** Latest checkpoint per environment after verifying the derived chain (checkpoint-baseline). */
  readonly expected_checkpoints?: Readonly<Record<string, VectorCheckpointState>>;
  readonly expected_policy?: VectorApprovalPolicy | null;
  readonly expected_pending?: Readonly<Record<string, VectorPendingProposal>>;
}

interface VectorEnvironmentState {
  readonly current_epoch: string;
  readonly created_at_seq: number;
  readonly epoch_start_seqs: Readonly<Record<string, number>>;
  readonly dek_commitments: Readonly<Record<string, string>>;
}

interface VectorHeadState {
  readonly after_seq: number;
  readonly members: Readonly<Record<string, VectorMemberState>>;
  readonly server_grants: readonly VectorServerGrant[];
  readonly environments: Readonly<Record<string, VectorEnvironmentState>>;
  readonly approval_policy: VectorApprovalPolicy | null;
  readonly pending_proposals: Readonly<Record<string, VectorPendingProposal>>;
}

function scopeMatchesVector(actual: MemberScope, expected: VectorScope): boolean {
  if (expected.kind === "all") {
    return actual.kind === "all";
  }
  const expectedIds = new Set(expected.environments ?? []);
  return (
    actual.kind === "listed" &&
    actual.environmentIds.length === expectedIds.size &&
    actual.environmentIds.every((id) => expectedIds.has(id))
  );
}

/**
 * Device-set match (§6.2 — 2026-09-19 DK). If the expectation has no
 * `devices`, only "one device, cap (owner, all)" is required (the added seq
 * is not checked — existing expectations carry no seq)
 */
function devicesMatchVector(
  actual: ReadonlyMap<string, ChainDevice>,
  expected: Readonly<Record<string, VectorDeviceState>> | undefined,
): boolean {
  if (expected === undefined) {
    const sole = soleDeviceOf({ devices: actual });
    return sole !== undefined && sole.roleCap === "owner" && sole.scope.kind === "all";
  }
  return (
    actual.size === Object.keys(expected).length &&
    Object.entries(expected).every(([fp, device]) => {
      const found = actual.get(fp);
      return (
        found !== undefined &&
        found.keyFingerprintHex === fp &&
        found.roleCap === device.role_cap &&
        found.addedSeq === device.added_seq &&
        scopeMatchesVector(found.scope, device.scope)
      );
    })
  );
}

/** Whether the derived-state member set matches the vector expectation (role + scope + device set) (compared as sets). */
export function membersMatchVector(
  members: ReadonlyMap<string, ChainMember>,
  expected: Readonly<Record<string, VectorMemberState>>,
): boolean {
  return (
    members.size === Object.keys(expected).length &&
    Object.entries(expected).every(([userId, state]) => {
      const actual = members.get(userId);
      return (
        actual !== undefined &&
        actual.role === state.role &&
        scopeMatchesVector(actual.scope, state.scope) &&
        devicesMatchVector(actual.devices, state.devices)
      );
    })
  );
}

/** Whether the derived-state policy matches the vector expectation (ops compared as a set; unspecified is not checked). */
export function policyMatchesVector(
  policy: ApprovalPolicy | null,
  expected: VectorApprovalPolicy | null | undefined,
): boolean {
  if (expected === undefined) {
    return true;
  }
  if (expected === null || policy === null) {
    return expected === policy;
  }
  const expectedOps = new Set(expected.ops);
  return (
    policy.requiredApprovals === Number(expected.required_approvals) &&
    policy.ops.length === expectedOps.size &&
    policy.ops.every((op) => expectedOps.has(op))
  );
}

/** Canonical form for comparing a single pending proposal (JSON with normalized order and types — the inner payload is the canonical bytes). */
function pendingProposalKey(input: {
  readonly hash: string;
  readonly proposalSeq: number;
  readonly proposerUserId: string;
  readonly proposerKeyFingerprintHex: string;
  readonly proposerRoleAtProposal: string;
  readonly inner: ProposableOperation;
  readonly expiresAtMs: number;
  readonly approvals: readonly ApprovalVote[];
}): string {
  return JSON.stringify([
    input.hash,
    input.proposalSeq,
    input.proposerUserId,
    input.proposerKeyFingerprintHex,
    input.proposerRoleAtProposal,
    input.inner.op,
    toHex(canonicalChainPayloadBytes(input.inner)),
    input.expiresAtMs,
    input.approvals.map((vote) => [vote.userId, vote.keyFingerprintHex]),
  ]);
}

/** Whether the derived-state pending-proposal set matches the vector expectation (unspecified is not checked). */
export function pendingMatchesVector(
  pending: ReadonlyMap<string, PendingProposal>,
  expected: Readonly<Record<string, VectorPendingProposal>> | undefined,
): boolean {
  if (expected === undefined) {
    return true;
  }
  const expectedKeys = Object.entries(expected).map(([hash, proposal]) =>
    pendingProposalKey({
      hash,
      proposalSeq: proposal.proposal_seq,
      proposerUserId: proposal.proposer_user_id,
      proposerKeyFingerprintHex: proposal.proposer_key_fingerprint_hex,
      proposerRoleAtProposal: proposal.proposer_role_at_proposal,
      inner: decodeInner(proposal.inner_op, proposal.inner_payload),
      expiresAtMs: Number(proposal.expires_at_ms),
      approvals: proposal.approvals.map((vote) => ({
        userId: testUserId(vote.user_id),
        keyFingerprintHex: vote.key_fingerprint_hex,
      })),
    }),
  );
  const actualKeys = [...pending.entries()].map(([hash, actual]) =>
    pendingProposalKey({ ...actual, hash: actual.proposalHashHex === hash ? hash : `${hash}!` }),
  );
  return expectedKeys.toSorted().join("\n") === actualKeys.toSorted().join("\n");
}

/**
 * Whether the derived-state active grant set matches the vector expectation
 * (snake_case) (§6.2 — including scope + lease_policy. Shared by chain.ts /
 * chain-negative.ts).
 */
export function serverGrantsMatchVector(
  serverGrants: ReadonlyMap<string, ServerGrant>,
  expected: readonly VectorServerGrant[],
): boolean {
  return (
    serverGrants.size === expected.length &&
    expected.every((grant) => {
      const actual = serverGrants.get(grant.server_key_fingerprint_hex);
      return (
        actual !== undefined &&
        actual.serverEncPubHex === grant.server_enc_pub_hex &&
        actual.grantSeq === grant.grant_seq &&
        actual.scopeEnvironmentIds.join(",") === grant.scope_environments.join(",") &&
        // lease_policy (§6.2) is part of the derived state too (match
        // including order — as-signed order)
        JSON.stringify(
          actual.leasePolicy.map((element) => ({
            issuer_url: element.issuerUrl,
            audience: element.audience,
            claim_constraints: element.claimConstraints.map((constraint) => ({
              claim_name: constraint.claimName,
              claim_value: constraint.claimValue,
            })),
          })),
        ) === JSON.stringify(grant.lease_policy)
      );
    })
  );
}

export const vectorEntries = chainVectors.entries as readonly VectorEntry[];
export const vectorNegatives = chainVectors.negative as readonly VectorNegative[];
export const vectorHeadStates =
  chainVectors.expected_head_states as unknown as readonly VectorHeadState[];
export const vectorValidAppends =
  chainVectors.valid_appends as unknown as readonly VectorValidAppend[];
export const vectorExtendedChains = chainVectors.extended_chains as unknown as Readonly<
  Record<string, VectorExtendedChain>
>;
/**
 * Key record. A `keys` key is a member's user_id or, for a device key,
 * `"<user_id>@<label>"` (2026-09-19 DK — convention 28. A device key carries
 * `user_id` / `label`). The signer is selected by (user_id, FP)
 */
export interface VectorKey {
  readonly user_id?: string;
  readonly label?: string;
  readonly enc_sk_seed_hex: string;
  readonly sig_sk_seed_hex: string;
  readonly enc_pub_hex: string;
  readonly sig_pub_hex: string;
  readonly key_fingerprint_hex: string;
}

export const vectorKeys = chainVectors.keys as Readonly<Record<string, VectorKey>>;

/**
 * Select the signing key by (user_id, key FP) (§6.2 — signers are identified
 * per device). Consults both the top-level keys and the derived chains'
 * keys. Returns undefined when not found
 */
export function vectorKeyFor(userId: string, keyFingerprintHex: string): VectorKey | undefined {
  const pools: readonly Readonly<Record<string, VectorKey>>[] = [
    vectorKeys,
    ...Object.values(vectorExtendedChains).flatMap((extended) =>
      extended.keys === undefined ? [] : [extended.keys],
    ),
  ];
  for (const pool of pools) {
    for (const [name, key] of Object.entries(pool)) {
      const owner = key.user_id ?? name;
      if (owner === userId && key.key_fingerprint_hex === keyFingerprintHex) {
        return key;
      }
    }
  }
  return undefined;
}
/** Standalone vectors for the checkpoint values_digest canonical form (§6.2). */
export const vectorValuesDigests = chainVectors.values_digests as readonly {
  readonly name: string;
  readonly entries: readonly {
    readonly variable_id: string;
    readonly version: string;
    readonly value_sig_hash_hex: string;
  }[];
  readonly values_digest_hex: string;
  readonly note?: string;
}[];
/** Dummy DEK and §5.2 commitment per (environment, epoch) (actually computed values). */
export const vectorEnvironmentDeks = chainVectors.environment_deks as Readonly<
  Record<
    string,
    Readonly<Record<string, { readonly dek_hex: string; readonly dek_commitment_hex: string }>>
  >
>;
function str(payload: Readonly<Record<string, unknown>>, key: string): string {
  const value = payload[key];
  if (typeof value !== "string") {
    throw new Error(`chain vector payload: expected string field ${key}`);
  }
  return value;
}

/** The two scope fields (§6.2 — the last two fields of add_member / change_role). */
function scopeFields(payload: Readonly<Record<string, unknown>>): {
  readonly scopeKind: ScopeKind;
  readonly scopeEnvironmentIds: readonly string[];
} {
  return {
    scopeKind: str(payload, "scope_kind") as ScopeKind,
    scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
  };
}

// Per-op snake_case → typed payload conversion table (a table replaces a
// high-cyclomatic switch — same shape as the implementation's
// PAYLOAD_SHAPES / OPERATION_APPLIERS)
const OPERATION_DECODERS: Readonly<
  Record<string, (payload: Readonly<Record<string, unknown>>) => ChainOperation>
> = {
  genesis: (payload) => ({
    op: "genesis",
    payload: { encPubHex: str(payload, "enc_pub_hex"), sigPubHex: str(payload, "sig_pub_hex") },
  }),
  add_member: (payload) => ({
    op: "add_member",
    payload: {
      targetUserId: testUserId(str(payload, "target_user_id")),
      encPubHex: str(payload, "enc_pub_hex"),
      sigPubHex: str(payload, "sig_pub_hex"),
      role: str(payload, "role") as Role,
      ...scopeFields(payload),
    },
  }),
  remove_member: (payload) => ({
    op: "remove_member",
    payload: { targetUserId: testUserId(str(payload, "target_user_id")) },
  }),
  change_role: (payload) => ({
    op: "change_role",
    payload: {
      targetUserId: testUserId(str(payload, "target_user_id")),
      newRole: str(payload, "new_role") as Role,
      ...scopeFields(payload),
    },
  }),
  create_environment: (payload) => ({
    op: "create_environment",
    payload: {
      environmentId: str(payload, "environment_id"),
      dekCommitmentHex: str(payload, "dek_commitment_hex"),
    },
  }),
  rotate_epoch: (payload) => ({
    op: "rotate_epoch",
    payload: {
      environmentId: str(payload, "environment_id"),
      newEpoch: Number(str(payload, "new_epoch")),
      reason: str(payload, "reason"),
      dekCommitmentHex: str(payload, "dek_commitment_hex"),
    },
  }),
  grant_server: (payload) => {
    const leasePolicy = payload["lease_policy"] as readonly VectorLeasePolicyIssuer[];
    return {
      op: "grant_server",
      payload: {
        serverEncPubHex: str(payload, "server_enc_pub_hex"),
        serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex"),
        scopeEnvironmentIds: payload["scope_environments"] as readonly string[],
        leasePolicy: leasePolicy.map((element) => ({
          issuerUrl: element.issuer_url,
          audience: element.audience,
          claimConstraints: element.claim_constraints.map((constraint) => ({
            claimName: constraint.claim_name,
            claimValue: constraint.claim_value,
          })),
        })),
      },
    };
  },
  revoke_server: (payload) => ({
    op: "revoke_server",
    payload: { serverKeyFingerprintHex: str(payload, "server_key_fingerprint_hex") },
  }),
  checkpoint: (payload) => {
    const environments = payload["environments"] as readonly Readonly<Record<string, unknown>>[];
    return {
      op: "checkpoint",
      payload: {
        environments: environments.map((entry) => ({
          environmentId: str(entry, "environment_id"),
          epoch: Number(str(entry, "epoch")),
          manifestVersion: Number(str(entry, "manifest_version")),
          manifestSigHashHex: str(entry, "manifest_sig_hash_hex"),
          valuesDigestHex: str(entry, "values_digest_hex"),
        })),
        auditHeadHashHex: str(payload, "audit_head_hash_hex"),
      },
    };
  },
  // Four-eyes (§6.2 — PF1). A propose's inner op is decoded recursively via
  // the same conversion table
  set_approval_policy: (payload) => ({
    op: "set_approval_policy",
    payload: {
      ops: payload["ops"] as readonly ApprovalTargetOp[],
      requiredApprovals: Number(str(payload, "required_approvals")),
    },
  }),
  propose: (payload) => ({
    op: "propose",
    payload: {
      inner: decodeInner(
        str(payload, "inner_op"),
        payload["inner_payload"] as Readonly<Record<string, unknown>>,
      ),
      expiresAtMs: Number(str(payload, "expires_at_ms")),
    },
  }),
  approve: (payload) => ({
    op: "approve",
    payload: { proposalHashHex: str(payload, "proposal_hash_hex") },
  }),
  withdraw: (payload) => ({
    op: "withdraw",
    payload: { proposalHashHex: str(payload, "proposal_hash_hex") },
  }),
  // Device keys (§6.2 — 2026-09-19 DK). revoke_device's FP list is carried
  // in signature order
  add_device: (payload) => ({
    op: "add_device",
    payload: {
      encPubHex: str(payload, "enc_pub_hex"),
      sigPubHex: str(payload, "sig_pub_hex"),
      roleCap: str(payload, "role_cap") as Role,
      ...scopeFields(payload),
    },
  }),
  revoke_device: (payload) => ({
    op: "revoke_device",
    payload: {
      targetUserId: testUserId(str(payload, "target_user_id")),
      deviceFingerprintsHex: payload["device_fingerprints"] as readonly string[],
    },
  }),
};

/**
 * Decodes a propose's inner op. A structural negative (unknown op, nesting,
 * missing field) cannot be decoded by the conversion table, so in that case
 * the raw payload is carried as-is and the subject under test is that the
 * implementation's structural check lands it on invalid-payload (does not
 * stop the check by throwing)
 */
function decodeInner(op: string, payload: Readonly<Record<string, unknown>>): ProposableOperation {
  try {
    return toOperation(op, payload) as ProposableOperation;
  } catch {
    return { op, payload } as unknown as ProposableOperation;
  }
}

function toOperation(op: string, payload: Readonly<Record<string, unknown>>): ChainOperation {
  const decode = OPERATION_DECODERS[op];
  if (decode === undefined) {
    throw new Error(`chain vector: unknown op ${op}`);
  }
  return decode(payload);
}

/** Convert a vector entry into a typed ChainEntry */
export function toTypedEntry(vector: VectorEntry): ChainEntry {
  return {
    ...toOperation(vector.op, vector.payload),
    suite: vector.suite,
    seq: vector.seq,
    prevHashHex: vector.prev_hash_hex,
    actor: {
      userId: testUserId(vector.actor.user_id),
      keyFingerprintHex: vector.actor.key_fingerprint_hex,
    },
    timestampMs: vector.timestamp_ms,
    signatureHex: vector.signature_hex,
  };
}

export const typedEntries: readonly ChainEntry[] = vectorEntries.map(toTypedEntry);

/**
 * Imports the signing key of (user_id, key FP) into WebCrypto from the
 * vector's seed (the shared preamble of deterministic re-signing and raw
 * signature verification — the 4 harnesses value / meta / manifest /
 * attestation). Returns null when the key is missing or the import fails
 */
export async function importVectorSigner(
  userId: string,
  keyFingerprintHex: string,
): Promise<{ readonly privateKey: CryptoKey; readonly publicKey: CryptoKey } | null> {
  const keys = vectorKeyFor(userId, keyFingerprintHex);
  if (keys === undefined) {
    return null;
  }
  const pair = await importSigningKeyPair({
    publicKey: fromHex(keys.sig_pub_hex),
    privateSeed: fromHex(keys.sig_sk_seed_hex),
  });
  const publicKey = await importSigningPublicKey(fromHex(keys.sig_pub_hex));
  if (!pair.ok || !publicKey.ok) {
    return null;
  }
  return { privateKey: pair.value.privateKey, publicKey: publicKey.value };
}
