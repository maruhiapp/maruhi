// The shared audit-actor type and mapping (AUDIT_SPEC §2), plus the
// chain-mirror mapping (§3.4).
//
// Gate of the identity rule (§1-2): actors in the audit log (D1 side)
// and in the membership-log mirror / data events (DO side) are
// represented by **the internal user_id and key fingerprint only**. The
// authenticated-principal → actor mapping is implemented solely here
// (auditActorOf); provider information (GitHub id, login, email, etc.)
// must never be added to this type. The input types for the DO
// (DataActor in apps/server data-plane.ts) and for D1 (D1AuditActor in
// db.package/audit.ts) derive from this type.
//
// The chain-mirror mapping (chainMirrorEvent) lives here because **the
// server's mirror append and the CLI's mirror verification (`maruhi
// audit verify` — AUDIT_SPEC §1-5 / §6 mitigation) share one
// implementation**. If the mapping were maintained in two places,
// verifier drift would produce false tamper detections (or misses).

import type { ChainActor, ChainEntry, ChainOp, ChainOperation } from "@maruhi/crypto";

import type {
  ChainMirrorEventName,
  ProjectAuditEventName,
  ProjectAuditEventPayload,
  ProjectAuditPayload,
} from "./audit-payloads.ts";
import type { AuthenticatedPrincipal, AuthMethod } from "./auth.ts";
import type { KeyFingerprintHex, UserId } from "./identity.ts";
import { decodeVariableId, isVariableId, type VariableId } from "./project.ts";

/**
 * A resolved audit actor (AUDIT_SPEC §2): the internal user id plus, depending
 * on how the request was authenticated, the maruhi-issued token id or the auth
 * method name. Never carries provider identifiers (GitHub id, login, email).
 */
export interface AuditActor {
  readonly userId: UserId;
  readonly apiTokenId?: string;
  readonly authMethod?: AuthMethod;
}

/**
 * Maps an authenticated principal to its audit actor (AUDIT_SPEC §2). The only
 * principal-to-actor mapping — both the DO data plane and the D1 audit log go
 * through this.
 */
export function auditActorOf(principal: AuthenticatedPrincipal): AuditActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

/**
 * Merges the actor's auth method into the event payload (AUDIT_SPEC §5.1:
 * auth_method is a payload attribute, not a column) — the stored payload.
 * Shared by the DO and the D1 serialization so the merge cannot drift
 * between the two. The event payload has already been checked against its
 * event's schema (audit-payloads.ts); the auth method is the actor's (§2).
 */
export function auditPayloadWith(
  actor: Pick<AuditActor, "authMethod">,
  payload: object | undefined,
): Readonly<Record<string, unknown>> {
  return {
    ...payload,
    ...(actor.authMethod === undefined ? {} : { authMethod: actor.authMethod }),
  };
}

// ---------------------------------------------------------------------------
// Chain mirror (AUDIT_SPEC §3.4): accepted entries → audit events.
// actor copies the chain entry's actor (user_id + key FP) as-is, and
// carries both the client time (entry.timestampMs) and the server's
// acceptance time.
// Four-eyes (PF1 — 2026-09-16 K5): approve / withdraw rows carry the
// seq of the proposal entry they reference; a completed approve
// additionally carries an applied-inner-op row (same chain_seq, actor =
// the proposer, viaProposalSeq in the payload). Neither can be mapped
// from the entry alone, so they take as input an index of proposals
// (ProposalIndex) derived from the verified chain.
// ---------------------------------------------------------------------------

/** The columns of an audit row besides the event and its payload (AUDIT_SPEC §5.1; unspecified = NULL). */
export interface AuditEventColumns {
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly actorType: "user" | "server" | "system";
  readonly actorUserId?: UserId;
  readonly actorKeyFingerprintHex?: KeyFingerprintHex;
  readonly actorApiTokenId?: string;
  /**
   * The session actor's auth method (AUDIT_SPEC §2 — the kind name only). Not
   * a column: the store merges it into the stored payload (§5.1).
   */
  readonly actorAuthMethod?: AuthMethod;
  readonly targetUserId?: UserId;
  readonly targetKeyFingerprintHex?: KeyFingerprintHex;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
}

/**
 * One project audit event (AUDIT_SPEC §3.3–§3.5): the columns plus the event
 * and its payload, a discriminated union on the event name whose payload is
 * the one AUDIT_SPEC §3 lists for that event (audit-payloads.ts). Shared
 * between the server-side append input (apps/server audit-store.ts) and the
 * client-side mirror verifier, so the mirror mapping below produces the exact
 * shape the server persists.
 */
export type AuditEventRecord = AuditEventColumns & ProjectAuditEventPayload;

/** The record of one project event. */
export type AuditEventRecordOf<E extends ProjectAuditEventName> = AuditEventColumns &
  Extract<ProjectAuditEventPayload, { readonly event: E }>;

/** The part of a mirror row an operation determines (event, target, coordinates, payload), per mirror event. */
type MirrorTail = {
  readonly [E in ChainMirrorEventName]: Pick<
    AuditEventColumns,
    "targetUserId" | "targetKeyFingerprintHex" | "environmentId" | "epoch"
  > &
    Extract<ProjectAuditEventPayload, { readonly event: E }>;
}[ChainMirrorEventName];

/**
 * op → mirror event name (§3.4). A whole-domain map over ChainOp (the
 * type enforces exhaustiveness); both mirrorTails and
 * CHAIN_MIRROR_EVENTS take their names from it — blocking the shape
 * where an added op updates only one of them and the verifier drifts
 * (false detections / misses).
 */
const MIRROR_EVENT_NAME = {
  genesis: "chain.genesis",
  add_member: "chain.member_added",
  remove_member: "chain.member_removed",
  change_role: "chain.role_changed",
  create_environment: "chain.environment_created",
  // Environment deletion on the chain (AUDIT_SPEC §3.4 — 2026-10-07)
  delete_environment: "chain.environment_deleted",
  rotate_epoch: "chain.epoch_rotated",
  grant_server: "chain.server_granted",
  revoke_server: "chain.server_revoked",
  checkpoint: "chain.checkpointed",
  // Four-eyes (AUDIT_SPEC §3.4 — 2026-09-14 PF1)
  set_approval_policy: "chain.approval_policy_changed",
  propose: "chain.proposed",
  approve: "chain.approved",
  withdraw: "chain.proposal_withdrawn",
  // Device keys (AUDIT_SPEC §3.4 — 2026-09-19 DK). Row generation (the acceptance side effect) is K3
  add_device: "chain.device_added",
  revoke_device: "chain.device_revoked",
} as const satisfies { readonly [K in ChainOp]: ChainMirrorEventName };

/**
 * All chain-mirror audit event names (AUDIT_SPEC §3.4) — the image of
 * `chainMirrorEvents`. Derived from the exhaustive per-op map so the mirror
 * verifier (`maruhi audit verify`) cannot silently miss a future ChainOp.
 */
export const CHAIN_MIRROR_EVENTS: readonly string[] = Object.values(MIRROR_EVENT_NAME);

/**
 * The `chain.` event namespace (AUDIT_SPEC §3.4). Mirror verification reads the
 * whole namespace by prefix rather than the known names one by one: a row that
 * claims a `chain.*` event outside `CHAIN_MIRROR_EVENTS` is evidence of forgery
 * and must not be able to hide from the verifier by using an unmapped name.
 */
export const CHAIN_MIRROR_EVENT_PREFIX = "chain.";

/** A `propose` entry on a verified chain. */
export type ProposeEntry = ChainEntry & { readonly op: "propose" };

/**
 * One proposal on a verified chain (CRYPTO_SPEC §6.2 — identified by the
 * `propose` entry's hash): the entry itself and, when the proposal was applied,
 * the seq of the `approve` entry that reached the quorum (`null` while pending
 * or after a `withdraw`).
 */
export interface IndexedProposal {
  readonly entry: ProposeEntry;
  readonly completedAtSeq: number | null;
}

/**
 * Proposals of a verified chain keyed by the `propose` entry hash — the input
 * `chainMirrorEvents` needs for `approve` / `withdraw` rows (AUDIT_SPEC §3.4:
 * `proposalChainSeq` / `completed` / the applied inner-op row). Built once per
 * verified chain by {@link indexProposals}; the server (mirror writer) and the
 * CLI (`maruhi audit verify`) share that derivation so neither can drift.
 */
export type ProposalIndex = ReadonlyMap<string, IndexedProposal>;

/**
 * Derives the {@link ProposalIndex} of a verified chain. Completion is read
 * off the chain's consensus rules rather than re-evaluated: once a proposal
 * leaves the pending set (quorum reached or withdrawn) any later `approve` /
 * `withdraw` naming it is `unknown-proposal` and cannot be on a verified
 * chain. So a proposal that is absent from the final pending set and is not
 * named by a `withdraw` was completed by the **last** `approve` naming it.
 *
 * @param entries the verified chain (seq order)
 * @param entryHashAt entry hash by seq (CRYPTO_SPEC §4.1 history index)
 * @param pendingHashes hashes of the proposals still pending at the head
 */
export function indexProposals(
  entries: readonly ChainEntry[],
  entryHashAt: (seq: number) => string | undefined,
  pendingHashes: ReadonlySet<string>,
): ProposalIndex {
  const proposals = new Map<string, { entry: ProposeEntry; lastApproveSeq: number | null }>();
  const withdrawn = new Set<string>();
  for (const entry of entries) {
    if (entry.op === "propose") {
      // entryHashAt is defined for every seq of the verified chain
      // (the index is built from the same chain). undefined is a
      // caller-side inconsistency: that proposal is not indexed, and an
      // approve / withdraw referencing it surfaces as a contract
      // violation in referencedProposal
      const hash = entryHashAt(entry.seq);
      if (hash !== undefined) {
        proposals.set(hash, { entry, lastApproveSeq: null });
      }
    } else if (entry.op === "approve") {
      const proposal = proposals.get(entry.payload.proposalHashHex);
      if (proposal !== undefined) {
        proposal.lastApproveSeq = entry.seq;
      }
    } else if (entry.op === "withdraw") {
      withdrawn.add(entry.payload.proposalHashHex);
    }
  }
  const index = new Map<string, IndexedProposal>();
  for (const [hash, proposal] of proposals) {
    const closedByQuorum = !pendingHashes.has(hash) && !withdrawn.has(hash);
    index.set(hash, {
      entry: proposal.entry,
      completedAtSeq: closedByQuorum ? proposal.lastApproveSeq : null,
    });
  }
  return index;
}

/** The actor an operation is attributed to (the entry actor, or the proposer for an applied inner op), plus what the entry alone cannot tell. */
interface MirrorSubject {
  readonly actor: ChainActor;
  /**
   * `add_device` only: the fingerprint of the key the entry puts on the chain
   * (AUDIT_SPEC §3.4 `chain.device_added` payload). SHA-256 is asynchronous, so
   * the caller (the acceptance side effect — K3) computes it and hands it in;
   * the mapping itself stays synchronous. Missing for an `add_device` = a
   * contract violation (throw), never a silent row without the fingerprint.
   */
  readonly addedDeviceKeyFingerprintHex?: KeyFingerprintHex;
  /** An applied inner op only (§3.4 — PF1): the seq of the `propose` entry that carried it. */
  readonly viaProposalSeq?: number;
  /**
   * `approve` / `withdraw` only (§3.4): the seq of the proposal the entry
   * names, and — for an `approve` — whether this entry completed it. They come
   * from the proposal index; missing = a contract violation (throw).
   */
  readonly referenced?: { readonly proposalChainSeq: number; readonly completed: boolean };
}

/** The per-entry extra input of {@link chainMirrorEvents} (see {@link MirrorSubject}). */
export interface ChainMirrorSubject {
  readonly addedDeviceKeyFingerprintHex?: KeyFingerprintHex;
}

/** An applied row's `viaProposalSeq`, spread last into a mirror payload (§3.4 — PF1). */
function viaOf(subject: MirrorSubject): { readonly viaProposalSeq?: number } {
  return subject.viaProposalSeq === undefined ? {} : { viaProposalSeq: subject.viaProposalSeq };
}

/** The payload of a mirror row whose op copies nothing: none, or an applied row's `viaProposalSeq` alone. */
function viaOnly(subject: MirrorSubject): {
  readonly payload?: { readonly viaProposalSeq: number };
} {
  return subject.viaProposalSeq === undefined
    ? {}
    : { payload: { viaProposalSeq: subject.viaProposalSeq } };
}

/** The referenced proposal of an `approve` / `withdraw` mapping (handed in by chainMirrorEvents). */
function referencedOf(subject: MirrorSubject, op: "approve" | "withdraw") {
  if (subject.referenced === undefined) {
    throw new Error(`chain mirror: ${op} requires the referenced proposal`);
  }
  return subject.referenced;
}

// Per-op mappings (the §3.4 table). The input is op + payload (+ actor
// — only genesis's and add_device's targets use it), so it applies both
// to signed entries and to a proposal's inner op. genesis's target is the
// creator = actor (so the start of the membership interval can be looked
// up in Q1's index)
const mirrorTails: {
  readonly [K in ChainOp]: (
    operation: Extract<ChainOperation, { op: K }> & MirrorSubject,
  ) => MirrorTail;
} = {
  genesis: (operation) => ({
    event: MIRROR_EVENT_NAME.genesis,
    targetUserId: operation.actor.userId,
    ...viaOnly(operation),
  }),
  // scope is copied too (AUDIT_SPEC §3.4 — 2026-09-14 ES: material to reconstruct §4.1's per-environment access windows)
  add_member: (operation) => ({
    event: MIRROR_EVENT_NAME.add_member,
    targetUserId: operation.payload.targetUserId,
    payload: {
      role: operation.payload.role,
      scopeKind: operation.payload.scopeKind,
      scopeEnvironmentIds: operation.payload.scopeEnvironmentIds,
      ...viaOf(operation),
    },
  }),
  remove_member: (operation) => ({
    event: MIRROR_EVENT_NAME.remove_member,
    targetUserId: operation.payload.targetUserId,
    ...viaOnly(operation),
  }),
  change_role: (operation) => ({
    event: MIRROR_EVENT_NAME.change_role,
    targetUserId: operation.payload.targetUserId,
    payload: {
      newRole: operation.payload.newRole,
      scopeKind: operation.payload.scopeKind,
      scopeEnvironmentIds: operation.payload.scopeEnvironmentIds,
      ...viaOf(operation),
    },
  }),
  // dek_commitment is copied into the payload (AUDIT_SPEC §3.4 — for
  // matching audit rows against chain-published commitments)
  create_environment: (operation) => ({
    event: MIRROR_EVENT_NAME.create_environment,
    environmentId: operation.payload.environmentId,
    epoch: 1,
    payload: { dekCommitmentHex: operation.payload.dekCommitmentHex, ...viaOf(operation) },
  }),
  delete_environment: (operation) => ({
    event: MIRROR_EVENT_NAME.delete_environment,
    environmentId: operation.payload.environmentId,
    ...viaOnly(operation),
  }),
  rotate_epoch: (operation) => ({
    event: MIRROR_EVENT_NAME.rotate_epoch,
    environmentId: operation.payload.environmentId,
    epoch: operation.payload.newEpoch,
    payload: {
      reason: operation.payload.reason,
      dekCommitmentHex: operation.payload.dekCommitmentHex,
      ...viaOf(operation),
    },
  }),
  grant_server: (operation) => ({
    event: MIRROR_EVENT_NAME.grant_server,
    targetKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
    // lease_policy is deliberately not copied (AUDIT_SPEC §1-2 /
    // AUTH_SPEC §14-4): claim_value can contain external identifiers
    // such as repository names, so it is not brought into audit rows.
    // The source of truth for the policy is the chain (grant payload),
    // matchable via chain_seq. The scope (the internal environment_id
    // set) is copied per §3.4
    payload: { scopeEnvironmentIds: operation.payload.scopeEnvironmentIds, ...viaOf(operation) },
  }),
  revoke_server: (operation) => ({
    event: MIRROR_EVENT_NAME.revoke_server,
    targetKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
    ...viaOnly(operation),
  }),
  // Copies the notarized digests (per-environment epoch /
  // manifest_version / manifest_sig_hash / values_digest and
  // audit_head_hash) into the payload (AUDIT_SPEC §3.4. Audit seq and
  // row counts are not copied even into the payload: the chain payload
  // itself is designed not to contain seq — CRYPTO_SPEC §6.2)
  checkpoint: (operation) => ({
    event: MIRROR_EVENT_NAME.checkpoint,
    payload: {
      environments: operation.payload.environments.map((tuple) => ({
        environmentId: tuple.environmentId,
        epoch: tuple.epoch,
        manifestVersion: tuple.manifestVersion,
        manifestSigHashHex: tuple.manifestSigHashHex,
        valuesDigestHex: tuple.valuesDigestHex,
      })),
      auditHeadHashHex: operation.payload.auditHeadHashHex,
      ...viaOf(operation),
    },
  }),
  // Four-eyes (AUDIT_SPEC §3.4 — 2026-09-14 PF1). The inner payload is
  // not copied (the chain is the source of truth). approve / withdraw's
  // referenced proposal (proposalChainSeq) and completed come from the
  // proposal index (chainMirrorEvents hands them in)
  set_approval_policy: (operation) => ({
    event: MIRROR_EVENT_NAME.set_approval_policy,
    payload: {
      ops: operation.payload.ops,
      requiredApprovals: operation.payload.requiredApprovals,
      ...viaOf(operation),
    },
  }),
  propose: (operation) => ({
    event: MIRROR_EVENT_NAME.propose,
    payload: { innerOp: operation.payload.inner.op, expiresAtMs: operation.payload.expiresAtMs },
  }),
  approve: (operation) => {
    const referenced = referencedOf(operation, "approve");
    return {
      event: MIRROR_EVENT_NAME.approve,
      payload: { proposalChainSeq: referenced.proposalChainSeq, completed: referenced.completed },
    };
  },
  withdraw: (operation) => ({
    event: MIRROR_EVENT_NAME.withdraw,
    payload: { proposalChainSeq: referencedOf(operation, "withdraw").proposalChainSeq },
  }),
  // Device keys (AUDIT_SPEC §3.4 — 2026-09-19 DK). add_device's target
  // = actor (one can only add one's own device); payload = device FP +
  // cap. revoke_device's target = the target; payload = the revoked FP
  // list (§4.1's detection trigger ★ — the detection variant is K3)
  add_device: (operation) => {
    if (operation.addedDeviceKeyFingerprintHex === undefined) {
      throw new Error("chain mirror: add_device requires the added device's key fingerprint");
    }
    return {
      event: MIRROR_EVENT_NAME.add_device,
      targetUserId: operation.actor.userId,
      payload: {
        deviceKeyFingerprint: operation.addedDeviceKeyFingerprintHex,
        roleCap: operation.payload.roleCap,
        scopeKind: operation.payload.scopeKind,
        scopeEnvironmentIds: operation.payload.scopeEnvironmentIds,
        ...viaOf(operation),
      },
    };
  },
  revoke_device: (operation) => ({
    event: MIRROR_EVENT_NAME.revoke_device,
    targetUserId: operation.payload.targetUserId,
    payload: {
      deviceKeyFingerprints: operation.payload.deviceFingerprintsHex,
      ...viaOf(operation),
    },
  }),
};

function mirrorTailOf(operation: ChainOperation & MirrorSubject): MirrorTail {
  return mirrorTails[operation.op](operation as never);
}

/** The proposal an `approve` / `withdraw` entry names; a verified chain always has it. */
function referencedProposal(
  entry: ChainEntry & { readonly op: "approve" | "withdraw" },
  index: ProposalIndex,
): IndexedProposal {
  const proposal = index.get(entry.payload.proposalHashHex);
  if (proposal === undefined) {
    // On a verified chain the referenced propose always precedes
    // (unknown-proposal is an invalid entry). A missing one is a bug in
    // how the index was built — a contract violation of the mapping's
    // input
    throw new Error(
      `chain mirror: entry seq=${entry.seq} (${entry.op}) names a proposal that is not in the proposal index`,
    );
  }
  return proposal;
}

/**
 * Maps one accepted chain entry to its §3.4 mirror row(s): exactly one row per
 * entry, plus — for an `approve` that reached the quorum — the applied
 * inner-op row (same `chainSeq`, actor = the proposer, `clientTs` = the
 * approve entry's timestamp, payload = the inner op's mirror payload +
 * `viaProposalSeq`). The order is mirror row first, applied row second (the
 * server writes them in this order in one transaction; rotation detection
 * reads the applied row as the latest membership event of its target).
 *
 * `index` comes from {@link indexProposals} over the verified chain the entry
 * belongs to (only `approve` / `withdraw` entries consult it).
 */
export function chainMirrorEvents(
  entry: ChainEntry,
  serverTs: number,
  index: ProposalIndex,
  subject: ChainMirrorSubject = {},
): readonly AuditEventRecord[] {
  const base = {
    serverTs,
    clientTs: entry.timestampMs,
    chainSeq: entry.seq,
    actorType: "user" as const,
  };
  const rowOf = (actor: ChainActor, tail: MirrorTail): AuditEventRecord => ({
    ...tail,
    ...base,
    actorUserId: actor.userId,
    actorKeyFingerprintHex: actor.keyFingerprintHex,
  });
  if (entry.op === "add_device") {
    // add_device's mapping needs the added device's FP (MirrorSubject — the accepting side computes it and hands it in)
    return [
      rowOf(
        entry.actor,
        mirrorTailOf({
          ...entry,
          ...(subject.addedDeviceKeyFingerprintHex === undefined
            ? {}
            : { addedDeviceKeyFingerprintHex: subject.addedDeviceKeyFingerprintHex }),
        }),
      ),
    ];
  }
  if (entry.op === "withdraw") {
    const proposal = referencedProposal(entry, index);
    return [
      rowOf(
        entry.actor,
        mirrorTailOf({
          ...entry,
          referenced: { proposalChainSeq: proposal.entry.seq, completed: false },
        }),
      ),
    ];
  }
  if (entry.op !== "approve") {
    return [rowOf(entry.actor, mirrorTailOf(entry))];
  }
  const proposal = referencedProposal(entry, index);
  const completed = proposal.completedAtSeq === entry.seq;
  const approved = rowOf(
    entry.actor,
    mirrorTailOf({ ...entry, referenced: { proposalChainSeq: proposal.entry.seq, completed } }),
  );
  if (!completed) {
    return [approved];
  }
  // The applied row (AUDIT_SPEC §3.4): the inner op's mirror mapping with
  // viaProposalSeq; actor is the proposer (the inner op's actor). The
  // discipline exists so §4.1's membership intervals (Q1) and grant
  // intervals (Q6) keep the same input structure — detection reads the
  // same rows via the same index as direct appends
  const inner = proposal.entry.payload.inner;
  return [
    approved,
    rowOf(
      proposal.entry.actor,
      mirrorTailOf({ ...inner, actor: proposal.entry.actor, viaProposalSeq: proposal.entry.seq }),
    ),
  ];
}

// ---------------------------------------------------------------------------
// The aggregated form of `var.read` (AUDIT_SPEC §3.3): one row per
// environment per value-carrying bulk pull, carrying the enumeration of
// returned variables in its payload. Payload construction (the server's
// pull) and interpretation (the server's rotation-required detection,
// the §7 filter, the CLI's display) share one implementation — the
// enumeration's shape (sort, key order) determines the input bytes of
// row_digest (§5.1), so writer and reader live in one place.
// ---------------------------------------------------------------------------

/** The audit event name of a value read (AUDIT_SPEC §3.3). */
export const VAR_READ_EVENT = "var.read";

/** One variable listed by an aggregated `var.read` row (AUDIT_SPEC §3.3). */
export interface AuditReadVariable {
  readonly variableId: VariableId;
  readonly epoch: number;
  readonly version: number;
}

/** The payload of an aggregated `var.read` row (AUDIT_SPEC §3.3 — its schema in audit-payloads.ts). */
export type AuditReadPayload = ProjectAuditPayload<"var.read">;

/**
 * Builds the payload of an aggregated `var.read` row: the values whose
 * ciphertext one read returned, sorted by (`variableId` in code-unit order,
 * `version`) with the key order fixed to variableId → epoch → version. A bulk
 * pull returns each active variable at most once (one entry per variable);
 * the version value range (AUTH_SPEC §12-7 — 2026-09-27 VH) returns several
 * versions of one variable (one entry per version). No pair repeats. The
 * stored JSON bytes feed the audit row digest (AUDIT_SPEC §5.1), which is why
 * the shape is fixed here rather than left to the caller.
 */
export function auditReadPayload(variables: readonly AuditReadVariable[]): AuditReadPayload {
  const sorted = variables.toSorted((a, b) =>
    a.variableId < b.variableId ? -1 : a.variableId > b.variableId ? 1 : a.version - b.version,
  );
  return {
    variables: sorted.map(({ variableId, epoch, version }) => ({ variableId, epoch, version })),
  };
}

/**
 * Reads the variables listed by an aggregated `var.read` payload. Returns
 * `null` when the payload is not the aggregated form — an unrelated event
 * or a malformed payload. Entries that are not well-formed are skipped rather than
 * failing the caller (the audit log is server-managed data; a malformed entry
 * is corruption to surface, not a reason to abort rotation detection).
 */
export function auditReadVariablesOf(
  payload: Readonly<Record<string, unknown>> | null | undefined,
): readonly AuditReadVariable[] | null {
  const listed = payload?.["variables"];
  if (!Array.isArray(listed)) {
    return null;
  }
  return listed.flatMap((entry: unknown): AuditReadVariable[] => {
    if (typeof entry !== "object" || entry === null) {
      return [];
    }
    const { variableId, epoch, version } = entry as Record<string, unknown>;
    return typeof variableId === "string" &&
      isVariableId(variableId) &&
      Number.isInteger(epoch) &&
      Number.isInteger(version)
      ? [
          {
            variableId: decodeVariableId(variableId),
            epoch: epoch as number,
            version: version as number,
          },
        ]
      : [];
  });
}
