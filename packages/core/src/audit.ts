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

export interface AuditActor {
  readonly userId: UserId;
  readonly apiTokenId?: string;
  readonly authMethod?: AuthMethod;
}

export function auditActorOf(principal: AuthenticatedPrincipal): AuditActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

export function auditPayloadWith(
  actor: Pick<AuditActor, "authMethod">,
  payload: object | undefined,
): Readonly<Record<string, unknown>> {
  return {
    ...payload,
    ...(actor.authMethod === undefined ? {} : { authMethod: actor.authMethod }),
  };
}

export interface AuditEventColumns {
  readonly serverTs: number;
  readonly clientTs?: number;
  readonly actorType: "user" | "server" | "system";
  readonly actorUserId?: UserId;
  readonly actorKeyFingerprintHex?: KeyFingerprintHex;
  readonly actorApiTokenId?: string;
  readonly actorAuthMethod?: AuthMethod;
  readonly targetUserId?: UserId;
  readonly targetKeyFingerprintHex?: KeyFingerprintHex;
  readonly environmentId?: string;
  readonly variableId?: string;
  readonly epoch?: number;
  readonly version?: number;
  readonly chainSeq?: number;
}

export type AuditEventRecord = AuditEventColumns & ProjectAuditEventPayload;

export type AuditEventRecordOf<E extends ProjectAuditEventName> = AuditEventColumns &
  Extract<ProjectAuditEventPayload, { readonly event: E }>;

type MirrorTail = {
  readonly [E in ChainMirrorEventName]: Pick<
    AuditEventColumns,
    "targetUserId" | "targetKeyFingerprintHex" | "environmentId" | "epoch"
  > &
    Extract<ProjectAuditEventPayload, { readonly event: E }>;
}[ChainMirrorEventName];

const MIRROR_EVENT_NAME = {
  genesis: "chain.genesis",
  add_member: "chain.member_added",
  remove_member: "chain.member_removed",
  change_role: "chain.role_changed",
  create_environment: "chain.environment_created",
  delete_environment: "chain.environment_deleted",
  rotate_epoch: "chain.epoch_rotated",
  grant_server: "chain.server_granted",
  revoke_server: "chain.server_revoked",
  checkpoint: "chain.checkpointed",
  set_approval_policy: "chain.approval_policy_changed",
  propose: "chain.proposed",
  approve: "chain.approved",
  withdraw: "chain.proposal_withdrawn",
  add_device: "chain.device_added",
  revoke_device: "chain.device_revoked",
} as const satisfies { readonly [K in ChainOp]: ChainMirrorEventName };

export const CHAIN_MIRROR_EVENTS: readonly string[] = Object.values(MIRROR_EVENT_NAME);

export const CHAIN_MIRROR_EVENT_PREFIX = "chain.";

export type ProposeEntry = ChainEntry & { readonly op: "propose" };

export interface IndexedProposal {
  readonly entry: ProposeEntry;
  readonly completedAtSeq: number | null;
}

export type ProposalIndex = ReadonlyMap<string, IndexedProposal>;

export function indexProposals(
  entries: readonly ChainEntry[],
  entryHashAt: (seq: number) => string | undefined,
  pendingHashes: ReadonlySet<string>,
): ProposalIndex {
  const proposals = new Map<string, { entry: ProposeEntry; lastApproveSeq: number | null }>();
  const withdrawn = new Set<string>();
  for (const entry of entries) {
    if (entry.op === "propose") {
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

interface MirrorSubject {
  readonly actor: ChainActor;
  readonly addedDeviceKeyFingerprintHex?: KeyFingerprintHex;
  readonly viaProposalSeq?: number;
  readonly referenced?: { readonly proposalChainSeq: number; readonly completed: boolean };
}

export interface ChainMirrorSubject {
  readonly addedDeviceKeyFingerprintHex?: KeyFingerprintHex;
}

function viaOf(subject: MirrorSubject): { readonly viaProposalSeq?: number } {
  return subject.viaProposalSeq === undefined ? {} : { viaProposalSeq: subject.viaProposalSeq };
}

function viaOnly(subject: MirrorSubject): {
  readonly payload?: { readonly viaProposalSeq: number };
} {
  return subject.viaProposalSeq === undefined
    ? {}
    : { payload: { viaProposalSeq: subject.viaProposalSeq } };
}

function referencedOf(subject: MirrorSubject, op: "approve" | "withdraw") {
  if (subject.referenced === undefined) {
    throw new Error(`chain mirror: ${op} requires the referenced proposal`);
  }
  return subject.referenced;
}

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
    payload: { scopeEnvironmentIds: operation.payload.scopeEnvironmentIds, ...viaOf(operation) },
  }),
  revoke_server: (operation) => ({
    event: MIRROR_EVENT_NAME.revoke_server,
    targetKeyFingerprintHex: operation.payload.serverKeyFingerprintHex,
    ...viaOnly(operation),
  }),
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

function referencedProposal(
  entry: ChainEntry & { readonly op: "approve" | "withdraw" },
  index: ProposalIndex,
): IndexedProposal {
  const proposal = index.get(entry.payload.proposalHashHex);
  if (proposal === undefined) {
    throw new Error(
      `chain mirror: entry seq=${entry.seq} (${entry.op}) names a proposal that is not in the proposal index`,
    );
  }
  return proposal;
}

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
  const inner = proposal.entry.payload.inner;
  return [
    approved,
    rowOf(
      proposal.entry.actor,
      mirrorTailOf({ ...inner, actor: proposal.entry.actor, viaProposalSeq: proposal.entry.seq }),
    ),
  ];
}

export const VAR_READ_EVENT = "var.read";

export interface AuditReadVariable {
  readonly variableId: VariableId;
  readonly epoch: number;
  readonly version: number;
}

export type AuditReadPayload = ProjectAuditPayload<"var.read">;

export function auditReadPayload(variables: readonly AuditReadVariable[]): AuditReadPayload {
  const sorted = variables.toSorted((a, b) =>
    a.variableId < b.variableId ? -1 : a.variableId > b.variableId ? 1 : a.version - b.version,
  );
  return {
    variables: sorted.map(({ variableId, epoch, version }) => ({ variableId, epoch, version })),
  };
}

export interface RotationRecommendedVariable {
  readonly variableId: string;
  readonly basis: "read" | "readable";
}

export function rotationRecommendedVariablesOf(
  payload: Readonly<Record<string, unknown>> | null | undefined,
): readonly RotationRecommendedVariable[] | null {
  const listed = payload?.["variables"];
  if (!Array.isArray(listed)) {
    return null;
  }
  return listed.flatMap((entry: unknown): RotationRecommendedVariable[] => {
    if (typeof entry !== "object" || entry === null) {
      return [];
    }
    const { variableId, basis } = entry as Record<string, unknown>;
    return typeof variableId === "string"
      ? [{ variableId, basis: basis === "read" ? "read" : "readable" }]
      : [];
  });
}

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
