import type { EnvironmentId, UserId, VariableId } from "@maruhi/core";
import { ROTATION_CONNECTORS } from "@maruhi/core";
import type { ChainState } from "@maruhi/crypto";
import { proposalRecipientsOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DataRejectedError,
  DataStoreShape,
  RotationProposalRejectReason,
  StoredProposal,
  StoredProposalVariable,
} from "../data.package/index.ts";
import { dataEvent, DataStore, rejectData, requireMemberState } from "../data.package/index.ts";
import type { StateCache } from "../do/chain-store.ts";
import type { ChainStore } from "../do/chain-store.ts";
import { MAX_PENDING_ROTATION_PROPOSALS, MAX_ROTATION_PROPOSALS_PER_WINDOW } from "../policy.ts";
import { projectBytesExceeded } from "../quotas.ts";
import type { ServerKey } from "../server-key.ts";
import { observeStorageLevel, StorageMeter } from "../storage-guard.ts";
import type { LeaseRejection, LeaseTokenFacts } from "./programs-lease.ts";
import { authorizeWorkload, recordDenied } from "./programs-lease.ts";

export type RotationConnector = (typeof ROTATION_CONNECTORS)[number];

export interface ProposalWrapInput {
  readonly recipientUserId: UserId;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface ProposalVariableInput {
  readonly variableId: VariableId;
  readonly baseVersion: number;
  readonly wraps: readonly ProposalWrapInput[];
}

export interface RotationProposalInput {
  readonly proposalId: string;
  readonly connector: RotationConnector;
  readonly facts: readonly string[];
  readonly expiresInDays: number;
  readonly variables: readonly ProposalVariableInput[];
}

export type ProposalRejection =
  | LeaseRejection
  | { readonly kind: "proposal-rejected"; readonly reason: RotationProposalRejectReason };

export interface ProposalReceipt {
  readonly proposalId: string;
  readonly expiresAtMs: number;
}

export type ProposalOutcome =
  | { readonly kind: "ok"; readonly value: ProposalReceipt }
  | { readonly kind: "rejected"; readonly rejection: ProposalRejection };

export interface MemberProposalValue extends Omit<StoredProposal, "connector"> {
  readonly connector: RotationConnector;
}

export interface ProposalResolutionInput {
  readonly outcome: "accepted" | "rejected";
  readonly versions: readonly { readonly variableId: VariableId; readonly version: number }[];
}

function proposalRecipientKeys(
  state: ChainState,
  environmentId: EnvironmentId,
): ReadonlySet<string> {
  return new Set(
    proposalRecipientsOf(state, environmentId).map(
      ({ member, device }) => `${member.userId}:${device.encPubHex}`,
    ),
  );
}

function storedConnector(value: string): RotationConnector {
  const found = ROTATION_CONNECTORS.find((connector) => connector === value);
  if (found === undefined) {
    throw new Error("unexpected connector in stored proposal row");
  }
  return found;
}

function recipientsMatch(
  expected: ReadonlySet<string>,
  wraps: readonly Pick<ProposalWrapInput, "recipientUserId" | "recipientEncPubHex">[],
): boolean {
  const seen = new Set<string>();
  for (const wrap of wraps) {
    const key = `${wrap.recipientUserId}:${wrap.recipientEncPubHex}`;
    if (!expected.has(key) || seen.has(key)) {
      return false;
    }
    seen.add(key);
  }
  return seen.size === expected.size;
}

function namesVariableTwice(variables: readonly { readonly variableId: VariableId }[]): boolean {
  return new Set(variables.map((variable) => variable.variableId)).size !== variables.length;
}

const variableRefusal = Effect.fnUntraced(function* (
  store: DataStoreShape,
  environmentId: EnvironmentId,
  recipients: ReadonlySet<string>,
  variable: ProposalVariableInput,
  nowMs: number,
): Effect.fn.Return<RotationProposalRejectReason | null> {
  const stored = yield* store.findVariable(environmentId, variable.variableId);
  if (stored === null || stored.deletedAtMs !== null || stored.latestStatus !== "active") {
    return "variable-inactive";
  }
  if (stored.latestVersion !== variable.baseVersion) {
    return "base-version-stale";
  }
  if (!recipientsMatch(recipients, variable.wraps)) {
    return "recipients-mismatch";
  }
  return (yield* store.variableHasPendingProposal(environmentId, variable.variableId, nowMs))
    ? "variable-pending"
    : null;
});

const proposalRefusal = Effect.fn("programs-proposal.proposalRefusal")(function* (
  store: DataStoreShape,
  state: ChainState,
  environmentId: EnvironmentId,
  proposal: RotationProposalInput,
  nowMs: number,
): Effect.fn.Return<RotationProposalRejectReason | null> {
  if (yield* store.proposalExists(proposal.proposalId)) {
    return "duplicate-id";
  }
  if (namesVariableTwice(proposal.variables)) {
    return "duplicate-variable";
  }
  const recipients = proposalRecipientKeys(state, environmentId);
  for (const variable of proposal.variables) {
    const reason = yield* variableRefusal(store, environmentId, recipients, variable, nowMs);
    if (reason !== null) {
      return reason;
    }
  }
  const pending = yield* store.countPendingProposals(nowMs);
  if (pending >= MAX_PENDING_ROTATION_PROPOSALS) {
    return "pending-limit";
  }
  const stored = yield* store.totalCiphertextBytes;
  return projectBytesExceeded(stored, proposalCiphertextBytes(proposal)) ? "storage-limit" : null;
});

function proposalCiphertextBytes(proposal: RotationProposalInput): number {
  let total = 0;
  for (const variable of proposal.variables) {
    for (const wrap of variable.wraps) {
      total += wrap.ciphertextHex.length / 2;
    }
  }
  return total;
}

export const proposeRotationProgram = Effect.fn("programs-proposal.proposeRotationProgram")(
  function* (
    environmentId: EnvironmentId,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
    proposal: RotationProposalInput,
    cache: StateCache,
  ): Effect.fn.Return<
    ProposalReceipt,
    ProposalRejection,
    ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
  > {
    const { state, grant, nowMs } = yield* authorizeWorkload(
      environmentId,
      ephemeralPubHex,
      facts,
      cache,
    );
    const store = yield* DataStore;
    if (store.isMirrorSync()) {
      return yield* Effect.fail<ProposalRejection>({
        kind: "proposal-rejected",
        reason: "mirror-read-only",
      });
    }
    yield* ensureStorageAdmitsMint;
    const window = yield* store.checkLeaseWindow(
      "proposed",
      MAX_ROTATION_PROPOSALS_PER_WINDOW,
      nowMs,
    );
    if (!window.allowed) {
      yield* recordDenied("rate-limited", facts.claimsDigestHex, nowMs);
      return yield* Effect.fail<ProposalRejection>({
        kind: "rate-limited",
        retryAfterSeconds: window.retryAfterSeconds,
      });
    }
    yield* sweepExpired(nowMs);
    const reason = yield* proposalRefusal(store, state, environmentId, proposal, nowMs);
    if (reason !== null) {
      return yield* Effect.fail<ProposalRejection>({ kind: "proposal-rejected", reason });
    }
    const expiresAtMs = nowMs + proposal.expiresInDays * DAY_MS;
    const audit = yield* AuditStore;
    yield* Effect.sync(() => {
      store.recordLeaseWindowUse("proposed", nowMs);
      store.recordLeaseBinding(
        facts.bindingKeyHex,
        ephemeralPubHex,
        facts.bindingExpiresAtMs,
        nowMs,
      );
      store.write.insertProposal(
        {
          proposalId: proposal.proposalId,
          environmentId,
          connector: proposal.connector,
          facts: proposal.facts,
          claimsDigestHex: facts.claimsDigestHex,
          grantChainSeq: grant.grantSeq,
          expiresAtMs,
          variables: proposal.variables,
        },
        nowMs,
      );
      audit.appendSync({
        event: "rotation.proposed",
        serverTs: nowMs,
        actorType: "system",
        environmentId,
        payload: {
          proposalId: proposal.proposalId,
          variableIds: proposal.variables.map((variable) => variable.variableId),
          claimsDigest: facts.claimsDigestHex,
          grantChainSeq: grant.grantSeq,
          connector: proposal.connector,
        },
      });
    });
    return { proposalId: proposal.proposalId, expiresAtMs };
  },
);

const sweepExpired = Effect.fn("programs-proposal.sweepExpired")(function* (
  nowMs: number,
  except?: string,
): Effect.fn.Return<void, never, DataStore | AuditStore> {
  const store = yield* DataStore;
  const audit = yield* AuditStore;
  yield* Effect.sync(() => {
    for (const expired of store.write.deleteExpiredProposals(nowMs, except)) {
      audit.appendSync({
        event: "rotation.proposal_expired",
        serverTs: nowMs,
        actorType: "system",
        environmentId: expired.environmentId,
        payload: { proposalId: expired.proposalId, expiresAtMs: expired.expiresAtMs },
      });
    }
  });
});

const DAY_MS = 24 * 60 * 60 * 1000;

const ensureStorageAdmitsMint: Effect.Effect<void, ProposalRejection, StorageMeter> = Effect.gen(
  function* () {
    if ((yield* observeStorageLevel) === "reject") {
      return yield* Effect.fail<ProposalRejection>({
        kind: "proposal-rejected",
        reason: "storage-limit",
      });
    }
  },
);

export interface PreflightVariableInput {
  readonly variableId: VariableId;
  readonly baseVersion: number;
}

export interface PreflightRecipientInput {
  readonly userId: UserId;
  readonly encPubHex: string;
}

export type PreflightOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "rejected"; readonly rejection: ProposalRejection };

export const preflightRotationProgram = Effect.fn("programs-proposal.preflightRotationProgram")(
  function* (
    environmentId: EnvironmentId,
    ephemeralPubHex: string,
    facts: LeaseTokenFacts,
    variables: readonly PreflightVariableInput[],
    cache: StateCache,
    recipients: readonly PreflightRecipientInput[],
  ): Effect.fn.Return<
    void,
    ProposalRejection,
    ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
  > {
    const { state } = yield* authorizeWorkload(environmentId, ephemeralPubHex, facts, cache);
    const store = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;
    if (store.isMirrorSync()) {
      return yield* preflightRefusal("mirror-read-only");
    }
    yield* ensureStorageAdmitsMint;
    const window = yield* store.checkLeaseWindow(
      "proposed",
      MAX_ROTATION_PROPOSALS_PER_WINDOW,
      nowMs,
    );
    if (!window.allowed) {
      return yield* Effect.fail<ProposalRejection>({
        kind: "rate-limited",
        retryAfterSeconds: window.retryAfterSeconds,
      });
    }
    yield* sweepExpired(nowMs);
    if (namesVariableTwice(variables)) {
      return yield* preflightRefusal("duplicate-variable");
    }
    for (const variable of variables) {
      yield* preflightVariable(store, environmentId, variable, nowMs);
    }
    if (
      !recipientsMatch(
        proposalRecipientKeys(state, environmentId),
        recipients.map((recipient) => ({
          recipientUserId: recipient.userId,
          recipientEncPubHex: recipient.encPubHex,
        })),
      )
    ) {
      return yield* preflightRefusal("recipients-mismatch");
    }
    if ((yield* store.countPendingProposals(nowMs)) >= MAX_PENDING_ROTATION_PROPOSALS) {
      return yield* preflightRefusal("pending-limit");
    }
  },
);

const preflightRefusal = (reason: RotationProposalRejectReason) =>
  Effect.fail<ProposalRejection>({ kind: "proposal-rejected", reason });

const preflightVariable = Effect.fnUntraced(function* (
  store: DataStore["Service"],
  environmentId: EnvironmentId,
  variable: PreflightVariableInput,
  nowMs: number,
): Effect.fn.Return<void, ProposalRejection> {
  const stored = yield* store.findVariable(environmentId, variable.variableId);
  if (stored === null || stored.deletedAtMs !== null || stored.latestStatus !== "active") {
    return yield* preflightRefusal("variable-inactive");
  }
  if (stored.latestVersion !== variable.baseVersion) {
    return yield* preflightRefusal("base-version-stale");
  }
  if (yield* store.variableHasPendingProposal(environmentId, variable.variableId, nowMs)) {
    return yield* preflightRefusal("variable-pending");
  }
});

function ownView(proposal: StoredProposal, userId: UserId): MemberProposalValue {
  return {
    ...proposal,
    connector: storedConnector(proposal.connector),
    variables: proposal.variables.map((variable): StoredProposalVariable => ({
      ...variable,
      wraps: variable.wraps.filter((wrap) => wrap.recipientUserId === userId),
    })),
  };
}

export const listRotationProposalsProgram = Effect.fn(
  "programs-proposal.listRotationProposalsProgram",
)(function* (actor: DataActor, cache: StateCache) {
  const { member } = yield* requireMemberState(actor.userId, "member", cache);
  const store = yield* DataStore;
  const nowMs = yield* Clock.currentTimeMillis;
  if (!store.isMirrorSync()) {
    yield* sweepExpired(nowMs);
  }
  const pending = yield* store.listPendingProposals(nowMs);
  return pending
    .filter((proposal) => scopeIncludesEnvironment(member.scope, proposal.environmentId))
    .map((proposal) => ownView(proposal, actor.userId));
});

const versionsRefusal = Effect.fn("programs-proposal.versionsRefusal")(function* (
  store: DataStoreShape,
  proposal: StoredProposal,
  versions: ProposalResolutionInput["versions"],
): Effect.fn.Return<RotationProposalRejectReason | null> {
  for (const variable of proposal.variables) {
    const named = versions.find((entry) => entry.variableId === variable.variableId);
    if (named === undefined || named.version <= variable.baseVersion) {
      return "version-missing";
    }
    const anchor = yield* store.versionAnchor(
      proposal.environmentId,
      variable.variableId,
      named.version,
    );
    if (anchor === null) {
      return "version-missing";
    }
  }
  return null;
});

export const resolveRotationProposalProgram = Effect.fn(
  "programs-proposal.resolveRotationProposalProgram",
)(function* (
  actor: DataActor,
  proposalId: string,
  resolution: ProposalResolutionInput,
  cache: StateCache,
): Effect.fn.Return<void, DataRejectedError, ChainStore | DataStore | AuditStore> {
  const { member } = yield* requireMemberState(actor.userId, "member", cache);
  const nowMs = yield* Clock.currentTimeMillis;
  yield* sweepExpired(nowMs, proposalId);
  const store = yield* DataStore;
  const proposal = yield* store.findProposal(proposalId);
  if (proposal === null) {
    return yield* rejectData({ kind: "rotation-proposal-not-found", proposalId });
  }
  if (!scopeIncludesEnvironment(member.scope, proposal.environmentId)) {
    return yield* rejectData({ kind: "rotation-proposal-not-found", proposalId });
  }
  if (resolution.outcome === "accepted") {
    const reason = yield* versionsRefusal(store, proposal, resolution.versions);
    if (reason !== null) {
      return yield* rejectData({ kind: "rotation-proposal-rejected", reason });
    }
  }
  const audit = yield* AuditStore;
  yield* Effect.sync(() => {
    store.write.deleteProposal(proposalId);
    audit.appendSync(
      dataEvent(
        actor,
        nowMs,
        resolution.outcome === "accepted"
          ? {
              event: "rotation.proposal_accepted",
              environmentId: proposal.environmentId,
              payload: { proposalId, versions: resolution.versions },
            }
          : {
              event: "rotation.proposal_rejected",
              environmentId: proposal.environmentId,
              payload: { proposalId },
            },
      ),
    );
  });
});
