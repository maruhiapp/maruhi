import type { UserId } from "@maruhi/core";
import type { ChainEntry, ChainState, Role } from "@maruhi/crypto";
import { Clock, Data, Effect } from "effect";

import type { AuditStore } from "../audit-store.ts";
import { standaloneCheckpointProgram } from "../checkpoint-accept.ts";
import type {
  DataOutcome,
  DataRejectedError,
  DataRejection,
  StoredHeadAttestation,
} from "../data.package/index.ts";
import { DataStore, rejectData, requireMemberState } from "../data.package/index.ts";
import type { AppliedProposal } from "../do/chain-accept.ts";
import { ensureParentHead, verifyAcceptableEntry } from "../do/chain-accept.ts";
import { commitAcceptedEntry } from "../do/chain-commit.ts";
import type { StateCache } from "../do/chain-store.ts";
import { ChainStore, deriveStoredState, updateStateCache } from "../do/chain-store.ts";
import { ensureProjectDoTables } from "../do/do-schema.ts";
import { MAX_DEVICES_PER_MEMBER } from "../policy.ts";
import { ensureProposalAdmitted } from "../quotas.ts";
import type { StorageMeter } from "../storage-guard.ts";
import { ensureStorageAdmitsGrowth } from "../storage-guard.ts";

class AlreadyInitializedError extends Data.TaggedError("AlreadyInitialized")<{
  readonly genesisActorUserId: string;
  readonly headSeq: number;
  readonly headHashHex: string;
}> {}
class ProjectIdMismatchError extends Data.TaggedError("ProjectIdMismatch")<object> {}
class FreshInitNotAdmittedError extends Data.TaggedError("FreshInitNotAdmitted")<object> {}

export interface ChainHeadValue {
  readonly headSeq: number;
  readonly headHashHex: string;
}

export interface AppendValue extends ChainHeadValue {
  readonly appliedProposal: AppliedProposal | null;
}

export interface ChainSnapshotValue {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly attestations: readonly StoredHeadAttestation[];
}

export type InitOutcome =
  | { readonly kind: "initialized"; readonly headSeq: number; readonly headHashHex: string }
  | {
      readonly kind: "already-initialized";
      readonly genesisActorUserId: string;
      readonly headSeq: number;
      readonly headHashHex: string;
    }
  | {
      readonly kind: "fresh-not-admitted";
    }
  | { readonly kind: "project-id-mismatch" }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

export interface InitAdmission {
  readonly admitFresh: boolean;
}

export type AppendOutcome = DataOutcome<AppendValue>;

export type SnapshotOutcome = DataOutcome<ChainSnapshotValue>;

function ensureChainMember(
  members: ReadonlyMap<string, unknown>,
  userId: UserId,
): Effect.Effect<void, DataRejectedError> {
  return members.has(userId) ? Effect.void : Effect.fail(rejectData({ kind: "not-member" }));
}

export const initProgram = Effect.fn("programs-chain.initProgram")(function* (
  expectedProjectId: string,
  entry: ChainEntry,
  admission: InitAdmission,
  storage: DurableObjectStorage,
  cache: StateCache,
) {
  const store = yield* ChainStore;
  const chain = yield* store.load;
  if (chain.headSeq > 0) {
    const genesisActor = chain.entries[0]?.actor.userId;
    if (genesisActor === undefined || chain.headHashHex === null) {
      return yield* Effect.die(new Error("initialized chain is missing genesis or head"));
    }
    return yield* new AlreadyInitializedError({
      genesisActorUserId: genesisActor,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
    });
  }
  if (!admission.admitFresh) {
    return yield* new FreshInitNotAdmittedError();
  }
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  if (applied.state.headHashHex !== expectedProjectId) {
    return yield* new ProjectIdMismatchError();
  }
  yield* Effect.sync(() => ensureProjectDoTables(storage));
  yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
});

const loadChainForMember = Effect.fn("programs-chain.loadChainForMember")(function* (
  callerUserId: UserId,
  cache: StateCache,
) {
  const store = yield* ChainStore;
  const chain = yield* store.load;
  if (chain.headSeq === 0 || chain.headHashHex === null) {
    return yield* rejectData({ kind: "not-initialized" });
  }
  const { state } = yield* deriveStoredState(chain, cache);
  yield* ensureChainMember(state.members, callerUserId);
  return {
    entries: chain.entries,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
    genesisHashHex: chain.genesisHashHex,
    totalCanonicalBytes: chain.totalCanonicalBytes,
    members: state.members,
    state,
  };
});

function growsAccessSet(entry: ChainEntry, state: ChainState): boolean {
  if (entry.op === "propose") {
    return isGrowthOp(entry.payload.inner.op);
  }
  if (entry.op === "approve") {
    const pending = state.pendingProposals.get(entry.payload.proposalHashHex);
    return pending !== undefined && isGrowthOp(pending.inner.op);
  }
  return isGrowthOp(entry.op);
}

const isGrowthOp = (op: ChainEntry["op"]): boolean => op === "add_member" || op === "grant_server";

export const appendProgram = Effect.fn("programs-chain.appendProgram")(function* (
  parentHeadHashHex: string,
  entry: ChainEntry,
  callerUserId: UserId,
  cache: StateCache,
): Effect.fn.Return<
  AppendValue,
  DataRejectedError,
  ChainStore | AuditStore | DataStore | StorageMeter
> {
  if (
    entry.op === "create_environment" ||
    entry.op === "rotate_epoch" ||
    entry.op === "delete_environment"
  ) {
    return yield* rejectData({ kind: "composite-required", op: entry.op });
  }
  if (entry.op === "checkpoint") {
    return yield* standaloneCheckpointProgram(parentHeadHashHex, entry, callerUserId, cache);
  }
  const chain = yield* loadChainForMember(callerUserId, cache);
  if (growsAccessSet(entry, chain.state)) {
    yield* ensureStorageAdmitsGrowth;
  }
  if (entry.op === "propose") {
    yield* ensureProposalAdmitted(
      entry.payload.expiresAtMs,
      chain.state.pendingProposals,
      yield* Clock.currentTimeMillis,
    );
  }
  if (entry.op === "add_device") {
    const active = chain.state.members.get(callerUserId)?.devices.size ?? 0;
    if (active >= MAX_DEVICES_PER_MEMBER) {
      return yield* rejectData({ kind: "device-limit", limit: MAX_DEVICES_PER_MEMBER });
    }
  }
  yield* ensureParentHead(chain, parentHeadHashHex);
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  const appliedProposal = yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return {
    headSeq: applied.state.headSeq,
    headHashHex: applied.state.headHashHex,
    appliedProposal,
  };
});

export const snapshotProgram = Effect.fn("programs-chain.snapshotProgram")(function* (
  callerUserId: UserId,
  cache: StateCache,
): Effect.fn.Return<ChainSnapshotValue, DataRejectedError, ChainStore | DataStore> {
  const chain = yield* loadChainForMember(callerUserId, cache);
  const dataStore = yield* DataStore;
  const attestations = (yield* dataStore.listHeadAttestations).filter((attestation) =>
    chain.members
      .get(attestation.attesterUserId)
      ?.devices.has(attestation.attesterKeyFingerprintHex),
  );
  return {
    entries: chain.entries,
    headSeq: chain.headSeq,
    headHashHex: chain.headHashHex,
    attestations,
  };
});

export const memberRoleProgram = (
  callerUserId: UserId,
  cache: StateCache,
): Effect.Effect<Role, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(callerUserId, "reader", cache), (context) => context.member.role);
