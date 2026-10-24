// The chain API's programs (CRYPTO_SPEC §6.4; AUTH_SPEC §11-2 / §11-3 /
// §12-8): the genesis acceptance (init), the generic append with its
// acceptance policies, the chain get and the caller's chain-derived role,
// with the values and outcomes the project DO's RPC methods (chain-do.ts)
// return. The 4 acceptance steps themselves are chain-accept.ts and
// chain-commit.ts, shared with the composite path (composite-programs.ts).
//
// The permit-serialization premise is the same as the other programs-*.

import type { UserId } from "@maruhi/core";
import type { ChainEntry, ChainState, Role } from "@maruhi/crypto";
import { Clock, Data, Effect } from "effect";

import type { AuditStore } from "../audit-store.ts";
import { standaloneCheckpointProgram } from "../checkpoint-accept.ts";
import { requireMemberState } from "../data/data-guards.ts";
import type { DataOutcome, DataRejectedError, DataRejection } from "../data/data-rejection.ts";
import { rejectData } from "../data/data-rejection.ts";
import type { StoredHeadAttestation } from "../data/data-store.ts";
import { DataStore } from "../data/data-store.ts";
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

// ---------------------------------------------------------------------------
// Typed errors (internal to the DO) and the outcome types at the RPC
// boundary
//
// Chain-API rejections also travel as DataRejection (data-rejection.ts): the
// tagged-error → outcome mapping is the single toDataOutcome (chain-do.ts),
// and the rejection → api-schema error mapping is consolidated into the one
// worker-side table rejectionErrors (data-http.ts — a Record shape whose
// exhaustiveness is type-enforced). Only init keeps a dedicated outcome,
// because it has a non-rejection branch — "already initialized" (the
// decision input of idempotent repair).
// ---------------------------------------------------------------------------

class AlreadyInitializedError extends Data.TaggedError("AlreadyInitialized")<{
  readonly genesisActorUserId: string;
  readonly headSeq: number;
  readonly headHashHex: string;
}> {}
class ProjectIdMismatchError extends Data.TaggedError("ProjectIdMismatch")<object> {}
/**
 * An init to an uninitialized DO arrived with the instruction "do not
 * admit a fresh initialization" from the worker's acceptance check (the
 * AUTH_SPEC §11-3 project-count limit). Reached only after the
 * existing-chain check — when already initialized, AlreadyInitialized
 * (the repair path) stands first.
 */
class FreshInitNotAdmittedError extends Data.TaggedError("FreshInitNotAdmitted")<object> {}

/** The chain head (the RPC value of a successful acceptance). */
export interface ChainHeadValue {
  readonly headSeq: number;
  readonly headHashHex: string;
}

/**
 * The acceptance result of a generic append: the new head + the proposal
 * a completed approve applied (four-eyes — K5). The worker runs the same
 * D1 post-processing as a direct append on `appliedProposal.inner`
 * (invite completed cross-check, membership projection). Not carried on
 * the wire (HTTP response)
 */
export interface AppendValue extends ChainHeadValue {
  readonly appliedProposal: AppliedProposal | null;
}

/**
 * A whole-chain snapshot (the RPC value of a successful get).
 * attestations are **only the latest head attestations of the current
 * members' valid devices** (AUTH_SPEC §16-1 — on top of the row deletion
 * at remove / revoke_device acceptance [chain-accept.ts], the
 * distribution side independently narrows to the current members' device
 * set as a separate defensive layer).
 */
export interface ChainSnapshotValue {
  readonly entries: readonly ChainEntry[];
  readonly headSeq: number;
  readonly headHashHex: string;
  readonly attestations: readonly StoredHeadAttestation[];
}

/** The initialization result crossing the RPC boundary (structured clone). */
export type InitOutcome =
  | { readonly kind: "initialized"; readonly headSeq: number; readonly headHashHex: string }
  | {
      /**
       * Already initialized. The genesis actor and the current head are
       * returned as the decision input of the worker-side idempotent
       * repair (AUTH_SPEC §11-3: a missing projects row + requester =
       * genesis actor counts as success).
       */
      readonly kind: "already-initialized";
      readonly genesisActorUserId: string;
      readonly headSeq: number;
      readonly headHashHex: string;
    }
  | {
      /**
       * Was uninitialized, but the worker's acceptance check (AUTH_SPEC
       * §11-3 — the org's project-count limit) did not admit a fresh
       * initialization (admitFresh = false). Nothing was written. The
       * worker maps it to 429 ProjectLimit. An initialized DO never
       * reaches this branch and proceeds to already-initialized (repair
       * path / 409)
       */
      readonly kind: "fresh-not-admitted";
    }
  | { readonly kind: "project-id-mismatch" }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

/**
 * The acceptance instruction of init (worker → DO). `admitFresh` =
 * whether a fresh initialization of an uninitialized DO is admitted (the
 * decision result of the AUTH_SPEC §11-3 project-count limit). Even with
 * false, the DO decides "already initialized?" inside its own
 * serialization before answering, so at the limit the §11-3 repair path
 * (already-initialized + missing row) is not blocked.
 */
export interface InitAdmission {
  readonly admitFresh: boolean;
}

/** The append result crossing the RPC boundary. */
export type AppendOutcome = DataOutcome<AppendValue>;

/** The chain-get result crossing the RPC boundary. */
export type SnapshotOutcome = DataOutcome<ChainSnapshotValue>;

// ---------------------------------------------------------------------------
// The Effect programs (the body of chain verification and acceptance
// decisions)
// ---------------------------------------------------------------------------

/** §6.2 / §11-2: reject anything that is not a chain-derived member (reader included). */
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
      // With headSeq > 0 both values exist as an invariant. Missing
      // means storage corruption; do not convert it into a success
      // response with an empty string — drop as a defect
      return yield* Effect.die(new Error("initialized chain is missing genesis or head"));
    }
    return yield* new AlreadyInitializedError({
      genesisActorUserId: genesisActor,
      headSeq: chain.headSeq,
      headHashHex: chain.headHashHex,
    });
  }
  // The AUTH_SPEC §11-3 project-count limit (already judged by the
  // worker): at the limit, decline only a fresh initialization. Placing
  // it after the "already initialized?" check (above) lets a repair
  // re-init (already-initialized) of an at-limit org through regardless
  // of the limit — this ordering is the implementation point of §11-3's
  // "do not block the repair path at the limit"
  if (!admission.admitFresh) {
    return yield* new FreshInitNotAdmittedError();
  }
  // The 4 acceptance steps for an empty chain (the capacity check is
  // vacuously satisfied on an empty chain). Anything other than
  // genesis, a bad signature, etc. is rejected by verifyChain with a
  // §6.3 reason code. On the Schema init accepts every op, but a
  // non-genesis at seq 1 always becomes a 422 under verifyChain's
  // framing rule (bad-genesis) — the four-eyes acceptance policy
  // (appendProgram) is not placed on init because of this invariant
  // (independent review D3)
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  // Project ID = genesis entry hash (§6.4). If the binding between the
  // routed DO and the entry is broken, do not accept (defense against a
  // worker-side bug)
  if (applied.state.headHashHex !== expectedProjectId) {
    return yield* new ProjectIdMismatchError();
  }
  // The genesis is accepted: materialize the DO's tables now (Sc-7 / A-4,
  // owner approval 2026-10-11 — AUTH_SPEC §14-3 / §11-3). Placed after every
  // refusal branch above (already-initialized, not-admitted, rejected,
  // project-id-mismatch), so a refused or probing request leaves no storage.
  yield* Effect.sync(() => ensureProjectDoTables(storage));
  yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
});

/**
 * The front stage shared by reads and appends: the initialization check
 * and the chain-derived membership check (§6.2 / §11-2). A non-member
 * gets nothing back, including the CAS's current-head information and
 * the acceptance policy's decision (the worker maps not-member to 404).
 */
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
    // The current derived state (the reference of the four-eyes
    // acceptance policy and the growth guard — appendProgram)
    state,
  };
});

/**
 * Whether the op grows the access set (the target of the AUTH_SPEC §12-8
 * growth guard). Besides a directly appended `add_member` / `grant_server`,
 * the four-eyes path stops **at the entry where the intent first
 * appears** (design record es-design.md §11 K5-D): a `propose` whose
 * inner op is a growth op, and an `approve` whose referenced pending
 * proposal's inner op is a growth op (regardless of whether it
 * completes). An `approve` whose referent is not pending is out of
 * scope (verifyChain rejects it with `unknown-proposal`). `withdraw`
 * (releases), `set_approval_policy` (bounded by chain capacity), and
 * proposals and approvals of remove / revoke / change_role
 * (remediation) are accepted even under rejection (§12-8 (b)(c)).
 */
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

/**
 * The acceptance program of a generic chain append (storage-guard.test.ts
 * also runs it, and pins under a StorageMeter with substituted
 * measurements both the rejection of add_member / grant_server and the
 * non-blocking of remove_member / checkpoint).
 */
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
  // AUTH_SPEC §6 / §12-4: create_environment / rotate_epoch /
  // delete_environment go only through the composite endpoints. The worker
  // handler refuses ahead of it, but the same guard sits on the DO side —
  // the authority of the acceptance decision — so that even if more call
  // paths into the generic append appear later, the state "the epoch /
  // environment is on the chain but the wraps / environment row are
  // missing" or "the chain says deleted but the data remains" can never be
  // created (defense in layers)
  if (
    entry.op === "create_environment" ||
    entry.op === "rotate_epoch" ||
    entry.op === "delete_environment"
  ) {
    return yield* rejectData({ kind: "composite-required", op: entry.op });
  }
  // A standalone (periodic) checkpoint (AUTH_SPEC §16-2): the generic
  // append accepts it, but branches into a dedicated path that performs
  // the acceptance verification (content cross-check against the state
  // at acceptance time) and the atomic snapshot save
  if (entry.op === "checkpoint") {
    return yield* standaloneCheckpointProgram(parentHeadHashHex, entry, callerUserId, cache);
  }
  const chain = yield* loadChainForMember(callerUserId, cache);
  // The DO storage total guard (AUTH_SPEC §12-8): only the
  // access-set-growing add_member / grant_server (both direct appends
  // and four-eyes proposals / approvals — growsAccessSet); aligned at
  // the entry because the natural follow-up wrap backfill is what is
  // rejected. remove_member / revoke_server / change_role (revocation,
  // permission narrowing = security remediation) and checkpoint
  // (bounded) are accepted even under rejection. Position: after
  // membership (§11-2), before CAS / verifyChain (resource protection
  // first)
  if (growsAccessSet(entry, chain.state)) {
    yield* ensureStorageAdmitsGrowth;
  }
  // The four-eyes propose acceptance policy (AUTH_SPEC §12-8 /
  // CRYPTO_SPEC §6.4 — not a consensus rule): the expires_at_ms upper
  // bound → the pending cap (expired ones do not count). The decision
  // inputs are the current derived state and the server clock, which
  // only the DO has (never placed on the worker — K5-B). Position: same
  // as the growth guard — "before the semantic checks (CAS /
  // verifyChain)"
  if (entry.op === "propose") {
    yield* ensureProposalAdmitted(
      entry.payload.expiresAtMs,
      chain.state.pendingProposals,
      yield* Clock.currentTimeMillis,
    );
  }
  // The device-count acceptance policy (AUTH_SPEC §12-8 / CRYPTO_SPEC
  // §6.4 — 2026-09-19 DK K3): an `add_device` is not accepted when the
  // actor's **valid** devices have reached the cap (counted on the
  // pre-acceptance derived state — revoked ones do not count). Same
  // position as the four-eyes pending cap (after membership, before
  // CAS / verifyChain). Not a consensus rule
  if (entry.op === "add_device") {
    const active = chain.state.members.get(callerUserId)?.devices.size ?? 0;
    if (active >= MAX_DEVICES_PER_MEMBER) {
      return yield* rejectData({ kind: "device-limit", limit: MAX_DEVICES_PER_MEMBER });
    }
  }
  yield* ensureParentHead(chain, parentHeadHashHex);
  // The 4 acceptance steps (size → capacity → verifyChain → insert +
  // mirror) are shared with the composite path (chain-accept.ts). A
  // completed approve writes the inner op's mirror-application row and
  // its side effects in the same commit, and returns the applied
  // proposal to the worker (K5-H)
  const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
  const appliedProposal = yield* commitAcceptedEntry(chain, entry, applied, canonicalBytes);
  updateStateCache(cache, applied);
  return {
    headSeq: applied.state.headSeq,
    headHashHex: applied.state.headHashHex,
    appliedProposal,
  };
});

/** The chain get (storage-guard.test.ts also pins that reads pass under rejection). */
export const snapshotProgram = Effect.fn("programs-chain.snapshotProgram")(function* (
  callerUserId: UserId,
  cache: StateCache,
): Effect.fn.Return<ChainSnapshotValue, DataRejectedError, ChainStore | DataStore> {
  const chain = yield* loadChainForMember(callerUserId, cache);
  // Bundling the attestations (AUTH_SPEC §16-1): only the latest
  // attestations of current members' **valid devices**. The row
  // deletion at remove_member / revoke_device acceptance
  // (chain-accept.ts) owns the convergence to the source of truth; the
  // narrowing here is an independent defensive layer (also matching
  // the §6.6 (1) client check)
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

/**
 * The calling principal's chain-derived role (the authorization input of
 * the invites API — AUTH_SPEC §15-2). The floor is reader (= being a
 * member): a non-member is rejected as not-member and the worker maps it
 * to 404 (§11-2). The admin / owner level judgment is done on the worker
 * side (per-endpoint rules like "a role=admin invite only by an owner").
 */
export const memberRoleProgram = (
  callerUserId: UserId,
  cache: StateCache,
): Effect.Effect<Role, DataRejectedError, ChainStore> =>
  Effect.map(requireMemberState(callerUserId, "reader", cache), (context) => context.member.role);
