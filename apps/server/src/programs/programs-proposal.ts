// Effect programs for sealed value proposals (CRYPTO_SPEC §5.3 / AUTH_SPEC
// §14-5 — PF7b).
//
// - mint: the workload path. Authentication and authorization are the
//   lease's (programs-lease.ts's authorizeWorkload — the OIDC facts
//   arrive from the worker, every mismatch is a uniform 404, the
//   first-come binding is a 401). Nothing here touches the server key:
//   the server stores ciphertexts it cannot open. The acceptance checks
//   (§14-5) run after authorization, so their reasons leak nothing to a
//   caller that did not match an on-chain lease policy
// - list: a member's view (member or above × environment ∈ scope), with
//   **only the caller's own wraps** — a wrap to someone else's device is
//   useless to the caller and would only reveal the recipient set
// - resolve: accepted (the member pushed the versions first — the
//   resolution creates no version and verifies the named ones exist) or
//   rejected. Both delete the rows; the audit row keeps the outcome
//
// The permit-serialization premise is the same as the other programs-*.

import type { ChainState } from "@maruhi/crypto";
import { effectivePermissionOf, scopeIncludesEnvironment } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { AuditStore } from "../audit-store.ts";
import type {
  DataActor,
  DataRejectedError,
  RotationProposalRejectReason,
} from "../data/data-plane.ts";
import { dataEvent, rejectData, requireMemberState, roleAtLeast } from "../data/data-plane.ts";
import type { DataStoreShape, StoredProposal, StoredProposalVariable } from "../data/data-store.ts";
import { DataStore } from "../data/data-store.ts";
import { deviceReceivesEnvironment } from "../dek-wraps.ts";
import type { StateCache } from "../do/chain-store.ts";
import type { ChainStore } from "../do/chain-store.ts";
import { MAX_PENDING_ROTATION_PROPOSALS, MAX_ROTATION_PROPOSALS_PER_WINDOW } from "../policy.ts";
import { projectBytesExceeded } from "../quotas.ts";
import type { ServerKey } from "../server-key.ts";
import { observeStorageLevel, StorageMeter } from "../storage-guard.ts";
import type { LeaseRejection, LeaseTokenFacts } from "./programs-lease.ts";
import { authorizeWorkload, recordDenied } from "./programs-lease.ts";

/** The rotation connectors a proposal may name (the api-schema RotationConnectorSchema vocabulary). */
const ROTATION_CONNECTORS = [
  "aws-iam-access-key",
  "cloudflare-api-token",
  "postgres",
  "mysql",
  "exec",
] as const;

export type RotationConnector = (typeof ROTATION_CONNECTORS)[number];

/** A proposed value sealed to one recipient device (the wire shape crossing the RPC boundary). */
export interface ProposalWrapInput {
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface ProposalVariableInput {
  readonly variableId: string;
  readonly baseVersion: number;
  readonly wraps: readonly ProposalWrapInput[];
}

/** The proposal a workload mints (AUTH_SPEC §14-5 — already Schema-validated by the worker). */
export interface RotationProposalInput {
  readonly proposalId: string;
  readonly connector: RotationConnector;
  readonly facts: readonly string[];
  /** 1 to 30 (Schema-bounded by the worker); the server sets the instant. */
  readonly expiresInDays: number;
  readonly variables: readonly ProposalVariableInput[];
}

/** The mint's rejections: the lease vocabulary plus the §14-5 acceptance checks. */
export type ProposalRejection =
  | LeaseRejection
  | { readonly kind: "proposal-rejected"; readonly reason: RotationProposalRejectReason };

export interface ProposalReceipt {
  readonly proposalId: string;
  readonly expiresAtMs: number;
}

/** The mint result crossing the RPC boundary (the same split as LeaseOutcome). */
export type ProposalOutcome =
  | { readonly kind: "ok"; readonly value: ProposalReceipt }
  | { readonly kind: "rejected"; readonly rejection: ProposalRejection };

/** A pending proposal as distributed to one member (own wraps only). */
export interface MemberProposalValue extends Omit<StoredProposal, "connector"> {
  readonly connector: RotationConnector;
}

/** A member's resolution (crosses the RPC boundary). */
export interface ProposalResolutionInput {
  readonly outcome: "accepted" | "rejected";
  readonly versions: readonly { readonly variableId: string; readonly version: number }[];
}

/**
 * The recipient set W(E) (CRYPTO_SPEC §5.3): every device of each current
 * member with role member or above whose effective scope includes E —
 * R(E) minus readers and server keys. Keyed like the wrap store
 * (`user_id:enc_pub_hex`).
 */
function proposalRecipientKeys(state: ChainState, environmentId: string): ReadonlySet<string> {
  const keys = new Set<string>();
  for (const [userId, member] of state.members) {
    for (const device of member.devices.values()) {
      // The device's effective permission (person ∩ device — §6.2): a
      // reader-capped device of a member could open the value but never
      // push it, so it is not a recipient
      if (
        roleAtLeast(effectivePermissionOf(member, device).role, "member") &&
        deviceReceivesEnvironment(member, device, environmentId)
      ) {
        keys.add(`${userId}:${device.encPubHex}`);
      }
    }
  }
  return keys;
}

/** The stored connector name narrowed to the vocabulary (anything else is storage corruption — a defect, never re-read as a default). */
function storedConnector(value: string): RotationConnector {
  const found = ROTATION_CONNECTORS.find((connector) => connector === value);
  if (found === undefined) {
    throw new Error("unexpected connector in stored proposal row");
  }
  return found;
}

/** §14-5 (5): the wraps of one variable are exactly W(E) — nobody missing, nobody extra, no duplicate device. */
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

/** §14-5 (3): whether a variable is named twice (judged over the whole list, before any per-variable check). */
function namesVariableTwice(variables: readonly { readonly variableId: string }[]): boolean {
  return new Set(variables.map((variable) => variable.variableId)).size !== variables.length;
}

/** §14-5 (4)–(6): one variable's checks (active, base version current, recipients exact, no pending proposal). */
const variableRefusal = (
  store: DataStoreShape,
  environmentId: string,
  recipients: ReadonlySet<string>,
  variable: ProposalVariableInput,
  nowMs: number,
): Effect.Effect<RotationProposalRejectReason | null> =>
  Effect.gen(function* () {
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
    // One proposal per variable at a time, at the mint as at the pre-flight
    // (ruling O revision, round 4 — two jobs that both pre-flighted before
    // either minted must not both store)
    return (yield* store.variableHasPendingProposal(environmentId, variable.variableId, nowMs))
      ? "variable-pending"
      : null;
  });

/** The §14-5 acceptance checks in their order ((2)–(7)); null = acceptable. */
const proposalRefusal = (
  store: DataStoreShape,
  state: ChainState,
  environmentId: string,
  proposal: RotationProposalInput,
  nowMs: number,
): Effect.Effect<RotationProposalRejectReason | null> =>
  Effect.gen(function* () {
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
    // The sealed values count toward the project's ciphertext cap
    // (§12-8 — the meter includes pending proposals), judged like a push
    const stored = yield* store.totalCiphertextBytes;
    return projectBytesExceeded(stored, proposalCiphertextBytes(proposal)) ? "storage-limit" : null;
  });

/** The bytes a proposal's sealed values add to the project's ciphertext meter (hex — two characters per byte). */
function proposalCiphertextBytes(proposal: RotationProposalInput): number {
  let total = 0;
  for (const variable of proposal.variables) {
    for (const wrap of variable.wraps) {
      total += wrap.ciphertextHex.length / 2;
    }
  }
  return total;
}

export const proposeRotationProgram = (
  environmentId: string,
  ephemeralPubHex: string,
  facts: LeaseTokenFacts,
  proposal: RotationProposalInput,
  cache: StateCache,
): Effect.Effect<
  ProposalReceipt,
  ProposalRejection,
  ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
> =>
  Effect.gen(function* () {
    // Steps 0–2 are the lease's (server key present, chain, grant ×
    // policy × scope → uniform 404, first-come binding → 401,
    // environment existence)
    const { state, grant, nowMs } = yield* authorizeWorkload(
      environmentId,
      ephemeralPubHex,
      facts,
      cache,
    );
    const store = yield* DataStore;
    // A mirror mints nothing (AUTH_SPEC §11-7) — judged after
    // authorization like every §14-5 reason (existence concealment), in
    // the proposal vocabulary because the workload's credential is not a
    // member's; the job mints against the source deployment
    if (store.isMirrorSync()) {
      return yield* Effect.fail<ProposalRejection>({
        kind: "proposal-rejected",
        reason: "mirror-read-only",
      });
    }
    // (1) The mint window — judged after authorization (existence
    // concealment), consumed only when a proposal is stored
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
    // Expired rows leave before the id and pending-count checks (an
    // expired proposal neither blocks its id nor counts)
    yield* sweepExpired(nowMs);
    const reason = yield* proposalRefusal(store, state, environmentId, proposal, nowMs);
    if (reason !== null) {
      return yield* Effect.fail<ProposalRejection>({ kind: "proposal-rejected", reason });
    }
    // The lifetime is a duration on the wire (ruling O revision): the
    // instant is the server's, so a client clock ahead of the server can
    // never make a proposal unacceptable after the issuer was touched
    const expiresAtMs = nowMs + proposal.expiresInDays * DAY_MS;
    // The storage-total guard observes (the caps above bound a
    // proposal's size; the mint is accepted under the warning level like
    // the lease — AUTH_SPEC §12-8)
    yield* observeStorageLevel;
    const audit = yield* AuditStore;
    yield* Effect.sync(() => {
      // Window consumption, the first-come binding (idempotent for the
      // key the lease bound), the rows, and the audit row in one
      // synchronous block
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
      // AUDIT_SPEC §3.3 rotation.proposed: actor system (the workload has
      // no maruhi identity); attribution is the claims digest + the
      // grant's seq, the same cross-check as server.lease_issued. No
      // external identifiers
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
  });

/**
 * The expiry sweep (before a mint, a pre-flight and a resolution): every
 * proposal past its expiry leaves, and a `rotation.proposal_expired` row
 * closes it (AUDIT_SPEC §3.3 — ruling P-2: every `proposed` row gets
 * exactly one closing row, so "minted but never accepted" is enumerable
 * from the log alone). Actor system, like the mint
 */
/**
 * Drops the expired rows and leaves each one's history as an audit row
 * (ruling P revision). The payload carries the expiry instant: the sweep
 * runs on the next mint, pre-flight or resolution, which in a quiet
 * project can be long after. `except` is a proposal a member is resolving
 * right now (ruling P revision: an expired-but-unswept proposal whose
 * member evidently did not abandon it is resolved, not swept).
 */
const sweepExpired = (
  nowMs: number,
  except?: string,
): Effect.Effect<void, never, DataStore | AuditStore> =>
  Effect.gen(function* () {
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

/** The pre-flight's variables (AUTH_SPEC §14-5 — O-4): what the job intends to propose, before the issuer is touched. */
export interface PreflightVariableInput {
  readonly variableId: string;
  readonly baseVersion: number;
}

/** The recipient set the job will seal to (public chain facts — ruling O revision, round 4): checked against W(E) before the issuer is touched. */
export interface PreflightRecipientInput {
  readonly userId: string;
  readonly encPubHex: string;
}

/** The pre-flight result crossing the RPC boundary (the same split as ProposalOutcome, no value). */
export type PreflightOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "rejected"; readonly rejection: ProposalRejection };

/**
 * The mint's pre-flight (AUTH_SPEC §14-5 — ruling O-4): the lease's
 * authorization, then every §14-5 check a sealed value is not needed
 * for — the variables active at the named base versions, no pending
 * proposal targeting one of them (`variable-pending`), the pending cap,
 * the mirror mark. Nothing is stored and no window is consumed; the
 * token's first-come binding is taken like the lease's.
 */
export const preflightRotationProgram = (
  environmentId: string,
  ephemeralPubHex: string,
  facts: LeaseTokenFacts,
  variables: readonly PreflightVariableInput[],
  cache: StateCache,
  recipients?: readonly PreflightRecipientInput[],
): Effect.Effect<
  void,
  ProposalRejection,
  ChainStore | DataStore | AuditStore | ServerKey | StorageMeter
> =>
  Effect.gen(function* () {
    const { state } = yield* authorizeWorkload(environmentId, ephemeralPubHex, facts, cache);
    const store = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;
    if (store.isMirrorSync()) {
      return yield* preflightRefusal("mirror-read-only");
    }
    // The mint window, read without consuming it (ruling O revision): a
    // job that would be rate-limited learns it before the issuer is touched
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
    // The recipient set the job will seal to, when it says (ruling O
    // revision, round 4): a disagreement with W(E) that is not a race — a
    // chain view that differs, a device registered since the lease — is
    // answered here, before the issuer is touched; the mint repeats it
    if (
      recipients !== undefined &&
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
  });

const preflightRefusal = (reason: RotationProposalRejectReason) =>
  Effect.fail<ProposalRejection>({ kind: "proposal-rejected", reason });

/** The mint's per-variable checks that do not depend on the sealed content (the same order as the mint). */
const preflightVariable = (
  store: DataStore["Service"],
  environmentId: string,
  variable: PreflightVariableInput,
  nowMs: number,
): Effect.Effect<void, ProposalRejection> =>
  Effect.gen(function* () {
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

/** A stored proposal narrowed to one member's view: the caller's own wraps only. */
function ownView(proposal: StoredProposal, userId: string): MemberProposalValue {
  return {
    ...proposal,
    connector: storedConnector(proposal.connector),
    variables: proposal.variables.map((variable): StoredProposalVariable => ({
      ...variable,
      wraps: variable.wraps.filter((wrap) => wrap.recipientUserId === userId),
    })),
  };
}

export const listRotationProposalsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    // member or above (§14-5 — a reader is never a recipient, so the
    // view would be empty by construction; the role floor says so
    // explicitly). Environments outside the person's scope are filtered
    const { member } = yield* requireMemberState(actor.userId, "member", cache);
    const store = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;
    // The list is the read that is about proposals, and the one a project
    // whose rotation job is gone still runs (the cron's --fail-on-pending):
    // it sweeps too, so expired rows get their closing audit row and leave
    // the §12-8 meter (ruling P revision, round 4 — the var.read precedent
    // for a read that appends). A mirror writes nothing; its source sweeps
    if (!store.isMirrorSync()) {
      yield* sweepExpired(nowMs);
    }
    const pending = yield* store.listPendingProposals(nowMs);
    return pending
      .filter((proposal) => scopeIncludesEnvironment(member.scope, proposal.environmentId))
      .map((proposal) => ownView(proposal, actor.userId));
  });

/** §14-5 accepted: every proposed variable is named with a stored version newer than its base. */
const versionsRefusal = (
  store: DataStoreShape,
  proposal: StoredProposal,
  versions: ProposalResolutionInput["versions"],
): Effect.Effect<RotationProposalRejectReason | null> =>
  Effect.gen(function* () {
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

export const resolveRotationProposalProgram = (
  actor: DataActor,
  proposalId: string,
  resolution: ProposalResolutionInput,
  cache: StateCache,
): Effect.Effect<void, DataRejectedError, ChainStore | DataStore | AuditStore> =>
  Effect.gen(function* () {
    const { member } = yield* requireMemberState(actor.userId, "member", cache);
    const nowMs = yield* Clock.currentTimeMillis;
    // The resolved proposal is reached expired or not: a member who began
    // the acceptance before the expiry has pushed signed versions already,
    // and their outcome belongs in the log as theirs, not as "nobody's"
    // (ruling P revision). Unknown / resolved / swept fold into one 404
    // (indistinguishable by design — a resolution cannot probe which)
    yield* sweepExpired(nowMs, proposalId);
    const store = yield* DataStore;
    const proposal = yield* store.findProposal(proposalId);
    if (proposal === null) {
      return yield* rejectData({ kind: "rotation-proposal-not-found", proposalId });
    }
    // The environment axis (§12-3): the person's scope, judged on the
    // stored environment (an unsigned operation — judged on the person,
    // like dismissals). The environment is known only from the stored
    // row, so the scope check cannot precede existence; folding the
    // refusal into the same 404 keeps an out-of-scope member from
    // telling "pending" apart from "resolved / expired / unknown"
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
            ? "rotation.proposal_accepted"
            : "rotation.proposal_rejected",
          {
            environmentId: proposal.environmentId,
            payload: {
              proposalId,
              ...(resolution.outcome === "accepted" ? { versions: resolution.versions } : {}),
            },
          },
        ),
      );
    });
  });
