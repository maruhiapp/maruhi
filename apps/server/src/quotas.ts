// Existence guards and quantity policies (AUTH_SPEC §12-8).
//
// - requireActive*: existence (non-tombstone) guards for
//   environments and variables; shared by the program layer and
//   composite requests (composite-programs.ts)
// - *Exceeded: pure functions for cap checks (actually generating the
//   cap row count is unrealistic, so the checks are exposed for unit
//   tests — the same shape as chain-accept.ts's chainCapacityExceeded)
// - ensure*: the check lifted into a limit-exceeded rejection

import type { PendingProposal } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MetaStatementStatusInput } from "./data/data-plane.ts";
import { rejectData } from "./data/data-plane.ts";
import { DataStore } from "./data/data-store.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_ENVIRONMENT_ROWS,
  MAX_PENDING_PROPOSALS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_PROPOSAL_LIFETIME_MS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "./policy.ts";

/**
 * AUTH_SPEC §11-3: the cap on active projects per org.
 * A pure function that decides, from numbers only, "does adding one
 * project to this org exceed the cap" (actually generating the cap
 * count is heavy, so the check is exposed for unit tests — the same
 * shape as the other *Exceeded). Acquiring the inputs (a D1 count)
 * and the check point (at init acceptance — after the org-permission
 * check, before DO init) live in worker-side handlers-membership.ts.
 * So does the treatment on reaching the cap (a report-only query to
 * the DO that does not plug the repair path).
 */
export function projectQuotaExceeded(activeProjectCount: number): boolean {
  return activeProjectCount + 1 > MAX_ACTIVE_PROJECTS_PER_ORG;
}

/** An extant (non-tombstone) environment. Absent → environment-not-found. */
export const requireActiveEnvironment = Effect.fn("quotas.requireActiveEnvironment")(function* (
  environmentId: string,
) {
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(environmentId);
  if (environment === null || environment.deletedAtMs !== null) {
    return yield* rejectData({ kind: "environment-not-found", environmentId });
  }
  return environment;
});

/** An extant (non-tombstone) variable. Absent → variable-not-found. */
export const requireActiveVariable = Effect.fn("quotas.requireActiveVariable")(function* (
  environmentId: string,
  variableId: string,
) {
  const store = yield* DataStore;
  const variable = yield* store.findVariable(environmentId, variableId);
  if (variable === null || variable.deletedAtMs !== null) {
    return yield* rejectData({ kind: "variable-not-found", variableId });
  }
  return variable;
});

/** The quantity policy on environment count (§12-8; called from composite creation — composite-programs.ts). */
export const ensureEnvironmentQuota = Effect.gen(function* () {
  const store = yield* DataStore;
  const counts = yield* store.countEnvironments;
  if (counts.active + 1 > MAX_ACTIVE_ENVIRONMENTS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environments",
      limit: MAX_ACTIVE_ENVIRONMENTS,
    });
  }
  if (counts.rows + 1 > MAX_ENVIRONMENT_ROWS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environment-rows",
      limit: MAX_ENVIRONMENT_ROWS,
    });
  }
});

/** The quantity policy on variable count and variable-row count (tombstones included) (§12-8). */
export const ensureVariableQuota = Effect.fn("quotas.ensureVariableQuota")(function* (
  environmentId: string,
) {
  const store = yield* DataStore;
  const counts = yield* store.countVariables(environmentId);
  if (counts.active + 1 > MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "variables",
      limit: MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
    });
  }
  if (counts.rows + 1 > MAX_VARIABLE_ROWS_PER_ENVIRONMENT) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "variable-rows",
      limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
    });
  }
});

/**
 * The cap on metaVersion row count (interim ruling — applies the
 * same value as §12-8's "versions / variable" to statement rows.
 * Blocks DO storage bloat via rename spam).
 * Deletion (status deleted) is out of scope: a tombstone is the
 * chain's terminal and adds at most one row, and blocking even
 * deletion at the cap would make a capped resource permanently
 * undeletable under any role (a collision with §12-8's "freed by
 * deletion" principle).
 * The check is against the stored state (latest + 1): a stale,
 * pre-CAS declared metaVersion is not misreported as limit-exceeded
 * — it becomes a 422 only when the cap is actually reached.
 */
export function metaVersionsExceeded(
  latestMetaVersion: number,
  status: MetaStatementStatusInput,
): boolean {
  return status !== "deleted" && latestMetaVersion + 1 > MAX_VERSIONS_PER_VARIABLE;
}

/** §12-8: the cap on accumulated ciphertext bytes. A pure function that includes the addition in the check (exposed for unit tests). */
export function projectBytesExceeded(storedBytes: number, addedBytes: number): boolean {
  return storedBytes + addedBytes > MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES;
}

export const ensureProjectCapacity = Effect.fn("quotas.ensureProjectCapacity")(function* (
  addedBytes: number,
) {
  const store = yield* DataStore;
  const stored = yield* store.totalCiphertextBytes;
  if (projectBytesExceeded(stored, addedBytes)) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "project-ciphertext-bytes",
      limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
    });
  }
});

/**
 * §12-8: the cap on accumulated DEK-wrap rows per project. A pure
 * function that includes the addition in the check (actually
 * generating the cap row count is unrealistic, so it is exposed for
 * unit tests).
 */
export function wrapRowsExceeded(storedRows: number, addedRows: number): boolean {
  return storedRows + addedRows > MAX_PROJECT_DEK_WRAP_ROWS;
}

/** Called on every wrap-insertion path (DEK registration, environment creation) (§12-8). */
export const ensureWrapRowCapacity = Effect.fn("quotas.ensureWrapRowCapacity")(function* (
  addedRows: number,
) {
  const store = yield* DataStore;
  const stored = yield* store.countWrapRows;
  if (wrapRowsExceeded(stored, addedRows)) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "dek-wrap-rows",
      limit: MAX_PROJECT_DEK_WRAP_ROWS,
    });
  }
});

// ---------------------------------------------------------------------------
// The acceptance policy for four-eyes proposals (AUTH_SPEC §12-8 /
// CRYPTO_SPEC §6.4 — not consensus rules; design record es-design.md
// §11 K5-B / K5-C). The inputs are the DO's chain-derived state (the
// pending set) and the server clock. The check order is the upper
// bound (entry-specific) → the pending cap (project state) — the same
// "entry-specific → state" as the existing size → capacity order.
// A proposal already expired at creation is not rejected (K5-C: it is
// merely excluded from the cap computation, occupies no resource, and
// the consensus rules close its approval as `proposal-expired`).
// ---------------------------------------------------------------------------

/** Whether a proposal is within its lifetime on the server clock (= counted in the pending-cap computation). Equality counts as in-lifetime (same direction as §6.2's `≤`). */
export function proposalIsLive(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs >= nowMs;
}

/** §6.4: whether `expires_at_ms` exceeds the server clock at acceptance + 30 days (pure function — exposed for unit tests). */
export function proposalLifetimeExceeded(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs > nowMs + MAX_PROPOSAL_LIFETIME_MS;
}

/** §12-8: whether adding one to the in-lifetime pending proposals exceeds the cap (pure function — exposed for unit tests). */
export function pendingProposalsExceeded(livePendingCount: number): boolean {
  return livePendingCount + 1 > MAX_PENDING_PROPOSALS;
}

/** The count of pending-set entries in the current derived state that are in-lifetime on the server clock. */
export function countLivePendingProposals(
  pending: ReadonlyMap<string, PendingProposal>,
  nowMs: number,
): number {
  let count = 0;
  for (const proposal of pending.values()) {
    if (proposalIsLive(proposal.expiresAtMs, nowMs)) {
      count += 1;
    }
  }
  return count;
}

/**
 * The acceptance policy of `propose` (upper bound → pending cap).
 * Called after the membership check and the growth guard, before CAS
 * / verifyChain (appendProgram in chain-do.ts).
 */
export const ensureProposalAdmitted = Effect.fn("quotas.ensureProposalAdmitted")(function* (
  expiresAtMs: number,
  pending: ReadonlyMap<string, PendingProposal>,
  nowMs: number,
) {
  if (proposalLifetimeExceeded(expiresAtMs, nowMs)) {
    return yield* rejectData({
      kind: "proposal-limit",
      reason: "proposal-lifetime",
      limit: MAX_PROPOSAL_LIFETIME_MS,
    });
  }
  if (pendingProposalsExceeded(countLivePendingProposals(pending, nowMs))) {
    return yield* rejectData({
      kind: "proposal-limit",
      reason: "pending-proposals",
      limit: MAX_PENDING_PROPOSALS,
    });
  }
});
