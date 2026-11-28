import type { EnvironmentId, VariableId } from "@maruhi/core";
import type { PendingProposal } from "@maruhi/crypto";
import { Effect } from "effect";

import { DataStore, rejectData } from "./data.package/index.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_ENVIRONMENT_CIPHERTEXT_BYTES,
  MAX_ENVIRONMENT_ROWS,
  MAX_PENDING_PROPOSALS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_PROPOSAL_LIFETIME_MS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
} from "./policy.ts";

export function projectQuotaExceeded(activeProjectCount: number): boolean {
  return activeProjectCount + 1 > MAX_ACTIVE_PROJECTS_PER_ORG;
}

export const requireActiveEnvironment = Effect.fn("quotas.requireActiveEnvironment")(function* (
  environmentId: EnvironmentId,
) {
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(environmentId);
  if (environment === null || environment.deletedAtMs !== null) {
    return yield* rejectData({ kind: "environment-not-found", environmentId });
  }
  return environment;
});

export const requireActiveVariable = Effect.fn("quotas.requireActiveVariable")(function* (
  environmentId: EnvironmentId,
  variableId: VariableId,
) {
  const store = yield* DataStore;
  const variable = yield* store.findVariable(environmentId, variableId);
  if (variable === null || variable.deletedAtMs !== null) {
    return yield* rejectData({ kind: "variable-not-found", variableId });
  }
  return variable;
});

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

export const ensureVariableQuota = Effect.fn("quotas.ensureVariableQuota")(function* (
  environmentId: EnvironmentId,
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

export function environmentBytesExceeded(
  totalBytes: number,
  replacedBytes: number,
  addedBytes: number,
): boolean {
  const resultingBytes = totalBytes - replacedBytes + addedBytes;
  return resultingBytes > MAX_ENVIRONMENT_CIPHERTEXT_BYTES && resultingBytes > totalBytes;
}

export const ensureEnvironmentCapacity = Effect.fn("quotas.ensureEnvironmentCapacity")(function* (
  environmentId: EnvironmentId,
  variableId: VariableId,
  addedBytes: number,
) {
  const store = yield* DataStore;
  const { totalBytes, variableBytes } = yield* store.environmentCiphertextBytes(
    environmentId,
    variableId,
  );
  if (environmentBytesExceeded(totalBytes, variableBytes, addedBytes)) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environment-ciphertext-bytes",
      limit: MAX_ENVIRONMENT_CIPHERTEXT_BYTES,
    });
  }
});

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

export function wrapRowsExceeded(storedRows: number, addedRows: number): boolean {
  return storedRows + addedRows > MAX_PROJECT_DEK_WRAP_ROWS;
}

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

export function proposalIsLive(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs >= nowMs;
}

export function proposalLifetimeExceeded(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs > nowMs + MAX_PROPOSAL_LIFETIME_MS;
}

export function pendingProposalsExceeded(livePendingCount: number): boolean {
  return livePendingCount + 1 > MAX_PENDING_PROPOSALS;
}

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
