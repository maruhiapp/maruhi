// `maruhi ci sync <target>`: syncing from a CI job
// (integration-options.md §3 supplement 7 P3 "re-apply at deploy
// time" / supplement 16 G1 "CI is http").
//
// The credential path is the same workload lease as `ci run`
// (ci-lease.ts — OIDC → DEK → decrypt), independent of the maruhi
// token, keychain, session, and config files. The only thing read
// is the sync config committed to the repository
// (`maruhi.sync.json` — a non-secret config like the anchor file).
//
// **No receipt is written** (shown in types — this path does not
// import sync-receipt.ts and receives no signing key [master key]):
// CI lacks the key used for CRYPTO_SPEC §4.1's write signature. So
// the CI sync is a "re-apply every selected variable" (an
// idempotent upsert), and without the deletion source (a receipt)
// **it deletes nothing**. Deletion is done by `maruhi sync apply`
// (with a receipt) at hand — stated in docs.
//
// A lease is per environment, so when the http driver's token lives
// in a different environment than the source, 2 environments are
// leased (with one OIDC token and one ephemeral key — ci-lease.ts).
// The grant's lease policy must allow both environments.

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import { type CiLeaseInput, leaseEnvironments } from "../ci-lease.ts";
import { countNoun, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import type { VerifiedLeaseMaterial } from "../lease-client.ts";
import type { ProcessRunner } from "../run.ts";
import type { SyncTarget } from "./sync-config.ts";
import { DEFAULT_HTTP_RETRY, type HttpRetryPolicy, type IntegrationToken } from "./sync-http.ts";
import {
  computePlan,
  failDriver,
  integrationTokenOf,
  prepareWork,
  requireProductionConsent,
  reviewPlan,
  runDriver,
  sourceVariablesOf,
  writesOf,
} from "./sync-plan.ts";

/** `maruhi ci sync`'s input (flags + the repository config's target). */
interface CiSyncInput extends CiLeaseInput {
  readonly target: SyncTarget;
  /** Explicit confirmation of apply to a production target (the same word as the local apply). */
  readonly yes: boolean;
  readonly httpRetry?: HttpRetryPolicy;
}

/** Pulls a leased environment's material (its absence is an implementation inconsistency). */
function materialOf(
  materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  environmentId: EnvironmentId,
): Effect.Effect<VerifiedLeaseMaterial, CliError> {
  const material = materials.get(environmentId);
  return material === undefined
    ? Effect.fail(cliError("The lease returned no material (internal inconsistency)"))
    : Effect.succeed(material);
}

/**
 * `maruhi ci sync <target>`: lease the target's source environment (and the
 * token environment for the http driver), then write every selected variable
 * to the target through its driver. No receipt is read or written: the CI
 * job holds no signing key, so it re-applies everything and deletes nothing.
 */
export const ciSyncOp = Effect.fn("sync-ci.ciSyncOp")(function* (
  input: CiSyncInput,
): Effect.fn.Return<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const { target } = input;
  const tokenEnvironment =
    target.driver.kind === "http" && target.driver.token.environment !== target.environment
      ? target.driver.token.environment
      : null;
  const materials = yield* leaseEnvironments({
    ...input,
    environmentIds: [target.environment, ...(tokenEnvironment === null ? [] : [tokenEnvironment])],
  });
  const source = yield* materialOf(materials, target.environment);
  const plan = yield* computePlan({
    target,
    source: sourceVariablesOf(source.variables),
    declared: source.declared,
    // No receipt: every selected variable is add (full re-apply); no deletion arises
    receipt: null,
  });
  yield* reviewPlan(target, plan, { kind: "none-in-ci" });
  const work = yield* prepareWork(target, plan, writesOf(source.variables));
  if (work.writes.length === 0) {
    yield* io.log("Nothing to apply: the target selects no variable with a value");
    return;
  }
  yield* requireProductionConsent(target, input.yes, "maruhi ci sync");
  let token: IntegrationToken | null = null;
  if (target.driver.kind === "http") {
    const holder = yield* materialOf(materials, target.driver.token.environment);
    token = yield* integrationTokenOf(target.driver.token, holder.variables);
  }
  const result = yield* runDriver({
    target,
    work,
    token,
    httpRetry: input.httpRetry ?? DEFAULT_HTTP_RETRY,
  });
  if (result.failure !== null) {
    return yield* failDriver({
      target,
      work,
      result,
      receiptsEnvironment: null,
      next: "re-run the job (every selected variable is written again)",
    });
  }
  yield* io.log(
    `Applied to target ${displayText(target.name)}: ${countNoun(result.written.length, "variable")} written (no receipt is kept in CI, and nothing is deleted)`,
  );
});
