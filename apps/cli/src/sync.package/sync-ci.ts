import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";
import type { HttpClient } from "effect/http";

import type { CiLeaseInput } from "../ci.package/index.ts";
import { countNoun, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import type { VerifiedLeaseMaterial } from "../lease.package/index.ts";
import type { ProcessRunner } from "../run.ts";
import type { SyncTarget } from "./sync-config.ts";
import { DEFAULT_HTTP_RETRY, type HttpRetryPolicy, type IntegrationToken } from "./sync-http.ts";

interface CiSyncInput extends CiLeaseInput {
  readonly target: SyncTarget;
  readonly yes: boolean;
  readonly httpRetry?: HttpRetryPolicy;
}

function materialOf(
  materials: ReadonlyMap<EnvironmentId, VerifiedLeaseMaterial>,
  environmentId: EnvironmentId,
): Effect.Effect<VerifiedLeaseMaterial, CliError> {
  const material = materials.get(environmentId);
  return material === undefined
    ? Effect.fail(cliError("The lease returned no material (internal inconsistency)"))
    : Effect.succeed(material);
}

export const ciSyncOp = Effect.fn("sync-ci.ciSyncOp")(function* (
  input: CiSyncInput,
): Effect.fn.Return<void, CliError, CliIo | ProcessRunner | HttpClient.HttpClient> {
  const io = yield* CliIo;
  const { leaseEnvironments } = yield* Effect.promise(() =>
    import("../ci.package/index.ts").then((m) => ({ leaseEnvironments: m.leaseEnvironments })),
  );
  const {
    computePlan,
    failDriver,
    integrationTokenOf,
    prepareWork,
    requireProductionConsent,
    reviewPlan,
    runDriver,
    sourceVariablesOf,
    writesOf,
  } = yield* Effect.promise(() =>
    import("./sync-plan.ts").then((m) => ({
      computePlan: m.computePlan,
      failDriver: m.failDriver,
      integrationTokenOf: m.integrationTokenOf,
      prepareWork: m.prepareWork,
      requireProductionConsent: m.requireProductionConsent,
      reviewPlan: m.reviewPlan,
      runDriver: m.runDriver,
      sourceVariablesOf: m.sourceVariablesOf,
      writesOf: m.writesOf,
    })),
  );
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
