import type { EnvironmentId } from "@maruhi/core";
import { Effect, type Stdio } from "effect";
import type { HttpClient } from "effect/http";

import { logWarnings } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import type { CliIo } from "../io.ts";
import { enforceDeclaredPresence, ProcessRunner, runOp, typeAdvisoryWarnings } from "../run.ts";
import { type CiLeaseInput, leaseEnvironments } from "./ci-lease.ts";

interface CiRunInput extends CiLeaseInput {
  readonly environmentId: EnvironmentId;
  readonly command: readonly string[];
}

export const ciRunOp = Effect.fn("ci-run.ciRunOp")(function* (
  input: CiRunInput,
): Effect.fn.Return<number, CliError, CliIo | ProcessRunner | HttpClient.HttpClient | Stdio.Stdio> {
  const materials = yield* leaseEnvironments({
    ...input,
    environmentIds: [input.environmentId],
  });
  const material = materials.get(input.environmentId);
  if (material === undefined) {
    return yield* Effect.fail(cliError("The lease returned no material (internal inconsistency)"));
  }
  yield* enforceDeclaredPresence(material.declared);
  yield* logWarnings(typeAdvisoryWarnings(material.variables));
  return yield* runOp({ command: input.command, variables: material.variables });
});
