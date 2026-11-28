import { isEnvironmentId, type EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { CliServices } from "./cli.ts";
import type { ProjectContext } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import { envRotateOp } from "./env.package/index.ts";
import { type CliError, usageError } from "./errors.ts";
import type { RotationSummary, SweepRotateMode } from "./rotation-sweep.ts";

function cliErrorForInvalidChainEnvironmentId(): CliError {
  return usageError(
    "A chain-derived environment ID fails the CLI's format check (the chain contradicts the server's acceptance policy)",
  );
}

export function sweepRotateFor(
  context: ProjectContext,
  reason: string,
): (
  environmentId: EnvironmentId,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, CliServices> {
  return (environmentId: EnvironmentId, mode: SweepRotateMode) =>
    Effect.gen(function* () {
      if (!isEnvironmentId(environmentId)) {
        return yield* Effect.fail(cliErrorForInvalidChainEnvironmentId());
      }
      const floorHandle = yield* floorHandleFor(context, environmentId);
      const verified = yield* context.resync;
      return yield* envRotateOp({
        client: context.client,
        verified,
        environmentId,
        recipient: context.recipient,
        reason: mode === "force" ? reason : undefined,
        forceNewEpoch: mode === "force",
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        resync: context.resync,
        floor: floorHandle,
      });
    });
}
