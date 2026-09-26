// The per-environment rotation injected into §7's whole-environment
// sweep (shared by server revoke / member remove / change-role).
// The consumer is effect-cli.ts.

import { isEnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { CliServices, ProjectContext } from "./context.ts";
import { floorHandleFor } from "./context.ts";
import type { RotationSummary } from "./env-rotate.ts";
import { envRotateOp } from "./env-rotate.ts";
import { type CliError, usageError } from "./errors.ts";
import type { SweepRotateMode } from "./rotation-sweep.ts";

/** A guard for when a chain-derived environment ID fails the CLI's format check (normally unreachable). */
function cliErrorForInvalidChainEnvironmentId(): CliError {
  return usageError(
    "A chain-derived environment ID fails the CLI's format check (the chain contradicts the server's acceptance policy)",
  );
}

/**
 * The per-environment rotation injected into §7's whole-environment
 * sweep. Since obligation-entry appends and earlier rotates have
 * advanced the chain, each environment starts from a re-synced
 * view. force = §7's force (new epoch required) / verify = the
 * verification pass (resumes an unfinished re-encryption if any).
 */
export function sweepRotateFor(
  context: ProjectContext,
  reason: string,
): (
  environmentId: string,
  mode: SweepRotateMode,
) => Effect.Effect<RotationSummary, CliError, CliServices> {
  return (environmentId: string, mode: SweepRotateMode) =>
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
        // A whole-environment sweep is not a migration operation —
        // tolerating a missing manifest is limited to the explicit
        // `maruhi env rotate <env> --init-manifest` (session-27 §14)
        initManifest: false,
        signerUserId: context.session.userId,
        signingKeyPair: context.masterKeys.sigKeyPair,
        resync: context.resync,
        floor: floorHandle,
      });
    });
}
