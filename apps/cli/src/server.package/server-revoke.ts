import { type EnvironmentId, type KeyFingerprintHex, type UserId } from "@maruhi/core";
import { isApprovalTarget, type ProposableOperation, type SigningKeyPair } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  type ProposedSummary,
} from "../approval.package/index.ts";
import { appendOperationWithRetry } from "../chain-append.ts";
import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { chainDeletedEnvironments, chainEnvironmentIds } from "../deks.ts";
import { cliError, type CliError } from "../errors.ts";
import {
  baselinesOf,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
} from "../rotation-sweep.ts";
import { compareCodePoints } from "../scope.ts";

export const REVOKE_ROTATION_REASON = "server-revoked";

type ServerRevokeOutcome =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: RevokeSummary };

export interface RevokeSummary extends SweepOutcome {
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string | null;
  readonly skippedDeleted: readonly EnvironmentId[];
}

function requireOwner(
  verified: VerifiedProject,
  signerUserId: UserId,
): Effect.Effect<void, CliError> {
  const member = verified.state.members.get(signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("Only an owner can run revoke_server (CRYPTO_SPEC §6.2)"));
  }
  return Effect.void;
}

function selectGrant(
  verified: VerifiedProject,
  fingerprintHex: string | null,
): Effect.Effect<{ readonly serverKeyFingerprintHex: KeyFingerprintHex } | null, CliError> {
  const grants = [...verified.state.serverGrants.values()];
  if (grants.length === 0) {
    return Effect.succeed(null);
  }
  if (fingerprintHex !== null) {
    const found = grants.find((grant) => grant.serverKeyFingerprintHex === fingerprintHex);
    if (found === undefined) {
      return Effect.fail(
        cliError(
          "No active grant matches --fingerprint (check the fingerprints of active grants with `maruhi project verify`)",
        ),
      );
    }
    return Effect.succeed({ serverKeyFingerprintHex: found.serverKeyFingerprintHex });
  }
  if (grants.length > 1) {
    return Effect.fail(
      cliError(
        `Multiple grants are active (${grants.map((grant) => grant.serverKeyFingerprintHex).join(", ")}). Specify which one to revoke with --fingerprint`,
      ),
    );
  }
  const only = grants[0];
  return only === undefined
    ? Effect.succeed(null)
    : Effect.succeed({ serverKeyFingerprintHex: only.serverKeyFingerprintHex });
}

function lastRevokeSeq(verified: VerifiedProject): number | null {
  for (let index = verified.applied.length - 1; index >= 0; index -= 1) {
    const applied = verified.applied[index];
    if (applied !== undefined && applied.operation.op === "revoke_server") {
      return applied.seq;
    }
  }
  return null;
}

export const sweepAfterRevoke = Effect.fn("server-revoke.sweepAfterRevoke")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly revokeSeq: number;
  readonly rotate: SweepRotate<R>;
}): Effect.fn.Return<
  SweepOutcome & { readonly skippedDeleted: readonly EnvironmentId[] },
  CliError,
  R
> {
  const deletedVerified = chainDeletedEnvironments(input.verified);
  const skippedDeleted = chainEnvironmentIds(input.verified)
    .filter((environmentId) => deletedVerified.has(environmentId))
    .toSorted(compareCodePoints);

  const sweep = yield* sweepRotations({
    rotate: input.rotate,
    verified: input.verified,
    baselines: baselinesOf(
      rotationMandates(input.verified).filter(
        (mandate) => mandate.kind === "server-revoked" && mandate.seq === input.revokeSeq,
      ),
    ),
    deletedVerified,
  });
  return { ...sweep, skippedDeleted };
});

export const serverRevokeOp = Effect.fn("server-revoke.serverRevokeOp")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly fingerprintHex: string | null;
  readonly signerUserId: UserId;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly rotate: SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<ServerRevokeOutcome, CliError, R> {
  yield* requireOwner(input.verified, input.signerUserId);
  const target = yield* selectGrant(input.verified, input.fingerprintHex);

  let verified = input.verified;
  let appended = false;
  let revokedFingerprint: string | null = null;

  if (target !== null) {
    const inner: ProposableOperation = {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: target.serverKeyFingerprintHex },
    };
    if (isApprovalTarget(inner, input.verified.state.approvalPolicy)) {
      const proposal = yield* proposeOperation(input, inner, (view) =>
        Effect.gen(function* () {
          yield* requireOwner(view, input.signerUserId);
          if (!view.state.serverGrants.has(target.serverKeyFingerprintHex)) {
            return yield* Effect.fail(
              cliError(
                "The grant was revoked by a concurrent run while this proposal was being appended — nothing to propose. Re-run `maruhi server revoke` to resume the rotation",
              ),
            );
          }
        }),
      );
      return { kind: "proposed", proposal };
    }

    revokedFingerprint = target.serverKeyFingerprintHex;
    const outcome = yield* appendOperationWithRetry(input, {
      operation: inner,
      initial: { verified, alreadyRevoked: false },
      settled: (state) => state.alreadyRevoked,
      recheck: (resynced) =>
        Effect.gen(function* () {
          yield* requireOwner(resynced, input.signerUserId);
          yield* ensureStillTarget(resynced, inner, false);
          return {
            verified: resynced,
            alreadyRevoked: !resynced.state.serverGrants.has(target.serverKeyFingerprintHex),
          };
        }),
    });
    verified = outcome.state.verified;
    appended = outcome.entry !== null;
    verified = yield* resyncExtended(input.resync, verified);
    if (verified.state.serverGrants.has(target.serverKeyFingerprintHex)) {
      return yield* Effect.fail(
        cliError(
          "The resync after revoke_server was accepted still shows the grant as active (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
  }

  const revokeSeq = lastRevokeSeq(verified);
  if (revokeSeq === null) {
    return yield* Effect.fail(
      cliError(
        "There is no active grant_server and no revoke_server on the chain (nothing to revoke)",
      ),
    );
  }
  const sweep = yield* sweepAfterRevoke({
    client: input.client,
    verified,
    revokeSeq,
    rotate: input.rotate,
  });
  return {
    kind: "applied",
    summary: { appended, serverKeyFingerprintHex: revokedFingerprint, ...sweep },
  };
});
