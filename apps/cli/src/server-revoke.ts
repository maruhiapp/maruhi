// `maruhi server revoke` (CRYPTO_SPEC §7 / §9).
//
// Appends revoke_server to the chain and forcibly rotates **every
// environment of the project** (§7 — the revocation's effectiveness
// is carried by rotation. A revoke without rotation is the
// pretense of "having stopped the disclosure"). The rotation
// reuses envRotateOp per environment (reason is a fixed string).
//
// Interruption recovery (no progress file — derived from the
// distributed state): even if it crashes after the revoke lands on
// the chain, a re-run converges around "the last revoke_server's
// seq":
// - An environment whose current epoch's start seq precedes the
//   revoke = not yet rotated → forced rotation (forceNewEpoch)
// - An environment whose start seq is after the revoke = the epoch
//   advanced, but **a mid-flight re-encryption crash may remain**
//   (§12-7's transient state) → the verification pass (envRotateOp
//   without forceNewEpoch = resumes the incomplete, check-only
//   otherwise) closes the "looks complete because the epoch merely
//   advanced" pretense
// A deleted environment is skipped only when a **verified deletion
// statement** exists (never skipped silently on the server's 404
// declaration alone — §7. If it cannot be verified it stays a
// target and surfaces as a rotate failure).

import { ChainHeadConflictError } from "@maruhi/api-schema";
import {
  type ChainEntry,
  isApprovalTarget,
  type ProposableOperation,
  type SigningKeyPair,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import {
  ensureStillTarget,
  type ProposalInput,
  proposeOperation,
  type ProposedSummary,
} from "./approval.ts";
import { appendEntry, signEntryAtHead } from "./chain-append.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { chainDeletedEnvironments } from "./deks.ts";
import { cliError, type CliError } from "./errors.ts";
import { retryOnConflict } from "./retry.ts";
import {
  baselinesOf,
  rotationMandates,
  type SweepOutcome,
  type SweepRotate,
  sweepRotations,
} from "./rotation-sweep.ts";
import { compareCodePoints } from "./scope.ts";

const MAX_ATTEMPTS = 5;

/** The reason recorded on the chain by the post-revoke whole-environment rotation (§6.2 payload). */
export const REVOKE_ROTATION_REASON = "server-revoked";

/** The revoke's result: a proposal (four-eyes — K6) or an application. */
type ServerRevokeOutcome =
  | { readonly kind: "proposed"; readonly proposal: ProposedSummary }
  | { readonly kind: "applied"; readonly summary: RevokeSummary };

export interface RevokeSummary extends SweepOutcome {
  /** Whether it was appended to the chain (false = no valid grant / already revoked by a concurrent revoke — resume from the post-revoke rest). */
  readonly appended: boolean;
  readonly serverKeyFingerprintHex: string | null;
  /** Environments skipped because the verified chain shows them deleted (delete_environment). */
  readonly skippedDeleted: readonly string[];
}

function requireOwner(
  verified: VerifiedProject,
  signerUserId: string,
): Effect.Effect<void, CliError> {
  const member = verified.state.members.get(signerUserId);
  if (member === undefined || member.role !== "owner") {
    return Effect.fail(cliError("Only an owner can run revoke_server (CRYPTO_SPEC §6.2)"));
  }
  return Effect.void;
}

/** Selects the grant to revoke (when several exist, disambiguate with --fingerprint). */
function selectGrant(
  verified: VerifiedProject,
  fingerprintHex: string | null,
): Effect.Effect<{ readonly serverKeyFingerprintHex: string } | null, CliError> {
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

/** Signs a revoke_server entry immediately after the current head (the shared core = chain-append.ts). */
function signRevokeEntry(input: {
  readonly verified: VerifiedProject;
  readonly signerUserId: string;
  readonly serverKeyFingerprintHex: string;
  readonly signingKeyPair: SigningKeyPair;
}): Effect.Effect<ChainEntry, CliError> {
  return signEntryAtHead({
    verified: input.verified,
    signerUserId: input.signerUserId,
    operation: {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: input.serverKeyFingerprintHex },
    },
    signingKeyPair: input.signingKeyPair,
    failureText: "Failed to sign the revoke_server entry",
  });
}

/** The applied seq of the last revoke_server on the chain (null when absent. Includes applications via a proposal — K6-C). */
function lastRevokeSeq(verified: VerifiedProject): number | null {
  for (let index = verified.applied.length - 1; index >= 0; index -= 1) {
    const applied = verified.applied[index];
    if (applied !== undefined && applied.operation.op === "revoke_server") {
      return applied.seq;
    }
  }
  return null;
}

/**
 * The whole-environment sweep after revoke application (§7).
 * Shared by the direct-append revoke and the fulfiller of an
 * approval that completed the application under four-eyes
 * (approval-approve.ts). `revokeSeq` = the obligation's reference
 * (the applied seq).
 */
export const sweepAfterRevoke = Effect.fn("server-revoke.sweepAfterRevoke")(function* <R>(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly revokeSeq: number;
  readonly rotate: SweepRotate<R>;
}): Effect.fn.Return<SweepOutcome & { readonly skippedDeleted: readonly string[] }, CliError, R> {
  // Excludes chain-deleted environments from the rotation targets
  // (a deleted environment returns 404 for both rotate and pull, and
  // no wrap remains to rotate). The only basis for exclusion is the
  // **delete_environment entry on the verified chain** — never
  // skipped silently on the server's 404 declaration alone (§7)
  const deletedVerified = chainDeletedEnvironments(input.verified);
  const skippedDeleted = [...input.verified.state.environments.keys()]
    .filter((environmentId) => deletedVerified.has(environmentId))
    .toSorted(compareCodePoints);

  // The obligation's environment set = every environment at the
  // revoke's point (§7 — revoke_server is immutable; the server
  // key cannot hold the DEK of a later-created environment). The
  // derivation is shared with rotationMandates
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
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /**
   * One environment's rotation (envRotateOp wrapped with the
   * per-environment floor — cli.ts injects it). force = reason
   * fixed + forceNewEpoch (§7's force), verify = no reason + no
   * forceNewEpoch (resumes an incomplete re-encryption if any,
   * check-only otherwise — creates no new epoch).
   */
  readonly rotate: SweepRotate<R>;
  readonly proposal: ProposalInput;
}): Effect.fn.Return<ServerRevokeOutcome, CliError, R> {
  yield* requireOwner(input.verified, input.signerUserId);
  const target = yield* selectGrant(input.verified, input.fingerprintHex);

  // Four-eyes (K6-A): when the policy covers revoke_server,
  // propose and finish (the whole-environment rotate is done by
  // the approver who completed the application — approval item
  // 22). A resume (no valid grant) is not proposed
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
  }

  let verified = input.verified;
  let appended = false;
  let revokedFingerprint: string | null = null;

  if (target !== null) {
    revokedFingerprint = target.serverKeyFingerprintHex;
    const outcome = yield* retryOnConflict(
      { verified, target: target.serverKeyFingerprintHex, alreadyRevoked: false },
      {
        maxAttempts: MAX_ATTEMPTS,
        attempt: (state) =>
          // Already revoked by a concurrent revoke — skip the append and proceed to rotation.
          state.alreadyRevoked
            ? Effect.succeed({ verified: state.verified, appended: false })
            : Effect.gen(function* () {
                const entry = yield* signRevokeEntry({
                  verified: state.verified,
                  signerUserId: input.signerUserId,
                  serverKeyFingerprintHex: state.target,
                  signingKeyPair: input.signingKeyPair,
                });
                yield* appendEntry(input.client, state.verified, entry);
                return { verified: state.verified, appended: true };
              }),
        classify: (error) => (error instanceof ChainHeadConflictError ? "head-conflict" : null),
        recover: (state) =>
          Effect.gen(function* () {
            const resynced = yield* resyncExtended(input.resync, state.verified);
            yield* requireOwner(resynced, input.signerUserId);
            yield* ensureStillTarget(
              resynced,
              { op: "revoke_server", payload: { serverKeyFingerprintHex: state.target } },
              false,
            );
            // If already revoked by a concurrent revoke, skip the append and proceed (the rotation still runs)
            return {
              verified: resynced,
              target: state.target,
              alreadyRevoked: !resynced.state.serverGrants.has(state.target),
            };
          }),
        exhaustedMessage: `revoke_server's chain-head conflict did not resolve (${MAX_ATTEMPTS} attempts). Wait a moment and re-run`,
      },
    );
    verified = outcome.verified;
    appended = outcome.appended;
    // After acceptance, a re-sync confirms the revocation's posting (the server declaration is not the source of truth)
    verified = yield* resyncExtended(input.resync, verified);
    if (verified.state.serverGrants.has(target.serverKeyFingerprintHex)) {
      return yield* Effect.fail(
        cliError(
          "The resync after revoke_server was accepted still shows the grant as active (the server's response contradicts the chain). Investigate the served chain",
        ),
      );
    }
  }

  // Deriving the rotation targets: on a run that appended, "the
  // last revoke's seq" is this run's append itself; on a run
  // that did not append (interruption recovery) it is taken
  // from the chain history
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
