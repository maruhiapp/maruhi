// Shared vocabulary of env-rotate.ts's two stages: the rotation input
// contract (RotateInput), the re-encryption material types (ReencryptTarget
// / ConflictedTarget / ReencryptContext), and the small helpers several
// stages use (the stage overview lives in env-rotate.ts).

import type { EnvironmentId } from "@maruhi/core";
import type { ChainMember, SigningKeyPair } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { requireWritingMember } from "./dek-wrap.ts";
import {
  type DekRecipient,
  refuseChainDeletedEnvironment,
  requireChainEnvironment,
} from "./deks.ts";
import { CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";

/** The re-encryption pass limit (one pass = a push to every target + re-fetch / re-verify of the conflicts). */
export const MAX_REENCRYPT_PASSES = 3;

export interface RotateInput {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly recipient: DekRecipient;
  /**
   * The reason recorded on the chain (the §6.2 payload field).
   * `undefined` means **`--reason` itself was not given** (distinct from
   * the empty string — checkReasonLength).
   */
  readonly reason: string | undefined;
  /**
   * Even with an unfinished re-encryption, never resume it — always create
   * a new epoch (`--new-epoch`). A guarantee for a caller that requires
   * "a new epoch definitely exists after this run" (the all-environment
   * rotation on a departing member's removal — §7).
   */
  readonly forceNewEpoch: boolean;
  readonly signerUserId: string;
  readonly signingKeyPair: SigningKeyPair;
  /** Resync (full chain re-verification). Used for CAS conflicts and post-acceptance confirmation. */
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The local floor (§6.3 — the check / commit of internal pulls and the floor advance of re-encryption pushes). */
  readonly floor: FloorHandle;
}

/** The material of one variable's re-encryption (the verified latest value + its plaintext). */
export interface ReencryptTarget {
  readonly value: VerifiedPulledValue;
  /**
   * Memory only. No path puts it on disk, in logs, or in error messages.
   * Since it holds the value itself (not just a DEK) for re-encryption, it
   * is wrapped in `Redacted` — unwrapping happens only inside
   * encryptAndSignPayload (the encryption boundary).
   */
  readonly plaintext: Redacted.Redacted<Uint8Array>;
}

/** One variable that got a 409 (keeps the known latest needed for verifying the winner and the claimed version). */
export interface ConflictedTarget {
  readonly variableId: string;
  /** The verified value I used as the prev's basis at the conflict. */
  readonly known: VerifiedPulledValue;
  /** The latest version the 409 claimed (the input of the winner-consistency check — never the basis of adopt/reject). */
  readonly currentVersion: number;
}

/**
 * Warning dedup. The first pull and each pass's rescan return the same
 * pull-wide SHOULD warnings (non-NFC names etc.), so naively listing them
 * prints the same line 4 times and buries the run-specific warnings
 * (concurrent deletions, a missing floor).
 */
export function dedupeWarnings(warnings: readonly string[]): readonly string[] {
  return [...new Set(warnings)];
}

/**
 * Early check of rotatability: the environment exists on the chain, I am a
 * current member, and my role is member or above (§6.2). Drops before the
 * pull (fetching values = recording var.read). With grant_server enabled,
 * the complete wrap set includes a server-key wrap (buildWrapCompleteSet —
 * §12-4 / §7's re-wrap duty).
 */
export const ensureRotatable = Effect.fn("env-rotate-shared.ensureRotatable")(function* (
  verified: VerifiedProject,
  environmentId: string,
  signerUserId: string,
  signingKeyPair: SigningKeyPair,
): Effect.fn.Return<ChainMember, CliError> {
  // A chain-deleted environment first: the deletion pruned it from every
  // listed scope, so the scope check would misreport it (§6.2 — the same
  // order as the command prologues)
  yield* refuseChainDeletedEnvironment(verified, environmentId);
  // Membership + the device's effective role (member or above) / scope are shared with env create
  const { member } = yield* requireWritingMember({
    verified,
    environmentId,
    signerUserId,
    signingKeyPair,
    operation: "rotate the epoch",
    forbidden:
      "A reader cannot rotate the epoch (rotate_epoch and value pushes require the member role or above — CRYPTO_SPEC §6.2)",
  });
  yield* requireChainEnvironment(verified, environmentId);
  return member;
});

/**
 * The context the 3 re-encryption functions share (one variable's push,
 * one pass's push, the end-of-pass rescan). Only the view and the targets
 * change per pass, so the invariants are bundled into one (avoids the
 * same long argument list being duplicated per call site).
 */
export interface ReencryptContext {
  readonly client: MaruhiClient;
  readonly environmentId: EnvironmentId;
  readonly floor: FloorHandle;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  /** The re-encryption's target epoch (the post-rotation new epoch / the current epoch on a resume). */
  readonly epoch: number;
  readonly dek: Redacted.Redacted<Uint8Array>;
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly writerUserId: string;
  /** My key FP (the attribution when recording my accepted writes into the ledger). */
  readonly writerKeyFingerprintHex: string;
  readonly signingKey: CryptoKey;
}

/**
 * Failures are carried back as a value, never thrown. A post-advance
 * failure must ride the "partial completion" reporting path — escaping as
 * an exception would lose the operational state.
 */
export function asOutcome<A, E, R>(
  effect: Effect.Effect<A, E, R>,
): Effect.Effect<
  { readonly kind: "ok"; readonly value: A } | { readonly kind: "failed"; readonly error: E },
  never,
  R
> {
  return effect.pipe(
    Effect.map((value) => ({ kind: "ok", value }) as const),
    Effect.catch((error) => Effect.succeed({ kind: "failed", error } as const)),
  );
}
