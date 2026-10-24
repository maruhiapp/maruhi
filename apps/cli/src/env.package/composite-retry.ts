// The CAS retry the two composite requests share (AUTH_SPEC §12-4): env
// create's create_environment composite (env-create.ts) and env rotate's
// rotate_epoch composite (env-rotate-send.ts) each send a signed chain
// entry with an epoch's complete DEK wrap set, and retry a conflict the
// same way through retry.ts's retryOnConflict. What the two share lives
// here: which failures are retryable, the recovery's resync and wrap-set
// reuse, and the wording when the attempts run out.

import type { WrappedDek } from "@maruhi/api-schema";
import { AuditHeadNotReadyError, ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainMember } from "@maruhi/crypto";
import { Effect } from "effect";

import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { sameWrapRecipientSet } from "../dek-wrap.ts";
import type { CliError } from "../errors.ts";

/** The CAS retry state: the verified view, own member row, and the epoch's wrap set. */
export interface CompositeState {
  readonly verified: VerifiedProject;
  readonly member: ChainMember;
  readonly deks: readonly WrappedDek[];
}

/**
 * The composites' retryable conflicts: a parent-head CAS failure
 * (ChainHeadConflict — a concurrent append), and AuditHeadNotReady (503 —
 * the bounded extension of the audit-head derived column is incomplete;
 * AUDIT_SPEC §5.1), which advances via the same recovery (resync +
 * re-sign + resend): even on a failure response the server's extension
 * is saved, and the re-extension on resend only covers the remainder. The
 * CLI's boundary checkpoint is not notarized (empty — ruling M-b), so the
 * 503 is unreachable from the current server, but it is classified
 * retryable defensively as a contract-declared error.
 */
export function classifyCompositeConflict(error: unknown): "head-conflict" | null {
  return error instanceof ChainHeadConflictError || error instanceof AuditHeadNotReadyError
    ? "head-conflict"
    : null;
}

/**
 * Recovers from a conflict. The resync is **extension-checked**
 * (§6.3-2b): it closes the path where a server that returned the conflict
 * serves a signature-valid shortened or forked chain, and the entry is
 * re-signed and the wrap set rebuilt on a rolled-back member / grant
 * state. `recheck` redoes the op's checks on the resynced view and
 * returns own member row; the wrap set is rebuilt only when the recipient
 * set changed (dek-wrap.ts — HPKE Seal is random, so unneeded re-wraps are
 * avoided). A definite error from the resync or `recheck` still surfaces
 * after the final attempt, per retryOnConflict's convention.
 */
export const recoverComposite = Effect.fn("composite-retry.recoverComposite")(function* (
  state: CompositeState,
  input: {
    readonly resync: Effect.Effect<VerifiedProject, CliError>;
    readonly environmentId: EnvironmentId;
    readonly recheck: (resynced: VerifiedProject) => Effect.Effect<ChainMember, CliError>;
    readonly buildWraps: (
      resynced: VerifiedProject,
    ) => Effect.Effect<readonly WrappedDek[], CliError>;
  },
): Effect.fn.Return<CompositeState, CliError> {
  const resynced = yield* resyncExtended(input.resync, state.verified);
  const member = yield* input.recheck(resynced);
  const deks = sameWrapRecipientSet(state.verified, resynced, input.environmentId)
    ? state.deks
    : yield* input.buildWraps(resynced);
  return { verified: resynced, member, deks };
});

/**
 * The wording once every attempt ended in a retryable conflict.
 * AuditHeadNotReady circulates under the same classification, so it names
 * both causes (prevents mis-guidance if it ever becomes reachable).
 */
export function compositeExhaustedMessage(subject: string, attempts: number): string {
  return `${subject} kept being rejected with retryable conflicts (a chain-head conflict, or audit-head materialization in progress) after ${attempts} attempts. Wait a moment and re-run — server-side progress is preserved`;
}
