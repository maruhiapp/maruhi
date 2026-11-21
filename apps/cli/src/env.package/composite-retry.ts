import type { WrappedDek } from "@maruhi/api-schema";
import { AuditHeadNotReadyError, ChainHeadConflictError } from "@maruhi/api-schema";
import type { EnvironmentId } from "@maruhi/core";
import type { ChainMember } from "@maruhi/crypto";
import { Effect } from "effect";

import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { sameWrapRecipientSet } from "../dek-wrap.ts";
import type { CliError } from "../errors.ts";

export interface CompositeState {
  readonly verified: VerifiedProject;
  readonly member: ChainMember;
  readonly deks: readonly WrappedDek[];
}

export function classifyCompositeConflict(error: unknown): "head-conflict" | null {
  return error instanceof ChainHeadConflictError || error instanceof AuditHeadNotReadyError
    ? "head-conflict"
    : null;
}

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

export function compositeExhaustedMessage(subject: string, attempts: number): string {
  return `${subject} kept being rejected with retryable conflicts (a chain-head conflict, or audit-head materialization in progress) after ${attempts} attempts. Wait a moment and re-run — server-side progress is preserved`;
}
