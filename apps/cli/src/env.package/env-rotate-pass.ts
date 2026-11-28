import { type VariableId } from "@maruhi/core";
import type { ChainDevice } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun, displayText } from "../display.ts";
import { CliError, cliError } from "../errors.ts";
import { CliIo } from "../io.ts";
import type { ReencryptedVariable } from "../rotation-sweep.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import { pushReencrypted, rescanEnvironment } from "./env-rotate-push.ts";
import {
  type ConflictedTarget,
  type ReencryptTarget,
  type RotateInput,
  type ReencryptContext,
  MAX_REENCRYPT_PASSES,
  asOutcome,
} from "./env-rotate-shared.ts";

interface ReencryptOutcome {
  readonly reencrypted: number;
  readonly alreadyCurrent: number;
  readonly remaining: number;
  readonly remainingExact: boolean;
  readonly failure: string | null;
  readonly written: readonly ReencryptedVariable[];
}

function failureMessage(
  failure: { readonly variableId: VariableId; readonly message: string } | null,
): string | null {
  return failure === null ? null : failure.message;
}

function pendingFailure(
  failure: { readonly variableId: VariableId; readonly message: string } | null,
  staleIds: ReadonlySet<VariableId>,
): string | null {
  if (failure === null) {
    return null;
  }
  return staleIds.has(failure.variableId) ? failure.message : null;
}

function blockingCause(
  pushFailure: string | null,
  undecryptable: readonly string[],
): string | null {
  return pushFailure ?? undecryptable[0] ?? null;
}

function noteStaleFailures(
  warnings: string[],
  blockingFailure: string | null,
  seenFailure: string | null,
): void {
  if (blockingFailure !== null) {
    return;
  }
  noteResolvedFailure(
    warnings,
    seenFailure,
    "they resolved in later passes (what remains incomplete is the conflicted portion)",
  );
}

function stalledOnUndecryptable(pending: readonly ReencryptTarget[], pass: number): boolean {
  return pending.length === 0 && pass < MAX_REENCRYPT_PASSES;
}

export function reencryptContext(
  input: RotateInput,
  writerDevice: ChainDevice,
  epochMaterial: {
    readonly epoch: number;
    readonly dek: Redacted.Redacted<Uint8Array>;
    readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  },
): ReencryptContext {
  return {
    client: input.client,
    environmentId: input.environmentId,
    floor: input.floor,
    resync: input.resync,
    writerUserId: input.signerUserId,
    writerKeyFingerprintHex: writerDevice.keyFingerprintHex,
    signingKey: input.signingKeyPair.privateKey,
    ...epochMaterial,
  };
}

interface PushPassResult {
  readonly reencrypted: number;
  readonly conflicted: readonly ConflictedTarget[];
  readonly epochStaleIds: ReadonlySet<VariableId>;
  readonly unfinishedIds: ReadonlySet<VariableId>;
  readonly written: readonly VerifiedPulledValue[];
  readonly firstFailure: { readonly variableId: VariableId; readonly message: string } | null;
  readonly warnings: readonly string[];
}

const runPushPass = Effect.fn("env-rotate-pass.runPushPass")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly pending: readonly ReencryptTarget[];
  readonly doneBefore: number;
}): Effect.fn.Return<PushPassResult, never, CliIo> {
  const io = yield* CliIo;
  const conflicted: ConflictedTarget[] = [];
  const written: VerifiedPulledValue[] = [];
  const unfinishedIds = new Set<VariableId>();
  const warnings: string[] = [];
  const total = input.doneBefore + input.pending.length;
  let reencrypted = 0;
  const epochStaleIds = new Set<VariableId>();
  let firstFailure: { readonly variableId: VariableId; readonly message: string } | null = null;
  for (const target of input.pending) {
    const attempt = yield* asOutcome(
      pushReencrypted({ context: input.context, view: input.view, target }),
    );
    if (attempt.kind === "failed") {
      const message = `Failed to re-encrypt variable ${displayText(target.value.name)}: ${attempt.error.message}`;
      warnings.push(message);
      firstFailure ??= { variableId: target.value.variableId, message };
      unfinishedIds.add(target.value.variableId);
      continue;
    }
    if (attempt.value.kind === "conflict") {
      conflicted.push({
        variableId: target.value.variableId,
        known: target.value,
        currentVersion: attempt.value.currentVersion,
      });
      unfinishedIds.add(target.value.variableId);
      continue;
    }
    if (attempt.value.kind === "deleted") {
      warnings.push(
        `Re-encryption of variable ${displayText(target.value.name)} was rejected with 404 (possibly deleted concurrently by another member). If it is gone from the re-fetched active set it is dropped from the targets; if it is still being served it is counted as incomplete`,
      );
      firstFailure ??= {
        variableId: target.value.variableId,
        message: `Re-encryption of variable ${displayText(target.value.name)} was rejected with 404 (possible concurrent deletion)`,
      };
      unfinishedIds.add(target.value.variableId);
      continue;
    }
    if (attempt.value.kind === "epoch-stale") {
      epochStaleIds.add(target.value.variableId);
      unfinishedIds.add(target.value.variableId);
      continue;
    }
    if (attempt.value.floorWarning !== null) {
      warnings.push(attempt.value.floorWarning);
    }
    written.push(attempt.value.written);
    reencrypted += 1;
    yield* io.log(
      `  Re-encrypted (${input.doneBefore + reencrypted}/${total}): ${displayText(target.value.name)} (version=${target.value.version + 1})`,
    );
  }
  return {
    reencrypted,
    conflicted,
    epochStaleIds,
    unfinishedIds,
    written,
    firstFailure,
    warnings,
  };
});

function recordKnown(
  known: Map<VariableId, ConflictedTarget>,
  values: readonly VerifiedPulledValue[],
): void {
  for (const value of values) {
    known.set(value.variableId, {
      variableId: value.variableId,
      known: value,
      currentVersion: value.version,
    });
  }
}

function recordConflicts(
  known: Map<VariableId, ConflictedTarget>,
  conflicted: readonly ConflictedTarget[],
): void {
  for (const conflict of conflicted) {
    known.set(conflict.variableId, conflict);
  }
}

type PassVerdict =
  | {
      readonly kind: "settled";
      readonly view: VerifiedProject;
      readonly remaining: number;
      readonly targets: readonly ReencryptTarget[];
      readonly undecryptable: readonly string[];
      readonly staleIds: ReadonlySet<VariableId>;
      readonly alreadyCurrent: number;
    }
  | { readonly kind: "unverified"; readonly remaining: number; readonly failure: string }
  | { readonly kind: "abort"; readonly message: string };

const settlePass = Effect.fn("env-rotate-pass.settlePass")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly known: ReadonlyMap<VariableId, ConflictedTarget>;
  readonly pass: PushPassResult;
  readonly reencrypted: number;
  readonly hasNextPass: boolean;
}): Effect.fn.Return<
  { readonly verdict: PassVerdict; readonly warnings: readonly string[] },
  never,
  never
> {
  const { environmentId, epoch } = input.context;
  const warnings: string[] = [];
  const rescan = yield* asOutcome(
    rescanEnvironment({
      context: input.context,
      view: input.view,
      known: input.known,
      unfinishedIds: input.pass.unfinishedIds,
      collectWarning: (warning) => warnings.push(warning),
      forceResync: input.pass.epochStaleIds.size > 0,
      decryptRemaining: input.hasNextPass,
    }),
  );
  const context = `Environment ${environmentId} has advanced to epoch ${epoch}, and re-encryption stopped after ${countNoun(input.reencrypted, "variable")}`;
  if (rescan.kind === "failed") {
    if (rescan.error.evidence === true) {
      return {
        warnings,
        verdict: {
          kind: "abort",
          message: `${rescan.error.message}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
        },
      } as const;
    }
    const pushFailure =
      input.pass.firstFailure === null
        ? ""
        : ` (there were also failures during re-encryption: ${input.pass.firstFailure.message})`;
    return {
      warnings,
      verdict: {
        kind: "unverified",
        remaining: input.pass.unfinishedIds.size,
        failure: `${rescan.error.message}${pushFailure}`,
      },
    } as const;
  }
  if (rescan.value.evidence !== null) {
    return {
      warnings,
      verdict: {
        kind: "abort",
        message: `${rescan.value.evidence}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
      },
    } as const;
  }
  if (input.pass.epochStaleIds.size > 0) {
    const unresolved = rescan.value.stale.filter((value) =>
      input.pass.epochStaleIds.has(value.variableId),
    );
    if (unresolved.length > 0) {
      return {
        warnings,
        verdict: {
          kind: "abort",
          message: `The server reported an epoch conflict, but the chain is still at epoch ${epoch} (the server's response contradicts the chain). ${context} — re-running will not resolve this`,
        },
      } as const;
    }
    warnings.push(
      `The server reported an epoch conflict for a re-encryption push, but the chain was still at epoch ${epoch} (the server's response contradicts the chain). The reported variable is not in the rescanned incomplete set (it was rewritten at the current epoch, or deleted), so processing continues — but the contradictory response itself warrants investigation`,
    );
  }
  return {
    warnings,
    verdict: {
      kind: "settled",
      view: rescan.value.view,
      remaining: rescan.value.stale.length,
      targets: rescan.value.targets,
      undecryptable: rescan.value.undecryptable,
      staleIds: new Set(rescan.value.stale.map((value) => value.variableId)),
      alreadyCurrent: rescan.value.alreadyCurrent,
    },
  } as const;
});

function noteResolvedFailure(warnings: string[], failure: string | null, resolution: string): void {
  if (failure !== null) {
    warnings.push(`There were failures during re-encryption, but ${resolution}: ${failure}`);
  }
}

export const reencryptCurrentValues = Effect.fn("env-rotate-pass.reencryptCurrentValues")(
  function* (input: {
    readonly context: ReencryptContext;
    readonly view: VerifiedProject;
    readonly targets: readonly ReencryptTarget[];
    readonly sink: string[];
  }): Effect.fn.Return<ReencryptOutcome, CliError, CliIo> {
    const warnings = input.sink;
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;
    let blockingFailure: string | null = null;
    let seenFailure: string | null = null;
    let staleCount = 0;
    const known = new Map<VariableId, ConflictedTarget>();
    const written: ReencryptedVariable[] = [];

    const outcome = (
      remaining: number,
      failure: string | null,
      remainingExact: boolean,
    ): ReencryptOutcome => ({
      reencrypted,
      alreadyCurrent,
      remaining,
      remainingExact,
      failure,
      written,
    });

    for (let pass = 1; pass <= MAX_REENCRYPT_PASSES; pass += 1) {
      recordKnown(
        known,
        pending.map((target) => target.value),
      );
      const attempted = yield* runPushPass({
        context: input.context,
        view,
        pending,
        doneBefore: reencrypted,
      });
      reencrypted += attempted.reencrypted;
      warnings.push(...attempted.warnings);
      written.push(
        ...attempted.written.map((value) => ({ name: value.name, version: value.version })),
      );
      recordKnown(known, attempted.written);
      recordConflicts(known, attempted.conflicted);
      const settled = yield* settlePass({
        context: input.context,
        view,
        known,
        pass: attempted,
        reencrypted,
        hasNextPass: pass < MAX_REENCRYPT_PASSES,
      });
      warnings.push(...settled.warnings);
      if (settled.verdict.kind === "unverified") {
        return outcome(settled.verdict.remaining, settled.verdict.failure, false);
      }
      if (settled.verdict.kind === "abort") {
        return yield* Effect.fail(cliError(settled.verdict.message));
      }
      view = settled.verdict.view;
      pending = settled.verdict.targets;
      alreadyCurrent += settled.verdict.alreadyCurrent;
      staleCount = settled.verdict.remaining;
      if (staleCount === 0) {
        noteResolvedFailure(
          warnings,
          failureMessage(attempted.firstFailure) ?? seenFailure,
          "the rescan confirmed completion",
        );
        return outcome(0, null, true);
      }
      blockingFailure = blockingCause(
        pendingFailure(attempted.firstFailure, settled.verdict.staleIds),
        settled.verdict.undecryptable,
      );
      seenFailure ??= failureMessage(attempted.firstFailure);
      if (stalledOnUndecryptable(pending, pass)) {
        break;
      }
    }
    noteStaleFailures(warnings, blockingFailure, seenFailure);
    return outcome(staleCount, blockingFailure, true);
  },
);
