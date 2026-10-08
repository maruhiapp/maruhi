// The bounded pass machinery of stage (ii) re-encryption (CRYPTO_SPEC §7):
// push pass -> rescan -> verdict, and the classification of an incomplete
// run (the stage overview lives in env-rotate.ts).

import { type VariableId } from "@maruhi/core";
import type { ChainDevice } from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { countNoun, displayText } from "./display.ts";
import { pushReencrypted, rescanEnvironment } from "./env-rotate-push.ts";
import {
  type ConflictedTarget,
  type ReencryptTarget,
  type RotateInput,
  type ReencryptContext,
  MAX_REENCRYPT_PASSES,
  asOutcome,
} from "./env-rotate-shared.ts";
import type { ReencryptedVariable } from "./env-rotate.ts";
import { CliError, cliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";

interface ReencryptOutcome {
  readonly reencrypted: number;
  readonly alreadyCurrent: number;
  readonly remaining: number;
  /**
   * Whether `remaining` is a **measurement** through the rescan (false =
   * the rescan was never reached and only the upper bound "the number not
   * completed this pass" is known).
   */
  readonly remainingExact: boolean;
  /**
   * The cause that interrupted the re-encryption (null = ran to the end).
   * Throwing a post-advance failure away as an exception would let the
   * fact "only the epoch advanced and re-encryption remains" slip past the
   * caller's partial-completion warning, so it is returned as a result.
   */
  readonly failure: string | null;
  /** My accepted writes (aggregated across all passes — material for RotationSummary.written). */
  readonly written: readonly ReencryptedVariable[];
}

/** Extracts just the message from a tagged failure (null-propagating). */
function failureMessage(
  failure: { readonly variableId: VariableId; readonly message: string } | null,
): string | null {
  return failure === null ? null : failure.message;
}

/**
 * Only a push failure corroborated by the end-of-pass reality becomes a
 * cause candidate. Listing a failure whose **variable resolved itself**
 * (like a concurrent deletion's 404) as the cause hides the real cause of
 * another variable that is actually still unfinished (a conflict, etc.).
 */
function pendingFailure(
  failure: { readonly variableId: VariableId; readonly message: string } | null,
  staleIds: ReadonlySet<VariableId>,
): string | null {
  if (failure === null) {
    return null;
  }
  return staleIds.has(failure.variableId) ? failure.message : null;
}

/**
 * The priority of an incompleteness cause: a push failure > unopenable
 * values > a conflict (the default wording = null). Folding an unopenable
 * value into "conflict" would send the user chasing a nonexistent
 * concurrent writer — what is actually needed is "a re-run by another
 * member who holds that epoch's wrap".
 */
function blockingCause(
  pushFailure: string | null,
  undecryptable: readonly string[],
): string | null {
  return pushFailure ?? undecryptable[0] ?? null;
}

/**
 * Closing a run that ended incomplete. When there is a cause
 * (blockingFailure) it is reported and nothing happens here; only without
 * one, the "failure that happened but is no longer the cause" is left as
 * a warning.
 */
function noteStaleFailures(
  warnings: string[],
  blockingFailure: string | null,
  seenFailure: string | null,
): void {
  if (blockingFailure !== null) {
    return;
  }
  // No failure on the last pass = what remains is the conflicts. Past failures are not the cause
  noteResolvedFailure(
    warnings,
    seenFailure,
    "they resolved in later passes (what remains incomplete is the conflicted portion)",
  );
}

/**
 * Whether the state is "unfinished work remains yet nothing can be
 * pushed" (= only undecryptable values are left). Cycling the remaining
 * passes would just repeat pulls without progress. The final pass's
 * targets is always empty since it "does not decrypt" — the judgment
 * looks only at passes that attempted decryption.
 */
function stalledOnUndecryptable(pending: readonly ReencryptTarget[], pass: number): boolean {
  return pending.length === 0 && pass < MAX_REENCRYPT_PASSES;
}

/** Builds the re-encryption context from a RotateInput + epoch-specific material. */
export function reencryptContext(
  input: RotateInput,
  /** The writer's signing device (the device holding this machine's key — device-key.ts). */
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

/** The result of one pass's pushes. */
interface PushPassResult {
  readonly reencrypted: number;
  readonly conflicted: readonly ConflictedTarget[];
  /**
   * The variables the server claimed an epoch conflict on (the rescan
   * does the matching against the chain). **Held as ids, not a count**:
   * "the claim contradicts the chain" may be asserted only when the very
   * claimed variable still remains on the rescan (if other variables
   * remain for other reasons, the run should be guided as an ordinary
   * partial completion).
   */
  readonly epochStaleIds: ReadonlySet<VariableId>;
  /** The variables that could not finish re-encrypting (409, transient failure, epoch conflict). */
  readonly unfinishedIds: ReadonlySet<VariableId>;
  /** My accepted writes (the ledger's new baseline). */
  readonly written: readonly VerifiedPulledValue[];
  /**
   * The first cause that failed individually (the pass itself doesn't
   * stop. The count lives in unfinishedIds). **Which variable failed** is
   * also kept: when the end-of-pass rescan finds that variable resolved
   * (like a concurrent deletion's 404), listing it as the incompleteness
   * cause would hide another variable's real cause, so the caller can
   * drop it by matching against reality.
   */
  readonly firstFailure: { readonly variableId: VariableId; readonly message: string } | null;
  readonly warnings: readonly string[];
}

/**
 * One pass of re-encryption pushes. Conflicts (409) go to the next
 * rescan; concurrent deletions (404) are warned and skipped.
 *
 * **An individual failure never aborts the pass**: abandoning the rest on
 * one variable's transient failure (a 502, etc.) would leave 97 of 100
 * variables readable under the old epoch's DEK when it falls on the 3rd.
 * And with one permanently-failing variable, the stable ordering would
 * make every later variable unreachable **on every re-run**. Failures are
 * aggregated as a count and a cause; the actual remainder is decided by
 * the end-of-pass rescan (the verified reality).
 */
const runPushPass = Effect.fn("env-rotate-pass.runPushPass")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly pending: readonly ReencryptTarget[];
  /** The starting number of the progress display's running count (the number re-encrypted so far). */
  readonly doneBefore: number;
}): Effect.fn.Return<PushPassResult, never, CliIo> {
  const io = yield* CliIo;
  const conflicted: ConflictedTarget[] = [];
  const written: VerifiedPulledValue[] = [];
  const unfinishedIds = new Set<VariableId>();
  const warnings: string[] = [];
  // The progress display's denominator is "the total known on this pass" (a rescan can grow the targets)
  const total = input.doneBefore + input.pending.length;
  let reencrypted = 0;
  const epochStaleIds = new Set<VariableId>();
  let firstFailure: { readonly variableId: VariableId; readonly message: string } | null = null;
  for (const target of input.pending) {
    const attempt = yield* asOutcome(
      pushReencrypted({ context: input.context, view: input.view, target }),
    );
    if (attempt.kind === "failed") {
      // The pass does not stop (never strand the remaining variables on
      // the old epoch). **Every variable's failure mode is kept**: only
      // one can be listed as the cause, so without a warning, a
      // permanently-failing variable (a too-large value, etc.) would
      // never surface its reason on any run and stay stranded on the old
      // epoch forever
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
      // The rescan judges reality by the chain-derived epoch. This
      // variable stays at the old epoch, so if the epoch did not move it
      // appears again as the next pass's target
      epochStaleIds.add(target.value.variableId);
      unfinishedIds.add(target.value.variableId);
      continue;
    }
    if (attempt.value.floorWarning !== null) {
      warnings.push(attempt.value.floorWarning);
    }
    // Promoting my accepted write into the ledger's baseline: lets later
    // rescans detect a rollback of my own writes (regression)
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

/**
 * Recording into the known-values ledger a value that passed §6.3
 * verification. There are two entries but one record shape:
 * - **this pass's targets**: kept as the consistency-check baseline
 *   (§12-5) because they can become the next pass's prev anchor — not
 *   limited to the ones that got a 409
 * - **my accepted writes**: even when the floor (SHOULD) update fails, the
 *   next rescan can compare against "the version I wrote" — detecting a
 *   response that rolls back an accepted write as a rollback regardless
 *   of the floor's presence
 * Both are "a value and its version that I verified as correct"; a split
 * record shape would weaken one side's §12-5 check, so they are unified
 * (only recordConflicts, which carries the 409's claimed version, is
 * different).
 */
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

/**
 * Overwriting the ledger at the 409's claimed version. No separate
 * conflict "set" is kept — the vanishing warning and the alreadyCurrent
 * accounting are based on the unfinished set (not limited to 409s), and
 * carrying a 409-only set around reads as "still used by some judgment".
 */
function recordConflicts(
  known: Map<VariableId, ConflictedTarget>,
  conflicted: readonly ConflictedTarget[],
): void {
  for (const conflict of conflicted) {
    known.set(conflict.variableId, conflict);
  }
}

/** The end-of-pass judgment (what to do with the completion check's result). */
type PassVerdict =
  /** Can continue (0 remaining = done). */
  | {
      readonly kind: "settled";
      readonly view: VerifiedProject;
      /** The number of variables still below the target epoch (the correct source of the completion judgment and the remaining count). */
      readonly remaining: number;
      /** The next pass's targets (empty on the final pass — no decryption even when remaining > 0). */
      readonly targets: readonly ReencryptTarget[];
      /** The reasons of the unopened values (reported as the incompleteness cause). */
      readonly undecryptable: readonly string[];
      /** The ids of variables still below the target epoch (used to pick the cause). */
      readonly staleIds: ReadonlySet<VariableId>;
      readonly alreadyCurrent: number;
    }
  /**
   * Completion could not be verified. `remaining` is "the number not
   * completed this pass", not a measurement — neither an upper nor a
   * lower bound (over-counted when another member's hand resolved the
   * conflicts, under-counted since a variable created mid-run isn't in
   * the count). The display side labels it "includes unverified"
   * (remainingExact = false).
   */
  | { readonly kind: "unverified"; readonly remaining: number; readonly failure: string }
  /** An abort no re-run resolves (cryptographic evidence, a server–chain contradiction). */
  | { readonly kind: "abort"; readonly message: string };

/**
 * The end-of-pass completion check and judgment. From the rescan's result
 * (always done regardless of conflicts / failures), one of continue /
 * done / unverified / abort is decided. The judgment priority is
 * "evidence > contradiction > continue" — evidence is resolved by no
 * re-run, so it is never folded into another reason.
 */
const settlePass = Effect.fn("env-rotate-pass.settlePass")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly known: ReadonlyMap<VariableId, ConflictedTarget>;
  readonly pass: PushPassResult;
  readonly reencrypted: number;
  /** Whether a next pass exists (= whether decrypting the remaining targets has a point). */
  readonly hasNextPass: boolean;
}): Effect.fn.Return<
  { readonly verdict: PassVerdict; readonly warnings: readonly string[] },
  never,
  never
> {
  const { environmentId, epoch } = input.context;
  // The collected warnings are not lost even when the rescan fails (the error channel cannot carry them)
  const warnings: string[] = [];
  const rescan = yield* asOutcome(
    rescanEnvironment({
      context: input.context,
      view: input.view,
      known: input.known,
      unfinishedIds: input.pass.unfinishedIds,
      collectWarning: (warning) => warnings.push(warning),
      // A pass where an epoch conflict was claimed re-fetches the chain before judging
      forceResync: input.pass.epochStaleIds.size > 0,
      decryptRemaining: input.hasNextPass,
    }),
  );
  const context = `Environment ${environmentId} has advanced to epoch ${epoch}, and re-encryption stopped after ${countNoun(input.reencrypted, "variable")}`;
  if (rescan.kind === "failed") {
    if (rescan.error.evidence === true) {
      // The rescan's pull was refused with evidence (a floor violation,
      // checkpoint-integrity rule 2). An immediate abort, same as the
      // decryption stage's evidence (rescan.value.evidence) — never
      // downgraded to "a re-run-fixable partial completion"
      return {
        warnings,
        verdict: {
          kind: "abort",
          message: `${rescan.error.message}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
        },
      } as const;
    }
    // **The rescan's failure takes priority**: a concurrent rotation's
    // detection and transient failures surface here, so they must not be
    // covered up by a single variable's transient failure (that would
    // disguise it as "a re-run fixes it" guidance)
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
    // Cryptographic evidence is the top-priority immediate abort (no
    // re-run resolves it). The epoch-advanced context is conveyed
    // together — emitting only the evidence would lose the operational
    // state
    return {
      warnings,
      verdict: {
        kind: "abort",
        message: `${rescan.value.evidence}\n${context}. This is evidence that re-running will not resolve — investigate the server's responses`,
      },
    } as const;
  }
  if (input.pass.epochStaleIds.size > 0) {
    // Even on the force-resynced chain the epoch did not move (if it
    // had, rescanEnvironment would have failed). The server's
    // EpochConflict claim contradicts the chain, and re-pushing that
    // variable cannot resolve it (same judgment as push-state.ts). But an
    // abort is allowed **only when the very claimed variable still
    // remains**: if it resolved — say another member finished writing it
    // at the same epoch — the rest remains for other reasons (a
    // transient failure, a conflict) and a re-run cleans up. Declaring
    // "a re-run won't resolve this" would keep both the resume guidance
    // and the remaining-count report from arriving. Whether
    // re-encryption is complete is decided by the verified reality, not
    // the server's self-claim. The judgment uses stale (always
    // populated) — targets is empty on the final pass
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

/**
 * The record of "a failure that happened but is no longer the cause".
 * Listing it as the cause misleads the investigation, but silently
 * dropping it erases the very fact that a 502 happened — it stays as a
 * warning with how it resolved.
 */
function noteResolvedFailure(warnings: string[], failure: string | null, resolution: string): void {
  if (failure !== null) {
    warnings.push(`There were failures during re-encryption, but ${resolution}: ${failure}`);
  }
}

/**
 * Re-encrypting the current values (§7): encrypt each target with the
 * target epoch's DEK and push it as an ordinary push, and **at the end of
 * every pass, rescan the environment and verify the completion** (up to
 * {@link MAX_REENCRYPT_PASSES} passes). The rescan doubles as confirming
 * the conflicts' reality (a winner already at the current epoch needs no
 * re-encryption) and discovering variables created after the first pull.
 * "Finished pushing every target" is not evidence of completion —
 * completion's evidence is "the re-fetched, re-verified view carries no
 * active value below the target epoch".
 *
 * Failures are never thrown — they come back as {@link
 * ReencryptOutcome.failure}: by the time this function runs the epoch has
 * already advanced, and throwing a mid-run failure (network, a concurrent
 * rotation, a floor write) as an exception would let the fact "only the
 * epoch advanced and re-encryption remains" slip past the
 * partial-completion reporting path. The exception is **cryptographic
 * evidence (RescanResult.evidence)** alone, which is an immediate abort
 * (the error channel) — it is not the "a re-run fixes it" kind of
 * failure, so it must not blend into partial-completion + resume guidance
 * (aligned with the push path's handling).
 */
export const reencryptCurrentValues = Effect.fn("env-rotate-pass.reencryptCurrentValues")(
  function* (input: {
    readonly context: ReencryptContext;
    readonly view: VerifiedProject;
    readonly targets: readonly ReencryptTarget[];
    /**
     * The warnings' receptacle (an array shared with the caller). Since an
     * abort escapes as an exception, returning them would lose the warnings
     * **only on failure** — an abort is exactly where a floor-update failure
     * or a concurrent-deletion notice matters most, so the destination is
     * shared and never lost.
     */
    readonly sink: string[];
  }): Effect.fn.Return<ReencryptOutcome, CliError, CliIo> {
    const warnings = input.sink;
    let view = input.view;
    let pending = input.targets;
    let reencrypted = 0;
    let alreadyCurrent = 0;
    /**
     * The failures that actually happened **on the latest pass** (= what
     * is blocking the completion now). Never carried across passes: if a
     * pass-1 transient failure resolved on pass 2, it is no longer the
     * cause. Carrying it would display a resolved failure while hiding
     * the real cause (an unresolvable 409 = "a conflict with a concurrent
     * push"), misdirecting the investigation toward verification failures
     * and floor violations.
     */
    let blockingFailure: string | null = null;
    /** Every failure that happened this run (for the "happened but resolved" report when it completes). */
    let seenFailure: string | null = null;
    /**
     * The number of variables still below the target epoch. **Fixed by
     * each pass's rescan**, so no initial value is held here (no path
     * reads it as 0 — it is read only after at least one pass ran).
     * Initializing it with the target count would dress an unreportable
     * number as "the default remaining count".
     */
    let staleCount = 0;
    /** The values that passed §6.3 verification this run (the baseline of the next pass's prev-anchor consistency check). */
    const known = new Map<VariableId, ConflictedTarget>();
    /** My accepted writes (aggregated across passes — the receipt-advance material). */
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
        // Never reached the rescan = the remaining count is not a measurement (PassVerdict's definition)
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
        // The re-fetched, re-verified view carries no active value below
        // the target epoch = complete. A transient mid-run failure stays
        // as a warning, a "happened but resolved in the end" fact (since
        // the completion was verified, it is not reported as a partial
        // completion with a non-zero exit)
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
        // Unfinished work remains yet nothing can be pushed = only
        // undecryptable values are left. Cycling the remaining passes
        // would just repeat pulls without progress
        break;
      }
    }
    noteStaleFailures(warnings, blockingFailure, seenFailure);
    // The passes ran out (not an abort): the remaining count is a **measurement** through the final pass's rescan
    return outcome(staleCount, blockingFailure, true);
  },
);
