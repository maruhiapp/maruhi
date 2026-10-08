// Stage (ii) writes of `maruhi env rotate`: pushing one re-encrypted value
// (an ordinary push signed by the performer as writer — CRYPTO_SPEC §7 /
// §4.1) and the verified rescan that drives the completion judgment and
// the §12-5 409 re-planning (the stage overview lives in env-rotate.ts).

import { Effect } from "effect";

import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { requireChainEnvironment } from "./deks.ts";
import { displayText } from "./display.ts";
import { decryptTargets, undecryptableWarning } from "./env-rotate-decrypt.ts";
import {
  type ConflictedTarget,
  type ReencryptTarget,
  type ReencryptContext,
  asOutcome,
} from "./env-rotate-shared.ts";
import { CliError, cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { variableIdOf } from "./ids.ts";
import { missingWrapReason } from "./pull.ts";
import { winnerInconsistency } from "./push-winner.ts";
import { encryptAndSignPayload } from "./push.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";
import { pullVerifiedEnvironment } from "./values.ts";

/** The result of one variable's re-encryption push (a conflict carries back the 409's claimed version). */
type PushAttempt =
  /**
   * Accepted. Accompanied by a warning only when the floor update failed
   * (the acceptance itself cannot be taken back). `written` is **my
   * accepted write** and becomes the consistency-check baseline of later
   * rescans (the floor is a SHOULD and its write can fail, so a rollback
   * use of one's own writes never relies on the floor alone).
   */
  | {
      readonly kind: "pushed";
      readonly floorWarning: string | null;
      readonly written: VerifiedPulledValue;
    }
  | { readonly kind: "conflict"; readonly currentVersion: number }
  /** A concurrent deletion (404). A deleted variable has no current value to re-encrypt. */
  | { readonly kind: "deleted" }
  /**
   * The server claimed an epoch conflict (409 EpochConflict). The cause
   * is not decided here — left to the rescan (a chain re-verification):
   * whether "another member rotated concurrently" or "the server's claim
   * contradicts the chain" is indistinguishable until the chain-derived
   * current epoch is observed (same discipline as push-state.ts's
   * epoch-conflict).
   */
  | { readonly kind: "epoch-stale" };

/**
 * The push of one variable's re-encryption (§7 / §4.1 — a re-encryption
 * is "an ordinary push signed by the performer as writer" and carries no
 * dedicated wire or authorization).
 */
export const pushReencrypted = Effect.fn("env-rotate-push.pushReencrypted")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly target: ReencryptTarget;
}): Effect.fn.Return<PushAttempt, CliError> {
  const { environmentId, epoch, dek, writerUserId, signingKey, floor, client } = input.context;
  const latest = input.target.value;
  const version = latest.version + 1;
  // The prev is the **self-computed** hash of the verified latest value
  // (never chain-sign onto the server-claimed hash — avoiding the
  // evidence-chain contamination of §12-5)
  const signed = yield* encryptAndSignPayload({
    verified: input.view,
    environmentId: environmentId,
    variableId: latest.variableId,
    epoch: epoch,
    version,
    prevValueSigHashHex: latest.signedBytesHashHex,
    dek: dek,
    value: input.target.plaintext,
    writerUserId: writerUserId,
    signingKey: signingKey,
  });
  const outcome = yield* client.variables
    .push({
      params: {
        projectId: input.view.projectId,
        environmentId: environmentId,
        variableId: latest.variableId,
      },
      // sameValueAs = the value-lineage declaration (AUTH_SPEC §12-5 —
      // SHOULD): this push is a new-epoch re-encryption of the latest
      // version's plaintext, so it inherits that value's origin and never
      // counts as clearing the needs-rotation flag (an upstream
      // credential update — AUDIT_SPEC §4.1-5)
      payload: { value: signed.payload, sameValueAs: latest.version },
    })
    .pipe(
      Effect.map(() => ({ kind: "pushed" }) as const),
      Effect.catchTags(
        {
          // There is a concurrent push's winner. Never decide on the
          // 409's claimed value — the caller re-fetches and re-verifies
          // the reality (whether the winner is already at the current
          // epoch)
          VersionConflict: (error) =>
            Effect.succeed({
              kind: "conflict",
              currentVersion: error.currentVersion,
            } satisfies PushAttempt),
          // A concurrent deletion. A deletion is a tombstone + the
          // deletion of all versions (§12-5), so there is no current
          // value to re-encrypt — aligned with the rescan side's
          // handling of the same race (warn and drop from the targets);
          // the remaining variables' processing is not stopped
          VariableNotFound: () => Effect.succeed({ kind: "deleted" } satisfies PushAttempt),
          // Never make the claim the source of truth: the chain re-verification happens in the rescan
          EpochConflict: () => Effect.succeed({ kind: "epoch-stale" } satisfies PushAttempt),
        },
        (error) => Effect.fail(toCliError(error)),
      ),
    );
  if (outcome.kind !== "pushed") {
    return outcome;
  }
  // Promoting my accepted write into the floor (§6.3). Since the meta
  // did not change, the floor's meta record stays the verified latest.
  // Rule (c)'s baseline does not move. Never let a floor write failure
  // turn an "accepted re-encryption" into unfinished: the acceptance
  // cannot be taken back and this variable already lives at the new
  // epoch. The lost (SHOULD) detection material is conveyed as a
  // warning, and the remaining variables' processing is not stopped
  const floorWarning = yield* floor
    .commitPush(
      latest.variableId,
      {
        status: "active",
        version,
        epoch: epoch,
        valueSigHashHex: signed.signedBytesHashHex,
        metaVersion: latest.metaVersion,
        metaSigHashHex: latest.metaSignedBytesHashHex,
      },
      { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex },
    )
    .pipe(
      Effect.as(null),
      Effect.catch((error) =>
        Effect.succeed(
          `Re-encryption of variable ${displayText(latest.name)} was accepted, but ${error.message} (some rollback-detection material for this variable is missing)`,
        ),
      ),
    );
  // My accepted write (assembled from the signed subject itself — not a server echo)
  const written: VerifiedPulledValue = {
    ...latest,
    version,
    epoch,
    nonceHex: signed.payload.nonceHex,
    ciphertextHex: signed.payload.ciphertextHex,
    prevValueSigHashHex: latest.signedBytesHashHex,
    signedBytesHashHex: signed.signedBytesHashHex,
    valueChainHeadSeq: input.view.state.headSeq,
    valueChainHeadHashHex: input.view.state.headHashHex,
    valueSignatureHex: signed.payload.signatureHex,
    writerUserId,
    writerKeyFingerprintHex: input.context.writerKeyFingerprintHex,
  };
  return { kind: "pushed", floorWarning, written };
});

/**
 * Matching known values against re-fetched ones. Against the values that
 * passed §6.3 verification in this run (the basis of the next pass's prev
 * anchors), it checks for rollbacks, equivocations, forked prev chains,
 * and disagreements with the 409 claims (the same winnerInconsistency as
 * the push path), and warns of variables that vanished while still
 * unfinished as concurrent deletions.
 *
 * The consistency check runs before the "adopt it or not" question
 * regardless: evidence is itself a fact worth aborting on and must not
 * hide behind the "no re-encryption needed" shortcut.
 */
function reconcileKnown(input: {
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * The variables that could not finish re-encrypting this pass (409,
   * transient failure, 404, epoch conflict). The vanishing warning and the
   * "another member already wrote it at the current epoch" accounting are
   * based on this set, not just 409s — otherwise a variable that fell to a
   * 502 would be counted in none of re-encrypted / already-current /
   * unfinished, and the totals would not add up.
   */
  readonly unfinishedIds: ReadonlySet<string>;
  readonly latest: readonly VerifiedPulledValue[];
  readonly epoch: number;
  readonly collectWarning: (warning: string) => void;
}): { readonly evidence: string | null; readonly alreadyCurrent: number } {
  const latestById = new Map(input.latest.map((value) => [value.variableId, value]));
  let alreadyCurrent = 0;
  for (const [variableId, previous] of input.known) {
    const latest = latestById.get(variableIdOf(variableId));
    if (latest === undefined) {
      if (input.unfinishedIds.has(variableId)) {
        // Vanished while unfinished = a concurrent deletion. Never silently dropped from the targets
        input.collectWarning(
          `Variable ${displayText(previous.known.name)} is no longer in the re-fetched active set (concurrently deleted by another member). Removing it from the re-encryption targets`,
        );
      }
      continue;
    }
    const inconsistency = winnerInconsistency(
      variableIdOf(variableId),
      previous.known,
      latest,
      previous.currentVersion,
    );
    if (inconsistency !== null) {
      return { evidence: inconsistency, alreadyCurrent: 0 };
    }
    if (input.unfinishedIds.has(variableId) && latest.epoch >= input.epoch) {
      alreadyCurrent += 1;
    }
  }
  return { evidence: null, alreadyCurrent };
}

/** The result of re-fetch + re-verify (doubles as the completion check and the re-plan of 409 conflicts). */
interface RescanResult {
  readonly view: VerifiedProject;
  /**
   * The active values still below the target epoch. **This side is
   * correct for the completion judgment and the remaining count**
   * (targets becomes empty on the final pass).
   */
  readonly stale: readonly VerifiedPulledValue[];
  /**
   * The re-encryption material from decrypting stale (= the next pass's
   * targets). **Empty on the final pass**: decrypting when no next pass
   * exists would build one unusable plaintext per variable in memory.
   */
  readonly targets: readonly ReencryptTarget[];
  /**
   * The reasons of the values that could not be opened. Even on the
   * final pass (no decryption) the presence of a wrap addressed to me is
   * still judged, so "only unopenable values remain" can always be
   * reported as a cause.
   */
  readonly undecryptable: readonly string[];
  /** The number of variables that had conflicts but were already written at the current epoch (no re-encryption needed). */
  readonly alreadyCurrent: number;
  /**
   * Cryptographic evidence (a rollback, equivocation, forked prev chain).
   * Non-null is an immediate abort — never mix it with the "a re-run
   * resolves it" kind of failure.
   */
  readonly evidence: string | null;
}

/**
 * Re-fetch + re-verify of the environment (§6.3). Two roles, one path:
 * 1. **The completion check**: confirm no active value below the target
 *    epoch remains. A variable another member created in the window
 *    between the first pull and the composite's acceptance was never in
 *    the initial target set (a post-acceptance create is only accepted at
 *    the current epoch — §12-5) and becomes visible for the first time in
 *    this rescan. Skipping it produces the shape "the epoch advanced and
 *    values still on the old DEK remain, yet completion was reported"
 * 2. **Re-planning 409 conflicts** (§12-5's retry procedure): verify the
 *    winner under §6.3, and apply **the winner's consistency check
 *    (winnerRegression, shared with push-winner.ts) before the adopt/reject
 *    decision**. Re-encryption re-anchors the prev onto the winner's
 *    signed-bytes hash and signs, so without the check one's own
 *    signature would chain onto a forked history (§12-5's evidence-chain
 *    contamination). The local floor catches rollbacks and same-version
 *    differences but is a SHOULD (absent on first sync / after
 *    corruption), and for an adjacent-prev mismatch the floor has no
 *    material at all
 */
export const rescanEnvironment = Effect.fn("env-rotate-push.rescanEnvironment")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  /**
   * The values that passed §6.3 verification at least once in this run
   * (variableId → known value + 409-claimed version). **Not limited to
   * variables that got a 409**: a variable recovered by the rescan after a
   * transient failure also becomes the next pass's prev anchor, so it
   * passes the same consistency check.
   */
  readonly known: ReadonlyMap<string, ConflictedTarget>;
  /**
   * The variables that could **not finish** re-encrypting this pass (409,
   * transient failure, 404, epoch conflict). If these vanished from the
   * active set they are warned as concurrent deletions — "finished" is
   * only for the ones *seen* to vanish; never dropped silently.
   */
  readonly unfinishedIds: ReadonlySet<string>;
  /**
   * The warnings' receptacle. To keep already-collected warnings (non-NFC
   * names, concurrent deletions) even on failure, they flow in here
   * instead of the return value (the error channel cannot carry
   * warnings).
   */
  readonly collectWarning: (warning: string) => void;
  /**
   * A forced resync of the chain. On a pass where the server claimed an
   * epoch conflict, **always** re-fetch the chain and re-derive the
   * current epoch without depending on pull's future-head condition
   * (without the re-fetch, another member's concurrent rotation would be
   * mistaken for "a server contradiction" — same discipline as push-state.ts's
   * epoch-conflict).
   */
  readonly forceResync: boolean;
  /**
   * Whether to decrypt the remaining targets. true only when a next pass
   * exists — the final pass only counts what remains, so no unusable
   * plaintext is built (decryption only right before use).
   */
  readonly decryptRemaining: boolean;
}): Effect.fn.Return<RescanResult, CliError> {
  const { client, environmentId, resync, floor, epoch, deksByEpoch } = input.context;
  const base = input.forceResync ? yield* resyncExtended(resync, input.view) : input.view;
  const pulled = yield* pullVerifiedEnvironment({
    client,
    verified: base,
    environmentId,
    resync,
    floor,
  });
  const view = pulled.verified;
  // Warnings flow **before any judgment**: even on a pass aborted by a
  // concurrent rotation, the SHOULD warnings this pull collected must
  // not be lost (the sink's discipline)
  for (const warning of pulled.warnings) {
    input.collectWarning(warning);
  }
  const environment = yield* requireChainEnvironment(view, environmentId);
  if (environment.currentEpoch !== epoch) {
    return yield* Effect.fail(
      cliError(
        `Environment ${environmentId}'s epoch advanced from ${epoch} to ${environment.currentEpoch} during re-encryption (a concurrent rotation by another member)`,
      ),
    );
  }
  const reconciled = reconcileKnown({
    known: input.known,
    unfinishedIds: input.unfinishedIds,
    latest: pulled.variables,
    epoch,
    collectWarning: input.collectWarning,
  });
  if (reconciled.evidence !== null) {
    return {
      view,
      stale: [],
      targets: [],
      undecryptable: [],
      alreadyCurrent: 0,
      evidence: reconciled.evidence,
    };
  }
  // The completion check + the next pass's targets: every active value
  // below the target epoch (not limited to the conflicts — a variable
  // created in the window also appears here)
  const stale = pulled.variables.filter((value) => value.epoch < epoch);
  if (!input.decryptRemaining) {
    // No decryption, but "can it be opened" is still judged: the
    // presence of a wrap addressed to me is known from a Map lookup and
    // builds no plaintext. Skipping it would disguise as the default
    // wording (conflict) the cause of a state that only surfaces on the
    // final pass — "only unopenable values remain"
    const missing = stale.filter((value) => !deksByEpoch.has(value.epoch)).map(missingWrapReason);
    // Like the passes that attempt decryption, per-variable warnings
    // are emitted too (with only the as-cause report, which variables
    // were stranded is invisible on a pass where a push failure took
    // priority)
    for (const reason of missing) {
      input.collectWarning(undecryptableWarning(reason));
    }
    return {
      view,
      stale,
      targets: [],
      undecryptable: missing,
      alreadyCurrent: reconciled.alreadyCurrent,
      evidence: null,
    };
  }
  // A missing wrap addressed to me (benign) never fails the rescan
  // itself: the completion judgment was made by the pre-decryption
  // stale, and dropping here would turn **even the pushable share** into
  // "completion could not be verified". On the other hand, a value that
  // cannot be opened despite holding the wrap (substitution / view
  // inconsistency) is treated as **evidence** — it was an
  // immediate-abort condition on the first pull, so it must not be
  // downgraded to "a re-run-fixable partial completion" just because it
  // surfaced mid-pass
  const attempted = yield* asOutcome(
    decryptTargets({
      verified: view,
      environmentId,
      values: stale,
      deksByEpoch,
      chainEpoch: environment.currentEpoch,
    }),
  );
  if (attempted.kind === "failed") {
    return {
      view,
      stale,
      targets: [],
      undecryptable: [],
      alreadyCurrent: 0,
      evidence: attempted.error.message,
    };
  }
  const decrypted = attempted.value;
  for (const reason of decrypted.undecryptable) {
    input.collectWarning(undecryptableWarning(reason));
  }
  return {
    view,
    stale,
    targets: decrypted.targets,
    undecryptable: decrypted.undecryptable,
    alreadyCurrent: reconciled.alreadyCurrent,
    evidence: null,
  };
});
