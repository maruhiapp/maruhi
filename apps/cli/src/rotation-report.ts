// Reporting of rotation results and exit-code derivation (shared
// by the sweeps of env rotate / server revoke / member remove /
// change-role). The consumers are commands/env.ts and
// commands/shared.ts. Text is English per ADR-0017 (all user-facing
// wording is English).

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import { countNoun, logWarnings } from "./display.ts";
import type { RotationSummary } from "./env-rotate.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";

/**
 * Reporting of partial completion / completion-unverified. The
 * epoch has advanced, and holders of the old epoch's DEK can still
 * read the current values of the not-yet-re-encrypted variables
 * (§7). Do not let it end with a "complete" face, nor a success
 * exit.
 */
const reportPartialRotation = Effect.fn("rotation-report.reportPartialRotation")(function* (
  environmentId: EnvironmentId,
  summary: RotationSummary,
  scope: string,
  skipped: string,
): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  // The remaining count of an interrupted run is an upper bound,
  // not a measurement (the re-scan was never reached, so the
  // contested ones may already have been written at the new epoch
  // by other members). Do not assert — show "including
  // unverified" instead. The remaining count of a run that only
  // exhausted its rounds IS a measured value that passed the
  // re-scan, so put a qualifier there to keep it from looking
  // suspect
  const scale =
    summary.remaining > 0
      ? `${countNoun(summary.remaining, "variable")} incomplete${summary.remainingExact ? "" : " (may include unconfirmed ones)"}`
      : "completion could not be verified";
  yield* io.log(
    `Partial completion: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}, ${scale})`,
  );
  // When there is a cause of failure, state it (so the bare fact
  // "only the epoch advanced" is not lost behind a raw error).
  // Only a run that descended before reaching the re-scan can be
  // called "interrupted"; a run that exhausted its rounds is
  // incomplete after having run to the end
  const stopped = summary.remainingExact
    ? "re-encryption did not complete"
    : "re-encryption was interrupted";
  const cause =
    summary.failure === null
      ? "conflicts with concurrent pushes did not resolve"
      : `${stopped}: ${summary.failure}`;
  yield* logWarning(
    `re-encryption for environment ${environmentId} has not completed (${cause}). Values not yet re-encrypted remain under DEKs older than epoch ${summary.epoch} — resolve the cause and re-run \`maruhi env rotate ${environmentId}\` to resume from the remainder without advancing the epoch (the re-run rescans the remainder, so the actual number of incomplete variables is confirmed there). However, if the cause is a verification failure or a local floor violation (= contradicting server responses), re-running will not resolve it — investigate the served evidence`,
  );
  return 1;
});

/**
 * Reporting of rotation results and the exit code. A completion
 * summary reports the re-encryption record; an incomplete portion
 * (partial completion) is shown as a warning — never end the "the
 * epoch advanced but re-encryption remains" state with a success
 * face.
 */
export const reportRotation = Effect.fn("rotation-report.reportRotation")(function* (
  environmentId: EnvironmentId,
  summary: RotationSummary,
  /** Whether the run requested a new epoch (--reason given or --new-epoch). */
  rotationRequested: boolean,
): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  yield* logWarnings(summary.warnings);
  const skipped =
    summary.alreadyCurrent === 0
      ? ""
      : `, ${countNoun(summary.alreadyCurrent, "variable")} already re-encrypted by concurrent updates`;
  if (summary.mode === "up-to-date") {
    // Check-only (nothing incomplete, no new epoch requested).
    // It is also the landing point of the re-run that the
    // partial-completion guidance advises, so state explicitly
    // that nothing was done
    yield* io.log(
      `Check complete: every active variable in environment ${environmentId} is encrypted at epoch ${summary.epoch} (no incomplete re-encryption). To create a new epoch, pass --reason`,
    );
    return 0;
  }
  const scope =
    summary.mode === "rotated"
      ? `rotated environment ${environmentId}: epoch ${summary.previousEpoch} → ${summary.epoch}`
      : `resumed re-encryption for environment ${environmentId} (epoch ${summary.epoch})`;
  if (summary.remaining > 0 || summary.failure !== null) {
    return yield* reportPartialRotation(environmentId, summary, scope, skipped);
  }
  if (summary.mode === "resumed") {
    // A resume is not "the requested rotation": no new epoch was
    // created, so the completion report must not look like a
    // rotation success (closing the shape where a run following a
    // departed member's removal gets counted as a success with
    // no new epoch)
    yield* io.log(
      `Done: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}). No new epoch was created (epoch remains ${summary.epoch})`,
    );
    if (!rotationRequested) {
      // A reasonless run = only requesting "resume the incomplete if any"
      return 0;
    }
    // A run that requested a rotation (--reason / --new-epoch)
    // switched to a resume, so **the exit code also** does not
    // say success: closing the shape where a script like `maruhi
    // env rotate prod --reason ... || exit 1` would take it as a
    // success with no new epoch
    yield* logWarning(
      `the requested rotation was not performed (the incomplete re-encryption was resumed first). If you still need a new epoch after this run, run the command again or pass --new-epoch`,
    );
    return 1;
  }
  yield* io.log(
    `Done: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped})`,
  );
  return 0;
});
