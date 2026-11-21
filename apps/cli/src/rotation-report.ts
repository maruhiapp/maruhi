import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import { countNoun, logWarnings } from "./display.ts";
import type { RotationSummary } from "./env.package/index.ts";
import type { CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";

const reportPartialRotation = Effect.fn("rotation-report.reportPartialRotation")(function* (
  environmentId: EnvironmentId,
  summary: RotationSummary,
  scope: string,
  skipped: string,
): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  const scale =
    summary.remaining > 0
      ? `${countNoun(summary.remaining, "variable")} incomplete${summary.remainingExact ? "" : " (may include unconfirmed ones)"}`
      : "completion could not be verified";
  yield* io.log(
    `Partial completion: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}, ${scale})`,
  );
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

export const reportRotation = Effect.fn("rotation-report.reportRotation")(function* (
  environmentId: EnvironmentId,
  summary: RotationSummary,
  rotationRequested: boolean,
): Effect.fn.Return<number, CliError, CliIo> {
  const io = yield* CliIo;
  yield* logWarnings(summary.warnings);
  const skipped =
    summary.alreadyCurrent === 0
      ? ""
      : `, ${countNoun(summary.alreadyCurrent, "variable")} already re-encrypted by concurrent updates`;
  if (summary.mode === "up-to-date") {
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
    yield* io.log(
      `Done: ${scope} (re-encrypted ${countNoun(summary.reencrypted, "variable")}${skipped}). No new epoch was created (epoch remains ${summary.epoch})`,
    );
    if (!rotationRequested) {
      return 0;
    }
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
