// The explicit confirmation of a terminal deletion (fail-closed), shared by
// `maruhi var rm` (var-rm.ts) and `maruhi env rm` (env-rm.ts).
//
// Without --force, an interactive terminal (both stdin and stdout being
// terminals — via the Stdio service) requires **retyping the target's
// identifier**; a non-interactive run refuses without --force. --force is
// the explicit risk acceptance, and the consequence is still printed (a
// deletion is never silent). Getting the judgment material via a service is
// CLAUDE.md's "never read process.* directly" discipline.

import { Effect, Stdio } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

/** The wording of one deletion's confirmation (every field is already display-neutralized by the caller). */
interface PermanentDeletion {
  /** The target as shown (e.g. `SHOP_URL`, `environment dev`). */
  readonly label: string;
  /** What disappears (one clause, e.g. "its value … is deleted immediately"). */
  readonly consequence: string;
  /** What terminal means for this target (e.g. "the variable cannot be restored"). */
  readonly irreversibility: string;
  /** The parenthesized reason in the non-interactive refusal. */
  readonly refusalReason: string;
  /** What the user retypes (e.g. "variable name", "environment ID"). */
  readonly typedNoun: string;
  /** The short form of typedNoun in the mismatch message (e.g. "name", "ID"). */
  readonly mismatchNoun: string;
  /** The exact text the user must retype (compared after trimming and NFC normalization). */
  readonly expected: string;
}

/**
 * Gates a terminal deletion: --force passes (after printing the consequence),
 * an interactive terminal requires retyping the identifier, and anything else
 * refuses with a typed error before anything is signed or sent.
 */
export const confirmPermanentDeletion = Effect.fn("deletion-confirm.confirmPermanentDeletion")(
  function* (
    force: boolean,
    deletion: PermanentDeletion,
  ): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
    const io = yield* CliIo;
    if (force) {
      // An explicit flag = explicit risk acceptance. The fact is still made visible (never delete silently)
      yield* io.logError(
        `Deleting ${deletion.label} without confirmation (--force): ${deletion.consequence}. Deletion is terminal — ${deletion.irreversibility}`,
      );
      return;
    }
    const stdio = yield* Stdio.Stdio;
    const interactive = (yield* stdio.stdinIsTerminal) && (yield* stdio.stdoutIsTerminal);
    if (!interactive) {
      return yield* Effect.fail(
        cliError(
          `Refusing to delete ${deletion.label} in a non-interactive environment without --force (${deletion.refusalReason}). Re-run with --force to accept that explicitly`,
        ),
      );
    }
    yield* io.logError(
      `You are about to delete ${deletion.label}: ${deletion.consequence}. Deletion is terminal — ${deletion.irreversibility}`,
    );
    const answer = yield* io.promptLine({
      prompt: `Type the ${deletion.typedNoun} to confirm the permanent deletion: `,
    });
    if (answer.trim().normalize("NFC") !== deletion.expected) {
      return yield* Effect.fail(
        cliError(
          `Aborted: the typed ${deletion.mismatchNoun} did not match (nothing was signed or sent)`,
        ),
      );
    }
  },
);

/**
 * The one-line notice of a CAS retry (§12-5) that re-resolved the confirmed
 * target under a different name than the confirmation showed (a concurrent
 * rename). The confirmation binds the target's ID, which never changes and is
 * never reused, so the deletion proceeds without a second prompt — but the
 * name the user saw is no longer the target's name, and that is said (the
 * notice ledger drops an identical line on a later retry).
 */
export function noteConcurrentRename(input: {
  /** The target as shown, without its name (e.g. `Environment dev`). */
  readonly subject: string;
  /** The name the confirmation showed. */
  readonly seenName: string;
  /** The re-resolved, verified current name. */
  readonly currentName: string;
}): Effect.Effect<void, never, CliIo> {
  return input.seenName === input.currentName
    ? Effect.void
    : logNote(
        `${input.subject} was renamed concurrently from ${displayText(input.seenName)} to ${displayText(input.currentName)}; deleting it under its new name (the confirmation binds the ID, not the name)`,
      );
}
