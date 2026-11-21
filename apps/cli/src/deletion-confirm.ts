import { Effect, Stdio } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

interface PermanentDeletion {
  readonly label: string;
  readonly consequence: string;
  readonly irreversibility: string;
  readonly refusalReason: string;
  readonly typedNoun: string;
  readonly mismatchNoun: string;
  readonly expected: string;
}

export const confirmPermanentDeletion = Effect.fn("deletion-confirm.confirmPermanentDeletion")(
  function* (
    force: boolean,
    deletion: PermanentDeletion,
  ): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
    const io = yield* CliIo;
    if (force) {
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

export function noteConcurrentRename(input: {
  readonly subject: string;
  readonly seenName: string;
  readonly currentName: string;
}): Effect.Effect<void, never, CliIo> {
  return input.seenName === input.currentName
    ? Effect.void
    : logNote(
        `${input.subject} was renamed concurrently from ${displayText(input.seenName)} to ${displayText(input.currentName)}; deleting it under its new name (the confirmation binds the ID, not the name)`,
      );
}
