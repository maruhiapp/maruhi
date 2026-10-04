// Opening verified values into re-encryption material for stage (ii) of
// `maruhi env rotate`, and the vocabulary for "a value cannot be opened"
// (the stage overview lives in env-rotate.ts).

import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { countNoun } from "./display.ts";
import type { ReencryptTarget } from "./env-rotate-shared.ts";
import { CliError, cliError } from "./errors.ts";
import { decryptVerifiedValue, missingWrapReason } from "./pull.ts";
import type { VerifiedPulledValue } from "./values-verify.ts";

/**
 * Preparing the re-encryption material (decryption + warning for the values that could not be opened).
 *
 * "Cannot open" = **only when no wrap of that epoch is addressed to me**
 * (any other decryption failure makes decryptTargets abort immediately).
 * Since this is a benign absence another member can open, the whole run is
 * never stopped for one — a revocation operation would otherwise give up
 * the range it could protect; the unopened share is reported as a partial
 * completion.
 *
 * This situation can only arise in §12-7's transitional state (an
 * old-epoch value remains). On the normal rotation path (no old-epoch
 * values = every value at the current epoch) it never happens, since the
 * current epoch's DEK is always held.
 */
export function decryptForRotation(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
  readonly warnings: string[];
}): Effect.Effect<readonly ReencryptTarget[], CliError> {
  return Effect.gen(function* () {
    const decrypted = yield* decryptTargets(input);
    for (const reason of decrypted.undecryptable) {
      input.warnings.push(undecryptableWarning(reason));
    }
    return decrypted.targets;
  });
}

/**
 * If nothing can be re-encrypted, never advance the epoch. Advancing
 * would only strand every current value on the old epoch's DEK — **not a
 * revocation** (a member with no wraps addressed to them / a response that
 * dropped every wrap, spinning only the epoch). --new-epoch doesn't help
 * either — with no value that can be opened, there is no material to
 * re-encrypt.
 */
export function ensureRotationIsUseful(
  targets: number,
  variables: number,
): Effect.Effect<void, CliError> {
  if (targets > 0 || variables === 0) {
    return Effect.void;
  }
  return Effect.fail(
    cliError(
      `${nothingDecryptable(variables)}. Advancing the epoch in this state would leave current values stranded under old-epoch DEKs, so nothing is actually revoked — a member holding wraps for those epochs must run this instead`,
    ),
  );
}

/**
 * The wording of "nothing can be opened". **Pinned to one place** (the
 * normal path's abort and the resume path's early cut-off state the same
 * fact — split, and dedupeWarnings would pass two lookalike lines about
 * the same situation).
 */
export function nothingDecryptable(variables: number): string {
  return `No values can be re-encrypted (wraps addressed to you are missing for all ${countNoun(variables, "variable")})`;
}

/**
 * The warning text of undecryptable values. **Pinned to one place**: when
 * the same variable is warned with slightly different wording per path,
 * dedupeWarnings (a set) would pass them as distinct — the mechanism put
 * in for dedup would itself emit the duplicates.
 */
export function undecryptableWarning(reason: string): string {
  return `Some values cannot be re-encrypted (${reason}). These variables remain under old-epoch DEKs — a member holding wraps for those epochs must re-run this`;
}

/** The decryption result. Unopened values come back as "undecryptable values" with a count and a reason. */
interface DecryptOutcome {
  readonly targets: readonly ReencryptTarget[];
  /**
   * The reason of a value that could not be opened because **no wrap of
   * that epoch is addressed to me**. This is a benign absence (another
   * member can open it), so one item never drops the whole run — a
   * rotation is a revocation operation, and leaving 99 openable values on
   * the old DEK because 1 cannot be opened gives up the range that could
   * be protected. **A value that cannot be opened despite holding the
   * wrap never enters here** (a possible ciphertext substitution or
   * inconsistency with the verified view — an immediate abort, same as
   * pull / run).
   */
  readonly undecryptable: readonly string[];
}

/** Decrypting the verified latest values (the re-encryption material). The decryption discipline is shared with pull. */
export function decryptTargets(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
}): Effect.Effect<DecryptOutcome, CliError> {
  return Effect.gen(function* () {
    const targets: ReencryptTarget[] = [];
    const undecryptable: string[] = [];
    for (const value of input.values) {
      // Only a benign absence (no wrap addressed to me) is skipped as an
      // "unopenable value". A decryption failure despite holding the wrap
      // is an AEAD authentication failure (a ciphertext substitution) or
      // an inconsistency with the verified view, and aborts immediately
      // like pull / run — collapsing it into "waiting on another member's
      // re-run" would report a substitution's sign as a benign operational
      // wait and guide toward stepping over it with --new-epoch
      //
      // "Benign" is judged only for an absence **at or below the
      // chain-derived current epoch**: for a value with a claimed epoch
      // beyond the current epoch, not holding that epoch's wrap is the
      // expected state (deks.ts refuses an over-the-cap wrap), so letting
      // it slip through this check would disguise an inconsistency with
      // the verified view as "waiting on another member". An over-the-cap
      // epoch makes decryptVerifiedValue abort immediately with the same
      // wording as pull / run (§6.3-4's epoch-not-current-at-head is the
      // main line; this is a defense line against a derivation
      // inconsistency)
      if (value.epoch <= input.chainEpoch && !input.deksByEpoch.has(value.epoch)) {
        undecryptable.push(missingWrapReason(value));
        continue;
      }
      const plaintext = yield* decryptVerifiedValue({
        verified: input.verified,
        environmentId: input.environmentId,
        variable: value,
        deksByEpoch: input.deksByEpoch,
        chainEpoch: input.chainEpoch,
      });
      targets.push({ value, plaintext });
    }
    return { targets, undecryptable };
  });
}
