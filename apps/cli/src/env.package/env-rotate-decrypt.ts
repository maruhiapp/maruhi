import { type EnvironmentId } from "@maruhi/core";
import { Effect, Redacted } from "effect";

import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun } from "../display.ts";
import { CliError, cliError } from "../errors.ts";
import { decryptVerifiedValue, missingWrapReason } from "../pull.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import type { ReencryptTarget } from "./env-rotate-shared.ts";

export const decryptForRotation = Effect.fn("env-rotate-decrypt.decryptForRotation")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly values: readonly VerifiedPulledValue[];
    readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
    readonly chainEpoch: number;
    readonly warnings: string[];
  }): Effect.fn.Return<readonly ReencryptTarget[], CliError> {
    const decrypted = yield* decryptTargets(input);
    for (const reason of decrypted.undecryptable) {
      input.warnings.push(undecryptableWarning(reason));
    }
    return decrypted.targets;
  },
);

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

export function nothingDecryptable(variables: number): string {
  return `No values can be re-encrypted (wraps addressed to you are missing for all ${countNoun(variables, "variable")})`;
}

export function undecryptableWarning(reason: string): string {
  return `Some values cannot be re-encrypted (${reason}). These variables remain under old-epoch DEKs — a member holding wraps for those epochs must re-run this`;
}

interface DecryptOutcome {
  readonly targets: readonly ReencryptTarget[];
  readonly undecryptable: readonly string[];
}

export const decryptTargets = Effect.fn("env-rotate-decrypt.decryptTargets")(function* (input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly values: readonly VerifiedPulledValue[];
  readonly deksByEpoch: ReadonlyMap<number, Redacted.Redacted<Uint8Array>>;
  readonly chainEpoch: number;
}): Effect.fn.Return<DecryptOutcome, CliError> {
  const targets: ReencryptTarget[] = [];
  const undecryptable: string[] = [];
  for (const value of input.values) {
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
