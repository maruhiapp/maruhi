import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";

export function parseFingerprintFlag(
  flagName: string,
  value: string | undefined,
  hint = "a server key fingerprint is 32 lowercase hex characters — serverKeyFingerprintHex in /auth/config",
): Effect.Effect<string | null, CliError> {
  if (value === undefined) {
    return Effect.succeed(null);
  }
  if (!/^[0-9a-f]{32}$/.test(value)) {
    return Effect.fail(usageError(`${flagName} is malformed (${hint})`));
  }
  return Effect.succeed(value);
}

export function parseUserFingerprintFlag(
  flagName: string,
  value: string | undefined,
): Effect.Effect<string | null, CliError> {
  return parseFingerprintFlag(
    flagName,
    value,
    "a user key fingerprint is 32 lowercase hex characters — the key fingerprint shown by `maruhi key show`",
  );
}
