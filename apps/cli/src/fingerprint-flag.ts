// Format validation of flags that take a key fingerprint (shared by
// server grant / revoke, invite accept, member add). The consumer is
// effect-cli.ts. Wording is English per ADR-0017.

import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";

/**
 * Format validation of a flag taking a key FP (lowercase hex, 32
 * chars = 16 bytes). Errors are reported under the **flag name as
 * typed** (shared across grant's --expect-fingerprint / revoke's
 * --fingerprint / the FP flags of invite and member — never point at
 * a flag name that does not exist and confuse). `hint` is the
 * guidance for where the FP comes from (per key kind).
 */
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

/** User-key FP flag (CRYPTO_SPEC §3) — inserts only the provenance guidance into the shared parser. */
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
