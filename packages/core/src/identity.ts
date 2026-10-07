// The two identity values that must never be confused (AUTH_SPEC §1-§2,
// §10): the internal user id (`users.id` — the principal across the whole
// system) and the provider's subject (`linked_identities.provider_user_id`
// — GitHub's numeric id). Both are branded because each carries an
// invariant a plain string cannot:
//
// - UserId: the membership log, the audit log and every reference to a
//   person hold the internal user id only (CLAUDE.md's identity rule).
//   The brand makes a provider identity — or any other string — a compile
//   error in those positions.
// - ProviderUserId: identities are looked up only by
//   (provider, provider_user_id), and the changeable login is never an
//   identifier (§2, §10). The brand keeps the login, and every other
//   string, out of that lookup key.
//
// The display login (`provider_login`) carries no invariant of its own and
// stays a plain string: the UserId brand already keeps it out of every
// user-id position.
//
// The key fingerprint — the other half of an actor on the chain and in the
// audit log — is branded too (KeyFingerprintHex, at the end of this file):
// it carries a format (16 bytes as lowercase hex) and a provenance
// (computed from public keys, or decoded with that format check).
//
// The brands are minted only at trust boundaries: decoding at the wire
// (these schemas, also behind CLI arguments; `decode*` for the few
// hand-written parsers), DB row mapping inside the server's repository
// service (the Drizzle column types), generation (a new user id, the
// subject the provider's API returns) and, for a fingerprint, computation
// from the keys. `.oxlintrc.json` enforces this: the schemas and `decode*`
// mints below may be imported only by the listed mint sites.

import type { KeyFingerprintHex, UserId } from "@maruhi/crypto";
import { computeServerKeyFingerprint, computeUserKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { Effect, Schema } from "effect";

import { cryptoEffect, type WrappedCryptoError } from "./crypto-errors.ts";

export type { KeyFingerprintHex, UserId } from "@maruhi/crypto";

/**
 * The brand's single assertion. `UserId` is a plain nominal type (crypto,
 * which owns the chain types that carry it, is Effect-free), so the brand
 * is applied with a refinement rather than `Schema.brand`. It accepts every
 * string: the brand records provenance — the value came out of a user-id
 * slot — not a format (AUTH_SPEC §11-1 keeps the chain independent of the
 * user id's format). Bounds belong to the field (`.check(...)` on top).
 */
function isUserId(_value: string): _value is UserId {
  return true;
}

/** Schema for an internal user id (AUTH_SPEC §2 `users.id`). Decoding mints a {@link UserId}. */
export const UserIdSchema = Schema.String.pipe(
  Schema.refine(isUserId, { expected: "an internal user id" }),
);

/**
 * Mints a {@link UserId} where no Schema field does the decoding — only at
 * a trust boundary: generating a new user id, a hand-written parser of a
 * wire or stored record (the restore worker's identities companion, the
 * CLI's keychain token record), or a field whose recipient class makes it
 * a user id (a DEK wrap addressed to a member).
 */
export const decodeUserId: (value: string) => UserId = Schema.decodeSync(UserIdSchema);

/** Schema for a provider subject (AUTH_SPEC §2 `provider_user_id` — GitHub's numeric id, not the login). */
export const ProviderUserIdSchema = Schema.String.pipe(Schema.brand("ProviderUserId"));

/** A provider subject: the identity-lookup key alongside the provider (AUTH_SPEC §2). */
export type ProviderUserId = typeof ProviderUserIdSchema.Type;

/** Mints a {@link ProviderUserId} from the subject the provider's API returned (AUTH_SPEC §3-2). */
export const decodeProviderUserId: (value: string) => ProviderUserId =
  Schema.decodeSync(ProviderUserIdSchema);

// ---------------------------------------------------------------------------
// Key fingerprints (CRYPTO_SPEC §3 / §9). The brand is crypto's
// `KeyFingerprintHex` (type-only there, like `UserId`); its runtime mints
// live here.
// ---------------------------------------------------------------------------

/** 16 bytes as lowercase hex — the device-key and the server-key fingerprint alike (CRYPTO_SPEC §3 / §9). */
const KEY_FINGERPRINT_HEX = /^[0-9a-f]{32}$/;

/**
 * The brand's single assertion. Unlike {@link UserId}, the brand carries a
 * format — 32 lowercase hex characters, so string equality is fingerprint
 * equality — and every string mint checks it.
 */
function isKeyFingerprintHex(value: string): value is KeyFingerprintHex {
  return KEY_FINGERPRINT_HEX.test(value);
}

/** Schema for a key fingerprint field (16 bytes, lowercase hex). Decoding mints a {@link KeyFingerprintHex}. */
export const KeyFingerprintHexSchema = Schema.String.pipe(
  Schema.refine(isKeyFingerprintHex, {
    expected: "a key fingerprint (16 bytes, lowercase hex — CRYPTO_SPEC §3)",
  }),
);

/**
 * Mints a {@link KeyFingerprintHex} where no Schema field does the decoding —
 * only at a trust boundary: a hand-written parser of a wire or stored record
 * (a CLI argument, the keychain record, a stored row the repository maps).
 * Throws on a malformed value.
 */
export const decodeKeyFingerprintHex: (value: string) => KeyFingerprintHex =
  Schema.decodeSync(KeyFingerprintHexSchema);

/**
 * The fingerprint of a device key pair (CRYPTO_SPEC §3), computed and minted in
 * one step. The only inputs are the two public keys, so the provenance — the
 * value was computed from those keys — holds by construction.
 */
export function userKeyFingerprintHex(
  encPublicKey: Uint8Array,
  sigPublicKey: Uint8Array,
): Effect.Effect<KeyFingerprintHex, WrappedCryptoError> {
  return cryptoEffect(() => computeUserKeyFingerprint(encPublicKey, sigPublicKey)).pipe(
    Effect.map(computedFingerprintHex),
  );
}

/** The fingerprint of a server (deployment) key (CRYPTO_SPEC §9), computed and minted in one step. */
export function serverKeyFingerprintHex(
  serverEncPublicKey: Uint8Array,
): Effect.Effect<KeyFingerprintHex, WrappedCryptoError> {
  return cryptoEffect(() => computeServerKeyFingerprint(serverEncPublicKey)).pipe(
    Effect.map(computedFingerprintHex),
  );
}

/** The hex form of computed fingerprint bytes (always 16 bytes from the compute functions; anything else is a defect). */
function computedFingerprintHex(fingerprint: Uint8Array): KeyFingerprintHex {
  return decodeKeyFingerprintHex(encodeHex(fingerprint));
}
