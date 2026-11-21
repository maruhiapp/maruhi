import type { KeyFingerprintHex, UserId } from "@maruhi/crypto";
import { computeServerKeyFingerprint, computeUserKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { Effect, Schema } from "effect";

import { cryptoEffect, type WrappedCryptoError } from "./crypto-errors.ts";

export type { KeyFingerprintHex, UserId } from "@maruhi/crypto";

function isUserId(_value: string): _value is UserId {
  return true;
}

export const UserIdSchema = Schema.String.pipe(
  Schema.refine(isUserId, { expected: "an internal user id" }),
);

export const decodeUserId: (value: string) => UserId = Schema.decodeSync(UserIdSchema);

export const ProviderUserIdSchema = Schema.String.pipe(Schema.brand("ProviderUserId"));

export type ProviderUserId = typeof ProviderUserIdSchema.Type;

export const decodeProviderUserId: (value: string) => ProviderUserId =
  Schema.decodeSync(ProviderUserIdSchema);

const KEY_FINGERPRINT_HEX = /^[0-9a-f]{32}$/;

export function isKeyFingerprintHex(value: string): boolean {
  return KEY_FINGERPRINT_HEX.test(value);
}

const narrowsKeyFingerprintHex = (value: string): value is KeyFingerprintHex =>
  KEY_FINGERPRINT_HEX.test(value);

export const KeyFingerprintHexSchema = Schema.String.pipe(
  Schema.refine(narrowsKeyFingerprintHex, {
    expected: "a key fingerprint (16 bytes, lowercase hex — CRYPTO_SPEC §3)",
  }),
);

export const decodeKeyFingerprintHex: (value: string) => KeyFingerprintHex =
  Schema.decodeSync(KeyFingerprintHexSchema);

export function userKeyFingerprintHex(
  encPublicKey: Uint8Array,
  sigPublicKey: Uint8Array,
): Effect.Effect<KeyFingerprintHex, WrappedCryptoError> {
  return cryptoEffect(() => computeUserKeyFingerprint(encPublicKey, sigPublicKey)).pipe(
    Effect.map(computedFingerprintHex),
  );
}

export function serverKeyFingerprintHex(
  serverEncPublicKey: Uint8Array,
): Effect.Effect<KeyFingerprintHex, WrappedCryptoError> {
  return cryptoEffect(() => computeServerKeyFingerprint(serverEncPublicKey)).pipe(
    Effect.map(computedFingerprintHex),
  );
}

function computedFingerprintHex(fingerprint: Uint8Array): KeyFingerprintHex {
  return decodeKeyFingerprintHex(encodeHex(fingerprint));
}
