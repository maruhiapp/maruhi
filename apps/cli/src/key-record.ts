// Generating a key record (`StoredMasterKey` — the common shape of
// CRYPTO_SPEC §3's device key / reserve key).
//
// The device key (keygen.ts) and the reserve key (reserve.ts) share
// the same record shape; only the placement differs (device key =
// keychain / agent memory, reserve key = inside the ledger's
// ciphertext). Generation uses only @maruhi/crypto's public API. The
// private side is wrapped in `Redacted` right after generation and
// never leaves this function as a bare string.

import { cryptoEffect, cryptoPromise } from "@maruhi/core";
import {
  encodeHex,
  exportEncryptionPrivateKey,
  exportEncryptionPublicKey,
  exportSigningPrivateSeed,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";

import { cliError, type CliError } from "./errors.ts";
import type { StoredMasterKey } from "./keychain.ts";

// A WebCrypto reject surfaces as `CryptoRejected` through the bridge and is
// mapped to a typed failure, not a defect (do not flow an uninspected
// external message to the terminal as an "internal error")
const keygenFailed = () => cliError("Failed to generate the keypair (crypto error)");

const keygenSerializeFailed = () =>
  cliError("Failed to generate the keypair (cannot serialize the private keys)");

/** Generates a fresh (enc, sig) key record with the private halves redacted. */
export function generateKeyRecord(): Effect.Effect<StoredMasterKey, CliError> {
  return Effect.gen(function* () {
    const encPair = yield* cryptoPromise("generateEncryptionKeyPair", () =>
      generateEncryptionKeyPair({ extractable: true }),
    ).pipe(Effect.mapError(keygenFailed));
    const sigPair = yield* cryptoPromise("generateSigningKeyPair", () =>
      generateSigningKeyPair({ extractable: true }),
    ).pipe(Effect.mapError(keygenFailed));
    const encPub = yield* cryptoPromise("exportEncryptionPublicKey", () =>
      exportEncryptionPublicKey(encPair.publicKey),
    ).pipe(Effect.mapError(keygenFailed));
    const sigPub = yield* cryptoPromise("exportSigningPublicKey", () =>
      exportSigningPublicKey(sigPair.publicKey),
    ).pipe(Effect.mapError(keygenFailed));
    const encSk = yield* cryptoEffect(() => exportEncryptionPrivateKey(encPair.privateKey)).pipe(
      Effect.mapError(keygenSerializeFailed),
    );
    const sigSeed = yield* cryptoEffect(() => exportSigningPrivateSeed(sigPair.privateKey)).pipe(
      Effect.mapError(keygenSerializeFailed),
    );
    return {
      suite: SUITE_ID,
      encPubHex: encodeHex(encPub),
      encSkHex: Redacted.make(encodeHex(encSk), { label: "master-enc-sk" }),
      sigPubHex: encodeHex(sigPub),
      sigSkSeedHex: Redacted.make(encodeHex(sigSeed), { label: "master-sig-seed" }),
    } satisfies StoredMasterKey;
  });
}
