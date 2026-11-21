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

const keygenFailed = () => cliError("Failed to generate the keypair (crypto error)");

const keygenSerializeFailed = () =>
  cliError("Failed to generate the keypair (cannot serialize the private keys)");

export const generateKeyRecord = Effect.fn("key-record.generateKeyRecord")(
  function* (): Effect.fn.Return<StoredMasterKey, CliError> {
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
  },
);
