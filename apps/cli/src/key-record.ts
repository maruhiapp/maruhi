// 鍵レコード(`StoredMasterKey` — CRYPTO_SPEC §3 の端末鍵 / 予備鍵の共通形)の生成。
//
// 端末鍵(keygen.ts)と予備鍵(reserve.ts)は同じレコード形で、違いは置き場だけ
// (端末鍵 = キーチェーン / agent メモリ、予備鍵 = 台帳の暗号文の中)。生成は
// @maruhi/crypto の公開 API のみ。秘密側は生成の直後に `Redacted` で包み、素の
// 文字列としてこの関数の外へ出ない。

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

// WebCrypto の reject は defect にせず型付きの失敗へ写す(未検査の外部
// メッセージを「内部エラー」として端末に流さない)
const keygenFailed = () => cliError("Failed to generate the keypair (crypto error)");

/** Generates a fresh (enc, sig) key record with the private halves redacted. */
export function generateKeyRecord(): Effect.Effect<StoredMasterKey, CliError> {
  return Effect.gen(function* () {
    const encPair = yield* Effect.tryPromise({
      try: () => generateEncryptionKeyPair({ extractable: true }),
      catch: keygenFailed,
    });
    const sigPair = yield* Effect.tryPromise({
      try: () => generateSigningKeyPair({ extractable: true }),
      catch: keygenFailed,
    });
    const encPub = yield* Effect.tryPromise({
      try: () => exportEncryptionPublicKey(encPair.publicKey),
      catch: keygenFailed,
    });
    const sigPub = yield* Effect.tryPromise({
      try: () => exportSigningPublicKey(sigPair.publicKey),
      catch: keygenFailed,
    });
    const encSk = yield* Effect.tryPromise({
      try: () => exportEncryptionPrivateKey(encPair.privateKey),
      catch: keygenFailed,
    });
    const sigSeed = yield* Effect.tryPromise({
      try: () => exportSigningPrivateSeed(sigPair.privateKey),
      catch: keygenFailed,
    });
    if (!encSk.ok || !sigSeed.ok) {
      return yield* Effect.fail(
        cliError("Failed to generate the keypair (cannot serialize the private keys)"),
      );
    }
    return {
      suite: SUITE_ID,
      encPubHex: encodeHex(encPub),
      encSkHex: Redacted.make(encodeHex(encSk.value), { label: "master-enc-sk" }),
      sigPubHex: encodeHex(sigPub),
      sigSkSeedHex: Redacted.make(encodeHex(sigSeed.value), { label: "master-sig-seed" }),
    } satisfies StoredMasterKey;
  });
}
