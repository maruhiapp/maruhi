// master keypair の生成と表示(CRYPTO_SPEC §3)。
//
// - 生成は @maruhi/crypto の公開 API のみ。extractable 生成 → 秘密鍵を
//   シリアライズして OS キーチェーンへ(平文ファイルへ書かない)
// - 既存鍵の上書きは拒否する: 鍵を失うと全プロジェクトの復号可能性を失い、
//   リカバリーコード(§8)は別セッションのスコープのため v1 に再発行経路がない
// - 表示(key show)は公開鍵とフィンガープリントのみ。秘密鍵は表示しない

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
import { Effect } from "effect";

import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { Keychain, masterKeyEntryName, type StoredMasterKey } from "./keychain.ts";
import { type CliSession, importMasterKeys, loadMasterKeys } from "./session.ts";

/** `maruhi key generate`: create and store the master keypair for the session user. */
export function keyGenerateOp(input: {
  readonly session: CliSession;
}): Effect.Effect<void, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const entryName = masterKeyEntryName(input.session.origin, input.session.userId);
    const existing = yield* keychain.get(entryName);
    if (existing !== null) {
      return yield* Effect.fail(
        cliError(
          "master 鍵は既に存在します。上書きすると既存プロジェクトの復号可能性を失うため拒否します(`maruhi key show` で確認できます)",
        ),
      );
    }

    const encPair = yield* Effect.promise(() => generateEncryptionKeyPair({ extractable: true }));
    const sigPair = yield* Effect.promise(() => generateSigningKeyPair({ extractable: true }));
    const encPub = yield* Effect.promise(() => exportEncryptionPublicKey(encPair.publicKey));
    const sigPub = yield* Effect.promise(() => exportSigningPublicKey(sigPair.publicKey));
    const encSk = yield* Effect.promise(() => exportEncryptionPrivateKey(encPair.privateKey));
    const sigSeed = yield* Effect.promise(() => exportSigningPrivateSeed(sigPair.privateKey));
    if (!encSk.ok || !sigSeed.ok) {
      return yield* Effect.fail(cliError("鍵の生成に失敗しました(秘密鍵をシリアライズできません)"));
    }

    const record: StoredMasterKey = {
      suite: SUITE_ID,
      encPubHex: encodeHex(encPub),
      encSkHex: encodeHex(encSk.value),
      sigPubHex: encodeHex(sigPub),
      sigSkSeedHex: encodeHex(sigSeed.value),
    };
    // 保存「前」にレコードを再インポートして自己検証する(検証失敗の壊れた
    // レコードをキーチェーンに残さない — レビューループ 1 [低])
    const validated = yield* importMasterKeys(record);
    yield* keychain.set(entryName, JSON.stringify(record));
    yield* io.log("master keypair を生成し、OS キーチェーンに保存しました");
    yield* io.log(`key fingerprint: ${validated.fingerprintHex}`);
    yield* io.log(
      "注意: この鍵を失うと参加プロジェクトの値を復号できなくなります(リカバリーコードは未実装)",
    );
  });
}

/** `maruhi key show`: print the public keys and fingerprint (never the private keys). */
export function keyShowOp(input: {
  readonly session: CliSession;
}): Effect.Effect<void, CliError, Keychain | CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* loadMasterKeys(input.session);
    // userId はサーバー由来の自由文字列。他の出力経路と同様サニタイズする
    yield* io.log(`user:            ${displayText(input.session.userId)}`);
    yield* io.log(`enc public key:  ${keys.record.encPubHex}`);
    yield* io.log(`sig public key:  ${keys.record.sigPubHex}`);
    yield* io.log(`key fingerprint: ${keys.fingerprintHex}`);
  });
}
