// master keypair の生成と表示(CRYPTO_SPEC §3)。
//
// - 生成は @maruhi/crypto の公開 API のみ。extractable 生成 → 秘密鍵を
//   シリアライズして OS キーチェーンへ(平文ファイルへ書かない)
// - 既存鍵の上書きは拒否する: 鍵を失うと全プロジェクトの復号可能性を失う
//   (復元はリカバリーコード経由 = `maruhi key recover` のみ)
// - 生成の後段でリカバリーコードを発行する(§8。recovery.ts — エージェント
//   環境では発行をスキップして案内する)
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
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import { displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { Keychain, type StoredMasterKey } from "./keychain.ts";
import { issueRecoveryAfterKeygen } from "./recovery.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  importMasterKeys,
  loadMasterKeys,
} from "./session.ts";

// WebCrypto の reject は defect にせず型付きの失敗へ写す(未検査の外部
// メッセージを「内部エラー」として端末に流さない)
const keygenFailed = () => cliError("鍵の生成に失敗しました(暗号処理エラー)");

/** `maruhi key generate`: create and store the master keypair for the session user. */
export function keyGenerateOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keychain = yield* Keychain;
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "master 鍵は既に存在します。上書きすると既存プロジェクトの復号可能性を失うため拒否します(`maruhi key show` で確認できます)",
    );

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
      "注意: この鍵を失うと参加プロジェクトの値を復号できなくなります。リカバリーコードが唯一の復元手段です",
    );
    yield* issueRecoveryAfterKeygen({ session: input.session, client: input.client });
  });
}

/** `maruhi key show`: print the public keys and fingerprint (never the private keys). */
export function keyShowOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* loadMasterKeys(input.session);
    // userId はサーバー由来の自由文字列。他の出力経路と同様サニタイズする
    yield* io.log(`user:            ${displayText(input.session.userId)}`);
    yield* io.log(`enc public key:  ${keys.record.encPubHex}`);
    yield* io.log(`sig public key:  ${keys.record.sigPubHex}`);
    yield* io.log(`key fingerprint: ${keys.fingerprintHex}`);
    // 保管リマインダ(ROADMAP の紛失対策 UX): 登録状態を常に表示し、未登録は
    // 発行コマンドを案内する。status はブロブを運ばない(AUTH_SPEC §13-2)。
    // show の本務はローカル鍵の表示なので、状態確認の失敗はコマンドを失敗させず
    // 「確認できなかった」と明示して劣化する(オフライン・トークン失効でも使える)
    const status = yield* input.client.auth
      .recoveryStatus({})
      .pipe(Effect.catch(() => Effect.succeed(null)));
    if (status === null) {
      yield* io.log("recovery:        確認できませんでした");
      yield* io.logError(
        "注意: リカバリー登録状態を確認できません(サーバーに接続できないかトークンが失効しています)。鍵情報の表示には影響しません",
      );
    } else if (status.registered) {
      const updated =
        status.updatedAtMs === null ? "" : `(更新: ${formatDateUtc(status.updatedAtMs)})`;
      yield* io.log(`recovery:        登録済み${updated}`);
    } else {
      yield* io.log("recovery:        未登録");
      yield* io.logError(
        "注意: リカバリーコードが未登録です。この鍵を失うと復元できません — `maruhi key recovery` で発行してください",
      );
    }
  });
}

/** unix ms を UTC の日付表記(YYYY-MM-DD)にする(リマインダ表示用)。 */
function formatDateUtc(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
