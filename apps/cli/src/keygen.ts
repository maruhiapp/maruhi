// 端末鍵の生成と表示(CRYPTO_SPEC §3 — 2026-09-19 DK: 旧「master keypair」は端末鍵)。
//
// - 生成は @maruhi/crypto の公開 API のみ(key-record.ts)。extractable 生成 → 秘密鍵を
//   シリアライズして OS キーチェーンへ(平文ファイルへ書かない)
// - 既存鍵の上書きは拒否する: 鍵を失うと全プロジェクトの復号可能性を失う
//   (復元は予備鍵経由 = `maruhi key recover` のみ)
// - **アイデンティティは 1 つ**(設計録 §9 K4-19): 台帳(リカバリー登録)が既にある
//   アカウントで `key generate` を打つのは「2 台目の端末」であり、鍵生成ではなく端末追加
//   (`maruhi device add`)へ案内する。台帳の状態が取れなければ fail-closed で拒否する。
//   鍵もコードも全端末も失った人の作り直しは `--new-identity`(名指しの明示)
// - 生成の後段で予備鍵を生成して封印する(§8 — recovery.ts。エージェント環境では
//   封印をスキップして案内する)
// - 表示(key show)は公開鍵とフィンガープリントのみ。秘密鍵は表示しない

import { Effect, Stdio } from "effect";
import type { HttpClient } from "effect/unstable/http";

import type { MaruhiClient } from "./api.ts";
import type { IdentityBacking } from "./config.ts";
import { displayText, formatUtcDate } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { fingerprintWords, formatWordList } from "./fp-words.ts";
import { CliIo } from "./io.ts";
import { offerGithubRegistration } from "./key-publish.ts";
import { generateKeyRecord } from "./key-record.ts";
import { Keychain, serializeStoredMasterKey } from "./keychain.ts";
import { logNote } from "./notice.ts";
import { OwnDeviceStore } from "./own-devices.ts";
import { issueRecoveryAfterKeygen } from "./recovery.ts";
import { recordedReserves } from "./reserve.ts";
import type { ProcessRunner } from "./run.ts";
import {
  type CliSession,
  ensureNoStoredMasterKey,
  cryptoBackendUsable,
  importMasterKeys,
  retryOnSupportedRuntime,
  storeMasterKeyAndReport,
  unsupportedCryptoCause,
  loadMasterKeys,
} from "./session.ts";

/** `maruhi key generate`: create and store this device's key for the session user. */
export function keyGenerateOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
  /** 裏付け元(CRYPTO_SPEC §6.5): `none` 以外なら生成直後に GitHub 登録の導線を出す。 */
  readonly identityBacking: IdentityBacking;
  /** `--new-identity`: 台帳があっても新しいアイデンティティを作る(K4-19 — 名指しの明示)。 */
  readonly newIdentity: boolean;
}): Effect.Effect<
  void,
  CliError,
  Keychain | CliIo | ProcessRunner | Stdio.Stdio | HttpClient.HttpClient | OwnDeviceStore
> {
  return Effect.gen(function* () {
    const entryName = yield* ensureNoStoredMasterKey(
      input.session,
      "A device key already exists on this machine. Overwriting it would destroy the ability to decrypt existing projects, so this is refused (check it with `maruhi key show`)",
    );
    // アイデンティティは 1 つ(K4-19): 台帳があれば「2 台目」= 端末追加へ
    if (!input.newIdentity) {
      const status = yield* input.client.auth
        .recoveryStatus({})
        .pipe(
          Effect.mapError(() =>
            cliError(
              "Cannot check whether your account already has a recovery ledger (the server is unreachable or the token is revoked), so the key was not generated. Re-run when the server is reachable, or pass --new-identity only if you are sure this is your first key",
            ),
          ),
        );
      if (status.registered) {
        return yield* Effect.fail(
          cliError(
            "Your account already has a reserve key in the recovery ledger, so this machine is a second device rather than a new identity. Register it with `maruhi device add` and approve it from a registered device with `maruhi device approve` (no key material moves). If every device and the recovery code / passkeys / guardians are all lost, rebuild with `maruhi key generate --new-identity` (existing project values become undecryptable until you are re-invited)",
          ),
        );
      }
    }

    const record = yield* generateKeyRecord();
    // 保存「前」にレコードを再インポートして自己検証する(検証失敗の壊れた
    // レコードをキーチェーンに残さない)。
    // 失敗の文言は**この経路専用**にする: 既定の文言はキーチェーンのレコードを
    // 指して削除を促すが、ここはまだ何も保存していない — 無い物の削除を案内する
    // ことになる。原因が環境(WebCrypto 非対応)なら鍵の問題ではないので、
    // それだけは言い分ける
    const validated = yield* importMasterKeys(record).pipe(
      Effect.catch(() =>
        Effect.flatMap(cryptoBackendUsable(), (usable) =>
          Effect.fail(
            cliError(
              usable
                ? "Could not load the generated key back (nothing was stored in the keychain). Report this as a maruhi bug"
                : // 保存前なので「保存されている鍵」は指せない。無事な物(=
                  // 何も書いていないこと)を言い、次の一手だけ共有する
                  `${unsupportedCryptoCause}. Nothing was stored in the keychain. ${retryOnSupportedRuntime}`,
            ),
          ),
        ),
      ),
    );
    // JSON.stringify(record) は使わない — 秘密側が伏字で保存され、鍵を
    // 復元できないレコードがキーチェーンに残る(keychain.ts の注記)。
    // 保存は上書き検出つき: ガードから鍵生成を挟んだこの位置では
    // 並行実行が先に書いている可能性があり、素の set は後勝ちで一方の鍵を
    // 黙って消す。後段の予備鍵の封印より前に失敗させる
    yield* storeMasterKeyAndReport({
      entryName,
      serialized: serializeStoredMasterKey(record),
      action: "Generated this device's key",
      fingerprintHex: validated.fingerprintHex,
    });
    yield* logNote(
      "this key belongs to this device only. Other machines get their own device key (`maruhi device add`); losing every device is covered by the reserve key created next",
    );
    yield* issueRecoveryAfterKeygen({ session: input.session, client: input.client });
    // 登録の導線(補足 21 裁定 G ⑥ (b)): リカバリーコードの儀式が終わってから聞く
    if (input.identityBacking !== "none") {
      yield* offerGithubRegistration({ session: input.session });
    }
  });
}

/** `maruhi key show`: print the public keys and fingerprints (never the private keys). */
export function keyShowOp(input: {
  readonly session: CliSession;
  readonly client: MaruhiClient;
}): Effect.Effect<void, CliError, Keychain | CliIo | HttpClient.HttpClient | OwnDeviceStore> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const keys = yield* loadMasterKeys(input.session);
    // userId はサーバー由来の自由文字列。他の出力経路と同様サニタイズする
    yield* io.log(`user:                   ${displayText(input.session.userId)}`);
    yield* io.log(`device enc public key:  ${keys.record.encPubHex}`);
    yield* io.log(`device sig public key:  ${keys.record.sigPubHex}`);
    yield* io.log(`device key fingerprint: ${keys.fingerprintHex}`);
    // FP のワード表示(§3): 招待の相互確認(§6.5)・端末追加(`device approve`)で
    // 自分の語列を読み上げる / 運ぶ再表示経路
    const words = yield* fingerprintWords(keys.fingerprintHex, "The key fingerprint is malformed");
    yield* io.log(`fp words:               ${formatWordList(words)}`);
    // 予備鍵(台帳にだけ住む — ローカル記録は公開側だけ)
    const reserves = yield* recordedReserves(input.session);
    const reserve = reserves[0];
    yield* io.log(
      `reserve key fingerprint: ${reserve === undefined ? "not recorded on this machine" : reserve.keyFingerprintHex}`,
    );
    // 保管リマインダ(ROADMAP の紛失対策 UX): 登録状態を常に表示し、未登録は
    // 発行コマンドを案内する。status はブロブを運ばない(AUTH_SPEC §13-2)。
    // show の本務はローカル鍵の表示なので、状態確認の失敗はコマンドを失敗させず
    // 「確認できなかった」と明示して劣化する(オフライン・トークン失効でも使える)
    const status = yield* input.client.auth
      .recoveryStatus({})
      .pipe(Effect.catch(() => Effect.succeed(null)));
    if (status === null) {
      yield* io.log("recovery:               could not be checked");
      yield* logNote(
        "the recovery registration status could not be checked (the server is unreachable or the token is revoked). This does not affect the key information shown above",
      );
    } else if (status.registered) {
      const updated =
        status.updatedAtMs === null ? "" : ` (updated: ${formatUtcDate(status.updatedAtMs)})`;
      yield* io.log(`recovery:               registered${updated}`);
      if (reserve === undefined) {
        yield* logNote(
          "the recovery ledger is registered but this machine has no record of the reserve key it holds. `maruhi key recovery` opens the ledger (recovery code or --passkey) and restores the record — on an install from before device keys, it also separates the reserve key from this device's key",
        );
      }
    } else {
      yield* io.log("recovery:               not registered");
      yield* logNote(
        "no reserve key is sealed in the recovery ledger. If you lose this device you lose access — create one with `maruhi key recovery`",
      );
    }
  });
}

/** Whether the account's recovery ledger is registered (typed failure when it cannot be checked). */
export function recoveryRegistered(
  client: MaruhiClient,
): Effect.Effect<boolean, CliError, HttpClient.HttpClient> {
  return client.auth.recoveryStatus({}).pipe(
    Effect.map((status) => status.registered),
    Effect.mapError(toCliError),
  );
}
