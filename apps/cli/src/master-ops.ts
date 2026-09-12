// master 鍵を使う KL3 の狭い操作(CRYPTO_SPEC §8.3 / §8.4)。
//
// ここに集めるのは「master 鍵で 1 回演算する」3 操作だけ: 保護者としての分片の
// 開封、旧端末としての B のラップ(承認バンドル)、要求者の一時鍵への封印(こちらは
// 鍵を要さないが、承認の組み立てを 1 か所に置く)。KL4(委任モデル — agent が
// 署名 / HPKE open を代行し鍵素材をソケットに出さない。integration-options.md
// 補足 19-3 (a))でサービス化する下地として、呼び出し側は `MasterKeys` を直に
// 触らずこの関数群を経由する。
//
// 平文の分片・KEK・B は各関数のローカルにのみ存在し、返り値以外へ出ない
// (ログ・エラーへ載せない — CLAUDE.md)。

import { ulid } from "@maruhi/core";
import {
  decodeHex,
  type EncryptionKey,
  type GuardianWrapContext,
  type HandoffWrapContext,
  type MasterWrapContext,
  openGuardianShare,
  sealHandoffValue,
  type WrappedDek,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Effect } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { serializeStoredMasterKey } from "./keychain.ts";
import type { MasterKeys } from "./session.ts";

/** 保護者として自分宛の分片を開く(承認の直前に呼び、結果は即座に再封印する)。 */
export function openOwnGuardianShare(input: {
  readonly masterKeys: MasterKeys;
  readonly wrapped: WrappedDek;
  readonly context: GuardianWrapContext;
}): Effect.Effect<Uint8Array, CliError> {
  return Effect.gen(function* () {
    // info は openGuardianShare が仕様のフィールド順で組む(移植は復号失敗 — §8.3)
    const opened = yield* Effect.tryPromise({
      try: () =>
        openGuardianShare({
          guardianKeyPair: input.masterKeys.encKeyPair,
          wrapped: input.wrapped,
          context: input.context,
        }),
      catch: () => cliError("Failed to open your guardian share (crypto error)"),
    });
    if (!opened.ok) {
      return yield* Effect.fail(
        cliError(
          "Cannot open your guardian share with the master key on this device. The ward may have registered the group against a previous key of yours — ask them to re-add you with `maruhi guardian add`",
        ),
      );
    }
    return opened.value;
  });
}

/** 旧端末として B を KEK_h でラップする(承認バンドルの同送分 — §8.4)。 */
export function wrapOwnBlobForHandoff(input: {
  readonly masterKeys: MasterKeys;
  readonly kek: Uint8Array;
  readonly context: MasterWrapContext;
}): Effect.Effect<{ readonly nonce: Uint8Array; readonly ciphertext: Uint8Array }, CliError> {
  return Effect.gen(function* () {
    // JSON.stringify(record) は使わない(秘密側が伏字になる — keychain.ts の注記)
    const blob = new TextEncoder().encode(serializeStoredMasterKey(input.masterKeys.record));
    const wrapped = yield* Effect.tryPromise({
      try: () => wrapMasterBlob({ kek: input.kek, masterSecretBlob: blob, context: input.context }),
      catch: () => cliError("Failed to wrap the master key for the handoff (crypto error)"),
    });
    if (!wrapped.ok) {
      return yield* Effect.fail(cliError("Failed to wrap the master key for the handoff"));
    }
    return wrapped.value;
  });
}

/** 要求者の一時公開鍵(コードから復号した E.pub)へ 32 バイト値を封印する。 */
export function sealForRequester(input: {
  readonly ephemeralPublicKey: EncryptionKey;
  readonly value: Uint8Array;
  readonly context: HandoffWrapContext;
}): Effect.Effect<WrappedDek, CliError> {
  return Effect.gen(function* () {
    const sealed = yield* Effect.tryPromise({
      try: () => sealHandoffValue(input),
      catch: () => cliError("Failed to seal the approval to the requester's key (crypto error)"),
    });
    if (!sealed.ok) {
      return yield* Effect.fail(cliError("Failed to seal the approval to the requester's key"));
    }
    return sealed.value;
  });
}

/**
 * 台帳のクライアント採番 id(ULID)。wrap_id / group_id は AAD / info が束縛する
 * ため、暗号化の前にクライアントが決める(AUTH_SPEC §13-9)。
 */
export function newLedgerId(): string {
  return ulid();
}

/** hex(32 バイト)→ 鍵素材。サーバー応答の形式不正は実装バグ / 改竄として拒否する。 */
export function decodeWrapped(input: {
  readonly encHex: string;
  readonly ciphertextHex: string;
}): Effect.Effect<WrappedDek, CliError> {
  const enc = decodeHex(input.encHex);
  const ciphertext = decodeHex(input.ciphertextHex);
  return enc === null || ciphertext === null
    ? Effect.fail(cliError("The server response is malformed (cannot decode hex)"))
    : Effect.succeed({ enc, ciphertext });
}
