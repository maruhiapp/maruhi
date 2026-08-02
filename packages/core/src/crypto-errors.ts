// @maruhi/crypto の CryptoResult(kind 判別 union)を Effect の型付きエラーへ
// マッピングするラッパー。
//
// 設計判断(セッション 04 裁定 (b)、2026-08-02 確定): crypto は Effect 非依存の
// 純粋関数 + エラー値、Effect ラップは core 側で行う。判別は crypto 側が `kind`、
// Effect 側は Data.TaggedError の `_tag`(タグ名は "Crypto" プレフィックス)。
//
// 絶対規則の継承: エラーには平文値・鍵素材・暗号文の断片を含めない。crypto 側の
// エラー値が識別子(field / seq / 理由コード)しか運ばないため、ここでの詰め替えも
// それ以外を追加しない。

import type { ChainInvalidReason, CryptoError, CryptoResult } from "@maruhi/crypto";
import { Data, Effect } from "effect";

/** Structural validation of an input failed (wrong length, malformed hex, …). */
export class CryptoInvalidInputError extends Data.TaggedError("CryptoInvalidInput")<{
  readonly field: string;
}> {}

/** Key material could not be imported into WebCrypto / HPKE. */
export class CryptoKeyImportError extends Data.TaggedError("CryptoKeyImport")<{
  readonly key: "encryption-public" | "encryption-private" | "signing-public" | "signing-private";
}> {}

/** AES-256-GCM encryption failed unexpectedly. */
export class CryptoEncryptError extends Data.TaggedError("CryptoEncrypt")<{
  readonly operation: "variable" | "recovery";
}> {}

/** AES-256-GCM decryption failed (tampered ciphertext, wrong AAD / nonce / key). */
export class CryptoDecryptError extends Data.TaggedError("CryptoDecrypt")<{
  readonly operation: "variable" | "recovery";
}> {}

/** HPKE Seal failed. */
export class CryptoDekWrapError extends Data.TaggedError("CryptoDekWrap")<object> {}

/** HPKE Open failed (tampered enc / ciphertext or mismatched info context). */
export class CryptoDekUnwrapError extends Data.TaggedError("CryptoDekUnwrap")<object> {}

/** Ed25519 signing failed. */
export class CryptoSignError extends Data.TaggedError("CryptoSign")<object> {}

/** Membership-chain verification failed at entry `seq` for `reason`. */
export class ChainInvalidError extends Data.TaggedError("ChainInvalid")<{
  readonly seq: number;
  readonly reason: ChainInvalidReason;
}> {}

/** Union of all Effect-tagged errors a wrapped @maruhi/crypto operation can fail with. */
export type WrappedCryptoError =
  | CryptoInvalidInputError
  | CryptoKeyImportError
  | CryptoEncryptError
  | CryptoDecryptError
  | CryptoDekWrapError
  | CryptoDekUnwrapError
  | CryptoSignError
  | ChainInvalidError;

/** Maps a raw `CryptoError` value onto its Effect-tagged counterpart. */
export function toWrappedCryptoError(error: CryptoError): WrappedCryptoError {
  switch (error.kind) {
    case "InvalidInput":
      return new CryptoInvalidInputError({ field: error.field });
    case "KeyImportFailed":
      return new CryptoKeyImportError({ key: error.key });
    case "EncryptFailed":
      return new CryptoEncryptError({ operation: error.operation });
    case "DecryptFailed":
      return new CryptoDecryptError({ operation: error.operation });
    case "DekWrapFailed":
      return new CryptoDekWrapError();
    case "DekUnwrapFailed":
      return new CryptoDekUnwrapError();
    case "SignFailed":
      return new CryptoSignError();
    case "ChainInvalid":
      return new ChainInvalidError({ seq: error.seq, reason: error.reason });
  }
}

/** Lifts a `CryptoResult` value into `Effect`, mapping errors by `kind`. */
export function fromCryptoResult<T>(result: CryptoResult<T>): Effect.Effect<T, WrappedCryptoError> {
  return result.ok ? Effect.succeed(result.value) : Effect.fail(toWrappedCryptoError(result.error));
}

/**
 * Runs an async @maruhi/crypto operation and lifts its `CryptoResult` into
 * `Effect`. The thunk must never reject — crypto operations return errors as
 * values by contract (packages/crypto は throw しない)。
 */
export function cryptoEffect<T>(
  run: () => Promise<CryptoResult<T>>,
): Effect.Effect<T, WrappedCryptoError> {
  return Effect.flatMap(Effect.promise(run), fromCryptoResult);
}
