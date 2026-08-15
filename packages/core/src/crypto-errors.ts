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

import type {
  ChainInvalidReason,
  CryptoError,
  CryptoResult,
  MetaInvalidReason,
  ValueInvalidReason,
} from "@maruhi/crypto";
import { Data, Effect } from "effect";

/** Structural validation of an input failed (wrong length, malformed hex, …). */
export class CryptoInvalidInputError extends Data.TaggedError("CryptoInvalidInput")<{
  readonly field: string;
}> {}

/** Key material could not be imported into WebCrypto / HPKE. */
export class CryptoKeyImportError extends Data.TaggedError("CryptoKeyImport")<{
  readonly key: "encryption-public" | "encryption-private" | "signing-public" | "signing-private";
}> {}

/** A private key could not be serialized (e.g. it is non-extractable). */
export class CryptoKeyExportError extends Data.TaggedError("CryptoKeyExport")<{
  readonly key: "encryption-private" | "signing-private";
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

/** DEK-wrap registration signature verification failed (CRYPTO_SPEC §5.1). */
export class CryptoDekWrapSignatureError extends Data.TaggedError(
  "CryptoDekWrapSignature",
)<object> {}

/** Invite-acceptance signature verification failed (CRYPTO_SPEC §6.5). */
export class CryptoInviteAcceptSignatureError extends Data.TaggedError(
  "CryptoInviteAcceptSignature",
)<object> {}

/**
 * An unwrapped DEK does not match the chain-published commitment for its
 * coordinates (CRYPTO_SPEC §5.2 — poison wrap).
 */
export class CryptoDekCommitmentError extends Data.TaggedError("CryptoDekCommitment")<object> {}

/**
 * A variable value failed the §4.1 / §6.3 verification (signature, declared
 * chain head, head-time authorization / epoch, or predecessor chaining) for
 * `reason`.
 */
export class CryptoValueInvalidError extends Data.TaggedError("CryptoValueInvalid")<{
  readonly reason: ValueInvalidReason;
}> {}

/**
 * A metadata statement failed the §4.2 / §6.3 verification (author
 * signature, declared chain head, head-time authorization, or predecessor
 * chaining) for `reason`.
 */
export class CryptoMetaStatementInvalidError extends Data.TaggedError(
  "CryptoMetaStatementInvalid",
)<{
  readonly reason: MetaInvalidReason;
}> {}

/** Membership-chain verification failed at entry `seq` for `reason`. */
export class ChainInvalidError extends Data.TaggedError("ChainInvalid")<{
  readonly seq: number;
  readonly reason: ChainInvalidReason;
}> {}

/** Union of all Effect-tagged errors a wrapped @maruhi/crypto operation can fail with. */
export type WrappedCryptoError =
  | CryptoInvalidInputError
  | CryptoKeyImportError
  | CryptoKeyExportError
  | CryptoEncryptError
  | CryptoDecryptError
  | CryptoDekWrapError
  | CryptoDekUnwrapError
  | CryptoSignError
  | CryptoDekWrapSignatureError
  | CryptoInviteAcceptSignatureError
  | CryptoDekCommitmentError
  | CryptoValueInvalidError
  | CryptoMetaStatementInvalidError
  | ChainInvalidError;

/** Maps a raw `CryptoError` value onto its Effect-tagged counterpart. */
export function toWrappedCryptoError(error: CryptoError): WrappedCryptoError {
  switch (error.kind) {
    case "InvalidInput":
      return new CryptoInvalidInputError({ field: error.field });
    case "KeyImportFailed":
      return new CryptoKeyImportError({ key: error.key });
    case "KeyExportFailed":
      return new CryptoKeyExportError({ key: error.key });
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
    case "DekWrapSignatureInvalid":
      return new CryptoDekWrapSignatureError();
    case "InviteAcceptSignatureInvalid":
      return new CryptoInviteAcceptSignatureError();
    case "DekCommitmentMismatch":
      return new CryptoDekCommitmentError();
    case "ValueInvalid":
      return new CryptoValueInvalidError({ reason: error.reason });
    case "MetaStatementInvalid":
      return new CryptoMetaStatementInvalidError({ reason: error.reason });
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
