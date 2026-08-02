// @maruhi/crypto の型付きエラー(判別可能 union)と Result 型。
//
// 設計判断(セッション 04、裁定待ちのデフォルト (b)):
// crypto は Effect に依存しない純粋なエラー値を返し、Effect ラップは packages/core 側で行う。
// 判別子は `kind`(oxlint の no-underscore-dangle と衝突しない中立名)。
// core 側の Effect ラップでは kind ごとに Data.TaggedError へマッピングする。
//
// 絶対規則: エラーには平文値・鍵素材・暗号文の断片を一切含めない。
// 文脈は識別子(seq / op / 理由コード)のみ。WebCrypto 例外の message も伝播させない
// (ランタイムによっては入力の断片を含みうるため)。

/** Reason codes for chain verification failure (see CRYPTO_SPEC §6.2 / §6.3). */
export type ChainInvalidReason =
  | "empty-chain"
  | "bad-suite"
  | "bad-seq"
  | "bad-prev-hash"
  | "bad-genesis"
  | "bad-signature"
  | "invalid-payload"
  | "insufficient-role"
  | "actor-not-member"
  | "actor-key-mismatch"
  | "last-owner-protected"
  | "unknown-target"
  | "duplicate-member"
  | "unknown-server-grant"
  | "grant-scope-narrowed"
  | "epoch-out-of-sequence";

/** Typed error union for all fallible @maruhi/crypto operations. */
export type CryptoError =
  /** Input failed structural validation (wrong length, malformed hex, etc.). */
  | { readonly kind: "InvalidInput"; readonly field: string }
  /** Key material could not be imported into WebCrypto / HPKE. */
  | {
      readonly kind: "KeyImportFailed";
      readonly key:
        | "encryption-public"
        | "encryption-private"
        | "signing-public"
        | "signing-private";
    }
  /** AES-256-GCM decryption failed (tampered ciphertext, wrong AAD/nonce/key). */
  | { readonly kind: "DecryptFailed"; readonly operation: "variable" | "recovery" }
  /** HPKE Seal failed. */
  | { readonly kind: "DekWrapFailed" }
  /** HPKE Open failed (tampered enc/ciphertext or mismatched info context). */
  | { readonly kind: "DekUnwrapFailed" }
  /** Ed25519 signing failed. */
  | { readonly kind: "SignFailed" }
  /** Chain verification failed at entry `seq` for `reason`. */
  | { readonly kind: "ChainInvalid"; readonly seq: number; readonly reason: ChainInvalidReason };

/**
 * Result of a fallible @maruhi/crypto operation. Errors are returned as values
 * (never thrown) so callers can wrap them into their own effect system.
 */
export type CryptoResult<T, E extends CryptoError = CryptoError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
