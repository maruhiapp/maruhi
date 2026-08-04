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
  | "duplicate-member-key"
  | "duplicate-environment"
  | "unknown-environment"
  | "unknown-server-grant"
  | "grant-scope-narrowed"
  | "epoch-out-of-sequence";

/**
 * Reason codes for rejecting a distributed variable value (CRYPTO_SPEC §4.1 /
 * §6.3 — value-signature.json の rule negative が固定する語彙):
 *
 * - `signature-invalid` — valid-format の Ed25519 検証失敗
 * - `writer-unknown` — チェーン履歴のどの時点にも (writer_user_id, 鍵 FP) の
 *   束縛が存在しない(検証鍵を選択できない)
 * - `chain-head-mismatch` — 宣言 seq は自ビュー内だが保存ハッシュと不一致
 *   (§6.3-2a: チェーン分岐または偽造の硬い証拠 — 即時拒否)
 * - `chain-head-future` — 宣言 seq が自ビューのヘッドより先(§6.3-2b:
 *   まず再同期し、延長として一致すれば再検証。この理由での即時拒否は誤り)
 * - `writer-not-member-at-head` / `writer-key-mismatch-at-head` /
 *   `writer-role-insufficient-at-head` — 宣言ヘッド時点の認可検査(§6.3-1/3。
 *   key-mismatch は remove → 別鍵 re-add の tenure 跨ぎを含む)
 * - `environment-not-created-at-head` / `epoch-not-current-at-head` —
 *   宣言ヘッド時点のエポック整合(§6.3-4)
 * - `prev-shape-mismatch` — version 1 は空 / version > 1 は 64 hex という
 *   prev の形の違反(predecessor を保持しない latest-only でも必ず検査する)
 * - `prev-hash-mismatch` / `epoch-regressed` — predecessor を渡された場合のみの
 *   連鎖・エポック単調性検査(§6.3-6 / §4.1)
 */
export type ValueInvalidReason =
  | "signature-invalid"
  | "writer-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "writer-not-member-at-head"
  | "writer-key-mismatch-at-head"
  | "writer-role-insufficient-at-head"
  | "environment-not-created-at-head"
  | "epoch-not-current-at-head"
  | "prev-shape-mismatch"
  | "prev-hash-mismatch"
  | "epoch-regressed";

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
  /** A private key could not be serialized (e.g. it is non-extractable). */
  | {
      readonly kind: "KeyExportFailed";
      readonly key: "encryption-private" | "signing-private";
    }
  /** AES-256-GCM encryption failed unexpectedly (e.g. oversized plaintext). */
  | { readonly kind: "EncryptFailed"; readonly operation: "variable" | "recovery" }
  /** AES-256-GCM decryption failed (tampered ciphertext, wrong AAD/nonce/key). */
  | { readonly kind: "DecryptFailed"; readonly operation: "variable" | "recovery" }
  /** HPKE Seal failed. */
  | { readonly kind: "DekWrapFailed" }
  /** HPKE Open failed (tampered enc/ciphertext or mismatched info context). */
  | { readonly kind: "DekUnwrapFailed" }
  /** Ed25519 signing failed. */
  | { readonly kind: "SignFailed" }
  /** DEK-wrap registration signature verification failed (CRYPTO_SPEC §5.1). */
  | { readonly kind: "DekWrapSignatureInvalid" }
  /**
   * An unwrapped DEK does not match the chain-published commitment for its
   * (environment, epoch) coordinates (CRYPTO_SPEC §5.2 — poison wrap).
   */
  | { readonly kind: "DekCommitmentMismatch" }
  /**
   * A variable value failed verification (CRYPTO_SPEC §4.1 / §6.3): the
   * write signature, the declared chain head, the head-time authorization /
   * epoch, or the predecessor chaining was rejected for `reason`.
   */
  | { readonly kind: "ValueInvalid"; readonly reason: ValueInvalidReason }
  /** Chain verification failed at entry `seq` for `reason`. */
  | { readonly kind: "ChainInvalid"; readonly seq: number; readonly reason: ChainInvalidReason };

/**
 * Result of a fallible @maruhi/crypto operation. Errors are returned as values
 * (never thrown) so callers can wrap them into their own effect system.
 */
export type CryptoResult<T, E extends CryptoError = CryptoError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
