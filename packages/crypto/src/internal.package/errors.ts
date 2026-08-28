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
  | "duplicate-server-key"
  | "epoch-out-of-sequence"
  // checkpoint op(§6.2。2026-08-27 セッション 33 — PR-F3a)。重複 environment_id は
  // payload 構造検査(invalid-payload)に属し、専用理由コードを持たない
  | "checkpoint-audit-role-insufficient"
  | "checkpoint-epoch-mismatch"
  | "checkpoint-regression";

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

/**
 * Reason codes for rejecting a distributed metadata statement (CRYPTO_SPEC
 * §4.2 / §6.3 — metadata-signature.json の rule negative が固定する語彙)。
 * 値(ValueInvalidReason)との違いはメタの意味論そのもの:
 *
 * - `signature-invalid` — valid-format の Ed25519 検証失敗
 * - `author-unknown` — チェーン履歴のどの時点にも (author_user_id, 鍵 FP) の
 *   束縛が存在しない(検証鍵を選択できない)
 * - `chain-head-mismatch` / `chain-head-future` — 宣言ヘッドの不一致 2 種
 *   (§6.3-2a / -2b。値署名と同じ区別 — future は再同期の入口)
 * - `author-not-member-at-head` / `author-key-mismatch-at-head` /
 *   `author-role-insufficient-at-head` — 宣言ヘッド時点の認可検査(§6.3-1/3。
 *   role 水準は環境の削除のみ admin、それ以外は member — §4.2 / AUTH_SPEC §12-3)
 * - `prev-shape-mismatch` — metaVersion 1 は空 / > 1 は 64 hex という prev の
 *   形の違反(predecessor を保持しない latest-only でも必ず検査する)
 * - `prev-hash-mismatch` — predecessor を渡された場合のみの連鎖検査(§6.3-6)
 * - `revived-after-delete` — deleted な predecessor の後続ステートメント
 *   (§4.2 の「削除後の再 active 化は禁止」— tombstone は終端)
 *
 * エポック整合(値の environment-not-created / epoch-not-current)に相当する
 * 理由は**存在しない**: メタはエポックアンカーを持たず(§4.2)、前進
 * meta_version への注入は v1 未検出の既知残余(§14.3-5)。
 */
export type MetaInvalidReason =
  | "signature-invalid"
  | "author-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "author-not-member-at-head"
  | "author-key-mismatch-at-head"
  | "author-role-insufficient-at-head"
  | "prev-shape-mismatch"
  | "prev-hash-mismatch"
  | "revived-after-delete";

/**
 * Reason codes for rejecting a distributed environment manifest (CRYPTO_SPEC
 * §4.3 / §6.3 — env-manifest.json の rule negative が固定する語彙)。
 * メタステートメント(MetaInvalidReason)との本質的な差はエポックアンカー:
 *
 * - `signature-invalid` — valid-format の Ed25519 検証失敗
 * - `issuer-unknown` — チェーン履歴のどの時点にも (issuer_user_id, 鍵 FP) の
 *   束縛が存在しない(検証鍵を選択できない)
 * - `chain-head-mismatch` / `chain-head-future` — 宣言ヘッドの不一致 2 種
 *   (§6.3-2a / -2b。値・メタと同じ区別 — future は再同期の入口)
 * - `issuer-not-member-at-head` / `issuer-key-mismatch-at-head` /
 *   `issuer-role-insufficient-at-head` — 宣言ヘッド時点の認可検査(§6.3-1/3。
 *   発行契機はすべて member 以上のメタ操作 — §4.3)
 * - `environment-not-created-at-head` / `epoch-not-current-at-head` —
 *   エポック整合(§4.3 (2)): マニフェストの epoch は宣言ヘッド時点の現エポックと
 *   一致するか、宣言ヘッドの**次の**エントリ(= 複合発行の同梱チェーンエントリ —
 *   AUTH_SPEC §12-4 / §12-5 (4))が当該環境にちょうどそのエポックを確立する
 * - `env-meta-mismatch` — (env_meta_version, env_meta_sig_hash_hex) が検証済み
 *   環境メタステートメントと不一致(AUTH_SPEC §12-5 (7) の再計算対象)
 * - `variables-digest-mismatch` — 検証済みステートメント集合(tombstone 込み)
 *   からの variables_digest 再計算が不一致 = 欠落・注入・順序違反(§4.3 (3))
 * - `prev-shape-mismatch` — manifestVersion 1 は空 / > 1 は 64 hex という prev の
 *   形の違反(predecessor を保持しない latest-only でも必ず検査する)
 * - `prev-hash-mismatch` / `epoch-regressed` — predecessor(検証済みの直前
 *   マニフェスト)を渡された場合のみの連鎖・エポック単調性検査(値の §4.1 と
 *   同型 — rotate 後に旧エポックを焼き込んだ前進 manifestVersion の検出)
 */
export type ManifestInvalidReason =
  | "signature-invalid"
  | "issuer-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "issuer-not-member-at-head"
  | "issuer-key-mismatch-at-head"
  | "issuer-role-insufficient-at-head"
  | "environment-not-created-at-head"
  | "epoch-not-current-at-head"
  | "env-meta-mismatch"
  | "variables-digest-mismatch"
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
  /** Invite-acceptance signature verification failed (CRYPTO_SPEC §6.5). */
  | { readonly kind: "InviteAcceptSignatureInvalid" }
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
  /**
   * A metadata statement failed verification (CRYPTO_SPEC §4.2 / §6.3): the
   * author signature, the declared chain head, the head-time authorization,
   * or the predecessor chaining was rejected for `reason`.
   */
  | { readonly kind: "MetaStatementInvalid"; readonly reason: MetaInvalidReason }
  /**
   * An environment manifest failed verification (CRYPTO_SPEC §4.3 / §6.3):
   * the issuer signature, the declared chain head, the head-time
   * authorization / epoch integrity, the env-meta / variables-digest
   * recomputation, or the predecessor chaining was rejected for `reason`.
   */
  | { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason }
  /** Chain verification failed at entry `seq` for `reason`. */
  | { readonly kind: "ChainInvalid"; readonly seq: number; readonly reason: ChainInvalidReason };

/**
 * Result of a fallible @maruhi/crypto operation. Errors are returned as values
 * (never thrown) so callers can wrap them into their own effect system.
 */
export type CryptoResult<T, E extends CryptoError = CryptoError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
