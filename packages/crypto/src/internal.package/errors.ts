// Typed errors (a discriminated union) and the Result type for @maruhi/crypto.
//
// Design decisions:
// crypto returns pure error values with no dependency on Effect; the Effect
// wrapping happens on the packages/core side.
// The discriminator is `kind` (a neutral name that does not collide with
// oxlint's no-underscore-dangle).
// The core-side Effect wrapper maps each kind to a Data.TaggedError.
//
// Absolute rule: errors never contain plaintext values, key material, or
// ciphertext fragments.
// Context is identifiers only (seq / op / reason codes). WebCrypto exception
// messages are not propagated either (some runtimes may include input
// fragments in them).

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
  // checkpoint op (§6.2). Duplicate environment_ids belong to the
  // payload structure check (invalid-payload) and have no dedicated reason
  // code
  | "checkpoint-audit-role-insufficient"
  | "checkpoint-epoch-mismatch"
  | "checkpoint-regression"
  // Environment scope (§6.2 — 2026-09-14 ES). The scope structure rule
  // (all + non-empty, duplicates, limit) is invalid-payload; existence of
  // each scope id reuses unknown-environment
  | "scope-role-mismatch"
  | "scope-not-contained"
  | "environment-out-of-scope"
  // Four-eyes (§6.2 — 2026-09-14 PF1). approve's owner check reuses
  // insufficient-role
  | "approval-required"
  | "approval-not-required"
  | "approval-quorum-unreachable"
  | "unknown-proposal"
  | "duplicate-approval"
  | "proposal-expired"
  | "proposal-void"
  // Device keys (§6.2 — 2026-09-19 DK). Key uniqueness is
  // duplicate-member-key; each id of a device scope is unknown-environment;
  // a signature by a revoked device is actor-key-mismatch; containment of
  // revoking another person's device reuses scope-not-contained
  | "unknown-device"
  | "last-device-protected"
  | "device-cap-exceeded";

/**
 * Reason codes for rejecting a distributed variable value (CRYPTO_SPEC §4.1 /
 * §6.3 — the vocabulary fixed by the rule negatives of value-signature.json):
 *
 * - `signature-invalid` — Ed25519 verification of a valid-format input failed
 * - `writer-unknown` — no point in chain history has a binding of
 *   (writer_user_id, key FP) (no verification key can be selected)
 * - `chain-head-mismatch` — the declared seq is within our view but does
 *   not match the stored hash (§6.3-2a: hard evidence of a chain fork or a
 *   forgery — reject immediately)
 * - `chain-head-future` — the declared seq is ahead of our view's head
 *   (§6.3-2b: resync first and re-verify if it matches as an extension;
 *   rejecting immediately on this reason is wrong)
 * - `writer-not-member-at-head` / `writer-key-mismatch-at-head` /
 *   `writer-role-insufficient-at-head` — authorization checks at the
 *   declared head (§6.3-1/3; key-mismatch includes tenure straddles of
 *   remove → re-add under a different key)
 * - `writer-environment-out-of-scope-at-head` — the writer's scope at the
 *   declared head does not contain the environment (§6.3's 3′ — right
 *   after the role check, before epoch consistency; 2026-09-14 ES)
 * - `environment-not-created-at-head` / `epoch-not-current-at-head` —
 *   epoch consistency at the declared head (§6.3-4)
 * - `prev-shape-mismatch` — a violation of the prev shape: empty at
 *   version 1, 64 hex at version > 1 (always checked, even latest-only
 *   without a predecessor)
 * - `prev-hash-mismatch` / `epoch-regressed` — chaining / epoch-
 *   monotonicity checks done only when a predecessor is given (§6.3-6 /
 *   §4.1)
 */
export type ValueInvalidReason =
  | "signature-invalid"
  | "writer-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "writer-not-member-at-head"
  | "writer-key-mismatch-at-head"
  | "writer-role-insufficient-at-head"
  | "writer-environment-out-of-scope-at-head"
  | "environment-not-created-at-head"
  | "epoch-not-current-at-head"
  | "prev-shape-mismatch"
  | "prev-hash-mismatch"
  | "epoch-regressed";

/**
 * Reason codes for rejecting a distributed metadata statement (CRYPTO_SPEC
 * §4.2 / §6.3 — the vocabulary fixed by the rule negatives of
 * metadata-signature.json). Its difference from the value
 * (ValueInvalidReason) codes is the semantics of metadata itself:
 *
 * - `signature-invalid` — Ed25519 verification of a valid-format input failed
 * - `author-unknown` — no point in chain history has a binding of
 *   (author_user_id, key FP) (no verification key can be selected)
 * - `chain-head-mismatch` / `chain-head-future` — the two ways a declared
 *   head mismatches (§6.3-2a / -2b; same distinction as value signatures —
 *   future is the entry point for resync)
 * - `author-not-member-at-head` / `author-key-mismatch-at-head` /
 *   `author-role-insufficient-at-head` — authorization checks at the
 *   declared head (§6.3-1/3; the role floor is admin only for environment
 *   deletion, member otherwise — §4.2 / AUTH_SPEC §12-3)
 * - `author-environment-out-of-scope-at-head` — the author's scope at the
 *   declared head does not contain the environment (§6.3's 3′ — both
 *   variable meta and environment meta are environment-targeted;
 *   2026-09-14 ES)
 * - `prev-shape-mismatch` — a violation of the prev shape: empty at
 *   metaVersion 1, 64 hex at > 1 (always checked, even latest-only without
 *   a predecessor)
 * - `prev-hash-mismatch` — the chaining check done only when a predecessor
 *   is given (§6.3-6)
 * - `revived-after-delete` — a successor statement to a deleted
 *   predecessor (§4.2's "no re-activation after delete" — a tombstone is
 *   terminal. Also applies to a transition to declared — the
 *   declared-after-delete vector)
 * - `declared-after-active` — a statement that declares the successor of
 *   an active predecessor (§4.2 layout v2 — never express a rollback of a
 *   value's existence. The only path that removes a value is deletion)
 * - `layout-regression` — a v1 successor statement to a layoutVersion 2
 *   predecessor (§4.2's per-variable layout monotonicity — allowing a
 *   regression would let a single rename silently erase the schema
 *   column, breaking the presence guarantee §14.2-8)
 *
 * There is **no** reason corresponding to epoch consistency (the value's
 * environment-not-created / epoch-not-current): metadata carries no epoch
 * anchor (§4.2), and injection into an advanced meta_version is the known
 * residual of an undetected v1 (§14.3-5).
 */
export type MetaInvalidReason =
  | "signature-invalid"
  | "author-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "author-not-member-at-head"
  | "author-key-mismatch-at-head"
  | "author-role-insufficient-at-head"
  | "author-environment-out-of-scope-at-head"
  | "prev-shape-mismatch"
  | "prev-hash-mismatch"
  | "revived-after-delete"
  | "declared-after-active"
  | "layout-regression";

/**
 * Reason codes for rejecting a distributed environment manifest
 * (CRYPTO_SPEC §4.3 / §6.3 — the vocabulary fixed by the rule negatives of
 * env-manifest.json). The essential difference from metadata statements
 * (MetaInvalidReason) is the epoch anchor:
 *
 * - `signature-invalid` — Ed25519 verification of a valid-format input failed
 * - `issuer-unknown` — no point in chain history has a binding of
 *   (issuer_user_id, key FP) (no verification key can be selected)
 * - `chain-head-mismatch` / `chain-head-future` — the two ways a declared
 *   head mismatches (§6.3-2a / -2b; same distinction as values and meta —
 *   future is the entry point for resync)
 * - `issuer-not-member-at-head` / `issuer-key-mismatch-at-head` /
 *   `issuer-role-insufficient-at-head` — authorization checks at the
 *   declared head (§6.3-1/3; every issuance trigger is a member-or-above
 *   meta operation — §4.3)
 * - `issuer-environment-out-of-scope-at-head` — the issuer's scope at the
 *   declared head does not contain the environment (§6.3's 3′ — right
 *   after the role check, before the prev / epoch checks; 2026-09-14 ES)
 * - `checkpoint-binding-mismatch` / `checkpoint-equivocation` /
 *   `environment-not-created-at-head` / `epoch-not-current-at-head` —
 *   epoch consistency (§4.3 (2)):
 *   if a `checkpoint` tuple for that (environment_id, manifest_version)
 *   exists on the verified chain, its (epoch, manifest_sig_hash) must
 *   match exactly (a mismatch is binding-mismatch; strict is not an
 *   alternative path). A differing tuple coexisting at the same
 *   coordinates is rejected as hard evidence of equivocation. Only when
 *   no tuple exists, a strict match against the current epoch at the
 *   declared head (the 2 reasons: env not created / epoch mismatch)
 * - `checkpoint-regressed` — rule 1 of checkpoint consistency (§6.3 /
 *   §4.3 (4)): a distribution whose manifestVersion or epoch falls below
 *   the environment's latest `checkpoint` basis (a rollback from a
 *   checkpointed state)
 * - `env-meta-mismatch` — (env_meta_version, env_meta_sig_hash_hex) does
 *   not match the verified environment meta statement (the recomputation
 *   target of AUTH_SPEC §12-5 (7))
 * - `variables-digest-mismatch` — recomputing variables_digest from the
 *   verified statement set (tombstones included) does not match =
 *   omission, injection, or an ordering violation (§4.3 (3))
 * - `prev-shape-mismatch` — a violation of the prev shape: empty at
 *   manifestVersion 1, 64 hex at > 1 (always checked, even latest-only
 *   without a predecessor)
 * - `prev-hash-mismatch` / `epoch-regressed` — chaining / epoch-
 *   monotonicity checks done only when a predecessor (the previous
 *   verified manifest) is given (isomorphic to §4.1 for values — detects
 *   an advanced manifestVersion that baked in an old epoch after a
 *   rotation)
 */
/**
 * Reason codes for rejecting a distributed head attestation (CRYPTO_SPEC
 * §6.6 — the vocabulary fixed by the rule negatives of
 * head-attestation.json). It shares the same 2-way head-binding
 * distinction as values and meta, but is treated differently at
 * reconciliation (§6.3 head gossip):
 *
 * - `signature-invalid` — Ed25519 verification of a valid-format input
 *   failed (not used as reconciliation material)
 * - `attester-unknown` — no point in chain history has a binding of
 *   (attester_user_id, key FP) (no verification key can be selected; not
 *   used as reconciliation material)
 * - `chain-head-mismatch` — the declared seq is within our view but does
 *   not match the stored hash (§6.3-2a / §6.6 reconciliation (a): since
 *   **the signature is verified**, the declaration itself is hard
 *   evidence of a fork (equivocation) or a leaked attester key — stop
 *   using that sync's artifacts and preserve the evidence)
 * - `chain-head-future` — the declared seq is ahead of our view's head
 *   (§6.3-2b / §6.6 reconciliation (b): normal if it resolves as an
 *   extension via bounded resync; otherwise (a))
 * - `attester-not-member-at-head` / `attester-key-mismatch-at-head` —
 *   membership / key-binding mismatch at the declared head (inclusive)
 *   (§6.6 (1)/(2); not used as reconciliation material). The required
 *   role floor is reader (every member may attest — §6.3), so there is
 *   no insufficient-role reason code
 */
export type AttestationInvalidReason =
  | "signature-invalid"
  | "attester-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "attester-not-member-at-head"
  | "attester-key-mismatch-at-head";

export type ManifestInvalidReason =
  | "signature-invalid"
  | "issuer-unknown"
  | "chain-head-mismatch"
  | "chain-head-future"
  | "issuer-not-member-at-head"
  | "issuer-key-mismatch-at-head"
  | "issuer-role-insufficient-at-head"
  | "issuer-environment-out-of-scope-at-head"
  | "environment-not-created-at-head"
  | "epoch-not-current-at-head"
  | "checkpoint-binding-mismatch"
  | "checkpoint-equivocation"
  | "checkpoint-regressed"
  | "env-meta-mismatch"
  | "variables-digest-mismatch"
  | "prev-shape-mismatch"
  | "prev-hash-mismatch"
  | "epoch-regressed";

/**
 * Which AES-256-GCM context an encrypt / decrypt failure belongs to:
 * `variable` (§4), `recovery` (§8 recovery-code wrap — unchanged) or
 * `master-wrap` (§8 ledger wraps under a passkey / guardian / handoff KEK).
 */
export type AeadOperation = "variable" | "recovery" | "master-wrap";

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
  | { readonly kind: "EncryptFailed"; readonly operation: AeadOperation }
  /** AES-256-GCM decryption failed (tampered ciphertext, wrong AAD/nonce/key). */
  | { readonly kind: "DecryptFailed"; readonly operation: AeadOperation }
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
  /** Invite link co-signature verification failed (CRYPTO_SPEC §6.5 — the link-key half). */
  | { readonly kind: "InviteLinkSignatureInvalid" }
  /** Invite issue signature verification failed (CRYPTO_SPEC §6.5 — the inviter's statement). */
  | { readonly kind: "InviteIssueSignatureInvalid" }
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
   * A metadata statement declares a wire `layoutVersion` beyond what this
   * build supports (CRYPTO_SPEC §4.2 layout selection — ruling CR): the client
   * must be updated. Checked **before** signature verification so an outdated
   * verifier fails with an honest "update required" error instead of a
   * signature failure that is indistinguishable from tampering.
   */
  | { readonly kind: "UnsupportedMetaLayout"; readonly layoutVersion: number }
  /**
   * An environment manifest failed verification (CRYPTO_SPEC §4.3 / §6.3):
   * the issuer signature, the declared chain head, the head-time
   * authorization / epoch integrity, the env-meta / variables-digest
   * recomputation, or the predecessor chaining was rejected for `reason`.
   */
  | { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason }
  /**
   * A head attestation failed verification (CRYPTO_SPEC §6.6): the attester
   * signature, the declared chain head (the 2-way distinction — §6.3-2), or
   * the head-time membership / key binding was rejected for `reason`.
   */
  | { readonly kind: "HeadAttestationInvalid"; readonly reason: AttestationInvalidReason }
  /** Chain verification failed at entry `seq` for `reason`. */
  | { readonly kind: "ChainInvalid"; readonly seq: number; readonly reason: ChainInvalidReason };

/**
 * Result of a fallible @maruhi/crypto operation. Errors are returned as values
 * (never thrown) so callers can wrap them into their own effect system.
 */
export type CryptoResult<T, E extends CryptoError = CryptoError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
