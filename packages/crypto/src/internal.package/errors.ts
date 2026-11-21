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
  | "checkpoint-audit-role-insufficient"
  | "checkpoint-epoch-mismatch"
  | "checkpoint-regression"
  | "scope-role-mismatch"
  | "scope-not-contained"
  | "environment-out-of-scope"
  | "approval-required"
  | "approval-not-required"
  | "approval-quorum-unreachable"
  | "unknown-proposal"
  | "duplicate-approval"
  | "proposal-expired"
  | "proposal-void"
  | "unknown-device"
  | "last-device-protected"
  | "device-cap-exceeded"
  | "environment-deleted";

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

export type AeadOperation = "variable" | "recovery" | "master-wrap";

export type CryptoError =
  | { readonly kind: "InvalidInput"; readonly field: string }
  | {
      readonly kind: "KeyImportFailed";
      readonly key:
        | "encryption-public"
        | "encryption-private"
        | "signing-public"
        | "signing-private";
    }
  | {
      readonly kind: "KeyExportFailed";
      readonly key: "encryption-private" | "signing-private";
    }
  | { readonly kind: "EncryptFailed"; readonly operation: AeadOperation }
  | { readonly kind: "DecryptFailed"; readonly operation: AeadOperation }
  | { readonly kind: "DekWrapFailed" }
  | { readonly kind: "DekUnwrapFailed" }
  | { readonly kind: "SignFailed" }
  | { readonly kind: "DekWrapSignatureInvalid" }
  | { readonly kind: "InviteAcceptSignatureInvalid" }
  | { readonly kind: "InviteLinkSignatureInvalid" }
  | { readonly kind: "InviteIssueSignatureInvalid" }
  | { readonly kind: "DekCommitmentMismatch" }
  | { readonly kind: "ValueInvalid"; readonly reason: ValueInvalidReason }
  | { readonly kind: "MetaStatementInvalid"; readonly reason: MetaInvalidReason }
  | { readonly kind: "UnsupportedMetaLayout"; readonly layoutVersion: number }
  | { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason }
  | { readonly kind: "HeadAttestationInvalid"; readonly reason: AttestationInvalidReason }
  | { readonly kind: "ChainInvalid"; readonly seq: number; readonly reason: ChainInvalidReason };

export type CryptoResult<T, E extends CryptoError = CryptoError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
