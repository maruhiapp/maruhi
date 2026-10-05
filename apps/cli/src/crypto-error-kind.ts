// The reverse of @maruhi/core's `toWrappedCryptoError`: user-visible
// verification messages are pinned to the crypto-side `kind` vocabulary
// (`reason=${error.kind}`), but a `WrappedCryptoError` carries only its
// payload fields, not the kind name. Recover the kind here.
//
// Discrimination by the constructor (same mechanism as `internalErrorKind`
// in failure.ts) — reading `_tag` directly is banned by oxlint.

import {
  ChainInvalidError,
  CryptoDecryptError,
  CryptoDekCommitmentError,
  CryptoDekUnwrapError,
  CryptoDekWrapError,
  CryptoDekWrapSignatureError,
  CryptoEncryptError,
  CryptoEnvManifestInvalidError,
  CryptoHeadAttestationInvalidError,
  CryptoInviteAcceptSignatureError,
  CryptoInviteIssueSignatureError,
  CryptoInviteLinkSignatureError,
  CryptoInvalidInputError,
  CryptoKeyExportError,
  CryptoKeyImportError,
  CryptoMetaStatementInvalidError,
  CryptoSignError,
  CryptoUnsupportedMetaLayoutError,
  CryptoValueInvalidError,
  type WrappedCryptoError,
} from "@maruhi/core";
import type { CryptoError } from "@maruhi/crypto";

const KIND_BY_CONSTRUCTOR = new Map<
  abstract new (...args: never[]) => WrappedCryptoError,
  CryptoError["kind"]
>([
  [CryptoInvalidInputError, "InvalidInput"],
  [CryptoKeyImportError, "KeyImportFailed"],
  [CryptoKeyExportError, "KeyExportFailed"],
  [CryptoEncryptError, "EncryptFailed"],
  [CryptoDecryptError, "DecryptFailed"],
  [CryptoDekWrapError, "DekWrapFailed"],
  [CryptoDekUnwrapError, "DekUnwrapFailed"],
  [CryptoSignError, "SignFailed"],
  [CryptoDekWrapSignatureError, "DekWrapSignatureInvalid"],
  [CryptoInviteAcceptSignatureError, "InviteAcceptSignatureInvalid"],
  [CryptoInviteLinkSignatureError, "InviteLinkSignatureInvalid"],
  [CryptoInviteIssueSignatureError, "InviteIssueSignatureInvalid"],
  [CryptoDekCommitmentError, "DekCommitmentMismatch"],
  [CryptoValueInvalidError, "ValueInvalid"],
  [CryptoMetaStatementInvalidError, "MetaStatementInvalid"],
  [CryptoUnsupportedMetaLayoutError, "UnsupportedMetaLayout"],
  [CryptoEnvManifestInvalidError, "EnvManifestInvalid"],
  [CryptoHeadAttestationInvalidError, "HeadAttestationInvalid"],
  [ChainInvalidError, "ChainInvalid"],
]);

/** The `CryptoError.kind` a wrapped error was converted from. */
export function cryptoErrorKind(error: WrappedCryptoError): CryptoError["kind"] {
  const kind = KIND_BY_CONSTRUCTOR.get(
    error.constructor as abstract new (...args: never[]) => WrappedCryptoError,
  );
  // WrappedCryptoError is a closed union — a non-member is a broken
  // invariant, surfaced as a defect rather than a guessed kind
  if (kind === undefined) {
    throw new Error("unclassified wrapped crypto error");
  }
  return kind;
}
