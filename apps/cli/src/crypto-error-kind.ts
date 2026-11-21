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

export function cryptoErrorKind(error: WrappedCryptoError): CryptoError["kind"] {
  const kind = KIND_BY_CONSTRUCTOR.get(
    error.constructor as abstract new (...args: never[]) => WrappedCryptoError,
  );
  if (kind === undefined) {
    throw new Error("unclassified wrapped crypto error");
  }
  return kind;
}
