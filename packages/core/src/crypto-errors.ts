import type {
  AeadOperation,
  AttestationInvalidReason,
  ChainInvalidReason,
  CryptoError,
  CryptoResult,
  ManifestInvalidReason,
  MetaInvalidReason,
  ValueInvalidReason,
} from "@maruhi/crypto";
import { Data, Effect } from "effect";

export class CryptoInvalidInputError extends Data.TaggedError("CryptoInvalidInput")<{
  readonly field: string;
}> {}

export class CryptoKeyImportError extends Data.TaggedError("CryptoKeyImport")<{
  readonly key: "encryption-public" | "encryption-private" | "signing-public" | "signing-private";
}> {}

export class CryptoKeyExportError extends Data.TaggedError("CryptoKeyExport")<{
  readonly key: "encryption-private" | "signing-private";
}> {}

export class CryptoEncryptError extends Data.TaggedError("CryptoEncrypt")<{
  readonly operation: AeadOperation;
}> {}

export class CryptoDecryptError extends Data.TaggedError("CryptoDecrypt")<{
  readonly operation: AeadOperation;
}> {}

export class CryptoDekWrapError extends Data.TaggedError("CryptoDekWrap")<object> {}

export class CryptoDekUnwrapError extends Data.TaggedError("CryptoDekUnwrap")<object> {}

export class CryptoSignError extends Data.TaggedError("CryptoSign")<object> {}

export class CryptoDekWrapSignatureError extends Data.TaggedError(
  "CryptoDekWrapSignature",
)<object> {}

export class CryptoInviteAcceptSignatureError extends Data.TaggedError(
  "CryptoInviteAcceptSignature",
)<object> {}

export class CryptoInviteLinkSignatureError extends Data.TaggedError(
  "CryptoInviteLinkSignature",
)<object> {}

export class CryptoInviteIssueSignatureError extends Data.TaggedError(
  "CryptoInviteIssueSignature",
)<object> {}

export class CryptoDekCommitmentError extends Data.TaggedError("CryptoDekCommitment")<object> {}

export class CryptoValueInvalidError extends Data.TaggedError("CryptoValueInvalid")<{
  readonly reason: ValueInvalidReason;
}> {}

export class CryptoMetaStatementInvalidError extends Data.TaggedError(
  "CryptoMetaStatementInvalid",
)<{
  readonly reason: MetaInvalidReason;
}> {}

export class CryptoUnsupportedMetaLayoutError extends Data.TaggedError(
  "CryptoUnsupportedMetaLayout",
)<{
  readonly layoutVersion: number;
}> {}

export class CryptoEnvManifestInvalidError extends Data.TaggedError("CryptoEnvManifestInvalid")<{
  readonly reason: ManifestInvalidReason;
}> {}

export class CryptoHeadAttestationInvalidError extends Data.TaggedError(
  "CryptoHeadAttestationInvalid",
)<{
  readonly reason: AttestationInvalidReason;
}> {}

export class ChainInvalidError extends Data.TaggedError("ChainInvalid")<{
  readonly seq: number;
  readonly reason: ChainInvalidReason;
}> {}

type CryptoExports = typeof import("@maruhi/crypto");

export type CryptoPromiseOperation = {
  [K in keyof CryptoExports]: CryptoExports[K] extends (...args: never) => Promise<infer Result>
    ? [Result] extends [CryptoResult<unknown>]
      ? never
      : K
    : never;
}[keyof CryptoExports];

type BarePromiseResult<Operation extends CryptoPromiseOperation> = Awaited<
  ReturnType<CryptoExports[Operation]>
>;

export class CryptoRejectedError extends Data.TaggedError("CryptoRejected")<{
  readonly operation: CryptoPromiseOperation;
}> {}

export class CryptoContractViolationError extends Data.TaggedError("CryptoContractViolation")<{
  readonly message: string;
}> {
  constructor() {
    super({ message: "a CryptoResult-returning crypto operation rejected or threw" });
  }
}

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
  | CryptoInviteLinkSignatureError
  | CryptoInviteIssueSignatureError
  | CryptoDekCommitmentError
  | CryptoValueInvalidError
  | CryptoMetaStatementInvalidError
  | CryptoUnsupportedMetaLayoutError
  | CryptoEnvManifestInvalidError
  | CryptoHeadAttestationInvalidError
  | ChainInvalidError;

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
    case "InviteLinkSignatureInvalid":
      return new CryptoInviteLinkSignatureError();
    case "InviteIssueSignatureInvalid":
      return new CryptoInviteIssueSignatureError();
    case "DekCommitmentMismatch":
      return new CryptoDekCommitmentError();
    case "ValueInvalid":
      return new CryptoValueInvalidError({ reason: error.reason });
    case "MetaStatementInvalid":
      return new CryptoMetaStatementInvalidError({ reason: error.reason });
    case "UnsupportedMetaLayout":
      return new CryptoUnsupportedMetaLayoutError({ layoutVersion: error.layoutVersion });
    case "EnvManifestInvalid":
      return new CryptoEnvManifestInvalidError({ reason: error.reason });
    case "HeadAttestationInvalid":
      return new CryptoHeadAttestationInvalidError({ reason: error.reason });
    case "ChainInvalid":
      return new ChainInvalidError({ seq: error.seq, reason: error.reason });
  }
}

export function fromCryptoResult<T>(result: CryptoResult<T>): Effect.Effect<T, WrappedCryptoError> {
  return result.ok ? Effect.succeed(result.value) : Effect.fail(toWrappedCryptoError(result.error));
}

export function cryptoEffect<T>(
  run: () => Promise<CryptoResult<T>>,
): Effect.Effect<T, WrappedCryptoError> {
  return Effect.flatMap(
    Effect.promise(async () => {
      try {
        return await run();
      } catch {
        throw new CryptoContractViolationError();
      }
    }),
    fromCryptoResult,
  );
}

export function cryptoPromise<Operation extends CryptoPromiseOperation>(
  operation: Operation,
  run: () => Promise<BarePromiseResult<Operation>>,
): Effect.Effect<BarePromiseResult<Operation>, CryptoRejectedError> {
  return Effect.tryPromise({
    try: run,
    catch: () => new CryptoRejectedError({ operation }),
  });
}
