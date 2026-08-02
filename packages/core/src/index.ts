// @maruhi/core — ドメイン型、Effect Schema、共有ロジック。
// crypto(Effect 非依存)と上位層(Effect ベース)の橋渡しはここで行う。

export {
  ChainInvalidError,
  CryptoDecryptError,
  CryptoDekUnwrapError,
  CryptoDekWrapError,
  CryptoEncryptError,
  cryptoEffect,
  CryptoInvalidInputError,
  CryptoKeyImportError,
  CryptoSignError,
  fromCryptoResult,
  toWrappedCryptoError,
  type WrappedCryptoError,
} from "./crypto-errors.ts";
export {
  anonymousPrincipal,
  type AuthenticatedPrincipal,
  type IssuedSession,
  type IssuedToken,
  type OrgRole,
  OrgRoleSchema,
  parseTokenScopes,
  permissionAtLeast,
  type Principal,
  RequestAuth,
  type RequestAuthShape,
  scopePermissionFor,
  SessionService,
  type SessionServiceShape,
  type TokenPermission,
  TokenPermissionSchema,
  type TokenScope,
  TokenScopeSchema,
  TokenService,
  type TokenServiceShape,
} from "./auth.ts";
export { isProjectId, type ProjectId, ProjectIdSchema } from "./project.ts";
