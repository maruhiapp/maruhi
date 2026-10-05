// Bridges @maruhi/crypto (Effect-free: pure functions + error values)
// into Effect. Two wrappers, matched to the two async return shapes
// crypto exposes:
//
//   - `cryptoEffect` for operations returning `Promise<CryptoResult<T>>`
//     (the normal contract — errors come back as values, mapped by
//     `kind` onto the tagged errors below). A rejection there is a
//     broken contract — a bug — and surfaces as a defect.
//   - `cryptoPromise` for the few exports returning a bare `Promise<T>`
//     (`CryptoPromiseOperation`). A rejection becomes
//     `CryptoRejectedError`; the rejection cause is dropped on purpose,
//     so no key material or value can ever ride along in an error.
//
// The discriminator is `kind` on the crypto side and Data.TaggedError's
// `_tag` on the Effect side (tag names carry the "Crypto" prefix).
//
// Inheriting the absolute rule: errors never contain fragments of
// plaintext values, key material, or ciphertexts. Because crypto-side
// error values carry only identifiers (field / seq / reason codes),
// this repacking adds nothing else.
//
// Call sites handle a wrapped crypto error in one of three ways only:
//   - `Effect.catchTag` — handle specific errors by `_tag`,
//   - `Effect.orDie` — an error means an invariant broke; make it a defect,
//   - `Effect.mapError` — re-wrap into a domain error.
//
// The "no leak" guarantee covers both channels: the typed error
// channel carries only `CryptoError`-derived fields (or just the
// operation name for `CryptoRejectedError`), and a `cryptoEffect`
// rejection dies with a fixed `CryptoContractViolationError` — the
// rejection value never reaches the defect.

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
  readonly operation: AeadOperation;
}> {}

/** AES-256-GCM decryption failed (tampered ciphertext, wrong AAD / nonce / key). */
export class CryptoDecryptError extends Data.TaggedError("CryptoDecrypt")<{
  readonly operation: AeadOperation;
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

/** Invite link co-signature verification failed (CRYPTO_SPEC §6.5). */
export class CryptoInviteLinkSignatureError extends Data.TaggedError(
  "CryptoInviteLinkSignature",
)<object> {}

/** Invite issue signature verification failed (CRYPTO_SPEC §6.5). */
export class CryptoInviteIssueSignatureError extends Data.TaggedError(
  "CryptoInviteIssueSignature",
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

/**
 * A metadata statement declares a wire `layoutVersion` beyond what this
 * build supports (CRYPTO_SPEC §4.2 layout selection): the client must be
 * updated. Distinct from `CryptoMetaStatementInvalid` so callers can show an
 * honest "update required" instead of a tampering warning.
 */
export class CryptoUnsupportedMetaLayoutError extends Data.TaggedError(
  "CryptoUnsupportedMetaLayout",
)<{
  readonly layoutVersion: number;
}> {}

/**
 * An environment manifest failed the §4.3 / §6.3 verification (issuer
 * signature, declared chain head, head-time authorization / epoch integrity,
 * env-meta / variables-digest recomputation, or predecessor chaining) for
 * `reason`.
 */
export class CryptoEnvManifestInvalidError extends Data.TaggedError("CryptoEnvManifestInvalid")<{
  readonly reason: ManifestInvalidReason;
}> {}

/**
 * A head attestation failed the §6.6 verification (attester signature,
 * declared chain head, or head-time membership / key binding) for `reason`.
 */
export class CryptoHeadAttestationInvalidError extends Data.TaggedError(
  "CryptoHeadAttestationInvalid",
)<{
  readonly reason: AttestationInvalidReason;
}> {}

/** Membership-chain verification failed at entry `seq` for `reason`. */
export class ChainInvalidError extends Data.TaggedError("ChainInvalid")<{
  readonly seq: number;
  readonly reason: ChainInvalidReason;
}> {}

type CryptoExports = typeof import("@maruhi/crypto");

/**
 * The @maruhi/crypto exports that return a bare `Promise` (no
 * `CryptoResult`) and can therefore reject. Derived from the package's
 * public surface: a new bare-Promise export widens this union (and what
 * `cryptoPromise` accepts) automatically, and an export switching to
 * `CryptoResult` drops out.
 */
export type CryptoPromiseOperation = {
  [K in keyof CryptoExports]: CryptoExports[K] extends (...args: never) => Promise<infer Result>
    ? [Result] extends [CryptoResult<unknown>]
      ? never
      : K
    : never;
}[keyof CryptoExports];

/** The awaited success type of the named bare-Promise export. */
type BarePromiseResult<Operation extends CryptoPromiseOperation> = Awaited<
  ReturnType<CryptoExports[Operation]>
>;

/**
 * A bare-Promise @maruhi/crypto operation (`CryptoPromiseOperation`)
 * rejected. The rejection cause is deliberately not kept — key material
 * and plaintext values must never be able to ride along in an error
 * (absolute rule). Deliberately not part of `WrappedCryptoError`: that
 * union mirrors `CryptoError` kinds 1:1, and a rejection is not a
 * `CryptoError` value.
 */
export class CryptoRejectedError extends Data.TaggedError("CryptoRejected")<{
  readonly operation: CryptoPromiseOperation;
}> {}

/**
 * A `Promise<CryptoResult>`-returning @maruhi/crypto operation rejected —
 * the crypto contract (errors come back as values, a promise never
 * rejects) was violated. Used only as a defect: it carries no part of
 * the rejection value, so nothing derived from key material or
 * plaintext can reach crash output (absolute rule). The `_tag` and a
 * fixed static message (so `Cause.pretty` renders a readable line) are
 * the whole diagnostic — the message is a constant, never runtime
 * data, so no payload exists to leak.
 */
export class CryptoContractViolationError extends Data.TaggedError("CryptoContractViolation")<{
  readonly message: string;
}> {
  constructor() {
    super({ message: "a CryptoResult-returning crypto operation rejected or threw" });
  }
}

/**
 * Union of the Effect-tagged errors a `CryptoResult`-returning
 * @maruhi/crypto operation can fail with — one member per `CryptoError`
 * kind. (`CryptoRejectedError` stays outside: see its doc.)
 */
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

/** Lifts a `CryptoResult` value into `Effect`, mapping errors by `kind`. */
export function fromCryptoResult<T>(result: CryptoResult<T>): Effect.Effect<T, WrappedCryptoError> {
  return result.ok ? Effect.succeed(result.value) : Effect.fail(toWrappedCryptoError(result.error));
}

/**
 * Runs an async @maruhi/crypto operation that returns `CryptoResult` and
 * lifts the result into `Effect`, mapping errors by `kind`. Only for
 * operations returning `CryptoResult` — crypto returns errors as values
 * by contract, so a rejection is a bug and surfaces as a defect
 * (`Effect.promise`). The defect is a fixed
 * `CryptoContractViolationError`: the rejection value is replaced
 * inside the thunk before `Effect.promise` can embed it, so no key
 * material or plaintext can leak into crash output. For exports
 * returning a bare `Promise`, use `cryptoPromise`.
 */
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

/**
 * Runs one of the bare-Promise @maruhi/crypto exports
 * (`CryptoPromiseOperation`) and lifts the value into `Effect`. The
 * thunk's return type is pinned to the named export's, so `operation`
 * and `run` cannot disagree. A rejection becomes `CryptoRejectedError`
 * carrying only `operation` — the rejection cause is never kept, so no
 * key material or value can leak into the error channel.
 */
export function cryptoPromise<Operation extends CryptoPromiseOperation>(
  operation: Operation,
  run: () => Promise<BarePromiseResult<Operation>>,
): Effect.Effect<BarePromiseResult<Operation>, CryptoRejectedError> {
  return Effect.tryPromise({
    try: run,
    catch: () => new CryptoRejectedError({ operation }),
  });
}
