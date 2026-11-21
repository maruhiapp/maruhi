import { decodeHex, encodeHex } from "./bytes.ts";
import { ROLE_RANK } from "./chain-device.ts";
import type { EnvironmentId } from "./chain-types.ts";

export { ROLE_RANK };
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";
import { scopeIncludesEnvironment } from "./member-scope.ts";

const SIGNATURE_BYTES = 64;
const FINGERPRINT_HEX_LENGTH = 16 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
const SIGNATURE_HEX_LENGTH = SIGNATURE_BYTES * 2;

export function invalidInput(field: string): {
  readonly ok: false;
  readonly error: CryptoError;
} {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

export function isLowercaseHexOfLength(value: string, length: number): boolean {
  return value.length === length && decodeHex(value) !== null;
}

export async function signEd25519Over(
  signedBytes: Uint8Array,
  signingKey: CryptoKey,
): Promise<CryptoResult<string>> {
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign("Ed25519", signingKey, signedBytes as BufferSource),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

export async function verifyEd25519Over(
  signedBytes: Uint8Array,
  signatureHex: string,
  publicKey: CryptoKey,
  onInvalid: CryptoError,
): Promise<CryptoResult<void>> {
  const signature = decodeHex(signatureHex);
  if (signature === null || signature.length !== SIGNATURE_BYTES) {
    return invalidInput("signatureHex");
  }
  try {
    const valid = await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signature as BufferSource,
      signedBytes as BufferSource,
    );
    return valid ? { ok: true, value: undefined } : { ok: false, error: onInvalid };
  } catch {
    return { ok: false, error: onInvalid };
  }
}

export function distributedInputInvalidField(input: {
  readonly actorKeyFingerprintHex: string;
  readonly actorKeyFingerprintField: string;
  readonly signatureHex: string;
  readonly predecessorSignedBytesHashHex: string | undefined;
}): string | null {
  if (!isLowercaseHexOfLength(input.actorKeyFingerprintHex, FINGERPRINT_HEX_LENGTH)) {
    return input.actorKeyFingerprintField;
  }
  if (!isLowercaseHexOfLength(input.signatureHex, SIGNATURE_HEX_LENGTH)) {
    return "signatureHex";
  }
  if (
    input.predecessorSignedBytesHashHex !== undefined &&
    !isLowercaseHexOfLength(input.predecessorSignedBytesHashHex, SHA256_HEX_LENGTH)
  ) {
    return "predecessor signedBytesHashHex";
  }
  return null;
}

export async function importActorKeyByFingerprint(input: {
  readonly history: ChainHistoryIndex;
  readonly actorUserId: string;
  readonly actorKeyFingerprintHex: string;
  readonly onUnknown: CryptoError;
}): Promise<CryptoResult<CryptoKey>> {
  const sigPubHex = input.history.sigKeyByFingerprint(
    input.actorUserId,
    input.actorKeyFingerprintHex,
  );
  if (sigPubHex === undefined) {
    return { ok: false, error: input.onUnknown };
  }
  const keyBytes = decodeHex(sigPubHex);
  if (keyBytes === null) {
    return { ok: false, error: input.onUnknown };
  }
  return importSigningPublicKey(keyBytes);
}

export interface HeadAuthorizationReasons<R> {
  readonly chainHeadFuture: R;
  readonly chainHeadMismatch: R;
  readonly notMemberAtHead: R;
  readonly keyMismatchAtHead: R;
  readonly roleInsufficientAtHead: R;
}

export interface HeadScopeCheck<R> {
  readonly environmentId: EnvironmentId;
  readonly outOfScopeAtHead: R;
}

export function headAuthorizationReason<R>(input: {
  readonly history: ChainHistoryIndex;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly actorUserId: string;
  readonly actorKeyFingerprintHex: string;
  readonly requiredRoleRank: number;
  readonly reasons: HeadAuthorizationReasons<R>;
  readonly scope?: HeadScopeCheck<R> | undefined;
}): R | null {
  if (input.chainHeadSeq > input.history.headSeq) {
    return input.reasons.chainHeadFuture;
  }
  if (input.history.entryHashAt(input.chainHeadSeq) !== input.chainHeadHashHex) {
    return input.reasons.chainHeadMismatch;
  }
  if (input.history.memberStateAt(input.actorUserId, input.chainHeadSeq) === undefined) {
    return input.reasons.notMemberAtHead;
  }
  const device = input.history.deviceStateAt(
    input.actorUserId,
    input.actorKeyFingerprintHex,
    input.chainHeadSeq,
  );
  if (device === undefined) {
    return input.reasons.keyMismatchAtHead;
  }
  const permission = device.permission;
  if (ROLE_RANK[permission.role] < input.requiredRoleRank) {
    return input.reasons.roleInsufficientAtHead;
  }
  if (
    input.scope !== undefined &&
    !scopeIncludesEnvironment(permission.scope, input.scope.environmentId)
  ) {
    return input.scope.outOfScopeAtHead;
  }
  return null;
}
