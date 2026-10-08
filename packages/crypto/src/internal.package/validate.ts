// Input validation / verification helpers shared by the signature modules
// (dek-wrap-sign.ts / meta-sign.ts / value-sign.ts / meta-verify.ts /
// value-verify.ts). Only lowercase fixed-length hex is the normalized form
// (allowing uppercase hex would give one datum multiple normalized forms and
// break the uniqueness of signatures and reconciliations).
//
// The error vocabularies (ValueInvalidReason / MetaInvalidReason /
// DekWrapSignatureInvalid) are intentionally distinct per spec, so they are
// not unified here: the error value / reason code returned on failure is
// injected by the caller via parameters; this module holds only the shared
// check logic.

import type { EnvironmentId } from "./chain-types.ts";
import { decodeHex, encodeHex } from "./bytes.ts";
import { ROLE_RANK } from "./chain-device.ts";

// The role order is defined only in chain-device.ts (re-exported here for the
// signature modules)
export { ROLE_RANK };
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";
import { scopeIncludesEnvironment } from "./member-scope.ts";

const SIGNATURE_BYTES = 64;
const FINGERPRINT_HEX_LENGTH = 16 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
const SIGNATURE_HEX_LENGTH = SIGNATURE_BYTES * 2;

/** An InvalidInput error value (field name only — never carries secrets or input fragments). */
export function invalidInput(field: string): {
  readonly ok: false;
  readonly error: CryptoError;
} {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/** Whether the value is a lowercase hex string of the given length (decodeHex accepts lowercase only). */
export function isLowercaseHexOfLength(value: string, length: number): boolean {
  return value.length === length && decodeHex(value) !== null;
}

/**
 * The shared core of Ed25519 signing (the sign of dek-wrap-sign /
 * invite-accept-sign). It performs only the WebCrypto signing and hex
 * encoding; structure validation of the signing target is done by the
 * caller first. The message of a WebCrypto exception is never propagated
 * (errors.ts's absolute rule).
 */
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

/**
 * The shared core of Ed25519 verification (the verify of dek-wrap-sign /
 * meta-sign / value-sign). It performs only the signature-shape check
 * (64-byte hex) and the WebCrypto verify. Verification failure and
 * WebCrypto exceptions (whose message may contain input fragments, so it is
 * never propagated — errors.ts's absolute rule) return the caller-injected
 * `onInvalid` as-is.
 */
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

/**
 * The shared input-check prologue of the distributed verifications
 * (meta-verify / value-verify). Only the actor-FP field name
 * (writerKeyFingerprintHex / authorKeyFingerprintHex) differs per caller,
 * so the name carried on InvalidInput is injected.
 */
export function distributedInputInvalidField(input: {
  readonly actorKeyFingerprintHex: string;
  /** The field name carried on InvalidInput (e.g. "writerKeyFingerprintHex"). */
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

/**
 * The shared core of key selection (the lead-in to §6.3-1): selects the key
 * matching the FP among those the history binds to the actor's user_id, and
 * imports it into WebCrypto. The check of the effective binding at the
 * declared head happens after signature verification (headAuthorizationReason)
 * — since the check order rules out a broken signature first, the selection
 * itself covers all tenure. When no binding exists, returns `onUnknown` in
 * the caller's vocabulary (writer-unknown / author-unknown).
 */
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
    // A key derived from a verified chain is always normalized hex (an
    // unreachable defensive line)
    return { ok: false, error: input.onUnknown };
  }
  return importSigningPublicKey(keyBytes);
}

/**
 * The reason-code mapping of the head-binding / authorization-time checks
 * (§6.3-1 to -3). The vocabulary is owned by the caller
 * (ValueInvalidReason / MetaInvalidReason) and not unified here.
 */
export interface HeadAuthorizationReasons<R> {
  readonly chainHeadFuture: R;
  readonly chainHeadMismatch: R;
  readonly notMemberAtHead: R;
  readonly keyMismatchAtHead: R;
  readonly roleInsufficientAtHead: R;
}

/**
 * §6.3's 3′ (2026-09-14 ES): an environment-targeting signature requires
 * that the actor's scope at the declared head contains the environment_id.
 * The reason code is the caller's vocabulary (writer- / author- /
 * issuer-environment-out-of-scope-at-head). Do not pass this for signatures
 * that carry no environment (head attestations).
 */
export interface HeadScopeCheck<R> {
  readonly environmentId: EnvironmentId;
  readonly outOfScopeAtHead: R;
}

/**
 * The shared check of head binding (§6.3-2) and authorization time
 * (§6.3-1 / -3) (the lead-in to meta-verify / value-verify's
 * headStateReason):
 * - Distinguishes the two kinds of mismatch: seq > own head = future (the
 *   entry point of resync); a hash mismatch at seq ≤ own head = hard
 *   evidence of a fork or a forgery
 * - Membership, key binding, and role at the declared head (inclusive). A
 *   key mismatch includes rejecting the remove → re-add-with-new-key tenure
 *   crossing (old interval's key × new interval's head) and a revoked
 *   device × a post-revocation head (2026-09-19 DK — device validity
 *   intervals)
 * - role / 3′ scope (when `scope` is passed) are judged by the **signing
 *   device's effective permission** (§6.3 "device-key selection and
 *   effective permission" — deviceStateAt's EffectivePermission, not the
 *   person's (role, scope). This is the single substitution point — design
 *   log dk-design.md §7 K2-4)
 * Epoch integrity (§6.3-4) is left to the caller since it is a check only
 * for value signatures.
 */
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
