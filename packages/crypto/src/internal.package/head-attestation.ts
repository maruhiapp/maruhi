import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { ProjectId, UserId } from "./chain-types.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { AttestationInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  isLowercaseHexOfLength,
  ROLE_RANK,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

export interface HeadAttestationContext {
  readonly suite: string;
  readonly projectId: ProjectId;
  readonly attesterUserId: UserId;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
}

function contextInvalidField(context: HeadAttestationContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.attesterUserId.length === 0) {
    return "context attesterUserId";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

export function buildHeadAttestationSignedBytes(context: HeadAttestationContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/head-attestation`,
    context.projectId,
    context.attesterUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

export async function computeHeadAttestationSignedBytesHash(
  context: HeadAttestationContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildHeadAttestationSignedBytes(context))) };
}

export async function signHeadAttestation(input: {
  readonly context: HeadAttestationContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildHeadAttestationSignedBytes(input.context), input.signingKey);
}

export async function verifyHeadAttestationSignature(input: {
  readonly context: HeadAttestationContext;
  readonly signatureHex: string;
  readonly attesterPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildHeadAttestationSignedBytes(input.context),
    input.signatureHex,
    input.attesterPublicKey,
    { kind: "HeadAttestationInvalid", reason: "signature-invalid" },
  );
}

export interface DistributedHeadAttestationInput {
  readonly history: ChainHistoryIndex;
  readonly context: HeadAttestationContext;
  readonly attesterKeyFingerprintHex: string;
  readonly signatureHex: string;
}

function attestationInvalid(reason: AttestationInvalidReason): {
  readonly ok: false;
  readonly error: {
    readonly kind: "HeadAttestationInvalid";
    readonly reason: AttestationInvalidReason;
  };
} {
  return { ok: false, error: { kind: "HeadAttestationInvalid", reason } };
}

const HEAD_ATTESTATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "attester-not-member-at-head",
  keyMismatchAtHead: "attester-key-mismatch-at-head",
  roleInsufficientAtHead: "attester-not-member-at-head",
} as const satisfies HeadAuthorizationReasons<AttestationInvalidReason>;

export async function verifyDistributedHeadAttestation(
  input: DistributedHeadAttestationInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    contextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
      actorKeyFingerprintField: "attesterKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: undefined,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    onUnknown: { kind: "HeadAttestationInvalid", reason: "attester-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyHeadAttestationSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    attesterPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headAuthorizationReason({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.reader,
    reasons: HEAD_ATTESTATION_REASONS,
  });
  if (headReason !== null) {
    return attestationInvalid(headReason);
  }

  return {
    ok: true,
    value: {
      signedBytesHashHex: encodeHex(await sha256(buildHeadAttestationSignedBytes(input.context))),
    },
  };
}
