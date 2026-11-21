import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ValueInvalidReason } from "./errors.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";
import {
  computeValueSignedBytesHash,
  valueContextInvalidField,
  type ValueSignatureContext,
  verifyValueSignature,
} from "./value-sign.ts";

export interface ValuePredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

export interface DistributedValueInput {
  readonly history: ChainHistoryIndex;
  readonly context: ValueSignatureContext;
  readonly writerKeyFingerprintHex: string;
  readonly signatureHex: string;
  readonly predecessor?: ValuePredecessor | undefined;
}

function valueInvalid(reason: ValueInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "ValueInvalid"; readonly reason: ValueInvalidReason };
} {
  return { ok: false, error: { kind: "ValueInvalid", reason } };
}

const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "writer-not-member-at-head",
  keyMismatchAtHead: "writer-key-mismatch-at-head",
  roleInsufficientAtHead: "writer-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<ValueInvalidReason>;

function headStateReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { history, context } = input;
  const authorization = headAuthorizationReason<ValueInvalidReason>({
    history,
    chainHeadSeq: context.chainHeadSeq,
    chainHeadHashHex: context.chainHeadHashHex,
    actorUserId: context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
    scope: {
      environmentId: context.environmentId,
      outOfScopeAtHead: "writer-environment-out-of-scope-at-head",
    },
  });
  if (authorization !== null) {
    return authorization;
  }
  const environment = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (environment === undefined) {
    return "environment-not-created-at-head";
  }
  if (environment.currentEpoch !== context.epoch) {
    return "epoch-not-current-at-head";
  }
  return null;
}

function prevReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { context, predecessor } = input;
  if ((context.version === 1) !== (context.prevValueSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  if (context.prevValueSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

export async function verifyDistributedValue(
  input: DistributedValueInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    valueContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.writerKeyFingerprintHex,
      actorKeyFingerprintField: "writerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    onUnknown: { kind: "ValueInvalid", reason: "writer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyValueSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    writerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return valueInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return valueInvalid(chainReason);
  }

  const hash = await computeValueSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
