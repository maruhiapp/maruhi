import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, MetaInvalidReason } from "./errors.ts";
import {
  computeMetaSignedBytesHash,
  metaContextRejection,
  metaLayoutVersionOf,
  type MetaStatementContext,
  type MetaStatementStatus,
  verifyMetaStatementSignature,
} from "./meta-sign.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";

export interface MetaPredecessor {
  readonly signedBytesHashHex: string;
  readonly status: MetaStatementStatus;
  readonly layoutVersion: number;
}

export interface DistributedMetaStatementInput {
  readonly history: ChainHistoryIndex;
  readonly context: MetaStatementContext;
  readonly authorKeyFingerprintHex: string;
  readonly signatureHex: string;
  readonly predecessor?: MetaPredecessor | undefined;
}

function metaInvalid(reason: MetaInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "MetaStatementInvalid"; readonly reason: MetaInvalidReason };
} {
  return { ok: false, error: { kind: "MetaStatementInvalid", reason } };
}

const REQUIRED_ROLE_RANK = ROLE_RANK.member;

const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "author-not-member-at-head",
  keyMismatchAtHead: "author-key-mismatch-at-head",
  roleInsufficientAtHead: "author-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<MetaInvalidReason>;

function headStateReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { history, context } = input;
  return headAuthorizationReason<MetaInvalidReason>({
    history,
    chainHeadSeq: context.chainHeadSeq,
    chainHeadHashHex: context.chainHeadHashHex,
    actorUserId: context.authorUserId,
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    requiredRoleRank: REQUIRED_ROLE_RANK,
    reasons: HEAD_AUTHORIZATION_REASONS,
    scope: {
      environmentId: context.environmentId,
      outOfScopeAtHead: "author-environment-out-of-scope-at-head",
    },
  });
}

function prevReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { context, predecessor } = input;
  if ((context.metaVersion === 1) !== (context.prevMetaSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  if (context.prevMetaSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (predecessor.status === "deleted") {
    return "revived-after-delete";
  }
  if (predecessor.status === "active" && context.status === "declared") {
    return "declared-after-active";
  }
  if (metaLayoutVersionOf(context) < predecessor.layoutVersion) {
    return "layout-regression";
  }
  return null;
}

export async function verifyDistributedMetaStatement(
  input: DistributedMetaStatementInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const rejection = metaContextRejection(input.context);
  if (rejection !== null) {
    return { ok: false, error: rejection };
  }
  const field = distributedInputInvalidField({
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    actorKeyFingerprintField: "authorKeyFingerprintHex",
    signatureHex: input.signatureHex,
    predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
  });
  if (field !== null) {
    return invalidInput(field);
  }

  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.authorUserId,
    actorKeyFingerprintHex: input.authorKeyFingerprintHex,
    onUnknown: { kind: "MetaStatementInvalid", reason: "author-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyMetaStatementSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    authorPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return metaInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return metaInvalid(chainReason);
  }

  const hash = await computeMetaSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
