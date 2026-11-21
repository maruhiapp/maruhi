import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ManifestInvalidReason } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  buildEnvManifestSignedBytes,
  computeVariablesDigest,
  type EnvManifestContext,
  manifestContextInvalidField,
  type VariablesDigestEntry,
  verifyEnvManifestSignature,
} from "./manifest-sign.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";

export interface EnvManifestPredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

export interface EnvManifestEnvMeta {
  readonly metaVersion: number;
  readonly sigHashHex: string;
}

export interface DistributedEnvManifestInput {
  readonly history: ChainHistoryIndex;
  readonly context: EnvManifestContext;
  readonly issuerKeyFingerprintHex: string;
  readonly signatureHex: string;
  readonly entries: readonly VariablesDigestEntry[];
  readonly envMeta: EnvManifestEnvMeta;
  readonly predecessor?: EnvManifestPredecessor | undefined;
}

function manifestInvalid(reason: ManifestInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason };
} {
  return { ok: false, error: { kind: "EnvManifestInvalid", reason } };
}

const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "issuer-not-member-at-head",
  keyMismatchAtHead: "issuer-key-mismatch-at-head",
  roleInsufficientAtHead: "issuer-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<ManifestInvalidReason>;

function epochIntegrityReason(
  input: DistributedEnvManifestInput,
  signedBytesHashHex: string,
): ManifestInvalidReason | null {
  const { history, context } = input;
  const tuple = history.checkpointTupleFor(context.environmentId, context.manifestVersion);
  if (tuple !== undefined) {
    if (tuple.kind === "conflicting") {
      return "checkpoint-equivocation";
    }
    return tuple.epoch === context.epoch && tuple.manifestSigHashHex === signedBytesHashHex
      ? null
      : "checkpoint-binding-mismatch";
  }
  const atHead = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (atHead === undefined) {
    return "environment-not-created-at-head";
  }
  return atHead.currentEpoch === context.epoch ? null : "epoch-not-current-at-head";
}

function checkpointIntegrityReason(
  input: DistributedEnvManifestInput,
): ManifestInvalidReason | null {
  const baseline = input.history.latestCheckpointFor(input.context.environmentId);
  if (baseline === undefined) {
    return null;
  }
  if (
    input.context.manifestVersion < baseline.manifestVersion ||
    input.context.epoch < baseline.epoch
  ) {
    return "checkpoint-regressed";
  }
  return null;
}

async function contentReason(
  input: DistributedEnvManifestInput,
): Promise<ManifestInvalidReason | null> {
  const { context } = input;
  if (
    context.envMetaVersion !== input.envMeta.metaVersion ||
    context.envMetaSigHashHex !== input.envMeta.sigHashHex
  ) {
    return "env-meta-mismatch";
  }
  const digest = await computeVariablesDigest(context.suite, input.entries);
  if (!digest.ok) {
    return "variables-digest-mismatch";
  }
  return digest.value === context.variablesDigestHex ? null : "variables-digest-mismatch";
}

function prevReason(input: DistributedEnvManifestInput): ManifestInvalidReason | null {
  const { context, predecessor } = input;
  if ((context.manifestVersion === 1) !== (context.prevManifestSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  if (context.prevManifestSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

export async function verifyDistributedEnvManifest(
  input: DistributedEnvManifestInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    manifestContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
      actorKeyFingerprintField: "issuerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    onUnknown: { kind: "EnvManifestInvalid", reason: "issuer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyEnvManifestSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    issuerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headAuthorizationReason<ManifestInvalidReason>({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
    scope: {
      environmentId: input.context.environmentId,
      outOfScopeAtHead: "issuer-environment-out-of-scope-at-head",
    },
  });
  if (headReason !== null) {
    return manifestInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return manifestInvalid(chainReason);
  }
  const signedBytesHashHex = encodeHex(await sha256(buildEnvManifestSignedBytes(input.context)));
  const epochReason = epochIntegrityReason(input, signedBytesHashHex);
  if (epochReason !== null) {
    return manifestInvalid(epochReason);
  }
  const digestReason = await contentReason(input);
  if (digestReason !== null) {
    return manifestInvalid(digestReason);
  }
  const checkpointReason = checkpointIntegrityReason(input);
  if (checkpointReason !== null) {
    return manifestInvalid(checkpointReason);
  }
  return { ok: true, value: { signedBytesHashHex } };
}
