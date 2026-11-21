import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  EnvManifestEnvMeta,
  ManifestInvalidReason,
  VariablesDigestEntry,
} from "@maruhi/crypto";
import { verifyDistributedEnvManifest } from "@maruhi/crypto";
import { Effect } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import type { MemberWithDevice } from "./data-guards.ts";
import type { EnvManifestInput } from "./data-plane.ts";
import type { ManifestRejectReason } from "./data-rejection.ts";
import { rejectData } from "./data-rejection.ts";
import { DataStore } from "./data-store.ts";

const MANIFEST_REJECT_REASONS: Readonly<Record<ManifestInvalidReason, ManifestRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "issuer-unknown": "chain-head-state-mismatch",
  "issuer-not-member-at-head": "chain-head-state-mismatch",
  "issuer-key-mismatch-at-head": "chain-head-state-mismatch",
  "issuer-role-insufficient-at-head": "chain-head-state-mismatch",
  "issuer-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "manifest-epoch-mismatch",
  "epoch-not-current-at-head": "manifest-epoch-mismatch",
  "epoch-regressed": "manifest-epoch-mismatch",
  "env-meta-mismatch": "manifest-digest-mismatch",
  "variables-digest-mismatch": "manifest-digest-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "checkpoint-binding-mismatch": "checkpoint-binding-mismatch",
  "checkpoint-equivocation": "checkpoint-equivocation",
  "checkpoint-regressed": "checkpoint-regressed",
};

export const manifestDigestEntries = Effect.fn("verify-manifest.manifestDigestEntries")(function* (
  environmentId: EnvironmentId,
  override: {
    readonly variableId: VariableId;
    readonly status: "active" | "deleted" | "declared";
    readonly metaVersion: number;
    readonly signedBytesHashHex: string;
  } | null,
) {
  const store = yield* DataStore;
  const stored = yield* store.variableDigestEntries(environmentId);
  if (override === null) {
    return stored;
  }
  const entry: VariablesDigestEntry = {
    variableId: override.variableId,
    status: override.status,
    metaVersion: override.metaVersion,
    metaSigHashHex: override.signedBytesHashHex,
  };
  const rest = stored.filter((candidate) => candidate.variableId !== override.variableId);
  return [...rest, entry];
});

export const storedEnvMeta = Effect.fn("verify-manifest.storedEnvMeta")(function* (
  environmentId: EnvironmentId,
) {
  const store = yield* DataStore;
  const environment = yield* store.findEnvironment(environmentId);
  if (environment === null) {
    return yield* Effect.die(new Error("environment row missing for manifest acceptance"));
  }
  const anchor = yield* store.environmentMetaAnchor(environmentId, environment.latestMetaVersion);
  if (anchor === null) {
    return yield* Effect.die(new Error("environment meta statement row missing"));
  }
  return { metaVersion: environment.latestMetaVersion, sigHashHex: anchor.signedBytesHashHex };
});

export const acceptManifestForMetaOp = Effect.fn("verify-manifest.acceptManifestForMetaOp")(
  function* (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly history: ChainHistoryIndex;
    readonly member: MemberWithDevice;
    readonly manifest: EnvManifestInput;
    readonly digestOverride: {
      readonly variableId: VariableId;
      readonly status: "active" | "deleted" | "declared";
      readonly metaVersion: number;
      readonly signedBytesHashHex: string;
    } | null;
    readonly envMeta?: EnvManifestEnvMeta;
  }) {
    const signedBytesHashHex = yield* acceptEnvManifest({
      projectId: input.projectId,
      environmentId: input.environmentId,
      history: input.history,
      member: input.member,
      manifest: input.manifest,
      entries: yield* manifestDigestEntries(input.environmentId, input.digestOverride),
      envMeta: input.envMeta ?? (yield* storedEnvMeta(input.environmentId)),
    });
    const store = yield* DataStore;
    return {
      writeSync: (nowMs: number): void => {
        store.write.upsertEnvironmentManifest(
          input.environmentId,
          input.manifest,
          signedBytesHashHex,
          { userId: input.member.userId, keyFingerprintHex: input.member.keyFingerprintHex },
          nowMs,
        );
      },
    };
  },
);

interface AcceptEnvManifestInput {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly manifest: EnvManifestInput;
  readonly entries: readonly VariablesDigestEntry[];
  readonly envMeta: EnvManifestEnvMeta;
}

const verifyManifestCryptographically = (
  input: AcceptEnvManifestInput,
  predecessor: { readonly signedBytesHashHex: string; readonly epoch: number } | undefined,
) =>
  Effect.map(
    catchCryptoErrors(
      cryptoEffect(() =>
        verifyDistributedEnvManifest({
          history: input.history,
          context: {
            suite: input.manifest.suite,
            projectId: input.projectId,
            environmentId: input.environmentId,
            epoch: input.manifest.epoch,
            manifestVersion: input.manifest.manifestVersion,
            variablesDigestHex: input.manifest.variablesDigestHex,
            envMetaVersion: input.manifest.envMetaVersion,
            envMetaSigHashHex: input.manifest.envMetaSigHashHex,
            prevManifestSigHashHex: input.manifest.prevManifestSigHashHex,
            issuerUserId: input.member.userId,
            chainHeadHashHex: input.manifest.chainHeadHashHex,
            chainHeadSeq: input.manifest.chainHeadSeq,
          },
          issuerKeyFingerprintHex: input.member.keyFingerprintHex,
          signatureHex: input.manifest.signatureHex,
          entries: input.entries,
          envMeta: input.envMeta,
          predecessor,
        }),
      ),
      {
        CryptoEnvManifestInvalid: (error) =>
          rejectData({
            kind: "manifest-rejected",
            reason: MANIFEST_REJECT_REASONS[error.reason],
          }),
        CryptoInvalidInput: "die",
        CryptoKeyImport: "die",
        CryptoKeyExport: "die",
        CryptoEncrypt: "die",
        CryptoDecrypt: "die",
        CryptoDekWrap: "die",
        CryptoDekUnwrap: "die",
        CryptoSign: "die",
        CryptoDekWrapSignature: "die",
        CryptoInviteAcceptSignature: "die",
        CryptoInviteLinkSignature: "die",
        CryptoInviteIssueSignature: "die",
        CryptoDekCommitment: "die",
        CryptoValueInvalid: "die",
        CryptoMetaStatementInvalid: "die",
        CryptoUnsupportedMetaLayout: "die",
        CryptoHeadAttestationInvalid: "die",
        ChainInvalid: "die",
      },
    ),
    (verified) => verified.signedBytesHashHex,
  );

export const acceptEnvManifest = Effect.fn("verify-manifest.acceptEnvManifest")(function* (
  input: AcceptEnvManifestInput,
) {
  const store = yield* DataStore;
  const anchor = yield* store.environmentManifestAnchor(input.environmentId);
  if (anchor === null) {
    return yield* Effect.die(new Error("environment manifest row missing"));
  }
  if (input.manifest.manifestVersion !== anchor.manifestVersion + 1) {
    return yield* rejectData({
      kind: "manifest-version-conflict",
      currentManifestVersion: anchor.manifestVersion,
    });
  }
  return yield* verifyManifestCryptographically(input, {
    signedBytesHashHex: anchor.signedBytesHashHex,
    epoch: anchor.epoch,
  });
});

export const acceptEnvManifestForCreation = Effect.fn(
  "verify-manifest.acceptEnvManifestForCreation",
)(function* (input: AcceptEnvManifestInput) {
  const store = yield* DataStore;
  const anchor = yield* store.environmentManifestAnchor(input.environmentId);
  if (anchor !== null) {
    return yield* Effect.die(
      new Error("environment manifest row already stored at creation acceptance"),
    );
  }
  return yield* verifyManifestCryptographically(input, undefined);
});
