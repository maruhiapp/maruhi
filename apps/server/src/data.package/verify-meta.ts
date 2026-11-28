import type { EnvironmentId, ProjectId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  MetaInvalidReason,
  MetaPredecessor,
  MetaStatementTarget,
  MetaVariableSchema,
} from "@maruhi/crypto";
import { SUPPORTED_META_LAYOUT_VERSIONS, verifyDistributedMetaStatement } from "@maruhi/crypto";
import { Effect } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import { MAX_SCHEMA_DESCRIPTION_CODEPOINTS, MAX_VERSIONS_PER_VARIABLE } from "../policy.ts";
import type { MemberWithDevice } from "./data-guards.ts";
import type { MetaStatementInput, MetaStatementStatusInput } from "./data-plane.ts";
import type { DataRejectedError, MetaStatementRejectReason } from "./data-rejection.ts";
import { rejectData } from "./data-rejection.ts";
import type { MetaAnchor } from "./data-store.ts";
import { DataStore } from "./data-store.ts";

const META_REJECT_REASONS: Readonly<Record<MetaInvalidReason, MetaStatementRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "author-unknown": "chain-head-state-mismatch",
  "author-not-member-at-head": "chain-head-state-mismatch",
  "author-key-mismatch-at-head": "chain-head-state-mismatch",
  "author-role-insufficient-at-head": "chain-head-state-mismatch",
  "author-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "revived-after-delete": "chain-head-state-mismatch",
  "declared-after-active": "chain-head-state-mismatch",
  "layout-regression": "layout-regression",
};

function cryptoSchemaOf(statement: MetaStatementInput): MetaVariableSchema | undefined {
  if (statement.schema === undefined) {
    return undefined;
  }
  const maxAge = statement.schema.maxAgeDays ?? null;
  return {
    varType: statement.schema.varType,
    required: statement.schema.required ? "true" : "false",
    description: statement.schema.description,
    maxAgeDays: maxAge === null ? "" : String(maxAge),
  };
}

const ensureLayoutShape = (statement: MetaStatementInput): Effect.Effect<void, DataRejectedError> =>
  statementLayoutVersion(statement) !== 3 || statement.schema?.maxAgeDays !== undefined
    ? Effect.void
    : Effect.fail(rejectData({ kind: "payload-mismatch", field: "maxAgeDays" }));

export const ensureMetaStatementSignature = Effect.fn("verify-meta.ensureMetaStatementSignature")(
  function* (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly target: MetaStatementTarget;
    readonly history: ChainHistoryIndex;
    readonly member: MemberWithDevice;
    readonly statement: MetaStatementInput;
    readonly predecessor?: MetaPredecessor | undefined;
  }) {
    yield* ensureLayoutShape(input.statement);
    const verified = yield* catchCryptoErrors(
      cryptoEffect(() =>
        verifyDistributedMetaStatement({
          history: input.history,
          context: {
            suite: input.statement.suite,
            projectId: input.projectId,
            environmentId: input.environmentId,
            target: input.target,
            name: input.statement.name,
            status: input.statement.status,
            layoutVersion: input.statement.layoutVersion,
            schema: cryptoSchemaOf(input.statement),
            metaVersion: input.statement.metaVersion,
            prevMetaSigHashHex: input.statement.prevMetaSigHashHex,
            authorUserId: input.member.userId,
            chainHeadHashHex: input.statement.chainHeadHashHex,
            chainHeadSeq: input.statement.chainHeadSeq,
          },
          authorKeyFingerprintHex: input.member.keyFingerprintHex,
          signatureHex: input.statement.signatureHex,
          predecessor: input.predecessor,
        }),
      ),
      {
        CryptoMetaStatementInvalid: (error) =>
          rejectData({
            kind: "meta-rejected",
            reason: META_REJECT_REASONS[error.reason],
          }),
        CryptoUnsupportedMetaLayout: () =>
          rejectData({ kind: "meta-rejected", reason: "unsupported-layout" }),
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
        CryptoEnvManifestInvalid: "die",
        CryptoHeadAttestationInvalid: "die",
        ChainInvalid: "die",
      },
    );
    return verified.signedBytesHashHex;
  },
);

export const ensureNfcName = (name: string): Effect.Effect<void, DataRejectedError> =>
  name.normalize("NFC") === name ? Effect.void : Effect.fail(rejectData({ kind: "name-not-nfc" }));

export const statementLayoutVersion = (statement: MetaStatementInput): number =>
  statement.layoutVersion ?? 1;

export const ensureSupportedLayout = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  SUPPORTED_META_LAYOUT_VERSIONS.includes(statementLayoutVersion(statement))
    ? Effect.void
    : Effect.fail(rejectData({ kind: "meta-rejected", reason: "unsupported-layout" }));

export const ensureDescriptionPolicy = (
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> => {
  if (statement.schema === undefined) {
    return Effect.void;
  }
  const description = statement.schema.description;
  if (/\p{Cc}/u.test(description)) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "control-characters" }));
  }
  if ([...description].length > MAX_SCHEMA_DESCRIPTION_CODEPOINTS) {
    return Effect.fail(rejectData({ kind: "description-rejected", reason: "too-long" }));
  }
  return Effect.void;
};

export type MetaOperation = "reissue" | "activate" | "delete";

function deletePreservationMismatch(
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  if (statement.name !== anchor.name) {
    return "name";
  }
  if (statementLayoutVersion(statement) !== anchor.layoutVersion) {
    return "layoutVersion";
  }
  if (anchor.schema === null || statement.schema === undefined) {
    return null;
  }
  const stored = anchor.schema;
  const declared = statement.schema;
  const comparisons: readonly (readonly [string, boolean])[] = [
    ["varType", declared.varType === stored.varType],
    ["required", declared.required === stored.required],
    ["description", declared.description === stored.description],
    ["maxAgeDays", (declared.maxAgeDays ?? null) === (stored.maxAgeDays ?? null)],
  ];
  return comparisons.find(([, same]) => !same)?.[0] ?? null;
}

function predecessorMismatch(
  operation: MetaOperation,
  anchor: MetaAnchor,
  statement: MetaStatementInput,
): string | null {
  switch (operation) {
    case "reissue":
      return statement.status === anchor.status ? null : "status";
    case "activate":
      if (anchor.status !== "declared") {
        return "status";
      }
      return statement.name === anchor.name ? null : "name";
    case "delete":
      return deletePreservationMismatch(anchor, statement);
  }
}

export const ensureMetaCas = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statement.metaVersion === latestMetaVersion + 1
    ? Effect.void
    : Effect.fail(
        rejectData({ kind: "meta-version-conflict", currentMetaVersion: latestMetaVersion }),
      );

export function metaVersionsExceeded(
  latestMetaVersion: number,
  status: MetaStatementStatusInput,
): boolean {
  return status !== "deleted" && latestMetaVersion + 1 > MAX_VERSIONS_PER_VARIABLE;
}

const ensureMetaQuota = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  metaVersionsExceeded(latestMetaVersion, statement.status)
    ? Effect.fail(
        rejectData({
          kind: "limit-exceeded",
          resource: "meta-versions",
          limit: MAX_VERSIONS_PER_VARIABLE,
        }),
      )
    : Effect.void;

export const acceptMetaStatement = Effect.fn("verify-meta.acceptMetaStatement")(function* (input: {
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly target: MetaStatementTarget;
  readonly operation: MetaOperation;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: MemberWithDevice;
  readonly statement: MetaStatementInput;
}) {
  yield* ensureSupportedLayout(input.statement);
  yield* ensureMetaQuota(input.latestMetaVersion, input.statement);
  yield* ensureMetaCas(input.latestMetaVersion, input.statement);
  const store = yield* DataStore;
  const anchor =
    input.target.kind === "variable"
      ? yield* store.variableMetaAnchor(
          input.environmentId,
          input.target.variableId,
          input.latestMetaVersion,
        )
      : yield* store.environmentMetaAnchor(input.environmentId, input.latestMetaVersion);
  if (anchor === null) {
    return yield* Effect.die(new Error("meta predecessor row missing after CAS acceptance"));
  }
  const mismatched = predecessorMismatch(input.operation, anchor, input.statement);
  if (mismatched !== null) {
    return yield* rejectData({ kind: "payload-mismatch", field: mismatched });
  }
  if (input.operation !== "delete") {
    yield* ensureDescriptionPolicy(input.statement);
  }
  return yield* ensureMetaStatementSignature({
    projectId: input.projectId,
    environmentId: input.environmentId,
    target: input.target,
    history: input.history,
    member: input.member,
    statement: input.statement,
    predecessor: {
      signedBytesHashHex: anchor.signedBytesHashHex,
      status: anchor.status,
      layoutVersion: anchor.layoutVersion,
    },
  });
});
