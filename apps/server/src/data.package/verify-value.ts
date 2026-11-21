import type { EnvironmentId, ProjectId, VariableId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  ChainState,
  ValueInvalidReason,
  ValuePredecessor,
} from "@maruhi/crypto";
import { verifyDistributedValue } from "@maruhi/crypto";
import { Effect } from "effect";

import { catchCryptoErrors } from "../crypto-catch.ts";
import type { MemberWithDevice } from "./data-guards.ts";
import { currentEpochOf } from "./data-guards.ts";
import type { ValueInput } from "./data-plane.ts";
import type {
  DataRejectedError,
  DataRejection,
  ValueSignatureRejectReason,
} from "./data-rejection.ts";
import { rejectData } from "./data-rejection.ts";
import { DataStore } from "./data-store.ts";

function checkValueCas(
  state: ChainState,
  environmentId: EnvironmentId,
  latestVersion: number,
  value: ValueInput,
): DataRejection | null {
  const currentEpoch = currentEpochOf(state, environmentId);
  if (value.epoch !== currentEpoch) {
    return { kind: "epoch-conflict", currentEpoch };
  }
  if (value.version !== latestVersion + 1) {
    return { kind: "version-conflict", currentVersion: latestVersion };
  }
  return null;
}

export const ensureValueCas = (
  state: ChainState,
  environmentId: EnvironmentId,
  latestVersion: number,
  value: ValueInput,
): Effect.Effect<void, DataRejectedError> => {
  const rejection = checkValueCas(state, environmentId, latestVersion, value);
  return rejection === null ? Effect.void : Effect.fail(rejectData(rejection));
};

const VALUE_REJECT_REASONS: Readonly<Record<ValueInvalidReason, ValueSignatureRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "writer-unknown": "chain-head-state-mismatch",
  "writer-not-member-at-head": "chain-head-state-mismatch",
  "writer-key-mismatch-at-head": "chain-head-state-mismatch",
  "writer-role-insufficient-at-head": "chain-head-state-mismatch",
  "writer-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "chain-head-state-mismatch",
  "epoch-not-current-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "epoch-regressed": "chain-head-state-mismatch",
};

export const ensureValueSignature = Effect.fn("verify-value.ensureValueSignature")(
  function* (input: {
    readonly projectId: ProjectId;
    readonly environmentId: EnvironmentId;
    readonly variableId: VariableId;
    readonly history: ChainHistoryIndex;
    readonly member: MemberWithDevice;
    readonly value: ValueInput;
  }) {
    const store = yield* DataStore;
    let predecessor: ValuePredecessor | undefined;
    if (input.value.version > 1) {
      const anchor = yield* store.versionAnchor(
        input.environmentId,
        input.variableId,
        input.value.version - 1,
      );
      if (anchor === null) {
        return yield* Effect.die(new Error("predecessor version row missing after CAS acceptance"));
      }
      predecessor = anchor;
    }
    const verified = yield* catchCryptoErrors(
      cryptoEffect(() =>
        verifyDistributedValue({
          history: input.history,
          context: {
            suite: input.value.suite,
            projectId: input.projectId,
            environmentId: input.environmentId,
            epoch: input.value.epoch,
            variableId: input.variableId,
            version: input.value.version,
            nonceHex: input.value.nonceHex,
            ciphertextHex: input.value.ciphertextHex,
            prevValueSigHashHex: input.value.prevValueSigHashHex,
            writerUserId: input.member.userId,
            chainHeadHashHex: input.value.chainHeadHashHex,
            chainHeadSeq: input.value.chainHeadSeq,
          },
          writerKeyFingerprintHex: input.member.keyFingerprintHex,
          signatureHex: input.value.signatureHex,
          predecessor,
        }),
      ),
      {
        CryptoValueInvalid: (error) =>
          rejectData({
            kind: "value-rejected",
            reason: VALUE_REJECT_REASONS[error.reason],
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
        CryptoMetaStatementInvalid: "die",
        CryptoUnsupportedMetaLayout: "die",
        CryptoEnvManifestInvalid: "die",
        CryptoHeadAttestationInvalid: "die",
        ChainInvalid: "die",
      },
    );
    return verified.signedBytesHashHex;
  },
);
