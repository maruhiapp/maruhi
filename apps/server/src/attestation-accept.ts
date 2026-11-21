import type { UserId } from "@maruhi/core";
import { cryptoEffect } from "@maruhi/core";
import type { AttestationInvalidReason } from "@maruhi/crypto";
import { verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { catchCryptoErrors } from "./crypto-catch.ts";
import type { AttestationRejectReason, DataRejectedError } from "./data.package/index.ts";
import {
  DataStore,
  rejectData,
  requireMemberState,
  withSigningDevice,
} from "./data.package/index.ts";
import type { ChainStore, StateCache } from "./do/chain-store.ts";
import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "./policy.ts";

export interface HeadAttestationSubmissionInput {
  readonly suite: "maruhi/v1";
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

const ATTESTATION_REJECT_REASONS: Readonly<
  Record<AttestationInvalidReason, AttestationRejectReason>
> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "attester-unknown": "chain-head-state-mismatch",
  "attester-not-member-at-head": "chain-head-state-mismatch",
  "attester-key-mismatch-at-head": "chain-head-state-mismatch",
};

export const putHeadAttestationProgram = Effect.fn("attestation-accept.putHeadAttestationProgram")(
  function* (
    callerUserId: UserId,
    input: HeadAttestationSubmissionInput,
    cache: StateCache,
  ): Effect.fn.Return<void, DataRejectedError, DataStore | ChainStore> {
    const context = yield* requireMemberState(callerUserId, "reader", cache);
    const store = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;

    const window = yield* store.checkAttestationWindow(
      callerUserId,
      MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW,
      nowMs,
    );
    if (!window.allowed) {
      return yield* rejectData({
        kind: "attestation-rate-limited",
        retryAfterSeconds: window.retryAfterSeconds,
      });
    }
    store.recordAttestationWindowUse(callerUserId, nowMs);

    const { device: attester } = yield* withSigningDevice(context.member, (candidate) =>
      catchCryptoErrors(
        cryptoEffect(() =>
          verifyDistributedHeadAttestation({
            history: context.history,
            context: {
              suite: input.suite,
              projectId: context.projectId,
              attesterUserId: candidate.userId,
              chainHeadHashHex: input.chainHeadHashHex,
              chainHeadSeq: input.chainHeadSeq,
            },
            attesterKeyFingerprintHex: candidate.keyFingerprintHex,
            signatureHex: input.signatureHex,
          }),
        ),
        {
          CryptoHeadAttestationInvalid: (error) =>
            rejectData({
              kind: "attestation-rejected",
              reason: ATTESTATION_REJECT_REASONS[error.reason],
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
          CryptoEnvManifestInvalid: "die",
          ChainInvalid: "die",
        },
      ),
    );

    const storedSeq = yield* store.headAttestationSeq(callerUserId, attester.keyFingerprintHex);
    if (storedSeq !== null && input.chainHeadSeq < storedSeq) {
      return yield* rejectData({ kind: "attestation-regression", storedSeq });
    }
    if (storedSeq !== null && input.chainHeadSeq === storedSeq) {
      return;
    }
    yield* Effect.sync(() =>
      store.write.upsertHeadAttestation(
        {
          attesterUserId: attester.userId,
          suite: input.suite,
          chainHeadSeq: input.chainHeadSeq,
          chainHeadHashHex: input.chainHeadHashHex,
          signatureHex: input.signatureHex,
          attesterKeyFingerprintHex: attester.keyFingerprintHex,
        },
        nowMs,
      ),
    );
  },
);
