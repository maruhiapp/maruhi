// Acceptance of head attestations (CRYPTO_SPEC §6.4 / §6.6, AUTH_SPEC §16-1).
//
// Order of acceptance checks:
//   1. Membership (reader or higher — non-members get not-member → worker
//      returns 404. The caller = attester is structural (the wire has no
//      attester field; the signed attester_user_id is the caller — the §12-5
//      rule))
//   2. Fixed-window rate limit per member (§16-1 drafted value 60/hour.
//      Checked after membership = a 429 does not leak existence to
//      non-members. Consumption is independent of acceptance — placed before
//      signature verification so Ed25519 work is bounded by rate)
//   3. §6.6 verification (signature = the current member's sig key at
//      acceptance time, declared head exists, membership and key binding at
//      the declared head). The implementation applies the same
//      verifyDistributedHeadAttestation as the client to the acceptance-time
//      history index — distributed material is only ever stored in a form
//      that passes client verification (§6.6) (the §6.4 pair: the server does
//      not store data clients would universally reject). The "membership at
//      the declared head" check, absent from the spec's acceptance
//      enumeration (§6.4), is a consequence of this sharing, and an honest
//      client's attestation (a head it synced and verified as a member ≥ its
//      own add position) always satisfies it
//   4. Monotonic seq advance over the stored attestation: regression = 409
//      (returns the stored seq — never silently succeed; regression by an
//      honest client is a symptom of a broken floor or concurrent CLIs and is
//      not quietly swallowed), same seq = idempotent 204 (the signature is
//      deterministic and head-match verified = a resend of identical
//      content; retry-safe), advance = upsert
//
// Storage is the latest single row per device (2026-09-19 DK; not put on the
// chain — §6.4). The acceptance time is stored but not distributed (§16-1).
// It is also not turned into an audit event (§16-3).

import { cryptoEffect } from "@maruhi/core";
import type { AttestationInvalidReason } from "@maruhi/crypto";
import { verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Clock, Effect } from "effect";

import { catchCryptoErrors } from "./crypto-catch.ts";
import type { AttestationRejectReason, DataRejectedError } from "./data/data-plane.ts";
import { rejectData, requireMemberState, withSigningDevice } from "./data/data-plane.ts";
import { DataStore } from "./data/data-store.ts";
import type { ChainStore, StateCache } from "./do/chain-store.ts";
import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "./policy.ts";

/** Wire submission content (attester is the caller — same shape as api-schema's submission). */
export interface HeadAttestationSubmissionInput {
  readonly suite: "maruhi/v1";
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/**
 * Mapping of crypto's detailed reasons onto the wire's 3 reasons (the same
 * folding as VALUE_REJECT_REASONS in verify-value.ts). chain-head-future is,
 * to the server, "a seq that does not exist on our chain", so it folds into
 * chain-head-unknown. Exhaustiveness is statically enforced by the Record
 * type.
 */
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

/**
 * Acceptance program for PUT /projects/:projectId/head-attestation (runs
 * under the DO's permit — no interruption between the decision and the
 * store). Success is void (204).
 */
export const putHeadAttestationProgram = Effect.fn("attestation-accept.putHeadAttestationProgram")(
  function* (
    callerUserId: string,
    input: HeadAttestationSubmissionInput,
    cache: StateCache,
  ): Effect.fn.Return<void, DataRejectedError, DataStore | ChainStore> {
    // 1. Membership (reader or higher — §16-1's "chain role reader or higher")
    const context = yield* requireMemberState(callerUserId, "reader", cache);
    const store = yield* DataStore;
    const nowMs = yield* Clock.currentTimeMillis;

    // 2. Fixed window per member (check → consume immediately: repeated rejected submissions also use the window)
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

    // 3. §6.6 verification (applies the same implementation as the client to
    //    the acceptance-time history index. project_id is taken from the DO's
    //    own chain (genesis hash) — the §12-5 coordinate-reconstruction
    //    invariant; not assembled from declared values). The attesting device
    //    is resolved from the signature (tries the caller's valid devices —
    //    design record §8 K3-1. The attester's key = the signing device's
    //    device key — CRYPTO_SPEC §6.6)
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
          // Every other kind is unreachable (InvalidInput /
          // KeyImportFailed with a Schema-validated wire + a key derived
          // from a verified chain; the rest are never returned by this
          // operation): implementation bug = defect. No secrets included
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

    // 4. Monotonic seq advance (regression 409 / same seq idempotent 204 /
    //    advance upsert) — only against the same device's stored row (no
    //    cross-device monotonicity imposed — AUTH_SPEC §16-1)
    const storedSeq = yield* store.headAttestationSeq(callerUserId, attester.keyFingerprintHex);
    if (storedSeq !== null && input.chainHeadSeq < storedSeq) {
      return yield* rejectData({ kind: "attestation-regression", storedSeq });
    }
    if (storedSeq !== null && input.chainHeadSeq === storedSeq) {
      // The same seq that passed the head-existence match (step 3) has the
      // same hash, and deterministic Ed25519 gives the same signature = a
      // resend of identical content. Idempotent success without rewriting
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
