// Server-side verification of value signatures and the (epoch,
// version) CAS (AUTH_SPEC §12-5 = CRYPTO_SPEC §4.1 / §6.4).

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
import type {
  DataRejectedError,
  DataRejection,
  MemberWithDevice,
  ValueInput,
  ValueSignatureRejectReason,
} from "./data-plane.ts";
import { currentEpochOf, rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";

/** The CAS against the stored value's (epoch, version) (§12-5): only the current epoch × latest + 1. */
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

/**
 * Mapping of crypto's detailed reasons → the wire's 3 reasons
 * (interim ruling C).
 * chain-head-future is, for the server, "a seq that does not exist
 * on its own chain", so it folds into chain-head-unknown (the
 * client-side resync branch does not exist on the server).
 * Exhaustiveness is statically enforced by the Record type (adding a
 * reason code would be a compile error).
 */
const VALUE_REJECT_REASONS: Readonly<Record<ValueInvalidReason, ValueSignatureRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "writer-unknown": "chain-head-state-mismatch",
  "writer-not-member-at-head": "chain-head-state-mismatch",
  "writer-key-mismatch-at-head": "chain-head-state-mismatch",
  "writer-role-insufficient-at-head": "chain-head-state-mismatch",
  // §6.3's 3′ (2026-09-14 ES): the writer is out of scope at the
  // declared head — same "mismatch with the state at the head" class
  // as role insufficiency (a 403 on the caller's scope axis is K3)
  "writer-environment-out-of-scope-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "chain-head-state-mismatch",
  "epoch-not-current-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "epoch-regressed": "chain-head-state-mismatch",
};

/**
 * Acceptance verification of a value signature (§12-5's 1–5). The
 * check order is after the CAS (epoch / version) and before the
 * quantity policy (session-14 ruling D). What is checked:
 *
 * 1. The signature is verified with the caller's chain-derived sig
 *    key at acceptance time, and writer_user_id is also the caller
 *    (refuses values signed by someone else being brought in)
 * 2. The declared head's (hash + seq) exact pair exists on the
 *    server's own chain
 * 3. The writer was member-or-above at the declared head, and the
 *    bound key then = the key at acceptance (refusing a head declared
 *    inside a stale membership interval after remove → re-add with a
 *    different key)
 * 4. At the declared head the environment was already created and
 *    current epoch = the value's epoch
 * 5. version 1 has an empty prev; version > 1 matches the stored
 *    N-1's signed-bytes hash
 *
 * The coordinates (project / environment / variable) are
 * reconstructed from server-side values (the genesis hash, the URL,
 * the storage destination) — not assembled from client-declared AAD
 * (§12-5). The declared head need not equal the current head; no seq
 * monotonicity or server-side epoch comparison is imposed either
 * (ruling D — structurally monotonic as a consequence of "accept the
 * current epoch only + rotate +1 + version CAS").
 *
 * On success returns the server-recomputed signed_bytes hash (which
 * is written to the stored row).
 * All crypto awaits complete inside this Effect (before the
 * synchronous write phase).
 */
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
    // predecessor (version > 1): the stored N-1's signed_bytes hash.
    // Post-CAS, so it always exists (absence = a storage /
    // implementation bug = defect). version 1 has no predecessor —
    // the shape check that prev is empty is done by
    // verifyDistributedValue
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
            // writer = the caller (§12-5's 1). The verification key
            // and the bound-key match at head time are checked by
            // verifyDistributedValue via the FP (the chain-derived
            // member at acceptance time)
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
        // Every other kind is unreachable (InvalidInput / KeyImportFailed
        // with a Schema-validated wire shape + keys derived from a
        // verified chain; the rest are never returned by this
        // operation): an implementation bug = defect; error values carry
        // no secrets
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
