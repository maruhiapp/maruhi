// 値署名のサーバー検証と (epoch, version) CAS(AUTH_SPEC §12-5 = CRYPTO_SPEC §4.1 / §6.4)。

import type {
  ChainHistoryIndex,
  ChainMember,
  ChainState,
  ValueInvalidReason,
  ValuePredecessor,
} from "@maruhi/crypto";
import { verifyDistributedValue } from "@maruhi/crypto";
import { Effect } from "effect";

import type {
  DataRejectedError,
  DataRejection,
  ValueInput,
  ValueSignatureRejectReason,
} from "./data-plane.ts";
import { currentEpochOf, rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";

/** 保存済みの値(epoch, version)に対する CAS(§12-5): 現エポック × 最新 + 1 のみ。 */
function checkValueCas(
  state: ChainState,
  environmentId: string,
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
  environmentId: string,
  latestVersion: number,
  value: ValueInput,
): Effect.Effect<void, DataRejectedError> => {
  const rejection = checkValueCas(state, environmentId, latestVersion, value);
  return rejection === null ? Effect.void : Effect.fail(rejectData(rejection));
};

/**
 * crypto の詳細理由 → ワイヤの 3 理由(仮裁定 C)への写像。
 * chain-head-future はサーバーにとって「自チェーンに存在しない seq」なので
 * chain-head-unknown に畳む(クライアント側の再同期分岐はサーバーには無い)。
 * 網羅は Record 型が静的に強制する(理由コード追加時にコンパイルエラー)。
 */
const VALUE_REJECT_REASONS: Readonly<Record<ValueInvalidReason, ValueSignatureRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "writer-unknown": "chain-head-state-mismatch",
  "writer-not-member-at-head": "chain-head-state-mismatch",
  "writer-key-mismatch-at-head": "chain-head-state-mismatch",
  "writer-role-insufficient-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "chain-head-state-mismatch",
  "epoch-not-current-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "epoch-regressed": "chain-head-state-mismatch",
};

/**
 * 値署名の受理検証(§12-5 の 1〜5)。判定順は CAS(epoch / version)の後・数量
 * ポリシーの前(session-14 裁定 D)。検査内容:
 *
 * 1. 署名は呼び出し主体の受理時点チェーン導出 sig 鍵で検証し、writer_user_id にも
 *    呼び出し主体を用いる(他人が署名した値の持ち込み拒否)
 * 2. 宣言ヘッド(hash + seq)の exact pair が自チェーン上に存在する
 * 3. 宣言ヘッド時点でも member 以上で、当時の束縛鍵 = 受理時点の鍵
 *    (remove → 別鍵 re-add の旧在籍区間ヘッド宣言の拒否)
 * 4. 宣言ヘッド時点で環境作成済みかつ current epoch = 値 epoch
 * 5. version 1 は prev 空、version > 1 は保存済み N-1 の signed-bytes hash と一致
 *
 * 座標(project / environment / variable)はサーバー側の値(genesis ハッシュ・
 * URL / 保存先)から再構成する — クライアント申告の AAD から組まない(§12-5)。
 * 宣言ヘッドは現ヘッドと同一でなくてよく、seq 単調性・サーバー独自のエポック
 * 単調比較も課さない(裁定 D — 「現エポックのみ受理 + rotate +1 + version CAS」の
 * 帰結として構造的に単調)。
 *
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す(保存行に書く)。
 * すべての crypto await はこの Effect 内で完了する(同期書き込みフェーズより前)。
 */
export const ensureValueSignature = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly value: ValueInput;
}) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    // predecessor(version > 1): 保存済み N-1 の signed_bytes ハッシュ。CAS 通過後
    // なので必ず存在する(欠落はストレージ / 実装バグ = defect)。version 1 は
    // predecessor なし — prev 空の形検査は verifyDistributedValue が行う
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
    const verified = yield* Effect.promise(() =>
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
          // writer = 呼び出し主体(§12-5 の 1)。検証鍵と head 時点の束縛一致は
          // FP(受理時点のチェーン導出メンバー)で verifyDistributedValue が検査
          writerUserId: input.member.userId,
          chainHeadHashHex: input.value.chainHeadHashHex,
          chainHeadSeq: input.value.chainHeadSeq,
        },
        writerKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.value.signatureHex,
        predecessor,
      }),
    );
    if (verified.ok) {
      return verified.value.signedBytesHashHex;
    }
    if (verified.error.kind === "ValueInvalid") {
      return yield* rejectData({
        kind: "value-rejected",
        reason: VALUE_REJECT_REASONS[verified.error.reason],
      });
    }
    // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済みチェーン
    // 由来の鍵では到達しない(実装バグ = defect。エラー値に秘密は含まれない)
    return yield* Effect.die(new Error(`value verification failed: ${verified.error.kind}`));
  });
