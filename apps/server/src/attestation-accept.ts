// ヘッド申告の受理(CRYPTO_SPEC §6.4 / §6.6、AUTH_SPEC §16-1 — 2026-08-28 PR-M4)。
//
// 受理検証の判定順:
//   1. メンバーシップ(reader 以上 — 非メンバーは not-member → worker が 404。
//      呼び出し主体 = attester は構造的(ワイヤに attester フィールドがなく、
//      署名対象の attester_user_id に呼び出し主体を用いる — §12-5 の規則))
//   2. メンバーあたり固定窓レート制限(§16-1 起草値 60/時。判定はメンバーシップの
//      後 = 429 が非メンバーへ存在を漏らさない。消費は受理可否に依らない —
//      Ed25519 検証の作業量をレートで有界にするため署名検証より前に置く)
//   3. §6.6 検証(署名 = 受理時点の現メンバーの sig 鍵・申告ヘッドの実在一致・
//      申告ヘッド時点の在籍と鍵束縛)。実装はクライアントと同一の
//      verifyDistributedHeadAttestation を受理時点の履歴索引へ適用する —
//      配布物は必ずクライアント検証(§6.6)を通る形しか保存しない(§6.4 の
//      両輪: クライアントが全拒否するデータをサーバーが保存しない)。仕様の
//      受理列挙(§6.4)にない「申告ヘッド時点の在籍」検査が加わるのはこの
//      共有の帰結で、正直なクライアントの申告(自分がメンバーとして同期・
//      検証したヘッド ≥ 自分の add 位置)は常に満たす
//   4. 保存済み申告からの seq 単調前進: 後退 = 409(保存済み seq を返す —
//      黙って成功させない。正直なクライアントの後退は床の破損・並行 CLI の
//      徴候であり静かに握り潰さない)、同一 seq = 冪等 204(署名は決定論的で
//      ヘッド一致検査済み = 同一内容の再送。リトライ安全)、前進 = upsert
//
// 保存はメンバーごと最新 1 行(チェーンに載せない — §6.4)。受理時刻は保存する
// が配布しない(§16-1)。監査イベント化もしない(§16-3)。

import type { AttestationInvalidReason } from "@maruhi/crypto";
import { verifyDistributedHeadAttestation } from "@maruhi/crypto";
import { Effect } from "effect";

import type { ChainStore, StateCache } from "./chain-store.ts";
import type { AttestationRejectReason, DataRejectedError } from "./data-plane.ts";
import { rejectData, requireMemberState } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { MAX_ATTESTATIONS_PER_MEMBER_PER_WINDOW } from "./policy.ts";

/** ワイヤの提出内容(attester は呼び出し主体 — api-schema の submission と同形)。 */
export interface HeadAttestationSubmissionInput {
  readonly suite: "maruhi/v1";
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

/**
 * crypto の詳細理由 → ワイヤの 3 理由への写像(verify-value.ts の
 * VALUE_REJECT_REASONS と同じ畳み方)。chain-head-future はサーバーにとって
 * 「自チェーンに存在しない seq」なので chain-head-unknown に畳む。
 * 網羅は Record 型が静的に強制する。
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
 * PUT /projects/:projectId/head-attestation の受理プログラム(DO の permit 下で
 * 実行 — 判定と保存の間に割り込みはない)。成功は void(204)。
 */
export const putHeadAttestationProgram = (
  callerUserId: string,
  input: HeadAttestationSubmissionInput,
  cache: StateCache,
): Effect.Effect<void, DataRejectedError, DataStore | ChainStore> =>
  Effect.gen(function* () {
    // 1. メンバーシップ(reader 以上 — §16-1 の「チェーン role reader 以上」)
    const context = yield* requireMemberState(callerUserId, "reader", cache);
    const store = yield* DataStore;
    const nowMs = Date.now();

    // 2. メンバーあたり固定窓(判定 → 即消費: 拒否される提出の反復も窓を使う)
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

    // 3. §6.6 検証(クライアントと同一実装を受理時点の履歴索引へ適用する。
    //    project_id は DO 自身のチェーン(genesis ハッシュ)から取る — §12-5 の
    //    座標再構成の不変条件。申告値から組まない)
    const verified = yield* Effect.promise(() =>
      verifyDistributedHeadAttestation({
        history: context.history,
        context: {
          suite: input.suite,
          projectId: context.projectId,
          attesterUserId: context.member.userId,
          chainHeadHashHex: input.chainHeadHashHex,
          chainHeadSeq: input.chainHeadSeq,
        },
        attesterKeyFingerprintHex: context.member.keyFingerprintHex,
        signatureHex: input.signatureHex,
      }),
    );
    if (!verified.ok) {
      if (verified.error.kind === "HeadAttestationInvalid") {
        return yield* rejectData({
          kind: "attestation-rejected",
          reason: ATTESTATION_REJECT_REASONS[verified.error.reason],
        });
      }
      // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済み
      // チェーン由来の鍵では到達しない(実装バグ = defect。秘密は含まれない)
      return yield* Effect.die(
        new Error(`head attestation verification failed: ${verified.error.kind}`),
      );
    }

    // 4. seq 単調前進(後退 409 / 同一 seq 冪等 204 / 前進 upsert)
    const storedSeq = yield* store.headAttestationSeq(callerUserId);
    if (storedSeq !== null && input.chainHeadSeq < storedSeq) {
      return yield* rejectData({ kind: "attestation-regression", storedSeq });
    }
    if (storedSeq !== null && input.chainHeadSeq === storedSeq) {
      // ヘッド実在一致(手順 3)を通過した同一 seq は同一ハッシュ・決定論的
      // Ed25519 の同一署名 = 同一内容の再送。書き直さず冪等成功
      return;
    }
    yield* Effect.sync(() =>
      store.write.upsertHeadAttestation(
        {
          attesterUserId: context.member.userId,
          suite: input.suite,
          chainHeadSeq: input.chainHeadSeq,
          chainHeadHashHex: input.chainHeadHashHex,
          signatureHex: input.signatureHex,
          attesterKeyFingerprintHex: context.member.keyFingerprintHex,
        },
        nowMs,
      ),
    );
  });
