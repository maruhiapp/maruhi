// DEK ラップの受理検証(AUTH_SPEC §12-6 = CRYPTO_SPEC §6.3 ゴーストメンバー対策の
// サーバー側)と dek.registered イベントの組み立て(AUDIT_SPEC §3.3)。

import type { ChainMember, ChainState } from "@maruhi/crypto";
import { decodeHex, importSigningPublicKey, verifyDekWrapSignature } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type { DataActor, DataRejection, DekRecipientClass, DekWrapInput } from "./data-plane.ts";
import { dataEvent, rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { MAX_DEK_WRAPS_PER_REQUEST } from "./policy.ts";
import { ensureWrapRowCapacity } from "./quotas.ts";

/** ワイヤ・RPC 境界で省略された受信者クラスの既定は member(AUTH_SPEC §12-6)。 */
export function wrapRecipientClass(ref: {
  readonly recipientClass?: DekRecipientClass;
}): DekRecipientClass {
  return ref.recipientClass ?? "member";
}

/**
 * (epoch × 受信者クラス × recipient) の重複検出キー。ラップの登録と削除は同じ
 * 一意性単位を共有する(書式をここに一本化し、両経路の受理境界がズレないように
 * する)。保存行の一意性は (environment, epoch, recipient_user_id) のまま —
 * member の user_id(ULID)と server の FP(hex 32 文字)は形式が交わらないため
 * クラス跨ぎの衝突は構造上生じないが、論理キーにはクラスを含めて明示する。
 */
export function wrapRefKey(ref: {
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
}): string {
  return `${ref.epoch}:${wrapRecipientClass(ref)}:${ref.recipientUserId}`;
}

/**
 * (環境, エポック) のラップ完全集合の期待受信者数(AUTH_SPEC §12-4 / §12-6 —
 * 2026-08-12 改訂): 現メンバー全員 + 当該環境が開示スコープに含まれる有効な
 * grant_server のサーバー鍵。初回登録の完全一致と複合リクエストの個数検査の
 * 両方がこの 1 定義を使う(受理境界をズラさない)。
 */
export function expectedWrapRecipientCount(state: ChainState, environmentId: string): number {
  let grants = 0;
  for (const grant of state.serverGrants.values()) {
    if (grant.scopeEnvironmentIds.includes(environmentId)) {
      grants += 1;
    }
  }
  return state.members.size + grants;
}

/** 1 リクエストのラップ件数上限(登録・削除の両経路で共通)。ok なら null。 */
export function checkWrapRequestCount(count: number): DataRejection | null {
  if (count > MAX_DEK_WRAPS_PER_REQUEST) {
    return {
      kind: "limit-exceeded",
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    };
  }
  return null;
}

/**
 * 受信者の同定(クラス別 — AUTH_SPEC §12-6)。member = user_id + enc 公開鍵の
 * 両方が現メンバーと厳密一致。server = recipientUserId 位置のサーバー鍵 FP +
 * enc 公開鍵の両方がチェーン導出の有効 grant_server の payload と厳密一致し、
 * かつ対象環境が開示スコープに含まれること(スコープ外は 422)。
 */
function checkWrapRecipient(
  state: ChainState,
  environmentId: string,
  wrap: DekWrapInput,
): DataRejection | null {
  if (wrapRecipientClass(wrap) === "server") {
    const grant = state.serverGrants.get(wrap.recipientUserId);
    if (grant === undefined) {
      return { kind: "dek-wrap-rejected", reason: "recipient-not-granted" };
    }
    if (grant.serverEncPubHex !== wrap.recipientEncPubHex) {
      return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
    }
    if (!grant.scopeEnvironmentIds.includes(environmentId)) {
      return { kind: "dek-wrap-rejected", reason: "scope-out-of-range" };
    }
    return null;
  }
  const member = state.members.get(wrap.recipientUserId);
  if (member === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-not-member" };
  }
  if (member.encPubHex !== wrap.recipientEncPubHex) {
    return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
  }
  return null;
}

/** 1 ラップの検査(認知的複雑度の分割)。ok なら null。 */
function checkOneWrap(
  state: ChainState,
  environmentId: string,
  currentEpoch: number,
  wrap: DekWrapInput,
  seen: Set<string>,
): DataRejection | null {
  if (wrap.epoch < 1 || wrap.epoch > currentEpoch) {
    return { kind: "dek-wrap-rejected", reason: "epoch-out-of-range" };
  }
  const recipientRejection = checkWrapRecipient(state, environmentId, wrap);
  if (recipientRejection !== null) {
    return recipientRejection;
  }
  const key = wrapRefKey(wrap);
  if (seen.has(key)) {
    return { kind: "dek-wrap-rejected", reason: "duplicate-recipient" };
  }
  seen.add(key);
  return null;
}

function checkWrapRecipients(
  state: ChainState,
  environmentId: string,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
): DataRejection | null {
  const countRejection = checkWrapRequestCount(wraps.length);
  if (countRejection !== null) {
    return countRejection;
  }
  const seen = new Set<string>();
  for (const wrap of wraps) {
    const rejection = checkOneWrap(state, environmentId, currentEpoch, wrap, seen);
    if (rejection !== null) {
      return rejection;
    }
  }
  return null;
}

/**
 * §12-6 / CRYPTO_SPEC §5.1: 全ラップの登録署名を検証する。署名者 = API 呼び出し
 * 主体の厳密一致が受理条件なので、検証鍵は呼び出し主体の**受理時点のチェーン
 * 導出 sig 公開鍵**(= 登録時点の鍵。全操作は permit 下で直列化されている)。
 * 他人が署名したラップの持ち込み(削除済みスロットへの第三者再投入を含む)は
 * ここで signature-invalid に落ちる。
 */
const ensureWrapSignatures = (
  projectId: string,
  environmentId: string,
  signer: ChainMember,
  wraps: readonly DekWrapInput[],
) =>
  Effect.gen(function* () {
    if (wraps.length === 0) {
      return;
    }
    // 検証済みチェーン由来の鍵はインポート可能が不変条件(失敗はストレージ /
    // 検証器のバグ = defect)。注: 後段のインポート成功は「WebCrypto の raw
    // Ed25519 インポートは長さ検査のみ」という現行ランタイム挙動にも依拠する
    // (add_member の対象メンバーの鍵はチェーン受理時にインポートされないため)。
    // ランタイムが点検証を導入した場合、不正な 32 バイト鍵を持つメンバー自身の
    // リクエストが defect になる(自傷のみ・攻撃には使えない)
    const signerKeyBytes = decodeHex(signer.sigPubHex);
    if (signerKeyBytes === null) {
      return yield* Effect.die(new Error("chain-derived signing key is not valid hex"));
    }
    const imported = yield* Effect.promise(() => importSigningPublicKey(signerKeyBytes));
    if (!imported.ok) {
      return yield* Effect.die(new Error("chain-derived signing key failed to import"));
    }
    for (const wrap of wraps) {
      const verified = yield* Effect.promise(() =>
        verifyDekWrapSignature({
          context: {
            suite: wrap.suite,
            projectId,
            environmentId,
            epoch: wrap.epoch,
            recipientUserId: wrap.recipientUserId,
            recipientEncPubHex: wrap.recipientEncPubHex,
            encHex: wrap.encHex,
            ciphertextHex: wrap.ciphertextHex,
            // 署名対象の署名者 = 呼び出し主体(§12-6)。鍵重複メンバーは
            // チェーン層(CRYPTO_SPEC §6.2)が禁止するが、仮に存在しても
            // 帰属付け替えはここで落ちる(§5.1 の独立防衛層)
            signerUserId: signer.userId,
          },
          signatureHex: wrap.signatureHex,
          signerPublicKey: imported.value,
        }),
      );
      if (!verified.ok) {
        // InvalidInput(構造不正)も含めて署名不受理に畳む(Schema 検証済みの
        // ワイヤでは実質 DekWrapSignatureInvalid のみ到達する)
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" });
      }
    }
  });

/**
 * エポックごとの集合検査(§12-6): 初回登録(既存ラップなし)は現メンバー集合 +
 * 開示スコープ内の有効 grant_server のサーバー鍵との完全一致(受信者検査済み
 * なので個数一致 = 完全 — 判定は受信者クラスを跨いで同一に適用する)、既存
 * エポックへの追記は既存 (エポック, 受信者) との重複を拒否する。
 */
const checkWrapSets = (environmentId: string, state: ChainState, wraps: readonly DekWrapInput[]) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const epochs = [...new Set(wraps.map((wrap) => wrap.epoch))];
    for (const epoch of epochs) {
      const epochWraps = wraps.filter((wrap) => wrap.epoch === epoch);
      const existing = yield* store.countWrapsForEpoch(environmentId, epoch);
      if (existing === 0) {
        if (epochWraps.length !== expectedWrapRecipientCount(state, environmentId)) {
          return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
        }
        continue;
      }
      for (const wrap of epochWraps) {
        if (yield* store.wrapExists(environmentId, epoch, wrap.recipientUserId)) {
          return yield* rejectData({
            kind: "dek-wrap-exists",
            epoch,
            recipientUserId: wrap.recipientUserId,
          });
        }
      }
    }
  });

/**
 * ラップ集合の受理検証(§12-6)+ 数量ポリシー(§12-8)+ 登録署名の検証
 * (CRYPTO_SPEC §5.1)。挿入は呼び出し側の同期書き込みフェーズで行う。
 * ラップ挿入の全経路 — 独立登録 API(バックフィル・修復再登録)と複合リクエスト
 * (環境作成・ローテーション — composite-programs.ts)— がここを通るため、
 * 累積行数上限と署名必須の結線はこの 1 箇所でよい。署名検証(Ed25519 × 件数)は
 * 最も高価なため、安価な検査(件数・受信者・重複・集合)がすべて通った後に行う。
 */
export const ensureWrapSetAcceptable = (
  projectId: string,
  environmentId: string,
  state: ChainState,
  signer: ChainMember,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
) =>
  Effect.gen(function* () {
    const rejection = checkWrapRecipients(state, environmentId, currentEpoch, wraps);
    if (rejection !== null) {
      return yield* rejectData(rejection);
    }
    yield* ensureWrapRowCapacity(wraps.length);
    yield* checkWrapSets(environmentId, state, wraps);
    yield* ensureWrapSignatures(projectId, environmentId, signer, wraps);
  });

/**
 * dek.registered(AUDIT_SPEC §3.3): 1 受信者 1 行(§5.1 の列構造 = 1 行 1
 * target)。member 受信者は target_user_id に載せ、(target_user_id, seq) の
 * 索引で「この受信者宛のラップの登録履歴」をそのまま引けるようにする。
 * server 受信者は user_id を持たない(§2 のアクターモデル)ため、サーバー鍵
 * FP を target_key_fingerprint に載せる(chain.server_granted — §3.4 — と
 * 同じ列。user_id 列にプロバイダ外識別子を混ぜない)。
 * actor_key_fingerprint には登録署名の署名者 FP を写す(§3.3 — セッション 07
 * 裁定 B「E の署名者 FP を写して突合可能にする」)。
 */
export function dekRegisteredEvent(
  actor: DataActor,
  signer: ChainMember,
  nowMs: number,
  environmentId: string,
  wrap: DekWrapInput,
): AuditEventInput {
  return dataEvent(actor, nowMs, "dek.registered", {
    environmentId,
    epoch: wrap.epoch,
    ...(wrapRecipientClass(wrap) === "server"
      ? { targetKeyFingerprintHex: wrap.recipientUserId }
      : { targetUserId: wrap.recipientUserId }),
    actorKeyFingerprintHex: signer.keyFingerprintHex,
  });
}
