// DEK ラップの受理検証(AUTH_SPEC §12-6 = CRYPTO_SPEC §6.3 ゴーストメンバー対策の
// サーバー側)と dek.registered イベントの組み立て(AUDIT_SPEC §3.3)。
//
// 端末軸(2026-09-19 DK — K3。設計録 dk-design.md §8 K3-1 / K3-4 / K3-5): 受信者
// 集合 R(E) は (人, 端末) の対 × 実効 scope に展開し、スロット主キーは受信者の
// enc 公開鍵を含む。登録署名の署名者(呼び出し主体の端末)は先頭のラップから
// 解決し(FP 昇順の試行 — 鍵の一意性により検証できる端末は高々 1 つ)、残りの
// ラップはその鍵だけで検証する。

import type { ChainMember, ChainState } from "@maruhi/crypto";
import {
  decodeHex,
  effectivePermissionOf,
  importSigningPublicKey,
  scopeIncludesEnvironment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type {
  DataActor,
  DataRejection,
  DekRecipientClass,
  DekWrapInput,
  MemberWithDevice,
} from "./data-plane.ts";
import { dataEvent, rejectData, withSigningDevice } from "./data-plane.ts";
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
 * (epoch × 受信者クラス × recipient × 端末鍵) の重複検出キー(削除経路 —
 * programs-dek)。クラスの真実源は保存行の recipient_class 列であり、削除経路は
 * このキーの重複検出に加えて保存値とのクラス突合で守る。端末鍵(enc 公開鍵)は
 * 任意(省略 = 当該 (epoch, recipient) の唯一のスロット — 設計録 §8 K3-3)。
 */
export function wrapRefKey(ref: {
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex?: string;
}): string {
  return `${ref.epoch}:${wrapRecipientClass(ref)}:${ref.recipientUserId}:${ref.recipientEncPubHex ?? ""}`;
}

/**
 * **登録経路**の重複検出キー = 保存行の一意性単位 (environment, epoch,
 * recipient_user_id, recipient_enc_pub_hex) と同粒度(クラスを含まない)。
 * member の user_id(ULID)と server の FP(hex 小文字 32 文字)は実際上形式が
 * 交わらないが、add_member の対象 user_id は意図的に存在検証されない自由文字列
 * (AUTH_SPEC §11-1)なので型も合意規則もそれを保証しない。クラス込みのキーで
 * 検査すると「member の user_id = 有効 grant のサーバー鍵 FP かつ同じ鍵」の
 * 衝突集合が受理段を通過し、書き込みフェーズの主キー違反 = defect(500)で
 * 当該環境のローテーション・作成が塞がる(A-1)。受理前にここで
 * 422(duplicate-recipient)に倒す。
 */
function wrapStorageKey(ref: {
  readonly epoch: number;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
}): string {
  return `${ref.epoch}:${ref.recipientUserId}:${ref.recipientEncPubHex}`;
}

/**
 * 受信者集合 R(E) の member 側の所属述語(CRYPTO_SPEC §6.2 — 端末軸。2026-09-19
 * DK): E ∈ 端末の実効 scope(人の scope ∩ 端末の scope — `effectivePermissionOf` が
 * 唯一の計算点)。grant 側の `scopeEnvironmentIds.includes(E)` と対にして、期待数
 * (下)と受信者判定(checkWrapRecipient)が同じ述語を使う —「判定は受信者クラス
 * を跨いで『同定(id + 鍵)∧ E ∈ 実効 scope』の 1 述語」(§6.2 / AUTH_SPEC §12-6)。
 */
function deviceReceivesEnvironment(
  member: ChainMember,
  device: { readonly roleCap: ChainMember["role"]; readonly scope: ChainMember["scope"] },
  environmentId: string,
): boolean {
  return scopeIncludesEnvironment(effectivePermissionOf(member, device).scope, environmentId);
}

/**
 * (環境, エポック) のラップ完全集合の期待受信者数(AUTH_SPEC §12-4 / §12-6) =
 * 受信者集合 R(E)(CRYPTO_SPEC §6.2 — 端末軸): 実効 scope に E を含む現メンバーの
 * 各端末 + 当該環境が開示スコープに含まれる有効な grant_server のサーバー鍵。
 * 初回登録の完全一致と複合リクエストの個数検査の両方がこの 1 定義を使う
 * (受理境界をズラさない)。
 */
export function expectedWrapRecipientCount(state: ChainState, environmentId: string): number {
  // 保存キー(= 登録経路の重複検出キー wrapStorageKey)は受信者クラスを含まない
  // ため、member の user_id と有効 grant のサーバー鍵 FP が同じ鍵で衝突した場合、
  // その 2 受信者は 1 スロットしか占められない。期待数も保存キーと同じ粒度 —
  // 識別子 + 鍵の重複除去済み和集合 — で数える(A-1 の残余の線引きは不変。
  // 端末軸で鍵が主キーに入ったため、衝突は「同じ id かつ同じ鍵」に縮んだ)
  const recipients = new Set<string>();
  for (const [userId, member] of state.members) {
    for (const device of member.devices.values()) {
      if (deviceReceivesEnvironment(member, device, environmentId)) {
        recipients.add(`${userId}:${device.encPubHex}`);
      }
    }
  }
  for (const [fingerprintHex, grant] of state.serverGrants) {
    if (grant.scopeEnvironmentIds.includes(environmentId)) {
      recipients.add(`${fingerprintHex}:${grant.serverEncPubHex}`);
    }
  }
  return recipients.size;
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
 * 受信者の同定(クラス別 — AUTH_SPEC §12-6)。member = user_id が現メンバー、
 * enc 公開鍵がその人の**有効な端末鍵**と厳密一致、かつ対象環境がその端末の
 * **実効 scope** に含まれること(scope 外は 422 `scope-out-of-range` — 2026-09-15 ES
 * K3 / 2026-09-19 DK。CRYPTO_SPEC §6.3 の「失効した端末・端末 scope 外の端末宛の
 * ラップの受理は禁止」= ゴーストメンバー対策の端末軸版)。
 * server = recipientUserId 位置のサーバー鍵 FP + enc 公開鍵の両方がチェーン導出の
 * 有効 grant_server の payload と厳密一致し、かつ対象環境が開示スコープに
 * 含まれること(スコープ外は同じ 422)。理由コードの順(同定 → 鍵 → scope)は
 * クラスを跨いで同一。
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
  // 受信者の鍵 = その人の有効な端末鍵のいずれか(R(E) の端末展開 — AUTH_SPEC §12-6)。
  // 失効済み・未登録の鍵宛は一致しない側へ倒す
  const device = [...member.devices.values()].find(
    (candidate) => candidate.encPubHex === wrap.recipientEncPubHex,
  );
  if (device === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
  }
  if (!deviceReceivesEnvironment(member, device, environmentId)) {
    return { kind: "dek-wrap-rejected", reason: "scope-out-of-range" };
  }
  return null;
}

/**
 * reader の自己バックフィルの述語(AUTH_SPEC §12-3 — 2026-09-19 DK。設計録 §8 K3-5):
 * 全ラップが受信者クラス member、受信者 = 呼び出し主体、かつ enc 公開鍵が呼び出し
 * 主体の有効な端末鍵のいずれか。1 つでも外れれば従来どおり member 以上を要する。
 * 判定は id + 鍵(id だけでは他人の鍵宛を「自分宛」と誤る)。
 */
export function allRecipientsAreOwnDevices(
  caller: ChainMember,
  wraps: readonly DekWrapInput[],
): boolean {
  const ownKeys = new Set([...caller.devices.values()].map((device) => device.encPubHex));
  return wraps.every(
    (wrap) =>
      wrapRecipientClass(wrap) === "member" &&
      wrap.recipientUserId === caller.userId &&
      ownKeys.has(wrap.recipientEncPubHex),
  );
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
  // 保存粒度(クラス無視)での重複検出。クラス違いの同一 (epoch, recipient, 鍵) も
  // 保存行としては共存できないため、同一クラスの重複と同じ理由で拒否する
  const key = wrapStorageKey(wrap);
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

/** 1 ラップの登録署名を 1 つの鍵で検証する(署名対象の署名者 = 呼び出し主体 — §12-6)。 */
const verifyOneWrapSignature = (
  projectId: string,
  environmentId: string,
  signer: MemberWithDevice,
  signerPublicKey: CryptoKey,
  wrap: DekWrapInput,
) =>
  Effect.gen(function* () {
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
        signerPublicKey,
      }),
    );
    if (!verified.ok) {
      // InvalidInput(構造不正)も含めて署名不受理に畳む(Schema 検証済みの
      // ワイヤでは実質 DekWrapSignatureInvalid のみ到達する)
      return yield* rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" });
    }
  });

/** 検証済みチェーン由来の sig 公開鍵のインポート(失敗はストレージ / 検証器のバグ = defect)。 */
const importSignerKey = (signer: MemberWithDevice) =>
  Effect.gen(function* () {
    // 注: 後段のインポート成功は「WebCrypto の raw Ed25519 インポートは長さ検査のみ」
    // という現行ランタイム挙動にも依拠する(add_member / add_device の対象鍵は
    // チェーン受理時にインポートされないため)。ランタイムが点検証を導入した場合、
    // 不正な 32 バイト鍵を持つメンバー自身のリクエストが defect になる(自傷のみ・
    // 攻撃には使えない)
    const signerKeyBytes = decodeHex(signer.sigPubHex);
    if (signerKeyBytes === null) {
      return yield* Effect.die(new Error("chain-derived signing key is not valid hex"));
    }
    const imported = yield* Effect.promise(() => importSigningPublicKey(signerKeyBytes));
    if (!imported.ok) {
      return yield* Effect.die(new Error("chain-derived signing key failed to import"));
    }
    return imported.value;
  });

/**
 * §12-6 / CRYPTO_SPEC §5.1: 全ラップの登録署名を検証し、署名した端末を返す。
 * 署名者 = API 呼び出し主体の厳密一致が受理条件なので、検証鍵は呼び出し主体の
 * **受理時点のチェーン導出 sig 公開鍵**(= 登録時点の鍵。全操作は permit 下で
 * 直列化されている)。端末は先頭のラップで解決し(`withSigningDevice` — 設計録 §8
 * K3-1)、残りはその鍵だけで検証する(全件 × 全端末にしない)。他人が署名した
 * ラップの持ち込み(削除済みスロットへの第三者再投入を含む)はここで
 * signature-invalid に落ちる。ラップが無ければ null(端末は決まらない —
 * 呼び出し側の個数検査が recipient-missing で拒む)。
 */
const ensureWrapSignatures = (
  projectId: string,
  environmentId: string,
  caller: ChainMember,
  wraps: readonly DekWrapInput[],
) =>
  Effect.gen(function* () {
    const [first, ...rest] = wraps;
    if (first === undefined) {
      return null;
    }
    const { device: signer, value: signerPublicKey } = yield* withSigningDevice(
      caller,
      (candidate) =>
        Effect.gen(function* () {
          const key = yield* importSignerKey(candidate);
          yield* verifyOneWrapSignature(projectId, environmentId, candidate, key, first);
          return key;
        }),
    );
    for (const wrap of rest) {
      yield* verifyOneWrapSignature(projectId, environmentId, signer, signerPublicKey, wrap);
    }
    return signer;
  });

/**
 * エポックごとの集合検査(§12-6): 初回登録(既存ラップなし)は受信者集合 R(E)
 * (実効 scope に E を含む現メンバーの各端末 + 開示スコープ内の有効 grant_server の
 * サーバー鍵)との完全一致(受信者検査済みなので個数一致 = 完全 — 判定は受信者
 * クラスを跨いで同一に適用する)、既存エポックへの追記は既存 (エポック, 受信者,
 * 端末鍵) との重複を拒否する。
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
        // 存在検査は保存キー (environment, epoch, recipient_user_id, recipient_enc_pub_hex)
        // と同粒度 — class 違いの同一 (ID, 鍵) も挿入すれば主キー衝突なので、ここで 409 に倒す
        const stored = yield* store.wrapStoredRecipient(
          environmentId,
          epoch,
          wrap.recipientUserId,
          wrap.recipientEncPubHex,
        );
        if (stored !== null) {
          // 占有ラップの保存済み受信者 enc 公開鍵を載せる(AUTH_SPEC §12-6)。
          // 端末軸の主キーでは送った鍵と常に一致する(旧鍵ラップは別スロット =
          // 新鍵の登録を塞がない)ので、材料としての役目は「登録済み = 冪等」の
          // 判定に縮む — ワイヤは不変(設計録 §8 K3-3)
          return yield* rejectData({
            kind: "dek-wrap-exists",
            epoch,
            recipientUserId: wrap.recipientUserId,
            storedRecipientEncPubHex: stored.recipientEncPubHex,
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
 * 返り値 = 署名した端末(呼び出し側が第 2 段の認可 — ensureDevicePermission — と
 * 書き込み・監査の署名者 FP に使う。ラップが無ければ null)。
 */
export const ensureWrapSetAcceptable = (
  projectId: string,
  environmentId: string,
  state: ChainState,
  caller: ChainMember,
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
    return yield* ensureWrapSignatures(projectId, environmentId, caller, wraps);
  });

/**
 * dek.registered(AUDIT_SPEC §3.3): 1 受信者 1 行(§5.1 の列構造 = 1 行 1
 * target)。member 受信者は target_user_id に載せ、(target_user_id, seq) の
 * 索引で「この受信者宛のラップの登録履歴」をそのまま引けるようにする。
 * server 受信者は user_id を持たない(§2 のアクターモデル)ため、サーバー鍵
 * FP を target_key_fingerprint に載せる(chain.server_granted — §3.4 — と
 * 同じ列。user_id 列にプロバイダ外識別子を混ぜない)。
 * actor_key_fingerprint には登録署名の署名者 FP(署名した端末)を写す(§3.3 —
 * セッション 07 裁定 B「E の署名者 FP を写して突合可能にする」)。
 */
export function dekRegisteredEvent(
  actor: DataActor,
  signer: { readonly keyFingerprintHex: string },
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
