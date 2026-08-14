// データプレーン(AUTH_SPEC §12)の共有部: RPC 境界を渡る型・拒否理由・
// 認可ガード(チェーン導出 role — CRYPTO_SPEC §6.2)。
//
// 拒否は DataRejectedError 1 種に畳み、DO の RPC 境界では DataOutcome の
// 判別 union として渡す(worker が api-schema の型付きエラーへ写像する)。

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import type {
  ChainHistoryIndex,
  ChainInvalidReason,
  ChainMember,
  ChainState,
  Role,
} from "@maruhi/crypto";
import { Data, Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type { StateCache, StoredChain } from "./chain-store.ts";
import { ChainStore, deriveStoredState } from "./chain-store.ts";

// ---------------------------------------------------------------------------
// RPC 境界を渡る入力・値(structured clone 安全な素のオブジェクトのみ)
// ---------------------------------------------------------------------------

/**
 * データ操作の監査アクター(AUDIT_SPEC §2)。worker が認証主体から
 * auditActorOf(@maruhi/core — 写像の唯一の実装)で作る。
 * 鍵 FP は持たない — ほとんどのデータ操作は署名を伴わないため。署名を伴う
 * 唯一の例外は DEK ラップ登録(CRYPTO_SPEC §5.1)で、その署名者 FP は worker
 * でなく DO がチェーン導出メンバーから取り、dek.registered イベントに写す。
 */
export type DataActor = AuditActor;

/**
 * スイート識別子(CRYPTO_SPEC §2 設計原則 4)。ワイヤは Schema の Literal が
 * 強制するため、RPC 境界・保存行の型もこの literal で表す(AUTH_SPEC §12-2)。
 */
export type WireSuite = "maruhi/v1";

/**
 * DEK ラップの受信者クラス(AUTH_SPEC §12-6。2026-08-12): member = チェーン上の
 * 現メンバー、server = 有効な grant_server のサーバー鍵。省略時は member。
 * server クラスでは recipientUserId 位置にサーバー鍵 FP(hex 小文字)が入る
 * (HPKE info / §5.1 署名対象と同じ置き換え — CRYPTO_SPEC §9)。
 */
export type DekRecipientClass = "member" | "server";

/**
 * 1 受信者宛のラップ済み DEK(AUTH_SPEC §12-6。ワイヤ表現と構造一致)。
 * signatureHex は登録署名(CRYPTO_SPEC §5.1)— 署名者は API 呼び出し主体と
 * 厳密一致(§12-6)のため、ワイヤ・RPC 境界に署名者 ID は載せない。
 */
export interface DekWrapInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
}

/** 保存済みラップの参照(§12-6 の修復経路の削除単位)。 */
export interface DekWrapRefInput {
  readonly epoch: number;
  readonly recipientClass?: DekRecipientClass;
  readonly recipientUserId: string;
}

/** ステートメントのライフサイクル状態(CRYPTO_SPEC §4.2)。 */
export type MetaStatementStatusInput = "active" | "deleted";

/**
 * メタデータステートメントの保存入力(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-5)。
 * 座標(environment / variable)は worker が URL・ステートメント申告値の一致を
 * 検査済みで、DO は保存先座標から署名対象を再構成する(§12-5 — ワイヤの申告値
 * から組まない)。author = 呼び出し主体が契約のため author の ID / FP はここに
 * 載せない(DO が受理時点のチェーン導出メンバーから取る)。
 */
export interface MetaStatementInput {
  readonly suite: WireSuite;
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  /** 直前ステートメントの signed_bytes の SHA-256(metaVersion 1 は空文字列)。 */
  readonly prevMetaSigHashHex: string;
  /** author が署名時点で最後に検証したチェーンヘッド(§4.2 の認可時点束縛)。 */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** ステートメント署名(Ed25519 — CRYPTO_SPEC §4.2)。 */
  readonly signatureHex: string;
}

/**
 * 配布されるメタデータステートメント(DistributedVariableMetaStatement /
 * DistributedEnvironmentMetaStatement と構造一致 — 変数用は variableId 付き)。
 * 保存済みの署名ブロックと author(受理時点の user_id + チェーン導出鍵 FP)を
 * そのまま返す(削除済み author の過去ステートメントの検証可能性 — §12-2)。
 */
export interface DistributedMetaStatementValue {
  readonly suite: WireSuite;
  readonly environmentId: string;
  readonly name: string;
  readonly status: MetaStatementStatusInput;
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly authorUserId: string;
  readonly authorKeyFingerprintHex: string;
}

/** 変数ステートメントの配布形(variableId 付き)。 */
export interface DistributedVariableMetaStatementValue extends DistributedMetaStatementValue {
  readonly variableId: string;
}

/**
 * 変数値の保存入力。AAD 構成要素のうち座標(project / environment / variable)は
 * worker が URL との一致を検査済み(§12-2)。DO は状態依存の epoch / version と
 * 値署名(§12-5 = CRYPTO_SPEC §4.1 / §6.4)を検査する。
 * writer = 呼び出し主体が契約のため writer の ID / FP はここに載せない
 * (DO が受理時点のチェーン導出メンバーから取る)。
 */
export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /** 直前 version の value_signed_bytes の SHA-256(version 1 は空文字列)。 */
  readonly prevValueSigHashHex: string;
  /** writer が署名時点で最後に検証したチェーンヘッド(§4.1 の認可時点束縛)。 */
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  /** 値の書き込み署名(Ed25519 — CRYPTO_SPEC §4.1)。 */
  readonly signatureHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 最新の環境メタステートメント(削除済み環境は deleted ステートメント)。 */
  readonly statement: DistributedMetaStatementValue;
}

export interface VariableVersionValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
}

/**
 * 一括 pull の 1 変数(§12-7)。保存済みの署名ブロックと writer(受理時点の
 * user_id + チェーン導出鍵 FP)を配布する — 現メンバー集合から再導出しない
 * (削除済み writer の過去値もチェーン履歴の当時の鍵で検証可能にするため)。
 * サーバー再計算の signed_bytes ハッシュは配布しない(検証者が自ら再計算する)。
 */
export interface PulledVariableValue {
  readonly variableId: string;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly prevValueSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
  readonly writerUserId: string;
  readonly writerKeyFingerprintHex: string;
}

/**
 * 配布されるラップ(RecipientDek と構造一致)。署名・署名者情報(登録受理時の
 * チェーン導出メンバーの user_id + 鍵 FP)を運び、配布時のクライアント検証
 * (CRYPTO_SPEC §5.1)を可能にする。
 */
export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly signatureHex: string;
  readonly signerUserId: string;
  readonly signerKeyFingerprintHex: string;
}

export interface EnvironmentPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 環境自身の最新メタステートメント(§12-7 の検証材料の同梱)。 */
  readonly statement: DistributedMetaStatementValue;
  /** アクティブ変数ごとの最新ステートメント + 最新バージョン。 */
  readonly variables: readonly (PulledVariableValue & {
    readonly statement: DistributedVariableMetaStatementValue;
  })[];
  /** 削除済み変数の deleted ステートメント(保存・配布し続ける — §12-5)。 */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
  readonly deks: readonly RecipientDekValue[];
}

/**
 * メタデータのみモードの応答(§12-7 — 2026-08-10): 値(暗号文)と DEK を
 * 含まない。§6.3 のメタ検証材料(環境 + アクティブ変数の最新ステートメント +
 * tombstone)のみを運ぶ。var.read は記録されない(AUDIT_SPEC §3.3)。
 */
export interface EnvironmentMetadataPullValue {
  readonly environmentId: string;
  readonly currentEpoch: number;
  /** 環境自身の最新メタステートメント。 */
  readonly statement: DistributedMetaStatementValue;
  /** アクティブ変数ごとの最新ステートメント(値は伴わない)。 */
  readonly variables: readonly DistributedVariableMetaStatementValue[];
  /** 削除済み変数の deleted ステートメント(§12-5)。 */
  readonly deletedVariables: readonly DistributedVariableMetaStatementValue[];
}

// ---------------------------------------------------------------------------
// 拒否理由(worker が api-schema の型付きエラーへ写像する)
// ---------------------------------------------------------------------------

export type ResourceConflictReason = "exists" | "retired" | "duplicate-name";

/**
 * 環境の 409 は表示名の衝突のみ(2026-08-03): ID の一意性(旧 exists / retired)は
 * チェーン合意規則 `duplicate-environment`(chain-entry-invalid)へ吸収された
 * (CRYPTO_SPEC §6.2 / AUTH_SPEC §12-4)。
 */
export type EnvironmentConflictReason = "duplicate-name";

export type DekWrapRejectReason =
  | "recipient-not-member"
  | "recipient-not-granted"
  | "recipient-key-mismatch"
  | "recipient-missing"
  | "duplicate-recipient"
  | "epoch-out-of-range"
  | "scope-out-of-range"
  | "signature-invalid";

/**
 * 値署名の 422 理由(AUTH_SPEC §12-5。仮裁定 C — 仕様の 3 理由のみ):
 * signature-invalid = valid-format の Ed25519 失敗 / chain-head-unknown =
 * 有効署名だが宣言 seq 不在またはその seq の保存 hash 不一致 /
 * chain-head-state-mismatch = head は既知だが head 時点の鍵・role・環境・
 * エポック不一致、または保存 predecessor と prev 不一致。
 */
export type ValueSignatureRejectReason =
  | "signature-invalid"
  | "chain-head-unknown"
  | "chain-head-state-mismatch";

/**
 * メタステートメントの 422 理由は値署名と同じ 3 語彙を共有する(session-12
 * §6-7 — 新理由コードを作らない)。chain-head-state-mismatch はヘッド時点の
 * 在籍・鍵束縛・role、prev の形 / 保存 predecessor との不一致、削除後の
 * 再ステートメント(revived-after-delete)を含む。
 */
export type MetaStatementRejectReason = ValueSignatureRejectReason;

export type DataLimitResource =
  | "environments"
  | "environment-rows"
  | "variables"
  | "variable-rows"
  | "versions"
  | "meta-versions"
  | "project-ciphertext-bytes"
  | "dek-wraps-per-request"
  | "dek-wrap-rows";

export type DataRejection =
  | { readonly kind: "not-initialized" }
  | { readonly kind: "not-member" }
  | { readonly kind: "insufficient-role" }
  | { readonly kind: "environment-not-found"; readonly environmentId: string }
  | {
      readonly kind: "environment-conflict";
      readonly environmentId: string;
      readonly reason: EnvironmentConflictReason;
    }
  // チェーン受理系(複合リクエスト §12-4 と汎用チェーン API — chain-do.ts —
  // の両方が使う。worker が api-schema の ChainHeadConflict / ChainEntryInvalid /
  // ChainEntryTooLarge / ChainCapacityExceeded / CompositeRequired へ写像する)
  | {
      readonly kind: "composite-required";
      readonly op: "create_environment" | "rotate_epoch";
    }
  | {
      readonly kind: "chain-head-conflict";
      readonly currentHeadSeq: number;
      readonly currentHeadHashHex: string;
    }
  | {
      readonly kind: "chain-entry-invalid";
      readonly seq: number;
      readonly reason: ChainInvalidReason;
    }
  | { readonly kind: "chain-entry-too-large"; readonly limitBytes: number }
  | {
      readonly kind: "chain-capacity-exceeded";
      readonly maxEntries: number;
      readonly maxTotalBytes: number;
    }
  // 複合内整合検査(§12-4): URL 座標と同梱エントリ payload の不一致
  | { readonly kind: "payload-mismatch"; readonly field: string }
  | { readonly kind: "variable-not-found"; readonly variableId: string }
  | {
      readonly kind: "variable-conflict";
      readonly variableId: string;
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict"; readonly currentEpoch: number }
  | { readonly kind: "value-rejected"; readonly reason: ValueSignatureRejectReason }
  | { readonly kind: "meta-rejected"; readonly reason: MetaStatementRejectReason }
  | { readonly kind: "meta-version-conflict"; readonly currentMetaVersion: number }
  | { readonly kind: "name-not-nfc" }
  | { readonly kind: "dek-wrap-rejected"; readonly reason: DekWrapRejectReason }
  | { readonly kind: "dek-wrap-exists"; readonly epoch: number; readonly recipientUserId: string }
  | {
      readonly kind: "dek-wrap-not-found";
      readonly epoch: number;
      readonly recipientUserId: string;
    }
  | {
      readonly kind: "limit-exceeded";
      readonly resource: DataLimitResource;
      readonly limit: number;
    };

/** データプレーンのプログラムが失敗として運ぶ唯一の型付きエラー。 */
export class DataRejectedError extends Data.TaggedError("DataRejected")<{
  readonly rejection: DataRejection;
}> {}

export const rejectData = (rejection: DataRejection): DataRejectedError =>
  new DataRejectedError({ rejection });

/** RPC 境界(structured clone)を渡るデータ操作の結果。 */
export type DataOutcome<T> =
  | { readonly kind: "ok"; readonly value: T }
  | { readonly kind: "rejected"; readonly rejection: DataRejection };

// ---------------------------------------------------------------------------
// 認可ガード(チェーン導出 role — CRYPTO_SPEC §6.2 / AUTH_SPEC §12-3)
// ---------------------------------------------------------------------------

const ROLE_RANK: Record<Role, number> = { reader: 1, member: 2, admin: 3, owner: 4 };

/** チェーン role の下限判定(reader < member < admin < owner)。 */
function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/** チェーン導出 role の下限検査(複合プログラム — composite-programs.ts — と共有)。 */
export function requireRole(
  state: ChainState,
  callerUserId: string,
  minimum: Role,
): Effect.Effect<ChainMember, DataRejectedError> {
  const member = state.members.get(callerUserId);
  if (member === undefined) {
    // §11-2: 非メンバーには現ヘッド・受理判定を含む一切を返さない(worker が 404 に写す)
    return Effect.fail(rejectData({ kind: "not-member" }));
  }
  return roleAtLeast(member.role, minimum)
    ? Effect.succeed(member)
    : Effect.fail(rejectData({ kind: "insufficient-role" }));
}

/**
 * requireMemberState の結果: 導出状態・履歴索引(値署名の宣言ヘッド時点検証の
 * 入力 — CRYPTO_SPEC §4.1 / §6.4)に加えて、呼び出し主体のチェーンメンバー
 * (登録署名・値署名の検証鍵と署名者 FP の源 — §5.1 / §4.1)と、プロジェクト ID
 * (= genesis エントリハッシュ。署名対象の座標)を返す。
 */
export interface MemberContext {
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly projectId: string;
}

/** 初期化済みチェーン(genesis ハッシュの存在を型で保証した StoredChain)。 */
export type InitializedChain = StoredChain & {
  readonly headHashHex: string;
  readonly genesisHashHex: string;
};

/**
 * チェーンのロードと初期化検査(データ操作・複合受理の共通前段)。未初期化は
 * not-initialized、headSeq > 0 なのに genesis / ヘッドが欠けるのはストレージ
 * 破損(defect)。
 */
export const loadInitializedChain: Effect.Effect<InitializedChain, DataRejectedError, ChainStore> =
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    if (chain.genesisHashHex === null) {
      return yield* Effect.die(new Error("initialized chain is missing its genesis hash"));
    }
    return { ...chain, headHashHex: chain.headHashHex, genesisHashHex: chain.genesisHashHex };
  });

/**
 * データ操作に共通する前段: 未初期化の検査 → チェーン導出 → メンバーシップと
 * role 下限の検査(§12-3 の判定順)。導出はチェーン API と同じキャッシュを流用する。
 */
export const requireMemberState = (
  callerUserId: string,
  minimum: Role,
  cache: StateCache,
): Effect.Effect<MemberContext, DataRejectedError, ChainStore> =>
  Effect.gen(function* () {
    const chain = yield* loadInitializedChain;
    const { state, history } = yield* deriveStoredState(chain, cache);
    const member = yield* requireRole(state, callerUserId, minimum);
    return { state, history, member, projectId: chain.genesisHashHex };
  });

/**
 * 環境の現エポック = チェーン導出値(CRYPTO_SPEC §6.2 / §6.3。2026-08-03)。
 * 環境の存在自体がチェーン導出(`create_environment`)になったため「未観測なら
 * 初期値 1」の既定値は廃止した。データ行は複合受理(§12-4)でチェーンエントリと
 * 原子的に作られるため、アクティブなデータ行があるのにチェーンに環境がないのは
 * 不変条件違反(ストレージ / 実装バグ)であり defect として落とす。
 */
export function currentEpochOf(state: ChainState, environmentId: string): number {
  const environment = state.environments.get(environmentId);
  if (environment === undefined) {
    throw new Error("environment missing from chain-derived state");
  }
  return environment.currentEpoch;
}

/**
 * データ操作の監査イベントを組み立てる(AUDIT_SPEC §3.3)。actor の
 * auth_method は列ではなく payload JSON に載せる(§5.1: 頻出属性のみ列に昇格)。
 * actor の鍵 FP は原則持たない(チェーンミラーの専有)が、**dek.registered のみ
 * 例外**として登録署名(CRYPTO_SPEC §5.1)の署名者 FP を actorKeyFingerprintHex
 * に写す(AUDIT_SPEC §3.3 — 監査行とチェーン外署名の突合用)。
 */
export function dataEvent(
  actor: DataActor,
  serverTs: number,
  event: string,
  fields: Pick<
    AuditEventInput,
    | "environmentId"
    | "variableId"
    | "epoch"
    | "version"
    | "targetUserId"
    | "targetKeyFingerprintHex"
    | "payload"
    | "actorKeyFingerprintHex"
  >,
): AuditEventInput {
  const payload = auditPayloadWith(actor, fields.payload);
  return {
    ...fields,
    event,
    serverTs,
    actorType: "user",
    actorUserId: actor.userId,
    ...(actor.apiTokenId === undefined ? {} : { actorApiTokenId: actor.apiTokenId }),
    ...(Object.keys(payload).length === 0 ? {} : { payload }),
  };
}
