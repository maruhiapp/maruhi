// データプレーン(AUTH_SPEC §12)の共有部: RPC 境界を渡る型・拒否理由・
// 認可ガード(チェーン導出 role — CRYPTO_SPEC §6.2)。
//
// 拒否は DataRejectedError 1 種に畳み、DO の RPC 境界では DataOutcome の
// 判別 union として渡す(worker が api-schema の型付きエラーへ写像する)。

import type { ChainMember, ChainState, Role } from "@maruhi/crypto";
import { Data, Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import { ChainStore, deriveStoredState } from "./chain-store.ts";

// ---------------------------------------------------------------------------
// RPC 境界を渡る入力・値(structured clone 安全な素のオブジェクトのみ)
// ---------------------------------------------------------------------------

/**
 * データ操作の監査アクター(AUDIT_SPEC §2)。worker が認証主体から作る。
 * 鍵 FP は持たない(データ操作は署名を伴わないため。FP を持つのはチェーン
 * ミラーのみ)。
 */
export interface DataActor {
  readonly userId: string;
  readonly apiTokenId?: string;
  readonly authMethod?: string;
}

/**
 * スイート識別子(CRYPTO_SPEC §2 設計原則 4)。ワイヤは Schema の Literal が
 * 強制するため、RPC 境界・保存行の型もこの literal で表す(AUTH_SPEC §12-2)。
 */
export type WireSuite = "maruhi/v1";

/** 1 受信者宛のラップ済み DEK(AUTH_SPEC §12-6。ワイヤ表現と構造一致)。 */
export interface DekWrapInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** 保存済みラップの参照(§12-6 の修復経路の削除単位)。 */
export interface DekWrapRefInput {
  readonly epoch: number;
  readonly recipientUserId: string;
}

/**
 * 変数値の保存入力。AAD 構成要素のうち座標(project / environment / variable)は
 * worker が URL との一致を検査済み(§12-2)。DO は状態依存の epoch / version を
 * 検査する。
 */
export interface ValueInput {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

export interface EnvironmentSummaryValue {
  readonly environmentId: string;
  readonly name: string;
  readonly currentEpoch: number;
}

export interface VariableVersionValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
}

export interface PulledVariableValue {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}

export interface RecipientDekValue {
  readonly suite: WireSuite;
  readonly epoch: number;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface EnvironmentPullValue {
  readonly environmentId: string;
  readonly name: string;
  readonly currentEpoch: number;
  readonly variables: readonly PulledVariableValue[];
  readonly deks: readonly RecipientDekValue[];
}

// ---------------------------------------------------------------------------
// 拒否理由(worker が api-schema の型付きエラーへ写像する)
// ---------------------------------------------------------------------------

export type ResourceConflictReason = "exists" | "retired" | "duplicate-name";

export type DekWrapRejectReason =
  | "recipient-not-member"
  | "recipient-key-mismatch"
  | "recipient-missing"
  | "duplicate-recipient"
  | "epoch-out-of-range";

export type DataLimitResource =
  | "environments"
  | "environment-rows"
  | "variables"
  | "variable-rows"
  | "versions"
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
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "variable-not-found"; readonly variableId: string }
  | {
      readonly kind: "variable-conflict";
      readonly variableId: string;
      readonly reason: ResourceConflictReason;
    }
  | { readonly kind: "version-conflict"; readonly currentVersion: number }
  | { readonly kind: "epoch-conflict"; readonly currentEpoch: number }
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

function requireRole(
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
 * データ操作に共通する前段: 未初期化の検査 → チェーン導出 → メンバーシップと
 * role 下限の検査(§12-3 の判定順)。導出はチェーン API と同じキャッシュを流用する。
 */
export const requireMemberState = (callerUserId: string, minimum: Role, cache: StateCache) =>
  Effect.gen(function* () {
    const store = yield* ChainStore;
    const chain = yield* store.load;
    if (chain.headSeq === 0 || chain.headHashHex === null) {
      return yield* rejectData({ kind: "not-initialized" });
    }
    const state = yield* deriveStoredState(chain, cache);
    yield* requireRole(state, callerUserId, minimum);
    return state;
  });

/** 環境の現エポック = チェーン観測値、未観測なら初期値 1(CRYPTO_SPEC §3)。 */
export function currentEpochOf(state: ChainState, environmentId: string): number {
  return state.environmentEpochs.get(environmentId) ?? 1;
}

/**
 * データ操作の監査イベントを組み立てる(AUDIT_SPEC §3.3)。actor の
 * auth_method は列ではなく payload JSON に載せる(§5.1: 頻出属性のみ列に昇格)。
 */
export function dataEvent(
  actor: DataActor,
  serverTs: number,
  event: string,
  fields: Pick<
    AuditEventInput,
    "environmentId" | "variableId" | "epoch" | "version" | "targetUserId" | "payload"
  >,
): AuditEventInput {
  const payload = {
    ...fields.payload,
    ...(actor.authMethod === undefined ? {} : { authMethod: actor.authMethod }),
  };
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
