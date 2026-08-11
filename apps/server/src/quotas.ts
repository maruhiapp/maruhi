// 存在ガードと数量ポリシー(AUTH_SPEC §12-8)。
//
// - requireActive*: 環境・変数の存在(非 tombstone)ガード。プログラム層と
//   複合リクエスト(composite-programs.ts)が共有する
// - *Exceeded: 上限判定の純関数(上限行数の実生成は非現実的なため、判定は
//   ユニットテスト用に公開する — chain-accept.ts の chainCapacityExceeded と同じ形)
// - ensure*: 判定 + limit-exceeded 拒否への持ち上げ

import { Effect } from "effect";

import type { MetaStatementStatusInput } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "./policy.ts";

/** 現存(非 tombstone)の環境。存在しなければ environment-not-found。 */
export const requireActiveEnvironment = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(environmentId);
    if (environment === null || environment.deletedAtMs !== null) {
      return yield* rejectData({ kind: "environment-not-found", environmentId });
    }
    return environment;
  });

/** 現存(非 tombstone)の変数。存在しなければ variable-not-found。 */
export const requireActiveVariable = (environmentId: string, variableId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const variable = yield* store.findVariable(environmentId, variableId);
    if (variable === null || variable.deletedAtMs !== null) {
      return yield* rejectData({ kind: "variable-not-found", variableId });
    }
    return variable;
  });

/** 環境数の数量ポリシー(§12-8。複合作成 — composite-programs.ts — から呼ぶ)。 */
export const ensureEnvironmentQuota = Effect.gen(function* () {
  const store = yield* DataStore;
  const counts = yield* store.countEnvironments;
  if (counts.active + 1 > MAX_ACTIVE_ENVIRONMENTS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environments",
      limit: MAX_ACTIVE_ENVIRONMENTS,
    });
  }
  if (counts.rows + 1 > MAX_ENVIRONMENT_ROWS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environment-rows",
      limit: MAX_ENVIRONMENT_ROWS,
    });
  }
});

/** 変数数・変数行数(tombstone 込み)の数量ポリシー(§12-8)。 */
export const ensureVariableQuota = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const counts = yield* store.countVariables(environmentId);
    if (counts.active + 1 > MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "variables",
        limit: MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
      });
    }
    if (counts.rows + 1 > MAX_VARIABLE_ROWS_PER_ENVIRONMENT) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "variable-rows",
        limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
      });
    }
  });

/**
 * metaVersion 行数の上限(仮裁定 — §12-8 の「バージョン数 / 変数」と同値を
 * ステートメント行にも適用。rename 連打による DO ストレージ肥大の遮断)。
 * 削除(status deleted)は対象外: tombstone は連鎖の終端で追加行は高々 1 行
 * であり、上限で削除まで遮断すると上限到達リソースがどの role でも恒久的に
 * 削除不能になる(§12-8 の「削除で解放される」原則との衝突 — レビュー②③)。
 * 判定は保存済み状態(latest + 1)基準: CAS 前の stale な申告 metaVersion を
 * limit-exceeded と誤報せず、実際に上限へ達したときのみ 422 にする。
 */
export function metaVersionsExceeded(
  latestMetaVersion: number,
  status: MetaStatementStatusInput,
): boolean {
  return status !== "deleted" && latestMetaVersion + 1 > MAX_VERSIONS_PER_VARIABLE;
}

/** §12-8: 累積暗号文バイトの上限。追加分を含めて判定する純関数(ユニットテスト用に公開)。 */
export function projectBytesExceeded(storedBytes: number, addedBytes: number): boolean {
  return storedBytes + addedBytes > MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES;
}

export const ensureProjectCapacity = (addedBytes: number) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const stored = yield* store.totalCiphertextBytes;
    if (projectBytesExceeded(stored, addedBytes)) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "project-ciphertext-bytes",
        limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      });
    }
  });

/**
 * §12-8: プロジェクト累積の DEK ラップ行数上限。追加分を含めて判定する純関数
 * (上限行数の実生成は非現実的なため、判定はユニットテスト用に公開する)。
 */
export function wrapRowsExceeded(storedRows: number, addedRows: number): boolean {
  return storedRows + addedRows > MAX_PROJECT_DEK_WRAP_ROWS;
}

/** ラップ挿入の全経路(DEK 登録・環境作成)で呼ぶ(§12-8)。 */
export const ensureWrapRowCapacity = (addedRows: number) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const stored = yield* store.countWrapRows;
    if (wrapRowsExceeded(stored, addedRows)) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "dek-wrap-rows",
        limit: MAX_PROJECT_DEK_WRAP_ROWS,
      });
    }
  });
