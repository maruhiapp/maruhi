// 存在ガードと数量ポリシー(AUTH_SPEC §12-8)。
//
// - requireActive*: 環境・変数の存在(非 tombstone)ガード。プログラム層と
//   複合リクエスト(composite-programs.ts)が共有する
// - *Exceeded: 上限判定の純関数(上限行数の実生成は非現実的なため、判定は
//   ユニットテスト用に公開する — chain-accept.ts の chainCapacityExceeded と同じ形)
// - ensure*: 判定 + limit-exceeded 拒否への持ち上げ

import type { PendingProposal } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MetaStatementStatusInput } from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_PROJECTS_PER_ORG,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_ENVIRONMENT_ROWS,
  MAX_PENDING_PROPOSALS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_PROPOSAL_LIFETIME_MS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "./policy.ts";

/**
 * AUTH_SPEC §11-3: org あたりのアクティブプロジェクト数上限。
 * 「この org に 1 件追加すると上限を超えるか」を数値のみで判定する純関数
 * (上限件数の実生成は重いため、判定はユニットテスト用に公開する — 他の
 * *Exceeded と同じ形)。判定材料の取得(D1 count)と判定点(init 受理 —
 * org 権限確認の後・DO init の前)は worker 側 handlers-membership.ts。
 * 上限到達時の扱い(DO への report-only 問い合わせで修復経路を塞がない)も同所。
 */
export function projectQuotaExceeded(activeProjectCount: number): boolean {
  return activeProjectCount + 1 > MAX_ACTIVE_PROJECTS_PER_ORG;
}

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
 * 削除不能になる(§12-8 の「削除で解放される」原則との衝突)。
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

// ---------------------------------------------------------------------------
// 四眼の受理ポリシー(AUTH_SPEC §12-8 / CRYPTO_SPEC §6.4 — 合意規則ではない。
// 設計録 es-design.md §11 K5-B / K5-C)。判定材料は DO のチェーン導出状態
// (pending 集合)とサーバー時計。判定順は上界(エントリ固有)→ pending 上限
// (プロジェクト状態)— サイズ → 容量の既存順と同じ「エントリ固有 → 状態」。
// 作成時点で既に失効している提案は拒否しない(K5-C: 上限の計算から除外される
// だけで資源を占有せず、合意規則が承認を `proposal-expired` で閉じる)。
// ---------------------------------------------------------------------------

/** サーバー時計で期限内(= pending 上限の計算に数える)か。等号は期限内(§6.2 の `≤` と同じ向き)。 */
export function proposalIsLive(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs >= nowMs;
}

/** §6.4: `expires_at_ms` が受理時サーバー時計 + 30 日を超えるか(純関数 — ユニットテスト用に公開)。 */
export function proposalLifetimeExceeded(expiresAtMs: number, nowMs: number): boolean {
  return expiresAtMs > nowMs + MAX_PROPOSAL_LIFETIME_MS;
}

/** §12-8: 期限内の pending 提案に 1 件足すと上限を超えるか(純関数 — ユニットテスト用に公開)。 */
export function pendingProposalsExceeded(livePendingCount: number): boolean {
  return livePendingCount + 1 > MAX_PENDING_PROPOSALS;
}

/** 現導出状態の pending 集合のうち、サーバー時計で期限内のものの数。 */
export function countLivePendingProposals(
  pending: ReadonlyMap<string, PendingProposal>,
  nowMs: number,
): number {
  let count = 0;
  for (const proposal of pending.values()) {
    if (proposalIsLive(proposal.expiresAtMs, nowMs)) {
      count += 1;
    }
  }
  return count;
}

/**
 * `propose` の受理ポリシー(上界 → pending 上限)。呼び出しはメンバーシップ判定と
 * 成長ガードの後・CAS / verifyChain の前(chain-do.ts の appendProgram)。
 */
export const ensureProposalAdmitted = (
  expiresAtMs: number,
  pending: ReadonlyMap<string, PendingProposal>,
  nowMs: number,
) =>
  Effect.gen(function* () {
    if (proposalLifetimeExceeded(expiresAtMs, nowMs)) {
      return yield* rejectData({
        kind: "proposal-limit",
        reason: "proposal-lifetime",
        limit: MAX_PROPOSAL_LIFETIME_MS,
      });
    }
    if (pendingProposalsExceeded(countLivePendingProposals(pending, nowMs))) {
      return yield* rejectData({
        kind: "proposal-limit",
        reason: "pending-proposals",
        limit: MAX_PENDING_PROPOSALS,
      });
    }
  });
