// データプレーンの Effect プログラム(AUTH_SPEC §12)。
//
// 判定順(§12-3): チェーン導出メンバーシップ + role 下限(requireMemberState)→
// 環境・変数の存在 → 意味論的検査(ID / 名前の衝突、エポック・バージョンの CAS、
// DEK ラップの受信者検証)→ 数量ポリシー(§12-8)→ 書き込み + 監査イベント
// (AUDIT_SPEC §3.3)。
//
// 変更系プログラムは DO の書き込みロック(Semaphore(1))下で実行される前提。
// pull はロックなしで走るため、監査追記は 1 文の同期 SQL(audit-store.ts)に
// 限定し、返した行とイベントが常に一致するようにしている。

import type { ChainState } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type {
  DataActor,
  DataRejectedError,
  DataRejection,
  DekWrapInput,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  ValueInput,
  VariableVersionValue,
} from "./data-plane.ts";
import { currentEpochOf, dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import type { EnvironmentRow, VariableRow } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "./policy.ts";

// ---------------------------------------------------------------------------
// 共有ガード
// ---------------------------------------------------------------------------

/** 現存(非 tombstone)の環境。存在しなければ environment-not-found。 */
const requireActiveEnvironment = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(environmentId);
    if (environment === null || environment.deletedAtMs !== null) {
      return yield* rejectData({ kind: "environment-not-found", environmentId });
    }
    return environment;
  });

const requireActiveVariable = (environmentId: string, variableId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const variable = yield* store.findVariable(environmentId, variableId);
    if (variable === null || variable.deletedAtMs !== null) {
      return yield* rejectData({ kind: "variable-not-found", variableId });
    }
    return variable;
  });

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

const ensureValueCas = (
  state: ChainState,
  environmentId: string,
  latestVersion: number,
  value: ValueInput,
): Effect.Effect<void, DataRejectedError> => {
  const rejection = checkValueCas(state, environmentId, latestVersion, value);
  return rejection === null ? Effect.void : Effect.fail(rejectData(rejection));
};

/** §12-8: 累積暗号文バイトの上限。追加分を含めて判定する純関数(ユニットテスト用に公開)。 */
export function projectBytesExceeded(storedBytes: number, addedBytes: number): boolean {
  return storedBytes + addedBytes > MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES;
}

const ensureProjectCapacity = (addedBytes: number) =>
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

// ---------------------------------------------------------------------------
// DEK ラップの受理検証(§12-6 = CRYPTO_SPEC §6.3 ゴーストメンバー対策のサーバー側)
// ---------------------------------------------------------------------------

/** 1 ラップの検査(§12-8 の純関数分割)。ok なら null。 */
export function checkOneWrap(
  state: ChainState,
  currentEpoch: number,
  wrap: DekWrapInput,
  seen: Set<string>,
): DataRejection | null {
  if (wrap.epoch < 1 || wrap.epoch > currentEpoch) {
    return { kind: "dek-wrap-rejected", reason: "epoch-out-of-range" };
  }
  const member = state.members.get(wrap.recipientUserId);
  if (member === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-not-member" };
  }
  if (member.encPubHex !== wrap.recipientEncPubHex) {
    return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
  }
  const key = `${wrap.epoch}:${wrap.recipientUserId}`;
  if (seen.has(key)) {
    return { kind: "dek-wrap-rejected", reason: "duplicate-recipient" };
  }
  seen.add(key);
  return null;
}

function checkWrapRecipients(
  state: ChainState,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
): DataRejection | null {
  if (wraps.length > MAX_DEK_WRAPS_PER_REQUEST) {
    return {
      kind: "limit-exceeded",
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    };
  }
  const seen = new Set<string>();
  for (const wrap of wraps) {
    const rejection = checkOneWrap(state, currentEpoch, wrap, seen);
    if (rejection !== null) {
      return rejection;
    }
  }
  return null;
}

/**
 * エポックごとの集合検査(§12-6): 初回登録(既存ラップなし)は現メンバー集合と
 * 完全一致(受信者検査済みなので個数一致 = 完全)、既存エポックへの追記は
 * 既存 (エポック, 受信者) との重複を拒否する。
 */
const checkWrapSets = (environmentId: string, state: ChainState, wraps: readonly DekWrapInput[]) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const epochs = [...new Set(wraps.map((wrap) => wrap.epoch))];
    for (const epoch of epochs) {
      const epochWraps = wraps.filter((wrap) => wrap.epoch === epoch);
      const existing = yield* store.countWrapsForEpoch(environmentId, epoch);
      if (existing === 0) {
        if (epochWraps.length !== state.members.size) {
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

const validateAndInsertWraps = (
  environmentId: string,
  state: ChainState,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
  nowMs: number,
) =>
  Effect.gen(function* () {
    const rejection = checkWrapRecipients(state, currentEpoch, wraps);
    if (rejection !== null) {
      return yield* rejectData(rejection);
    }
    yield* checkWrapSets(environmentId, state, wraps);
    const store = yield* DataStore;
    for (const wrap of wraps) {
      yield* store.insertWrap(environmentId, wrap, nowMs);
    }
  });

// ---------------------------------------------------------------------------
// 環境管理(§12-4)
// ---------------------------------------------------------------------------

/** 作成不可の理由(§12-1 / §12-4): 現存 = exists、tombstone・チェーン観測済み = retired。 */
function environmentIdUnavailable(
  existing: EnvironmentRow | null,
  state: ChainState,
  environmentId: string,
): DataRejection | null {
  if (existing !== null) {
    const reason = existing.deletedAtMs === null ? "exists" : "retired";
    return { kind: "environment-conflict", environmentId, reason };
  }
  if (state.environmentEpochs.has(environmentId)) {
    return { kind: "environment-conflict", environmentId, reason: "retired" };
  }
  return null;
}

const ensureEnvironmentQuota = Effect.gen(function* () {
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

export const createEnvironmentProgram = (
  actor: DataActor,
  input: { readonly environmentId: string; readonly name: string; readonly deks: readonly DekWrapInput[] },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "member", cache);
    const store = yield* DataStore;
    const existing = yield* store.findEnvironment(input.environmentId);
    const unavailable = environmentIdUnavailable(existing, state, input.environmentId);
    if (unavailable !== null) {
      return yield* rejectData(unavailable);
    }
    yield* ensureEnvironmentQuota;
    if (yield* store.environmentNameTaken(input.name, null)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId: input.environmentId,
        reason: "duplicate-name",
      });
    }
    // 未使用 ID(チェーン未観測)なので現エポックは常に初期値 1(§12-4)
    const now = Date.now();
    yield* validateAndInsertWraps(input.environmentId, state, 1, input.deks, now);
    yield* store.insertEnvironment(input.environmentId, input.name, now);
    const audit = yield* AuditStore;
    yield* audit.append(
      dataEvent(actor, now, "env.created", {
        environmentId: input.environmentId,
        payload: { name: input.name },
      }),
    );
    return {
      environmentId: input.environmentId,
      name: input.name,
      currentEpoch: 1,
    } satisfies EnvironmentSummaryValue;
  });

export const renameEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  name: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    if (yield* store.environmentNameTaken(name, environmentId)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    yield* store.setEnvironmentName(environmentId, name);
    const audit = yield* AuditStore;
    yield* audit.append(
      dataEvent(actor, Date.now(), "env.renamed", { environmentId, payload: { name } }),
    );
  });

export const deleteEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 監査上の存在区間を閉じる: 配下の各変数に var.deleted を先に記録する(§12-4)
    const variables = yield* store.listActiveVariables(environmentId);
    for (const variable of variables) {
      yield* audit.append(
        dataEvent(actor, now, "var.deleted", {
          environmentId,
          variableId: variable.variableId,
        }),
      );
    }
    yield* store.retireEnvironment(environmentId, now);
    yield* audit.append(
      dataEvent(actor, now, "env.deleted", {
        environmentId,
        payload: { name: environment.name },
      }),
    );
  });

export const listEnvironmentsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    const environments = yield* store.listEnvironments;
    return environments.map(
      (environment): EnvironmentSummaryValue => ({
        ...environment,
        currentEpoch: currentEpochOf(state, environment.environmentId),
      }),
    );
  });

// ---------------------------------------------------------------------------
// 変数とバージョニング(§12-5)
// ---------------------------------------------------------------------------

function variableIdUnavailable(
  existing: VariableRow | null,
  variableId: string,
): DataRejection | null {
  if (existing === null) {
    return null;
  }
  const reason = existing.deletedAtMs === null ? "exists" : "retired";
  return { kind: "variable-conflict", variableId, reason };
}

const ensureVariableQuota = (environmentId: string) =>
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

/** バージョン行の書き込み + var.version_pushed の記録(create / push 共通の末尾)。 */
const insertVersionWithAudit = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  nowMs: number,
) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    yield* store.insertVersion(
      environmentId,
      variableId,
      value.version,
      value.epoch,
      value.nonceHex,
      value.ciphertextHex,
      value.ciphertextHex.length / 2,
      nowMs,
    );
    const audit = yield* AuditStore;
    yield* audit.append(
      dataEvent(actor, nowMs, "var.version_pushed", {
        environmentId,
        variableId,
        epoch: value.epoch,
        version: value.version,
      }),
    );
  });

export const createVariableProgram = (
  actor: DataActor,
  environmentId: string,
  input: { readonly variableId: string; readonly name: string; readonly value: ValueInput },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const existing = yield* store.findVariable(environmentId, input.variableId);
    const unavailable = variableIdUnavailable(existing, input.variableId);
    if (unavailable !== null) {
      return yield* rejectData(unavailable);
    }
    yield* ensureVariableQuota(environmentId);
    if (yield* store.variableNameTaken(environmentId, input.name, null)) {
      return yield* rejectData({
        kind: "variable-conflict",
        variableId: input.variableId,
        reason: "duplicate-name",
      });
    }
    // 作成は version 1 の値を同梱する(§12-5)。CAS は latest = 0 相当
    yield* ensureValueCas(state, environmentId, 0, input.value);
    yield* ensureProjectCapacity(input.value.ciphertextHex.length / 2);
    const now = Date.now();
    yield* store.insertVariable(environmentId, input.variableId, input.name, now);
    const audit = yield* AuditStore;
    yield* audit.append(
      dataEvent(actor, now, "var.created", {
        environmentId,
        variableId: input.variableId,
        payload: { name: input.name },
      }),
    );
    yield* insertVersionWithAudit(actor, environmentId, input.variableId, input.value, now);
    return {
      variableId: input.variableId,
      version: input.value.version,
      epoch: input.value.epoch,
    } satisfies VariableVersionValue;
  });

export const pushVersionProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
    if (value.version > MAX_VERSIONS_PER_VARIABLE) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "versions",
        limit: MAX_VERSIONS_PER_VARIABLE,
      });
    }
    yield* ensureProjectCapacity(value.ciphertextHex.length / 2);
    yield* insertVersionWithAudit(actor, environmentId, variableId, value, Date.now());
    return {
      variableId,
      version: value.version,
      epoch: value.epoch,
    } satisfies VariableVersionValue;
  });

export const renameVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  name: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    yield* requireActiveVariable(environmentId, variableId);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    yield* store.setVariableName(environmentId, variableId, name);
    const audit = yield* AuditStore;
    yield* audit.append(
      dataEvent(actor, Date.now(), "var.renamed", {
        environmentId,
        variableId,
        payload: { name },
      }),
    );
  });

export const deleteVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    yield* requireActiveVariable(environmentId, variableId);
    const store = yield* DataStore;
    const now = Date.now();
    yield* store.retireVariable(environmentId, variableId, now);
    const audit = yield* AuditStore;
    yield* audit.append(dataEvent(actor, now, "var.deleted", { environmentId, variableId }));
  });

// ---------------------------------------------------------------------------
// 一括 pull(§12-7)と DEK 配布(§12-6)
// ---------------------------------------------------------------------------

export const pullEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "reader", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const variables = yield* store.latestVersions(environmentId);
    const deks = yield* store.listWrapsForRecipient(environmentId, actor.userId);
    // 監査(AUDIT_SPEC §3.3): 一括 pull は返した変数ごとに var.read を 1 行
    const audit = yield* AuditStore;
    const now = Date.now();
    for (const variable of variables) {
      yield* audit.append(
        dataEvent(actor, now, "var.read", {
          environmentId,
          variableId: variable.variableId,
          epoch: variable.epoch,
          version: variable.version,
        }),
      );
    }
    return {
      environmentId,
      name: environment.name,
      currentEpoch: currentEpochOf(state, environmentId),
      variables,
      deks,
    } satisfies EnvironmentPullValue;
  });

export const registerDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  wraps: readonly DekWrapInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const state = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const currentEpoch = currentEpochOf(state, environmentId);
    yield* validateAndInsertWraps(environmentId, state, currentEpoch, wraps, Date.now());
  });

export const listMyDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    return yield* store.listWrapsForRecipient(environmentId, actor.userId);
  });
