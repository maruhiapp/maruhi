// 変数とバージョニングの Effect プログラム(AUTH_SPEC §12-5)。
//
// 判定順(§12-3)と permit 直列化の前提は旧 data-programs.ts のとおり:
// requireMemberState → 環境・変数の存在 → CAS → 署名検証 → 数量ポリシー →
// 原子書き込み + 監査(AUDIT_SPEC §3.3)。

import type { ChainMember } from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type {
  DataActor,
  DataRejection,
  MetaStatementInput,
  ValueInput,
  VariableVersionValue,
} from "./data-plane.ts";
import { dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import type { DataWriteOps, VariableRow } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import { MAX_VERSIONS_PER_VARIABLE } from "./policy.ts";
import {
  ensureProjectCapacity,
  ensureVariableQuota,
  requireActiveEnvironment,
  requireActiveVariable,
} from "./quotas.ts";
import {
  acceptMetaStatement,
  ensureMetaCas,
  ensureMetaStatementSignature,
  ensureNfcName,
} from "./verify-meta.ts";
import { ensureValueCas, ensureValueSignature } from "./verify-value.ts";

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

/**
 * バージョン行の書き込み + var.version_pushed の記録(create / push 共通の末尾)。
 * 同期関数: 呼び出し側の書き込みフェーズ(単一の Effect.sync)内で使う。
 * writer は受理時点のチェーン導出メンバー(値署名の検証に使った鍵の持ち主 —
 * CRYPTO_SPEC §4.1)。監査は chain-derived writer FP のみを写す(AUDIT_SPEC §3.3 —
 * 署名・signed bytes・hash・nonce・暗号文は監査に載せない)。
 *
 * `reencryption` は writer 申告の再暗号化マーカー(AUTH_SPEC §12-5)。true の
 * ときだけ payload に写す(§3.3 — 未申告・false は写さない)。受理判定には
 * 一切関与しない — 読むのは要ローテーション検出の解消導出(§4.1-5)だけ。
 */
function writeVersionWithAudit(
  write: DataWriteOps,
  appendAudit: (event: AuditEventInput) => void,
  actor: DataActor,
  writer: ChainMember,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  reencryption: boolean,
  signedBytesHashHex: string,
  nowMs: number,
): void {
  write.insertVersion(
    environmentId,
    variableId,
    value,
    value.ciphertextHex.length / 2,
    signedBytesHashHex,
    { userId: writer.userId, keyFingerprintHex: writer.keyFingerprintHex },
    nowMs,
  );
  appendAudit(
    dataEvent(actor, nowMs, "var.version_pushed", {
      environmentId,
      variableId,
      epoch: value.epoch,
      version: value.version,
      actorKeyFingerprintHex: writer.keyFingerprintHex,
      ...(reencryption ? { payload: { reencryption: true } } : {}),
    }),
  );
}

export const createVariableProgram = (
  actor: DataActor,
  environmentId: string,
  input: {
    readonly variableId: string;
    readonly statement: MetaStatementInput;
    readonly value: ValueInput;
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const existing = yield* store.findVariable(environmentId, input.variableId);
    const unavailable = variableIdUnavailable(existing, input.variableId);
    if (unavailable !== null) {
      return yield* rejectData(unavailable);
    }
    yield* ensureVariableQuota(environmentId);
    yield* ensureNfcName(input.statement.name);
    if (yield* store.variableNameTaken(environmentId, input.statement.name, null)) {
      return yield* rejectData({
        kind: "variable-conflict",
        variableId: input.variableId,
        reason: "duplicate-name",
      });
    }
    // 作成 = version 1 の値 + metaVersion 1 のステートメントの同梱(§12-5)。
    // ワイヤ Schema が metaVersion 1・active・prev 空を固定するが、CAS は
    // 防衛線として残す(latest = 0 相当)
    yield* ensureMetaCas(0, input.statement);
    yield* ensureValueCas(state, environmentId, 0, input.value);
    // 同梱 version 1 の値・同梱ステートメントとも通常経路と同一の署名検証を
    // 受ける(§12-5 — 作成経由の検証迂回は値・メタとも不可)。判定順:
    // CAS → メタ署名 → 値署名 → 数量ポリシー(裁定 D への挿入)
    const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
      projectId,
      environmentId,
      target: { kind: "variable", variableId: input.variableId },
      history,
      member,
      statement: input.statement,
    });
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId: input.variableId,
      history,
      member,
      value: input.value,
    });
    yield* ensureProjectCapacity(input.value.ciphertextHex.length / 2);
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): 変数行 + ステートメント行 + version 1 +
    // 監査 2 行を原子的に書く(「latest_version = 0 のまま ID だけ占有された
    // 変数」を残さない)
    yield* Effect.sync(() => {
      store.write.insertVariable(environmentId, input.variableId, input.statement.name, now);
      store.write.insertVariableMetaStatement(
        environmentId,
        input.variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      // var.created の FP = 同梱 v1 の writer FP = author FP(同一主体 — §12-5。
      // テストが固定する)
      audit.appendSync(
        dataEvent(actor, now, "var.created", {
          environmentId,
          variableId: input.variableId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
      // 作成は定義上、再暗号化ではない(マーカーの申告面も持たない — §12-5)
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        input.variableId,
        input.value,
        false,
        signedBytesHashHex,
        now,
      );
    });
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
  reencryption: boolean,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
    // 判定順(裁定 D): epoch / version CAS → 値署名(署名 → 宣言 head →
    // head 時点状態 → predecessor)→ 数量ポリシー → 原子書き込み。
    // 不受理時は variable / version / latest / audit のいずれも変更しない
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId,
      history,
      member,
      value,
    });
    if (value.version > MAX_VERSIONS_PER_VARIABLE) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "versions",
        limit: MAX_VERSIONS_PER_VARIABLE,
      });
    }
    yield* ensureProjectCapacity(value.ciphertextHex.length / 2);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        variableId,
        value,
        reencryption,
        signedBytesHashHex,
        now,
      );
    });
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
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
    });
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, "var.renamed", {
          environmentId,
          variableId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // deleted の name は直前 active 名を保持する(§4.2 — byte-exact)
    if (statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
    });
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ: tombstone + 全バージョン削除 + deleted ステートメント行
    // (保存・配布し続ける — §12-5)+ var.deleted(author FP — AUDIT_SPEC §3.3)
    yield* Effect.sync(() => {
      store.write.retireVariable(environmentId, variableId, now);
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, "var.deleted", {
          environmentId,
          variableId,
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });
