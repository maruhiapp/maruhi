// 環境管理と一括 pull の Effect プログラム(AUTH_SPEC §12-4 / §12-7)。
// 作成・ローテーションは複合リクエスト(composite-programs.ts)。
//
// 判定順(§12-3)と permit 直列化の前提は旧 data-programs.ts のとおり:
// requireMemberState → 環境の存在 → 意味論的検査 → 数量ポリシー → 原子書き込み。

import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type {
  DataActor,
  EnvironmentListValue,
  EnvironmentMetadataPullValue,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  EnvManifestInput,
  MetaStatementInput,
} from "./data-plane.ts";
import {
  currentEpochOf,
  dataEvent,
  optionalDistributionFields,
  rejectData,
  requireMemberState,
} from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { requireActiveEnvironment } from "./quotas.ts";
import { acceptManifestForMetaOp } from "./verify-manifest.ts";
import { acceptMetaStatement, ensureNfcName } from "./verify-meta.ts";

export const renameEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  manifest: EnvManifestInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.environmentNameTaken(statement.name, environmentId)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    // 判定順(値の裁定 D と同型): 上限 → CAS → ステートメント署名 →
    // マニフェスト受理 → 原子書き込み
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "environment" },
      latestMetaVersion: environment.latestMetaVersion,
      history,
      member,
      statement,
    });
    // マニフェストの複合受理(§12-4 / §12-5): 環境 rename は新しい
    // envMetaSigHashHex を写したマニフェスト(manifestVersion + 1)を同梱する。
    // envMeta の期待値は rename 適用後 = 今回のステートメント自身
    const acceptedManifest = yield* acceptManifestForMetaOp({
      projectId,
      environmentId,
      history,
      member,
      manifest,
      digestOverride: null,
      envMeta: { metaVersion: statement.metaVersion, sigHashHex: signedBytesHashHex },
    });
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      acceptedManifest.writeSync(now);
      audit.appendSync(
        dataEvent(actor, now, "env.renamed", {
          environmentId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    // 受理時点 admin(§12-3)。宣言ヘッド時点 admin は署名検証(§12-3 の
    // 二重判定 — env × deleted の必要 role)が検査する
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "admin", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    // deleted の name は直前 active 名を保持する(§4.2 — byte-exact)
    if (statement.name !== environment.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "environment" },
      latestMetaVersion: environment.latestMetaVersion,
      history,
      member,
      statement,
    });
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    const variables = yield* store.listActiveVariables(environmentId);
    // 書き込みフェーズ(単一タスク): tombstone + データ削除 + deleted ステート
    // メント行と、存在区間を閉じる変数ごとの var.deleted(§12-4)+ env.deleted を
    // 原子的に書く。カスケード削除される変数は個別のステートメントを持たない
    // ため、var.deleted の FP は環境削除ステートメントの author FP を写す
    // (「FP = 署名の証跡」の意味論 — この削除を認可した署名は env 側にある)
    yield* Effect.sync(() => {
      store.write.retireEnvironment(environmentId, now);
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendManySync([
        ...variables.map((variable) =>
          dataEvent(actor, now, "var.deleted", {
            environmentId,
            variableId: variable.variableId,
            actorKeyFingerprintHex: member.keyFingerprintHex,
          }),
        ),
        dataEvent(actor, now, "env.deleted", {
          environmentId,
          payload: { name: environment.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      ]);
    });
  });

export const listEnvironmentsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    const environments = yield* store.listEnvironmentStatements;
    // 削除済み環境もチェーン上に create_environment を持つ(チェーンは削除を
    // 観測しない — §6.2)ため、currentEpochOf は全行で導出可能
    return {
      environments: environments.map((environment): EnvironmentSummaryValue => ({
        environmentId: environment.environmentId,
        currentEpoch: currentEpochOf(state, environment.environmentId),
        statement: environment.statement,
      })),
      // schemaPolicy の advisory 同梱(§12-7 / §12-11 — 検証規則の入力にしない)
      schemaPolicy: yield* store.schemaPolicy,
    } satisfies EnvironmentListValue;
  });

/**
 * pull 系(値付き・メタデータのみ)共通の前段: reader 認可・環境の存在・
 * 環境自身の最新ステートメント(§12-7 の検証材料の同梱)。環境行はステート
 * メントと原子的に作られる(複合受理)ため、欠落は不変条件違反 = defect。
 */
const requirePullContext = (actor: DataActor, environmentId: string, cache: StateCache) =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const statement = yield* store.environmentStatement(environmentId);
    if (statement === null) {
      return yield* Effect.die(new Error("environment meta statement row missing"));
    }
    // 最新マニフェスト(§12-7 の同梱材料 — 2026-08-18)。null はマニフェスト
    // 導入前に作成された環境の移行完了までの過渡状態のみ(初期化後の環境は
    // 全メタ操作 / rotate が原子的に upsert するため必ず存在する)
    const manifest = yield* store.environmentManifest(environmentId);
    return { state, store, statement, manifest };
  });

export const pullEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, store, statement, manifest } = yield* requirePullContext(
      actor,
      environmentId,
      cache,
    );
    const variables = yield* store.latestVersions(environmentId);
    // 削除済み変数の deleted ステートメントも配布し続ける(§12-5 — 削除の
    // 否認・無断復活の検出材料。暗号文は削除済みなので値は伴わない)
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    // declared 変数はステートメントのみ配布する(§12-7 — 値・バージョンは
    // 存在しない。マニフェストのダイジェスト再計算の材料として必須)
    const declaredVariables = yield* store.declaredVariableStatements(environmentId);
    const deks = yield* store.listWrapsForRecipient(environmentId, actor.userId);
    // チェックポイント時点の値スナップショット(§12-7 — 2026-08-28 PR-M3):
    // 当該環境を含む最新 checkpoint の保存行(§16-2)があれば必ず同梱する。
    // クライアント規則 2(CRYPTO_SPEC §6.3)は基準あり + 列挙なしを拒否する
    const checkpointSnapshot = yield* store.checkpointSnapshot(environmentId);
    // 監査(AUDIT_SPEC §3.3): 一括 pull は返した変数ごとに var.read を 1 行
    // (返した行に対して記録するため、行とイベントは常に一致する)
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      audit.appendManySync(
        variables.map((variable) =>
          dataEvent(actor, now, "var.read", {
            environmentId,
            variableId: variable.variableId,
            epoch: variable.epoch,
            version: variable.version,
          }),
        ),
      );
    });
    return {
      environmentId,
      currentEpoch: currentEpochOf(state, environmentId),
      statement,
      variables,
      deletedVariables,
      // declared 変数が無ければキー自体を置かない(optionalKey のワイヤ形)
      ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
      deks,
      schemaPolicy: yield* store.schemaPolicy,
      ...optionalDistributionFields(manifest, checkpointSnapshot),
    } satisfies EnvironmentPullValue;
  });

/**
 * メタデータのみモード(§12-7 — 2026-08-10): 値(暗号文)と DEK を返さず、
 * §6.3 のメタ検証材料のみ返す。認可は一括 pull と同一(reader)。監査は
 * **何も記録しない** — var.read の記録条件は暗号文の配布であり、読んでいない
 * ものを読んだと記録しない(AUDIT_SPEC §3.3)。
 */
export const pullEnvironmentMetadataProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, store, statement, manifest } = yield* requirePullContext(
      actor,
      environmentId,
      cache,
    );
    // declared 変数のステートメントも variables に載る(削除済みでない全変数の
    // 最新形 — §12-7。status が判別を担う)
    const variables = yield* store.activeVariableStatements(environmentId);
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    return {
      environmentId,
      currentEpoch: currentEpochOf(state, environmentId),
      statement,
      variables,
      deletedVariables,
      schemaPolicy: yield* store.schemaPolicy,
      ...(manifest === null ? {} : { manifest }),
    } satisfies EnvironmentMetadataPullValue;
  });
