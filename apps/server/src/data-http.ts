// データプレーンのハンドラ共通部(AUTH_SPEC §12)。
//
// - DO の DataRejection → api-schema の型付きエラーへの写像
// - 申告 AAD 構成要素と保存先座標の一致検査(§12-2。リクエスト内容のみに依存する
//   自己整合検査であり、存在情報を運ばない)
// - 値サイズの先行検査(§12-8。資源保護は意味論的判定に優先 — §12-3)

import type { EncryptedPayload } from "@maruhi/api-schema";
import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  CompositeRequiredError,
  DataLimitExceededError,
  DekWrapExistsError,
  DekWrapNotFoundError,
  DekWrapRejectedError,
  EnvironmentConflictError,
  EnvironmentNotFoundError,
  EpochConflictError,
  ForbiddenError,
  MetaStatementRejectedError,
  MetaVersionConflictError,
  NameNotNfcError,
  PayloadMismatchError,
  ProjectNotFoundError,
  RotationFlagNotFoundError,
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { TokenPermission } from "@maruhi/core";
import { auditActorOf, RequestAuth } from "@maruhi/core";
import type { Role } from "@maruhi/crypto";
import { Effect, Schema } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";

import { ensureTokenScopeForProject } from "./authz.ts";
import type { ProjectChainDO } from "./chain-do.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejection,
  EnvironmentPullValue,
  MetaStatementInput,
  ValueInput,
} from "./data-plane.ts";
import { roleAtLeast } from "./data-plane.ts";
import { MAX_VALUE_CIPHERTEXT_BYTES } from "./policy.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

/** 204 応答(書き込み系エンドポイント共通)。 */
export const noContent = HttpServerResponse.empty({ status: 204 });

/**
 * EncryptedPayload → DO へ渡す保存入力(座標は検査済み、状態依存部と署名
 * ブロック — CRYPTO_SPEC §4.1 — を運ぶ)。
 */
export function toValueInput(payload: EncryptedPayload): ValueInput {
  return {
    suite: payload.suite,
    epoch: payload.aad.epoch,
    version: payload.aad.version,
    nonceHex: payload.nonceHex,
    ciphertextHex: payload.ciphertextHex,
    prevValueSigHashHex: payload.prevValueSigHashHex,
    chainHeadHashHex: payload.chainHeadHashHex,
    chainHeadSeq: payload.chainHeadSeq,
    signatureHex: payload.signatureHex,
  };
}

/** §12-8: 値の暗号文サイズの先行検査(hex は 1 バイト = 2 文字)。 */
export function checkValueSize(payload: EncryptedPayload): Effect.Effect<void, ValueTooLargeError> {
  return payload.ciphertextHex.length / 2 > MAX_VALUE_CIPHERTEXT_BYTES
    ? Effect.fail(new ValueTooLargeError({ limitBytes: MAX_VALUE_CIPHERTEXT_BYTES }))
    : Effect.void;
}

interface AadCoordinates {
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
}

function aadMismatchField(payload: EncryptedPayload, coordinates: AadCoordinates): string | null {
  if (payload.aad.projectId !== coordinates.projectId) {
    return "projectId";
  }
  if (payload.aad.environmentId !== coordinates.environmentId) {
    return "environmentId";
  }
  if (payload.aad.variableId !== coordinates.variableId) {
    return "variableId";
  }
  return null;
}

/**
 * §12-2: 申告 AAD の座標成分(project / environment / variable)とリクエストの
 * 保存先座標の一致検査。epoch / version は状態依存のため DO 側で検査する。
 */
export function checkAadCoordinates(
  payload: EncryptedPayload,
  coordinates: AadCoordinates,
): Effect.Effect<void, PayloadMismatchError> {
  const field = aadMismatchField(payload, coordinates);
  return field === null ? Effect.void : Effect.fail(new PayloadMismatchError({ field }));
}

/**
 * ステートメント申告座標とリクエスト保存先座標の一致検査(§12-5 の座標再構成の
 * 前提)。DO は URL / 保存先から署名対象を再構成するため、不一致な申告はどのみち
 * 署名検証で落ちるが、AAD 座標検査(§12-2 の 1a)と同じくリクエスト内容のみに
 * 依存する自己整合検査として worker で先行拒否し、食い違った座標を可視化する。
 */
export function checkStatementCoordinates(
  statement: { readonly environmentId: string; readonly variableId?: string },
  coordinates: { readonly environmentId: string; readonly variableId?: string },
): Effect.Effect<void, PayloadMismatchError> {
  if (statement.environmentId !== coordinates.environmentId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementEnvironmentId" }));
  }
  if (coordinates.variableId !== undefined && statement.variableId !== coordinates.variableId) {
    return Effect.fail(new PayloadMismatchError({ field: "statementVariableId" }));
  }
  return Effect.void;
}

/** ワイヤのステートメント → DO へ渡す保存入力(座標は検査済み)。 */
export function toMetaStatementInput(statement: {
  readonly suite: "maruhi/v1";
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly metaVersion: number;
  readonly prevMetaSigHashHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}): MetaStatementInput {
  return {
    suite: statement.suite,
    name: statement.name,
    status: statement.status,
    metaVersion: statement.metaVersion,
    prevMetaSigHashHex: statement.prevMetaSigHashHex,
    chainHeadHashHex: statement.chainHeadHashHex,
    chainHeadSeq: statement.chainHeadSeq,
    signatureHex: statement.signatureHex,
  };
}

/**
 * DO の保存行 → ワイヤの DistributedEncryptedPayload(§12-2 / §12-7)。AAD は
 * 保存座標から再構成する(保存時に座標一致を検査済みなので、これは同値の
 * 自己記述表現)。suite は保存行の値を返す(CRYPTO_SPEC §2 設計原則 4)。
 * 署名ブロックと writer / ステートメント + author(受理時点の user_id + 鍵 FP)は
 * 保存行をそのまま返す — 現メンバー集合から再導出しない(削除済み writer /
 * author の過去データの検証可能性)。サーバー再計算の signed_bytes ハッシュは
 * 値・ステートメントとも配布しない。
 */
export function toWireVariable(
  projectId: string,
  environmentId: string,
  row: EnvironmentPullValue["variables"][number],
) {
  return {
    variableId: row.variableId,
    statement: row.statement,
    value: {
      suite: row.suite,
      aad: {
        projectId,
        environmentId,
        epoch: row.epoch,
        variableId: row.variableId,
        version: row.version,
      },
      nonceHex: row.nonceHex,
      ciphertextHex: row.ciphertextHex,
      prevValueSigHashHex: row.prevValueSigHashHex,
      chainHeadHashHex: row.chainHeadHashHex,
      chainHeadSeq: row.chainHeadSeq,
      signatureHex: row.signatureHex,
      writerUserId: row.writerUserId,
      writerKeyFingerprintHex: row.writerKeyFingerprintHex,
    },
  };
}

// ---------------------------------------------------------------------------
// DataRejection → 型付きエラー
// ---------------------------------------------------------------------------

type DataApiError =
  | ProjectNotFoundError
  | ForbiddenError
  | EnvironmentNotFoundError
  | EnvironmentConflictError
  | CompositeRequiredError
  | ChainHeadConflictError
  | ChainEntryInvalidError
  | ChainEntryTooLargeError
  | ChainCapacityExceededError
  | PayloadMismatchError
  | VariableNotFoundError
  | VariableConflictError
  | VersionConflictError
  | EpochConflictError
  | ValueSignatureRejectedError
  | MetaStatementRejectedError
  | MetaVersionConflictError
  | NameNotNfcError
  | DekWrapRejectedError
  | DekWrapExistsError
  | DekWrapNotFoundError
  | RotationFlagNotFoundError
  | DataLimitExceededError;

// kind ごとの小さな写像(§11-2: 未初期化と非メンバーは区別せず 404 に畳む)。
// satisfies で網羅性を強制しつつ kind ごとの戻り値型を保つ(dataRejectionError の
// 呼び出し側 — handlers-membership.ts のチェーン系写像 — が精密なエラー union を
// 受け取れるように)
const rejectionErrors = {
  "not-initialized": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "not-member": (_rejection, projectId) => new ProjectNotFoundError({ projectId }),
  "insufficient-role": () => new ForbiddenError({ reason: "insufficient-role" }),
  "environment-not-found": (rejection) =>
    new EnvironmentNotFoundError({ environmentId: rejection.environmentId }),
  "environment-conflict": (rejection) =>
    new EnvironmentConflictError({
      environmentId: rejection.environmentId,
      reason: rejection.reason,
    }),
  // チェーン受理系(複合リクエスト §12-4 と汎用チェーン API の共有)
  "composite-required": (rejection) => new CompositeRequiredError({ op: rejection.op }),
  "chain-head-conflict": (rejection) =>
    new ChainHeadConflictError({
      currentHeadSeq: rejection.currentHeadSeq,
      currentHeadHashHex: rejection.currentHeadHashHex,
    }),
  "chain-entry-invalid": (rejection) =>
    new ChainEntryInvalidError({ seq: rejection.seq, reason: rejection.reason }),
  "chain-entry-too-large": (rejection) =>
    new ChainEntryTooLargeError({ limitBytes: rejection.limitBytes }),
  "chain-capacity-exceeded": (rejection) =>
    new ChainCapacityExceededError({
      maxEntries: rejection.maxEntries,
      maxTotalBytes: rejection.maxTotalBytes,
    }),
  "payload-mismatch": (rejection) => new PayloadMismatchError({ field: rejection.field }),
  "variable-not-found": (rejection) =>
    new VariableNotFoundError({ variableId: rejection.variableId }),
  "variable-conflict": (rejection) =>
    new VariableConflictError({ variableId: rejection.variableId, reason: rejection.reason }),
  "version-conflict": (rejection) =>
    new VersionConflictError({ currentVersion: rejection.currentVersion }),
  "epoch-conflict": (rejection) => new EpochConflictError({ currentEpoch: rejection.currentEpoch }),
  "value-rejected": (rejection) => new ValueSignatureRejectedError({ reason: rejection.reason }),
  "meta-rejected": (rejection) => new MetaStatementRejectedError({ reason: rejection.reason }),
  "meta-version-conflict": (rejection) =>
    new MetaVersionConflictError({ currentMetaVersion: rejection.currentMetaVersion }),
  "name-not-nfc": () => new NameNotNfcError(),
  "dek-wrap-rejected": (rejection) => new DekWrapRejectedError({ reason: rejection.reason }),
  "dek-wrap-exists": (rejection) =>
    new DekWrapExistsError({
      epoch: rejection.epoch,
      recipientUserId: rejection.recipientUserId,
      // 占有ラップの保存済み受信者 enc 公開鍵(AUTH_SPEC §12-6 — 2026-08-15)
      storedRecipientEncPubHex: rejection.storedRecipientEncPubHex,
    }),
  "dek-wrap-not-found": (rejection) =>
    new DekWrapNotFoundError({
      epoch: rejection.epoch,
      recipientUserId: rejection.recipientUserId,
    }),
  "rotation-flag-not-found": (rejection) =>
    new RotationFlagNotFoundError({
      environmentId: rejection.environmentId,
      variableId: rejection.variableId,
    }),
  "limit-exceeded": (rejection) =>
    new DataLimitExceededError({ resource: rejection.resource, limit: rejection.limit }),
} satisfies {
  readonly [K in DataRejection["kind"]]: (
    rejection: Extract<DataRejection, { kind: K }>,
    projectId: string,
  ) => DataApiError;
};

/**
 * DataRejection → api-schema の型付きエラー(kind ごとの写像の唯一の置き場所)。
 * チェーン API ハンドラ(handlers-membership.ts)も RPC outcome の kind を
 * DataRejection の kind に揃えたうえでここを通す(写像の二重管理をしない)。
 */
export function dataRejectionError<K extends DataRejection["kind"]>(
  rejection: Extract<DataRejection, { kind: K }>,
  projectId: string,
): ReturnType<(typeof rejectionErrors)[K]> {
  return rejectionErrors[rejection.kind](rejection as never, projectId) as ReturnType<
    (typeof rejectionErrors)[K]
  >;
}

/**
 * エンドポイント契約(HttpApiEndpoint の error 宣言)のうち、DO 拒否の写像
 * (rejectionErrors)として現れうるエラー型。契約宣言に含まれる worker 先行検査
 * 専用のエラー(ValueTooLarge 等)は DataRejection から生成されないため除く。
 */
type ContractDataError<Endpoint extends HttpApiEndpoint.Top> = Extract<
  HttpApiEndpoint.Error<Endpoint>["Type"],
  DataApiError
>;

// endpoint.error(宣言 Schema の集合。HttpApiEndpoint の公開プロパティ)から
// 構成した「エラー値が契約に含まれるか」の判定列。エンドポイントはビルド時に
// 固定される値なのでエンドポイントごとに 1 回だけ構成すればよい
const contractFilters = new WeakMap<object, ReadonlyArray<(error: DataApiError) => boolean>>();

function contractFilterOf(
  endpoint: HttpApiEndpoint.Top,
): ReadonlyArray<(error: DataApiError) => boolean> {
  let filters = contractFilters.get(endpoint);
  if (filters === undefined) {
    filters = Array.from(endpoint.error, (schema) => Schema.is(schema));
    contractFilters.set(endpoint, filters);
  }
  return filters;
}

/**
 * DO の outcome をハンドラの成功値 / 型付きエラーへ写す。返してよいエラーの
 * 集合はエンドポイントの契約宣言(api-schema の error: [...])そのものから
 * 実行時(endpoint.error の Schema 判定)・型(Error 型引数)の両面で導出する
 * ため、宣言と写像がズレることはない。契約外の拒否はプログラム側の不変条件
 * 違反として defect(500)に落とす。テストから直接検証できるよう公開する。
 */
export function unwrapDataOutcome<T, Endpoint extends HttpApiEndpoint.Top>(
  outcome: DataOutcome<T>,
  projectId: string,
  endpoint: Endpoint,
): Effect.Effect<T, ContractDataError<Endpoint>> {
  if (outcome.kind === "ok") {
    return Effect.succeed(outcome.value);
  }
  const error = dataRejectionError(outcome.rejection, projectId);
  return contractFilterOf(endpoint).some((allows) => allows(error))
    ? Effect.fail(error as ContractDataError<Endpoint>)
    : Effect.die(error);
}

/**
 * データプレーンのハンドラ共通経路(§12-3 の判定順): 認証主体の解決 →
 * トークンスコープ(スコープ外 404 / 水準不足 403)→ DO RPC → outcome の写像。
 * ハンドラ固有の先行検査(値サイズ・AAD 座標)は呼び出し側がこの前に行う。
 *
 * `endpoint` にはハンドラ引数の endpoint(処理中のエンドポイントそのもの)を
 * 渡す。契約上返しうるエラーはそこから導出されるため、手書きの列挙は無い。
 * カリー形なのは「T(RPC の値型)は明示、Endpoint は推論」を両立させるため
 * (TS は型引数の部分適用を許さない)。
 */
export const callProjectData =
  <T>() =>
  <Endpoint extends HttpApiEndpoint.Top>(options: {
    readonly endpoint: Endpoint;
    readonly projectId: string;
    readonly permission: TokenPermission;
    readonly invoke: (
      stub: DurableObjectStub<ProjectChainDO>,
      actor: DataActor,
    ) => PromiseLike<unknown>;
  }) =>
    Effect.gen(function* () {
      const principal = yield* (yield* RequestAuth).principal;
      yield* ensureTokenScopeForProject(principal, options.projectId, options.permission);
      const env = yield* WorkerEnv;
      const outcome = yield* rpcCall<DataOutcome<T>>(() =>
        options.invoke(projectStub(env, options.projectId), auditActorOf(principal)),
      );
      return yield* unwrapDataOutcome(outcome, options.projectId, options.endpoint);
    });

/**
 * D1 バックのプロジェクト配下エンドポイント共通の前段(招待 API — AUTH_SPEC
 * §15-2 — と invite.* 監査読み取り — AUDIT_SPEC §7 — が共用): トークンスコープ
 * admin(スコープ外 404 — §11-2)→ DO の memberRoleFor(非メンバー 404)→
 * チェーン role admin 以上(未満 403)。通過したら呼び出し主体と role を返す
 * (owner 限定判定用)。
 */
export const requireProjectChainAdmin = <Endpoint extends HttpApiEndpoint.Top>(
  projectId: string,
  endpoint: Endpoint,
) =>
  Effect.gen(function* () {
    const principal = yield* (yield* RequestAuth).principal;
    yield* ensureTokenScopeForProject(principal, projectId, "admin");
    const env = yield* WorkerEnv;
    const outcome = yield* rpcCall<DataOutcome<Role>>(() =>
      projectStub(env, projectId).memberRoleFor(principal.userId),
    );
    const role = yield* unwrapDataOutcome(outcome, projectId, endpoint);
    if (!roleAtLeast(role, "admin")) {
      return yield* Effect.fail(new ForbiddenError({ reason: "insufficient-role" }));
    }
    return { principal, role };
  });
