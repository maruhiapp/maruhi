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
  ValueSignatureRejectedError,
  ValueTooLargeError,
  VariableConflictError,
  VariableNotFoundError,
  VersionConflictError,
} from "@maruhi/api-schema";
import type { AuthenticatedPrincipal, TokenPermission } from "@maruhi/core";
import { RequestAuth } from "@maruhi/core";
import { Effect, Schema } from "effect";
import { HttpServerResponse } from "effect/unstable/http";
import type { HttpApiEndpoint } from "effect/unstable/httpapi";

import { ensureTokenScopeForProject } from "./authz.ts";
import type { ProjectChainDO } from "./chain-do.ts";
import type {
  DataActor,
  DataOutcome,
  DataRejection,
  MetaStatementInput,
  ValueInput,
} from "./data-plane.ts";
import { MAX_VALUE_CIPHERTEXT_BYTES } from "./policy.ts";
import { projectStub, rpcCall, WorkerEnv } from "./worker-env.ts";

/** 204 応答(書き込み系エンドポイント共通)。 */
export const noContent = HttpServerResponse.empty({ status: 204 });

/** 認証主体 → 監査アクター(AUDIT_SPEC §2)。 */
function dataActorOf(principal: AuthenticatedPrincipal): DataActor {
  return principal.kind === "token"
    ? { userId: principal.userId, apiTokenId: principal.tokenId }
    : { userId: principal.userId, authMethod: principal.authMethod };
}

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

// ---------------------------------------------------------------------------
// DataRejection → 型付きエラー
// ---------------------------------------------------------------------------

type DataApiError =
  | ProjectNotFoundError
  | ForbiddenError
  | EnvironmentNotFoundError
  | EnvironmentConflictError
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
  // 複合リクエスト(§12-4)のチェーン受理系(エラー契約の複合エンドポイントへの移動)
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
    new DekWrapExistsError({ epoch: rejection.epoch, recipientUserId: rejection.recipientUserId }),
  "dek-wrap-not-found": (rejection) =>
    new DekWrapNotFoundError({
      epoch: rejection.epoch,
      recipientUserId: rejection.recipientUserId,
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
        options.invoke(projectStub(env, options.projectId), dataActorOf(principal)),
      );
      return yield* unwrapDataOutcome(outcome, options.projectId, options.endpoint);
    });
