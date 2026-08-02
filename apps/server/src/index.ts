// @maruhi/server — Workers + DO。Effect v4 HttpApi(ADR-0005)。
// サーバーコードは Web 標準 + Workers API のみ。Bun 固有 API(bun:*)は使用禁止。
//
// ソースは素の Workers API(export default { fetch } + DurableObject クラス)の
// まま内部を Effect で実装する(ADR-0012: wrangler / Alchemy v2 両対応)。

import {
  ChainCapacityExceededError,
  ChainEntryInvalidError,
  ChainEntryTooLargeError,
  ChainHeadConflictError,
  maruhiApi,
  ProjectAlreadyInitializedError,
  ProjectNotFoundError,
} from "@maruhi/api-schema";
import { computeChainEntryHash } from "@maruhi/crypto";
import { Context, Effect, FileSystem, Layer, Path } from "effect";
import { Etag, HttpPlatform, HttpRouter } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { RequestAuth, unauthenticatedRequestAuth } from "./auth.ts";
import type {
  AppendOutcome,
  Env,
  InitOutcome,
  ProjectChainDO,
  SnapshotOutcome,
} from "./chain-do.ts";
import { MAX_REQUEST_BODY_BYTES } from "./policy.ts";

export { ProjectChainDO } from "./chain-do.ts";
export type { Env } from "./chain-do.ts";

class WorkerEnv extends Context.Service<WorkerEnv, Env>()("WorkerEnv") {}

const projectStub = (env: Env, projectId: string): DurableObjectStub<ProjectChainDO> =>
  env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));

// workers-types の RPC スタブ型は union 戻り値をメンバーごとの Promise 交差型に
// 分配してしまうため、DO メソッドの宣言どおりの Promise<Outcome> へ戻す
const rpcCall = <T>(call: () => PromiseLike<unknown>): Effect.Effect<T> =>
  Effect.promise(() => call() as Promise<T>);

// RPC 境界の outcome → api-schema の型付きエラー / 成功レスポンスへの写像。
// "project-id-mismatch" は worker が自分で計算した ID を渡す限り起こらない
// (起きたら実装バグなので defect として落とす)

type PolicyRejection = Extract<
  AppendOutcome,
  { kind: "chain-invalid" | "entry-too-large" | "capacity-exceeded" }
>;

/** init / append に共通する受理拒否(検証失敗・サイズ / 累積上限)の写像。 */
function policyFailure(
  outcome: Extract<PolicyRejection, { kind: "chain-invalid" | "entry-too-large" }>,
): ChainEntryInvalidError | ChainEntryTooLargeError;
function policyFailure(
  outcome: PolicyRejection,
): ChainEntryInvalidError | ChainEntryTooLargeError | ChainCapacityExceededError;
function policyFailure(outcome: PolicyRejection) {
  switch (outcome.kind) {
    case "chain-invalid":
      return new ChainEntryInvalidError({ seq: outcome.seq, reason: outcome.reason });
    case "entry-too-large":
      return new ChainEntryTooLargeError({ limitBytes: outcome.limitBytes });
    case "capacity-exceeded":
      return new ChainCapacityExceededError({
        maxEntries: outcome.maxEntries,
        maxTotalBytes: outcome.maxTotalBytes,
      });
  }
}

const mapInitOutcome = (projectId: string, outcome: InitOutcome) => {
  switch (outcome.kind) {
    case "initialized":
      return Effect.succeed({
        projectId,
        headSeq: outcome.headSeq,
        headHashHex: outcome.headHashHex,
      });
    case "already-initialized":
      return Effect.fail(new ProjectAlreadyInitializedError({ projectId }));
    case "project-id-mismatch":
      return Effect.die(new Error("project id mismatch between worker and DO"));
    default:
      return Effect.fail(policyFailure(outcome));
  }
};

const mapAppendOutcome = (projectId: string, outcome: AppendOutcome) => {
  switch (outcome.kind) {
    case "appended":
      return Effect.succeed({
        projectId,
        headSeq: outcome.headSeq,
        headHashHex: outcome.headHashHex,
      });
    case "not-initialized":
      return Effect.fail(new ProjectNotFoundError({ projectId }));
    case "head-conflict":
      return Effect.fail(
        new ChainHeadConflictError({
          currentHeadSeq: outcome.currentHeadSeq,
          currentHeadHashHex: outcome.currentHeadHashHex,
        }),
      );
    default:
      return Effect.fail(policyFailure(outcome));
  }
};

const membershipLive = HttpApiBuilder.group(maruhiApi, "membership", (handlers) =>
  handlers
    .handle("init", ({ payload }) =>
      Effect.gen(function* () {
        // 認証境界(auth.ts)。既知の制約: 主体は認可判定に未使用 — 追記系の保護は
        // チェーン署名の検証のみ(認証セッションで置き換わる)
        yield* (yield* RequestAuth).principal;
        const env = yield* WorkerEnv;
        // プロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4)。
        // DO 側で検証・再計算との一致を確認した上で保存される
        const projectId = yield* Effect.promise(() => computeChainEntryHash(payload.entry));
        const outcome = yield* rpcCall<InitOutcome>(() =>
          projectStub(env, projectId).init(projectId, payload.entry),
        );
        return yield* mapInitOutcome(projectId, outcome);
      }),
    )
    .handle("get", ({ params }) =>
      Effect.gen(function* () {
        yield* (yield* RequestAuth).principal;
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<SnapshotOutcome>(() =>
          projectStub(env, params.projectId).snapshot(),
        );
        if (outcome.kind === "not-initialized") {
          return yield* Effect.fail(new ProjectNotFoundError({ projectId: params.projectId }));
        }
        return {
          projectId: params.projectId,
          entries: outcome.entries,
          headSeq: outcome.headSeq,
          headHashHex: outcome.headHashHex,
        };
      }),
    )
    .handle("append", ({ params, payload }) =>
      Effect.gen(function* () {
        yield* (yield* RequestAuth).principal;
        const env = yield* WorkerEnv;
        const outcome = yield* rpcCall<AppendOutcome>(() =>
          projectStub(env, params.projectId).append(payload.parentHeadHashHex, payload.entry),
        );
        return yield* mapAppendOutcome(params.projectId, outcome);
      }),
    ),
);

// spike-b の検証知見: HttpApiBuilder.layer は型上 HttpPlatform / FileSystem /
// Etag.Generator / Path を要求する(JSON API だけなら実行時には呼ばれない)。
// workerd には FS がないので FileSystem.layerNoop で型要求だけ満たす
const platformContext = Layer.mergeAll(
  HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
  FileSystem.layerNoop({}),
  Etag.layer,
  Path.layer,
);

const apiLive = HttpApiBuilder.layer(maruhiApi).pipe(
  Layer.provide(membershipLive),
  Layer.provide(platformContext),
);

const webHandler = HttpRouter.toWebHandler(apiLive);

export default {
  fetch(request, env): Promise<Response> | Response {
    // HTTP 境界の生ボディ上限(policy.ts)。JSON パース前のメモリ DoS 防御なので、
    // スキーマ外の素の 413 で返す(正規化バイト列基準の受理判定は DO 内で行う)
    const contentLength = Number(request.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      return new Response(null, { status: 413 });
    }
    const requestContext = Context.make(WorkerEnv, env).pipe(
      Context.add(RequestAuth, unauthenticatedRequestAuth),
    );
    return webHandler.handler(request, requestContext);
  },
} satisfies ExportedHandler<Env>;
