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
import { canonicalChainEntryBytes, computeChainEntryHash } from "@maruhi/crypto";
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
import { MAX_ENTRY_CANONICAL_BYTES, MAX_REQUEST_BODY_BYTES } from "./policy.ts";

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
        // DO へ渡す前に worker 側でも受理ポリシーを先行検査する: サイズ超過エントリの
        // ハッシュ計算・DO 転送を避け、エンコーダの例外は 5xx でなく 422 に落とす
        // (受理判定の権威は引き続き DO — ここは前段の資源保護)
        const canonicalBytes = yield* Effect.try({
          try: () => canonicalChainEntryBytes(payload.entry).length,
          catch: () =>
            new ChainEntryInvalidError({ seq: payload.entry.seq, reason: "invalid-payload" }),
        });
        if (canonicalBytes > MAX_ENTRY_CANONICAL_BYTES) {
          return yield* Effect.fail(
            new ChainEntryTooLargeError({ limitBytes: MAX_ENTRY_CANONICAL_BYTES }),
          );
        }
        // プロジェクト ID = genesis エントリハッシュ(CRYPTO_SPEC §6.4)。
        // DO 側で検証・再計算との一致を確認した上で保存される
        const projectId = yield* Effect.tryPromise({
          try: () => computeChainEntryHash(payload.entry),
          catch: () =>
            new ChainEntryInvalidError({ seq: payload.entry.seq, reason: "invalid-payload" }),
        });
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

/** チャンク列を 1 本のバイト列へ連結する。 */
function concatChunks(chunks: readonly Uint8Array[], total: number): Uint8Array {
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/**
 * ストリームを上限までバッファして返す(超過は null)。Content-Length は
 * クライアント申告値であり信用できない(欠落・偽装・chunked)ため、上限は
 * 実測で強制する。
 */
async function readStreamWithinLimit(
  stream: ReadableStream<Uint8Array>,
  limitBytes: number,
): Promise<Uint8Array | null> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return concatChunks(chunks, total);
    }
    total += value.length;
    if (total > limitBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
}

/** Content-Length 申告値による安価な事前棄却(ヘッダー欠落は 0 扱い = 通す)。 */
function declaredLengthExceedsCap(request: Request): boolean {
  const declared = Number(request.headers.get("content-length"));
  return Number.isFinite(declared) && declared > MAX_REQUEST_BODY_BYTES;
}

/**
 * HTTP 境界の生ボディ上限(policy.ts)。JSON パース前のメモリ DoS 防御。
 * 超過は null(呼び出し側がスキーマ外の素の 413 で返す)。上限内のボディは
 * バッファ済みバイト列に置き換えて後段(JSON パース)へ渡す。
 */
async function capRequestBody(request: Request): Promise<Request | null> {
  if (declaredLengthExceedsCap(request)) {
    return null;
  }
  if (request.body === null) {
    return request;
  }
  const body = await readStreamWithinLimit(request.body, MAX_REQUEST_BODY_BYTES);
  if (body === null) {
    return null;
  }
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body: body.buffer as ArrayBuffer,
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const cappedRequest = await capRequestBody(request);
    if (cappedRequest === null) {
      return new Response(null, { status: 413 });
    }
    const requestContext = Context.make(WorkerEnv, env).pipe(
      Context.add(RequestAuth, unauthenticatedRequestAuth),
    );
    return webHandler.handler(cappedRequest, requestContext);
  },
} satisfies ExportedHandler<Env>;
