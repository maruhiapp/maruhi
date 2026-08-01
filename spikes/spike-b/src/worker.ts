// スパイク B: 使い捨て検証コード。製品コードではない。
// 検証対象:
//   1. Durable Object 内で ManagedRuntime を構築し、Effect サービス経由で DO SQLite を読み書きする
//   2. Worker の fetch を Effect v4 HttpApi(HttpRouter.toWebHandler)で処理する
//   3. ソース自体は素の Workers API(export default { fetch } + DurableObject クラス)なので、
//      wrangler でも Alchemy v2(Async Worker 形式)でもデプロイできる(ADR-0012 の両対応)

import { DurableObject } from "cloudflare:workers";
import { Context, Effect, FileSystem, Layer, ManagedRuntime, Path } from "effect";
import { Etag, HttpPlatform, HttpRouter } from "effect/unstable/http";
import { HttpApiBuilder } from "effect/unstable/httpapi";

import { spikeApi } from "./api.ts";

export interface Env {
  COUNTER: DurableObjectNamespace<CounterDO>;
}

// ---------------------------------------------------------------------------
// Durable Object: ManagedRuntime パターン
// DO インスタンス生成時に Layer から ManagedRuntime を 1 度だけ構築し、
// 各 RPC メソッドは runtime.runPromise で Effect を実行する。
// ストレージアクセスは Effect サービス(CounterStore)の背後に隔離する
// (ADR-0006 の「リポジトリ層をサービス境界に閉じる」の縮小版)。
// ---------------------------------------------------------------------------

interface CounterStoreShape {
  readonly get: Effect.Effect<number>;
  readonly increment: (by: number) => Effect.Effect<number>;
}

class CounterStore extends Context.Service<CounterStore, CounterStoreShape>()("CounterStore") {}

const counterStoreLayer = (sql: SqlStorage): Layer.Layer<CounterStore> =>
  Layer.sync(CounterStore, () => {
    sql.exec(
      "CREATE TABLE IF NOT EXISTS counter (id INTEGER PRIMARY KEY CHECK (id = 0), value INTEGER NOT NULL)",
    );
    return {
      get: Effect.sync(() => {
        const row = sql.exec("SELECT value FROM counter WHERE id = 0").toArray()[0];
        return row === undefined ? 0 : Number(row["value"]);
      }),
      increment: (by) =>
        Effect.sync(() => {
          const row = sql
            .exec(
              `INSERT INTO counter (id, value) VALUES (0, ?)
               ON CONFLICT (id) DO UPDATE SET value = value + excluded.value
               RETURNING value`,
              by,
            )
            .toArray()[0];
          if (row === undefined) throw new Error("RETURNING row missing");
          return Number(row["value"]);
        }),
    };
  });

export class CounterDO extends DurableObject<Env> {
  readonly #runtime: ManagedRuntime.ManagedRuntime<CounterStore, never>;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#runtime = ManagedRuntime.make(counterStoreLayer(ctx.storage.sql));
  }

  getValue(): Promise<number> {
    return this.#runtime.runPromise(
      Effect.gen(function* () {
        const store = yield* CounterStore;
        return yield* store.get;
      }),
    );
  }

  increment(by: number): Promise<number> {
    return this.#runtime.runPromise(
      Effect.gen(function* () {
        const store = yield* CounterStore;
        return yield* store.increment(by);
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// Worker: HttpApi 実装。env(DO バインディング)は Worker 実行時にしか手に入らないため、
// ハンドラは WorkerEnv サービスを要求し、fetch がリクエストごとの Context として渡す。
// ハンドラ本体(toWebHandler)は isolate ごとに 1 度だけ構築される。
// ---------------------------------------------------------------------------

class WorkerEnv extends Context.Service<WorkerEnv, Env>()("WorkerEnv") {}

const counterGroupLive = HttpApiBuilder.group(spikeApi, "counter", (handlers) =>
  handlers
    .handle("get", ({ params }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const stub = env.COUNTER.get(env.COUNTER.idFromName(params.name));
        const value = yield* Effect.promise(() => stub.getValue());
        return { name: params.name, value };
      }),
    )
    .handle("increment", ({ params, payload }) =>
      Effect.gen(function* () {
        const env = yield* WorkerEnv;
        const stub = env.COUNTER.get(env.COUNTER.idFromName(params.name));
        const value = yield* Effect.promise(() => stub.increment(payload.by));
        return { name: params.name, value };
      }),
    ),
);

// 検証知見: HttpApiBuilder.layer は型上 HttpPlatform / FileSystem / Etag.Generator / Path を
// 要求する(ファイルレスポンス等で使うため。JSON API だけなら実行時には呼ばれない)。
// workerd にはファイルシステムがないので FileSystem.layerNoop で型要求だけ満たす。
const platformContext = Layer.mergeAll(
  HttpPlatform.layer.pipe(Layer.provide(FileSystem.layerNoop({}))),
  FileSystem.layerNoop({}),
  Etag.layer,
  Path.layer,
);

const apiLive = HttpApiBuilder.layer(spikeApi).pipe(
  Layer.provide(counterGroupLive),
  Layer.provide(platformContext),
);

const webHandler = HttpRouter.toWebHandler(apiLive);

export default {
  fetch(request, env): Promise<Response> {
    return webHandler.handler(request, Context.make(WorkerEnv, env));
  },
} satisfies ExportedHandler<Env>;
