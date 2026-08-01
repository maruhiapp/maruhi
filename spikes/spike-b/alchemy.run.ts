// スパイク B: Alchemy v2(Effect スタイル)でのデプロイ定義(ADR-0012 の運用側経路)。
// ポイント: Worker 実装は素の Workers API(src/worker.ts)のまま、Alchemy の
// 「Async Worker」形式(実装 Effect を渡さず main を指すだけ)で包む。
// これにより同一ソースを wrangler.jsonc(セルフホスト経路)と本ファイル(運用経路)の
// 両方からデプロイできる。実デプロイは Cloudflare 資格情報が必要なため未実施
// (docs/notes/spike-b.md 参照)。

import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Effect from "effect/Effect";

import type { CounterDO } from "./src/worker.ts";

export const Worker = Cloudflare.Worker("SpikeB", {
  main: "./src/worker.ts",
  // 検証知見: v2 ドキュメントの DO の例は Async Worker で `bindings:` を使っているが、
  // 実際の WorkerProps の型は `env:`(bindings? は WorkerVersion 側のプロパティ)
  env: {
    COUNTER: Cloudflare.DurableObject<CounterDO>("COUNTER", {
      className: "CounterDO",
    }),
  },
});

// Alchemy 側の env 型導出(wrangler 側は test/env.d.ts の Cloudflare.Env 拡張が対応物)
export type WorkerEnv = Cloudflare.InferEnv<typeof Worker>;

export default Alchemy.Stack(
  "spike-b",
  { providers: Cloudflare.providers(), state: Cloudflare.state() },
  Effect.gen(function* () {
    const worker = yield* Worker;
    return { workerName: worker.workerName };
  }),
);
