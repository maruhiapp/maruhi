// スパイク B: 使い捨て検証コード。製品コードではない。
// Effect v4(4.0.0-beta.102)の HttpApi(effect/unstable/httpapi)でダミー API を定義する。
// v4 では @effect/platform が effect 本体に統合され、HttpApi は unstable 名前空間にある。

import { Schema } from "effect";
import { HttpApi, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

export const CounterValue = Schema.Struct({
  name: Schema.String,
  value: Schema.Number,
});

export const spikeApi = HttpApi.make("spike-b").add(
  HttpApiGroup.make("counter")
    .add(
      HttpApiEndpoint.get("get", "/counter/:name", {
        params: { name: Schema.String },
        success: CounterValue,
      }),
    )
    .add(
      HttpApiEndpoint.post("increment", "/counter/:name/increment", {
        params: { name: Schema.String },
        // 検証知見: payload に素のフィールド群({ by: Schema.Number })を渡すと
        // v4 は application/x-www-form-urlencoded として扱う(JSON は 415 になる)。
        // JSON ボディにするには Schema.Struct(...) を明示する。
        payload: Schema.Struct({ by: Schema.Number }),
        success: CounterValue,
      }),
    ),
);
