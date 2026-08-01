// vitest-pool-workers(workerd 実環境)で HttpApi → DO → DO SQLite の結線を検証する。
import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import type { CounterDO } from "../src/worker.ts";

const increment = (by: number) =>
  SELF.fetch("https://example.com/counter/spike/increment", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ by }),
  });

describe("spike-b: Effect v4 HttpApi + DO(ManagedRuntime)+ DO SQLite", () => {
  it("runs inside workerd", () => {
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });

  it("GET /counter/:name returns 0 for a fresh counter", async () => {
    const response = await SELF.fetch("https://example.com/counter/fresh");
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ name: "fresh", value: 0 });
  });

  it("POST /counter/:name/increment increments through HttpApi → DO → SQLite", async () => {
    const first = await increment(3);
    expect(first.status).toBe(200);
    await expect(first.json()).resolves.toEqual({ name: "spike", value: 3 });

    const second = await increment(4);
    await expect(second.json()).resolves.toEqual({ name: "spike", value: 7 });

    const got = await SELF.fetch("https://example.com/counter/spike");
    await expect(got.json()).resolves.toEqual({ name: "spike", value: 7 });
  });

  it("rejects a payload that fails schema validation", async () => {
    const response = await SELF.fetch("https://example.com/counter/spike/increment", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ by: "not-a-number" }),
    });
    expect(response.status).toBe(400);
  });

  it("persists into the DO's own SQLite (verified via runInDurableObject)", async () => {
    const id = env.COUNTER.idFromName("direct");
    const stub = env.COUNTER.get(id);
    await stub.increment(41);
    await stub.increment(1);

    // DO インスタンス内部に入り、SQLite の実データを直接確認する
    await runInDurableObject(stub, async (_instance: CounterDO, state) => {
      const rows = state.storage.sql.exec("SELECT id, value FROM counter").toArray();
      expect(rows).toEqual([{ id: 0, value: 42 }]);
    });
  });
});
