import { describe, expect, it } from "vitest";

import worker from "../src/index.ts";

describe("@maruhi/server placeholder worker", () => {
  it("runs inside workerd", () => {
    // vitest-pool-workers が本当に workerd 上でテストを実行していることの検証
    expect(navigator.userAgent).toBe("Cloudflare-Workers");
  });

  it("responds with 200", async () => {
    const response = worker.fetch();
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe("maruhi");
  });
});
