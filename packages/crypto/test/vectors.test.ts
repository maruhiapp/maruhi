// テストベクター準拠チェック(CRYPTO_SPEC §11)。
// node / workerd / browser の 3 プロジェクトで同一実行される(vitest.*.config.ts 参照)。
// Bun ランタイムは test/run-in-bun.ts が同じチェックを直接実行する。

import { describe, expect, it } from "vitest";

import { runAllChecks } from "./all-checks.ts";

describe("@maruhi/crypto test vectors", async () => {
  const results = await runAllChecks();

  it("has results", () => {
    expect(results.length).toBeGreaterThan(0);
  });

  for (const r of results) {
    it(r.name, () => {
      expect(r.ok, r.detail).toBe(true);
    });
  }
});
