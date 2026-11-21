import { describe, expect, it } from "vite-plus/test";

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
