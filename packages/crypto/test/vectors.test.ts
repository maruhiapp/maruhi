// Conformance checks against the test vectors (CRYPTO_SPEC §11).
// Run identically across the 3 projects node / workerd / browser (see vitest.*.config.ts).
// For the Bun runtime, test/run-in-bun.ts runs the same checks directly.

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
