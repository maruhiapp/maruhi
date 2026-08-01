// node / workerd / browser の 3 プロジェクトで同一実行されるテスト(vitest.config.ts 参照)。
// Bun ランタイムは src/run-in-bun.ts で別途検証する。
import { describe, expect, it } from "vitest";

import { runChecks } from "../src/checks.ts";

describe("HPKE candidates: roundtrip / interop / RFC 9180 vectors", async () => {
  const results = await runChecks();

  it("has results", () => {
    // どの環境で実行されたかと、観察項目(合否なし)の記録を出力する
    const ua = typeof navigator === "undefined" ? "(no navigator)" : navigator.userAgent;
    console.log(`[spike-c] runtime userAgent: ${ua}`);
    for (const r of results.filter((x) => x.name.startsWith("observe:"))) {
      console.log(`[spike-c] ${r.name} -> ${r.detail}`);
    }
    expect(results.length).toBeGreaterThan(0);
  });

  for (const r of results) {
    it(r.name, () => {
      expect(r.ok, r.detail).toBe(true);
    });
  }
});
