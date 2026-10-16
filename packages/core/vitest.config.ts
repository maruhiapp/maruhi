import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "core",
    // The whole-tree source scans (test/brand-casts.test.ts reads every
    // src file under apps/ and packages/) measured 5-6s on the 2-core CI
    // runner once the vitest gate ran as per-suite parallel members —
    // the default 5s trips under that contention. Keep hang detection
    // while leaving headroom
    testTimeout: 30_000,
  },
});
