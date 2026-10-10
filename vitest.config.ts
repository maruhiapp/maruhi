import { defineConfig } from "vitest/config";

// crypto / core / cli run in the normal environment; server uses
// @cloudflare/vitest-plugin (a real workerd environment).
// The web (dashboard) and site (LP + docs — Blume) e2e are separate
// steps that assume a built dist.
export default defineConfig({
  test: {
    sequence: {
      // File-order shuffle that enforces order independence in the server
      // suite (audit T-2). It lives at the root because Vitest 4.1.x derives
      // file order from this root sequencer alone — a project's own
      // sequence.shuffle is ignored when it runs as a project here. The
      // rationale, reproduction steps, and cost are documented at the canonical
      // site, apps/server/vitest.config.ts (the isolate: false note). The other
      // projects keep default per-file isolation, so a shuffled file order is
      // harmless for them.
      shuffle: { files: true },
    },
    projects: [
      "packages/*/vitest.config.ts",
      "apps/cli/vitest.config.ts",
      "apps/server/vitest.config.ts",
      // web's e2e stays a separate step assuming a built dist (CI 9).
      // Only unit is integrated
      "apps/web/vitest.unit.config.ts",
      // site's e2e is likewise a separate step (CI 9b). Only unit
      // (drift detection of the generated theme) is integrated
      "apps/site/vitest.unit.config.ts",
    ],
  },
});
