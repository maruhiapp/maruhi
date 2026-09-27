import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { unstable_readConfig } from "wrangler";

import { fakeGitHub } from "./test/support/fake-github.ts";
import { readDrizzleMigrations } from "./test/support/read-migrations.ts";

// Pass wrangler.jsonc's real values to serving-topology.test.ts (the
// run_worker_first all-endpoints coverage sweep). workerd cannot read
// fs, so read it on the Node side
const wranglerConfig = unstable_readConfig({
  config: new URL("wrangler.jsonc", import.meta.url).pathname,
});

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Replace outbound fetches to GitHub with the fake (real network is forbidden)
        outboundService: fakeGitHub,
        // The ops-foundation H3 evacuation destination (local R2 — an
        // optional binding absent from wrangler.jsonc's top level.
        // Reproduces the hosted environment's shape in tests)
        r2Buckets: ["OPS_BACKUP_BUCKET"],
        bindings: {
          // GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET are Workers
          // Secrets in production (they don't appear in
          // wrangler.jsonc), so tests inject a "configured server"'s
          // dummy values here (unconfigured-detection tests pass a
          // swapped env to worker.fetch — auth.test.ts)
          GITHUB_CLIENT_ID: "dummy-github-client-id",
          GITHUB_CLIENT_SECRET: "dummy-github-client-secret",
          // The deployment keypair's IKM (CRYPTO_SPEC §9). A
          // Workers Secret in production. The §14 lease-path tests
          // build a server-bound wrap with the real key derived
          // from this IKM and verify the server can unwrap it
          SERVER_ENC_KEY_IKM: "b0".repeat(32),
          // The tripwire-notification webhook (hosted-ops.md §2-B).
          // The fake (fake-github.ts) receives it. The sent body's
          // contents are checked via an OpsNotifier swap
          // (ops-alerts.test.ts)
          OPS_ALERT_WEBHOOK_URL: "https://ops-webhook.test/hook",
          // wrangler.jsonc's real assets.run_worker_first value
          // (the coverage sweep's inspection target)
          TEST_RUN_WORKER_FIRST: (wranglerConfig.assets?.run_worker_first ?? null) as string[],
          // The D1 migrations (passed to applyD1Migrations on the
          // test side). The path is config-file-relative
          // (absolutized so a root vitest run doesn't break).
          // Miniflare bindings is Record<string, Json>. D1Migration[]
          // is JSON-compatible but the interface lacks an index
          // signature, so it's widened for the Json assignment
          // (vitest-pool-workers 0.21 / miniflare 5 type tightening).
          TEST_MIGRATIONS: readDrizzleMigrations(
            new URL("drizzle/", import.meta.url).pathname,
          ) as Array<{
            name: string;
            queries: string[];
            [key: string]: string | string[];
          }>,
        },
      },
    }),
  ],
  test: {
    name: "server",
    // Tests with many HTTP round-trips through the real workerd
    // environment (10+ requests per test) can exceed the default 5s
    // depending on suite-wide load (measured flakes). On slow CI
    // runners (2 cores) the vector-driven chain-replay tests have
    // measured over 30s. Keep the boundedness of hang detection
    // while leaving headroom
    testTimeout: 60_000,
    // The data-plane fixture (beforeEach) issues a PAT per user via
    // the real path (the CLI login handoff = 6 round-trips —
    // AUTH_SPEC §11-1's ruling forbids stubbing) and then replays
    // the base chain through the API, so the default 10s can be
    // exceeded under load (measured flakes). Same here — keep hang
    // detection while leaving headroom
    hookTimeout: 30_000,
    // Rather than rebuilding workerd per file, reuse one workerd
    // per worker (default = core count - 1). With the default
    // isolate: true, each test file re-imports Effect + the server
    // body (measured 5-6s/file, ~290s CPU across 50 files), which
    // dominated suite time. Measured (4 cores): wall clock 160s →
    // 51s.
    //
    // Trade-off: D1 / DO / R2 storage is shared between files
    // handled by the same worker (vitest-plugin 1.x's isolation
    // unit is "the worker"). This suite's fixtures never assumed
    // isolation even between tests within a file, and beforeEach
    // wipes all of D1's auth tables (support/auth.ts resetAuthDb)
    // and resets the target project DO (support/project-do.ts), so
    // the same discipline holds across file boundaries. Confirmed
    // all 50 files pass when run serially on 1 worker in shuffled
    // order. If a flake suggesting cross-file state dependence
    // appears, first check whether that file's fixture upholds the
    // "build your own precondition state yourself" discipline
    // (restoring isolate is the last resort). R2
    // (OPS_BACKUP_BUCKET) has no shared reset: a test reading the
    // bucket either restricts itself to a file-unique prefix
    // (ops-backup.test.ts's `oversize-test/<doId>/`) or, when it
    // must scan the product's key layout, empties that prefix
    // itself in beforeEach (ops-restore.test.ts's `restore/`).
    //
    // Prerequisite: @cloudflare/vitest-plugin 1.1.2 or later.
    // Earlier harnesses have a bug where SELF.fetch's per-request
    // cost grows in proportion to the cumulative request count, so
    // reusing workerd slows the whole suite quadratically.
    isolate: false,
    // Discard console output from passing tests. The server emits
    // an Effect HttpMiddleware.logger INFO line ("Sent HTTP
    // response") per response, which produced 10-odd thousand log
    // blocks (~97k lines) per CI run — unreadable, plus the
    // transfer/rendering cost. Output from failing tests is still
    // shown in full as before
    silent: "passed-only",
  },
});
