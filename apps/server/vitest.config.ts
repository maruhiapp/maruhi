import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vite-plus/test/config";
import { unstable_readConfig } from "wrangler";

import { vitestPoolAliases } from "../../scripts/vitest-aliases.ts";
import { fakeGitHub } from "./test/support/fake-github.ts";
import { readDevVarsExample } from "./test/support/read-dev-vars.ts";
import { readDrizzleMigrations } from "./test/support/read-migrations.ts";

const devVars = readDevVarsExample(new URL(".dev.vars.example", import.meta.url).pathname);

const wranglerConfig = unstable_readConfig({
  config: new URL("wrangler.jsonc", import.meta.url).pathname,
});

export default defineConfig({
  resolve: { alias: vitestPoolAliases },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        outboundService: fakeGitHub,
        r2Buckets: ["OPS_BACKUP_BUCKET"],
        bindings: {
          ...devVars,
          OPS_ALERT_WEBHOOK_URL: "https://ops-webhook.test/hook",
          TEST_RUN_WORKER_FIRST: (wranglerConfig.assets?.run_worker_first ?? null) as string[],
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
    fsModuleCache: false,
    testTimeout: 60_000,
    hookTimeout: 30_000,
    isolate: false,
    silent: "passed-only",
    sequence: {
      shuffle: { files: true },
    },
  },
});
