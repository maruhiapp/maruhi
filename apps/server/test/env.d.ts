// cloudflare:test の env(Cloudflare.Env)に wrangler.jsonc のバインディング型を与える
declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/chain-do.ts").ProjectChainDO>;
    DB: D1Database;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    /** vitest.config.ts の miniflare bindings で注入(applyD1Migrations 用) */
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
  }
}
