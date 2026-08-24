// cloudflare:test の env(Cloudflare.Env)に wrangler.jsonc のバインディング型を与える
declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/chain-do.ts").ProjectChainDO>;
    DB: D1Database;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    /** デプロイメント keypair の ikm(A1 — 任意。テスト既定では未設定)。 */
    SERVER_ENC_KEY_IKM?: string;
    /** 発信元 IP レート制限(deepsec M3/B11/M5 — wrangler.jsonc の ratelimits)。 */
    DEVICE_EXCHANGE_RATE_LIMIT?: RateLimit;
    LEASE_RATE_LIMIT?: RateLimit;
    /** vitest.config.ts の miniflare bindings で注入(applyD1Migrations 用) */
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
  }
}
