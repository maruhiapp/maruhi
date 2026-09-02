// cloudflare:test の env(Cloudflare.Env)に wrangler.jsonc のバインディング型を与える
declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/chain-do.ts").ProjectChainDO>;
    DB: D1Database;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    /** デプロイメント keypair の ikm(A1 — 任意。テスト既定では未設定)。 */
    SERVER_ENC_KEY_IKM?: string;
    /** 発信元 IP レート制限(deepsec M5/R7・AUTH_SPEC §4-1 — wrangler.jsonc の ratelimits)。 */
    CLI_START_RATE_LIMIT?: RateLimit;
    CLI_POLL_RATE_LIMIT?: RateLimit;
    LEASE_RATE_LIMIT?: RateLimit;
    OAUTH_CALLBACK_RATE_LIMIT?: RateLimit;
    SIGNUP_START_RATE_LIMIT?: RateLimit;
    /** 運用基盤 H3(vitest.config.ts の miniflare r2Buckets / bindings)。 */
    OPS_BACKUP_BUCKET?: R2Bucket;
    OPS_ALERT_WEBHOOK_URL?: string;
    /** vitest.config.ts の miniflare bindings で注入(applyD1Migrations 用) */
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    /**
     * vitest.config.ts の miniflare bindings で注入: wrangler.jsonc の
     * assets.run_worker_first(serving-topology.test.ts の被覆スイープ用)
     */
    TEST_RUN_WORKER_FIRST: string[] | boolean | undefined;
  }
}
