// Gives the wrangler.jsonc binding types to cloudflare:test's env (Cloudflare.Env)
declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/do/chain-do.ts").ProjectChainDO>;
    DB: D1Database;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    /** ikm of the deployment keypair (optional; unset in the test default). */
    SERVER_ENC_KEY_IKM?: string;
    /** Source-IP rate limits (AUTH_SPEC §4-1 — wrangler.jsonc ratelimits). */
    CLI_START_RATE_LIMIT: RateLimit;
    CLI_POLL_RATE_LIMIT: RateLimit;
    LEASE_RATE_LIMIT: RateLimit;
    OAUTH_CALLBACK_RATE_LIMIT: RateLimit;
    SIGNUP_START_RATE_LIMIT: RateLimit;
    /** Operations foundation (vitest.config.ts miniflare r2Buckets / bindings). */
    OPS_BACKUP_BUCKET?: R2Bucket;
    OPS_ALERT_WEBHOOK_URL?: string;
    /** Injected via vitest.config.ts miniflare bindings (for applyD1Migrations) */
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    /**
     * Injected via vitest.config.ts miniflare bindings: wrangler.jsonc's
     * assets.run_worker_first (for the coverage sweep in
     * serving-topology.test.ts)
     */
    TEST_RUN_WORKER_FIRST: string[] | boolean | undefined;
  }
}
