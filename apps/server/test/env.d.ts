declare namespace Cloudflare {
  interface Env {
    PROJECT_CHAIN: DurableObjectNamespace<import("../src/do/chain-do.ts").ProjectChainDO>;
    DB: D1Database;
    GITHUB_CLIENT_ID: string;
    GITHUB_CLIENT_SECRET: string;
    SERVER_ENC_KEY_IKM?: string;
    CLI_START_RATE_LIMIT: RateLimit;
    CLI_POLL_RATE_LIMIT: RateLimit;
    CLI_VERIFY_RATE_LIMIT: RateLimit;
    CLI_APPROVE_RATE_LIMIT: RateLimit;
    LEASE_RATE_LIMIT: RateLimit;
    OAUTH_CALLBACK_RATE_LIMIT: RateLimit;
    SIGNUP_START_RATE_LIMIT: RateLimit;
    OPS_BACKUP_BUCKET?: R2Bucket;
    OPS_ALERT_WEBHOOK_URL?: string;
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    TEST_RUN_WORKER_FIRST: string[] | boolean | undefined;
  }
}
