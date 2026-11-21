// See ADR-0026.
import * as Cloudflare from "@alchemy.run/cloudflare";
import * as Alchemy from "alchemy";
import * as Effect from "effect/Effect";

const COMPATIBILITY = {
  date: "2026-10-09",
  flags: ["no_nodejs_compat", "no_nodejs_compat_v2"],
};

export default Alchemy.Stack(
  "maruhi",
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const db = yield* Cloudflare.D1.Database("Database", {
      name: "maruhi",
      migrations: "apps/server/drizzle",
    }).pipe(Alchemy.RemovalPolicy.protect());

    const opsBackupBucket = yield* Cloudflare.R2.Bucket("OpsBackupBucket", {
      name: "maruhi-ops-backup",
      lifecycleRules: [
        {
          id: "Default Multipart Abort Rule",
          enabled: true,
          abortMultipartUploadsTransition: { condition: { type: "Age", maxAge: 604_800 } },
        },
        {
          id: "retain-35d",
          enabled: true,
          deleteObjectsTransition: { condition: { type: "Age", maxAge: 3_024_000 } },
          abortMultipartUploadsTransition: { condition: { type: "Age", maxAge: 86_400 } },
        },
      ],
      cors: [],
      domains: [],
      publicAccess: false,
    }).pipe(Alchemy.RemovalPolicy.protect());

    const cliStartRateLimit = Cloudflare.RateLimit("CliStartRateLimit", {
      namespaceId: 1001,
      simple: { limit: 10, period: 60 },
    });
    const leaseRateLimit = Cloudflare.RateLimit("LeaseRateLimit", {
      namespaceId: 1002,
      simple: { limit: 60, period: 60 },
    });
    const oauthCallbackRateLimit = Cloudflare.RateLimit("OauthCallbackRateLimit", {
      namespaceId: 1003,
      simple: { limit: 30, period: 60 },
    });
    const cliPollRateLimit = Cloudflare.RateLimit("CliPollRateLimit", {
      namespaceId: 1004,
      simple: { limit: 30, period: 60 },
    });
    const signupStartRateLimit = Cloudflare.RateLimit("SignupStartRateLimit", {
      namespaceId: 1005,
      simple: { limit: 10, period: 60 },
    });
    const cliVerifyRateLimit = Cloudflare.RateLimit("CliVerifyRateLimit", {
      namespaceId: 1006,
      simple: { limit: 30, period: 60 },
    });
    const cliApproveRateLimit = Cloudflare.RateLimit("CliApproveRateLimit", {
      namespaceId: 1007,
      simple: { limit: 30, period: 60 },
    });

    const secretsStore = Cloudflare.SecretsStore.Store.lookup({
      name: "default_secrets_store",
    });
    const githubClientIdSecret = Cloudflare.SecretsStore.Secret.lookup({
      storeId: secretsStore.storeId,
      name: "GITHUB_CLIENT_ID",
    });
    const githubClientSecretSecret = Cloudflare.SecretsStore.Secret.lookup({
      storeId: secretsStore.storeId,
      name: "GITHUB_CLIENT_SECRET",
    });
    const serverEncKeyIkmSecret = Cloudflare.SecretsStore.Secret.lookup({
      storeId: secretsStore.storeId,
      name: "SERVER_ENC_KEY_IKM",
    });
    const opsAlertWebhookUrlSecret = Cloudflare.SecretsStore.Secret.lookup({
      storeId: secretsStore.storeId,
      name: "OPS_ALERT_WEBHOOK_URL",
    });

    const hosted = yield* Cloudflare.Worker("HostedServer", {
      name: "maruhi-server-hosted",
      main: "apps/server/src/index.ts",
      domain: "my.maruhi.app",
      workersDev: false,
      compatibility: COMPATIBILITY,
      crons: ["17 3 * * *", "23 * * * *"],
      limits: { cpuMs: 300_000 },
      observability: {
        enabled: true,
        redactQueryString: true,
        logs: { enabled: true, invocationLogs: false, headSamplingRate: 1 },
      },
      assets: {
        directory: "apps/web/dist/public",
        htmlHandling: "auto-trailing-slash",
        notFoundHandling: "single-page-application",
        runWorkerFirst: ["/auth/*", "/projects", "/projects/*", "/invites", "/invites/*"],
      },
      env: {
        DB: db,
        OPS_BACKUP_BUCKET: opsBackupBucket,
        PROJECT_CHAIN: {
          kind: "Cloudflare.DurableObject",
          name: "ProjectChainDO",
          className: "ProjectChainDO",
          storage: "sqlite",
        },
        CLI_START_RATE_LIMIT: cliStartRateLimit,
        LEASE_RATE_LIMIT: leaseRateLimit,
        OAUTH_CALLBACK_RATE_LIMIT: oauthCallbackRateLimit,
        CLI_POLL_RATE_LIMIT: cliPollRateLimit,
        SIGNUP_START_RATE_LIMIT: signupStartRateLimit,
        CLI_VERIFY_RATE_LIMIT: cliVerifyRateLimit,
        CLI_APPROVE_RATE_LIMIT: cliApproveRateLimit,
        GITHUB_CLIENT_ID: githubClientIdSecret,
        GITHUB_CLIENT_SECRET: githubClientSecretSecret,
        SERVER_ENC_KEY_IKM: serverEncKeyIkmSecret,
        OPS_ALERT_WEBHOOK_URL: opsAlertWebhookUrlSecret,
      },
    });

    const site = yield* Cloudflare.Worker("Site", {
      name: "maruhi-site",
      domain: "maruhi.app",
      workersDev: false,
      compatibility: { date: "2026-10-09" },
      assets: {
        directory: "apps/site/dist",
        htmlHandling: "drop-trailing-slash",
        notFoundHandling: "404-page",
      },
    });

    return { hostedUrl: hosted.url, siteUrl: site.url };
  }),
);
