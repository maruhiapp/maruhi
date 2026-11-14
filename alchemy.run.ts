// Alchemy v2 program for the hosted deployment (ADR-0012, ops task O9).
//
// Scope: ONLY the hosted worker (`maruhi-server-hosted`) and the apex
// site (`maruhi-site`) are declared here. The self-host worker and the
// restore worker stay on the plain `cf` CLI (apps/server/cloudflare
// .config.ts): the self-hosting path must remain Alchemy-free
// (docs/SELF_HOSTING.md), and the restore worker is ops-only and
// deployed on demand.
//
// The application source stays Alchemy-independent (ROADMAP): both
// workers use the async Worker form — `main` points at the existing
// entry module and bindings are declared as props. Worker names are
// pinned exactly with `name` — the hosted name is load-bearing outside
// this file (the restore worker binds its DO namespace cross-worker,
// and the apex domain points at the site worker).
//
// D1 and R2 are bound by lookup only: Alchemy never creates, migrates,
// updates or deletes them. D1 migrations stay with the cf flow
// (`db:migrate:hosted` in apps/server/package.json), and the backup /
// restore machinery keeps owning the bucket's lifecycle.
//
// Deploy with an explicit stage so physical naming is stable:
//   bun run alchemy:deploy
// Preview (read-only) with:
//   bun run alchemy:plan
import * as Cloudflare from "@alchemy.run/cloudflare";
import * as Alchemy from "alchemy";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";

// One runtime contract with the cf config (apps/server/cloudflare
// .config.ts): past 2026-08-04 the date alone would switch
// nodejs_compat on; the server uses no Node APIs, so both Node compat
// layers stay off explicitly, independent of the date.
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
    // Lookup by name, not id: the id already lives in
    // apps/server/cloudflare.config.ts (scripts/d1-id.ts reads it
    // there), name matches the wrangler runbooks, and a recreated
    // database that reuses the name survives the swap.
    const db = Cloudflare.D1.Database.lookup({ name: "maruhi" });
    const opsBackupBucket = Cloudflare.R2.Bucket.lookup({
      name: "maruhi-ops-backup",
    });

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
        // Query strings carry OAuth codes; the cf config sets this
        // and check-hosted-config.ts asserts it as an invariant.
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
        // The same-worker Durable Object binding for the plain
        // ProjectChainDO class (apps/server/src/do/chain-do.ts, sqlite
        // storage). The class stays a plain export of the worker
        // entry; the binding is declared with the provider's
        // DurableObjectLike shape, which the provider's binding
        // normalization turns into a durable_object_namespace binding.
        // The reconcile adopts the existing class by name; its
        // exports map carries the storage Cloudflare already reports,
        // and the declared "sqlite" applies only to a class that does
        // not exist yet. No scriptName: this worker hosts it.
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
        // All four Workers Secrets the hosted worker carries today
        // (wrangler.jsonc's hosted comment; src/worker-env.ts). An
        // Alchemy upload rebuilds the binding list from this program,
        // so a secret left undeclared here would be dropped by the
        // adopting deploy — declaring them is what keeps them. Values
        // come from the deploy environment (Config.Redacted) and are
        // uploaded as secret_text on every deploy; they never live in
        // this file. The deploying operator must hold all four values.
        GITHUB_CLIENT_ID: yield* Config.Redacted("GITHUB_CLIENT_ID"),
        GITHUB_CLIENT_SECRET: yield* Config.Redacted("GITHUB_CLIENT_SECRET"),
        SERVER_ENC_KEY_IKM: yield* Config.Redacted("SERVER_ENC_KEY_IKM"),
        OPS_ALERT_WEBHOOK_URL: yield* Config.Redacted("OPS_ALERT_WEBHOOK_URL"),
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
