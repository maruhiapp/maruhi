// Alchemy v2 program for the hosted deployment (ADR-0012, ops task O9).
//
// Scope: the hosted worker (`maruhi-server-hosted`), the apex
// site (`maruhi-site`), and the hosted database and ops backup
// bucket as managed resources (ADR-0012 revision 2). The self-host worker and the
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
// D1 and R2 are managed resources (ADR-0012 revision 2, reversing
// revision 1's lookup-only ruling): the database's migrations are
// declared here and applied by the deploy, and the bucket's full
// recorded configuration — the `retain-35d` lifecycle rule, the
// default multipart abort rule, no CORS, no custom domains, no public
// access — is declared in full, because the provider's reconcile
// syncs those sub-resources to the declared props (an omitted prop
// reads as "clear"). Both resources carry RemovalPolicy.protect():
// a plan that would delete or replace either fails before anything
// is applied.
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
    // Managed by name, not id: the id already lives in
    // apps/server/cloudflare.config.ts (scripts/d1-id.ts reads it
    // there), name matches the wrangler runbooks, and pinning the name
    // is what makes the first deploy adopt the existing database
    // instead of replacing it (a name change plans as a replace —
    // and protect() below refuses even that). No jurisdiction /
    // primaryLocationHint: both are replace triggers.
    //
    // The `migrations` prop is what moves hosted migration ownership
    // from `cf d1 migrations apply` to the deploy: the existing
    // drizzle-kit files under apps/server/drizzle drive it as-is
    // (the path is relative to the repository root, like `main` and
    // the assets directories below). The first deploy converts the
    // wrangler-written `d1_migrations` history into Alchemy's
    // `__alchemy_migrations` ledger — one-way and fail-closed (a
    // history row with no matching local file stops the deploy) —
    // and leaves the old table frozen.
    const db = yield* Cloudflare.D1.Database("Database", {
      name: "maruhi",
      migrations: "apps/server/drizzle",
    }).pipe(Alchemy.RemovalPolicy.protect());

    // Managed, with the bucket's full recorded configuration declared
    // in full (ops task O2; the recipe in docs/SELF_HOSTING.md —
    // recorded, not yet live-dumped: ADR-0012 revision 2 lists the
    // operator preconditions that verify it against the live bucket
    // before the adopting deploy): the provider's reconcile syncs
    // lifecycle rules / CORS / domains / public access to the declared
    // props — omitting one reads as "clear it" — but it diffs the
    // declaration against the live bucket and writes only on a
    // mismatch, so the deletion risk is neutralized. The comparison
    // is order-sensitive, so the rules are declared in the bucket's
    // creation order (default rule first); a residual mismatch would
    // be a content-identical re-PUT, never a deletion. Ages are
    // seconds. The first rule is the default every bucket is created
    // with (recorded in the hosted-ops notes as the "Default
    // Multipart Abort Rule", 7 days); its exact live id is verified
    // at the adopting plan (ADR-0012 revision 2 lists the stop
    // conditions). No locationHint / jurisdiction (replace triggers)
    // and no storageClass (the live bucket is Standard, the
    // provider's default).
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
