import { bindings, defineConfig, exports, triggers } from "cf/config";

// Shared across the self-host default and the hosted mode (cf modes do not
// inherit bindings — hosted re-declares them). check-hosted-config.ts asserts
// both stay identical to the wrangler.jsonc mirror.
const DAILY_TRIGGERS = [
  triggers.scheduled({
    schedule: "17 3 * * *",
  }),
  triggers.scheduled({
    schedule: "23 * * * *",
  }),
];

const RATE_LIMIT_BINDINGS = {
  CLI_START_RATE_LIMIT: bindings.rateLimit({
    namespace: "1001",
    simple: {
      limit: 10,
      period: 60,
    },
  }),
  LEASE_RATE_LIMIT: bindings.rateLimit({
    namespace: "1002",
    simple: {
      limit: 60,
      period: 60,
    },
  }),
  OAUTH_CALLBACK_RATE_LIMIT: bindings.rateLimit({
    namespace: "1003",
    simple: {
      limit: 30,
      period: 60,
    },
  }),
  CLI_POLL_RATE_LIMIT: bindings.rateLimit({
    namespace: "1004",
    simple: {
      limit: 30,
      period: 60,
    },
  }),
  SIGNUP_START_RATE_LIMIT: bindings.rateLimit({
    namespace: "1005",
    simple: {
      limit: 10,
      period: 60,
    },
  }),
};

const PROJECT_CHAIN_EXPORTS = {
  ProjectChainDO: exports.durableObject({
    storage: "sqlite",
  }),
};

const SPA_ASSETS = {
  htmlHandling: "auto-trailing-slash",
  notFoundHandling: "single-page-application",
  runWorkerFirst: ["/auth/*", "/projects", "/projects/*", "/invites", "/invites/*"],
};

/**
 * Worker environments are selected through ctx.mode and the cf --mode flag:
 *
 *   cf deploy / cf dev        -> self-host worker "maruhi-server"
 *   cf deploy --mode hosted   -> hosted worker "maruhi-server-hosted"
 *   cf deploy --mode restore  -> ops-only restore worker "maruhi-restore"
 *      (what wrangler.restore.jsonc used to describe; deploy it only during
 *      restore work, then remove it with `cf workers delete maruhi-restore`)
 *
 * Any other --mode fails fast, matching wrangler's behaviour for an unknown
 * --env name.
 * @see https://developers.cloudflare.com/workers/wrangler/environments/
 *
 * D1 migrations no longer live in the config: `migrations_dir` /
 * `migrations_pattern` became the `--dir` / `--pattern` flags of
 * `cf d1 migrations apply` (see the db:migrate scripts in package.json).
 * The `.dev.vars.example` template is intentionally not migrated: it holds the
 * dummy values for local `cf dev` (copied to `.dev.vars`) and is the source of
 * the server tests' dummy bindings (vitest.config.ts), not a `secrets.required`
 * entry.
 */
export default defineConfig((ctx) => {
  switch (ctx.mode) {
    case "hosted": {
      return {
        worker: {
          name: "maruhi-server-hosted",
          compatibilityDate: "2026-07-01",
          entrypoint: "src/index.ts",
          workersDev: false,
          previewUrls: false,
          limits: {
            cpuMs: 300000,
          },
          observability: {
            enabled: true,
            redactQueryString: true,
            logs: {
              enabled: true,
              invocationLogs: false,
              headSamplingRate: 1,
            },
          },
          assets: SPA_ASSETS,
          domains: ["my.maruhi.app"],
          triggers: DAILY_TRIGGERS,
          env: {
            DB: bindings.d1({
              name: "maruhi",
              id: "c45d4f84-3142-46cf-ab3b-c9571ca7eed0",
            }),
            OPS_BACKUP_BUCKET: bindings.r2({
              name: "maruhi-ops-backup",
            }),
            PROJECT_CHAIN: bindings.durableObject({
              worker: "maruhi-server-hosted",
              exportName: "ProjectChainDO",
            }),
            ...RATE_LIMIT_BINDINGS,
          },
          exports: PROJECT_CHAIN_EXPORTS,
        },
      };
    }
    case "restore": {
      // Restore worker (operations-only, non-HTTP, not permanently deployed —
      // docs/notes/hosted-ops.md §2-E / §5-2). Deploy it only during restore
      // work with `cf deploy --mode restore`, then remove it with
      // `cf workers delete maruhi-restore`. It has no HTTP handler
      // (workers.dev is also disabled); its only job is a per-minute cron
      // that reads restore/jobs/ in the evacuation bucket.
      return {
        worker: {
          name: "maruhi-restore",
          compatibilityDate: "2026-07-01",
          entrypoint: "src/restore-worker.ts",
          workersDev: false,
          previewUrls: false,
          limits: {
            cpuMs: 300000,
          },
          triggers: [
            triggers.scheduled({
              schedule: "* * * * *",
            }),
          ],
          env: {
            // The production worker's D1 (the same database as the hosted
            // mode): an import job (PF3 — identitiesKey) provisions the
            // imported project's users, identities, org, projects row and
            // membership projection here after the DO restore
            DB: bindings.d1({
              name: "maruhi",
              id: "c45d4f84-3142-46cf-ab3b-c9571ca7eed0",
            }),
            OPS_BACKUP_BUCKET: bindings.r2({
              name: "maruhi-ops-backup",
            }),
            // The production worker's DO namespace, bound cross-worker.
            // The entity behind `cf deploy --mode hosted` is
            // `maruhi-server-hosted`; scripts/check-hosted-config.ts
            // cross-checks the effective name against this.
            PRODUCTION_PROJECT_CHAIN: bindings.durableObject({
              worker: "maruhi-server-hosted",
              exportName: "ProjectChainDO",
            }),
            // Namespace for drills — a separate class inside this
            // worker (does not intersect with production).
            DRILL_PROJECT_CHAIN: bindings.durableObject({
              worker: "maruhi-restore",
              exportName: "RestoreDrillDO",
            }),
          },
          exports: {
            RestoreDrillDO: exports.durableObject({
              storage: "sqlite",
            }),
          },
        },
      };
    }
    case undefined: {
      return {
        worker: {
          name: "maruhi-server",
          compatibilityDate: "2026-07-01",
          entrypoint: "src/index.ts",
          workersDev: true,
          previewUrls: false,
          assets: SPA_ASSETS,
          triggers: DAILY_TRIGGERS,
          env: {
            DB: bindings.d1({
              name: "maruhi",
              id: "00000000-0000-4000-8000-000000000000",
            }),
            PROJECT_CHAIN: bindings.durableObject({
              worker: "maruhi-server",
              exportName: "ProjectChainDO",
            }),
            ...RATE_LIMIT_BINDINGS,
          },
          exports: PROJECT_CHAIN_EXPORTS,
        },
      };
    }
    default: {
      throw new Error(
        `Unknown cf --mode "${ctx.mode}". Expected "hosted" or "restore", or omit --mode for the self-host worker.`,
      );
    }
  }
});
