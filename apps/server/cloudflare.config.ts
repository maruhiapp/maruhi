import { bindings, defineConfig, defineWorker, exports, triggers } from "cf/config";

// See ADR-0026.
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
  CLI_VERIFY_RATE_LIMIT: bindings.rateLimit({
    namespace: "1006",
    simple: {
      limit: 30,
      period: 60,
    },
  }),
  CLI_APPROVE_RATE_LIMIT: bindings.rateLimit({
    namespace: "1007",
    simple: {
      limit: 30,
      period: 60,
    },
  }),
};

const COMPATIBILITY_DATE = "2026-10-09";
const COMPATIBILITY_FLAGS = ["no_nodejs_compat", "no_nodejs_compat_v2"];

const PROJECT_CHAIN_EXPORTS = {
  ProjectChainDO: exports.durableObject({
    storage: "sqlite",
  }),
};

const SPA_ASSETS = {
  htmlHandling: "auto-trailing-slash" as const,
  notFoundHandling: "single-page-application" as const,
  runWorkerFirst: ["/auth/*", "/projects", "/projects/*", "/invites", "/invites/*"],
};

export const SELF_HOST_WORKER = defineWorker({
  name: "maruhi-server",
  compatibilityDate: COMPATIBILITY_DATE,
  compatibilityFlags: COMPATIBILITY_FLAGS,
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
});

const SECRETS_STORE_ID = "93c7bc6956634cd59d4432b299a9cb34";

const ACCOUNT_ID = "66174a06aae84ed383e75d0c0d35566e";

const HOSTED_SECRET_BINDINGS = {
  GITHUB_CLIENT_ID: bindings.secretsStoreSecret({
    storeId: SECRETS_STORE_ID,
    secretName: "GITHUB_CLIENT_ID",
  }),
  GITHUB_CLIENT_SECRET: bindings.secretsStoreSecret({
    storeId: SECRETS_STORE_ID,
    secretName: "GITHUB_CLIENT_SECRET",
  }),
  SERVER_ENC_KEY_IKM: bindings.secretsStoreSecret({
    storeId: SECRETS_STORE_ID,
    secretName: "SERVER_ENC_KEY_IKM",
  }),
  OPS_ALERT_WEBHOOK_URL: bindings.secretsStoreSecret({
    storeId: SECRETS_STORE_ID,
    secretName: "OPS_ALERT_WEBHOOK_URL",
  }),
};

export const HOSTED_WORKER = defineWorker({
  name: "maruhi-server-hosted",
  compatibilityDate: COMPATIBILITY_DATE,
  compatibilityFlags: COMPATIBILITY_FLAGS,
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
    ...HOSTED_SECRET_BINDINGS,
  },
  exports: PROJECT_CHAIN_EXPORTS,
});

export const RESTORE_WORKER = defineWorker({
  name: "maruhi-restore",
  compatibilityDate: COMPATIBILITY_DATE,
  compatibilityFlags: COMPATIBILITY_FLAGS,
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
    DB: bindings.d1({
      name: "maruhi",
      id: "c45d4f84-3142-46cf-ab3b-c9571ca7eed0",
    }),
    OPS_BACKUP_BUCKET: bindings.r2({
      name: "maruhi-ops-backup",
    }),
    PRODUCTION_PROJECT_CHAIN: bindings.durableObject({
      worker: "maruhi-server-hosted",
      exportName: "ProjectChainDO",
    }),
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
});

export default defineConfig((ctx) => {
  switch (ctx.mode) {
    case "hosted": {
      return { accountId: ACCOUNT_ID, worker: HOSTED_WORKER };
    }
    case "restore": {
      return { accountId: ACCOUNT_ID, worker: RESTORE_WORKER };
    }
    case undefined: {
      return { worker: SELF_HOST_WORKER };
    }
    default: {
      throw new Error(
        `Unknown cf --mode "${ctx.mode}". Expected "hosted" or "restore", or omit --mode for the self-host worker.`,
      );
    }
  }
});
