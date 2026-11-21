import type { HttpListSpec, HttpPreset, PathToken } from "./sync-http.ts";

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

const VERCEL_BATCH = 25;

const NETLIFY_CONTEXTS = [
  "production",
  "deploy-preview",
  "branch-deploy",
  "branch",
  "dev",
  "dev-server",
  "all",
] as const;

const NETLIFY_NON_SECRET_CONTEXTS = new Set(["all", "dev", "dev-server"]);

const NETLIFY_SECRET_SCOPES = ["builds", "functions", "runtime"] as const;

const NETLIFY_ENV_PATH: readonly PathToken[] = [
  "/api/v1/accounts/",
  { kind: "option", option: "accountId" },
  "/env",
];
const NETLIFY_KEY_PATH: readonly PathToken[] = [...NETLIFY_ENV_PATH, "/", { kind: "name" }];
const NETLIFY_SITE_QUERY = { site_id: { kind: "option", option: "siteId" } } as const;

const NETLIFY_LIST: HttpListSpec = {
  path: NETLIFY_ENV_PATH,
  query: NETLIFY_SITE_QUERY,
  itemsField: null,
  keyField: "key",
};

export const HTTP_PRESETS = {
  "cloudflare-workers": {
    host: "api.cloudflare.com",
    label: "the Cloudflare API",
    write: {
      kind: "upsert",
      batch: 100,
      request: {
        method: "PATCH",
        path: [
          "/client/v4/accounts/",
          { kind: "option", option: "accountId" },
          "/workers/scripts/",
          { kind: "option", option: "scriptName" },
          "/secrets-bulk",
        ],
        query: {},
        contentType: "application/merge-patch+json",
        body: { secrets: { kind: "entries" } },
        entries: "object-by-name",
        entry: { name: { kind: "name" }, text: { kind: "value" }, type: "secret_text" },
        deletedEntry: null,
      },
    },
    delete: { kind: "in-write" },
    response: "cloudflare-v4",
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      accountId: { type: "string", required: true },
      name: { type: "string", required: true },
      environment: { type: "string", required: false },
    },
    describeOptions: ["name", "environment"],
    derive: (options) => ({
      scriptName:
        typeof options["environment"] === "string"
          ? `${String(options["name"])}-${options["environment"]}`
          : String(options["name"]),
    }),
    tokenHint:
      "an API token scoped to the account with the Workers Scripts: Edit permission (see the Deploy targets page in the docs)",
  },
  vercel: {
    host: "api.vercel.com",
    label: "the Vercel API",
    write: {
      kind: "upsert",
      batch: VERCEL_BATCH,
      request: {
        method: "POST",
        path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env"],
        query: { upsert: "true", teamId: { kind: "option", option: "teamId" } },
        contentType: "application/json",
        body: { kind: "entries" },
        entries: "array",
        entry: {
          key: { kind: "name" },
          value: { kind: "value" },
          type: { kind: "option", option: "type" },
          target: [{ kind: "option", option: "environment" }],
          gitBranch: { kind: "option", option: "gitBranch" },
        },
      },
    },
    delete: {
      kind: "lookup",
      list: {
        path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env"],
        query: {
          target: { kind: "option", option: "environment" },
          gitBranch: { kind: "option", option: "gitBranch" },
          teamId: { kind: "option", option: "teamId" },
        },
        itemsField: "envs",
        keyField: "key",
        nextPage: ["pagination", "next"],
      },
      match: {
        idField: "id",
        targetField: "target",
        targetOption: "environment",
        branchField: "gitBranch",
        branchOption: "gitBranch",
      },
      remove: {
        method: "DELETE",
        path: ["/v10/projects/", { kind: "option", option: "projectId" }, "/env/", { kind: "id" }],
        query: { teamId: { kind: "option", option: "teamId" } },
      },
    },
    response: "vercel-env",
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      environment: { type: "string", required: true, values: VERCEL_ENVIRONMENTS },
      gitBranch: { type: "string", required: false },
      projectId: { type: "string", required: true },
      teamId: { type: "string", required: false },
      sensitive: { type: "boolean", required: false },
    },
    describeOptions: ["environment", "gitBranch"],
    derive: (options) => ({
      type:
        options["environment"] === "development" || options["sensitive"] === false
          ? "encrypted"
          : "sensitive",
    }),
    tokenHint:
      "an access token created in the Vercel dashboard, scoped to the team that owns the project (see the Deploy targets page in the docs)",
  },
  netlify: {
    host: "api.netlify.com",
    label: "the Netlify API",
    write: {
      kind: "create-or-update",
      list: NETLIFY_LIST,
      create: {
        method: "POST",
        path: NETLIFY_ENV_PATH,
        query: NETLIFY_SITE_QUERY,
        contentType: "application/json",
        body: { kind: "entries" },
        entries: "array",
        entry: {
          key: { kind: "name" },
          is_secret: { kind: "option", option: "isSecret" },
          scopes: { kind: "option", option: "scopes" },
          values: [
            {
              context: { kind: "option", option: "context" },
              context_parameter: { kind: "option", option: "branch" },
              value: { kind: "value" },
            },
          ],
        },
      },
      update: {
        method: "PATCH",
        path: NETLIFY_KEY_PATH,
        query: NETLIFY_SITE_QUERY,
        contentType: "application/json",
        body: { kind: "entries" },
        entries: "single",
        entry: {
          context: { kind: "option", option: "context" },
          context_parameter: { kind: "option", option: "branch" },
          value: { kind: "value" },
        },
      },
      updateGuards: [
        {
          field: "is_secret",
          option: "isSecret",
          hint: "Netlify cannot turn an existing variable into a secret through the request that sets one context's value. Mark it as secret in the Netlify dashboard, delete it there and apply again, or set \"secret\": false in the target's options",
        },
      ],
    },
    delete: {
      kind: "lookup",
      list: NETLIFY_LIST,
      match: {
        valuesField: "values",
        idField: "id",
        targetField: "context",
        targetOption: "context",
        branchField: "context_parameter",
        branchOption: "branch",
      },
      remove: {
        method: "DELETE",
        path: [...NETLIFY_KEY_PATH, "/value/", { kind: "id" }],
        query: NETLIFY_SITE_QUERY,
      },
      removeItem: { method: "DELETE", path: NETLIFY_KEY_PATH, query: NETLIFY_SITE_QUERY },
    },
    response: "netlify-env",
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      accountId: { type: "string", required: true },
      siteId: { type: "string", required: true },
      context: { type: "string", required: true, values: NETLIFY_CONTEXTS },
      branch: { type: "string", required: false },
      secret: { type: "boolean", required: false },
    },
    describeOptions: ["context", "branch"],
    check: (options) => {
      if (options["context"] === "branch" && typeof options["branch"] !== "string") {
        return "branch is required when context is branch (the branch name)";
      }
      if (options["context"] !== "branch" && options["branch"] !== undefined) {
        return "branch applies only when context is branch";
      }
      if (
        options["secret"] === true &&
        NETLIFY_NON_SECRET_CONTEXTS.has(String(options["context"]))
      ) {
        return `secret cannot be true when context is ${String(options["context"])} (Netlify keeps secret values out of the all and dev contexts)`;
      }
      return null;
    },
    derive: (options) => {
      const isSecret =
        options["secret"] ?? !NETLIFY_NON_SECRET_CONTEXTS.has(String(options["context"]));
      return isSecret === true ? { isSecret, scopes: NETLIFY_SECRET_SCOPES } : { isSecret: false };
    },
    tokenHint:
      "a personal access token from the Netlify user settings (Applications, Personal access tokens; see the Deploy targets page in the docs)",
  },
} as const satisfies Readonly<Record<string, HttpPreset>>;
