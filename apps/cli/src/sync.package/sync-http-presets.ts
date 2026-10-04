// The built-in http presets of `maruhi sync`'s http driver
// (sync-http.ts): the declarative HTTP_PRESETS — the same first-class
// targets as the exec presets, plus Netlify — and the vendor constants
// they declare on (Vercel's environments and batch cap; Netlify's
// deploy contexts, secret-excluded contexts, secret scopes, paths, and
// the shared list spec). Data only — the request code is generic over
// the HttpPreset type.

import type { HttpListSpec, HttpPreset, PathToken } from "./sync-http.ts";

const VERCEL_ENVIRONMENTS = ["production", "preview", "development"] as const;

// Vercel's per-request item limit is not in the public docs (the CLI goes
// one at a time). The total limit (64 KB / deployment) does not depend on
// the count, so sit on the conservative side of an unknown limit
const VERCEL_BATCH = 25;

// Netlify's deploy contexts (the closed set of swagger's `context`.
// `branch` takes the `branch` option's branch name into `context_parameter`)
const NETLIFY_CONTEXTS = [
  "production",
  "deploy-preview",
  "branch-deploy",
  "branch",
  "dev",
  "dev-server",
  "all",
] as const;

// Contexts where a secret cannot be placed (docs: "Secret values must be
// set to explicit deploy contexts"; CLI: "specify a non-development
// context". `dev-server` is in the CLI's SUPPORTED_CONTEXTS but the secret
// check looks at names containing `dev` = dev-server is also excluded)
const NETLIFY_NON_SECRET_CONTEXTS = new Set(["all", "dev", "dev-server"]);

// A secret variable cannot have the post_processing scope (the docs'
// Secrets Controller). netlify-cli specifies the other 3 scopes when
// creating one — copy the same shape (non-secret sends no scopes and
// leaves Netlify's default = every scope. Choosing scopes is Pro and up)
const NETLIFY_SECRET_SCOPES = ["builds", "functions", "runtime"] as const;

const NETLIFY_ENV_PATH: readonly PathToken[] = [
  "/api/v1/accounts/",
  { kind: "option", option: "accountId" },
  "/env",
];
const NETLIFY_KEY_PATH: readonly PathToken[] = [...NETLIFY_ENV_PATH, "/", { kind: "name" }];
const NETLIFY_SITE_QUERY = { site_id: { kind: "option", option: "siteId" } } as const;

/** Netlify's list (the write's existence check and the delete's id matching read the same list). */
const NETLIFY_LIST: HttpListSpec = {
  path: NETLIFY_ENV_PATH,
  query: NETLIFY_SITE_QUERY,
  itemsField: null,
  keyField: "key",
};

/** Built-in http presets (the same first-class targets as the exec presets, plus Netlify). */
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
    // wrangler's getLegacyScriptName: a named environment is `<name>-<env>`
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
    // The API stores the value verbatim (the CLI's stdin-sourced constraints do not apply)
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      environment: { type: "string", required: true, values: VERCEL_ENVIRONMENTS },
      gitBranch: { type: "string", required: false },
      projectId: { type: "string", required: true },
      teamId: { type: "string", required: false },
      sensitive: { type: "boolean", required: false },
    },
    // projectId / teamId are opaque IDs (they don't become the header line's name), so they're not listed
    describeOptions: ["environment", "gitBranch"],
    // Vercel CLI's resolveFinalType: development cannot be sensitive;
    // --no-sensitive is encrypted (= a value that can be read back).
    // Everything else is sensitive
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
    // Netlify has no upsert (POST = create, PATCH = the value of one
    // context of an existing key). Look the name up in the list, one
    // request per variable (the partial-failure shape of an array POST is
    // not in the docs, so fix the count at 1 and attribute the delivered
    // names exactly)
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
      // PATCH cannot change is_secret (premise (1)). Never place a value
      // meant for a secret onto a variable that already exists as
      // non-secret
      updateGuards: [
        {
          field: "is_secret",
          option: "isSecret",
          hint: "Netlify cannot turn an existing variable into a secret through the request that sets one context's value. Mark it as secret in the Netlify dashboard, delete it there and apply again, or set \"secret\": false in the target's options",
        },
      ],
    },
    // The delete covers only this target's context value
    // (`DELETE …/value/{id}`). If that was the variable's last value, delete
    // the whole key (leave no empty variable). Other contexts' values are
    // untouched
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
    // The value limit is 5,000 characters (docs) — an excess surfaces as an API failure in the message (never silently truncated)
    constraints: { maxBytes: null, nonEmpty: false, trailingNewline: "kept", name: null },
    options: {
      accountId: { type: "string", required: true },
      siteId: { type: "string", required: true },
      context: { type: "string", required: true, values: NETLIFY_CONTEXTS },
      branch: { type: "string", required: false },
      secret: { type: "boolean", required: false },
    },
    // accountId / siteId are opaque IDs (they don't become the header line's name), so they're not listed
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
    // The default is secret (a value that cannot be read back on the
    // Netlify side — same direction as Vercel's sensitive). On a context
    // where a secret cannot be placed, the default flips to false. A secret
    // cannot have the post_processing scope, so the same 3 scopes as the
    // CLI are specified explicitly
    derive: (options) => {
      const isSecret =
        options["secret"] ?? !NETLIFY_NON_SECRET_CONTEXTS.has(String(options["context"]));
      return isSecret === true ? { isSecret, scopes: NETLIFY_SECRET_SCOPES } : { isSecret: false };
    },
    tokenHint:
      "a personal access token from the Netlify user settings (Applications, Personal access tokens; see the Deploy targets page in the docs)",
  },
} as const satisfies Readonly<Record<string, HttpPreset>>;
