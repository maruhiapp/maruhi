// The http driver of `maruhi sync` (stage 2 — integration-options.md §3
// supplement 13 W1 "CI and not-yet-installed = http" / supplement 14 M2
// "presets are declarative" / supplement 15 X2 "an integration token is an
// ordinary variable").
//
// On a machine without the vendor CLI (CI, people who don't want it
// installed), maruhi's own code bulk-upserts to the vendor's HTTP API.
// Another driver on the same config and the same plan / apply as the exec
// driver (sync-exec.ts) — not a substitute for fetching the CLI.
//
// What the types decide:
//   - A value's placeholder (the `value` of {@link EntryToken}) may only sit
//     in **a body entry**. No value token exists in the URL path / query /
//     header templates ({@link PathToken})
//   - The destination is fixed by the preset's declaration (`host`). There
//     is no door for config to swap the host
//   - The integration token is handed to `HttpClientRequest.bearerToken`
//     still `Redacted` (the upstream unwraps it inside — no hand-built
//     header assembly, for the same reason as api.ts)
//
// The vendor APIs as they actually are (verified in implementation):
//   - wrangler 4.128.0 `secret bulk` = `PATCH /accounts/{account}/workers/scripts/
//     {script}/secrets-bulk`, `Content-Type: application/merge-patch+json`,
//     body `{"secrets": {NAME: {"name","text","type":"secret_text"} | null}}`
//     (null = delete). `--env` composes the script name `<name>-<env>`
//     (getLegacyScriptName). An undeployed Worker is error code 10007 /
//     10090 (isWorkerNotFoundError) — wrangler creates a draft Worker; the
//     http driver does not, and guides with a typed error instead.
//     The envelope is `{success, errors[{code,message}], messages, result}`
//   - Vercel CLI 59.11.7 `env add --force` = `POST /v10/projects/{id}/env?upsert=true`,
//     body `{type, key, value, target[], gitBranch}` (type = production /
//     preview is "sensitive"; development or --no-sensitive is
//     "encrypted"). The public REST docs also accept an **array** on the
//     same endpoint (bulk), and the response is `{created, failed[]}`.
//     `env rm` = `GET /v10/projects/{id}/env?target=&gitBranch=` to look up
//     the id, then `DELETE /v10/projects/{id}/env/{envId}`. team is
//     `?teamId=`.
//     The CLI also retries 429 / Retry-After (sleep + skew)
//   - Netlify (verified against the swagger 2.57.1 at open-api.netlify.com,
//     docs.netlify.com, and netlify-cli's `env:set` / `env:unset`): base
//     `https://api.netlify.com/api/v1`, and environment variables live on an
//     **account (team)-scoped** endpoint that a `site_id` query points at a
//     site. `POST /accounts/{account_id}/env?site_id=` (array. **Creation
//     only**), `PATCH /accounts/{account_id}/env/{key}?site_id=` (body
//     `{context, context_parameter?, value}` = create / update the value of
//     one context of an **existing key**. swagger verbatim: "for an existing
//     environment variable"), `GET /accounts/{account_id}/env?site_id=`
//     (array. secret values are not returned), `DELETE …/env/{key}`
//     (per key = every context), `DELETE …/env/{key}/value/{id}` (only one
//     context's value). netlify-cli itself also looks the name up in the
//     list and then branches "POST if absent, PATCH if present (with a
//     context)" = there is no standalone upsert. The error body is
//     `{code, message}`. A secret (`is_secret`) is write-only, cannot be
//     placed on `all` / `dev`, and cannot have the `post_processing` scope
//     (the CLI sends the 3 scopes builds / functions / runtime explicitly).
//     The rate limit is 500 req / min (`X-RateLimit-*`; whether 429 carries
//     `Retry-After` is not in the docs)
//
// Response bodies are handled on the premise that they can echo values and
// tokens (Vercel's `created` returns the value): on success they are
// discarded; on failure only the extracted fragments are shown, after going
// through sync-exec.ts's scrubVendorOutput (redact, then truncate).

import { Duration, Effect, Redacted } from "effect";
import { HttpClient, HttpClientRequest } from "effect/unstable/http";

import { decodeValueText, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { scrubVendorOutput, type SyncWrite } from "./sync-exec.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";
import { CLI_VERSION } from "./version.ts";

/**
 * One token of a URL path or query. A literal, an option value, the target-side
 * ID of a delete, or the variable name — there is deliberately no token for the
 * value here.
 */
export type PathToken =
  | string
  | { readonly kind: "option"; readonly option: string }
  /** The delete's second step only: the target-side ID looked up via the list. */
  | { readonly kind: "id" }
  /** Requests carrying exactly one variable only (each step of create-or-update, removeItem): the variable name. */
  | { readonly kind: "name" };

/** One leaf of the per-variable entry template (the only place a value goes). */
export type EntryToken =
  | { readonly kind: "name" }
  | { readonly kind: "value" }
  | { readonly kind: "option"; readonly option: string };

/** JSON tree whose leaves may be literals or tokens of `T`. */
export type JsonTemplate<T> =
  | string
  | number
  | boolean
  | null
  | T
  | readonly JsonTemplate<T>[]
  | { readonly [key: string]: JsonTemplate<T> };

/** Tokens allowed in the request body outside the entries. */
export type BodyToken =
  | { readonly kind: "entries" }
  | { readonly kind: "option"; readonly option: string };

/**
 * How a batch's entries are laid out inside the body. `single` = the request
 * carries exactly one variable and the body's `entries` token is that entry.
 */
export type EntriesLayout = "object-by-name" | "array" | "single";

/** One write request (a batch of variables, or exactly one for `single`). */
export interface HttpWriteSpec {
  readonly method: "POST" | "PATCH" | "PUT";
  readonly path: readonly PathToken[];
  /** The query (options whose value is undefined are omitted). */
  readonly query: Readonly<Record<string, PathToken>>;
  readonly contentType: string;
  /** The whole body (contains one `{kind: "entries"}`). */
  readonly body: JsonTemplate<BodyToken>;
  readonly entries: EntriesLayout;
  /** One variable's entry (the only place a value token sits). */
  readonly entry: JsonTemplate<EntryToken>;
  /**
   * A deletion's entry (the shape that rides along with writes in
   * object-by-name — a JSON `null` under Workers' merge-patch). Only
   * presets with `delete.kind === "in-write"` carry this.
   */
  readonly deletedEntry?: JsonTemplate<EntryToken>;
}

/** A list request of the target's variables (used for the ID / key matching only — never for values). */
export interface HttpListSpec {
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
  /** The response field that holds the list (null = the body itself is the array). */
  readonly itemsField: string | null;
  readonly keyField: string;
  /**
   * The path of the field that says the list has a continuation (Vercel =
   * `pagination.next`). Omitted = the list is always complete. A name
   * missing from a list that has a continuation is not evidence that it is
   * "gone", and not evidence that it "doesn't exist" either (fail-closed).
   */
  readonly nextPage?: readonly [string, string];
}

/**
 * How writes reach the target: one request upserts a batch (Workers / Vercel),
 * or the target has no upsert and the preset lists the existing keys once,
 * then creates the missing ones and updates the rest, one request per variable
 * (Netlify). The list is read for the key names only.
 */
export type HttpWriteStrategy =
  | { readonly kind: "upsert"; readonly request: HttpWriteSpec; readonly batch: number }
  | {
      readonly kind: "create-or-update";
      readonly list: HttpListSpec;
      /** Names not in the list (`entries` is `array` or `single`, one request per variable). */
      readonly create: HttpWriteSpec;
      /** Names in the list (same). */
      readonly update: HttpWriteSpec;
      /**
       * The guard of an attribute an update request **cannot change**: when
       * the derived option is true, the write is not sent unless the list
       * item's `field` is also true (Netlify's `is_secret` — PATCH only
       * takes a value, so a non-secret variable must not silently get a
       * value meant for a secret).
       */
      readonly updateGuards?: readonly {
        readonly field: string;
        readonly option: string;
        /** The tail of the message (what to do). */
        readonly hint: string;
      }[];
    };

/** A DELETE request of the lookup delete (by ID, or by name for a whole item). */
export interface HttpRemoveSpec {
  readonly method: "DELETE";
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
}

/** How a delete is expressed: riding along in a write (a merge-patch null), or looked up in a list then deleted one by one. */
export type HttpDeleteSpec =
  | { readonly kind: "in-write" }
  | {
      readonly kind: "lookup";
      readonly list: HttpListSpec;
      /**
       * Matching the target-side environment (a same-named variable of a
       * different environment is never deleted): among the item's elements
       * (or each element of the `valuesField` array), those whose
       * `targetField` equals (or contains, if an array) the `targetOption`
       * value, and whose `branchField` equals the `branchOption` value
       * (or is unset when there is none), have their `idField` deleted.
       */
      readonly match: {
        /** The nesting where the item's elements carrying an id live (Netlify's `values[]`). The item itself when absent. */
        readonly valuesField?: string;
        readonly idField: string;
        readonly targetField: string;
        readonly targetOption: string;
        readonly branchField: string;
        readonly branchOption: string;
      };
      readonly remove: HttpRemoveSpec;
      /**
       * The per-item deletion sent instead when the matched elements were
       * **all** of the item's elements (Netlify: a variable whose other
       * contexts have no values is deleted per key, leaving no empty
       * variable).
       */
      readonly removeItem?: HttpRemoveSpec;
    };

/** How a response is read (a closed set — additions are one entry here). */
export type ResponseKind = "cloudflare-v4" | "vercel-env" | "netlify-env";

/** Derived options (config values + `derive`'s products. Arrays are used only as body leaves). */
export type DerivedOptions = Readonly<Record<string, string | boolean | readonly string[]>>;

/** A declarative http preset (data — no per-vendor request code). */
export interface HttpPreset {
  /** The destination (fixed. Config cannot change it). */
  readonly host: string;
  /** The human-facing name (for messages — "the Vercel API"). */
  readonly label: string;
  readonly write: HttpWriteStrategy;
  readonly delete: HttpDeleteSpec;
  readonly response: ResponseKind;
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  /**
   * The option names that compose the target's display name (the plan /
   * apply header line — sync-plan.ts's describeDestination). In
   * declaration order, only the set string values are listed. Only
   * non-sensitive options go up (IDs are redundant, so they don't).
   */
  readonly describeOptions: readonly string[];
  /**
   * Consistency across the config's options (one option's type and closed
   * set are checked by the `options` declaration). The reason when invalid
   * (it becomes the config's validation message. The value entered is not
   * shown).
   */
  readonly check?: (options: ResolvedOptions) => string | null;
  /** Values derived from the config's options (a script name, Vercel's type, etc. Values are never touched). */
  readonly derive: (options: ResolvedOptions) => DerivedOptions;
  /** Guidance for creating the integration token (for error messages. Points at the docs section). */
  readonly tokenHint: string;
}

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

/** An integration token (already decrypted — kept wrapped until just before it goes on the header). */
export type IntegrationToken = Redacted.Redacted<string>;

/** The retry tuning (shortened in tests). */
export interface HttpRetryPolicy {
  /** The number of attempts for one request (including the first). */
  readonly attempts: number;
  readonly baseDelay: Duration.Duration;
  /** The cap on honoring `Retry-After` (beyond it the request fails instead of waiting). */
  readonly maxDelay: Duration.Duration;
}

/** Production retry: 3 attempts, doubling from 0.5 s, honoring Retry-After up to 30 s. */
export const DEFAULT_HTTP_RETRY: HttpRetryPolicy = {
  attempts: 3,
  baseDelay: Duration.millis(500),
  maxDelay: Duration.seconds(30),
};

/** The result of one request (the caller discards or redacts a body that can contain values / tokens). */
interface HttpOutcome {
  readonly status: number;
  readonly text: string;
}

/** Reading a vendor API's response body (broken JSON is null). */
function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // A body that is not JSON (a WAF block page, etc.) = treated as an unreadable response
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Per-request material allowed on the path (a delete's ID, a one-variable request's name). */
interface PathSubject {
  readonly id: string | null;
  readonly name: string | null;
}

const NO_SUBJECT: PathSubject = { id: null, name: null };

/** Expanding the path / query tokens (a value never goes on — the token type has none). */
function renderPathToken(
  token: PathToken,
  options: DerivedOptions,
  subject: PathSubject,
): string | undefined {
  if (typeof token === "string") {
    return token;
  }
  if (token.kind === "id" || token.kind === "name") {
    const value = subject[token.kind];
    if (value === null) {
      throw new Error(`preset uses a ${token.kind} token in a request that has none`);
    }
    return encodeURIComponent(value);
  }
  const value = options[token.option];
  return typeof value === "string" ? encodeURIComponent(value) : undefined;
}

/** Expanding a path (a missing required option is a declaration/verification mismatch = internal error). */
function renderPath(
  path: readonly PathToken[],
  options: DerivedOptions,
  subject: PathSubject,
): string {
  return path
    .map((token) => {
      const rendered = renderPathToken(token, options, subject);
      if (rendered === undefined) {
        throw new Error("preset path names an option the config does not resolve");
      }
      return rendered;
    })
    .join("");
}

/** Expanding a query (unset options are omitted). */
function renderQuery(
  query: Readonly<Record<string, PathToken>>,
  options: DerivedOptions,
): Readonly<Record<string, string>> {
  const params: Record<string, string> = {};
  for (const [key, token] of Object.entries(query)) {
    const rendered = renderPathToken(token, options, NO_SUBJECT);
    if (rendered !== undefined) {
      // The query is encoded by UrlParams afterwards (don't double-apply the path encoding)
      params[key] = typeof token === "string" ? rendered : decodeURIComponent(rendered);
    }
  }
  return params;
}

/**
 * Expanding one entry. The value token places the plaintext unwrapped from
 * `Redacted` onto a JSON leaf (this function's product is used only as
 * material for the request body — it never flows to logs or errors).
 */
function renderEntry(
  template: JsonTemplate<EntryToken>,
  input: { readonly name: string; readonly text: string | null; readonly options: DerivedOptions },
): unknown {
  if (template === null || typeof template !== "object") {
    return template;
  }
  if (Array.isArray(template)) {
    return (template as readonly JsonTemplate<EntryToken>[]).map((item) =>
      renderEntry(item, input),
    );
  }
  if (isToken(template)) {
    return renderEntryToken(template as EntryToken, input);
  }
  const rendered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(template as Record<string, JsonTemplate<EntryToken>>)) {
    const item = renderEntry(value, input);
    // undefined (an unset option) is omitted with its key (JSON.stringify would drop it too)
    if (item !== undefined) {
      rendered[key] = item;
    }
  }
  return rendered;
}

/** Whether a template leaf is a token (an object with `kind`). */
function isToken(template: object): boolean {
  return "kind" in template && typeof (template as { kind?: unknown }).kind === "string";
}

/** The value of one token (name / value / option. An unset option is undefined = omitted). */
function renderEntryToken(
  token: EntryToken,
  input: { readonly name: string; readonly text: string | null; readonly options: DerivedOptions },
): unknown {
  switch (token.kind) {
    case "name":
      return input.name;
    case "value":
      return input.text;
    case "option":
      return input.options[token.option];
  }
}

/** Expanding the whole body (the expanded entry set goes at the `entries` position). */
function renderBody(
  template: JsonTemplate<BodyToken>,
  entries: unknown,
  options: DerivedOptions,
): unknown {
  if (template === null || typeof template !== "object") {
    return template;
  }
  if (Array.isArray(template)) {
    return (template as readonly JsonTemplate<BodyToken>[]).map((item) =>
      renderBody(item, entries, options),
    );
  }
  if (isToken(template)) {
    const token = template as BodyToken;
    return token.kind === "entries" ? entries : options[token.option];
  }
  const rendered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(template as Record<string, JsonTemplate<BodyToken>>)) {
    const item = renderBody(value, entries, options);
    if (item !== undefined) {
      rendered[key] = item;
    }
  }
  return rendered;
}

/** One planned request of a target: the names it carries, and how to build it. */
export interface HttpBatch {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}

/** Derived options (config values + `derive`'s products). */
export function resolveOptions(preset: HttpPreset, options: ResolvedOptions): DerivedOptions {
  return { ...options, ...preset.derive(options) };
}

/**
 * Splits writes (and, for presets whose delete rides along, deletes) into
 * batches: one request's worth for an upsert preset, and one batch holding
 * every write for a create-or-update preset (it lists the target once, then
 * sends one request per variable — reported together). Pure — nothing is
 * sent here.
 */
export function buildBatches(input: {
  readonly preset: HttpPreset;
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}): readonly HttpBatch[] {
  const { preset } = input;
  const batches: HttpBatch[] = [];
  const inWrite = preset.delete.kind === "in-write";
  const items: (readonly [string, SyncWrite | null])[] = [
    ...input.writes.map((write) => [write.name, write] as const),
    ...(inWrite ? input.deletes.map((name) => [name, null] as const) : []),
  ];
  const size = preset.write.kind === "upsert" ? preset.write.batch : Math.max(1, items.length);
  for (let start = 0; start < items.length; start += size) {
    const chunk = items.slice(start, start + size);
    batches.push({
      kind: "write",
      names: chunk.map(([name]) => name),
      writes: chunk.flatMap(([, write]) => (write === null ? [] : [write])),
      deletes: chunk.flatMap(([name, write]) => (write === null ? [name] : [])),
    });
  }
  if (!inWrite) {
    for (const name of input.deletes) {
      batches.push({ kind: "delete", names: [name], writes: [], deletes: [name] });
    }
  }
  return batches;
}

/** The input of the stateful sending part (for one target). */
export interface HttpTargetInput {
  readonly preset: HttpPreset;
  readonly options: DerivedOptions;
  readonly token: IntegrationToken;
  readonly retry: HttpRetryPolicy;
}

/** The outcome of one vendor API request (only extracted fragments of the body go out). */
export interface HttpRequestResult {
  /** Names delivered successfully (a partial-success response [Vercel's failed] is split here). */
  readonly delivered: readonly string[];
  /** The failure (null = everything succeeded). The message is already redacted and carries only variable names and response fragments. */
  readonly failure: {
    readonly names: readonly string[];
    /**
     * What happened (the head of the error message — discriminates the 5
     * sentence shapes: refused / unconfirmed response / send failure /
     * list failure / not sent. `lines` gives the details). Never carries
     * a value.
     */
    readonly what: string;
    readonly lines: readonly string[];
  } | null;
}

const RETRIABLE_STATUSES = new Set([429, 502, 503, 504]);

/** Interpreting `Retry-After` (seconds or an HTTP date). null if unreadable. */
function retryAfterOf(header: string | undefined, now: number): Duration.Duration | null {
  if (header === undefined) {
    return null;
  }
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Duration.seconds(seconds);
  }
  const at = Date.parse(header);
  return Number.isNaN(at) ? null : Duration.millis(Math.max(0, at - now));
}

/**
 * Sends one request with the preset's bearer token, retrying transport
 * failures and 429 / 502 / 503 / 504 (upserts and deletes are idempotent, so a
 * re-send is safe). The response body is returned whole for the caller to
 * interpret and scrub — never logged here.
 */
function send(
  input: HttpTargetInput,
  request: HttpClientRequest.HttpClientRequest,
): Effect.Effect<HttpOutcome, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const client = yield* HttpClient.HttpClient;
    const prepared = request.pipe(
      HttpClientRequest.bearerToken(input.token),
      HttpClientRequest.setHeader("accept", "application/json"),
      HttpClientRequest.setHeader("user-agent", `maruhi-cli/${CLI_VERSION}`),
    );
    let lastFailure = "";
    for (let attempt = 1; attempt <= input.retry.attempts; attempt += 1) {
      const outcome = yield* client.execute(prepared).pipe(
        Effect.flatMap((response) =>
          Effect.map(response.text, (text) => ({
            kind: "response" as const,
            status: response.status,
            retryAfter: retryAfterOf(response.headers["retry-after"], Date.now()),
            text,
          })),
        ),
        // A transport-layer failure (DNS, connection, TLS). The message is only a description of the destination; no body
        Effect.catch((error) =>
          Effect.succeed({ kind: "transport" as const, message: describeTransport(error) }),
        ),
      );
      if (outcome.kind === "response" && !RETRIABLE_STATUSES.has(outcome.status)) {
        return { status: outcome.status, text: outcome.text };
      }
      lastFailure =
        outcome.kind === "transport"
          ? outcome.message
          : `${input.preset.label} answered ${outcome.status}`;
      if (attempt === input.retry.attempts) {
        break;
      }
      const backoff = Duration.times(input.retry.baseDelay, 2 ** (attempt - 1));
      const wait =
        outcome.kind === "response" && outcome.retryAfter !== null ? outcome.retryAfter : backoff;
      if (Duration.isGreaterThan(wait, input.retry.maxDelay)) {
        return yield* Effect.fail(
          cliError(
            `${input.preset.label} asked to retry after ${Math.ceil(Duration.toSeconds(wait))} seconds (Retry-After), longer than maruhi waits. Run \`maruhi sync apply\` again later`,
          ),
        );
      }
      yield* Effect.sleep(wait);
    }
    return yield* Effect.fail(
      cliError(`${lastFailure} (${input.retry.attempts} attempts). Check the network and retry`),
    );
  });
}

/** Describing a transport-layer failure (only the destination host and the error kind. No body or headers). */
function describeTransport(error: unknown): string {
  const tag = isRecord(error) && typeof error["_tag"] === "string" ? error["_tag"] : "error";
  const description =
    isRecord(error) && typeof error["description"] === "string" ? `: ${error["description"]}` : "";
  return `Could not reach the vendor API (${tag}${displayText(description)})`;
}

/** Extracts the showable fragments from a response body and redacts them (values, tokens). */
function scrubbed(
  lines: readonly string[],
  writes: readonly SyncWrite[],
  token: IntegrationToken,
): string[] {
  return scrubVendorOutput(lines.join("\n"), writes, [token]);
}

/** Turns a Cloudflare envelope's errors / messages into lines. */
function cloudflareLines(body: unknown, status: number): string[] {
  if (!isRecord(body)) {
    return [`HTTP ${status}`];
  }
  return [
    `HTTP ${status}`,
    ...recordsOf(body["errors"]).map(
      (entry) => `error ${String(entry["code"] ?? "")}: ${String(entry["message"] ?? "")}`,
    ),
    ...arrayOf(body["messages"]).map((message) =>
      typeof message === "string" ? message : String(isRecord(message) ? message["message"] : ""),
    ),
  ];
}

/** Empty unless an array (absorbs wobble in the response shape). */
function arrayOf(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Only the object elements of an array. */
function recordsOf(value: unknown): readonly Record<string, unknown>[] {
  return arrayOf(value).filter(isRecord);
}

/** The set of Cloudflare errors[].code values. */
function cloudflareCodes(body: unknown): Set<number> {
  const codes = new Set<number>();
  if (isRecord(body) && Array.isArray(body["errors"])) {
    for (const entry of body["errors"]) {
      if (isRecord(entry) && typeof entry["code"] === "number") {
        codes.add(entry["code"]);
      }
    }
  }
  return codes;
}

// wrangler's isWorkerNotFoundError (worker-not-found-error.ts)
const CLOUDFLARE_WORKER_NOT_FOUND = new Set([10007, 10090]);

/** The Cloudflare v4 envelope check: 2xx and `success: true`. */
function readCloudflare(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status >= 200 && outcome.status < 300 && isRecord(body) && body["success"] === true) {
    return { delivered: batch.names, failure: null };
  }
  const codes = cloudflareCodes(body);
  const lines = cloudflareLines(body, outcome.status);
  if ([...codes].some((code) => CLOUDFLARE_WORKER_NOT_FOUND.has(code))) {
    lines.push(
      `No Worker named ${displayText(String(input.options["scriptName"]))} exists in this account. maruhi does not create one: deploy the Worker first (\`wrangler deploy\`), then apply again`,
    );
  }
  return {
    delivered: [],
    failure: {
      names: batch.names,
      what: `${input.preset.label} refused the request`,
      lines: scrubbed(lines, batch.writes, input.token),
    },
  };
}

/** Reading Vercel's `{created, failed[]}` (partial success is split by name). */
function readVercel(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  if (outcome.status < 200 || outcome.status >= 300 || !isRecord(body)) {
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} refused the request`,
        lines: scrubbed(vercelErrorLines(outcome.status, body), batch.writes, input.token),
      },
    };
  }
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  if (!("created" in body)) {
    // A write 2xx without `created` = not the expected response shape (a
    // schema change, an intermediary's response). Not read as delivered
    return {
      delivered: [],
      failure: {
        names: batch.names,
        what: `${input.preset.label} did not confirm the write`,
        lines: scrubbed(
          [`HTTP ${outcome.status} without a created field (unexpected response shape)`],
          batch.writes,
          input.token,
        ),
      },
    };
  }
  const failed = recordsOf(body["failed"]);
  if (failed.length === 0) {
    // An empty failed means everything was delivered (created's shape wobbles between one entry and an array)
    return { delivered: batch.names, failure: null };
  }
  const created = body["created"];
  const createdKeys = new Set(keysOf(Array.isArray(created) ? created : [created]));
  const failures = failed.map(vercelFailureOf);
  const failedNames = new Set(failures.flatMap((entry) => (entry.key === null ? [] : [entry.key])));
  // If the failed names cannot be identified, the whole batch is undelivered (don't mis-record as delivered)
  const delivered =
    failedNames.size === 0
      ? []
      : batch.names.filter((name) => !failedNames.has(name) && createdKeys.has(name));
  const names = batch.names.filter((name) => !delivered.includes(name));
  const lines = [`HTTP ${outcome.status}`, ...failures.map((entry) => entry.line)];
  return {
    delivered,
    failure: {
      names,
      what: `${input.preset.label} refused the request`,
      lines: scrubbed(lines, batch.writes, input.token),
    },
  };
}

/** The display lines of Vercel's non-2xx response (`{error: {code, message}}`). */
function vercelErrorLines(status: number, body: unknown): string[] {
  const error = isRecord(body) && isRecord(body["error"]) ? body["error"] : null;
  return error === null
    ? [`HTTP ${status}`]
    : [`HTTP ${status}`, `error ${String(error["code"] ?? "")}: ${String(error["message"] ?? "")}`];
}

/** The `key` of a response entry (string ones only). */
function keysOf(entries: readonly unknown[]): readonly string[] {
  return entries.filter(isRecord).flatMap((entry) => {
    const key = entry["key"];
    return typeof key === "string" ? [key] : [];
  });
}

/** One Vercel `failed[]` entry → the failed name and a display line (redaction is the caller's). */
function vercelFailureOf(entry: Record<string, unknown>): {
  readonly key: string | null;
  readonly line: string;
} {
  const error = isRecord(entry["error"]) ? entry["error"] : {};
  const named = [error["key"], error["envVarKey"]].find((value) => typeof value === "string");
  const key = typeof named === "string" ? named : null;
  return {
    key,
    line: `error ${String(error["code"] ?? "")}${key === null ? "" : ` (${key})`}: ${String(error["message"] ?? "")}`,
  };
}

/** The display lines of Netlify's non-2xx response (`{code, message}`) (only the status when the body is not JSON). */
function netlifyErrorLines(status: number, body: unknown): string[] {
  return isRecord(body) && typeof body["message"] === "string"
    ? [`HTTP ${status}`, `error ${String(body["code"] ?? status)}: ${body["message"]}`]
    : [`HTTP ${status}`];
}

/**
 * Reading Netlify: 2xx. For a write (POST = array / PATCH = one variable)
 * the response's `key` must also carry the name (a differently-shaped 2xx
 * is not read as "delivered" — same posture as Vercel's `created`). A
 * delete is a 204 with no body. The response echoes the value (discarded).
 */
function readNetlify(
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
): HttpRequestResult {
  const body = parseJson(outcome.text);
  const failure = (what: string, lines: readonly string[]): HttpRequestResult => ({
    delivered: [],
    failure: { names: batch.names, what, lines: scrubbed(lines, batch.writes, input.token) },
  });
  if (outcome.status < 200 || outcome.status >= 300) {
    return failure(
      `${input.preset.label} refused the request`,
      netlifyErrorLines(outcome.status, body),
    );
  }
  if (batch.kind === "delete") {
    return { delivered: batch.names, failure: null };
  }
  const keys = new Set(keysOf(Array.isArray(body) ? body : [body]));
  return batch.names.every((name) => keys.has(name))
    ? { delivered: batch.names, failure: null }
    : failure(`${input.preset.label} did not confirm the write`, [
        `HTTP ${outcome.status} without the variable in the response (unexpected response shape)`,
      ]);
}

function readResponse(
  kind: ResponseKind,
  outcome: HttpOutcome,
  batch: HttpBatch,
  input: HttpTargetInput,
) {
  switch (kind) {
    case "cloudflare-v4":
      return readCloudflare(outcome, batch, input);
    case "vercel-env":
      return readVercel(outcome, batch, input);
    case "netlify-env":
      return readNetlify(outcome, batch, input);
  }
}

/**
 * Building a write request (the value is unwrapped here and placed in the
 * body, and the product is handed only to the send). A `single`
 * declaration takes exactly one variable, and its name goes on the path's
 * name token.
 */
function buildWriteRequest(
  input: HttpTargetInput,
  write: HttpWriteSpec,
  batch: HttpBatch,
): HttpClientRequest.HttpClientRequest {
  const single = write.entries === "single";
  if (single && batch.names.length !== 1) {
    throw new Error("a single-variable write was built for a batch of another size");
  }
  const entries = renderEntries(write, batch, input.options);
  const laid =
    write.entries === "object-by-name"
      ? Object.fromEntries(entries)
      : single
        ? entries[0]?.[1]
        : entries.map(([, entry]) => entry);
  const body = renderBody(write.body, laid, input.options);
  const subject: PathSubject = { id: null, name: single ? (batch.names[0] ?? null) : null };
  return HttpClientRequest.make(write.method)(
    `https://${input.preset.host}${renderPath(write.path, input.options, subject)}`,
    { urlParams: renderQuery(write.query, input.options) },
  ).pipe(HttpClientRequest.bodyText(JSON.stringify(body), write.contentType));
}

/** Expands a batch's entries (writes + riding deletes) with their names (the value is unwrapped here). */
function renderEntries(
  write: HttpWriteSpec,
  batch: HttpBatch,
  options: DerivedOptions,
): (readonly [string, unknown])[] {
  const entries: (readonly [string, unknown])[] = [];
  for (const item of batch.writes) {
    // Why it is unwrapped: the value leaf of a body entry (the moment the
    // value leaves maruhi. This product flows only into the request body,
    // and failure display uses only fragments extracted from the response
    // and redacted)
    const text = decodeValueText(Redacted.value(item.value));
    if (text === null) {
      // A defensive line on the premise that prepareWork (sync-plan.ts) has already filtered these out before sending
      throw new Error("a value that is not valid UTF-8 reached the http driver");
    }
    entries.push([item.name, renderEntry(write.entry, { name: item.name, text, options })]);
  }
  for (const name of batch.deletes) {
    if (write.deletedEntry === undefined) {
      throw new Error("a delete rode along on a preset that has no deleted entry");
    }
    entries.push([name, renderEntry(write.deletedEntry, { name, text: null, options })]);
  }
  return entries;
}

/** Reading a list (the array of items and its completeness). On failure, already-redacted lines. */
type Listing =
  | { readonly items: readonly Record<string, unknown>[]; readonly complete: boolean }
  | { readonly failure: readonly string[] };

/**
 * Reads the list once (values are discarded unread — used only for
 * name/ID matching). Also returns whether there might be a next page (if
 * there is, "absent" is not evidence — fail-closed).
 */
function fetchListing(
  input: HttpTargetInput,
  spec: HttpListSpec,
): Effect.Effect<Listing, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.get(
      `https://${input.preset.host}${renderPath(spec.path, input.options, NO_SUBJECT)}`,
      { urlParams: renderQuery(spec.query, input.options) },
    );
    const outcome = yield* send(input, request);
    const body = parseJson(outcome.text);
    const listed: unknown =
      spec.itemsField === null ? body : isRecord(body) ? body[spec.itemsField] : undefined;
    if (outcome.status < 200 || outcome.status >= 300 || !Array.isArray(listed)) {
      return {
        failure: scrubbed(
          [`HTTP ${outcome.status} while listing variables at the target`],
          [],
          input.token,
        ),
      };
    }
    return { items: listed.filter(isRecord), complete: isListingComplete(spec, body) };
  });
}

/** Whether there is no next page (Vercel's `pagination.next`. No declaration / null = the list is complete). */
function isListingComplete(spec: HttpListSpec, body: unknown): boolean {
  if (spec.nextPage === undefined || !isRecord(body)) {
    return true;
  }
  const [pageField, nextField] = spec.nextPage;
  const pagination = body[pageField];
  const next = isRecord(pagination) ? pagination[nextField] : undefined;
  return next === undefined || next === null || next === false;
}

/** The list items in name-addressable form (only those with a string `keyField`). */
function listedByKey(
  items: readonly Record<string, unknown>[],
  keyField: string,
): Map<string, Record<string, unknown>> {
  const byKey = new Map<string, Record<string, unknown>>();
  for (const item of items) {
    const key = item[keyField];
    if (typeof key === "string") {
      byKey.set(key, item);
    }
  }
  return byKey;
}

/**
 * The guard of an attribute an update cannot change (`updateGuards`): the
 * message when broken (variable name and attribute name only — no value),
 * null when honored.
 */
function guardUpdate(
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  name: string,
  item: Record<string, unknown>,
  options: DerivedOptions,
): string | null {
  for (const guard of write.updateGuards ?? []) {
    if (options[guard.option] === true && item[guard.field] !== true) {
      return `${displayText(name)} already exists at the target with ${guard.field} off, and the config asks for it on. ${guard.hint}`;
    }
  }
  return null;
}

/** The delete's matching: whether the element belongs to "this target's environment" (a same-named variable of a different environment is never deleted). */
function matchesTarget(
  element: Record<string, unknown>,
  match: Extract<HttpDeleteSpec, { kind: "lookup" }>["match"],
  options: DerivedOptions,
): boolean {
  const target = options[match.targetOption];
  const branch = options[match.branchOption];
  const targets = element[match.targetField];
  const elementBranch = element[match.branchField];
  const targetMatches = Array.isArray(targets) ? targets.includes(target) : targets === target;
  const branchMatches =
    typeof branch === "string"
      ? elementBranch === branch
      : elementBranch === undefined || elementBranch === null;
  return targetMatches && branchMatches;
}

/**
 * The delete's first step: look up the target-side IDs in the list.
 * `whole` = the matched elements were all of that name's item's elements
 * (the item may be deleted whole — only presets with a `removeItem` use
 * this).
 */
function lookupIds(
  items: readonly Record<string, unknown>[],
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  name: string,
  options: DerivedOptions,
): { readonly ids: readonly string[]; readonly whole: boolean } {
  const ids: string[] = [];
  let matchedItems = 0;
  let wholeItems = 0;
  for (const item of items.filter((entry) => entry[spec.list.keyField] === name)) {
    const { valuesField } = spec.match;
    const elements = valuesField === undefined ? [item] : recordsOf(item[valuesField]);
    const hits = elements.filter((element) => matchesTarget(element, spec.match, options));
    if (hits.length === 0) {
      continue;
    }
    matchedItems += 1;
    if (valuesField !== undefined && hits.length === elements.length) {
      wholeItems += 1;
    }
    for (const hit of hits) {
      const id = hit[spec.match.idField];
      if (typeof id === "string") {
        ids.push(id);
      }
    }
  }
  return { ids, whole: matchedItems > 0 && wholeItems === matchedItems };
}

/** A batch of exactly one variable (each step of create-or-update goes through readResponse). */
function singleBatch(write: SyncWrite): HttpBatch {
  return { kind: "write", names: [write.name], writes: [write], deletes: [] };
}

/**
 * The create-or-update write: look the names up in the list, send a create
 * for each absent name and an update for each present one, one variable at
 * a time. Stop at the first failure and return the delivered names (if a
 * same-named variable gets created between the listing and the send, the
 * create surfaces as a target-side failure — the next apply becomes an
 * update).
 */
function createOrUpdate(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const listing = yield* fetchListing(input, write.list);
    if ("failure" in listing) {
      // The listing did get a response back (lines state the HTTP status),
      // so don't say "not sent" — what failed is reported as the listing's
      // failure
      return {
        delivered: [],
        failure: {
          names: batch.names,
          what: `${input.preset.label} did not list the existing variables`,
          lines: listing.failure,
        },
      };
    }
    if (!listing.complete) {
      // Judging by a list that has a continuation would create a name that
      // already exists and fail (or create it twice under the target's
      // rules). Stop without sending anything
      return {
        delivered: [],
        failure: {
          names: batch.names,
          what: "maruhi did not send the request",
          lines: [
            `${input.preset.label} returned a paginated list of variables, so maruhi could not tell which of them already exist at the target. Nothing was written; apply again later`,
          ],
        },
      };
    }
    return yield* writeOneByOne(
      input,
      write,
      batch,
      listedByKey(listing.items, write.list.keyField),
    );
  });
}

/** The sending part of create-or-update: one variable at a time, stopping at the first failure. */
function writeOneByOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  batch: HttpBatch,
  existing: ReadonlyMap<string, Record<string, unknown>>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const delivered: string[] = [];
    for (const item of batch.writes) {
      const one = singleBatch(item);
      const listed = existing.get(item.name);
      // Even if sending one variable fails with a typed error (attempts
      // exhausted, Retry-After exceeded), the names delivered earlier in
      // this batch are not lost: reported as that variable's failure, and
      // the delivered ones go to the receipt (in create-or-update the whole
      // write is one batch, so letting it fall erases the run's progress)
      const result = yield* (
        listed === undefined
          ? createOrRecover(input, write, one)
          : updateOne(input, write, one, listed)
      ).pipe(
        Effect.catch((error: CliError) =>
          Effect.succeed({
            delivered: [],
            failure: {
              names: one.names,
              what: `the request to ${input.preset.label} failed`,
              lines: [error.message],
            },
          }),
        ),
      );
      if (result.failure !== null) {
        return { delivered, failure: result.failure };
      }
      delivered.push(item.name);
    }
    return { delivered, failure: null };
  });
}

/** A name in the list: pass the guard (`updateGuards`), then send one update. */
function updateOne(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
  listed: Record<string, unknown>,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  const refused = guardUpdate(write, one.names[0] ?? "", listed, input.options);
  if (refused !== null) {
    // Stop without sending (no value lands. The delivered share goes to the receipt)
    return Effect.succeed({
      delivered: [],
      failure: { names: one.names, what: "maruhi did not send the request", lines: [refused] },
    });
  }
  return Effect.map(send(input, buildWriteRequest(input, write.update, one)), (outcome) =>
    readResponse(input.preset.response, outcome, one, input),
  );
}

/**
 * A name not in the list: send the create. create is not an upsert (it
 * refuses an existing key), so shapes like a delivered response lost and
 * resent (`send`'s retry) or a same-named variable created between the
 * listing and the send come back as a target-side failure. In that case,
 * **re-read the list** and switch to an update if the name is there
 * (regardless of the response's wording). If not, the create's failure
 * stands.
 */
function createOrRecover(
  input: HttpTargetInput,
  write: Extract<HttpWriteStrategy, { kind: "create-or-update" }>,
  one: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const outcome = yield* send(input, buildWriteRequest(input, write.create, one));
    const created = readResponse(input.preset.response, outcome, one, input);
    if (created.failure === null) {
      return created;
    }
    // Even if the re-read listing fails (transport layer, attempts
    // exhausted = a typed error), fall back to reporting the create's
    // failure: failing here would keep names already delivered in the same
    // batch off the receipt
    const listing = yield* fetchListing(input, write.list).pipe(
      Effect.catch((error: CliError) => Effect.succeed({ failure: [error.message] })),
    );
    if ("failure" in listing) {
      return withRecheckFailure(created, listing.failure);
    }
    if (!listing.complete) {
      return created;
    }
    const listed = listedByKey(listing.items, write.list.keyField).get(one.names[0] ?? "");
    return listed === undefined ? created : yield* updateOne(input, write, one, listed);
  });
}

/** Attaches the re-read listing's failure (already-redacted lines) to a create's failure. */
function withRecheckFailure(
  created: HttpRequestResult,
  lines: readonly string[],
): HttpRequestResult {
  return created.failure === null
    ? created
    : {
        delivered: created.delivered,
        failure: {
          names: created.failure.names,
          what: created.failure.what,
          lines: [
            ...created.failure.lines,
            `Could not re-check the target after the failed create: ${lines.join(" ")}`,
          ],
        },
      };
}

/**
 * Runs one batch against the vendor API: the write request(s), or the
 * lookup-then-delete pair for presets whose delete does not ride along.
 *
 * Even when the batch's send fails with a typed error (attempts exhausted,
 * Retry-After exceeded), return it as that batch's failure: the caller
 * (sync-plan.ts's runBatches) is mid-way folding the names earlier batches
 * delivered, and failing here would erase that progress (a delete batch's
 * listing and DELETEs, an upsert's second-and-later batches). Uniform
 * across every http preset and batch kind (exec's runInvocations has the
 * same shape — a launch failure is folded into that invocation's
 * failure). A create-or-update write receives one variable at a time
 * inside and keeps the delivered share.
 */
export function runBatch(
  input: HttpTargetInput,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, never, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    if (batch.kind === "write") {
      const { write } = input.preset;
      if (write.kind === "create-or-update") {
        return yield* createOrUpdate(input, write, batch);
      }
      const outcome = yield* send(input, buildWriteRequest(input, write.request, batch));
      return readResponse(input.preset.response, outcome, batch, input);
    }
    const spec = input.preset.delete;
    if (spec.kind !== "lookup") {
      throw new Error("a delete batch was built for a preset whose deletes ride along");
    }
    return yield* lookupAndRemove(input, spec, batch);
  }).pipe(
    Effect.catch((error: CliError) =>
      Effect.succeed({
        delivered: [],
        failure: {
          names: batch.names,
          what: `the request to ${input.preset.label} failed`,
          lines: [error.message],
        },
      }),
    ),
  );
}

/** A delete batch (one name): look the ID up in the list, then delete per value (or per item). */
function lookupAndRemove(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const name = batch.names[0] ?? "";
    const listing = yield* fetchListing(input, spec.list);
    if ("failure" in listing) {
      // The listing did get a response back (lines state the HTTP status),
      // so don't say "not sent"
      return {
        delivered: [],
        failure: {
          names: batch.names,
          what: `${input.preset.label} did not list the existing variables`,
          lines: listing.failure,
        },
      };
    }
    const looked = lookupIds(listing.items, spec, name, input.options);
    if (looked.ids.length === 0 && !listing.complete) {
      // A name missing from a list that has a continuation: cannot say
      // it's "gone". Don't record it as delivered and leave it on the
      // receipt (the next apply tries again — fail-closed)
      return {
        delivered: [],
        failure: {
          names: batch.names,
          what: "maruhi did not send the request",
          lines: [
            `${input.preset.label} returned a paginated list of variables, so maruhi could not confirm that ${displayText(name)} is gone from the target. It stays in the receipt; remove it at the target yourself, or apply again`,
          ],
        },
      };
    }
    // Absent from a complete list = already deleted at the target (the re-read only matches IDs; values are never read)
    if (looked.whole && spec.removeItem !== undefined) {
      return yield* removeOne(input, spec.removeItem, batch, { id: null, name });
    }
    return yield* removeByIds(input, spec, batch, name, looked.ids);
  });
}

/** The delete's second step: DELETE each looked-up ID (404 = deleted concurrently right after the listing). */
function removeByIds(
  input: HttpTargetInput,
  spec: Extract<HttpDeleteSpec, { kind: "lookup" }>,
  batch: HttpBatch,
  name: string,
  ids: readonly string[],
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    for (const id of ids) {
      const result = yield* removeOne(input, spec.remove, batch, { id, name });
      if (result.failure !== null) {
        return result;
      }
    }
    return { delivered: batch.names, failure: null };
  });
}

/** One DELETE (by ID or name). 404 is "already gone" = success. */
function removeOne(
  input: HttpTargetInput,
  spec: HttpRemoveSpec,
  batch: HttpBatch,
  subject: PathSubject,
): Effect.Effect<HttpRequestResult, CliError, HttpClient.HttpClient> {
  return Effect.gen(function* () {
    const request = HttpClientRequest.make(spec.method)(
      `https://${input.preset.host}${renderPath(spec.path, input.options, subject)}`,
      { urlParams: renderQuery(spec.query, input.options) },
    );
    const outcome = yield* send(input, request);
    return outcome.status === 404
      ? { delivered: batch.names, failure: null }
      : readResponse(input.preset.response, outcome, batch, input);
  });
}

/**
 * Whether the text contains a character that cannot go on a header value:
 * C0 control characters (including newlines), DEL, or outside ISO-8859-1
 * (fetch's `Headers` refuses them with a TypeError — turned into a typed
 * error).
 */
function hasNonHeaderCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || code > 0xff) {
      return true;
    }
  }
  return false;
}

/** Checking an integration token (a shape that can go on a header). The message carries only the variable name. */
export function checkIntegrationToken(name: string, bytes: Uint8Array): CliError | string {
  const text = decodeValueText(bytes);
  if (text === null || text.length === 0) {
    return cliError(`The token variable ${displayText(name)} is empty or not valid UTF-8`);
  }
  // A character that cannot go on a header value (newline, control character) — `echo`'s trailing newline is typical
  if (hasNonHeaderCharacter(text)) {
    return cliError(
      `The token variable ${displayText(name)} contains a newline, a control character, or a character outside ISO-8859-1, so it cannot be sent as an Authorization header. Push the token without a trailing newline (\`printf %s\` instead of \`echo\`)`,
    );
  }
  return text;
}
