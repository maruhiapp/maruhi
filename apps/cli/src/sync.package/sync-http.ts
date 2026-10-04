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

import { Duration, Redacted } from "effect";
import { HttpClientRequest } from "effect/http";

import { decodeValueText, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import type { SyncWrite } from "./sync-exec.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";

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
export interface HttpOutcome {
  readonly status: number;
  readonly text: string;
}

/** Reading a vendor API's response body (broken JSON is null). */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // A body that is not JSON (a WAF block page, etc.) = treated as an unreadable response
    return null;
  }
}

/** Empty unless an array (absorbs wobble in the response shape). */
export function arrayOf(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Only the object elements of an array. */
export function recordsOf(value: unknown): readonly Record<string, unknown>[] {
  return arrayOf(value).filter(isRecord);
}

/** Per-request material allowed on the path (a delete's ID, a one-variable request's name). */
export interface PathSubject {
  readonly id: string | null;
  readonly name: string | null;
}

export const NO_SUBJECT: PathSubject = { id: null, name: null };

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
export function renderPath(
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
export function renderQuery(
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

/**
 * Building a write request (the value is unwrapped here and placed in the
 * body, and the product is handed only to the send). A `single`
 * declaration takes exactly one variable, and its name goes on the path's
 * name token.
 */
export function buildWriteRequest(
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
