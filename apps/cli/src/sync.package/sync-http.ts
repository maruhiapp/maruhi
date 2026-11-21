import { Duration, Redacted } from "effect";
import { HttpClientRequest } from "effect/http";

import { decodeValueText, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { isRecord } from "../json-record.ts";
import type { SyncWrite } from "./sync-exec.ts";
import type { OptionSpec, ResolvedOptions, ValueConstraints } from "./sync-types.ts";

export type PathToken =
  | string
  | { readonly kind: "option"; readonly option: string }
  | { readonly kind: "id" }
  | { readonly kind: "name" };

export type EntryToken =
  | { readonly kind: "name" }
  | { readonly kind: "value" }
  | { readonly kind: "option"; readonly option: string };

export type JsonTemplate<T> =
  | string
  | number
  | boolean
  | null
  | T
  | readonly JsonTemplate<T>[]
  | { readonly [key: string]: JsonTemplate<T> };

export type BodyToken =
  | { readonly kind: "entries" }
  | { readonly kind: "option"; readonly option: string };

export type EntriesLayout = "object-by-name" | "array" | "single";

export interface HttpWriteSpec {
  readonly method: "POST" | "PATCH" | "PUT";
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
  readonly contentType: string;
  readonly body: JsonTemplate<BodyToken>;
  readonly entries: EntriesLayout;
  readonly entry: JsonTemplate<EntryToken>;
  readonly deletedEntry?: JsonTemplate<EntryToken>;
}

export interface HttpListSpec {
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
  readonly itemsField: string | null;
  readonly keyField: string;
  readonly nextPage?: readonly [string, string];
}

export type HttpWriteStrategy =
  | { readonly kind: "upsert"; readonly request: HttpWriteSpec; readonly batch: number }
  | {
      readonly kind: "create-or-update";
      readonly list: HttpListSpec;
      readonly create: HttpWriteSpec;
      readonly update: HttpWriteSpec;
      readonly updateGuards?: readonly {
        readonly field: string;
        readonly option: string;
        readonly hint: string;
      }[];
    };

export interface HttpRemoveSpec {
  readonly method: "DELETE";
  readonly path: readonly PathToken[];
  readonly query: Readonly<Record<string, PathToken>>;
}

export type HttpDeleteSpec =
  | { readonly kind: "in-write" }
  | {
      readonly kind: "lookup";
      readonly list: HttpListSpec;
      readonly match: {
        readonly valuesField?: string;
        readonly idField: string;
        readonly targetField: string;
        readonly targetOption: string;
        readonly branchField: string;
        readonly branchOption: string;
      };
      readonly remove: HttpRemoveSpec;
      readonly removeItem?: HttpRemoveSpec;
    };

export type ResponseKind = "cloudflare-v4" | "vercel-env" | "netlify-env";

export type DerivedOptions = Readonly<Record<string, string | boolean | readonly string[]>>;

export interface HttpPreset {
  readonly host: string;
  readonly label: string;
  readonly write: HttpWriteStrategy;
  readonly delete: HttpDeleteSpec;
  readonly response: ResponseKind;
  readonly constraints: ValueConstraints;
  readonly options: Readonly<Record<string, OptionSpec>>;
  readonly describeOptions: readonly string[];
  readonly check?: (options: ResolvedOptions) => string | null;
  readonly derive: (options: ResolvedOptions) => DerivedOptions;
  readonly tokenHint: string;
}

export type IntegrationToken = Redacted.Redacted<string>;

export interface HttpRetryPolicy {
  readonly attempts: number;
  readonly baseDelay: Duration.Duration;
  readonly maxDelay: Duration.Duration;
}

export const DEFAULT_HTTP_RETRY: HttpRetryPolicy = {
  attempts: 3,
  baseDelay: Duration.millis(500),
  maxDelay: Duration.seconds(30),
};

export interface HttpOutcome {
  readonly status: number;
  readonly text: string;
}

export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

export function arrayOf(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function recordsOf(value: unknown): readonly Record<string, unknown>[] {
  return arrayOf(value).filter(isRecord);
}

export interface PathSubject {
  readonly id: string | null;
  readonly name: string | null;
}

export const NO_SUBJECT: PathSubject = { id: null, name: null };

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

export function renderQuery(
  query: Readonly<Record<string, PathToken>>,
  options: DerivedOptions,
): Readonly<Record<string, string>> {
  const params: Record<string, string> = {};
  for (const [key, token] of Object.entries(query)) {
    const rendered = renderPathToken(token, options, NO_SUBJECT);
    if (rendered !== undefined) {
      params[key] = typeof token === "string" ? rendered : decodeURIComponent(rendered);
    }
  }
  return params;
}

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
    if (item !== undefined) {
      rendered[key] = item;
    }
  }
  return rendered;
}

function isToken(template: object): boolean {
  return "kind" in template && typeof (template as { kind?: unknown }).kind === "string";
}

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

export interface HttpBatch {
  readonly kind: "write" | "delete";
  readonly names: readonly string[];
  readonly writes: readonly SyncWrite[];
  readonly deletes: readonly string[];
}

export function resolveOptions(preset: HttpPreset, options: ResolvedOptions): DerivedOptions {
  return { ...options, ...preset.derive(options) };
}

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

export interface HttpTargetInput {
  readonly preset: HttpPreset;
  readonly options: DerivedOptions;
  readonly token: IntegrationToken;
  readonly retry: HttpRetryPolicy;
}

export interface HttpRequestResult {
  readonly delivered: readonly string[];
  readonly failure: {
    readonly names: readonly string[];
    readonly what: string;
    readonly lines: readonly string[];
  } | null;
}

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

function renderEntries(
  write: HttpWriteSpec,
  batch: HttpBatch,
  options: DerivedOptions,
): (readonly [string, unknown])[] {
  const entries: (readonly [string, unknown])[] = [];
  for (const item of batch.writes) {
    const text = decodeValueText(Redacted.value(item.value));
    if (text === null) {
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

function hasNonHeaderCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || code > 0xff) {
      return true;
    }
  }
  return false;
}

export function checkIntegrationToken(name: string, bytes: Uint8Array): CliError | string {
  const text = decodeValueText(bytes);
  if (text === null || text.length === 0) {
    return cliError(`The token variable ${displayText(name)} is empty or not valid UTF-8`);
  }
  if (hasNonHeaderCharacter(text)) {
    return cliError(
      `The token variable ${displayText(name)} contains a newline, a control character, or a character outside ISO-8859-1, so it cannot be sent as an Authorization header. Push the token without a trailing newline (\`printf %s\` instead of \`echo\`)`,
    );
  }
  return text;
}
