// The Schema machinery shared by the user-edited config files
// (sync.package/sync-config.ts, rotate-config.ts,
// proxy.package/proxy-config.ts). Each config describes its document as
// a Schema whose ordered checks run the same steps the hand-written
// validators did, in the same order — the first failure's reason is the
// one the user sees, worded exactly as before.
//
// The currency inside a check is the `Reason` — a `Schema.FilterIssue`:
// a plain string is a complete reason, a `{path, issue}` pair names the
// field the issue belongs to, and an issue that starts with a separator
// (space / colon / dot) is a suffix appended to the dotted path
// ("variables.X.connector" + " must be ..."). A reason never contains the
// offending value.

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { isEnvironmentId } from "@maruhi/core";
import { Effect, FileSystem, Result, Schema, SchemaIssue } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { isRecord, parseConfigHeader, unknownKeys } from "./json-record.ts";

/** A validation failure (the reason's string). Never includes the value itself. */
export type Invalid = string;

/** A validation failure as a filter issue: a reason string, a `{path, issue}` pair, or a nested issue. */
export type Reason = Schema.FilterIssue;

/** Whether a parse step produced a {@link Reason} rather than a value. */
export function isReason(value: unknown): value is Reason {
  return (
    typeof value === "string" ||
    SchemaIssue.isIssue(value) ||
    (isRecord(value) &&
      Array.isArray(value["path"]) &&
      (typeof value["issue"] === "string" || SchemaIssue.isIssue(value["issue"])))
  );
}

/** Wraps a {@link Reason} as a real issue so an outer `{path, issue}` can prefix it (makeFilter's own normalization). */
export function reasonIssue(reason: Reason): SchemaIssue.Issue {
  if (SchemaIssue.isIssue(reason)) {
    return reason;
  }
  if (typeof reason === "string") {
    return new SchemaIssue.InvalidValue({ message: reason });
  }
  return new SchemaIssue.Pointer(
    reason.path,
    typeof reason.issue === "string"
      ? new SchemaIssue.InvalidValue({ message: reason.issue })
      : reason.issue,
  );
}

const reasonFormatter = SchemaIssue.makeFormatterStandardSchemaV1();

/**
 * The first issue rendered as the user's reason: a flattened message
 * starting with a separator (space / colon / dot) is a suffix appended to
 * the dotted path; anything else is already a complete reason.
 */
export function issueReason(issue: SchemaIssue.Issue): Invalid {
  const first = reasonFormatter(issue).issues[0];
  if (first === undefined) {
    return "is invalid";
  }
  const path = first.path ?? [];
  const message = first.message;
  if (
    path.length === 0 ||
    !(message.startsWith(" ") || message.startsWith(":") || message.startsWith("."))
  ) {
    return message;
  }
  return `${path.map(String).join(".")}${message}`;
}

/** A JSON object boundary: a non-object input reports the annotated suffix. */
export const JsonRecord = (suffix: string) =>
  Schema.Record(Schema.String, Schema.Unknown).annotate({ message: suffix });

/** A string leaf: a non-string input and a failed predicate report the same suffix. */
export const stringLeaf = (suffix: string, test: (value: string) => boolean) =>
  Schema.String.annotate({ message: suffix }).check(
    Schema.makeFilter((value) => (test(value) ? undefined : suffix)),
  );

/** An environment ID leaf (the `isEnvironmentId` shape — the typed value is never echoed). */
export const environmentId = (suffix: string) => stringLeaf(suffix, isEnvironmentId);

// An environment variable name (run.ts's SAFE_ENV_NAME — a POSIX identifier)
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** An environment variable name leaf (a POSIX identifier). */
export const envNameLeaf = (suffix: string) => stringLeaf(suffix, (value) => ENV_NAME.test(value));

/** Decodes `record[key]` against a schema; the failure carries the key's path. */
export function field<S extends Schema.ConstraintDecoder<unknown>>(
  record: Record<string, unknown>,
  key: string,
  schema: S,
): { readonly value: S["Type"] } | Reason {
  const decoded = Schema.decodeUnknownResult(schema)(record[key]);
  return Result.isSuccess(decoded)
    ? { value: decoded.success }
    : { path: [key], issue: decoded.failure.issue };
}

/** The `has unknown keys (...)` refusal every record shape shares (a typo is reported, never silently ignored). */
export function unknownKeysRefusal(
  record: Record<string, unknown>,
  allowed: readonly string[],
  tail: string,
): Reason | undefined {
  const unknown = unknownKeys(record, allowed);
  return unknown.length === 0
    ? undefined
    : { path: [], issue: ` has unknown keys (${unknown.join(", ")}); ${tail}` };
}

/** The `parseConfigHeader` check every user-edited config runs first (its failure's string is a verbatim reason). */
export function configHeader(allowed: readonly string[]) {
  return Schema.makeFilter((record: Record<string, unknown>) => {
    const header = parseConfigHeader(record, allowed);
    return typeof header === "string" ? header : undefined;
  });
}

/**
 * Reading and interpreting one user-edited config file. A read failure is
 * the same "cannot read" whichever way it failed (`what` and `hint` carry
 * the wording); a `string` from `parse` is the reason the file is
 * invalid. FileSystem stays inside this module — the argument layer is
 * given a dying FileSystem on purpose (cli-runner.ts), so the callers
 * never take the service into their environment.
 */
export function loadConfig<T>(
  path: string,
  what: string,
  hint: string,
  parse: (content: string) => T | Invalid,
): Effect.Effect<{ readonly parsed: T; readonly content: string }, CliError> {
  return Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    const content = yield* fs
      .readFileString(path, "utf8")
      .pipe(Effect.mapError(() => cliError(`Cannot read the ${what} ${path}. ${hint}`)));
    const parsed = parse(content);
    if (typeof parsed === "string") {
      return yield* Effect.fail(cliError(`The ${what} ${path} is invalid: ${parsed}`));
    }
    return { parsed, content };
  }).pipe(Effect.provide(BunFileSystem.layer));
}
