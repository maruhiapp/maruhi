// The Schema machinery shared by the user-edited config files
// (sync.package/sync-config.ts, rotate-config.ts,
// proxy.package/proxy-config.ts). Each config reads its document in one
// pass of steps over Schema-decoded leaves, in the same order the
// hand-written validators ran — the first failure's reason is the one the
// user sees, worded exactly as before.
//
// A step returns a `Parsed<A>` (a `Result` — the built value, or the
// `SchemaIssue` the reason is rendered from), and steps compose with
// `Result.gen`. An issue's message that starts with a separator (space /
// colon / dot) is a suffix appended to the dotted path of the field it
// belongs to ("variables.X.connector" + " must be ..."); any other message
// is a complete reason. A reason never contains the offending value, and
// never names an array entry's position (the wording never did).

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { isEnvironmentId } from "@maruhi/core";
import { Effect, FileSystem, Result, Schema, SchemaIssue } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { JsonRecord, parseConfigHeader, unknownKeys } from "./json-record.ts";
import { SAFE_ENV_NAME } from "./run.ts";

/** A validation failure (the reason's string). Never includes the value itself. */
export type Invalid = string;

/** One config step's outcome: the built value, or the issue its reason is rendered from. */
export type Parsed<A> = Result.Result<A, SchemaIssue.Issue>;

/** A refusal at `path` (relative to the step's own field; empty = the field itself). */
export function refuse(message: string, path: ReadonlyArray<PropertyKey> = []): Parsed<never> {
  const issue = new SchemaIssue.InvalidValue({ message });
  return Result.fail(path.length === 0 ? issue : new SchemaIssue.Pointer(path, issue));
}

/** A step's failure placed under `path` (the key its value was read from). */
export function at<A>(path: ReadonlyArray<PropertyKey>, parsed: Parsed<A>): Parsed<A> {
  return Result.mapError(parsed, (issue) => new SchemaIssue.Pointer(path, issue));
}

/** Decodes `value` against a leaf schema. */
export function decode<S extends Schema.ConstraintDecoder<unknown>>(
  schema: S,
  value: unknown,
): Parsed<S["Type"]> {
  return Result.mapError(Schema.decodeUnknownResult(schema)(value), (error) => error.issue);
}

/** Decodes `record[key]` against a leaf schema; the failure carries the key's path. */
export function field<S extends Schema.ConstraintDecoder<unknown>>(
  record: Readonly<Record<string, unknown>>,
  key: string,
  schema: S,
): Parsed<S["Type"]> {
  return at([key], decode(schema, record[key]));
}

const reasonFormatter = SchemaIssue.makeFormatterStandardSchemaV1();

/**
 * The first issue rendered as the user's reason: a message starting with a
 * separator (space / colon / dot) is a suffix appended to the dotted path
 * (array positions left out); anything else is already a complete reason.
 */
function issueReason(issue: SchemaIssue.Issue): Invalid {
  const first = reasonFormatter(issue).issues[0];
  if (first === undefined) {
    return "is invalid";
  }
  const path = (first.path ?? []).filter((segment) => typeof segment !== "number");
  const message = first.message;
  if (
    path.length === 0 ||
    !(message.startsWith(" ") || message.startsWith(":") || message.startsWith("."))
  ) {
    return message;
  }
  return `${path.map(String).join(".")}${message}`;
}

/** A JSON object boundary: a non-object input reports `message`. */
export const objectLeaf = (message: string) => JsonRecord.annotate({ message });

/** A string leaf: a non-string input and a failed predicate report the same `message`. */
export const stringLeaf = (message: string, test: (value: string) => boolean) =>
  Schema.String.annotate({ message }).check(
    Schema.makeFilter((value) => (test(value) ? undefined : message)),
  );

/** An environment ID leaf (the `isEnvironmentId` shape — the typed value is never echoed). */
export const environmentId = (message: string) => stringLeaf(message, isEnvironmentId);

/** An environment variable name leaf (run.ts's SAFE_ENV_NAME — a POSIX identifier). */
export const envNameLeaf = (message: string) =>
  stringLeaf(message, (value) => SAFE_ENV_NAME.test(value));

/**
 * `schema`, or the key left out. A value no member accepts (a number, a
 * boolean, an array, an object, null) reports `message` — the leaf's own
 * wording — instead of the union's default "Expected X | undefined".
 */
export const undefinedOr = <S extends Schema.Top>(message: string, schema: S) =>
  Schema.UndefinedOr(schema).annotate({ message });

/** `schema`, null, or the key left out (null reads as absent); otherwise as {@link undefinedOr}. */
export const nullishOr = <S extends Schema.Top>(message: string, schema: S) =>
  Schema.NullishOr(schema).annotate({ message });

/** A check that answers with its reason (null / undefined = it passes), as a step. */
export function refusal(reason: Invalid | null | undefined): Parsed<void> {
  return reason === null || reason === undefined ? Result.succeed(undefined) : refuse(reason);
}

/** The `has unknown keys (...)` wording every record shape shares, or undefined when every key is known. */
function unknownKeysMessage(
  record: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
  tail: string,
): string | undefined {
  const unknown = unknownKeys(record, allowed);
  return unknown.length === 0 ? undefined : ` has unknown keys (${unknown.join(", ")}); ${tail}`;
}

/** Refuses keys outside `allowed` (a typo is reported, never silently ignored). */
export function knownKeys(
  record: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
  tail: string,
): Parsed<void> {
  return refusal(unknownKeysMessage(record, allowed, tail));
}

/** An object leaf that also refuses keys outside `allowed` (the shape of a nested record with fixed keys). */
export const closedRecord = (message: string, allowed: readonly string[], tail: string) =>
  objectLeaf(message).check(
    Schema.makeFilter((record) => unknownKeysMessage(record, allowed, tail)),
  );

/** The header every user-edited config shares (json-record.ts's `parseConfigHeader` — its reason is a complete one). */
export function configHeader(
  record: Record<string, unknown>,
  rootKeys: readonly string[],
): Parsed<{ readonly projectId: string | undefined }> {
  const header = parseConfigHeader(record, rootKeys);
  return typeof header === "string" ? refuse(header) : Result.succeed(header);
}

const JSON_DOCUMENT = Schema.fromJsonString(Schema.Unknown);
const TOP_LEVEL = objectLeaf("the top level must be an object");

/** Interpreting a config's JSON text: a JSON object, then `parse` over it (the reason's string when invalid). */
export function parseConfigDocument<A>(
  content: string,
  parse: (record: Record<string, unknown>) => Parsed<A>,
): A | Invalid {
  const json = Schema.decodeUnknownResult(JSON_DOCUMENT)(content);
  if (Result.isFailure(json)) {
    return "not valid JSON";
  }
  return Result.match(Result.flatMap(decode(TOP_LEVEL, json.success), parse), {
    onFailure: issueReason,
    onSuccess: (value) => value,
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
