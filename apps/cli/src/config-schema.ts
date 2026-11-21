import { environmentIdSchemaWithMessage, type ProjectId } from "@maruhi/core";
import { Effect, Result, Schema, SchemaIssue } from "effect";

import { cliError, type CliError } from "./errors.ts";
import {
  JsonRecord,
  parseConfigHeader,
  parseJsonRecord,
  readNamedFile,
  unknownKeys,
} from "./json-record.ts";
import { SAFE_ENV_NAME } from "./run.ts";

export type Invalid = string;

export type Parsed<A> = Result.Result<A, SchemaIssue.Issue>;

export function refuse(message: string, path: ReadonlyArray<PropertyKey> = []): Parsed<never> {
  const issue = new SchemaIssue.InvalidValue({ message });
  return Result.fail(path.length === 0 ? issue : new SchemaIssue.Pointer(path, issue));
}

export function at<A>(path: ReadonlyArray<PropertyKey>, parsed: Parsed<A>): Parsed<A> {
  return Result.mapError(parsed, (issue) => new SchemaIssue.Pointer(path, issue));
}

export function decode<S extends Schema.ConstraintDecoder<unknown>>(
  schema: S,
  value: unknown,
): Parsed<S["Type"]> {
  return Result.mapError(Schema.decodeUnknownResult(schema)(value), (error) => error.issue);
}

export function field<S extends Schema.ConstraintDecoder<unknown>>(
  record: Readonly<Record<string, unknown>>,
  key: string,
  schema: S,
): Parsed<S["Type"]> {
  return at([key], decode(schema, record[key]));
}

const reasonFormatter = SchemaIssue.makeFormatterStandardSchemaV1();

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

export const objectLeaf = (message: string) => JsonRecord.annotate({ message });

export const stringLeaf = (message: string, test: (value: string) => boolean) =>
  Schema.String.annotate({ message }).check(
    Schema.makeFilter((value) => (test(value) ? undefined : message)),
  );

export const environmentId = environmentIdSchemaWithMessage;

export const envNameLeaf = (message: string) =>
  stringLeaf(message, (value) => SAFE_ENV_NAME.test(value));

export const undefinedOr = <S extends Schema.Top>(message: string, schema: S) =>
  Schema.UndefinedOr(schema).annotate({ message });

export const nullishOr = <S extends Schema.Top>(message: string, schema: S) =>
  Schema.NullishOr(schema).annotate({ message });

export function refusal(reason: Invalid | null | undefined): Parsed<void> {
  return reason === null || reason === undefined ? Result.succeed(undefined) : refuse(reason);
}

function unknownKeysMessage(
  record: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
  tail: string,
): string | undefined {
  const unknown = unknownKeys(record, allowed);
  return unknown.length === 0 ? undefined : ` has unknown keys (${unknown.join(", ")}); ${tail}`;
}

export function knownKeys(
  record: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
  tail: string,
): Parsed<void> {
  return refusal(unknownKeysMessage(record, allowed, tail));
}

export const closedRecord = (message: string, allowed: readonly string[], tail: string) =>
  objectLeaf(message).check(
    Schema.makeFilter((record) => unknownKeysMessage(record, allowed, tail)),
  );

export function configHeader(
  record: Record<string, unknown>,
  rootKeys: readonly string[],
): Parsed<{ readonly projectId: ProjectId | undefined }> {
  const header = parseConfigHeader(record, rootKeys);
  return typeof header === "string" ? refuse(header) : Result.succeed(header);
}

export function parseConfigDocument<A>(
  content: string,
  parse: (record: Record<string, unknown>) => Parsed<A>,
): A | Invalid {
  const record = parseJsonRecord(content);
  if (typeof record === "string") {
    return record;
  }
  return Result.match(parse(record), {
    onFailure: issueReason,
    onSuccess: (value) => value,
  });
}

export const loadConfig = Effect.fn("config-schema.loadConfig")(function* <T>(
  path: string,
  what: string,
  hint: string,
  parse: (content: string) => T | Invalid,
): Effect.fn.Return<{ readonly parsed: T; readonly content: string }, CliError> {
  const content = yield* readNamedFile(path, cliError(`Cannot read the ${what} ${path}. ${hint}`));
  const parsed = parse(content);
  if (typeof parsed === "string") {
    return yield* Effect.fail(cliError(`The ${what} ${path} is invalid: ${parsed}`));
  }
  return { parsed, content };
});
