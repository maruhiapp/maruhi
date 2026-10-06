// Shared entry point for non-secret JSON documents (repository anchor, sync
// config, proxy config, sync receipt): does it parse as JSON, and is the top
// level an object? The reason is returned as a short English string and the
// caller adds "which file and why" (the content itself is never put in the
// message).
//
// The ledger helpers at the bottom describe a stored file as one Schema:
// `readJsonFile` reads + decodes (only a `PlatformError` whose reason is
// `NotFound` is "file absent"), `writeJsonFileAtomic` encodes + writes
// (temp + rename — never a torn write).

import { dirname } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { EnvironmentIdSchema, isProjectId } from "@maruhi/core";
import { MAX_SCOPE_ENVIRONMENTS } from "@maruhi/crypto";
import { Effect, FileSystem, type PlatformError, Result, Schema } from "effect";

import { cliError, type CliError } from "./errors.ts";

/** Parses `content` as a JSON object; returns the reason when it is not one. */
export function parseJsonRecord(content: string): Record<string, unknown> | string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return "not valid JSON";
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return "the top level must be an object";
  }
  return parsed as Record<string, unknown>;
}

/** Whether `value` is a plain object (the shape of a config section). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The keys of `record` outside `allowed` (a typo is reported, never silently ignored). */
export function unknownKeys(record: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(record).filter((key) => !allowed.includes(key));
}

/**
 * The header every repository config shares (sync-config.ts /
 * proxy-config.ts): only the accepted top-level keys, `version: 1`, and an
 * optional `project` that is a project ID. Returns the project ID (or
 * undefined) or the reason.
 */
export function parseConfigHeader(
  parsed: Record<string, unknown>,
  rootKeys: readonly string[],
): { readonly projectId: string | undefined } | string {
  const unknown = unknownKeys(parsed, rootKeys);
  if (unknown.length > 0) {
    return `unknown top-level keys (${unknown.join(", ")}); accepted: ${rootKeys.join(", ")}`;
  }
  if (parsed["version"] !== 1) {
    return "unsupported config version (expected 1)";
  }
  const project = parsed["project"];
  if (project !== undefined && (typeof project !== "string" || !isProjectId(project))) {
    return "project must be the project ID (64 hex digits) when present";
  }
  return { projectId: project };
}

/**
 * A config the CLI applies without being told (`maruhi push` → the sync
 * config, `maruhi run` → the proxy config): null when the file is absent,
 * `load(path)` when it exists, and `unreadable` as the error when it exists
 * but cannot be stat'ed — a broken config is reported, never skipped.
 */
export function loadIfPresent<A>(
  path: string,
  load: (path: string) => Effect.Effect<A, CliError>,
  unreadable: string,
): Effect.Effect<A | null, CliError> {
  return Effect.gen(function* () {
    // `exists` = access(F_OK): a PlatformError whose reason is NotFound is
    // false; every other read failure is `unreadable` (the same discipline as
    // the stat() version). The layer is provided only around the existence
    // check so `load` keeps the caller's environment.
    const exists = yield* Effect.flatMap(FileSystem.FileSystem, (fs) => fs.exists(path)).pipe(
      Effect.mapError(() => cliError(unreadable)),
      Effect.provide(BunFileSystem.layer),
    );
    return exists ? yield* load(path) : null;
  });
}

/** A per-user ledger file as read (`corrupt` is distinguishable from `missing` — a person deals with it). */
export type LedgerRead<T> =
  | { readonly state: "loaded"; readonly file: T }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

// ---- Schema-described ledger files (FileSystem-backed) ----

/** A whole non-secret JSON object (the top level of a ledger or config file). */
export const JsonRecord = Schema.Record(Schema.String, Schema.Unknown);

/** A positive integer field (seqs / epochs / timestamps in the ledger files). */
export const PositiveInt = Schema.Number.check(
  Schema.makeFilter((n) => (Number.isSafeInteger(n) && n > 0) || "expected a positive integer"),
);

/** A 16-byte fingerprint hex (32 chars — CRYPTO_SPEC §3). */
export const Hex32 = Schema.String.check(Schema.isPattern(/^[0-9a-f]{32}$/));

/** A 32-byte hex (64 chars — SHA-256-sized hashes and public keys). */
export const Hex64 = Schema.String.check(Schema.isPattern(/^[0-9a-f]{64}$/));

/**
 * A scope's environment-id list (CRYPTO_SPEC §6.2 — AUTH_SPEC §12-1 id
 * format, at most 256, no duplicates).
 */
export const ScopeEnvironmentIds = Schema.Array(EnvironmentIdSchema).check(
  Schema.makeFilter(
    (ids) =>
      (ids.length <= MAX_SCOPE_ENVIRONMENTS && new Set(ids).size === ids.length) ||
      `scope environment ids must be unique and at most ${MAX_SCOPE_ENVIRONMENTS}`,
  ),
);

/**
 * A record-level filter enforcing a map-key format (invite ids, fingerprints,
 * book keys). A checked Record **key** schema only *selects* keys — a
 * non-matching key is silently dropped — so the format rule is a filter on
 * the decoded record instead: a bad key rejects the whole file (the
 * strict-decode discipline).
 */
export function recordKeysMatch(match: RegExp | ((key: string) => boolean)) {
  const test = typeof match === "function" ? match : (key: string) => match.test(key);
  return Schema.makeFilter(
    (record: Readonly<Record<string, unknown>>) =>
      Object.keys(record).every(test) || "a record key is not in the expected form",
  );
}

/**
 * Reads `path` and decodes its JSON content by `schema`. Only a
 * `PlatformError` whose reason is `NotFound` (not created yet) is `missing`;
 * a parse or schema failure is `corrupt` (strict decoding — one malformed
 * entry rejects the whole file); every other read failure (EACCES / EISDIR /
 * EIO) stays an error so a writer never replaces a file it could not read
 * (the pins / fingerprint-ledger discipline — review finding §21 R-15).
 */
export function readJsonFile<S extends Schema.ConstraintCodec<unknown>>(
  path: string,
  schema: S,
): Effect.Effect<LedgerRead<S["Type"]>, PlatformError.PlatformError, FileSystem.FileSystem> {
  return Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    const json = yield* fs.readFileString(path, "utf8");
    const decoded = Schema.decodeUnknownResult(Schema.fromJsonString(schema))(json);
    return Result.isFailure(decoded)
      ? ({ state: "corrupt" } as const)
      : ({ state: "loaded", file: decoded.success } as const);
  }).pipe(
    Effect.catchReason("PlatformError", "NotFound", () =>
      Effect.succeed({ state: "missing" } as const),
    ),
  );
}

/**
 * Reading one user-named file's content: any read failure becomes the
 * caller's `unreadable` error ("cannot read" is the same whichever way it
 * failed). FileSystem stays inside this module — the caller's
 * FileSystem-providing environment (dying on purpose, cli-runner.ts) is
 * never touched, BunFileSystem is provided locally.
 */
export function readNamedFile(path: string, unreadable: CliError): Effect.Effect<string, CliError> {
  return Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    return yield* fs.readFileString(path, "utf8");
  }).pipe(
    Effect.mapError(() => unreadable),
    Effect.provide(BunFileSystem.layer),
  );
}

/**
 * Writes `value` to `path` encoded by `schema`, atomically: the directory is
 * created (mode 0o700), the JSON goes to a temp sibling (mode 0o600), and a
 * rename moves it over `path` — a partial file is never observable. Encoding
 * is checked, so a value that would not decode again is refused.
 */
export function writeJsonFileAtomic<S extends Schema.ConstraintCodec<unknown>>(
  path: string,
  schema: S,
  value: S["Type"],
): Effect.Effect<void, PlatformError.PlatformError | Schema.SchemaError, FileSystem.FileSystem> {
  return Effect.gen(function* () {
    const encoded = yield* Effect.fromResult(Schema.encodeResult(schema)(value));
    const fs = yield* FileSystem.FileSystem;
    yield* fs.makeDirectory(dirname(path), { recursive: true, mode: 0o700 });
    const temp = `${path}.${process.pid}.tmp`;
    yield* fs.writeFileString(temp, `${JSON.stringify(encoded, null, 2)}\n`, { mode: 0o600 });
    yield* fs.rename(temp, path);
  });
}
