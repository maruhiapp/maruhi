import { dirname } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { decodeProjectId, isProjectId, type ProjectId, EnvironmentIdSchema } from "@maruhi/core";
import { MAX_SCOPE_ENVIRONMENTS } from "@maruhi/crypto";
import { Effect, FileSystem, type PlatformError, Result, Schema } from "effect";

import { cliError, type CliError } from "./errors.ts";
import { isRecord, parseJsonRecord, unknownKeys } from "./json-record-pure.ts";

export { isRecord, parseJsonRecord, unknownKeys };

export function parseConfigHeader(
  parsed: Record<string, unknown>,
  rootKeys: readonly string[],
): { readonly projectId: ProjectId | undefined } | string {
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
  return { projectId: project === undefined ? undefined : decodeProjectId(project) };
}

export const loadIfPresent = Effect.fn("json-record.loadIfPresent")(function* <A>(
  path: string,
  load: (path: string) => Effect.Effect<A, CliError>,
  unreadable: string,
): Effect.fn.Return<A | null, CliError> {
  const exists = yield* Effect.flatMap(FileSystem.FileSystem, (fs) => fs.exists(path)).pipe(
    Effect.mapError(() => cliError(unreadable)),
    Effect.provide(BunFileSystem.layer),
  );
  return exists ? yield* load(path) : null;
});

export type LedgerRead<T> =
  | { readonly state: "loaded"; readonly file: T }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

export const JsonRecord = Schema.Record(Schema.String, Schema.Unknown);

export const PositiveInt = Schema.Number.check(
  Schema.makeFilter((n) => (Number.isSafeInteger(n) && n > 0) || "expected a positive integer"),
);

export const Hex32 = Schema.String.check(Schema.isPattern(/^[0-9a-f]{32}$/));

export const Hex64 = Schema.String.check(Schema.isPattern(/^[0-9a-f]{64}$/));

export const ScopeEnvironmentIds = Schema.Array(EnvironmentIdSchema).check(
  Schema.makeFilter(
    (ids) =>
      (ids.length <= MAX_SCOPE_ENVIRONMENTS && new Set(ids).size === ids.length) ||
      `scope environment ids must be unique and at most ${MAX_SCOPE_ENVIRONMENTS}`,
  ),
);

export function recordKeysMatch(match: RegExp | ((key: string) => boolean)) {
  const test = typeof match === "function" ? match : (key: string) => match.test(key);
  return Schema.makeFilter(
    (record: Readonly<Record<string, unknown>>) =>
      Object.keys(record).every(test) || "a record key is not in the expected form",
  );
}

export const readJsonFile = Effect.fn("json-record.readJsonFile")(
  function* <S extends Schema.ConstraintCodec<unknown>>(
    path: string,
    schema: S,
  ): Effect.fn.Return<LedgerRead<S["Type"]>, PlatformError.PlatformError, FileSystem.FileSystem> {
    const fs = yield* FileSystem.FileSystem;
    const json = yield* fs.readFileString(path, "utf8");
    const decoded = Schema.decodeUnknownResult(Schema.fromJsonString(schema))(json);
    return Result.isFailure(decoded)
      ? ({ state: "corrupt" } as const)
      : ({ state: "loaded", file: decoded.success } as const);
  },
  Effect.catchReason("PlatformError", "NotFound", () =>
    Effect.succeed({ state: "missing" } as const),
  ),
);

export const readNamedFile: (
  path: string,
  unreadable: CliError,
) => Effect.Effect<string, CliError> = Effect.fn("json-record.readNamedFile")(
  function* (path: string, _unreadable: CliError) {
    const fs = yield* FileSystem.FileSystem;
    return yield* fs.readFileString(path, "utf8");
  },
  (effect, _path, unreadable) => effect.pipe(Effect.mapError(() => unreadable)),
  Effect.provide(BunFileSystem.layer),
);

export const writeJsonFileAtomic = Effect.fn("json-record.writeJsonFileAtomic")(function* <
  S extends Schema.ConstraintCodec<unknown>,
>(
  path: string,
  schema: S,
  value: S["Type"],
): Effect.fn.Return<void, PlatformError.PlatformError | Schema.SchemaError, FileSystem.FileSystem> {
  const encoded = yield* Effect.fromResult(Schema.encodeResult(schema)(value));
  const fs = yield* FileSystem.FileSystem;
  yield* fs.makeDirectory(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.tmp`;
  yield* fs.writeFileString(temp, `${JSON.stringify(encoded, null, 2)}\n`, { mode: 0o600 });
  yield* fs.rename(temp, path);
});
