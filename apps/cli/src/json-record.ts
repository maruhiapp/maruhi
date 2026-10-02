// Shared entry point for non-secret JSON documents (repository anchor, sync
// config, proxy config, sync receipt): does it parse as JSON, and is the top
// level an object? The reason is returned as a short English string and the
// caller adds "which file and why" (the content itself is never put in the
// message).

import { readFile, stat } from "node:fs/promises";

import { isProjectId } from "@maruhi/core";
import { Effect } from "effect";

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
    const exists = yield* Effect.tryPromise({
      try: () => stat(path).then(() => true),
      catch: (error: unknown) => error,
    }).pipe(
      Effect.catch((error: unknown) =>
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? Effect.succeed(false)
          : Effect.fail(cliError(unreadable)),
      ),
    );
    return exists ? yield* load(path) : null;
  });
}

/** A per-user ledger file as read (`corrupt` is distinguishable from `missing` — a person deals with it). */
export type LedgerRead<T> =
  | { readonly state: "loaded"; readonly file: T }
  | { readonly state: "missing" }
  | { readonly state: "corrupt" };

/**
 * Reads a per-user ledger (own-devices, accepted proxy configs): absent =
 * `missing`, unreadable by `decode` = `corrupt`. Strict decoding, no partial
 * reads (the pins / fingerprint-ledger discipline).
 */
export async function readLedger<T>(
  path: string,
  decode: (json: string) => T | null,
): Promise<LedgerRead<T>> {
  let json: string;
  try {
    json = await readFile(path, "utf8");
  } catch {
    return { state: "missing" };
  }
  const file = decode(json);
  return file === null ? { state: "corrupt" } : { state: "loaded", file };
}
