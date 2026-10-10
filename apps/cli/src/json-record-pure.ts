// Dependency-free JSON-record helpers: the pure string/object checks that the
// rest of the CLI shares. This module imports nothing (no node, effect,
// @maruhi/*, or FileSystem), so a lean module can use it without pulling in a
// heavy graph — the passkey listener (the CLI's one TCP security boundary)
// stays on node: builtins plus these pure helpers.
//
// `json-record.ts` re-exports all three, so callers that already live in the
// FileSystem-backed graph keep importing them from there.

/**
 * Parses `content` as a JSON object; returns the reason when it is not one.
 *
 * The reason is one of two fixed English strings. Neither the parsed content
 * nor the underlying JSON parse-error text is ever placed in it, so this is
 * safe to call on a secret-bearing body (the caller adds "which input and
 * why"; the value itself never reaches the message).
 */
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
