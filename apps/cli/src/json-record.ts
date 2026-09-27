// Shared entry point for non-secret JSON documents (repository anchor, sync
// config, sync receipt): does it parse as JSON, and is the top level an
// object? The reason is returned as a short English string and the caller
// adds "which file and why" (the content itself is never put in the message).

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
