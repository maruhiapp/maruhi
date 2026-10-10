// The record guard for server-reported JSON, shared by the chain view's
// fold and the audit reader.

/** Whether a value is a record (null and arrays excluded). A report is never trusted by type — only its shape is read. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
