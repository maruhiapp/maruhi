// The as-recorded form of a server timestamp, shared by the audit list
// and the invitation list.

/**
 * The as-recorded display form of a server timestamp (ms): the ISO
 * form, UTC explicit. Human-readable listings use `ServerTime`; this is
 * reserved for the audit's expanded part (Recorded at — the value as
 * recorded).
 */
export function formatServerTime(ms: number): string {
  const date = new Date(ms);
  return Number.isFinite(date.getTime()) ? date.toISOString() : String(ms);
}
