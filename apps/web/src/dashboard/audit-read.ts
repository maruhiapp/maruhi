// Display derivation for the aggregated `var.read` (AUDIT_SPEC §3.3 —
// one row per environment per bulk pull with values, with the payload
// enumerating the returned variables). Pure functions only (unit-test
// target).
//
// The server / CLI share @maruhi/core's auditReadVariablesOf, but the
// web holds only type-only imports from api-schema (keeping the TCB
// minimal — see the top of types.ts), so the same interpretation lives
// here. Every value is as reported by the server and is not validated —
// an element's acceptance condition is identical to core's (variableId
// is a string and epoch / version are integers), and anything else is
// dropped (so the two never diverge in count or display).
import type { AuditEvent } from "./types.ts";

/**
 * One variable listed by an aggregated `var.read` row, as reported by the
 * server. Entries without an integer epoch and version are dropped.
 */
export interface ListedReadVariable {
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Shapes one element of the enumeration. Dropped unless it satisfies
 * the same acceptance condition as @maruhi/core's auditReadVariablesOf
 * (variableId is a string and epoch / version are integers).
 */
function listedReadVariableOf(entry: unknown): ListedReadVariable | null {
  return isJsonRecord(entry) && isListedReadVariable(entry)
    ? { variableId: entry.variableId, epoch: entry.epoch, version: entry.version }
    : null;
}

/** The acceptance condition (variableId is a string and epoch / version are integers — same as core). */
function isListedReadVariable(
  entry: Record<string, unknown>,
): entry is Record<string, unknown> & ListedReadVariable {
  return (
    typeof entry["variableId"] === "string" &&
    Number.isInteger(entry["epoch"]) &&
    Number.isInteger(entry["version"])
  );
}

/** The payload's `variables` enumeration (null if not an array = not the aggregated shape). */
function listedVariablesOf(
  payload: AuditEvent["payload"] | undefined,
): ReadonlyArray<ListedReadVariable> | null {
  const listed = payload?.["variables"];
  return Array.isArray(listed)
    ? listed.map(listedReadVariableOf).filter((entry) => entry !== null)
    : null;
}

/** Detecting an aggregated var.read: event name + missing variableId + the enumeration. */
export function aggregatedReadVariables(
  event: Pick<AuditEvent, "event" | "variableId" | "payload">,
): ReadonlyArray<ListedReadVariable> | null {
  return event.event === "var.read" && event.variableId === undefined
    ? listedVariablesOf(event.payload)
    : null;
}

/**
 * The rest of an aggregated var.read's payload with the variable
 * enumeration removed (authMethod etc.). null if empty. The enumeration
 * is shown folded; the rest is shown as JSON, verbatim from the record,
 * as before.
 */
export function payloadWithoutVariables(
  payload: NonNullable<AuditEvent["payload"]>,
): Readonly<Record<string, unknown>> | null {
  const { variables: _variables, ...rest } = payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

/** The list summary (English — ADR-0017): "read 3 variables" / "read 1 variable". */
export function readSummaryLabel(listed: ReadonlyArray<ListedReadVariable>): string {
  const variables = new Set(listed.map((entry) => entry.variableId)).size;
  const noun = variables === 1 ? "variable" : "variables";
  // The version value range (AUTH_SPEC §12-7 — VH) lists several versions
  // of one variable; a bulk pull lists each variable once
  return listed.length === variables
    ? `read ${variables} ${noun}`
    : `read ${listed.length} versions of ${variables} ${noun}`;
}

/**
 * The value-lineage label of a `var.version_pushed` row (AUDIT_SPEC §3.3 —
 * 2026-09-27 VH): the kind is derived from `sameValueAs` (the previous
 * version = a re-encryption, older = a rollback). null when the push
 * declared none (a fresh value) or the payload is not well-formed.
 */
export function lineageLabel(
  event: Pick<AuditEvent, "event" | "version" | "payload">,
): string | null {
  const sameValueAs = sameValueAsOf(event);
  if (sameValueAs === null) {
    return null;
  }
  const previous = (event.version ?? 0) - 1;
  return `${sameValueAs === previous ? "re-encryption of" : "rollback to"} v ${sameValueAs}`;
}

/** The lineage declaration a var.version_pushed row recorded (null for any other row or shape). */
function sameValueAsOf(event: Pick<AuditEvent, "event" | "payload">): number | null {
  if (event.event !== "var.version_pushed") {
    return null;
  }
  const value = event.payload?.["sameValueAs"];
  return typeof value === "number" ? value : null;
}

/** The display shape of an expanded row: `var-id · epoch 1 · v 2`. */
export function listedReadVariableLabel(variable: ListedReadVariable): string {
  return `${variable.variableId} · epoch ${variable.epoch} · v ${variable.version}`;
}
