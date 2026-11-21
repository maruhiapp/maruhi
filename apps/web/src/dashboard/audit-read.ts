import { isRecord } from "./json-record.ts";
import type { AuditEvent } from "./types.ts";

export interface ListedReadVariable {
  readonly variableId: string;
  readonly epoch: number;
  readonly version: number;
}

function listedReadVariableOf(entry: unknown): ListedReadVariable | null {
  return isRecord(entry) && isListedReadVariable(entry)
    ? { variableId: entry.variableId, epoch: entry.epoch, version: entry.version }
    : null;
}

function isListedReadVariable(
  entry: Record<string, unknown>,
): entry is Record<string, unknown> & ListedReadVariable {
  return (
    typeof entry["variableId"] === "string" &&
    Number.isInteger(entry["epoch"]) &&
    Number.isInteger(entry["version"])
  );
}

function listedVariablesOf(
  payload: AuditEvent["payload"] | undefined,
): ReadonlyArray<ListedReadVariable> | null {
  const listed = payload?.["variables"];
  return Array.isArray(listed)
    ? listed.map(listedReadVariableOf).filter((entry) => entry !== null)
    : null;
}

export function aggregatedReadVariables(
  event: Pick<AuditEvent, "event" | "variableId" | "payload">,
): ReadonlyArray<ListedReadVariable> | null {
  return event.event === "var.read" && event.variableId === undefined
    ? listedVariablesOf(event.payload)
    : null;
}

export interface FlaggedVariable {
  readonly variableId: string;
  readonly basis: string;
}

function flaggedVariableOf(entry: unknown): FlaggedVariable | null {
  if (isRecord(entry) && typeof entry["variableId"] === "string") {
    const basis = entry["basis"];
    return { variableId: entry["variableId"], basis: basis === "read" ? "read" : "readable" };
  }
  return null;
}

function listedFlaggedVariablesOf(
  payload: AuditEvent["payload"] | undefined,
): ReadonlyArray<FlaggedVariable> | null {
  const listed = payload?.["variables"];
  return Array.isArray(listed)
    ? listed.map(flaggedVariableOf).filter((entry) => entry !== null)
    : null;
}

export function aggregatedRecommendedVariables(
  event: Pick<AuditEvent, "event" | "variableId" | "payload">,
): ReadonlyArray<FlaggedVariable> | null {
  return event.event === "rotation.recommended" && event.variableId === undefined
    ? listedFlaggedVariablesOf(event.payload)
    : null;
}

export function flagSummaryLabel(listed: ReadonlyArray<FlaggedVariable>): string {
  return `flags ${listed.length} ${listed.length === 1 ? "variable" : "variables"}`;
}

export function flaggedVariableLabel(variable: FlaggedVariable): string {
  return `${variable.variableId} · ${variable.basis}`;
}

export function payloadWithoutVariables(
  payload: NonNullable<AuditEvent["payload"]>,
): Readonly<Record<string, unknown>> | null {
  const { variables: _variables, ...rest } = payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

export function readSummaryLabel(listed: ReadonlyArray<ListedReadVariable>): string {
  const variables = new Set(listed.map((entry) => entry.variableId)).size;
  const noun = variables === 1 ? "variable" : "variables";
  return listed.length === variables
    ? `read ${variables} ${noun}`
    : `read ${listed.length} versions of ${variables} ${noun}`;
}

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

function sameValueAsOf(event: Pick<AuditEvent, "event" | "payload">): number | null {
  if (event.event !== "var.version_pushed") {
    return null;
  }
  const value = event.payload?.["sameValueAs"];
  return typeof value === "number" ? value : null;
}

export function listedReadVariableLabel(variable: ListedReadVariable): string {
  return `${variable.variableId} · epoch ${variable.epoch} · v ${variable.version}`;
}
