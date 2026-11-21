import { DEFAULT_AUDIT_EVENTS_PAGE_LIMIT } from "@maruhi/api-schema";
import {
  type AuditReadVariable,
  auditReadVariablesOf,
  type RotationRecommendedVariable,
  rotationRecommendedVariablesOf,
  VAR_READ_EVENT,
} from "@maruhi/core";

import { countNoun, displayText, formatUtcSeconds } from "../display.ts";
import type { MirrorTrust, WireAuditEvent } from "./audit-mirror.ts";

export interface AuditPageOptions {
  readonly limit: number | null;
  readonly before: string | null;
}

export function pageQueryOf(page: AuditPageOptions): { before?: string; limit?: number } {
  return {
    ...(page.before === null ? {} : { before: page.before }),
    ...(page.limit === null ? {} : { limit: page.limit }),
  };
}

export function aggregatedReadOf(event: WireAuditEvent): readonly AuditReadVariable[] | null {
  if (event.event !== VAR_READ_EVENT || event.variableId !== undefined) {
    return null;
  }
  return auditReadVariablesOf(event.payload);
}

function describeReadCount(listed: readonly AuditReadVariable[]): string {
  const variables = new Set(listed.map((variable) => variable.variableId)).size;
  return listed.length === variables
    ? countNoun(variables, "variable")
    : `${countNoun(listed.length, "version")} of ${countNoun(variables, "variable")}`;
}

export function aggregatedRecommendedOf(
  event: WireAuditEvent,
): readonly RotationRecommendedVariable[] | null {
  return event.event === "rotation.recommended" && event.variableId === undefined
    ? rotationRecommendedVariablesOf(event.payload)
    : null;
}

const formatTs = formatUtcSeconds;

function describeActor(event: WireAuditEvent): string {
  const actor = event.actor;
  if (actor.type === "server") {
    return `server:fp=${actor.keyFingerprintHex ?? "?"}`;
  }
  if (actor.type === "system") {
    return "system";
  }
  const id = actor.userId === undefined ? "(unknown)" : displayText(actor.userId);
  const viaToken = actor.apiTokenId === undefined ? "" : " (via token)";
  return `user:${id}${viaToken}`;
}

function describeTarget(event: WireAuditEvent): string | null {
  if (event.targetUserId !== undefined) {
    return `target=${displayText(event.targetUserId)}`;
  }
  if (event.targetKeyFingerprintHex !== undefined) {
    return `target=server:${event.targetKeyFingerprintHex}`;
  }
  return null;
}

export function variableLabel(variableId: string, resolvedName: string | null): string {
  return resolvedName === null
    ? displayText(variableId)
    : `${displayText(resolvedName)} (${displayText(variableId)})`;
}

function aggregatedSummaryParts(event: WireAuditEvent, matched: string | null): readonly string[] {
  const read = aggregatedReadOf(event);
  const flagged = read === null ? aggregatedRecommendedOf(event) : null;
  const summary =
    read !== null
      ? `read=${describeReadCount(read)}`
      : flagged !== null
        ? `flags=${countNoun(flagged.length, "variable")}`
        : null;
  if (summary === null) {
    return [];
  }
  return matched === null ? [summary] : [summary, `matched=${matched}`];
}

function coordinateParts(
  event: WireAuditEvent,
  resolvedName: string | null,
  matched: string | null,
): readonly string[] {
  const parts: string[] = [];
  if (event.environmentId !== undefined) {
    parts.push(`env=${displayText(event.environmentId)}`);
  }
  parts.push(...aggregatedSummaryParts(event, matched));
  if (event.variableId !== undefined) {
    parts.push(`var=${variableLabel(event.variableId, resolvedName)}`);
  }
  if (event.epoch !== undefined) {
    parts.push(
      `${event.event === "rotation.recommended" ? "exposureEpoch" : "epoch"}=${event.epoch}`,
    );
  }
  if (event.version !== undefined) {
    parts.push(`version=${event.version}`);
  }
  return parts;
}

function trailerParts(event: WireAuditEvent, trust: MirrorTrust | null): readonly string[] {
  const parts: string[] = [];
  if (event.chainSeq !== undefined || trust !== null) {
    const seqPart = event.chainSeq === undefined ? "" : `chain_seq=${event.chainSeq}`;
    if (trust === null) {
      parts.push(`${seqPart} (mirror=unverified — no chain verification context)`);
    } else {
      parts.push(seqPart === "" ? `(${trust.label})` : `${seqPart} (${trust.label})`);
    }
  }
  const recorded = recordedPayloadOf(event);
  if (recorded !== null) {
    parts.push(`recorded=${displayText(JSON.stringify(recorded))}`);
  }
  return parts;
}

function recordedPayloadOf(event: WireAuditEvent): Readonly<Record<string, unknown>> | null {
  if (event.payload === undefined) {
    return null;
  }
  if (aggregatedReadOf(event) === null && aggregatedRecommendedOf(event) === null) {
    return event.payload;
  }
  const { variables: _variables, ...rest } = event.payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

export function formatEventLine(
  event: WireAuditEvent,
  resolvedName: string | null,
  trust: MirrorTrust | null,
  matched: string | null = null,
): string {
  const target = describeTarget(event);
  return [
    ...(event.seq === undefined ? [] : [`seq=${event.seq}`]),
    formatTs(event.serverTs),
    displayText(event.event),
    `actor=${describeActor(event)}`,
    ...(target === null ? [] : [target]),
    ...coordinateParts(event, resolvedName, matched),
    ...trailerParts(event, trust),
  ].join("\t");
}

export function continuationHint(
  events: readonly WireAuditEvent[],
  requestedLimit: number | null,
  command: string,
): string | null {
  const pageSize = requestedLimit ?? DEFAULT_AUDIT_EVENTS_PAGE_LIMIT;
  const last = events[events.length - 1];
  if (last === undefined || events.length < pageSize) {
    return null;
  }
  return `To continue: \`${command} --before ${last.id}\``;
}
