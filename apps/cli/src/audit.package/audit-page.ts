// How `maruhi audit`'s listings print a page of audit rows. list
// (audit-list.ts) and invites / self (audit-d1.ts) share the paging
// options, the one-line form of a row, the summary of an aggregated row
// (AUDIT_SPEC §3.3 — var.read and rotation.recommended) and the
// continuation hint.
//
// TCB discipline (AUDIT_SPEC §7 — audit-mirror.ts): display names are
// resolved only from verified meta-statements (including tombstones of
// deleted variables); a name snapshot inside a payload is displayed
// separately as a "record" (never promoted to the display-name position).

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

/** The paging spec shared by list / invites / self. before is the id of the previous page's last row. */
export interface AuditPageOptions {
  readonly limit: number | null;
  readonly before: string | null;
}

/** Page spec → query (unspecified keys are not sent = left to the server defaults). */
export function pageQueryOf(page: AuditPageOptions): { before?: string; limit?: number } {
  return {
    ...(page.before === null ? {} : { before: page.before }),
    ...(page.limit === null ? {} : { limit: page.limit }),
  };
}

/**
 * The variable enumeration of an aggregated `var.read` row (AUDIT_SPEC
 * §3.3). An aggregated row carries no variable ID column (variableId
 * absent); it enumerates the read variables in the payload's
 * `variables`. Other events return null. Interpretation uses the same
 * shared implementation as the server.
 */
export function aggregatedReadOf(event: WireAuditEvent): readonly AuditReadVariable[] | null {
  if (event.event !== VAR_READ_EVENT || event.variableId !== undefined) {
    return null;
  }
  return auditReadVariablesOf(event.payload);
}

/**
 * The count of an aggregated read: one entry per variable for a bulk pull;
 * several versions of one variable for the version value range (AUTH_SPEC
 * §12-7 — VH), counted as such.
 */
function describeReadCount(listed: readonly AuditReadVariable[]): string {
  const variables = new Set(listed.map((variable) => variable.variableId)).size;
  return listed.length === variables
    ? countNoun(variables, "variable")
    : `${countNoun(listed.length, "version")} of ${countNoun(variables, "variable")}`;
}

/**
 * The variable enumeration of an aggregated `rotation.recommended` row (§3.3
 * Sc-5 — one row per environment, per chunk; variableId column absent, the
 * flagged variables and their basis in the payload's `variables`). Other
 * events return null. Uses the same shared reader as the server (@maruhi/core).
 */
export function aggregatedRecommendedOf(
  event: WireAuditEvent,
): readonly RotationRecommendedVariable[] | null {
  return event.event === "rotation.recommended" && event.variableId === undefined
    ? rotationRecommendedVariablesOf(event.payload)
    : null;
}

// serverTs is a server-claimed unbounded number: display it with the total
// shared formatter so out-of-Date-range values do not become a defect
// (RangeError)
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

/** A variable's display label (`NAME (id)` when a verified name exists, the id alone otherwise). */
export function variableLabel(variableId: string, resolvedName: string | null): string {
  return resolvedName === null
    ? displayText(variableId)
    : `${displayText(resolvedName)} (${displayText(variableId)})`;
}

/**
 * The summary column of an aggregated row (§3.3): var.read's `read=` count or
 * rotation.recommended's `flags=` count — the enumeration (tens / ~100 KiB)
 * is never dumped on the line (it rides --expand-reads / the recorded payload
 * stripped of `variables`). With --var, the matched variable's item follows.
 * A row is one kind, so at most one summary.
 */
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

/** The coordinate/number columns (env / var / epoch / version — absent ones are not printed). */
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
    // A rotation.recommended row's epoch is its exposure bound, not a
    // value's epoch (AUDIT_SPEC §3.3 / §4.1-5 — VH)
    parts.push(
      `${event.event === "rotation.recommended" ? "exposureEpoch" : "epoch"}=${event.epoch}`,
    );
  }
  if (event.version !== undefined) {
    parts.push(`version=${event.version}`);
  }
  return parts;
}

/** The trailer columns (chain_seq + reconciliation label / recorded payload). */
function trailerParts(event: WireAuditEvent, trust: MirrorTrust | null): readonly string[] {
  const parts: string[] = [];
  if (event.chainSeq !== undefined || trust !== null) {
    const seqPart = event.chainSeq === undefined ? "" : `chain_seq=${event.chainSeq}`;
    if (trust === null) {
      // Even if a caller forgets the trust computation, do not display
      // chain_seq label-less like a verified coordinate (the last line of
      // defense)
      parts.push(`${seqPart} (mirror=unverified — no chain verification context)`);
    } else {
      parts.push(seqPart === "" ? `(${trust.label})` : `${seqPart} (${trust.label})`);
    }
  }
  const recorded = recordedPayloadOf(event);
  if (recorded !== null) {
    // A prefix making explicit this is the recorded content (a server claim).
    // It may carry a name snapshot but is never promoted to the display-name
    // position (the var= label) — TCB discipline
    parts.push(`recorded=${displayText(JSON.stringify(recorded))}`);
  }
  return parts;
}

/**
 * The payload printed under recorded=. For an aggregated var.read, only
 * the remainder after dropping the variable enumeration (`variables` —
 * can reach tens of KB; the read= summary, --var's match display, and
 * --expand-reads' expanded lines carry it) is printed (authMethod etc.).
 */
function recordedPayloadOf(event: WireAuditEvent): Readonly<Record<string, unknown>> | null {
  if (event.payload === undefined) {
    return null;
  }
  // An aggregated var.read or rotation.recommended carries its enumeration in
  // `variables` (tens / ~100 KiB); it is surfaced by the read= / flags=
  // summary and --var's match, so drop it from recorded= (authMethod,
  // trigger, triggerChainSeq, revokedDeviceKeyFingerprints remain)
  if (aggregatedReadOf(event) === null && aggregatedRecommendedOf(event) === null) {
    return event.payload;
  }
  const { variables: _variables, ...rest } = event.payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

/** Rendering of one line. Display names (resolvedName) come only from verified statements. */
export function formatEventLine(
  event: WireAuditEvent,
  resolvedName: string | null,
  trust: MirrorTrust | null,
  matched: string | null = null,
): string {
  const target = describeTarget(event);
  return [
    // seq rides only on an admin-visible response (§7 — non-admin never sees the ordinal)
    ...(event.seq === undefined ? [] : [`seq=${event.seq}`]),
    formatTs(event.serverTs),
    displayText(event.event),
    `actor=${describeActor(event)}`,
    ...(target === null ? [] : [target]),
    ...coordinateParts(event, resolvedName, matched),
    ...trailerParts(event, trust),
  ].join("\t");
}

/** The continuation hint at the page end (only when the page came back full to limit). */
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
