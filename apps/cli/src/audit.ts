// `maruhi audit` (AUDIT_SPEC §6 / §7).
//
// - list: the project DO's audit events (newest-first, seq cursor). The
//   visibility classes (§6) are server-enforced; this side only renders
// - invites: D1 read of invite.* (chain role admin — server-enforced)
// - self: the user's own view of user events (§3.1 / §6 — the monitoring
//   path for the to-be-monitored events)
// - verify: bijection verification of the chain mirror (the client
//   implementation of §1-5 "the mirror can be rebuilt from the chain" /
//   §6's mitigation "the mirror can be verified by reconciling against the
//   chain"). Rebuilds the expected mirror column from the verified chain
//   and detects the three directions — missing, forged, altered. The
//   mapping is shared with the server (@maruhi/core's chainMirrorEvent) —
//   structurally blocking false alarms from verifier drift under double
//   maintenance
//
// TCB discipline (AUDIT_SPEC §7): every field of a response is a server
// claim. Display names are resolved only from verified meta-statements
// (including tombstones of deleted variables); a name snapshot inside a
// payload is displayed separately as a "record" (never promoted to the
// display-name position). chain.* rows show their reconciliation result
// against the verified chain as a label.
// Plaintext values and key material never pass through this module.

import {
  type AuditEventSchema,
  DEFAULT_AUDIT_EVENTS_PAGE_LIMIT,
  MAX_AUDIT_EVENTS_PAGE_LIMIT,
} from "@maruhi/api-schema";
import type { AuditEventRecord, AuditReadVariable, ProposalIndex } from "@maruhi/core";
import {
  auditReadVariablesOf,
  CHAIN_MIRROR_EVENT_PREFIX,
  CHAIN_MIRROR_EVENTS,
  chainMirrorEvents,
  VAR_READ_EVENT,
} from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { proposalIndexOf } from "./chain-applied.ts";
import type { CliServices, ProjectContextBase, SessionContext } from "./context.ts";
import { countNoun, displayText, formatUtcSeconds } from "./display.ts";
import type { CliError } from "./errors.ts";
import { cliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { logNote, logWarning } from "./notice.ts";
import { type NameIndex, resolveNames } from "./rotation.ts";

/**
 * The wire audit event (the received shape of api-schema's
 * AuditEventSchema — the type is derived from the Schema; its shape is not
 * duplicated here). Every field is a server claim (the TCB discipline
 * above).
 */
export type WireAuditEvent = typeof AuditEventSchema.Type;

/** The paging spec shared by list / invites / self. before is the id of the previous page's last row. */
export interface AuditPageOptions {
  readonly limit: number | null;
  readonly before: string | null;
}

/** list's filters (AUDIT_SPEC §7 vocabulary). */
export interface AuditListFilters {
  readonly event: string | null;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly environmentId: string | null;
  readonly variableId: string | null;
}

/** list's display options. */
interface AuditListOptions {
  /**
   * Expand the aggregated `var.read` form (AUDIT_SPEC §3.3 — one row per
   * environment per value pull) into one line per variable. The default is a
   * count-only summary.
   */
  readonly expandReads: boolean;
}

/**
 * The variable enumeration of an aggregated `var.read` row (AUDIT_SPEC
 * §3.3). An aggregated row carries no variable ID column (variableId
 * absent); it enumerates the read variables in the payload's
 * `variables`. Other events return null. Interpretation uses the same
 * shared implementation as the server.
 */
function aggregatedReadOf(event: WireAuditEvent): readonly AuditReadVariable[] | null {
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

// ---------------------------------------------------------------------------
// Mirror reconciliation (§1-5 / §6)
// ---------------------------------------------------------------------------

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonRecordEqual(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => key in right && jsonEqual(left[key], right[key]))
  );
}

/** Structural equality of JSON values (key-order independent). */
function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => jsonEqual(item, b[index]));
  }
  return isJsonRecord(a) && isJsonRecord(b) && jsonRecordEqual(a, b);
}

function describeValue(value: unknown): string {
  return displayText(value === undefined ? "(none)" : JSON.stringify(value));
}

/**
 * Of one entry's expected mirror rows, the one with the same event name as
 * the observed row (a completed approve has two rows — `chain.approved` plus
 * the inner op's applied row — and the event names never overlap). If the
 * name matches no expected row, the first row is returned and the mismatch
 * is reported on event.
 */
function expectedRowFor(
  entry: ChainEntry,
  observed: WireAuditEvent,
  index: ProposalIndex,
): AuditEventRecord {
  const rows = chainMirrorEvents(entry, observed.serverTs, index);
  const first = rows[0];
  if (first === undefined) {
    // chainMirrorEvents returns 1+ rows (every op has a mapping)
    throw new Error("chain mirror mapping produced no rows");
  }
  return rows.find((row) => row.event === observed.event) ?? first;
}

/**
 * Reconciliation of a chain.* mirror row against the expected row. Rebuilds
 * the expected row from the same mapping as the server (chainMirrorEvents)
 * and lists the mismatched fields (empty = match). serverTs is out of scope —
 * it is the server's acceptance time and the client has nothing to verify it
 * against. A chain.* payload derives from the signed entry (an applied row
 * derives from the proposal entry's inner op), so it is in scope.
 */
function mirrorMismatches(expected: AuditEventRecord, observed: WireAuditEvent): readonly string[] {
  const reasons: string[] = [];
  const check = (label: string, want: unknown, got: unknown): void => {
    if (!jsonEqual(want, got)) {
      reasons.push(`${label}: expected ${describeValue(want)} / recorded ${describeValue(got)}`);
    }
  };
  check("event", expected.event, observed.event);
  check("client_ts", expected.clientTs, observed.clientTs);
  check("actor.type", expected.actorType, observed.actor.type);
  check("actor.user_id", expected.actorUserId, observed.actor.userId);
  check("actor.key_fingerprint", expected.actorKeyFingerprintHex, observed.actor.keyFingerprintHex);
  check("target.user_id", expected.targetUserId, observed.targetUserId);
  check(
    "target.key_fingerprint",
    expected.targetKeyFingerprintHex,
    observed.targetKeyFingerprintHex,
  );
  // The mapping never sets api_token_id on a mirror row (§3.4's actor is a
  // copy of the chain entry's). The expectation is always undefined, but the
  // check is explicit to block misleading into a fake "via token" display
  check("actor.api_token_id", expected.actorApiTokenId, observed.actor.apiTokenId);
  check("environment_id", expected.environmentId, observed.environmentId);
  check("variable_id", expected.variableId, observed.variableId);
  check("epoch", expected.epoch, observed.epoch);
  check("version", expected.version, observed.version);
  check("payload", expected.payload, observed.payload);
  return reasons;
}

/** Verified-chain seq → entry index. */
function entryIndexOf(entries: readonly ChainEntry[]): ReadonlyMap<number, ChainEntry> {
  return new Map(entries.map((entry) => [entry.seq, entry]));
}

/**
 * Whether an approve / withdraw's referenced proposal is missing from the
 * proposal index. Unreachable on a verified chain (the index is built from
 * the same verified chain — an unknown-proposal is an invalid entry), but
 * verify (reports it as a problem) and list (an unverified label) share the
 * same predicate.
 */
function proposalMissingFor(entry: ChainEntry, index: ProposalIndex): boolean {
  return (
    (entry.op === "approve" || entry.op === "withdraw") && !index.has(entry.payload.proposalHashHex)
  );
}

/** A chain.* row's trust label (for display) and mismatch details. */
interface MirrorTrust {
  readonly label: string;
  readonly mismatches: readonly string[];
}

function mirrorTrustOf(
  observed: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
  index: ProposalIndex,
): MirrorTrust {
  if (observed.chainSeq === undefined) {
    return { label: "mirror=mismatch", mismatches: ["chain_seq: the mirror row has no chain_seq"] };
  }
  if (observed.chainSeq > headSeq) {
    // Can also happen in an honest race where the chain grew after the sync —
    // not evidence on its own, but verify decides the distinction from
    // forgery (contiguity from just after the head)
    return {
      label: "mirror=unverified (newer than the local chain — confirm with `maruhi audit verify`)",
      mismatches: [],
    };
  }
  const entry = entries.get(observed.chainSeq);
  if (entry === undefined) {
    return {
      label: "mirror=mismatch",
      mismatches: [`chain_seq: the verified chain has no entry at seq=${observed.chainSeq}`],
    };
  }
  if (proposalMissingFor(entry, index)) {
    return {
      label:
        "mirror=unverified (the referenced proposal is not on the verified chain — re-run after a full sync)",
      mismatches: [],
    };
  }
  const mismatches = mirrorMismatches(expectedRowFor(entry, observed, index), observed);
  return mismatches.length === 0
    ? { label: "mirror=OK", mismatches }
    : { label: "mirror=mismatch", mismatches };
}

/**
 * The explicit distrust label for a row that carries chain_seq while its
 * event name is outside chain.*.
 *
 * On an honest server the only writer that sets chainSeq is
 * chainMirrorEvent, so this combination shows a forged provenance claim.
 * Starting from the event name alone, a row that escaped one step outside
 * the namespace would display as a bare `chain_seq=N` and would not even
 * fall under verify's eventPrefix=chain. filter.
 */
function outsideChainNamespaceTrust(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined || event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid outside the chain.* namespace)",
    mismatches: [
      `event: chain_seq is present on ${displayText(event.event)}, but only chain.* mirror rows may carry chain provenance`,
    ],
  };
}

/** Provenance judgment of a project audit row. Looks at the presence of chainSeq before the event name. */
function projectMirrorTrustOf(
  event: WireAuditEvent,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
  index: ProposalIndex,
): MirrorTrust | null {
  return (
    outsideChainNamespaceTrust(event) ??
    (event.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)
      ? mirrorTrustOf(event, entries, headSeq, index)
      : null)
  );
}

/** The D1 path (invites / self) stores no chain provenance. If present: forgery or corruption. */
function d1MirrorTrustOf(event: WireAuditEvent): MirrorTrust | null {
  if (event.chainSeq === undefined) {
    return null;
  }
  return {
    label: "mirror=unverified (chain_seq is invalid on this audit endpoint)",
    mismatches: [
      `chain_seq: ${event.chainSeq} is present on a D1-backed audit row, but this endpoint does not store chain provenance`,
    ],
  };
}

/** Maps trust mismatches to terminal warnings (empty = unverified but not tamper-decidable on its own). */
function mirrorWarnings(event: WireAuditEvent, trust: MirrorTrust | null): readonly string[] {
  return (trust?.mismatches ?? []).map(
    (mismatch) =>
      `audit row ${event.id} makes a chain provenance claim that is invalid or does not match the verified chain — ${mismatch} (the audit log is server-managed data, so this mismatch is evidence of server-side tampering or corruption — AUDIT_SPEC §6)`,
  );
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

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
function variableLabel(variableId: string, resolvedName: string | null): string {
  return resolvedName === null
    ? displayText(variableId)
    : `${displayText(resolvedName)} (${displayText(variableId)})`;
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
  const listed = aggregatedReadOf(event);
  if (listed !== null) {
    // Aggregated row: the variable enumeration lives in the payload (the
    // summary is count-only; expansion is --expand-reads). With --var, add
    // that variable's item (shows why the row matched)
    parts.push(`read=${describeReadCount(listed)}`);
    if (matched !== null) {
      parts.push(`matched=${matched}`);
    }
  }
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
  if (aggregatedReadOf(event) === null) {
    return event.payload;
  }
  const { variables: _variables, ...rest } = event.payload;
  return Object.keys(rest).length === 0 ? null : rest;
}

/**
 * The expanded lines of an aggregated var.read (one line per variable —
 * `--expand-reads`). Display names come only from verified statements
 * (the same TCB discipline as the var= label).
 */
function expandedReadLines(
  listed: readonly AuditReadVariable[],
  names: NameIndex | undefined,
): readonly string[] {
  return listed.map((variable) => `\t- ${listedVariableLabel(variable, names)}`);
}

/** The display form of one variable of an aggregated row (shared by the expanded lines and --var's match display). */
function listedVariableLabel(variable: AuditReadVariable, names: NameIndex | undefined): string {
  return `var=${variableLabel(variable.variableId, names?.get(variable.variableId) ?? null)}\tepoch=${variable.epoch}\tversion=${variable.version}`;
}

/** Rendering of one line. Display names (resolvedName) come only from verified statements. */
function formatEventLine(
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
function continuationHint(
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

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

function fetchProjectEvents(
  client: MaruhiClient,
  projectId: string,
  page: AuditPageOptions,
  filters: AuditListFilters,
): Effect.Effect<readonly WireAuditEvent[], CliError> {
  return client.audit
    .events({
      params: { projectId },
      query: {
        ...pageQueryOf(page),
        ...(filters.event === null ? {} : { event: filters.event }),
        ...(filters.actorUserId === null ? {} : { actorUserId: filters.actorUserId }),
        ...(filters.targetUserId === null ? {} : { targetUserId: filters.targetUserId }),
        ...(filters.variableId === null ? {} : { variableId: filters.variableId }),
        ...(filters.environmentId === null ? {} : { environmentId: filters.environmentId }),
      },
    })
    .pipe(
      Effect.mapError(toCliError),
      Effect.map((response) => response.events),
    );
}

/**
 * `maruhi audit` (list): displaying audit events. chain.* rows are
 * reconciled against the verified chain; any mismatch (= evidence of
 * tampering) makes exit code 1 (the same discipline as invite list's
 * integrity check — being readable and being sound are not conflated).
 */
/**
 * The set of environment IDs subject to name resolution (the environment of
 * rows carrying a variableId; when expanding, also an aggregated var.read's
 * environment — the expanded lines draw names).
 */
function environmentIdsForNames(
  events: readonly WireAuditEvent[],
  options: AuditListOptions,
  matchVariableId: string | null,
): readonly string[] {
  const ids = new Set<string>();
  const resolveListed = options.expandReads || matchVariableId !== null;
  for (const event of events) {
    if (event.environmentId === undefined) {
      continue;
    }
    if (event.variableId !== undefined || (resolveListed && aggregatedReadOf(event) !== null)) {
      ids.add(event.environmentId);
    }
  }
  return [...ids].toSorted();
}

/** One row's render result (body + expanded lines + mirror-mismatch warnings). Pure — holds no Effect. */
function renderListEvent(
  event: WireAuditEvent,
  names: ReadonlyMap<string, NameIndex>,
  entries: ReadonlyMap<number, ChainEntry>,
  headSeq: number,
  index: ProposalIndex,
  options: AuditListOptions,
  matchVariableId: string | null,
): { readonly lines: readonly string[]; readonly warnings: readonly string[] } {
  const environmentNames =
    event.environmentId === undefined ? undefined : names.get(event.environmentId);
  const name =
    event.variableId === undefined ? null : (environmentNames?.get(event.variableId) ?? null);
  const trust = projectMirrorTrustOf(event, entries, headSeq, index);
  const warnings = mirrorWarnings(event, trust);
  const listed = aggregatedReadOf(event);
  // With --var: the item of the variable the aggregated row matched on (the server returns rows whose enumeration contains that variable)
  const hit = listed?.find((variable) => variable.variableId === matchVariableId);
  const matched = hit === undefined ? null : listedVariableLabel(hit, environmentNames);
  return {
    lines: [
      formatEventLine(event, name, trust, matched),
      ...(listed === null || !options.expandReads
        ? []
        : expandedReadLines(listed, environmentNames)),
    ],
    warnings,
  };
}

export const auditListOp = Effect.fn("audit.auditListOp")(function* (
  context: ProjectContextBase,
  page: AuditPageOptions,
  filters: AuditListFilters,
  options: AuditListOptions,
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const events = yield* fetchProjectEvents(context.client, context.projectId, page, filters);
  if (events.length === 0) {
    yield* io.log("No audit events (no rows match the filter / cursor)");
    return 0;
  }
  const names = yield* resolveNames(
    context,
    environmentIdsForNames(events, options, filters.variableId),
  );
  const entries = entryIndexOf(context.verified.entries);
  const index = proposalIndexOf(context.verified);
  const integrityFailures = yield* logListEvents(events, (event) =>
    renderListEvent(
      event,
      names,
      entries,
      context.verified.state.headSeq,
      index,
      options,
      filters.variableId,
    ),
  );
  if (!options.expandReads && events.some((event) => aggregatedReadOf(event) !== null)) {
    yield* logNote(
      "var.read rows are recorded per value pull and list the variables read (AUDIT_SPEC §3.3). Re-run with --expand-reads to print one line per variable",
    );
  }
  const hint = continuationHint(events, page.limit, "maruhi audit");
  if (hint !== null) {
    yield* io.log(hint);
  }
  return integrityFailures > 0 ? 1 : 0;
});

/** Prints each row's body and expanded lines to stdout, the mirror warnings to stderr, and returns the warning count. */
const logListEvents = Effect.fn("audit.logListEvents")(function* (
  events: readonly WireAuditEvent[],
  render: (event: WireAuditEvent) => ReturnType<typeof renderListEvent>,
): Effect.fn.Return<number, never, CliIo> {
  const io = yield* CliIo;
  let integrityFailures = 0;
  for (const event of events) {
    const rendered = render(event);
    for (const line of rendered.lines) {
      yield* io.log(line);
    }
    integrityFailures += rendered.warnings.length;
    for (const warning of rendered.warnings) {
      yield* logWarning(warning);
    }
  }
  return integrityFailures;
});

// ---------------------------------------------------------------------------
// invites / self
// ---------------------------------------------------------------------------

/** Page spec → query (unspecified keys are not sent = left to the server defaults). */
function pageQueryOf(page: AuditPageOptions): { before?: string; limit?: number } {
  return {
    ...(page.before === null ? {} : { before: page.before }),
    ...(page.limit === null ? {} : { limit: page.limit }),
  };
}

interface D1AuditRenderResult {
  readonly events: readonly WireAuditEvent[];
  readonly integrityFailures: number;
}

/** The common path for a D1-side page (invites / self): fetch → render the list → continuation hint. */
const fetchAndRenderD1Events = Effect.fn("audit.fetchAndRenderD1Events")(function* <E>(input: {
  readonly request: Effect.Effect<{ readonly events: readonly WireAuditEvent[] }, E>;
  readonly page: AuditPageOptions;
  readonly emptyMessage: string;
  readonly command: string;
}): Effect.fn.Return<D1AuditRenderResult, CliError, CliIo> {
  const io = yield* CliIo;
  const events = yield* input.request.pipe(
    Effect.mapError(toCliError),
    Effect.map((response) => response.events),
  );
  if (events.length === 0) {
    yield* io.log(input.emptyMessage);
    return { events, integrityFailures: 0 };
  }
  let integrityFailures = 0;
  for (const event of events) {
    // A D1 row has no chain provenance. Even if a malicious response slips
    // chain_seq in, it is not displayed as a bare coordinate — warn +
    // non-zero exit (S1)
    const trust = d1MirrorTrustOf(event);
    const warnings = mirrorWarnings(event, trust);
    yield* io.log(formatEventLine(event, null, trust));
    integrityFailures += warnings.length;
    for (const warning of warnings) {
      yield* logWarning(warning);
    }
  }
  const hint = continuationHint(events, input.page.limit, input.command);
  if (hint !== null) {
    yield* io.log(hint);
  }
  return { events, integrityFailures };
});

/** `maruhi audit invites`: the audit rows of invite.* (chain role admin — server-enforced). */
export function auditInvitesOp(
  context: ProjectContextBase,
  page: AuditPageOptions,
): Effect.Effect<number, CliError, CliServices> {
  return fetchAndRenderD1Events({
    request: context.client.audit.invites({
      params: { projectId: context.projectId },
      query: pageQueryOf(page),
    }),
    page,
    emptyMessage: "No invite audit events",
    command: "maruhi audit invites",
  }).pipe(Effect.map((result) => (result.integrityFailures > 0 ? 1 : 0)));
}

/** `maruhi audit self`: one's own account events (§3.1 — monitoring the to-be-monitored events). */
export const auditSelfOp = Effect.fn("audit.auditSelfOp")(function* (
  context: SessionContext,
  page: AuditPageOptions,
): Effect.fn.Return<number, CliError, CliServices> {
  const rendered = yield* fetchAndRenderD1Events({
    request: context.client.audit.self({ query: pageQueryOf(page) }),
    page,
    emptyMessage: "No account audit events",
    command: "maruhi audit self",
  });
  const events = rendered.events;
  // The implication of a to-be-monitored event (AUDIT_SPEC §3.1) is attached here once
  if (events.some((event) => event.event === "auth.recovery_blob_fetched")) {
    yield* logNote(
      "auth.recovery_blob_fetched (a fetch of the sealed reserve key) is present. If you do not recognize a fetch, reissue your recovery code (`maruhi key recovery`) and revoke your tokens and sessions",
    );
  }
  return rendered.integrityFailures > 0 ? 1 : 0;
});

// ---------------------------------------------------------------------------
// verify (mirror bijection verification)
// ---------------------------------------------------------------------------

// §3.4's mirror event names use the shared mapping (@maruhi/core's
// CHAIN_MIRROR_EVENTS — derived from ChainOp's total map). A hand-written
// list would miss a future op addition only here, and the contiguity check
// would wrongly convict an honest server of forgery

const VERIFY_PAGE_LIMIT = MAX_AUDIT_EVENTS_PAGE_LIMIT;
// Chain acceptance policy (10,000 entries) ÷ 200 per page = a theoretical
// maximum of 50 pages. A hard cap so a server whose cursor does not advance
// cannot loop forever. Because one paging pass per namespace draws all mirror
// rows, the cap is a single total, not per event kind
const VERIFY_MAX_PAGES = 100;

type MirrorRowSelector = "chain-namespace" | "chain-seq-present";

/**
 * The shared paging engine (used by verify and `maruhi audit reconcile`).
 * fetchPage fetches one page (newest-first); the cursor is the previous
 * page's last row's id. onRow is the per-row check + collection (a failure
 * aborts as a contradictory server response). bound is a static page-count
 * cap — null means uncapped, in which case termination is carried by the
 * caller's row check (reconcile bounds the total row count via the
 * strictly-decreasing admin-visible `seq`).
 */
export const paginateAuditEvents = Effect.fn("audit.paginateAuditEvents")(function* (input: {
  readonly pageLimit: number;
  readonly fetchPage: (before: string | null) => Effect.Effect<readonly WireAuditEvent[], CliError>;
  readonly onRow: (row: WireAuditEvent) => Effect.Effect<void, CliError>;
  readonly bound: { readonly maxPages: number; readonly exceededMessage: string } | null;
}): Effect.fn.Return<void, CliError> {
  let before: string | null = null;
  for (let page = 0; input.bound === null || page < input.bound.maxPages; page += 1) {
    // The annotation breaks self-referential inference inside the generator (before → rows → before)
    const cursor: string | null = before;
    const rows: readonly WireAuditEvent[] = yield* input.fetchPage(cursor);
    for (const row of rows) {
      yield* input.onRow(row);
    }
    if (rows.length < input.pageLimit) {
      return;
    }
    before = rows[rows.length - 1]?.id ?? null;
  }
  // Leaving the loop = bound was non-null and maxPages was reached
  return yield* Effect.fail(cliError(input.bound?.exceededMessage ?? "unreachable"));
});

/**
 * Fetch all pages of one mirror-candidate filter (newest-first; cursor is a
 * row id). A re-appearing row id is refused as a contradictory server
 * response (a non-advancing cursor, duplicate row distribution) — ids are
 * opaque and cannot be ordinally compared, so progress is checked as set
 * non-duplication.
 */
const fetchMirrorRowsForSelector = Effect.fn("audit.fetchMirrorRowsForSelector")(function* (
  client: MaruhiClient,
  projectId: string,
  selector: MirrorRowSelector,
): Effect.fn.Return<readonly WireAuditEvent[], CliError> {
  const rows: WireAuditEvent[] = [];
  const seen = new Set<string>();
  yield* paginateAuditEvents({
    pageLimit: VERIFY_PAGE_LIMIT,
    bound: {
      maxPages: VERIFY_MAX_PAGES,
      exceededMessage:
        "The audit log exceeded the theoretical page-count limit — the server response contradicts itself",
    },
    fetchPage: (before) =>
      client.audit
        .events({
          params: { projectId },
          query: {
            limit: VERIFY_PAGE_LIMIT,
            ...(selector === "chain-namespace"
              ? { eventPrefix: CHAIN_MIRROR_EVENT_PREFIX }
              : { chainSeqPresent: "true" as const }),
            ...(before === null ? {} : { before }),
          },
        })
        .pipe(
          Effect.mapError(toCliError),
          Effect.map((response) => response.events as readonly WireAuditEvent[]),
        ),
    onRow: (row) => {
      if (seen.has(row.id)) {
        return Effect.fail(
          cliError(
            `Audit-log paging is not advancing (${selector}, row ${displayText(row.id)} was returned twice) — the server response contradicts itself. Aborting the mirror verification`,
          ),
        );
      }
      seen.add(row.id);
      rows.push(row);
      return Effect.void;
    },
  });
  return rows;
});

/**
 * verify's full mirror candidate set. The union of two sets:
 *
 * 1. every row in the `chain.` namespace — also catches names missing from
 *    the mapping and missing chain_seq
 * 2. every row carrying chain_seq — catches forged provenance one step
 *    outside the namespace
 *
 * A genuine mirror row lands in both, so dedupe by row id. If the same id's
 * content changed between the filters, the server response contradicts
 * itself and verification cannot proceed.
 */
const fetchAllMirrorRows = Effect.fn("audit.fetchAllMirrorRows")(function* (
  client: MaruhiClient,
  projectId: string,
): Effect.fn.Return<readonly WireAuditEvent[], CliError> {
  const byId = new Map<string, WireAuditEvent>();
  for (const selector of ["chain-namespace", "chain-seq-present"] as const) {
    const rows = yield* fetchMirrorRowsForSelector(client, projectId, selector);
    for (const row of rows) {
      const existing = byId.get(row.id);
      if (existing !== undefined && !jsonEqual(existing, row)) {
        return yield* Effect.fail(
          cliError(
            `Audit row ${displayText(row.id)} changed between mirror-verification queries — the server response contradicts itself`,
          ),
        );
      }
      byId.set(row.id, row);
    }
  }
  return [...byId.values()];
});

/** The result of indexing mirror rows (bundled by chain_seq, with unverifiable rows sorted out). */
interface MirrorBuckets {
  readonly byChainSeq: ReadonlyMap<number, readonly WireAuditEvent[]>;
  readonly problems: readonly string[];
  /** The count of "newer than the local chain" rows contiguous from just after head (unverified). */
  readonly aheadRows: number;
}

/**
 * The contiguity check of rows newer than head. In an honest extension (the
 * chain advanced between the sync and the page fetch), those rows' chain_seq
 * run contiguously from head+1 with no gaps — mirrors are written in the same
 * transaction as acceptance and seq is gapless (§3.4 / §5.1). At most 2 rows
 * share one chain_seq (a completed approve's `chain.approved` + the applied
 * row — §3.4). A non-contiguous seq or a seq with 3+ rows is treated as
 * evidence of "forged rows claiming nonexistent entries" (blocks
 * verification bypass via an unreachable chain_seq).
 */
function aheadContiguityProblems(ahead: readonly number[], headSeq: number): readonly string[] {
  const problems: string[] = [];
  const counts = new Map<number, number>();
  for (const chainSeq of ahead) {
    counts.set(chainSeq, (counts.get(chainSeq) ?? 0) + 1);
  }
  let expected = headSeq + 1;
  for (const chainSeq of [...counts.keys()].toSorted((a, b) => a - b)) {
    if (chainSeq !== expected) {
      problems.push(
        `chain_seq=${chainSeq}: mirror rows newer than the local chain (head seq=${headSeq}) are not contiguous from just after the head (expected ${expected}) — an honest extension is contiguous with no gaps, so this is evidence of forged rows claiming nonexistent entries`,
      );
    }
    const count = counts.get(chainSeq) ?? 0;
    if (count > 2) {
      problems.push(
        `chain_seq=${chainSeq}: ${countNoun(count, "mirror row")} newer than the local chain — no chain entry has more than 2 mirror rows (a completed approve has its own row plus the applied inner-op row — AUDIT_SPEC §3.4), so this is evidence of forged rows`,
      );
    }
    expected = chainSeq + 1;
  }
  return problems;
}

/** Indexes the fetched chain.* rows by chain_seq (a pure function before verification). */
function bucketMirrorRows(rows: readonly WireAuditEvent[], headSeq: number): MirrorBuckets {
  const byChainSeq = new Map<number, WireAuditEvent[]>();
  const problems: string[] = [];
  const ahead: number[] = [];
  for (const row of rows) {
    // chain_seq's presence is treated as the trust boundary ahead of the
    // event name. The only writer of a genuine chain_seq is chainMirrorEvent,
    // so a row outside the namespace is a forged provenance claim that no
    // real op can reconcile against
    if (!row.event.startsWith(CHAIN_MIRROR_EVENT_PREFIX)) {
      problems.push(
        `Audit row ${displayText(row.id)}: chain_seq=${row.chainSeq ?? "(missing)"} is present outside the chain.* namespace (${displayText(row.event)}) — only chain mirror rows may carry chain provenance (evidence of a forged row)`,
      );
      continue;
    }
    // Inside the namespace, an event name missing from the mapping is itself
    // evidence of forgery: a real op's mirror always lands in
    // chainMirrorEvent's image. The row cannot proceed to chain_seq
    // reconciliation, so it is confirmed as a problem here and we move on
    if (!CHAIN_MIRROR_EVENTS.includes(row.event)) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row claims an unknown chain op (${displayText(row.event)}) — no chain operation maps to this event name, so the row cannot mirror a real entry (evidence of a forged row)`,
      );
      continue;
    }
    if (row.chainSeq === undefined) {
      problems.push(
        `Audit row ${displayText(row.id)}: the mirror row has no chain_seq (${displayText(row.event)})`,
      );
    } else if (row.chainSeq > headSeq) {
      ahead.push(row.chainSeq);
    } else {
      byChainSeq.set(row.chainSeq, [...(byChainSeq.get(row.chainSeq) ?? []), row]);
    }
  }
  problems.push(...aheadContiguityProblems(ahead, headSeq));
  return { byChainSeq, problems, aheadRows: ahead.length };
}

/** Reconcile the observed rows against one expected row (missing / duplicate / field mismatch). */
function expectedRowProblems(
  entry: ChainEntry,
  expected: AuditEventRecord,
  rows: readonly WireAuditEvent[],
  index: ProposalIndex,
): readonly string[] {
  const observed = rows[0];
  if (observed === undefined) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): no corresponding ${displayText(expected.event)} mirror row (a missing row — mirrors are written in the same transaction as chain acceptance, so this is evidence of a concealed deletion)`,
    ];
  }
  if (rows.length > 1) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): ${countNoun(rows.length, `${displayText(expected.event)} mirror row`)} found (duplicates — rows ${rows.map((row) => displayText(row.id)).join(", ")})`,
    ];
  }
  // serverTs is out of scope (the observed row's value is copied onto the expected row before comparing)
  return mirrorMismatches(expectedRowFor(entry, observed, index), observed).map(
    (mismatch) => `chain_seq=${entry.seq} (audit row ${displayText(observed.id)}): ${mismatch}`,
  );
}

/**
 * One entry's bijection + mapping-match check (empty = no problem). The
 * expected set is the 1 row chainMirrorEvents returns (2 rows for a
 * completed approve); observed rows are paired to expected rows by event
 * name: an expected row with no observed row is missing, 2+ observed is a
 * duplicate, and a row with an event name outside the expected set is excess
 * (an applied row on an incomplete approve, a row claiming a different op,
 * etc.). A mismatch in any field of an applied row, including
 * `viaProposalSeq`, is listed as a mapping mismatch (AUDIT_SPEC §3.4 —
 * 2026-09-16 K5).
 */
function entryMirrorProblems(
  entry: ChainEntry,
  matched: readonly WireAuditEvent[],
  index: ProposalIndex,
): readonly string[] {
  // On a verified chain the referenced propose is always in the index (an
  // unknown-proposal is an invalid entry). A miss is a contradiction in the
  // index's construction and the expected rows cannot be built, so do not
  // drop it as a defect — report it as a verification failure with the
  // chain_seq (pullfrog round 1)
  if (proposalMissingFor(entry, index)) {
    return [
      `chain_seq=${entry.seq} (op=${entry.op}): the referenced proposal is not on the verified chain, so the expected mirror rows cannot be reconstructed — re-run \`maruhi audit verify\` after a full sync; if this persists it is a verifier inconsistency, not evidence about the audit log`,
    ];
  }
  const expectedRows = chainMirrorEvents(entry, 0, index);
  const expectedEvents = new Set<string>(expectedRows.map((row) => row.event));
  const problems = expectedRows.flatMap((expected) =>
    expectedRowProblems(
      entry,
      expected,
      matched.filter((row) => row.event === expected.event),
      index,
    ),
  );
  const unexpected = matched
    .filter((row) => !expectedEvents.has(row.event))
    .map(
      (row) =>
        `chain_seq=${entry.seq} (op=${entry.op}): unexpected mirror row ${displayText(row.id)} (${displayText(row.event)}) — the entry maps to ${expectedRows.map((expected) => displayText(expected.event)).join(" + ")} only (an applied inner-op row exists only for an approve that reached the quorum — AUDIT_SPEC §3.4), so this is evidence of a forged row`,
    );
  return [...problems, ...unexpected];
}

/**
 * `maruhi audit verify`: mirror bijection verification. Checks that every
 * entry of the verified chain (1..headSeq) and the chain.* mirror rows
 * correspond 1:1 (a completed approve adds the applied inner-op row —
 * AUDIT_SPEC §3.4) and that every field matches the mapping. Detects the
 * three directions — missing (concealed deletion), forged (a row not on the
 * chain), altered — covering even the missing case that per-row
 * reconciliation (list's labels) cannot see in principle, which is this
 * command's added value. It reads only class 1, so every member can run it.
 */
export const auditVerifyOp = Effect.fn("audit.auditVerifyOp")(function* (
  context: ProjectContextBase,
): Effect.fn.Return<number, CliError, CliServices> {
  const io = yield* CliIo;
  const rows = yield* fetchAllMirrorRows(context.client, context.projectId);
  const headSeq = context.verified.state.headSeq;
  const buckets = bucketMirrorRows(rows, headSeq);
  const index = proposalIndexOf(context.verified);
  const problems = [
    ...buckets.problems,
    ...context.verified.entries.flatMap((entry) =>
      entryMirrorProblems(entry, buckets.byChainSeq.get(entry.seq) ?? [], index),
    ),
  ];
  if (problems.length === 0 && buckets.aheadRows === 0) {
    yield* io.log(
      `Mirror bijection verification OK: chain entries 1..${headSeq} \u2194 chain.* mirror rows match the mapping (one row per entry, plus the applied inner-op row of each completed approve — AUDIT_SPEC §3.4)`,
    );
    return 0;
  }
  if (buckets.aheadRows > 0) {
    // Never say "OK" while unverified rows remain (do not paper over, with
    // a successful exit, the shape where forged rows permanently sit inside
    // the unverified allowance)
    yield* io.logError(
      `Mirror verification incomplete: ${countNoun(buckets.aheadRows, "row")} newer than the local chain could not be verified in this run (this can happen when the chain grew right after the sync). Re-run \`maruhi audit verify\` — if this does not resolve, those mirror rows claim entries that do not exist on the chain (suspected forgery)`,
    );
  }
  for (const problem of problems) {
    yield* io.logError(`Mirror verification failure: ${problem}`);
  }
  if (problems.length > 0) {
    yield* io.logError(
      `Mirror verification found ${countNoun(problems.length, "problem")}. The audit log is server-managed data (AUDIT_SPEC §6) and these mismatches are evidence of server-side tampering or corruption — the distributed chain (signed and verified) is the truth; do not trust the audit log`,
    );
  }
  return 1;
});
