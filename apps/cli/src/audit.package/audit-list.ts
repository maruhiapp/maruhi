// `maruhi audit list`, which bare `maruhi audit` also runs (AUDIT_SPEC §6 /
// §7): the project DO's audit events (newest-first, seq cursor). The
// visibility classes (§6) are server-enforced; this side only renders. Each
// chain.* row is reconciled against the verified chain (audit-mirror.ts),
// and a variable's name comes from verified statements only
// (audit-page.ts).

import {
  type AuditReadVariable,
  decodeEnvironmentId,
  type EnvironmentId,
  isEnvironmentId,
  type ProjectId,
  type ProposalIndex,
  type RotationRecommendedVariable,
  type UserId,
  type VariableId,
} from "@maruhi/core";
import type { ChainEntry } from "@maruhi/crypto";
import { Effect } from "effect";

import type { MaruhiClient } from "../api.ts";
import { proposalIndexOf } from "../chain-applied.ts";
import type { CliServices, ProjectContextBase } from "../context.ts";
import type { CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { CliIo } from "../io.ts";
import { logNote, logWarning } from "../notice.ts";
import { type NameIndex, resolveNames } from "../rotation.ts";
import { mirrorWarnings, projectMirrorTrustOf, type WireAuditEvent } from "./audit-mirror.ts";
import {
  aggregatedReadOf,
  aggregatedRecommendedOf,
  type AuditPageOptions,
  continuationHint,
  formatEventLine,
  pageQueryOf,
  variableLabel,
} from "./audit-page.ts";

/** list's filters (AUDIT_SPEC §7 vocabulary). */
export interface AuditListFilters {
  readonly event: string | null;
  readonly actorUserId: UserId | null;
  readonly targetUserId: UserId | null;
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
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

function fetchProjectEvents(
  client: MaruhiClient,
  projectId: ProjectId,
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
 * The set of environment IDs subject to name resolution (the environment of
 * rows carrying a variableId; when expanding, also an aggregated var.read's
 * environment — the expanded lines draw names).
 */
function environmentIdsForNames(
  events: readonly WireAuditEvent[],
  options: AuditListOptions,
  matchVariableId: string | null,
): readonly EnvironmentId[] {
  const ids = new Set<EnvironmentId>();
  const resolveListed = options.expandReads || matchVariableId !== null;
  for (const event of events) {
    if (event.environmentId === undefined) {
      continue;
    }
    // A wire env id out of §12-1's form cannot mint — skip it from name
    // resolution (degrades to identifier display, never a defect — the
    // same SHOULD-level treatment as a failed metadata pull)
    if (
      (event.variableId !== undefined ||
        (resolveListed &&
          (aggregatedReadOf(event) !== null || aggregatedRecommendedOf(event) !== null))) &&
      isEnvironmentId(event.environmentId)
    ) {
      ids.add(decodeEnvironmentId(event.environmentId));
    }
  }
  return [...ids].toSorted();
}

/** The display form of one flagged variable of an aggregated rotation.recommended row (shared by --var's match display). */
function recommendedVariableLabel(
  variable: RotationRecommendedVariable,
  names: NameIndex | undefined,
): string {
  return `var=${variableLabel(variable.variableId, names?.get(variable.variableId) ?? null)}\tbasis=${variable.basis}`;
}

/** The display form of one variable of an aggregated row (shared by the expanded lines and --var's match display). */
function listedVariableLabel(variable: AuditReadVariable, names: NameIndex | undefined): string {
  return `var=${variableLabel(variable.variableId, names?.get(variable.variableId) ?? null)}\tepoch=${variable.epoch}\tversion=${variable.version}`;
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
  const flagged = aggregatedRecommendedOf(event);
  // With --var: the item of the variable the aggregated row matched on (the
  // server returns rows whose enumeration contains that variable — var.read or
  // rotation.recommended; a row is one kind, so at most one matches)
  const readHit = listed?.find((variable) => variable.variableId === matchVariableId);
  const flagHit = flagged?.find((variable) => variable.variableId === matchVariableId);
  const matched =
    readHit !== undefined
      ? listedVariableLabel(readHit, environmentNames)
      : flagHit !== undefined
        ? recommendedVariableLabel(flagHit, environmentNames)
        : null;
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

/** Verified-chain seq → entry index. */
function entryIndexOf(entries: readonly ChainEntry[]): ReadonlyMap<number, ChainEntry> {
  return new Map(entries.map((entry) => [entry.seq, entry]));
}

/**
 * `maruhi audit` (list): displaying audit events. chain.* rows are
 * reconciled against the verified chain; any mismatch (= evidence of
 * tampering) makes exit code 1 (the same discipline as invite list's
 * integrity check — being readable and being sound are not conflated).
 */
export const auditListOp = Effect.fn("audit-list.auditListOp")(function* (
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
const logListEvents = Effect.fn("audit-list.logListEvents")(function* (
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
