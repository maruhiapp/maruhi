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

export interface AuditListFilters {
  readonly event: string | null;
  readonly actorUserId: UserId | null;
  readonly targetUserId: UserId | null;
  readonly environmentId: EnvironmentId | null;
  readonly variableId: VariableId | null;
}

interface AuditListOptions {
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

function recommendedVariableLabel(
  variable: RotationRecommendedVariable,
  names: NameIndex | undefined,
): string {
  return `var=${variableLabel(variable.variableId, names?.get(variable.variableId) ?? null)}\tbasis=${variable.basis}`;
}

function listedVariableLabel(variable: AuditReadVariable, names: NameIndex | undefined): string {
  return `var=${variableLabel(variable.variableId, names?.get(variable.variableId) ?? null)}\tepoch=${variable.epoch}\tversion=${variable.version}`;
}

function expandedReadLines(
  listed: readonly AuditReadVariable[],
  names: NameIndex | undefined,
): readonly string[] {
  return listed.map((variable) => `\t- ${listedVariableLabel(variable, names)}`);
}

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

function entryIndexOf(entries: readonly ChainEntry[]): ReadonlyMap<number, ChainEntry> {
  return new Map(entries.map((entry) => [entry.seq, entry]));
}

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
