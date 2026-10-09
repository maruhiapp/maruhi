"use client";

// The shared list of the S6 audit viewer (ruling BQ —
// docs/notes/session-43.md).
// The three consumers — the project axis, the invite axis, and the
// self axis — use the same component.
//
// - The heading is the role-adaptive prescribed wording "Events
//   visible to your role" (AUDIT_SPEC §7 — never hints at the
//   existence or count of an invisible class)
// - `seq` is shown only by "whether the response carries seq" (the
//   role's pre-judgment is not replicated on the client — the decision
//   point stays server authorization only)
// - Paging is only the `before`-cursor (row_id) Load more. No counts
//   are displayed
// - Every field is the server-reported value as recorded. Display-name
//   resolution (via verified statements) is not performed — name
//   resolution on a web app without verification becomes trusting a
//   name without statement verification (AUTH_SPEC §12-2), so only
//   identifiers are shown
//
// DP3 amendment 5 (docs/notes/web-design-pass.md §5 ruling P): the
// shape is "one column of rows + expand in place".
// One row = an Astryx `Collapsible` (CollapsibleGroup hasDividers —
// the `CollapsibleDividedAccordion` block's shape). The trigger =
// event name, actor, coordinates, server time (+ seq); the expanded
// part = every field (MetadataList) + the payload as recorded + the
// var.read enumeration. The left-right split (amendment 3's
// `incident-console` shape) was withdrawn because on a wide screen the
// gap between row and detail grew too large and the shape changed at
// 1024px. One column keeps the same shape at any width, with the
// detail directly under the row (HP5 — reading the audit on mobile).
// No Table (keeps the rows at a readable width). Wording, items, and
// order are invariant (the §4 display discipline — never claims
// "verified", FP is a reference value, no counts).
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Collapsible, CollapsibleGroup } from "@astryxdesign/core/Collapsible";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import * as stylex from "@stylexjs/stylex";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import type { ApiFailure, ApiResult } from "./api.ts";
import {
  aggregatedReadVariables,
  listedReadVariableLabel,
  payloadWithoutVariables,
  lineageLabel,
  readSummaryLabel,
} from "./audit-read.ts";
import {
  EmptyNotice,
  FailureNotice,
  formatServerTime,
  HexText,
  LoadingRow,
  ServerTime,
} from "./shared.tsx";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

/** Fetches one page. `before` is the row_id of the previous page's last row (AUDIT_SPEC §7). */
export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

// The label column width of the expanded part's MetadataList (96, same as `incident-console`'s inspector)
const DETAIL_LABEL_WIDTH = 96;

/** A label : value fragment (not emitted when the value is missing). */
interface Fragment {
  label: string;
  value: string;
}

function fragment(label: string, value: string | number | undefined): Fragment | undefined {
  return value === undefined ? undefined : { label, value: String(value) };
}

function isPresent(part: Fragment | undefined): part is Fragment {
  return part !== undefined;
}

/** The actor's principal (internal user_id / server / system). Provider information is structurally absent. */
function actorHead(event: AuditEvent): string {
  const actor = event.actor;
  return actor.type === "user" ? (actor.userId ?? "(unknown user)") : actor.type;
}

/** The actor's accompanying identifiers (key FP, token id) — reference values, not verification material (§4-3). */
function actorFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("key", event.actor.keyFingerprintHex),
    fragment("token", event.actor.apiTokenId),
  ].filter(isPresent);
}

/** The row's coordinates (target / environment / variable / epoch / version / chainSeq). */
function detailFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("target", event.targetUserId),
    fragment("target key", event.targetKeyFingerprintHex),
    fragment("env", event.environmentId),
    fragment("var", event.variableId),
    // A rotation.recommended row's epoch is its exposure bound (AUDIT_SPEC §3.3 — VH)
    fragment(event.event === "rotation.recommended" ? "exposure epoch" : "epoch", event.epoch),
    fragment("v", event.version),
    fragment("value", lineageLabel(event) ?? undefined),
    fragment("chain seq", event.chainSeq),
  ].filter(isPresent);
}

/** A row of labeled fragments (may wrap). */
function Fragments({ items }: { items: ReadonlyArray<Fragment> }): ReactNode {
  if (items.length === 0) return null;
  return (
    <HStack gap={2} wrap="wrap" align="center">
      {items.map((item) => (
        <Text key={item.label} type="supporting" size="sm">
          {item.label} <HexText>{item.value}</HexText>
        </Text>
      ))}
    </HStack>
  );
}

// ---------------------------------------------------------------------------
// The row's trigger (the always-visible summary)
// ---------------------------------------------------------------------------

/**
 * One event's summary = the content of the Collapsible's trigger
 * (button). Order: actor → coordinates → seq / time.
 * seq and time share one line, continuing to the right of the event
 * name (not pushed to the far right — a wide screen must not open a
 * gap between name and time. Ruling Q). On narrow widths it wraps
 * under the name. seq is shown only when the response carries it
 * (response-adaptive — AUDIT_SPEC §7). Inside a button, so it carries
 * no interactive elements (Text / HexText, Timestamp without a hover
 * card).
 */
function EventSummary({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  return (
    <VStack gap={1}>
      <HStack gap={4} align="center" wrap="wrap">
        <Text weight="semibold">{event.event}</Text>
        <HStack gap={3} align="center">
          {event.seq === undefined ? null : (
            <Text type="supporting" size="sm" hasTabularNumbers>
              seq {event.seq}
            </Text>
          )}
          <ServerTime ms={event.serverTs} hasTooltip={false} />
        </HStack>
      </HStack>
      <HStack gap={2} wrap="wrap" align="center">
        <Text type="supporting" size="sm">
          by <HexText>{actorHead(event)}</HexText>
        </Text>
        <Fragments items={detailFragments(event)} />
        {listed === null ? null : (
          <Text type="supporting" size="sm">
            {readSummaryLabel(listed)}
          </Text>
        )}
      </HStack>
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// The expanded part (every field — MetadataList + the payload as
// recorded)
// ---------------------------------------------------------------------------

function DetailItem({ label, value }: { label: string; value: string | undefined }): ReactNode {
  if (value === undefined) return null;
  return (
    <MetadataListItem label={label}>
      <HexText>{value}</HexText>
    </MetadataListItem>
  );
}

// Keeps the formatted JSON's newlines and indentation, and wraps long
// hex at any position (no horizontal scrolling).
// Astryx `CodeBlock` emits an inline `style`
// (contain-intrinsic-block-size) per line chunk, so it cannot render
// under the strict CSP (style-src 'self') (DK K5-11 — design record
// dk-design.md §10). A payload is the audit's recorded value and needs
// no syntax highlighting, so it is drawn with `Text type="code"` +
// xstyle's pre-wrap
const payloadStyles = stylex.create({
  pre: {
    whiteSpace: "pre-wrap",
    overflowWrap: "anywhere",
    wordBreak: "break-all",
    minWidth: 0,
  },
});

/** The payload as recorded (the server-reported JSON as-is — no syntax highlighting, no inline style). */
function RecordedPayload({ payload }: { payload: Readonly<Record<string, unknown>> }): ReactNode {
  return (
    <VStack gap={1}>
      <Text weight="semibold">Payload (as recorded)</Text>
      <Card variant="muted" padding={3}>
        <Text as="div" type="code" size="sm" xstyle={payloadStyles.pre}>
          {JSON.stringify(payload, null, 2)}
        </Text>
      </Card>
    </VStack>
  );
}

function ReadsList({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  if (listed === null) return null;
  // The aggregated var.read (AUDIT_SPEC §3.3): the payload holds the
  // variable enumeration. The enumeration is sorted by variableId with
  // no duplicates — usable as keys. edgeCompensation cancels the items'
  // inline inset against the Collapsible panel's padding, so the rows
  // line up with the heading above (and the Payload heading) instead of
  // sitting 8px in
  return (
    <VStack gap={2}>
      <Text weight="semibold">{readSummaryLabel(listed)}</Text>
      <List density="compact" edgeCompensation="inline">
        {listed.map((variable) => (
          <ListItem
            key={`${variable.variableId}:${variable.version}`}
            label={listedReadVariableLabel(variable)}
          />
        ))}
      </List>
    </VStack>
  );
}

/** The payload minus the enumeration (variables). The payload itself when not the aggregated shape. */
function recordedPayload(event: AuditEvent): Readonly<Record<string, unknown>> | null {
  if (event.payload === undefined) return null;
  return aggregatedReadVariables(event) === null
    ? event.payload
    : payloadWithoutVariables(event.payload);
}

/** The expanded part: every field as recorded (labels only indicate the kind of identifier — §4-3). */
function EventDetails({ event }: { event: AuditEvent }): ReactNode {
  const payload = recordedPayload(event);
  return (
    <VStack gap={4}>
      <MetadataList columns="single" label={{ position: "start", width: DETAIL_LABEL_WIDTH }}>
        <DetailItem label="Seq" value={event.seq === undefined ? undefined : String(event.seq)} />
        {/* The server time as recorded (ISO in UTC). The row's display is in the viewer's timezone */}
        <DetailItem label="Recorded at" value={formatServerTime(event.serverTs)} />
        <DetailItem label="Actor" value={actorHead(event)} />
        {actorFragments(event).map((item) => (
          <DetailItem key={item.label} label={item.label} value={item.value} />
        ))}
        {detailFragments(event).map((item) => (
          <DetailItem key={item.label} label={item.label} value={item.value} />
        ))}
        <DetailItem label="Row id" value={event.id} />
      </MetadataList>
      {payload === null ? null : <RecordedPayload payload={payload} />}
      <ReadsList event={event} />
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// The paging state
// ---------------------------------------------------------------------------

interface LoadedState {
  events: AuditEvent[];
  /** The latest page came back empty (or empty from the start) = nothing further back. */
  exhausted: boolean;
}

/** The last row's row_id = the next page's `before` cursor. */
function nextCursor(current: LoadedState | undefined): string | undefined {
  return current?.events.at(-1)?.id;
}

function appendPage(
  current: LoadedState | undefined,
  page: ReadonlyArray<AuditEvent>,
): LoadedState {
  return {
    events: [...(current?.events ?? []), ...page],
    exhausted: page.length === 0,
  };
}

/**
 * Load more. The button is never swapped out while loading (a
 * LoadingRow would make the focused element disappear and focus fall
 * to body); Astryx's isLoading shows a spinner + aria-busy instead.
 * isInterruptible exists because native disabled is not added (a
 * disabled element also loses focus); a double load is blocked by the
 * handler-side guard.
 */
function LoadMoreRow({
  isLoading,
  exhausted,
  onLoadMore,
}: {
  isLoading: boolean;
  exhausted: boolean;
  onLoadMore: () => void;
}): ReactNode {
  if (exhausted && !isLoading) return null;
  return (
    <HStack>
      <Button
        label="Load more"
        variant="secondary"
        isLoading={isLoading}
        isInterruptible
        onClick={() => {
          if (!isLoading) onLoadMore();
        }}
        data-testid="load-more-events"
      />
    </HStack>
  );
}

/** CollapsibleGroup(single)'s onChange value → the open row's id (undefined when closed). */
function openedId(value: string | string[]): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * The list of rows (one column). At most one row is open (single) —
 * other rows never move while the expanded part is being read.
 * The expansion state is held by this component and survives appended
 * pages.
 */
function EventRows({ events }: { events: ReadonlyArray<AuditEvent> }): ReactNode {
  const [openId, setOpenId] = useState<string | undefined>(undefined);
  return (
    <CollapsibleGroup
      type="single"
      hasDividers
      density="balanced"
      value={openId ?? ""}
      onChange={(value) => setOpenId(openedId(value))}
    >
      {events.map((event) => (
        <Collapsible key={event.id} value={event.id} trigger={<EventSummary event={event} />}>
          <EventDetails event={event} />
        </Collapsible>
      ))}
    </CollapsibleGroup>
  );
}

/** The body after the first page arrives: the rows + an appended-form failure + Load more. */
function LoadedEventsView({
  loaded,
  failure,
  isLoading,
  onLoadMore,
  testId,
}: {
  loaded: LoadedState;
  failure: ApiFailure | undefined;
  isLoading: boolean;
  onLoadMore: () => void;
  testId: string;
}): ReactNode {
  return (
    <VStack gap={4} data-testid={testId}>
      <EventRows events={loaded.events} />
      {/* Appended form (ruling B-b): the Load more failure is added below the already-rendered list */}
      {failure !== undefined ? <FailureNotice failure={failure} onRetry={onLoadMore} /> : null}
      <LoadMoreRow isLoading={isLoading} exhausted={loaded.exhausted} onLoadMore={onLoadMore} />
    </VStack>
  );
}

export function AuditEventList({
  fetchPage,
  emptyTitle,
  testId,
}: {
  fetchPage: AuditPageFetcher;
  emptyTitle: string;
  testId: string;
}): ReactNode {
  const [loaded, setLoaded] = useState<LoadedState | undefined>(undefined);
  const [failure, setFailure] = useState<ApiFailure | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);
  // The generation of the consumed axis (fetchPage). When the axis
  // changes, a stale in-flight response is discarded —
  // a late-arriving old-axis page cannot bleed into the new axis's
  // list
  const generationRef = useRef(0);

  const loadMore = useCallback(
    async (current: LoadedState | undefined) => {
      const generation = generationRef.current;
      setIsLoading(true);
      setFailure(undefined);
      const result = await fetchPage(nextCursor(current));
      if (generation !== generationRef.current) return;
      setIsLoading(false);
      if (result.kind !== "ok") {
        setFailure(result);
        return;
      }
      setLoaded(appendPage(current, result.value.events));
    },
    [fetchPage],
  );

  useEffect(() => {
    // When fetchPage (= the consumed axis) changes, advance the
    // generation and reload
    generationRef.current += 1;
    setLoaded(undefined);
    setFailure(undefined);
    void loadMore(undefined);
  }, [loadMore]);

  if (loaded === undefined) {
    // Replacement form (ruling B-a): rendered in place of the body until the first page arrives
    return failure !== undefined ? (
      <FailureNotice failure={failure} onRetry={() => void loadMore(undefined)} />
    ) : (
      <LoadingRow label="Loading events" />
    );
  }
  if (loaded.events.length === 0) {
    return (
      <EmptyNotice
        title={emptyTitle}
        description="No events are visible to your role, as reported by the server."
        // The audit's box has no heading (directly under the page h1), so h2 (DP3 ruling E-(c))
        headingLevel={2}
        testId={`${testId}-empty`}
      />
    );
  }
  return (
    <LoadedEventsView
      loaded={loaded}
      failure={failure}
      isLoading={isLoading}
      onLoadMore={() => void loadMore(loaded)}
      testId={testId}
    />
  );
}
