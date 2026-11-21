"use client";

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
  aggregatedRecommendedVariables,
  flaggedVariableLabel,
  flagSummaryLabel,
  listedReadVariableLabel,
  payloadWithoutVariables,
  lineageLabel,
  readSummaryLabel,
} from "./audit-read.ts";
import { HexText, ServerTime } from "./display.tsx";
import { EmptyNotice, FailureNotice, LoadingRow } from "./resource-states.tsx";
import { formatServerTime } from "./server-time.ts";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

const DETAIL_LABEL_WIDTH = 96;

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

function actorHead(event: AuditEvent): string {
  const actor = event.actor;
  return actor.type === "user" ? (actor.userId ?? "(unknown user)") : actor.type;
}

function actorFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("key", event.actor.keyFingerprintHex),
    fragment("token", event.actor.apiTokenId),
  ].filter(isPresent);
}

function detailFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("target", event.targetUserId),
    fragment("target key", event.targetKeyFingerprintHex),
    fragment("env", event.environmentId),
    fragment("var", event.variableId),
    fragment(event.event === "rotation.recommended" ? "exposure epoch" : "epoch", event.epoch),
    fragment("v", event.version),
    fragment("value", lineageLabel(event) ?? undefined),
    fragment("chain seq", event.chainSeq),
  ].filter(isPresent);
}

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

function EventSummary({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  const flagged = aggregatedRecommendedVariables(event);
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
        {flagged === null ? null : (
          <Text type="supporting" size="sm">
            {flagSummaryLabel(flagged)}
          </Text>
        )}
      </HStack>
    </VStack>
  );
}

function DetailItem({ label, value }: { label: string; value: string | undefined }): ReactNode {
  if (value === undefined) return null;
  return (
    <MetadataListItem label={label}>
      <HexText>{value}</HexText>
    </MetadataListItem>
  );
}

const payloadStyles = stylex.create({
  pre: {
    whiteSpace: "pre-wrap",
  },
});

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
  return (
    <VStack gap={2}>
      <Text weight="semibold">{readSummaryLabel(listed)}</Text>
      <List density="compact" edge="outset">
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

function FlagsList({ event }: { event: AuditEvent }): ReactNode {
  const flagged = aggregatedRecommendedVariables(event);
  if (flagged === null) return null;
  return (
    <VStack gap={2}>
      <Text weight="semibold">{flagSummaryLabel(flagged)}</Text>
      <List density="compact" edge="outset">
        {flagged.map((variable) => (
          <ListItem key={variable.variableId} label={flaggedVariableLabel(variable)} />
        ))}
      </List>
    </VStack>
  );
}

function recordedPayload(event: AuditEvent): Readonly<Record<string, unknown>> | null {
  if (event.payload === undefined) return null;
  return aggregatedReadVariables(event) === null && aggregatedRecommendedVariables(event) === null
    ? event.payload
    : payloadWithoutVariables(event.payload);
}

function EventDetails({ event }: { event: AuditEvent }): ReactNode {
  const payload = recordedPayload(event);
  return (
    <VStack gap={4}>
      <MetadataList columns="single" label={{ position: "start", width: DETAIL_LABEL_WIDTH }}>
        <DetailItem label="Seq" value={event.seq === undefined ? undefined : String(event.seq)} />
        {}
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
      <FlagsList event={event} />
    </VStack>
  );
}

interface LoadedState {
  events: AuditEvent[];
  exhausted: boolean;
}

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

function openedId(value: string | string[]): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

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
      {}
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
  const [loadingGeneration, setLoadingGeneration] = useState<number | undefined>(undefined);
  const isLoading = loadingGeneration !== undefined;
  const generationRef = useRef(0);

  const loadMore = useCallback(
    async (current: LoadedState | undefined) => {
      const generation = generationRef.current;
      setLoadingGeneration(generation);
      setFailure(undefined);
      let result: Awaited<ReturnType<typeof fetchPage>>;
      try {
        result = await fetchPage(nextCursor(current));
      } finally {
        setLoadingGeneration((inFlight) => (inFlight === generation ? undefined : inFlight));
      }
      if (generation !== generationRef.current) return;
      if (result.kind !== "ok") {
        setFailure(result);
        return;
      }
      setLoaded(appendPage(current, result.value.events));
    },
    [fetchPage],
  );

  useEffect(() => {
    generationRef.current += 1;
    setLoaded(undefined);
    setFailure(undefined);
    void loadMore(undefined);
  }, [loadMore]);

  if (loaded === undefined) {
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
