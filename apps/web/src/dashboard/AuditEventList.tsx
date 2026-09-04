"use client";

// S6 監査ビューアの共通リスト(裁定 BQ — docs/notes/session-43.md)。
// project 軸・invite 軸・本人軸の 3 消費点で同一部品を使う。
//
// - 見出しは役割適応の規定文言「Events visible to your role」(AUDIT_SPEC §7 —
//   不可視クラスの存在・件数を示唆しない)
// - `seq` は「応答に seq が載っているか」でのみ出し分ける(役割の事前判定を
//   クライアントに複製しない — 判定点はサーバー認可だけに保つ)
// - ページングは `before` カーソル(row_id)の Load more のみ。件数は表示しない
// - 全フィールドは記録どおりのサーバー申告値。表示名の解決(検証済み
//   ステートメント経由)は行わない — 検証を持たない Web での名前解決は
//   ステートメント検証なしの名前信用になる(AUTH_SPEC §12-2)ため識別子のみ表示
//
// DP3 改訂 3(docs/notes/web-design-pass.md §5 裁定 C 改訂): 形は Astryx の
// `incident-console` テンプレート(「行の待ち行列 + 選択行のインスペクタ」)に従う。
// 行 = `List` の `ListItem`(label = イベント名、description = 主体と座標、
// endContent = サーバー時刻)、選択行の全フィールドは 1024px 超では `LayoutPanel`
// (`MetadataList`)、以下では全画面 `Dialog`(`detail-page` テンプレートのモバイル型)
// に出す。Table は使わない(行が読める幅を保つ — HP5)。文言・項目・順序は不変
// (§4 の表示規律 — 「検証済み」を名乗らない・FP は参照値・件数を出さない)。
import { Button } from "@astryxdesign/core/Button";
import { CodeBlock } from "@astryxdesign/core/CodeBlock";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { Divider } from "@astryxdesign/core/Divider";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { useMediaQuery } from "@astryxdesign/core/hooks";
import { HStack, Layout, LayoutContent, StackItem, VStack } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Heading, Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import type { ApiFailure, ApiResult } from "./api.ts";
import {
  aggregatedReadVariables,
  listedReadVariableLabel,
  payloadWithoutVariables,
  readSummaryLabel,
} from "./audit-read.ts";
import {
  EmptyNotice,
  FailureNotice,
  formatServerTime,
  HexText,
  INSPECTOR_VIEWPORT_QUERY,
  LoadingRow,
} from "./shared.tsx";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

/** 1 ページの取得。`before` は前ページ末尾行の row_id(AUDIT_SPEC §7)。 */
export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

// インスペクタの幅(`incident-console` の既定 380。構造幅は生 px でよい — Astryx layout docs)
const INSPECTOR_WIDTH = 380;
// MetadataList のラベル列幅(`incident-console` と同じ 96)
const INSPECTOR_LABEL_WIDTH = 96;

/** ラベル : 値 の断片(値が欠落なら出さない)。 */
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

/** actor の主体(内部 user_id / server / system)。プロバイダ情報は構造上載らない。 */
function actorHead(event: AuditEvent): string {
  const actor = event.actor;
  return actor.type === "user" ? (actor.userId ?? "(unknown user)") : actor.type;
}

/** actor の付随識別子(鍵 FP・トークン id)— 参照値であり照合材料ではない(§4-3)。 */
function actorFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("key", event.actor.keyFingerprintHex),
    fragment("token", event.actor.apiTokenId),
  ].filter(isPresent);
}

/** 行の座標情報(target / 環境 / 変数 / epoch / version / chainSeq)。 */
function detailFragments(event: AuditEvent): Fragment[] {
  return [
    fragment("target", event.targetUserId),
    fragment("target key", event.targetKeyFingerprintHex),
    fragment("env", event.environmentId),
    fragment("var", event.variableId),
    fragment("epoch", event.epoch),
    fragment("v", event.version),
    fragment("chain seq", event.chainSeq),
  ].filter(isPresent);
}

/** ラベル付き断片の並び(折り返し可)。 */
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
// 行(incident-console の IncidentRows の形)
// ---------------------------------------------------------------------------

/**
 * 1 イベント = 1 行。description は主体 + 座標の要約(全フィールドはインスペクタ)。
 * seq は応答に載っているときだけ先頭に出す(応答適応 — AUDIT_SPEC §7)。
 */
function EventRow({
  event,
  isSelected,
  onSelect,
}: {
  event: AuditEvent;
  isSelected: boolean;
  onSelect: () => void;
}): ReactNode {
  const listed = aggregatedReadVariables(event);
  return (
    <ListItem
      label={event.event}
      description={
        <HStack gap={2} wrap="wrap" align="center">
          {event.seq === undefined ? null : (
            <Text type="supporting" size="sm">
              seq <HexText>{String(event.seq)}</HexText>
            </Text>
          )}
          <HexText>{actorHead(event)}</HexText>
          <Fragments items={detailFragments(event)} />
          {listed === null ? null : (
            <Text type="supporting" size="sm">
              {readSummaryLabel(listed.length)}
            </Text>
          )}
        </HStack>
      }
      endContent={
        <Text type="supporting" size="sm" hasTabularNumbers>
          {formatServerTime(event.serverTs)}
        </Text>
      }
      onClick={onSelect}
      isSelected={isSelected}
    />
  );
}

// ---------------------------------------------------------------------------
// インスペクタ(incident-console の IncidentInspector の形 — MetadataList)
// ---------------------------------------------------------------------------

function InspectorItem({ label, value }: { label: string; value: string | undefined }): ReactNode {
  if (value === undefined) return null;
  return (
    <MetadataListItem label={label}>
      <HexText>{value}</HexText>
    </MetadataListItem>
  );
}

/** 記録どおりの payload(サーバー申告の JSON をそのまま)。 */
function RecordedPayload({ payload }: { payload: Readonly<Record<string, unknown>> }): ReactNode {
  return (
    <CodeBlock
      code={JSON.stringify(payload, null, 2)}
      language="json"
      title="Payload (as recorded)"
      size="sm"
      width="100%"
      isWrapped
      hasCopyButton={false}
    />
  );
}

function ReadsList({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  if (listed === null) return null;
  // 集約形 var.read(AUDIT_SPEC §3.3): 変数の列挙は payload が持つ。列挙は
  // variableId 昇順・重複なし — キーに使える
  return (
    <VStack gap={2}>
      <Heading level={4} accessibilityLevel={3}>
        {readSummaryLabel(listed.length)}
      </Heading>
      <List density="compact">
        {listed.map((variable) => (
          <ListItem key={variable.variableId} label={listedReadVariableLabel(variable)} />
        ))}
      </List>
    </VStack>
  );
}

/** payload のうち列挙(variables)以外。集約形でなければ payload そのもの。 */
function recordedPayload(event: AuditEvent): Readonly<Record<string, unknown>> | null {
  if (event.payload === undefined) return null;
  return aggregatedReadVariables(event) === null
    ? event.payload
    : payloadWithoutVariables(event.payload);
}

/** 選択行の全フィールド(記録どおり・ラベルは識別子の種類を示すだけ — §4-3)。 */
function EventInspector({ event }: { event: AuditEvent }): ReactNode {
  const payload = recordedPayload(event);
  return (
    <VStack gap={4}>
      <VStack gap={1}>
        <Text type="supporting" color="secondary" hasTabularNumbers>
          {formatServerTime(event.serverTs)}
        </Text>
        <Heading level={3} accessibilityLevel={2}>
          {event.event}
        </Heading>
      </VStack>
      <Divider />
      <MetadataList columns="single" label={{ position: "start", width: INSPECTOR_LABEL_WIDTH }}>
        <InspectorItem
          label="Seq"
          value={event.seq === undefined ? undefined : String(event.seq)}
        />
        <InspectorItem label="Actor" value={actorHead(event)} />
        {actorFragments(event).map((item) => (
          <InspectorItem key={item.label} label={item.label} value={item.value} />
        ))}
        {detailFragments(event).map((item) => (
          <InspectorItem key={item.label} label={item.label} value={item.value} />
        ))}
        <InspectorItem label="Row id" value={event.id} />
      </MetadataList>
      {payload === null ? null : <RecordedPayload payload={payload} />}
      <ReadsList event={event} />
    </VStack>
  );
}

/**
 * 1024px 超: 右のインスペクタ(`incident-console` の end パネルの形。タブパネルの中に
 * 置くため Layout の end スロットでなく HStack + 縦 Divider で並べる)。
 * 以下: 全画面 Dialog(`detail-page` テンプレートのモバイル型)。
 */
function InspectorSurface({
  event,
  hasInspectorPanel,
  onClose,
}: {
  event: AuditEvent | undefined;
  hasInspectorPanel: boolean;
  onClose: () => void;
}): ReactNode {
  if (hasInspectorPanel) {
    return (
      <VStack as="aside" width={INSPECTOR_WIDTH} aria-label="Event details">
        {event === undefined ? (
          <EmptyState
            title="No event selected"
            description="Select an event to see every recorded field."
            headingLevel={2}
            isCompact
          />
        ) : (
          <EventInspector event={event} />
        )}
      </VStack>
    );
  }
  return (
    <Dialog variant="fullscreen" isOpen={event !== undefined} onOpenChange={onClose}>
      <Layout
        header={<DialogHeader title="Event details" onOpenChange={onClose} />}
        content={
          <LayoutContent padding={4}>
            {event === undefined ? null : <EventInspector event={event} />}
          </LayoutContent>
        }
      />
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// ページング状態
// ---------------------------------------------------------------------------

interface LoadedState {
  events: AuditEvent[];
  /** 直近ページが空(または初回から空)= これ以上遡れない。 */
  exhausted: boolean;
}

/** 末尾行の row_id = 次ページの `before` カーソル。 */
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
  if (isLoading) return <LoadingRow label="Loading events" />;
  if (exhausted) return null;
  return <Button label="Load more" variant="secondary" onClick={onLoadMore} />;
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
  const hasInspectorPanel = useMediaQuery(INSPECTOR_VIEWPORT_QUERY);
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined);
  const selected = loaded.events.find((event) => event.id === selectedId);
  const rows = (
    <VStack gap={4} align="start" data-testid={testId}>
      <List density="balanced" hasDividers>
        {loaded.events.map((event) => (
          <EventRow
            key={event.id}
            event={event}
            isSelected={event.id === selectedId}
            onSelect={() => setSelectedId(event.id)}
          />
        ))}
      </List>
      {/* 追記形(裁定 B-b): 既に描けた一覧の下に Load more の失敗を足す */}
      {failure !== undefined ? <FailureNotice failure={failure} onRetry={onLoadMore} /> : null}
      <LoadMoreRow isLoading={isLoading} exhausted={loaded.exhausted} onLoadMore={onLoadMore} />
    </VStack>
  );
  const inspector = (
    <InspectorSurface
      event={selected}
      hasInspectorPanel={hasInspectorPanel}
      onClose={() => setSelectedId(undefined)}
    />
  );
  if (!hasInspectorPanel) {
    return (
      <>
        {rows}
        {inspector}
      </>
    );
  }
  return (
    <HStack gap={6} align="stretch">
      <StackItem size="fill">{rows}</StackItem>
      <Divider orientation="vertical" />
      {inspector}
    </HStack>
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
  // 消費軸(fetchPage)の世代。軸が変わったら旧 in-flight 応答を捨てる —
  // 後着の旧軸ページが新しい軸のリストへ混入しない(PR #107 Bugbot 指摘の修正)
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
    // fetchPage(= 消費軸)が変わったら世代を進めて読み直す
    generationRef.current += 1;
    setLoaded(undefined);
    setFailure(undefined);
    void loadMore(undefined);
  }, [loadMore]);

  if (loaded === undefined) {
    // 置換形(裁定 B-a): 初回ページが取れるまでは本体の代わりに描く
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
