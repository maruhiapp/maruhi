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
// DP3 改訂 5(docs/notes/web-design-pass.md §5 裁定 P): 形は「1 列の行 + その場で展開」。
// 1 行 = Astryx `Collapsible`(CollapsibleGroup hasDividers — `CollapsibleDividedAccordion`
// ブロックの形)。トリガー = イベント名・主体・座標・サーバー時刻(+ seq)、展開部 = 全
// フィールド(MetadataList)+ 記録どおりの payload + var.read の列挙。左右分割(改訂 3 の
// `incident-console` 形)は広い画面で行と詳細の間が空きすぎ、1024px で形が変わるため撤回。
// 1 列は幅によらず同じ形で、行の直下に詳細が出る(HP5 — モバイルで監査を読む)。
// Table は使わない(行が読める幅を保つ)。文言・項目・順序は不変(§4 の表示規律 —
// 「検証済み」を名乗らない・FP は参照値・件数を出さない)。
import { Button } from "@astryxdesign/core/Button";
import { CodeBlock } from "@astryxdesign/core/CodeBlock";
import { Collapsible, CollapsibleGroup } from "@astryxdesign/core/Collapsible";
import { HStack, StackItem, VStack } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import type { ApiFailure, ApiResult } from "./api.ts";
import {
  aggregatedReadVariables,
  listedReadVariableLabel,
  payloadWithoutVariables,
  readSummaryLabel,
} from "./audit-read.ts";
import { EmptyNotice, FailureNotice, formatServerTime, HexText, LoadingRow } from "./shared.tsx";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

/** 1 ページの取得。`before` は前ページ末尾行の row_id(AUDIT_SPEC §7)。 */
export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

// 展開部の MetadataList のラベル列幅(`incident-console` のインスペクタと同じ 96)
const DETAIL_LABEL_WIDTH = 96;

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
// 行のトリガー(常に見える要約)
// ---------------------------------------------------------------------------

/**
 * 1 イベントの要約 = Collapsible のトリガー(ボタン)の中身。主体 → 座標 → 時刻 / seq の順。
 * seq は応答に載っているときだけ出す(応答適応 — AUDIT_SPEC §7)。ボタンの中なので
 * 対話要素を含めない(Text / HexText のみ)。
 */
function EventSummary({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  return (
    <HStack gap={4} align="start" width="100%">
      <StackItem size="fill">
        <VStack gap={1}>
          <Text weight="semibold">{event.event}</Text>
          <HStack gap={2} wrap="wrap" align="center">
            <Text type="supporting" size="sm">
              by <HexText>{actorHead(event)}</HexText>
            </Text>
            <Fragments items={detailFragments(event)} />
            {listed === null ? null : (
              <Text type="supporting" size="sm">
                {readSummaryLabel(listed.length)}
              </Text>
            )}
          </HStack>
        </VStack>
      </StackItem>
      <VStack gap={0} align="end">
        <Text type="supporting" size="sm" hasTabularNumbers>
          {formatServerTime(event.serverTs)}
        </Text>
        {event.seq === undefined ? null : (
          <Text type="supporting" size="sm" hasTabularNumbers>
            seq {event.seq}
          </Text>
        )}
      </VStack>
    </HStack>
  );
}

// ---------------------------------------------------------------------------
// 展開部(全フィールド — MetadataList + 記録どおりの payload)
// ---------------------------------------------------------------------------

function DetailItem({ label, value }: { label: string; value: string | undefined }): ReactNode {
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
      <Text weight="semibold">{readSummaryLabel(listed.length)}</Text>
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

/** 展開部: 記録どおりの全フィールド(ラベルは識別子の種類を示すだけ — §4-3)。 */
function EventDetails({ event }: { event: AuditEvent }): ReactNode {
  const payload = recordedPayload(event);
  return (
    <VStack gap={4}>
      <MetadataList columns="single" label={{ position: "start", width: DETAIL_LABEL_WIDTH }}>
        <DetailItem label="Seq" value={event.seq === undefined ? undefined : String(event.seq)} />
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
  return (
    <HStack>
      <Button label="Load more" variant="secondary" onClick={onLoadMore} />
    </HStack>
  );
}

/** CollapsibleGroup(single)の onChange 値 → 開いている行の id(閉じたら undefined)。 */
function openedId(value: string | string[]): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * 行の一覧(1 列)。開いている行は 1 つ(single)— 展開部を読む間は他の行が動かない。
 * 展開の状態はこの部品が持ち、ページを継ぎ足しても保たれる。
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

/** 初回ページが取れた後の本体: 行 + 追記形の失敗 + Load more。 */
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
      {/* 追記形(裁定 B-b): 既に描けた一覧の下に Load more の失敗を足す */}
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
