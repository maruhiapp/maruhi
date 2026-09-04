"use client";

// S6 監査ビューアの共通リスト(裁定 BQ — docs/notes/session-43.md)。
// project 軸・invite 軸・本人軸の 3 消費点で同一部品を使う。
//
// - 見出しは役割適応の規定文言「Events visible to your role」(AUDIT_SPEC §7 —
//   不可視クラスの存在・件数を示唆しない)
// - `seq` 列は「応答に seq が載っているか」でのみ出し分ける(役割の事前判定を
//   クライアントに複製しない — 判定点はサーバー認可だけに保つ)
// - ページングは `before` カーソル(row_id)の Load more のみ。件数は表示しない
// - 全フィールドは記録どおりのサーバー申告値。表示名の解決(検証済み
//   ステートメント経由)は行わない — 検証を持たない Web での名前解決は
//   ステートメント検証なしの名前信用になる(AUTH_SPEC §12-2)ため識別子のみ表示
//
// DP3(裁定 C / D — docs/notes/web-design-pass.md §5): 可読性は「1 行に畳んだ
// 文字列」を「ラベル付きの断片」に分解して上げる(actor = 主体 + 鍵 FP + トークン
// id の 2〜3 行、details = ラベル : 値の対)。文言・項目・順序は変えない(§4 の
// 表示規律 — 「検証済み」を名乗らない・FP は参照値・件数を出さない)。狭い幅
// (AppShell の md 以下)では同じ行データを Table でなく List(1 イベント = 1 項目)
// で描く — HP5(モバイルで監査を読む利害関係者)のための表示形の切替であり、
// 列の意味は同じ。
import { Button } from "@astryxdesign/core/Button";
import { Collapsible } from "@astryxdesign/core/Collapsible";
import { useMediaQuery } from "@astryxdesign/core/hooks";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
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
  LoadingRow,
  NARROW_VIEWPORT_QUERY,
} from "./shared.tsx";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

/** 1 ページの取得。`before` は前ページ末尾行の row_id(AUDIT_SPEC §7)。 */
export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

interface AuditRow extends Record<string, unknown> {
  id: string;
  event: AuditEvent;
}

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

/**
 * 集約形 var.read(AUDIT_SPEC §3.3)の件数要約。変数の列挙は payload が持ち、
 * ここでは要約だけを出す(列挙は PayloadCell の展開)。
 */
function ReadSummary({ event }: { event: AuditEvent }): ReactNode {
  const listed = aggregatedReadVariables(event);
  if (listed === null) return null;
  return (
    <Text type="supporting" size="sm">
      {readSummaryLabel(listed.length)}
    </Text>
  );
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

function ActorCell({ event }: { event: AuditEvent }): ReactNode {
  return (
    <VStack gap={0.5}>
      <HexText>{actorHead(event)}</HexText>
      <Fragments items={actorFragments(event)} />
    </VStack>
  );
}

function PayloadCell({ event }: { event: AuditEvent }): ReactNode {
  if (event.payload === undefined) return null;
  const listed = aggregatedReadVariables(event);
  if (listed === null) {
    return <RecordedPayload payload={event.payload} />;
  }
  // 集約形 var.read: 変数の列挙は折り畳みで展開する(数十〜数百件になりうる —
  // 既定は閉じた状態で要約〔detailFragments〕だけを見せる)。列挙以外の payload
  // (authMethod 等)は従来どおり記録どおりの JSON で出す
  const rest = payloadWithoutVariables(event.payload);
  return (
    <VStack gap={0.5}>
      {rest === null ? null : <RecordedPayload payload={rest} />}
      <Collapsible
        trigger={<Text size="sm">Show variables</Text>}
        defaultIsOpen={false}
        value={`reads-${event.id}`}
      >
        <VStack gap={0.5}>
          {/* 列挙は variableId 昇順・重複なし(AUDIT_SPEC §3.3)— キーに使える */}
          {listed.map((variable) => (
            <HexText size="2xs" key={variable.variableId}>
              {listedReadVariableLabel(variable)}
            </HexText>
          ))}
        </VStack>
      </Collapsible>
    </VStack>
  );
}

/** 記録どおりの payload(サーバー申告の JSON をそのまま — 2 行で切り詰め、全文はツールチップ)。 */
function RecordedPayload({ payload }: { payload: Readonly<Record<string, unknown>> }): ReactNode {
  return (
    <Text type="code" size="2xs" wordBreak="break-all" maxLines={2} hasTruncateTooltip>
      {JSON.stringify(payload)}
    </Text>
  );
}

function DetailsCell({ event }: { event: AuditEvent }): ReactNode {
  return (
    <VStack gap={1}>
      <Fragments items={detailFragments(event)} />
      <ReadSummary event={event} />
      <PayloadCell event={event} />
    </VStack>
  );
}

const SEQ_COLUMN: TableColumn<AuditRow> = {
  key: "seq",
  header: "Seq",
  width: pixel(72),
  renderCell: (row: AuditRow) => (
    <Text type="code" size="sm" hasTabularNumbers>
      {row.event.seq ?? ""}
    </Text>
  ),
};

const EVENT_COLUMNS: TableColumn<AuditRow>[] = [
  {
    key: "event",
    header: "Event",
    width: pixel(200),
    renderCell: (row: AuditRow) => (
      <Text type="code" size="sm" weight="medium">
        {row.event.event}
      </Text>
    ),
  },
  {
    key: "when",
    header: "Server time (UTC)",
    width: pixel(210),
    renderCell: (row: AuditRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {formatServerTime(row.event.serverTs)}
      </Text>
    ),
  },
  {
    key: "actor",
    header: "Actor",
    width: proportional(1),
    renderCell: (row: AuditRow) => <ActorCell event={row.event} />,
  },
  {
    key: "details",
    header: "Details",
    width: proportional(1),
    renderCell: (row: AuditRow) => <DetailsCell event={row.event} />,
  },
];

/** 狭い幅の 1 イベント = 1 項目(列の意味は Table と同じ。seq は時刻の行に出す)。 */
function EventListItem({ event }: { event: AuditEvent }): ReactNode {
  return (
    <ListItem
      label={event.event}
      description={
        <VStack gap={1}>
          <HStack gap={2} wrap="wrap" align="center">
            {event.seq === undefined ? null : (
              <Text type="supporting" size="sm">
                seq <HexText>{String(event.seq)}</HexText>
              </Text>
            )}
            <Text type="supporting" size="sm" hasTabularNumbers>
              {formatServerTime(event.serverTs)}
            </Text>
          </HStack>
          <ActorCell event={event} />
          <DetailsCell event={event} />
        </VStack>
      }
    />
  );
}

function EventsView({
  events,
  isNarrow,
}: {
  events: ReadonlyArray<AuditEvent>;
  isNarrow: boolean;
}): ReactNode {
  if (isNarrow) {
    return (
      <List density="compact" hasDividers>
        {events.map((event) => (
          <EventListItem key={event.id} event={event} />
        ))}
      </List>
    );
  }
  // seq は admin 可視の project DO 応答にのみ載る(AUDIT_SPEC §7)。列の表示は
  // 応答適応: 1 行でも seq を運んでいれば列を出す
  const hasSeq = events.some((event) => event.seq !== undefined);
  const rows: AuditRow[] = events.map((event) => ({ id: event.id, event }));
  const columns = hasSeq ? [SEQ_COLUMN, ...EVENT_COLUMNS] : EVENT_COLUMNS;
  return <Table data={rows} columns={columns} idKey="id" density="compact" dividers="rows" />;
}

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
  return <Button label="Load more" variant="secondary" size="sm" onClick={onLoadMore} />;
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
  const isNarrow = useMediaQuery(NARROW_VIEWPORT_QUERY);
  return (
    <VStack gap={3} align="start" data-testid={testId}>
      <EventsView events={loaded.events} isNarrow={isNarrow} />
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
        testId={testId}
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
