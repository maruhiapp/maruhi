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
import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";

import type { ApiFailure, ApiResult } from "./api.ts";
import { FailureNotice, formatServerTime, LoadingRow } from "./shared.tsx";
import type { AuditEvent, AuditEventsPage } from "./types.ts";

/** 1 ページの取得。`before` は前ページ末尾行の row_id(AUDIT_SPEC §7)。 */
export type AuditPageFetcher = (before: string | undefined) => Promise<ApiResult<AuditEventsPage>>;

interface AuditRow extends Record<string, unknown> {
  id: string;
  event: AuditEvent;
}

/** `prefix value` の表示片(値が欠落なら出さない)。 */
function labeled(prefix: string, value: string | number | undefined): string | undefined {
  return value === undefined ? undefined : `${prefix} ${value}`;
}

function isPresent(part: string | undefined): part is string {
  return part !== undefined;
}

/** actor の表示形(内部 user_id / server / system + 鍵 FP + トークン id)。 */
function actorLabel(event: AuditEvent): string {
  const actor = event.actor;
  const head = actor.type === "user" ? (actor.userId ?? "(unknown user)") : actor.type;
  return [head, labeled("key", actor.keyFingerprintHex), labeled("token", actor.apiTokenId)]
    .filter(isPresent)
    .join(" · ");
}

/** 行の座標情報(target / 環境 / 変数 / epoch / version / chainSeq)を 1 行に畳む。 */
function detailLabel(event: AuditEvent): string {
  return [
    labeled("target", event.targetUserId),
    labeled("target key", event.targetKeyFingerprintHex),
    labeled("env", event.environmentId),
    labeled("var", event.variableId),
    labeled("epoch", event.epoch),
    labeled("v", event.version),
    labeled("chain seq", event.chainSeq),
  ]
    .filter(isPresent)
    .join(" · ");
}

function PayloadCell({ event }: { event: AuditEvent }): ReactNode {
  if (event.payload === undefined) return null;
  return (
    <Text type="code" size="4xs" wordBreak="break-all" maxLines={2} hasTruncateTooltip>
      {JSON.stringify(event.payload)}
    </Text>
  );
}

const SEQ_COLUMN: TableColumn<AuditRow> = {
  key: "seq",
  header: "Seq",
  width: pixel(72),
  renderCell: (row: AuditRow) => (
    <Text type="code" size="sm">
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
      <Text type="code" size="sm">
        {row.event.event}
      </Text>
    ),
  },
  {
    key: "when",
    header: "Server time (UTC)",
    width: pixel(200),
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
    renderCell: (row: AuditRow) => (
      <Text size="sm" wordBreak="break-all">
        {actorLabel(row.event)}
      </Text>
    ),
  },
  {
    key: "details",
    header: "Details",
    width: proportional(1),
    renderCell: (row: AuditRow) => (
      <VStack gap={0.5}>
        <Text size="sm" wordBreak="break-all">
          {detailLabel(row.event)}
        </Text>
        <PayloadCell event={row.event} />
      </VStack>
    ),
  },
];

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
  // seq は admin 可視の project DO 応答にのみ載る(AUDIT_SPEC §7)。列の表示は
  // 応答適応: 1 行でも seq を運んでいれば列を出す
  const hasSeq = loaded.events.some((event) => event.seq !== undefined);
  const rows: AuditRow[] = loaded.events.map((event) => ({ id: event.id, event }));
  const columns = hasSeq ? [SEQ_COLUMN, ...EVENT_COLUMNS] : EVENT_COLUMNS;
  return (
    <VStack gap={3} data-testid={testId}>
      <Table data={rows} columns={columns} idKey="id" density="compact" dividers="rows" />
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
    return failure !== undefined ? (
      <FailureNotice failure={failure} onRetry={() => void loadMore(undefined)} />
    ) : (
      <LoadingRow label="Loading events" />
    );
  }
  if (loaded.events.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        description="No events are visible to your role, as reported by the server."
        headingLevel={3}
        isCompact
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
