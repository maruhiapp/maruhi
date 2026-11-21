"use client";

import { VStack } from "@astryxdesign/core/Layout";
import { pixel, Table, type TableColumn } from "@astryxdesign/core/Table";
import type { ReactNode } from "react";

import { FailureNotice, type FailureSubject, LoadingRow } from "./resource-states.tsx";
import { RevocationOutcome, RevokeButton } from "./revocation.tsx";
import { SectionBlock } from "./sections.tsx";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

export interface RevocableListState<T> {
  readonly state: ResourceState<T>;
  readonly reload: () => void;
  readonly revocation: RevocationState;
  readonly arm: (id: string | undefined) => void;
  readonly confirm: (id: string, successMessage: string) => void;
}

export function useRevocableList<T>(
  listPath: string,
  revokePath: (id: string) => string,
): RevocableListState<T> {
  const { state, reload } = useApiResource<T>(listPath);
  const { revocation, arm, confirm } = useRevocation(revokePath, reload);
  return { state, reload, revocation, arm, confirm };
}

type ListRow = Record<string, unknown> & { id: string };

interface ListTable<T, Row extends ListRow> {
  toRows: (value: T) => Row[];
  columns: ReadonlyArray<TableColumn<Row>>;
  tableTestId: string;
  empty: ReactNode;
  isRevocable?: (row: Row) => boolean;
  revokeName: (row: Row) => string;
}

function actionsColumn<Row extends ListRow>(
  table: Pick<ListTable<unknown, Row>, "isRevocable" | "revokeName">,
  isLocked: boolean,
  onArm: (id: string | undefined) => void,
): TableColumn<Row> {
  return {
    key: "actions",
    header: "Actions",
    width: pixel(200),
    renderCell: (row: Row) =>
      table.isRevocable === undefined || table.isRevocable(row) ? (
        <RevokeButton
          onArm={() => onArm(row.id)}
          isLocked={isLocked}
          accessibleName={table.revokeName(row)}
        />
      ) : null,
  };
}

function ListingTable<T, Row extends ListRow>({
  rows,
  table,
  isLocked,
  onArm,
}: {
  rows: Row[];
  table: ListTable<T, Row>;
  isLocked: boolean;
  onArm: (id: string | undefined) => void;
}): ReactNode {
  if (rows.length === 0) return table.empty;
  return (
    <Table
      data={rows}
      columns={[...table.columns, actionsColumn(table, isLocked, onArm)]}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid={table.tableTestId}
    />
  );
}

function ListingResource<T, Row extends ListRow>({
  list,
  loadingLabel,
  listSubject,
  table,
}: {
  list: RevocableListState<T>;
  loadingLabel: string;
  listSubject: FailureSubject;
  table: ListTable<T, Row>;
}): ReactNode {
  const { state, reload, revocation, arm } = list;
  if (state.kind === "loading") return <LoadingRow label={loadingLabel} />;
  if (state.kind === "failed") {
    return <FailureNotice failure={state.failure} onRetry={reload} subject={listSubject} />;
  }
  return (
    <ListingTable
      rows={table.toRows(state.value)}
      table={table}
      isLocked={revocation.pendingId !== undefined || state.refreshing}
      onArm={arm}
    />
  );
}

interface RevocationWording {
  title: string;
  description: string;
  successMessage: string;
  subject: FailureSubject;
}

export function RevocableList<T, Row extends ListRow>({
  list,
  testId,
  title,
  description,
  loadingLabel,
  listSubject,
  table,
  revocationWording,
  notes,
}: {
  list: RevocableListState<T>;
  testId: string;
  title?: string | undefined;
  description?: string | undefined;
  loadingLabel: string;
  listSubject: FailureSubject;
  table: ListTable<T, Row>;
  revocationWording: RevocationWording;
  notes: ReactNode;
}): ReactNode {
  return (
    <VStack gap={4} data-testid={testId}>
      <SectionBlock title={title} description={description}>
        <ListingResource
          list={list}
          loadingLabel={loadingLabel}
          listSubject={listSubject}
          table={table}
        />
      </SectionBlock>
      {}
      <RevocationOutcome
        revocation={list.revocation}
        title={revocationWording.title}
        description={revocationWording.description}
        successMessage={revocationWording.successMessage}
        subject={revocationWording.subject}
        arm={list.arm}
        confirm={list.confirm}
      />
      {notes}
    </VStack>
  );
}
