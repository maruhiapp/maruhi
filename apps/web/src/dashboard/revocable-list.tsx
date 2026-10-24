"use client";

// The skeleton of a revocable list (S8 invites, S9 tokens): the
// listing's three states, its table with a Revoke on each revocable row,
// and below it the revocation outcome and the screen's static guidance.
// A screen gives the row conversion, the data columns, which rows can be
// revoked, and the wording; the skeleton appends the Actions column and
// disables every row's Revoke while a revocation runs or the list is
// re-fetched. The listing and the revocation state come from
// useRevocableList, which the screen calls and passes in as `list`, so
// that the screen's wording can draw on them (S9's dialog names the
// armed token). The revocation state stays outside the list resource
// (the header comment of use-revocation.ts).
import { VStack } from "@astryxdesign/core/Layout";
import { pixel, Table, type TableColumn } from "@astryxdesign/core/Table";
import type { ReactNode } from "react";

import { FailureNotice, type FailureSubject, LoadingRow } from "./resource-states.tsx";
import { RevocationOutcome, RevokeButton } from "./revocation.tsx";
import { SectionBlock } from "./sections.tsx";
import { type ResourceState, useApiResource } from "./use-api-resource.ts";
import { type RevocationState, useRevocation } from "./use-revocation.ts";

/** The listing and the revocation state of its rows. */
export interface RevocableListState<T> {
  readonly state: ResourceState<T>;
  readonly reload: () => void;
  readonly revocation: RevocationState;
  readonly arm: (id: string | undefined) => void;
  readonly confirm: (id: string, successMessage: string) => void;
}

/** The listing at listPath and the revocation of its rows (revokePath is an id → DELETE path builder). */
export function useRevocableList<T>(
  listPath: string,
  revokePath: (id: string) => string,
): RevocableListState<T> {
  const { state, reload } = useApiResource<T>(listPath);
  const { revocation, arm, confirm } = useRevocation(revokePath, reload);
  return { state, reload, revocation, arm, confirm };
}

/** A table row of the listing: its id is what a revocation deletes. */
type ListRow = Record<string, unknown> & { id: string };

/** What the screen gives for its table and its Revoke. */
interface ListTable<T, Row extends ListRow> {
  toRows: (value: T) => Row[];
  /** The data columns (the skeleton appends the Actions column). */
  columns: ReadonlyArray<TableColumn<Row>>;
  tableTestId: string;
  /** The empty listing (an EmptyNotice). */
  empty: ReactNode;
  /** Which rows have a Revoke (every row when omitted). */
  isRevocable?: (row: Row) => boolean;
  /** The spoken name of a row's Revoke, which identifies the row. */
  revokeName: (row: Row) => string;
}

/** The Actions column: a Revoke on each revocable row. */
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
  // Replacement form (ruling B-a). During the post-revocation re-fetch
  // (refreshing) the previous list stays, and each row's Revoke is
  // disabled the same as when one is in flight (prevents a double
  // revocation on a pre-refetch row)
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

/** A revocation's wording: the confirm dialog, the success announcement and the failure noun. */
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
  /**
   * The list's heading and its description (both omitted when the page
   * h1 doubles as the heading: SectionBlock then draws only the box).
   */
  title?: string | undefined;
  description?: string | undefined;
  loadingLabel: string;
  /** The noun of a failed listing's 404 wording. */
  listSubject: FailureSubject;
  table: ListTable<T, Row>;
  revocationWording: RevocationWording;
  /** The static guidance below the list. */
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
      {/* Confirmation is modal (AlertDialogAsyncAction template) + an appended-form failure (ruling B-b) */}
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
