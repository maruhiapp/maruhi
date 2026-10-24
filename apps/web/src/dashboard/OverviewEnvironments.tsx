"use client";

// The S5 overview tab's Environments section (ProjectScreenOverview.tsx):
// the environments and their variable names (a metadata-only pull).
import { Button } from "@astryxdesign/core/Button";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode, useId, useState } from "react";

import { HexText } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { EmptyNotice, FailureNotice, LoadingRow } from "./resource-states.tsx";
import { SectionBlock } from "./sections.tsx";
import type { EnvironmentList, EnvironmentMetadataPull, EnvironmentSummary } from "./types.ts";
import { useApiResource } from "./use-api-resource.ts";

/** One listed environment (the server lists live environments only; a deleted one is on the chain — AUTH_SPEC §12-7). */
interface EnvironmentRow extends Record<string, unknown> {
  id: string;
  name: string;
  epoch: number;
}

function toEnvironmentRow(env: EnvironmentSummary): EnvironmentRow {
  return {
    id: env.environmentId,
    name: env.statement.name,
    epoch: env.currentEpoch,
  };
}

interface VariableRow extends Record<string, unknown> {
  id: string;
  name: string;
  deleted: boolean;
}

const VARIABLE_COLUMNS: TableColumn<VariableRow>[] = [
  {
    key: "name",
    header: "Variable",
    width: proportional(1),
    renderCell: (row: VariableRow) => (
      <HStack gap={2} align="center" wrap="wrap">
        <Text type="code" size="sm" hasStrikethrough={row.deleted}>
          {row.name}
        </Text>
        {row.deleted ? <Token label="deleted" size="sm" color="gray" /> : null}
      </HStack>
    ),
  },
  {
    key: "id",
    header: "Variable ID",
    width: proportional(1),
    renderCell: (row: VariableRow) => <HexText>{row.id}</HexText>,
  },
];

/** The selected environment's variable names (rows = a Table — a collection is drawn as rows). Values are structurally absent from the response. */
function VariableNames({ pull }: { pull: EnvironmentMetadataPull }): ReactNode {
  const rows: VariableRow[] = [
    ...pull.variables.map((s) => ({ id: s.variableId, name: s.name, deleted: false })),
    ...pull.deletedVariables.map((s) => ({ id: s.variableId, name: s.name, deleted: true })),
  ];
  return (
    <VStack gap={2} data-testid="variable-list">
      <Text type="supporting">
        Variable names in <Text type="code">{pull.environmentId}</Text> (names travel as metadata
        statements; values never appear in this dashboard):
      </Text>
      {rows.length === 0 ? (
        <EmptyNotice
          title="No variables"
          description="No variable names in this environment, as reported by the server."
        />
      ) : (
        <Table
          data={rows}
          columns={VARIABLE_COLUMNS}
          idKey="id"
          density="compact"
          dividers="rows"
        />
      )}
    </VStack>
  );
}

function VariablesSection({
  projectId,
  environmentId,
}: {
  projectId: string;
  environmentId: string;
}): ReactNode {
  const { state, reload } = useApiResource<EnvironmentMetadataPull>(
    apiPaths.pullMetadata(projectId, environmentId),
  );
  if (state.kind === "loading") return <LoadingRow label="Loading variable names" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return <VariableNames pull={state.value} />;
}

/**
 * The environment table's columns. The Variables column's button is a
 * discloser that opens and closes the variable-names section below the
 * table (aria-expanded + aria-controls pointing at the section's id
 * while open — a closed section is not in the DOM).
 */
function buildEnvironmentColumns(
  selectedEnvironmentId: string | undefined,
  onToggle: (environmentId: string) => void,
  variablesRegionId: string,
): TableColumn<EnvironmentRow>[] {
  return [
    {
      key: "name",
      header: "Environment",
      width: proportional(1),
      renderCell: (row: EnvironmentRow) => <Text size="sm">{row.name}</Text>,
    },
    {
      key: "id",
      header: "Environment ID",
      width: proportional(1),
      renderCell: (row: EnvironmentRow) => <HexText>{row.id}</HexText>,
    },
    {
      key: "epoch",
      header: "Epoch",
      width: pixel(80),
      renderCell: (row: EnvironmentRow) => (
        <Text type="supporting" size="sm" hasTabularNumbers>
          {row.epoch}
        </Text>
      ),
    },
    {
      key: "names",
      header: "Variables",
      width: pixel(130),
      renderCell: (row: EnvironmentRow) => (
        <Button
          label={row.id === selectedEnvironmentId ? "Hide names" : "Variable names"}
          variant="ghost"
          size="sm"
          onClick={() => onToggle(row.id)}
          aria-expanded={row.id === selectedEnvironmentId}
          aria-controls={row.id === selectedEnvironmentId ? variablesRegionId : undefined}
        />
      ),
    },
  ];
}

function EnvironmentsBody({
  projectId,
  environments,
}: {
  projectId: string;
  environments: ReadonlyArray<EnvironmentSummary>;
}): ReactNode {
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState<string | undefined>(undefined);
  const variablesRegionId = useId();
  const onToggle = (environmentId: string) =>
    setSelectedEnvironmentId(environmentId === selectedEnvironmentId ? undefined : environmentId);
  const rows = environments.map(toEnvironmentRow);
  return (
    <SectionBlock
      title="Environments"
      description="Environments and their variable names (metadata only — values never appear here)."
    >
      {rows.length === 0 ? (
        <EmptyNotice
          title="No environments"
          description="Environments of this project appear here, as reported by the server."
          testId="env-empty"
        />
      ) : (
        <Table
          data={rows}
          columns={buildEnvironmentColumns(selectedEnvironmentId, onToggle, variablesRegionId)}
          idKey="id"
          density="balanced"
          hasHover
          dividers="rows"
          data-testid="env-table"
        />
      )}
      {selectedEnvironmentId !== undefined ? (
        <VStack id={variablesRegionId} data-testid="variables-region">
          <VariablesSection projectId={projectId} environmentId={selectedEnvironmentId} />
        </VStack>
      ) : null}
    </SectionBlock>
  );
}

export function EnvironmentsSection({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<EnvironmentList>(apiPaths.environments(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading environments" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return <EnvironmentsBody projectId={projectId} environments={state.value.environments} />;
}
