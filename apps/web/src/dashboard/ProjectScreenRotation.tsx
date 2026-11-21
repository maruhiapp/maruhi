"use client";

import { Code } from "@astryxdesign/core/Code";
import { VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import type { ReactNode } from "react";

import { ServerTime } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { EmptyNotice, FailureNotice, LoadingRow } from "./resource-states.tsx";
import { Callout, SectionBlock } from "./sections.tsx";
import type { RotationFlag, RotationFlagList } from "./types.ts";
import { useApiResource } from "./use-api-resource.ts";

interface FlagRow extends Record<string, unknown> {
  id: string;
  environmentId: string;
  variableId: string;
  basis: string;
  trigger: string;
  recommendedAtMs: number;
}

const USER_TRIGGER_LABELS: ReadonlyMap<string, string> = new Map([
  ["change_role", "member role/scope changed"],
  ["revoke_device", "device revoked"],
]);

function userTriggerLabel(trigger: RotationFlag["trigger"]): string {
  return USER_TRIGGER_LABELS.get(trigger) ?? "member removed";
}

function flagTrigger(flag: RotationFlag): string {
  const subject =
    flag.targetUserId !== undefined
      ? `${userTriggerLabel(flag.trigger)}: ${flag.targetUserId}`
      : flag.targetServerKeyFingerprintHex !== undefined
        ? `server revoked: ${flag.targetServerKeyFingerprintHex}`
        : "";
  return subject === ""
    ? ""
    : `${subject} (chain seq ${flag.triggerChainSeq})${reopenedSuffix(flag)}`;
}

function reopenedSuffix(flag: RotationFlag): string {
  return flag.reopenedByVersion === undefined
    ? ""
    : `; re-opened by the rollback in v${flag.reopenedByVersion}`;
}

function toFlagRow(flag: RotationFlag): FlagRow {
  return {
    id: `${flag.environmentId}:${flag.variableId}`,
    environmentId: flag.environmentId,
    variableId: flag.variableId,
    basis: flag.basis,
    trigger: flagTrigger(flag),
    recommendedAtMs: flag.recommendedAtMs,
  };
}

const FLAG_COLUMNS: TableColumn<FlagRow>[] = [
  { key: "environmentId", header: "Environment", width: proportional(1) },
  { key: "variableId", header: "Variable", width: proportional(1) },
  {
    key: "basis",
    header: "Basis",
    width: pixel(110),
    renderCell: (row: FlagRow) => (
      <Token
        label={row.basis === "read" ? "read" : "readable"}
        size="sm"
        color={row.basis === "read" ? "red" : "orange"}
      />
    ),
  },
  {
    key: "trigger",
    header: "Trigger",
    width: proportional(2),
    renderCell: (row: FlagRow) => (
      <Text size="sm" wordBreak="break-all">
        {row.trigger}
      </Text>
    ),
  },
  {
    key: "recommendedAtMs",
    header: "Recommended at",
    width: pixel(220),
    renderCell: (row: FlagRow) => <ServerTime ms={row.recommendedAtMs} />,
  },
];

function RotationFlagsView({ flags }: { flags: ReadonlyArray<RotationFlag> }): ReactNode {
  if (flags.length === 0) {
    return (
      <EmptyNotice
        title="No rotation flags"
        description="No rotation flags are currently effective, as reported by the server."
        headingLevel={2}
        testId="rotation-empty"
      />
    );
  }
  return (
    <Table
      data={flags.map(toFlagRow)}
      columns={FLAG_COLUMNS}
      idKey="id"
      density="balanced"
      hasHover
      dividers="rows"
      data-testid="rotation-table"
    />
  );
}

export function RotationTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<RotationFlagList>(apiPaths.rotationFlags(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading rotation flags" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <VStack gap={4}>
      <SectionBlock>
        <RotationFlagsView flags={state.value.flags} />
      </SectionBlock>
      {}
      <Callout title="Rotating and dismissing" headingLevel={2} testId="rotation-note">
        A flag means the upstream credential should be rotated. Rotate the value, then dismiss the
        flag from the CLI: <Code>maruhi rotation dismiss</Code> (admin). Dismissing is not available
        in the dashboard.
      </Callout>
    </VStack>
  );
}
