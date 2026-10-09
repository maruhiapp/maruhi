"use client";

// The S5 overview tab (the chain — members, head, servers — the
// four-eyes approvals, and the environments + variable names
// sections). See ProjectScreen.tsx for the screen's tab framework.
import { Button } from "@astryxdesign/core/Button";
import { Code } from "@astryxdesign/core/Code";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { type ReactNode, useId, useState } from "react";

import {
  reportedDeviceCount,
  type ReportedDevice,
  type ReportedMember,
  type ReportedPolicy,
  type ReportedProposal,
  type ReportedServer,
} from "./chain-view-reported.ts";
import { deriveReportedView } from "./chain-view.ts";
import { apiPaths } from "./endpoints.ts";
import { shortId } from "./ids.ts";
import {
  Callout,
  EmptyNotice,
  ExpiryCell,
  FailureNotice,
  HexText,
  LoadingRow,
  RoleToken,
  SectionBlock,
  SECTION_GAP,
} from "./shared.tsx";
import type {
  ChainSnapshot,
  EnvironmentList,
  EnvironmentMetadataPull,
  EnvironmentSummary,
} from "./types.ts";
import { useApiResource } from "./use-api-resource.ts";

// ---------------------------------------------------------------------------
// S5: overview tab — the chain (members, head, servers)
// ---------------------------------------------------------------------------

interface MemberRow extends Record<string, unknown> {
  id: string;
  role: string;
  /** Environment scope as reported (`all environments` or the listed ids — ES K4). */
  scope: string;
  sinceSeq: number;
  /** Device keys as reported (DK K5 — the chain-view fold). */
  devices: ReadonlyArray<ReportedDevice>;
  deviceCount: number;
  unresolvedRevocations: number;
}

/** The display wording of a scope (a fold of the server report — drawn the same way as the Granted servers Scope column). */
function describeMemberScope(member: ReportedMember): string {
  if (member.scopeKind === "all") return "all environments";
  return member.scopeEnvironmentIds.length === 0
    ? "no environments"
    : member.scopeEnvironmentIds.join(", ");
}

/**
 * The wording of a device cap (same as the CLI's `describeCap` —
 * apps/cli/src/device-key.ts: `owner/all`, `member/dev, staging`,
 * `owner/no environments`). The same fact is written the same way on
 * the web and the CLI (K5-3).
 */
function describeCap(device: ReportedDevice): string {
  if (device.scopeKind === "all") return `${device.roleCap}/all`;
  return `${device.roleCap}/${
    device.scopeEnvironmentIds.length === 0
      ? "no environments"
      : device.scopeEnvironmentIds.join(", ")
  }`;
}

/** Only a bounded device carries the cap (same as the CLI's `describeDevice`). */
function isBounded(device: ReportedDevice): boolean {
  return device.roleCap !== "owner" || device.scopeKind !== "all";
}

const FINGERPRINT_NOT_REPORTED = "fingerprint not reported";

/** The chip's wording: the shortened FP (or not reported) + `(cap)` only when bounded. */
function deviceChipLabel(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex;
  const head = fp === null ? FINGERPRINT_NOT_REPORTED : shortId(fp);
  return isBounded(device) ? `${head} (${describeCap(device)})` : head;
}

/** The chip's description (the full FP, cap, and adding seq — for hover / assistive tech). */
function deviceChipDescription(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex ?? FINGERPRINT_NOT_REPORTED;
  return `${fp} · cap ${describeCap(device)} · added at seq ${device.addedSeq}`;
}

/** The chip of one device (shortened FP + bound. The full FP and cap go in the description). */
function DeviceChip({ device }: { device: ReportedDevice }): ReactNode {
  return (
    <Token
      label={deviceChipLabel(device)}
      size="sm"
      color={device.keyFingerprintHex === null ? "gray" : "default"}
      description={deviceChipDescription(device)}
    />
  );
}

/**
 * The Devices column: the device count (exact, by arithmetic) + one
 * chip per device. An FP appears only once it could be bound from the
 * reported bytes (the `add_device` wire carries no FP — K5-1). When
 * unresolved entries exist, one sentence notes how many of the unbound
 * devices were revoked (which ones is unknown).
 */
function DeviceChips({ row }: { row: MemberRow }): ReactNode {
  return (
    <VStack gap={1}>
      <Text size="sm" hasTabularNumbers>
        {row.deviceCount}
      </Text>
      <HStack gap={1} wrap="wrap">
        {row.devices.map((device) => (
          <DeviceChip key={`${device.encPubHex}:${device.sigPubHex}`} device={device} />
        ))}
      </HStack>
      {row.unresolvedRevocations === 0 ? null : (
        <Text type="supporting" size="sm">
          {row.unresolvedRevocations === 1
            ? "1 of the devices without a reported fingerprint was revoked; which one is not reported."
            : `${row.unresolvedRevocations} of the devices without a reported fingerprint were revoked; which ones is not reported.`}
        </Text>
      )}
    </VStack>
  );
}

const MEMBER_COLUMNS: TableColumn<MemberRow>[] = [
  {
    key: "id",
    header: "User",
    width: proportional(1),
    renderCell: (row: MemberRow) => <HexText>{row.id}</HexText>,
  },
  {
    key: "role",
    header: "Role",
    width: pixel(110),
    renderCell: (row: MemberRow) => <RoleToken role={row.role} />,
  },
  {
    key: "scope",
    header: "Scope",
    width: proportional(1),
    renderCell: (row: MemberRow) => (
      <Text type="supporting" size="sm">
        {row.scope}
      </Text>
    ),
  },
  {
    key: "devices",
    header: "Devices",
    width: proportional(2),
    renderCell: (row: MemberRow) => <DeviceChips row={row} />,
  },
  {
    key: "sinceSeq",
    header: "Since (chain seq)",
    width: pixel(140),
    renderCell: (row: MemberRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {row.sinceSeq}
      </Text>
    ),
  },
];

function attestationSummary(snapshot: ChainSnapshot): string {
  // Only the report's shape is read (defense against a hostile server
  // — an unreadable row is dropped without being counted)
  const attestations = snapshot.attestations.filter(
    (a) =>
      typeof a === "object" &&
      a !== null &&
      typeof a.attesterUserId === "string" &&
      typeof a.chainHeadSeq === "number",
  );
  if (attestations.length === 0) return "None reported";
  const parts = attestations.map((a) => `${a.attesterUserId} at seq ${a.chainHeadSeq}`);
  return `${attestations.length} reported: ${parts.join(" · ")}`;
}

// The label column width of a MetadataList (same scale as
// `incident-console`'s inspector. The label-value correspondence stays
// readable even when a 64-hex value wraps)
const CHAIN_LABEL_WIDTH = 200;

/** The chain summary (the `detail-page` template's under-heading metadata shape — a MetadataList). */
function ChainSummary({ snapshot }: { snapshot: ChainSnapshot }): ReactNode {
  return (
    <MetadataList columns="single" label={{ position: "start", width: CHAIN_LABEL_WIDTH }}>
      <MetadataListItem label="Chain head">
        <Text hasTabularNumbers>seq {snapshot.headSeq}</Text>
      </MetadataListItem>
      <MetadataListItem label="Head digest">
        <HexText>{snapshot.headHashHex}</HexText>
      </MetadataListItem>
      <MetadataListItem label="Member head attestations">
        <Text>{attestationSummary(snapshot)}</Text>
      </MetadataListItem>
    </MetadataList>
  );
}

interface ServerRow extends Record<string, unknown> {
  id: string;
  scope: string;
}

const SERVER_COLUMNS: TableColumn<ServerRow>[] = [
  {
    key: "id",
    header: "Server key",
    width: proportional(1),
    renderCell: (row: ServerRow) => <HexText>{row.id}</HexText>,
  },
  {
    key: "scope",
    header: "Scope",
    width: proportional(1),
    renderCell: (row: ServerRow) => (
      <Text type="supporting" size="sm">
        {row.scope}
      </Text>
    ),
  },
];

/** Granted server keys (rows = a Table — a collection is drawn as rows). */
function ServersList({ servers }: { servers: ReadonlyArray<ReportedServer> }): ReactNode {
  if (servers.length === 0) return null;
  const rows: ServerRow[] = servers.map((server) => ({
    id: server.keyFingerprintHex,
    scope:
      server.scopeEnvironmentIds.length === 0
        ? "no environments in scope"
        : server.scopeEnvironmentIds.join(", "),
  }));
  return (
    <SectionBlock
      title="Granted servers"
      description="Server keys granted on this project and their environment scope, as reported by the server."
    >
      <Table data={rows} columns={SERVER_COLUMNS} idKey="id" density="compact" dividers="rows" />
    </SectionBlock>
  );
}

interface ProposalRow extends Record<string, unknown> {
  id: string;
  seq: number;
  proposer: string;
  operation: string;
  approvals: string;
  expiresAtMs: number;
}

const PROPOSAL_COLUMNS: TableColumn<ProposalRow>[] = [
  {
    key: "id",
    header: "Proposal",
    width: proportional(1),
    renderCell: (row: ProposalRow) => <HexText>{shortId(row.id)}</HexText>,
  },
  {
    key: "seq",
    header: "Seq",
    width: pixel(80),
    renderCell: (row: ProposalRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {row.seq}
      </Text>
    ),
  },
  {
    key: "proposer",
    header: "Proposer",
    width: proportional(1),
    renderCell: (row: ProposalRow) => <HexText>{row.proposer}</HexText>,
  },
  {
    key: "operation",
    header: "Operation",
    width: proportional(2),
    renderCell: (row: ProposalRow) => (
      <Text type="supporting" size="sm">
        {row.operation}
      </Text>
    ),
  },
  {
    key: "approvals",
    header: "Approvals",
    width: pixel(110),
    renderCell: (row: ProposalRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {row.approvals}
      </Text>
    ),
  },
  {
    key: "expiresAtMs",
    header: "Expires",
    width: pixel(180),
    renderCell: (row: ProposalRow) => <ExpiryCell expiresAtMs={row.expiresAtMs} />,
  },
];

function describePolicy(policy: ReportedPolicy | null): string {
  if (policy === null) return "Off — every operation is appended directly";
  return `On — ${policy.requiredApprovals} owner approvals for: ${[...policy.ops].toSorted().join(", ")} (plus policy changes and any owner addition or promotion)`;
}

/**
 * The four-eyes policy and pending proposals (K6-J — read-only.
 * Approving and withdrawing are the CLI's: ADR-0018). The vote count
 * is a recount, not the record (the chain-view fold).
 */
function ApprovalsView({
  policy,
  proposals,
}: {
  policy: ReportedPolicy | null;
  proposals: ReadonlyArray<ReportedProposal>;
}): ReactNode {
  const rows: ProposalRow[] = proposals.map((proposal) => ({
    id: proposal.proposalHashHex,
    seq: proposal.proposalSeq,
    proposer: proposal.proposerUserId,
    operation: proposal.innerSummary,
    approvals:
      policy === null
        ? `${proposal.votes} (policy off)`
        : `${proposal.votes} / ${policy.requiredApprovals}`,
    expiresAtMs: proposal.expiresAtMs,
  }));
  return (
    <SectionBlock
      title="Four-eyes approvals"
      description="Approval policy and pending proposals, as reported by the server. Approvals are recounted against the current owners; approve or withdraw with the CLI."
      testId="approvals-section"
    >
      <MetadataList columns="single" label={{ position: "start", width: CHAIN_LABEL_WIDTH }}>
        <MetadataListItem label="Policy">
          <Text>{describePolicy(policy)}</Text>
        </MetadataListItem>
      </MetadataList>
      {rows.length === 0 ? (
        <EmptyNotice
          title="No pending proposals"
          description="Nothing is waiting for approval, as reported by the server."
          headingLevel={3}
          testId="proposals-empty"
        />
      ) : (
        <Table
          data={rows}
          columns={PROPOSAL_COLUMNS}
          idKey="id"
          density="compact"
          dividers="rows"
          data-testid="proposal-table"
        />
      )}
      <Callout title="Approve from the CLI" headingLevel={3} testId="approvals-note">
        Owners approve with <Code>maruhi approval approve</Code> and proposers withdraw with{" "}
        <Code>maruhi approval withdraw</Code>. The approval that reaches the quorum applies the
        operation and runs the follow-up rotation or key distribution. Approving is not available in
        the dashboard.
      </Callout>
    </SectionBlock>
  );
}

/**
 * Entries dropped as unreadable are never silently absorbed (K5-17):
 * a dropped `add_device` leaves a device missing and a dropped
 * `revoke_device` leaves one in, so the display may be off in either
 * direction (never asserts a single direction — K5-18). Not rendered
 * at 0. Verification is the CLI's job
 */
function UnreadableEntriesNote({ count }: { count: number }): ReactNode {
  if (count === 0) return null;
  const rows = count === 1 ? "1 entry" : `${count} entries`;
  const verb = count === 1 ? "was" : "were";
  return (
    <Text type="supporting" size="sm" data-testid="unreadable-entries">
      {`${rows} in the reported chain could not be read and ${verb} left out; the view above may not match what those entries would have produced. Verify with maruhi project verify.`}
    </Text>
  );
}

function ChainView({ snapshot }: { snapshot: ChainSnapshot }): ReactNode {
  const view = deriveReportedView(snapshot.entries ?? [], snapshot.headHashHex);
  const memberRows: MemberRow[] = view.members.map((m) => ({
    id: m.userId,
    role: m.role,
    scope: describeMemberScope(m),
    sinceSeq: m.sinceSeq,
    devices: m.devices,
    deviceCount: reportedDeviceCount(m),
    unresolvedRevocations: m.unresolvedRevocations,
  }));
  return (
    <VStack gap={SECTION_GAP} data-testid="chain-section">
      <ChainSummary snapshot={snapshot} />
      <SectionBlock
        title="Members"
        description="Chain-derived members, roles, environment scopes and device keys, as reported by the server. A device's fingerprint appears once the reported entries bind it; an unbound fingerprint does not change the count. Verify with maruhi member list."
      >
        <Table
          data={memberRows}
          columns={MEMBER_COLUMNS}
          idKey="id"
          density="balanced"
          hasHover
          dividers="rows"
          data-testid="member-table"
        />
        <UnreadableEntriesNote count={view.unreadableEntries} />
      </SectionBlock>
      <ServersList servers={view.servers} />
      <ApprovalsView policy={view.policy} proposals={view.proposals} />
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// S5: overview tab — environments and variable names (metadata-only
// pull)
// ---------------------------------------------------------------------------

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

function EnvironmentsSection({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<EnvironmentList>(apiPaths.environments(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading environments" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return <EnvironmentsBody projectId={projectId} environments={state.value.environments} />;
}

/**
 * The overview tab. The chain fetch (§11) doubles as the
 * project-existence check and is the leading resource; the
 * environment list is read only once the chain arrives — on a uniform
 * 404 / 403 this avoids the same Banner stacking per section (found
 * when revisiting DP3 ruling B). The one-round-trip serialization is
 * accepted.
 */
export function OverviewTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<ChainSnapshot>(apiPaths.chain(projectId));
  // Replacement form (ruling B-a) — VariablesSection /
  // EnvironmentsSection / RotationTab below are the same
  if (state.kind === "loading") return <LoadingRow label="Loading chain" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <VStack gap={SECTION_GAP}>
      <ChainView snapshot={state.value} />
      <EnvironmentsSection projectId={projectId} />
    </VStack>
  );
}
