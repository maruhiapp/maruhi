"use client";

// S5 project overview / S6 audit (project and invites axes) / S7
// rotation-needed flags (design document §3). Read-only; every
// display is server-reported (§4).
//
// - S5: the chain fetch (§11) is folded for display (chain-view.ts —
//   not verification).
//   The environment listing (§12-4) + a pull of the selected
//   environment's metadata only (§12-7 — values and DEKs structurally
//   never appear in a response; no var.read is recorded either)
// - S6: AuditEventList (ruling BQ). The invites axis is limited to
//   chain role admin, and a 403 is displayed as-is with the role
//   wording (no role check that hides the tab in advance)
// - S7: no dismiss here (ADR-0018 amendment 2's boundary principle —
//   erasing a warning). Only static guidance pointing at the CLI
//   `maruhi rotation dismiss`
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { Text } from "@astryxdesign/core/Text";
import { ToggleButton, ToggleButtonGroup } from "@astryxdesign/core/ToggleButton";
import { Token } from "@astryxdesign/core/Token";
import { useRouteParams } from "@funstack/router";
import * as stylex from "@stylexjs/stylex";
import { type ReactNode, useId, useMemo, useState } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import {
  deriveReportedView,
  type ReportedDevice,
  reportedDeviceCount,
  type ReportedMember,
  type ReportedPolicy,
  type ReportedProposal,
  type ReportedServer,
} from "./chain-view.ts";
import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { isProjectId, shortId } from "./ids.ts";
import { InvitesTab } from "./InvitesTab.tsx";
import { projectRoute, spaPaths } from "./routes.ts";
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
  ServerTime,
} from "./shared.tsx";
import type {
  AuditEventsPage,
  ChainSnapshot,
  EnvironmentList,
  EnvironmentMetadataPull,
  EnvironmentSummary,
  RotationFlag,
  RotationFlagList,
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
  return `${fp} · cap ${describeCap(device)} · since seq ${device.addedSeq}`;
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
        Owners approve with <Text type="code">maruhi approval approve</Text> and proposers withdraw
        with <Text type="code">maruhi approval withdraw</Text>. The approval that reaches the quorum
        applies the operation and runs the follow-up rotation or key distribution. Approving is not
        available in the dashboard.
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

interface EnvironmentRow extends Record<string, unknown> {
  id: string;
  name: string;
  status: string;
  epoch: number;
}

function toEnvironmentRow(env: EnvironmentSummary): EnvironmentRow {
  return {
    id: env.environmentId,
    name: env.statement.name,
    status: env.statement.status,
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
      renderCell: (row: EnvironmentRow) => (
        <HStack gap={2} align="center">
          <Text size="sm" hasStrikethrough={row.status === "deleted"}>
            {row.name}
          </Text>
          {row.status === "deleted" ? <Token label="deleted" size="sm" color="gray" /> : null}
        </HStack>
      ),
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
      renderCell: (row: EnvironmentRow) =>
        row.status === "deleted" ? null : (
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
function OverviewTab({ projectId }: { projectId: string }): ReactNode {
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

// ---------------------------------------------------------------------------
// S6: audit tab (the project / invites axes. The self axis is
// /dashboard/account)
// ---------------------------------------------------------------------------

function AuditTab({ projectId }: { projectId: string }): ReactNode {
  const [axis, setAxis] = useState("project");
  const fetchProjectEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(apiPaths.auditEvents(projectId, before)),
    [projectId],
  );
  const fetchInviteEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(apiPaths.auditInvites(projectId, before)),
    [projectId],
  );
  return (
    <VStack gap={4}>
      <HStack gap={3} justify="between" align="center" wrap="wrap">
        {/* The prescribed wording (AUDIT_SPEC §7 / design document §4-4): never hints at the existence or count of an invisible class */}
        <Text type="supporting" data-testid="audit-caption">
          Events visible to your role, as reported by the server.
        </Text>
        {/* Axis switching is a ToggleButtonGroup(single). SegmentedControl's unselected-label
            contrast is 4.26:1 (12px) in dark, short of AA (a11y audit — an upstream candidate) */}
        <ToggleButtonGroup
          label="Audit source"
          type="single"
          value={axis}
          onChange={(value: string | null) => {
            if (value !== null) setAxis(value);
          }}
          size="sm"
        >
          <ToggleButton value="project" label="Project events" />
          <ToggleButton value="invites" label="Invites" />
        </ToggleButtonGroup>
      </HStack>
      <SectionBlock>
        {axis === "project" ? (
          <AuditEventList
            fetchPage={fetchProjectEvents}
            emptyTitle="No events"
            testId="audit-list-project"
          />
        ) : (
          <AuditEventList
            fetchPage={fetchInviteEvents}
            emptyTitle="No invite events"
            testId="audit-list-invites"
          />
        )}
      </SectionBlock>
      <Text type="supporting">
        Completeness checks (gap detection, mirror reconciliation) are the CLI's job:{" "}
        <Text type="code">maruhi audit verify</Text> /{" "}
        <Text type="code">maruhi audit reconcile</Text>.
      </Text>
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// S7: rotation-needed flags
// ---------------------------------------------------------------------------

interface FlagRow extends Record<string, unknown> {
  id: string;
  environmentId: string;
  variableId: string;
  basis: string;
  trigger: string;
  recommendedAtMs: number;
}

// The wording of person-targeted triggers (remove_member takes the
// default removal wording).
// As a Map it never hits a prototype-chain name (a hostile trigger
// string)
const USER_TRIGGER_LABELS: ReadonlyMap<string, string> = new Map([
  ["change_role", "member role/scope changed"],
  ["revoke_device", "device revoked"],
]);

function userTriggerLabel(trigger: RotationFlag["trigger"]): string {
  return USER_TRIGGER_LABELS.get(trigger) ?? "member removed";
}

/**
 * The display form of a trigger (a removal / a demoted or narrowed
 * principal / the owner of a revoked device / a revoked server key).
 * When the target is a person it uses the `trigger` (AUDIT_SPEC §3.3
 * — 2026-09-14 ES; `revoke_device` is 2026-09-19 DK) wording.
 * The tail carries the triggering chain seq (`triggerChainSeq` —
 * carried by the response): a `revoke_device` row carries no device
 * FP, so the seq lets one trace the mirrored row on the Audit tab
 * (`chain.device_revoked` — which has the FP) (K5-5 re-exploration).
 */
function flagTrigger(flag: RotationFlag): string {
  const subject =
    flag.targetUserId !== undefined
      ? `${userTriggerLabel(flag.trigger)}: ${flag.targetUserId}`
      : flag.targetServerKeyFingerprintHex !== undefined
        ? `server revoked: ${flag.targetServerKeyFingerprintHex}`
        : "";
  return subject === "" ? "" : `${subject} (chain seq ${flag.triggerChainSeq})`;
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
        // A box without a heading (inside a tab, directly under the
        // page h1), so h2 — sitting level with the following Callout
        // (h2)
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

function RotationTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<RotationFlagList>(apiPaths.rotationFlags(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading rotation flags" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return (
    <VStack gap={4}>
      <SectionBlock>
        <RotationFlagsView flags={state.value.flags} />
      </SectionBlock>
      {/* Dismissing is not on the web (ADR-0018 amendment 2 — erasing a warning is a governance operation) */}
      <Callout title="Rotating and dismissing" headingLevel={2} testId="rotation-note">
        A flag means the upstream credential should be rotated. Rotate the value, then dismiss the
        flag from the CLI: <Text type="code">maruhi rotation dismiss</Text> (admin). Dismissing is
        not available in the dashboard.
      </Callout>
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// The screen body
// ---------------------------------------------------------------------------

const PROJECT_TABS = ["overview", "audit", "rotation", "invites"] as const;
type ProjectTab = (typeof PROJECT_TABS)[number];

const PROJECT_TAB_PANELS: Record<ProjectTab, string> = {
  overview: "project-panel-overview",
  audit: "project-panel-audit",
  rotation: "project-panel-rotation",
  invites: "project-panel-invites",
};

// A tabpanel takes its name from the corresponding tab (APG). Astryx
// does not auto-assign ids to Tabs, so an explicit id is placed on
// the tab side and referenced via aria-labelledby
const PROJECT_TAB_IDS: Record<ProjectTab, string> = {
  overview: "project-tab-overview",
  audit: "project-tab-audit",
  rotation: "project-tab-rotation",
  invites: "project-tab-invites",
};

// The `hidden` attribute alone does not hide: VStack's own
// `display:flex` (in `@layer astryx-base`) beats the Astryx reset's
// `:where([hidden]){display:none}` (in `@layer reset`). Between StyleX
// rules the later one wins, so it works (ADR-0013 ②)
const panelStyles = stylex.create({
  hidden: { display: "none" },
});

function isProjectTab(value: string): value is ProjectTab {
  return (PROJECT_TABS as ReadonlyArray<string>).includes(value);
}

function ProjectTabBody({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  if (tab === "audit") return <AuditTab projectId={projectId} />;
  if (tab === "rotation") return <RotationTab projectId={projectId} />;
  // S8 (ruling CP): the project axis's management surface is a tab.
  // Keyed by projectId so a revocation state cannot carry over to
  // another project
  if (tab === "invites") return <InvitesTab key={projectId} projectId={projectId} />;
  return <OverviewTab projectId={projectId} />;
}

/** The TabList for the header slot (it switches panels within one screen, so WAI-ARIA tabs, not a nav landmark). */
function ProjectTabList({
  tab,
  onChange,
}: {
  tab: ProjectTab;
  onChange: (tab: ProjectTab) => void;
}): ReactNode {
  return (
    <TabList
      value={tab}
      onChange={(value) => {
        if (isProjectTab(value)) onChange(value);
      }}
      size="md"
      role="tablist"
      aria-label="Project"
      hasDivider
    >
      <Tab
        id={PROJECT_TAB_IDS.overview}
        value="overview"
        label="Overview"
        panelId={PROJECT_TAB_PANELS.overview}
      />
      <Tab
        id={PROJECT_TAB_IDS.audit}
        value="audit"
        label="Audit"
        panelId={PROJECT_TAB_PANELS.audit}
      />
      <Tab
        id={PROJECT_TAB_IDS.rotation}
        value="rotation"
        label="Rotation flags"
        panelId={PROJECT_TAB_PANELS.rotation}
      />
      <Tab
        id={PROJECT_TAB_IDS.invites}
        value="invites"
        label="Invites"
        panelId={PROJECT_TAB_PANELS.invites}
      />
    </TabList>
  );
}

function ProjectTabPanels({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  return PROJECT_TABS.map((id) => (
    <VStack
      key={id}
      id={PROJECT_TAB_PANELS[id]}
      role="tabpanel"
      aria-labelledby={PROJECT_TAB_IDS[id]}
      hidden={tab !== id}
      xstyle={tab === id ? undefined : panelStyles.hidden}
    >
      {tab === id ? <ProjectTabBody tab={id} projectId={projectId} /> : null}
    </VStack>
  ));
}

/** The project screen for a well-formed ID (the `detail-page` template's shape: back link → h1 → ID → tabs). */
function ProjectPage({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState<ProjectTab>("overview");
  // The heading and the sidebar's child item use the shortened form
  // (first and last 6 digits). The full text is shown right under the
  // heading in a HexText
  const label = shortId(projectId);
  return (
    <DashboardShell
      destination="projects"
      project={{ id: projectId, label }}
      backLink={{ label: "Projects", href: spaPaths.dashboard() }}
      title={`Project ${label}`}
      intro={<HexText testId="project-id">{projectId}</HexText>}
      tabs={<ProjectTabList tab={tab} onChange={setTab} />}
    >
      <ProjectTabPanels tab={tab} projectId={projectId} />
    </DashboardShell>
  );
}

/** A path that fails the ID's format (the server is not asked). */
function InvalidProjectPage({ projectId }: { projectId: string }): ReactNode {
  return (
    <DashboardShell
      destination="projects"
      backLink={{ label: "Projects", href: spaPaths.dashboard() }}
      title="Project"
      intro={<HexText testId="project-id">{projectId}</HexText>}
    >
      <Banner
        status="warning"
        title="Not a project ID"
        description="A project ID is 64 lowercase hex characters. Nothing was requested from the server."
      />
    </DashboardShell>
  );
}

export function ProjectScreen(): ReactNode {
  const { projectId } = useRouteParams(projectRoute);
  return isProjectId(projectId) ? (
    <ProjectPage projectId={projectId} />
  ) : (
    <InvalidProjectPage projectId={projectId} />
  );
}
