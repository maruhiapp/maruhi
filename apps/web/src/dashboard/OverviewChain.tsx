"use client";

import { Code } from "@astryxdesign/core/Code";
import { VStack } from "@astryxdesign/core/Layout";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import type { ReactNode } from "react";

import type { ReportedPolicy, ReportedProposal, ReportedServer } from "./chain-view-reported.ts";
import { deriveReportedView } from "./chain-view.ts";
import { ExpiryCell, HexText } from "./display.tsx";
import { shortId } from "./ids.ts";
import { MembersSection } from "./OverviewMembers.tsx";
import { EmptyNotice } from "./resource-states.tsx";
import { Callout, SectionBlock, SECTION_GAP } from "./sections.tsx";
import type { ChainSnapshot } from "./types.ts";

function attestationSummary(snapshot: ChainSnapshot): string {
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

const CHAIN_LABEL_WIDTH = 200;

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

export function ChainView({ snapshot }: { snapshot: ChainSnapshot }): ReactNode {
  const view = deriveReportedView(snapshot.entries ?? [], snapshot.headHashHex);
  return (
    <VStack gap={SECTION_GAP} data-testid="chain-section">
      <ChainSummary snapshot={snapshot} />
      <MembersSection members={view.members} unreadableEntries={view.unreadableEntries} />
      <ServersList servers={view.servers} />
      <ApprovalsView policy={view.policy} proposals={view.proposals} />
    </VStack>
  );
}
