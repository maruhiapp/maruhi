"use client";

// S5 プロジェクト概要 / S6 監査(project・invites 軸)/ S7 要ローテーション
// フラグ(設計文書 §3)。読み取りのみ・全表示はサーバー申告(§4)。
//
// - S5: チェーン取得(§11)を表示用に畳み込む(chain-view.ts — 検証ではない)。
//   環境一覧(§12-4)+ 選択環境のメタデータのみ pull(§12-7 — 値・DEK は
//   構造的に応答へ現れない。var.read も記録されない)
// - S6: AuditEventList(裁定 BQ)。invites 軸はチェーン role admin 限定で、
//   403 は役割文言のまま表示する(タブを事前に隠す role 判定は置かない)
// - S7: dismiss は置かない(ADR-0018 改訂 2 の境界原則 — 警告の消去)。
//   CLI `maruhi rotation dismiss` への静的案内のみ
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
import { type ReactNode, useMemo, useState } from "react";

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
// S5: 概要タブ — チェーン(メンバー・ヘッド・サーバー)
// ---------------------------------------------------------------------------

interface MemberRow extends Record<string, unknown> {
  id: string;
  role: string;
  /** Environment scope as reported (`all environments` or the listed ids — ES K4). */
  scope: string;
  sinceSeq: number;
  /** Device keys as reported (DK K5 — chain-view の畳み込み)。 */
  devices: ReadonlyArray<ReportedDevice>;
  deviceCount: number;
  unresolvedRevocations: number;
}

/** 表示用の scope 文言(サーバー申告の畳み込み — Granted servers の Scope 列と同じ描き方)。 */
function describeMemberScope(member: ReportedMember): string {
  if (member.scopeKind === "all") return "all environments";
  return member.scopeEnvironmentIds.length === 0
    ? "no environments"
    : member.scopeEnvironmentIds.join(", ");
}

/**
 * 端末 cap の字面(CLI `describeCap` — apps/cli/src/device-key.ts — と同じ: `owner/all`、
 * `member/dev, staging`、`owner/no environments`)。Web と CLI で同じ事実は同じ字面(K5-3)。
 */
function describeCap(device: ReportedDevice): string {
  if (device.scopeKind === "all") return `${device.roleCap}/all`;
  return `${device.roleCap}/${
    device.scopeEnvironmentIds.length === 0
      ? "no environments"
      : device.scopeEnvironmentIds.join(", ")
  }`;
}

/** 上限のある端末だけ cap を添える(CLI `describeDevice` と同じ)。 */
function isBounded(device: ReportedDevice): boolean {
  return device.roleCap !== "owner" || device.scopeKind !== "all";
}

const FINGERPRINT_NOT_REPORTED = "fingerprint not reported";

/** chip の字面: 短縮 FP(無ければ not reported)+ 上限があるときだけ `(cap)`。 */
function deviceChipLabel(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex;
  const head = fp === null ? FINGERPRINT_NOT_REPORTED : shortId(fp);
  return isBounded(device) ? `${head} (${describeCap(device)})` : head;
}

/** chip の説明(全長 FP・cap・追加 seq — hover / 支援技術向け)。 */
function deviceChipDescription(device: ReportedDevice): string {
  const fp = device.keyFingerprintHex ?? FINGERPRINT_NOT_REPORTED;
  return `${fp} · cap ${describeCap(device)} · since seq ${device.addedSeq}`;
}

/** 端末 1 つの chip(短縮 FP + 上限。全長 FP と cap は description)。 */
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
 * Devices 列: 端末数(算術で正確)+ 端末ごとの chip。FP は申告のバイト列から束縛できた
 * ときだけ出る(`add_device` のワイヤは FP を運ばない — K5-1)。unresolved があれば、
 * 未束縛のうち幾つが失効したか(どれかは不明)を 1 文で添える。
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
  const attestations = snapshot.attestations ?? [];
  if (attestations.length === 0) return "None reported";
  const parts = attestations.map((a) => `${a.attesterUserId} at seq ${a.chainHeadSeq}`);
  return `${attestations.length} reported: ${parts.join(" · ")}`;
}

// MetadataList のラベル列幅(`incident-console` のインスペクタと同じ規模。64 hex の値が折り返しても
// ラベルと値の対応が読める)
const CHAIN_LABEL_WIDTH = 200;

/** チェーンの要約(`detail-page` テンプレートの見出し直下メタデータの形 — MetadataList)。 */
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

/** 付与済みサーバー鍵(行 = Table — 集合は行で描く)。 */
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
 * 四眼の方針と pending 提案(K6-J — 読み取りのみ。承認・撤回は CLI: ADR-0018)。票数は
 * 記録ではなく再集計(chain-view の畳み込み)。
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
 * 読めずに落とした端末 op は黙って吸収しない(K5-17): 表示は落とした行が作ったはずの集合の
 * 上位集合になりうる。0 なら描かない。検証は CLI
 */
function UnreadableDeviceEntriesNote({ count }: { count: number }): ReactNode {
  if (count === 0) return null;
  const rows = count === 1 ? "1 device entry" : `${count} device entries`;
  const verb = count === 1 ? "was" : "were";
  return (
    <Text type="supporting" size="sm" data-testid="unreadable-device-entries">
      {`${rows} in the reported chain could not be read and ${verb} left out; the device sets above may include devices those entries would have removed. Verify with maruhi project verify.`}
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
        description="Chain-derived members, roles, environment scopes and device keys, as reported by the server. A device's fingerprint appears once the reported entries bind it; the device count is exact either way. Verify with maruhi member list."
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
        <UnreadableDeviceEntriesNote count={view.unreadableDeviceEntries} />
      </SectionBlock>
      <ServersList servers={view.servers} />
      <ApprovalsView policy={view.policy} proposals={view.proposals} />
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// S5: 概要タブ — 環境と変数名(メタデータのみ pull)
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

/** 選択環境の変数名(行 = Table — 集合は行で描く)。値は構造上応答に無い。 */
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

function buildEnvironmentColumns(
  selectedEnvironmentId: string | undefined,
  onToggle: (environmentId: string) => void,
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
          columns={buildEnvironmentColumns(selectedEnvironmentId, onToggle)}
          idKey="id"
          density="balanced"
          hasHover
          dividers="rows"
          data-testid="env-table"
        />
      )}
      {selectedEnvironmentId !== undefined ? (
        <VariablesSection projectId={projectId} environmentId={selectedEnvironmentId} />
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
 * 概要タブ。チェーン取得(§11)をプロジェクトの存在確認を兼ねる先頭リソースとし、
 * 環境一覧はチェーンが取れてから読む — 一様 404 / 403 のとき同じ Banner が節ごとに
 * 並ぶ形(DP3 裁定 B の見直しで判明)を避ける。1 往復の直列化は受容。
 */
function OverviewTab({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<ChainSnapshot>(apiPaths.chain(projectId));
  // 置換形(裁定 B-a)— 以下 VariablesSection / EnvironmentsSection / RotationTab も同じ
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
// S6: 監査タブ(project / invites 軸。本人軸は /dashboard/account)
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
        {/* 規定文言(AUDIT_SPEC §7 / 設計文書 §4-4): 不可視クラスの存在・件数を示唆しない */}
        <Text type="supporting" data-testid="audit-caption">
          Events visible to your role, as reported by the server.
        </Text>
        {/* 軸の切替は ToggleButtonGroup(single)。SegmentedControl は dark で非選択ラベルの
            コントラストが 4.26:1(12px)で AA に届かない(a11y 監査 — 上流候補) */}
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
// S7: 要ローテーションフラグ
// ---------------------------------------------------------------------------

interface FlagRow extends Record<string, unknown> {
  id: string;
  environmentId: string;
  variableId: string;
  basis: string;
  trigger: string;
  recommendedAtMs: number;
}

// 人を対象にする trigger の字面(未知・欠落は従来どおり除名として推定 — 旧サーバーの行)。
// Map なのでプロトタイプ鎖の名前(敵対的な trigger 文字列)に当たらない
const USER_TRIGGER_LABELS: ReadonlyMap<string, string> = new Map([
  ["change_role", "member role/scope changed"],
  ["revoke_device", "device revoked"],
]);

function userTriggerLabel(trigger: string | undefined): string {
  return (trigger === undefined ? undefined : USER_TRIGGER_LABELS.get(trigger)) ?? "member removed";
}

/**
 * トリガー(削除 / 降格・縮小された主体 / 失効された端末の持ち主 / 失効されたサーバー鍵)
 * の表示形。`trigger`(AUDIT_SPEC §3.3 — 2026-09-14 ES、`revoke_device` は 2026-09-19 DK)が
 * あればそれを使い、無ければ従来どおり target の有無から推定する(旧サーバーの応答)。
 * 末尾に契機のチェーン seq(`triggerChainSeq` — 応答が運ぶ)を添える: `revoke_device` の行は
 * 端末 FP を運ばないので、seq で Audit タブのミラー行(`chain.device_revoked` — FP 入り)を
 * 辿れるようにする(K5-5 再探索)。
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
        // 見出し無しの箱(タブ内、ページ h1 の直下)なので h2 — 後続の Callout(h2)と並ぶ
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
      {/* dismiss は Web に置かない(ADR-0018 改訂 2 — 警告の消去はガバナンス操作) */}
      <Callout title="Rotating and dismissing" headingLevel={2} testId="rotation-note">
        A flag means the upstream credential should be rotated. Rotate the value, then dismiss the
        flag from the CLI: <Text type="code">maruhi rotation dismiss</Text> (admin). Dismissing is
        not available in the dashboard.
      </Callout>
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// 画面本体
// ---------------------------------------------------------------------------

const PROJECT_TABS = ["overview", "audit", "rotation", "invites"] as const;
type ProjectTab = (typeof PROJECT_TABS)[number];

const PROJECT_TAB_PANELS: Record<ProjectTab, string> = {
  overview: "project-panel-overview",
  audit: "project-panel-audit",
  rotation: "project-panel-rotation",
  invites: "project-panel-invites",
};

// tabpanel は対応する tab から名前を取る(APG)。Astryx は Tab に自動 id を
// 振らないので、明示 id を tab 側に置いて aria-labelledby で指す
const PROJECT_TAB_IDS: Record<ProjectTab, string> = {
  overview: "project-tab-overview",
  audit: "project-tab-audit",
  rotation: "project-tab-rotation",
  invites: "project-tab-invites",
};

// `hidden` 属性だけでは隠れない: Astryx の reset(`@layer reset` の
// `:where([hidden]){display:none}`)より VStack 自身の `display:flex`
// (`@layer astryx-base`)が勝つ。StyleX 同士なら後勝ちで効く(ADR-0013 ②)
const panelStyles = stylex.create({
  hidden: { display: "none" },
});

function isProjectTab(value: string): value is ProjectTab {
  return (PROJECT_TABS as ReadonlyArray<string>).includes(value);
}

function ProjectTabBody({ tab, projectId }: { tab: ProjectTab; projectId: string }): ReactNode {
  if (tab === "audit") return <AuditTab projectId={projectId} />;
  if (tab === "rotation") return <RotationTab projectId={projectId} />;
  // S8(裁定 CP): project 軸の管理面はタブ。失効状態が別プロジェクトへ
  // 持ち越されないよう projectId でキーする
  if (tab === "invites") return <InvitesTab key={projectId} projectId={projectId} />;
  return <OverviewTab projectId={projectId} />;
}

/** header スロット用の TabList(同一画面内のパネル切替なので nav landmark でなく WAI-ARIA tabs)。 */
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

/** 妥当な ID のプロジェクト画面(`detail-page` テンプレートの形: 戻りリンク → h1 → ID → タブ)。 */
function ProjectPage({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState<ProjectTab>("overview");
  // 見出しとサイドバーの子項目は短縮形(先頭・末尾 6 桁)。全文は見出し直下に HexText で出す
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

/** ID の形式を満たさないパス(サーバーには問い合わせない)。 */
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
