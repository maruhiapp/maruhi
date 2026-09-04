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
import { Button } from "@astryxdesign/core/Button";
import { Divider } from "@astryxdesign/core/Divider";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { Heading, Text } from "@astryxdesign/core/Text";
import { ToggleButton, ToggleButtonGroup } from "@astryxdesign/core/ToggleButton";
import { Token } from "@astryxdesign/core/Token";
import { useRouteParams } from "@funstack/router";
import * as stylex from "@stylexjs/stylex";
import { type ReactNode, useMemo, useState } from "react";

import { apiGet } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { deriveReportedView, type ReportedServer } from "./chain-view.ts";
import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { InvitesTab } from "./InvitesTab.tsx";
import { projectRoute, spaPaths } from "./routes.ts";
import {
  EmptyNotice,
  FailureNotice,
  formatServerTime,
  HexText,
  LoadingRow,
  RoleToken,
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

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// S5: 概要タブ — チェーン(メンバー・ヘッド・サーバー)
// ---------------------------------------------------------------------------

interface MemberRow extends Record<string, unknown> {
  id: string;
  role: string;
  sinceSeq: number;
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
  if (attestations.length === 0) return "No member head attestations reported.";
  const parts = attestations.map((a) => `${a.attesterUserId} at seq ${a.chainHeadSeq}`);
  return `${attestations.length} member head attestation(s) reported: ${parts.join(" · ")}`;
}

function ServersList({ servers }: { servers: ReadonlyArray<ReportedServer> }): ReactNode {
  if (servers.length === 0) return null;
  return (
    <VStack gap={2}>
      <Heading level={3}>Granted servers</Heading>
      {servers.map((server) => (
        <HStack key={server.keyFingerprintHex} gap={2} align="center" wrap="wrap">
          <HexText>{server.keyFingerprintHex}</HexText>
          <Text type="supporting" size="sm">
            {server.scopeEnvironmentIds.length === 0
              ? "no environments in scope"
              : `scope: ${server.scopeEnvironmentIds.join(", ")}`}
          </Text>
        </HStack>
      ))}
    </VStack>
  );
}

function ChainView({ snapshot }: { snapshot: ChainSnapshot }): ReactNode {
  const view = deriveReportedView(snapshot.entries ?? []);
  const memberRows: MemberRow[] = view.members.map((m) => ({
    id: m.userId,
    role: m.role,
    sinceSeq: m.sinceSeq,
  }));
  return (
    <VStack gap={4} data-testid="chain-section">
      <VStack gap={1}>
        <Text type="supporting">
          Chain head: seq {snapshot.headSeq} · <HexText>{snapshot.headHashHex}</HexText>
        </Text>
        <Text type="supporting">{attestationSummary(snapshot)}</Text>
      </VStack>
      <VStack gap={2}>
        <Heading level={2}>Members</Heading>
        <Table
          data={memberRows}
          columns={MEMBER_COLUMNS}
          idKey="id"
          density="compact"
          dividers="rows"
          data-testid="member-table"
        />
      </VStack>
      <ServersList servers={view.servers} />
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

function VariableNameRow({
  statement,
  deleted,
}: {
  statement: { variableId: string; name: string };
  deleted: boolean;
}): ReactNode {
  return (
    <HStack gap={2} align="center" wrap="wrap">
      <Text type="code" size="sm" hasStrikethrough={deleted}>
        {statement.name}
      </Text>
      <HexText size="xsm">{statement.variableId}</HexText>
      {deleted ? <Token label="deleted" size="sm" color="gray" /> : null}
    </HStack>
  );
}

function VariableNames({ pull }: { pull: EnvironmentMetadataPull }): ReactNode {
  const rows = [
    ...pull.variables.map((statement) => ({ statement, deleted: false })),
    ...pull.deletedVariables.map((statement) => ({ statement, deleted: true })),
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
        rows.map(({ statement, deleted }) => (
          <VariableNameRow key={statement.variableId} statement={statement} deleted={deleted} />
        ))
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
    <VStack gap={3}>
      <Heading level={2}>Environments</Heading>
      {rows.length === 0 ? (
        <EmptyNotice
          title="No environments"
          description="Environments of this project appear here, as reported by the server."
        />
      ) : (
        <Table
          data={rows}
          columns={buildEnvironmentColumns(selectedEnvironmentId, onToggle)}
          idKey="id"
          density="compact"
          dividers="rows"
          data-testid="env-table"
        />
      )}
      {selectedEnvironmentId !== undefined ? (
        <VariablesSection projectId={projectId} environmentId={selectedEnvironmentId} />
      ) : null}
    </VStack>
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
    <VStack gap={5}>
      <ChainView snapshot={state.value} />
      <Divider />
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
            コントラストが 4.26:1(12px)で AA に届かない(DP3 a11y 監査 — 上流候補) */}
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

/** トリガー(削除された主体 / 失効されたサーバー鍵)の表示形。 */
function flagTrigger(flag: RotationFlag): string {
  if (flag.targetUserId !== undefined) return `member removed: ${flag.targetUserId}`;
  if (flag.targetServerKeyFingerprintHex !== undefined) {
    return `server revoked: ${flag.targetServerKeyFingerprintHex}`;
  }
  return "";
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
    header: "Recommended at (UTC)",
    width: pixel(200),
    renderCell: (row: FlagRow) => (
      <Text type="supporting" size="sm" hasTabularNumbers>
        {formatServerTime(row.recommendedAtMs)}
      </Text>
    ),
  },
];

function RotationFlagsView({ flags }: { flags: ReadonlyArray<RotationFlag> }): ReactNode {
  if (flags.length === 0) {
    return (
      <EmptyNotice
        title="No rotation flags"
        description="No rotation flags are currently effective, as reported by the server."
        testId="rotation-empty"
      />
    );
  }
  return (
    <Table
      data={flags.map(toFlagRow)}
      columns={FLAG_COLUMNS}
      idKey="id"
      density="compact"
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
      <RotationFlagsView flags={state.value.flags} />
      {/* dismiss は Web に置かない(ADR-0018 改訂 2 — 警告の消去はガバナンス操作) */}
      <Text type="supporting" data-testid="rotation-note">
        A flag means the upstream credential should be rotated. Rotate the value, then dismiss the
        flag from the CLI: <Text type="code">maruhi rotation dismiss</Text> (admin). Dismissing is
        not available in the dashboard.
      </Text>
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

function ProjectTabs({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState<ProjectTab>("overview");
  return (
    <VStack gap={5}>
      {/* 同一画面内のパネル切替なので navigation landmark ではなく WAI-ARIA tabs */}
      <TabList
        value={tab}
        onChange={(value) => {
          if (isProjectTab(value)) setTab(value);
        }}
        size="md"
        role="tablist"
        aria-label="Project"
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
      {PROJECT_TABS.map((id) => (
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
      ))}
    </VStack>
  );
}

/** パンくず用の短縮形(先頭・末尾 8 桁)。全文は見出し直下に HexText で出す。 */
function shortProjectId(projectId: string): string {
  return `${projectId.slice(0, 8)}…${projectId.slice(-8)}`;
}

export function ProjectScreen(): ReactNode {
  const { projectId } = useRouteParams(projectRoute);
  const isProjectId = PROJECT_ID_PATTERN.test(projectId);
  return (
    <DashboardShell
      destination="projects"
      breadcrumbs={[{ label: "Projects", href: spaPaths.dashboard() }]}
      title={isProjectId ? `Project ${shortProjectId(projectId)}` : "Project"}
      intro={<HexText testId="project-id">{projectId}</HexText>}
    >
      {isProjectId ? (
        <ProjectTabs projectId={projectId} />
      ) : (
        <Text as="p" type="supporting">
          This is not a project ID (a project ID is 64 lowercase hex characters).
        </Text>
      )}
    </DashboardShell>
  );
}
