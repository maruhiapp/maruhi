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
import { Card } from "@astryxdesign/core/Card";
import { Divider } from "@astryxdesign/core/Divider";
import { HStack, Layout, LayoutContent, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { Heading, Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { useRouteParams } from "@funstack/router";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";

import { type ApiFailure, apiGet, type ApiResult } from "./api.ts";
import { AuditEventList } from "./AuditEventList.tsx";
import { deriveReportedView, type ReportedServer } from "./chain-view.ts";
import { apiPaths } from "./endpoints.ts";
import { projectRoute } from "./routes.ts";
import {
  FailureNotice,
  formatServerTime,
  LoadingRow,
  RoleToken,
  ServerReportedNote,
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

const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

/**
 * 単発 GET の 3 状態(loading / failure / value)を持つ小さなフック。
 * path 変更・再読込で古い in-flight 応答は捨てる(effect のクリーンアップで
 * stale マーク — 後着の旧プロジェクト応答が新しい画面を上書きしない。
 * PR #107 Bugbot 指摘の修正)。
 */
function useApiResource<T>(path: string): {
  state: { kind: "loading" } | { kind: "failed"; failure: ApiFailure } | { kind: "ok"; value: T };
  reload: () => void;
} {
  const [state, setState] = useState<
    { kind: "loading" } | { kind: "failed"; failure: ApiFailure } | { kind: "ok"; value: T }
  >({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let stale = false;
    setState({ kind: "loading" });
    void apiGet<T>(path).then((result: ApiResult<T>) => {
      if (stale) return;
      setState(
        result.kind === "ok"
          ? { kind: "ok", value: result.value }
          : { kind: "failed", failure: result },
      );
    });
    return () => {
      stale = true;
    };
  }, [path, attempt]);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);
  return { state, reload };
}

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
    renderCell: (row: MemberRow) => (
      <Text type="code" size="sm" wordBreak="break-all">
        {row.id}
      </Text>
    ),
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
          <Text type="code" size="sm" wordBreak="break-all">
            {server.keyFingerprintHex}
          </Text>
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
          Chain head: seq {snapshot.headSeq} ·{" "}
          <Text type="code" size="sm" wordBreak="break-all">
            {snapshot.headHashHex}
          </Text>
        </Text>
        <Text type="supporting">{attestationSummary(snapshot)}</Text>
      </VStack>
      <VStack gap={2}>
        <Heading level={3}>Members</Heading>
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

function ChainSection({ projectId }: { projectId: string }): ReactNode {
  const { state, reload } = useApiResource<ChainSnapshot>(apiPaths.chain(projectId));
  if (state.kind === "loading") return <LoadingRow label="Loading chain" />;
  if (state.kind === "failed") return <FailureNotice failure={state.failure} onRetry={reload} />;
  return <ChainView snapshot={state.value} />;
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
      <Text type="supporting" size="sm" wordBreak="break-all">
        {statement.variableId}
      </Text>
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
        <Text type="supporting">No variables reported.</Text>
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
      renderCell: (row: EnvironmentRow) => (
        <Text type="code" size="sm" wordBreak="break-all">
          {row.id}
        </Text>
      ),
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
      header: "",
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
      <Heading level={3}>Environments</Heading>
      {rows.length === 0 ? (
        <Text type="supporting">No environments reported.</Text>
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

function OverviewTab({ projectId }: { projectId: string }): ReactNode {
  return (
    <VStack gap={5}>
      <ChainSection projectId={projectId} />
      <Divider />
      <EnvironmentsSection projectId={projectId} />
    </VStack>
  );
}

// ---------------------------------------------------------------------------
// S6: 監査タブ(project / invites 軸。本人軸は /dashboard/account)
// ---------------------------------------------------------------------------

function auditPath(base: string, before: string | undefined): string {
  return before === undefined ? base : `${base}?before=${encodeURIComponent(before)}`;
}

function AuditTab({ projectId }: { projectId: string }): ReactNode {
  const [axis, setAxis] = useState("project");
  const fetchProjectEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(auditPath(apiPaths.auditEvents(projectId), before)),
    [projectId],
  );
  const fetchInviteEvents = useMemo(
    () => (before: string | undefined) =>
      apiGet<AuditEventsPage>(auditPath(apiPaths.auditInvites(projectId), before)),
    [projectId],
  );
  return (
    <VStack gap={4}>
      <HStack gap={3} justify="between" align="center" wrap="wrap">
        {/* 規定文言(AUDIT_SPEC §7 / 設計文書 §4-4): 不可視クラスの存在・件数を示唆しない */}
        <Text type="supporting" data-testid="audit-caption">
          Events visible to your role, as reported by the server.
        </Text>
        <SegmentedControl label="Audit source" value={axis} onChange={setAxis} size="sm">
          <SegmentedControlItem value="project" label="Project events" />
          <SegmentedControlItem value="invites" label="Invites" />
        </SegmentedControl>
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
      <Text type="supporting" data-testid="rotation-empty">
        No rotation flags are currently effective, as reported by the server.
      </Text>
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

function ProjectTabBody({ tab, projectId }: { tab: string; projectId: string }): ReactNode {
  if (tab === "audit") return <AuditTab projectId={projectId} />;
  if (tab === "rotation") return <RotationTab projectId={projectId} />;
  return <OverviewTab projectId={projectId} />;
}

function ProjectTabs({ projectId }: { projectId: string }): ReactNode {
  const [tab, setTab] = useState("overview");
  return (
    <VStack gap={5}>
      <TabList value={tab} onChange={setTab} size="md">
        <Tab value="overview" label="Overview" />
        <Tab value="audit" label="Audit" />
        <Tab value="rotation" label="Rotation flags" />
      </TabList>
      <ProjectTabBody tab={tab} projectId={projectId} />
      <Divider />
      <ServerReportedNote />
    </VStack>
  );
}

export function ProjectScreen(): ReactNode {
  const { projectId } = useRouteParams(projectRoute);
  return (
    <Layout
      contentWidth={960}
      padding={6}
      content={
        <LayoutContent>
          <VStack gap={5}>
            <VStack gap={2}>
              <Link href="/dashboard">← All projects</Link>
              <Heading level={1}>Project</Heading>
              <Text type="code" size="sm" wordBreak="break-all" data-testid="project-id">
                {projectId}
              </Text>
            </VStack>
            <Card padding={5}>
              {PROJECT_ID_PATTERN.test(projectId) ? (
                <ProjectTabs projectId={projectId} />
              ) : (
                <Text as="p" type="supporting">
                  This is not a project ID (a project ID is 64 lowercase hex characters).
                </Text>
              )}
            </Card>
          </VStack>
        </LayoutContent>
      }
    />
  );
}
