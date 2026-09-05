"use client";

// S4 プロジェクト一覧(設計文書 §3)。S3(サインイン)とセッション状態は
// DashboardShell(DP3 裁定 A)へ移した — 本画面は ok 状態の本文のみ。
//
// - GET /projects(AUTH_SPEC §11-5 — 応答は projectId + チェーン導出 role の
//   サーバー申告値のみ)。nextAfter カーソルの Load more。プロジェクト ID
//   (genesis ハッシュ = capability)直入力の補助経路を正式に置く(設計文書 §3 S4
//   の暫定縮退の昇格)
import { Button } from "@astryxdesign/core/Button";
import { Grid } from "@astryxdesign/core/Grid";
import { HStack, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { type ReactNode, useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet } from "./api.ts";
import { DashboardShell } from "./DashboardShell.tsx";
import { apiPaths } from "./endpoints.ts";
import { spaPaths } from "./routes.ts";
import {
  EmptyNotice,
  FailureNotice,
  HexText,
  LoadingRow,
  navigateTo,
  RoleToken,
  SectionHeader,
  SECTION_GAP,
} from "./shared.tsx";
import type { ProjectList } from "./types.ts";

// プロジェクト ID の形式(genesis エントリの SHA-256 hex — CRYPTO_SPEC §6.4)。
// @maruhi/core の isProjectId と同形だが、実行コードを bundle に持ち込まない
// 方針(裁定 BR)のためリテラルで持つ
const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

interface ProjectRow extends Record<string, unknown> {
  id: string;
  role: string;
}

interface ProjectsState {
  rows: ProjectRow[];
  nextAfter: string | undefined;
}

/**
 * プロジェクト ID 直入力(`settings` テンプレートの 2 列 = 見出し + 説明 | 入力)。
 * 狭い幅では Grid が 1 列に畳む。
 */
function OpenByIdSection(): ReactNode {
  const [projectId, setProjectId] = useState("");
  const [showFormatNote, setShowFormatNote] = useState(false);
  const open = () => {
    const trimmed = projectId.trim();
    if (PROJECT_ID_PATTERN.test(trimmed)) {
      navigateTo(spaPaths.project(trimmed));
    } else {
      setShowFormatNote(true);
    }
  };
  return (
    <Grid columns={{ minWidth: 320 }} gap={10}>
      <SectionHeader
        title="Open a project by ID"
        description="A project ID works like a bookmark: paste one to open its overview directly."
      />
      <VStack gap={2}>
        <HStack gap={2} align="end" wrap="wrap">
          <TextInput
            label="Project ID"
            isLabelHidden
            value={projectId}
            onChange={(value) => {
              setProjectId(value);
              setShowFormatNote(false);
            }}
            data-testid="project-id-input"
          />
          <Button label="Open" variant="secondary" onClick={open} />
        </HStack>
        {showFormatNote ? (
          <Text as="p" type="supporting" role="alert">
            A project ID is 64 lowercase hex characters.
          </Text>
        ) : null}
      </VStack>
    </Grid>
  );
}

// ---------------------------------------------------------------------------
// S4: プロジェクト一覧
// ---------------------------------------------------------------------------

const PROJECT_COLUMNS: TableColumn<ProjectRow>[] = [
  {
    key: "id",
    header: "Project",
    width: proportional(1),
    renderCell: (row: ProjectRow) => (
      <Link href={spaPaths.project(row.id)}>
        <HexText>{row.id}</HexText>
      </Link>
    ),
  },
  {
    key: "role",
    header: "Your role",
    width: pixel(110),
    renderCell: (row: ProjectRow) => <RoleToken role={row.role} />,
  },
];

function appendProjects(current: ProjectsState | undefined, page: ProjectList): ProjectsState {
  const rows = page.projects.map((p) => ({ id: p.projectId, role: p.role }));
  return { rows: [...(current?.rows ?? []), ...rows], nextAfter: page.nextAfter };
}

/**
 * 空ページはリストの終端ではない(AUTH_SPEC §11-5): 候補ページは ghost 除外・
 * 確認失敗の省略で `{ projects: [], nextAfter }` になりうる。行が増えるか
 * nextAfter が尽きるまでカーソルを進める(PR #107 Bugbot 指摘の修正 —
 * 深さは候補ページ数で有界)。既出カーソルの再出現(壊れた・敵対的な
 * サーバー — 交互カーソルを含む)は終端扱いにして追跡を打ち切る: 追跡回数は
 * 相異なるカーソル数で全域有界(クライアントのサーバー不信の姿勢の均一化)。
 */
function shouldFollowCursor(
  page: ProjectList,
  next: ProjectsState,
  visitedCursors: Set<string>,
): boolean {
  if (page.projects.length > 0) return false;
  if (next.nextAfter === undefined) return false;
  if (visitedCursors.has(next.nextAfter)) return false;
  visitedCursors.add(next.nextAfter);
  return true;
}

async function loadNonEmptyPage(
  current: ProjectsState | undefined,
  visitedCursors: Set<string>,
): Promise<{ kind: "ok"; value: ProjectsState } | ApiFailure> {
  const result = await apiGet<ProjectList>(apiPaths.projects(current?.nextAfter));
  if (result.kind !== "ok") return result;
  const next = appendProjects(current, result.value);
  return shouldFollowCursor(result.value, next, visitedCursors)
    ? loadNonEmptyPage(next, visitedCursors)
    : { kind: "ok", value: next };
}

function ProjectsFooter({
  isLoading,
  nextAfter,
  onLoadMore,
}: {
  isLoading: boolean;
  nextAfter: string | undefined;
  onLoadMore: () => void;
}): ReactNode {
  if (isLoading) return <LoadingRow label="Loading projects" />;
  if (nextAfter === undefined) return null;
  return (
    <Button
      label="Load more"
      variant="secondary"
      onClick={onLoadMore}
      data-testid="load-more-projects"
    />
  );
}

function ProjectsTableView({
  projects,
  failure,
  isLoading,
  onLoadMore,
}: {
  projects: ProjectsState;
  failure: ApiFailure | undefined;
  isLoading: boolean;
  onLoadMore: () => void;
}): ReactNode {
  return (
    <VStack gap={4} align="start" data-testid="project-list">
      <Table
        data={projects.rows}
        columns={PROJECT_COLUMNS}
        idKey="id"
        density="balanced"
        hasHover
        dividers="rows"
      />
      {/* 追記形(裁定 B-b): 既に描けた一覧の下に Load more の失敗を足す */}
      {failure !== undefined ? <FailureNotice failure={failure} onRetry={onLoadMore} /> : null}
      <ProjectsFooter
        isLoading={isLoading}
        nextAfter={projects.nextAfter}
        onLoadMore={onLoadMore}
      />
    </VStack>
  );
}

function ProjectListSection(): ReactNode {
  const [projects, setProjects] = useState<ProjectsState | undefined>(undefined);
  const [failure, setFailure] = useState<ApiFailure | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);

  const loadPage = useCallback(async (current: ProjectsState | undefined) => {
    setIsLoading(true);
    setFailure(undefined);
    const result = await loadNonEmptyPage(current, new Set());
    setIsLoading(false);
    if (result.kind !== "ok") {
      setFailure(result);
      return;
    }
    setProjects(result.value);
  }, []);

  useEffect(() => {
    void loadPage(undefined);
  }, [loadPage]);

  if (projects === undefined) {
    // 置換形(裁定 B-a): 初回ページが取れるまでは本体の代わりに描く
    return failure !== undefined ? (
      <FailureNotice failure={failure} onRetry={() => void loadPage(undefined)} />
    ) : (
      <LoadingRow label="Loading projects" />
    );
  }
  if (projects.rows.length === 0) {
    return (
      <EmptyNotice
        title="No projects"
        description="Projects you are a member of appear here, as reported by the server. Create one with the maruhi CLI."
        testId="project-empty"
      />
    );
  }
  return (
    <ProjectsTableView
      projects={projects}
      failure={failure}
      isLoading={isLoading}
      onLoadMore={() => void loadPage(projects)}
    />
  );
}

// ---------------------------------------------------------------------------
// 画面本体
// ---------------------------------------------------------------------------

export function DashboardScreen(): ReactNode {
  return (
    <DashboardShell
      destination="projects"
      title="Projects"
      intro={
        <Text as="p" type="supporting">
          Projects you are a member of, with your chain-derived role, as reported by the server.
          Open a project to see its members, environments, audit log, and rotation flags.
        </Text>
      }
    >
      {/* ページ見出しが一覧の見出しを兼ねる(1 領域に主見出しは 1 つ — Astryx layout docs)。
          節見出しを持つのは 2 つ目の節(Open a project by ID)だけ */}
      <VStack gap={SECTION_GAP}>
        <ProjectListSection />
        <OpenByIdSection />
      </VStack>
    </DashboardShell>
  );
}
