"use client";

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
import { HexText, RoleToken } from "./display.tsx";
import { apiPaths } from "./endpoints.ts";
import { isProjectId } from "./ids.ts";
import { navigateTo } from "./navigation.ts";
import { EmptyNotice, FailureNotice, LoadingRow } from "./resource-states.tsx";
import { spaPaths } from "./routes.ts";
import { SectionBlock, SectionHeader, SECTION_GAP } from "./sections.tsx";
import type { ProjectList } from "./types.ts";

const FORMAT_ERROR = {
  type: "error",
  message: "A project ID is 64 lowercase hex characters.",
} as const;

interface ProjectRow extends Record<string, unknown> {
  id: string;
  role: string;
}

interface ProjectsState {
  rows: ProjectRow[];
  nextAfter: string | undefined;
}

function OpenByIdSection(): ReactNode {
  const [projectId, setProjectId] = useState("");
  const [showFormatNote, setShowFormatNote] = useState(false);
  const open = () => {
    const trimmed = projectId.trim();
    if (isProjectId(trimmed)) {
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
      {}
      <HStack gap={2} align="start" wrap="wrap">
        <TextInput
          label="Project ID"
          isLabelHidden
          value={projectId}
          onChange={(value) => {
            setProjectId(value);
            setShowFormatNote(false);
          }}
          onEnter={open}
          {...(showFormatNote ? { status: FORMAT_ERROR } : {})}
          statusVariant="detached"
          data-testid="project-id-input"
        />
        <Button label="Open" variant="secondary" onClick={open} />
      </HStack>
    </Grid>
  );
}

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
  const rows = current === undefined ? [] : [...current.rows];
  const seen = new Set(rows.map((row) => row.id));
  for (const project of page.projects) {
    if (seen.has(project.projectId)) continue;
    seen.add(project.projectId);
    rows.push({ id: project.projectId, role: project.role });
  }
  return { rows, nextAfter: page.nextAfter };
}

const MAX_EMPTY_PAGE_HOPS = 10;

function shouldFollowCursor(
  page: ProjectList,
  next: ProjectsState,
  visitedCursors: Set<string>,
): boolean {
  return (
    page.projects.length === 0 &&
    next.nextAfter !== undefined &&
    consumeCursor(visitedCursors, next.nextAfter)
  );
}

function consumeCursor(visitedCursors: Set<string>, cursor: string): boolean {
  if (visitedCursors.has(cursor) || visitedCursors.size >= MAX_EMPTY_PAGE_HOPS) return false;
  visitedCursors.add(cursor);
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
  if (nextAfter === undefined && !isLoading) return null;
  return (
    <Button
      label="Load more"
      variant="secondary"
      isLoading={isLoading}
      isInterruptible
      onClick={() => {
        if (!isLoading) onLoadMore();
      }}
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
      {}
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
    let result: Awaited<ReturnType<typeof loadNonEmptyPage>>;
    try {
      result = await loadNonEmptyPage(current, new Set());
    } finally {
      setIsLoading(false);
    }
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
        headingLevel={2}
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
      {}
      <VStack gap={SECTION_GAP}>
        <SectionBlock>
          <ProjectListSection />
        </SectionBlock>
        <OpenByIdSection />
      </VStack>
    </DashboardShell>
  );
}
