"use client";

// S4 project list (design document §3). S3 (sign-in) and the session
// state moved into DashboardShell (DP3 ruling A) — this screen is only
// the ok-state body.
//
// - GET /projects (AUTH_SPEC §11-5 — the response carries only the
//   server-reported projectId + chain-derived role). A nextAfter-cursor
//   Load more. The auxiliary path of typing a project ID (the genesis
//   hash = the capability) directly is formally in place (the promotion
//   of design document §3 S4's provisional reduction)
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
import { isProjectId } from "./ids.ts";
import { spaPaths } from "./routes.ts";
import {
  EmptyNotice,
  FailureNotice,
  HexText,
  LoadingRow,
  navigateTo,
  RoleToken,
  SectionBlock,
  SectionHeader,
  SECTION_GAP,
} from "./shared.tsx";
import type { ProjectList } from "./types.ts";

// A format error (client-side judgment — the server is not asked).
// Carried on the TextInput's status
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

/**
 * Direct project-ID input (the `settings` template's two columns =
 * heading + description | input). On narrow widths the Grid folds to
 * one column.
 */
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
      {/* The format error rides TextInput's own status (detached — appears below the input). Enter also Opens */}
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

// ---------------------------------------------------------------------------
// S4: the project list
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
  // Dedupe additions against already-rendered rows so a hostile or
  // broken server repeating the same projectId cannot grow rows and
  // React keys
  const rows = current === undefined ? [] : [...current.rows];
  const seen = new Set(rows.map((row) => row.id));
  for (const project of page.projects) {
    if (seen.has(project.projectId)) continue;
    seen.add(project.projectId);
    rows.push({ id: project.projectId, role: project.role });
  }
  return { rows, nextAfter: page.nextAfter };
}

/** The cap on auto-following empty pages — a resource bound against a server that returns a fresh cursor every time. Past it, control defers to "load more" */
const MAX_EMPTY_PAGE_HOPS = 10;

/**
 * An empty page is not the end of the list (AUTH_SPEC §11-5): a
 * candidate page can become `{ projects: [], nextAfter }` via ghost
 * exclusion or confirmation-failure omission. Advance the cursor until
 * a row appears or nextAfter runs out (depth is bounded by the number
 * of candidate pages). A cursor already seen reappearing (a broken or
 * hostile server — including alternating cursors) is treated as the end
 * and the following stops. The follow count is bounded by the smaller
 * of the distinct-cursor count "and" the fixed cap
 * (MAX_EMPTY_PAGE_HOPS) — even a server that mints a new cursor every
 * time has a ceiling on GETs and the Set's growth (past it: manual
 * load more)
 */
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

/** If the cursor may be followed, records it and returns true (false when already seen or over the cap). */
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
  // Never swap the button out while loading (preserves focus — same
  // shape as AuditEventList's LoadMoreRow).
  // isInterruptible = no native disabled. Double-loading is blocked on
  // the handler side
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
      {/* Appended form (ruling B-b): the Load more failure is added below the already-rendered list */}
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
    // Replacement form (ruling B-a): rendered in place of the body until the first page arrives
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
        // The list's box has no heading (the page h1 doubles as it), so h2
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

// ---------------------------------------------------------------------------
// The screen body
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
      {/* The page heading doubles as the list's heading (one main heading per region — Astryx layout docs).
          Only the second section (Open a project by ID) carries a section heading */}
      <VStack gap={SECTION_GAP}>
        <SectionBlock>
          <ProjectListSection />
        </SectionBlock>
        <OpenByIdSection />
      </VStack>
    </DashboardShell>
  );
}
