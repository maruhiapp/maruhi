"use client";

// S3 ログイン + S4 プロジェクト一覧(認証状態で出し分け — 設計文書 §3)。
//
// - S3: /auth/github/start への導線のみ(Web OAuth — AUTH_SPEC §3)。
//   ログアウトは POST /auth/logout + CSRF ヘッダー(api.ts が一律付与)
// - S4: GET /projects(AUTH_SPEC §11-5 — 応答は projectId + チェーン導出 role の
//   サーバー申告値のみ)。nextAfter カーソルの Load more。プロジェクト ID
//   (genesis ハッシュ = capability)直入力の補助経路を正式に置く(設計文書 §3 S4
//   の暫定縮退の昇格)
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Divider } from "@astryxdesign/core/Divider";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack, Layout, LayoutContent, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { pixel, proportional, Table, type TableColumn } from "@astryxdesign/core/Table";
import { Heading, Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { type ReactNode, useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, apiPost } from "./api.ts";
import { FailureNotice, LoadingRow, navigateTo, RoleToken, ServerReportedNote } from "./shared.tsx";
import type { Me, ProjectList } from "./types.ts";

// プロジェクト ID の形式(genesis エントリの SHA-256 hex — CRYPTO_SPEC §6.4)。
// @maruhi/core の isProjectId と同形だが、実行コードを bundle に持ち込まない
// 方針(裁定 BR)のためリテラルで持つ
const PROJECT_ID_PATTERN = /^[0-9a-f]{64}$/;

type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; signedOutNow: boolean }
  | { status: "ok"; me: Me }
  | { status: "failed"; failure: ApiFailure };

interface ProjectRow extends Record<string, unknown> {
  id: string;
  role: string;
}

interface ProjectsState {
  rows: ProjectRow[];
  nextAfter: string | undefined;
}

function LoginCard({ signedOutNow }: { signedOutNow: boolean }): ReactNode {
  return (
    <Card padding={6} maxWidth={480} data-testid="login-card">
      <VStack gap={4}>
        <Heading level={2}>Sign in</Heading>
        {signedOutNow ? (
          <Text as="p" color="secondary">
            You are signed out.
          </Text>
        ) : (
          <Text as="p" color="secondary">
            The maruhi dashboard is a read-only view of your projects, as reported by the server.
            Secrets never appear here — values live on your own machines and are handled by the CLI.
          </Text>
        )}
        <Link href="/auth/github/start" data-testid="sign-in-link">
          Sign in with GitHub
        </Link>
      </VStack>
    </Card>
  );
}

function OpenByIdCard(): ReactNode {
  const [projectId, setProjectId] = useState("");
  const [showFormatNote, setShowFormatNote] = useState(false);
  const open = () => {
    const trimmed = projectId.trim();
    if (PROJECT_ID_PATTERN.test(trimmed)) {
      navigateTo(`/dashboard/projects/${trimmed}`);
    } else {
      setShowFormatNote(true);
    }
  };
  return (
    <VStack gap={2} maxWidth={640}>
      <Heading level={3}>Open a project by ID</Heading>
      <Text as="p" type="supporting">
        A project ID works like a bookmark: paste one to open its overview directly.
      </Text>
      <HStack gap={2} align="end">
        <TextInput
          label="Project ID"
          isLabelHidden
          size="sm"
          value={projectId}
          onChange={(value) => {
            setProjectId(value);
            setShowFormatNote(false);
          }}
          data-testid="project-id-input"
        />
        <Button label="Open" variant="secondary" size="sm" onClick={open} />
      </HStack>
      {showFormatNote ? (
        <Text as="p" type="supporting">
          A project ID is 64 lowercase hex characters.
        </Text>
      ) : null}
    </VStack>
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
      <Link href={`/dashboard/projects/${row.id}`}>
        <Text type="code" size="sm" wordBreak="break-all">
          {row.id}
        </Text>
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

function projectsPath(after: string | undefined): string {
  return after === undefined ? "/projects" : `/projects?after=${encodeURIComponent(after)}`;
}

function appendProjects(current: ProjectsState | undefined, page: ProjectList): ProjectsState {
  const rows = page.projects.map((p) => ({ id: p.projectId, role: p.role }));
  return { rows: [...(current?.rows ?? []), ...rows], nextAfter: page.nextAfter };
}

/**
 * 空ページはリストの終端ではない(AUTH_SPEC §11-5): 候補ページは ghost 除外・
 * 確認失敗の省略で `{ projects: [], nextAfter }` になりうる。行が増えるか
 * nextAfter が尽きるまでカーソルを進める(PR #107 Bugbot 指摘の修正 —
 * 深さは候補ページ数で有界)。
 */
function morePagesNeeded(
  page: ProjectList,
  next: ProjectsState,
  previousAfter: string | undefined,
): boolean {
  // 前進しないカーソル(壊れた・敵対的なサーバー)は終端扱いにして追跡を
  // 打ち切る — クライアントのサーバー不信の姿勢を無限ループ耐性でも揃える
  return (
    page.projects.length === 0 && next.nextAfter !== undefined && next.nextAfter !== previousAfter
  );
}

async function loadNonEmptyPage(
  current: ProjectsState | undefined,
): Promise<{ kind: "ok"; value: ProjectsState } | ApiFailure> {
  const result = await apiGet<ProjectList>(projectsPath(current?.nextAfter));
  if (result.kind !== "ok") return result;
  const next = appendProjects(current, result.value);
  return morePagesNeeded(result.value, next, current?.nextAfter)
    ? loadNonEmptyPage(next)
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
      size="sm"
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
    <VStack gap={3} data-testid="project-list">
      <Table
        data={projects.rows}
        columns={PROJECT_COLUMNS}
        idKey="id"
        density="compact"
        dividers="rows"
      />
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
    const result = await loadNonEmptyPage(current);
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
    return failure !== undefined ? (
      <FailureNotice failure={failure} onRetry={() => void loadPage(undefined)} />
    ) : (
      <LoadingRow label="Loading projects" />
    );
  }
  if (projects.rows.length === 0) {
    return (
      <EmptyState
        title="No projects"
        description="Projects you are a member of appear here, as reported by the server. Create one with the maruhi CLI."
        headingLevel={3}
        isCompact
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
// 画面本体(S3 / S4 の出し分け)
// ---------------------------------------------------------------------------

function SignedInBody({ me, onSignOut }: { me: Me; onSignOut: () => void }): ReactNode {
  return (
    <VStack gap={6}>
      <HStack gap={3} justify="between" align="center" wrap="wrap">
        <Text type="supporting" data-testid="signed-in-user">
          Signed in as <Text type="code">{me.userId}</Text>
        </Text>
        <HStack gap={3} align="center">
          <Link href="/dashboard/account">Account audit</Link>
          <Button
            label="Sign out"
            variant="ghost"
            size="sm"
            onClick={onSignOut}
            data-testid="sign-out"
          />
        </HStack>
      </HStack>
      <ProjectListSection />
      <Divider />
      <OpenByIdCard />
      <ServerReportedNote />
    </VStack>
  );
}

function DashboardBody({
  auth,
  onRetry,
  onSignOut,
}: {
  auth: AuthState;
  onRetry: () => void;
  onSignOut: () => void;
}): ReactNode {
  if (auth.status === "loading") return <LoadingRow label="Checking your session" />;
  if (auth.status === "signed-out") return <LoginCard signedOutNow={auth.signedOutNow} />;
  if (auth.status === "failed") return <FailureNotice failure={auth.failure} onRetry={onRetry} />;
  return <SignedInBody me={auth.me} onSignOut={onSignOut} />;
}

export function DashboardScreen(): ReactNode {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });

  const loadMe = useCallback(async () => {
    setAuth({ status: "loading" });
    const result = await apiGet<Me>("/auth/me");
    if (result.kind === "ok") {
      setAuth({ status: "ok", me: result.value });
    } else if (result.kind === "unauthorized") {
      setAuth({ status: "signed-out", signedOutNow: false });
    } else {
      setAuth({ status: "failed", failure: result });
    }
  }, []);

  useEffect(() => {
    void loadMe();
  }, [loadMe]);

  const signOut = useCallback(async () => {
    const result = await apiPost("/auth/logout");
    if (result.kind === "ok" || result.kind === "unauthorized") {
      setAuth({ status: "signed-out", signedOutNow: true });
    } else {
      setAuth({ status: "failed", failure: result });
    }
  }, []);

  return (
    <Layout
      contentWidth={960}
      padding={6}
      content={
        <LayoutContent>
          <VStack gap={5}>
            <HStack gap={3} justify="between" align="center">
              <Heading level={1}>㊙ maruhi dashboard</Heading>
              <Link href="/">Home</Link>
            </HStack>
            <DashboardBody
              auth={auth}
              onRetry={() => void loadMe()}
              onSignOut={() => void signOut()}
            />
          </VStack>
        </LayoutContent>
      }
    />
  );
}
