"use client";

// アプリシェル(DP3 裁定 A — docs/notes/web-design-pass.md §5)。認証が要る画面
// (S4〜S9)はすべてこのシェルの中に描く:
//
// - AppShell + TopNav(ロゴ・3 つの到達点・ユーザー表示・Sign out)。モバイル幅
//   (AppShell の md = 768px 未満)では TopNav が圧縮バーになり、到達点は
//   AppShell 生成のドロワーへ移る(スキップリンク・main ランドマークも AppShell)
// - セッション状態(`GET /auth/me`)はシェルが 1 か所で持つ。401 は全画面で
//   同じサインインカードに落ちる(旧 DashboardScreen の S3 をここへ移した)。
//   本文は状態 ok のときだけ描く(子のフェッチは me の確認後 — 1 往復の直列化を
//   受け入れて、401 時に本文が一瞬描かれてから消える形を避ける)
// - ログアウトは POST /auth/logout + CSRF ヘッダー(api.ts が一律付与)
// - 表示規律の但し書き(ServerReportedNote)はページ末尾にシェルが 1 回置く
//
// 文言はすべて英語(ADR-0017)。
import { AppShell } from "@astryxdesign/core/AppShell";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { useMediaQuery } from "@astryxdesign/core/hooks";
import { Icon } from "@astryxdesign/core/Icon";
import { HStack, Layout, LayoutContent, VStack } from "@astryxdesign/core/Layout";
import { Link } from "@astryxdesign/core/Link";
import { Heading, Text } from "@astryxdesign/core/Text";
import { TopNav, TopNavHeading, TopNavItem } from "@astryxdesign/core/TopNav";
import { type ReactNode, useCallback, useEffect, useState } from "react";

import { type ApiFailure, apiGet, apiPost } from "./api.ts";
import { apiPaths } from "./endpoints.ts";
import { MaruhiMark } from "./MaruhiMark.tsx";
import { markResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
import { FailureNotice, LoadingRow, NARROW_VIEWPORT_QUERY, ServerReportedNote } from "./shared.tsx";
import type { Me } from "./types.ts";

/** TopNav の到達点(選択状態 = aria-current="page")。project 画面は Projects 配下。 */
export type ShellDestination = "projects" | "tokens" | "account";

/** パンくずの 1 段(最後の段は呼び出し側が isCurrent にしない — 現在地は見出し)。 */
export interface Crumb {
  label: string;
  href: string;
}

type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; signedOutNow: boolean }
  | { status: "ok"; me: Me }
  | { status: "failed"; failure: ApiFailure };

// 到達点の目録(表示順)。パスは routes.ts の spaPaths だけを経由する(裁定 CA)
const DESTINATIONS: ReadonlyArray<{ id: ShellDestination; label: string; href: string }> = [
  { id: "projects", label: "Projects", href: spaPaths.dashboard() },
  { id: "tokens", label: "API tokens", href: spaPaths.tokens() },
  { id: "account", label: "Account audit", href: spaPaths.account() },
];

// 到達点は 3 つ(TopNav の「5 以下」に収まる。増えるときは SideNav へ — Astryx layout docs)
function NavItems({ current }: { current: ShellDestination }): ReactNode {
  return DESTINATIONS.map((d) => (
    <TopNavItem key={d.id} label={d.label} href={d.href} isSelected={d.id === current} />
  ));
}

// 内部 user_id は ULID(26 文字 — AUTH_SPEC §9)。狭い幅の圧縮バーには収まらないので、
// ユーザー表示は到達点と一緒にドロワー側(startContent)へ移し、バーには Sign out だけを残す
function SignedInAs({ me }: { me: Me }): ReactNode {
  return (
    <Text type="supporting" data-testid="signed-in-user">
      Signed in as <Text type="code">{me.userId}</Text>
    </Text>
  );
}

function SignOutButton({ onSignOut }: { onSignOut: () => void }): ReactNode {
  return (
    <Button label="Sign out" variant="ghost" size="sm" onClick={onSignOut} data-testid="sign-out" />
  );
}

function LoginCard({ signedOutNow }: { signedOutNow: boolean }): ReactNode {
  return (
    <Card padding={6} maxWidth={480} data-testid="login-card">
      <VStack gap={4}>
        <Heading level={1}>Sign in</Heading>
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
        {/* 復帰マーカー(裁定 BU): OAuth 完了後に S1 経由で /dashboard へ戻る */}
        <Link
          href={apiPaths.githubStart()}
          onClick={markResumeToDashboard}
          data-testid="sign-in-link"
        >
          Sign in with GitHub
        </Link>
      </VStack>
    </Card>
  );
}

function PageHeader({
  breadcrumbs,
  title,
  intro,
}: {
  breadcrumbs: ReadonlyArray<Crumb> | undefined;
  title: string;
  intro: ReactNode;
}): ReactNode {
  return (
    <VStack gap={2}>
      {breadcrumbs === undefined || breadcrumbs.length === 0 ? null : (
        <Breadcrumbs variant="supporting">
          {breadcrumbs.map((crumb) => (
            <BreadcrumbItem key={crumb.href} href={crumb.href}>
              {crumb.label}
            </BreadcrumbItem>
          ))}
          <BreadcrumbItem isCurrent>{title}</BreadcrumbItem>
        </Breadcrumbs>
      )}
      <Heading level={1}>{title}</Heading>
      {intro}
    </VStack>
  );
}

/** ページ本文(セッション状態で出し分け)。見出しはサインイン後にだけ出す。 */
function ShellPage({
  auth,
  onRetry,
  breadcrumbs,
  title,
  intro,
  children,
}: {
  auth: AuthState;
  onRetry: () => void;
  breadcrumbs: ReadonlyArray<Crumb> | undefined;
  title: string;
  intro: ReactNode;
  children: ReactNode;
}): ReactNode {
  if (auth.status === "loading") return <LoadingRow label="Checking your session" />;
  // サインイン前はページ見出しを出さない(サインインカードの見出しが h1 になる)
  if (auth.status === "signed-out") return <LoginCard signedOutNow={auth.signedOutNow} />;
  const header = <PageHeader breadcrumbs={breadcrumbs} title={title} intro={intro} />;
  if (auth.status === "failed") {
    return (
      <>
        {header}
        <FailureNotice failure={auth.failure} onRetry={onRetry} />
      </>
    );
  }
  return (
    <>
      {header}
      {children}
      <ServerReportedNote />
    </>
  );
}

/**
 * セッション状態(loading / signed-out / ok / failed)。ok のときだけ me を持つ。
 * サインアウトは成功・401 のどちらでも signed-out(signedOutNow)へ落とす。
 */
function useSession(): { auth: AuthState; reload: () => void; signOut: () => void } {
  const [auth, setAuth] = useState<AuthState>({ status: "loading" });
  const reload = useCallback(() => {
    setAuth({ status: "loading" });
    void apiGet<Me>(apiPaths.me()).then((result) => {
      if (result.kind === "ok") {
        setAuth({ status: "ok", me: result.value });
      } else if (result.kind === "unauthorized") {
        setAuth({ status: "signed-out", signedOutNow: false });
      } else {
        setAuth({ status: "failed", failure: result });
      }
    });
  }, []);
  useEffect(() => {
    reload();
  }, [reload]);
  const signOut = useCallback(() => {
    void apiPost(apiPaths.logout()).then((result) => {
      if (result.kind === "ok" || result.kind === "unauthorized") {
        setAuth({ status: "signed-out", signedOutNow: true });
      } else {
        setAuth({ status: "failed", failure: result });
      }
    });
  }, []);
  return { auth, reload, signOut };
}

// 狭い幅ではユーザー表示を到達点と一緒にドロワー側(startContent)へ移す
function NavStart({ destination, me }: { destination: ShellDestination; me: Me }): ReactNode {
  const isNarrow = useMediaQuery(NARROW_VIEWPORT_QUERY);
  return (
    <>
      <NavItems current={destination} />
      {isNarrow ? <SignedInAs me={me} /> : null}
    </>
  );
}

function NavEnd({ me, onSignOut }: { me: Me; onSignOut: () => void }): ReactNode {
  const isNarrow = useMediaQuery(NARROW_VIEWPORT_QUERY);
  return (
    <HStack gap={3} align="center">
      {isNarrow ? null : <SignedInAs me={me} />}
      <SignOutButton onSignOut={onSignOut} />
    </HStack>
  );
}

/** 到達点・ユーザー表示・Sign out を載せた TopNav(サインイン前はロゴのみ)。 */
function ShellTopNav({
  destination,
  me,
  onSignOut,
}: {
  destination: ShellDestination;
  me: Me | undefined;
  onSignOut: () => void;
}): ReactNode {
  const heading = (
    <TopNavHeading
      logo={<Icon icon={MaruhiMark} color="accent" size="md" />}
      heading="maruhi"
      headingHref={spaPaths.dashboard()}
    />
  );
  if (me === undefined) return <TopNav label="Dashboard" heading={heading} />;
  return (
    <TopNav
      label="Dashboard"
      heading={heading}
      startContent={<NavStart destination={destination} me={me} />}
      endContent={<NavEnd me={me} onSignOut={onSignOut} />}
    />
  );
}

/**
 * 認証が要る画面の共通フレーム。`title` はページの h1(AppShell は見出しを描かない
 * ので、本文の最初の見出しがページの h1 になる)。`breadcrumbs` は親階層のみ渡す
 * (現在地は title から補う)。`intro` は見出し直下の 1〜2 行。
 */
export function DashboardShell({
  destination,
  breadcrumbs,
  title,
  intro,
  children,
}: {
  destination: ShellDestination;
  breadcrumbs?: ReadonlyArray<Crumb>;
  title: string;
  intro?: ReactNode;
  children: ReactNode;
}): ReactNode {
  const { auth, reload, signOut } = useSession();
  const me = auth.status === "ok" ? auth.me : undefined;
  return (
    <AppShell
      height="auto"
      variant="section"
      topNav={<ShellTopNav destination={destination} me={me} onSignOut={signOut} />}
    >
      <Layout
        height="auto"
        contentWidth={960}
        padding={6}
        content={
          <LayoutContent>
            <VStack gap={6}>
              <ShellPage
                auth={auth}
                onRetry={reload}
                breadcrumbs={breadcrumbs}
                title={title}
                intro={intro}
              >
                {children}
              </ShellPage>
            </VStack>
          </LayoutContent>
        }
      />
    </AppShell>
  );
}
