"use client";

import { AppShell } from "@astryxdesign/core/AppShell";
import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Center } from "@astryxdesign/core/Center";
import { Layout, LayoutContent, LayoutHeader, VStack } from "@astryxdesign/core/Layout";
import { SideNav, SideNavHeading, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Heading, Text } from "@astryxdesign/core/Text";
import { Outlet } from "@funstack/router";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";

import { type ApiFailure, apiGet, apiPost } from "./api.ts";
import { apiPaths } from "./endpoints.ts";
import {
  ArrowRightStartOnRectangleIcon,
  ClipboardDocumentListIcon,
  ComputerDesktopIcon,
  FolderIcon,
  KeyIcon,
  UserCircleIcon,
} from "./icons.tsx";
import { FailureNotice, LoadingRow } from "./resource-states.tsx";
import { markResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
import { SECTION_GAP, ServerReportedNote } from "./sections.tsx";
import { SessionExpiredContext } from "./session-expiry.ts";
import type { Me } from "./types.ts";

type ShellDestination = "projects" | "tokens" | "devices" | "account";

interface BackLink {
  label: string;
  href: string;
}

const LOGO_INVERTED_SRC = "/logo-inverted.svg";
const SIDE_NAV_LOGO_PX = 24;
const SIGN_IN_LOGO_PX = 40;

const CONTENT_WIDTH = 1200;

interface CurrentProject {
  id: string;
  label: string;
}

interface ShellNav {
  destination: ShellDestination;
  project: CurrentProject | undefined;
}

const ShellNavContext = createContext<((nav: ShellNav) => void) | undefined>(undefined);

function useShellNav(destination: ShellDestination, project: CurrentProject | undefined): void {
  const setNav = useContext(ShellNavContext);
  const projectId = project?.id;
  const projectLabel = project?.label;
  useLayoutEffect(() => {
    setNav?.({
      destination,
      project:
        projectId === undefined || projectLabel === undefined
          ? undefined
          : { id: projectId, label: projectLabel },
    });
  }, [setNav, destination, projectId, projectLabel]);
}

const BASE_DOCUMENT_TITLE = "maruhi";

function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} — ${BASE_DOCUMENT_TITLE}`;
    return () => {
      document.title = BASE_DOCUMENT_TITLE;
    };
  }, [title]);
}

type AuthState =
  | { status: "loading" }
  | { status: "signed-out"; signedOutNow: boolean }
  | { status: "ok"; me: Me }
  | { status: "failed"; failure: ApiFailure };

const DESTINATIONS: ReadonlyArray<{
  id: ShellDestination;
  label: string;
  href: string;
  icon: typeof FolderIcon;
}> = [
  { id: "projects", label: "Projects", href: spaPaths.dashboard(), icon: FolderIcon },
  { id: "tokens", label: "API tokens", href: spaPaths.tokens(), icon: KeyIcon },
  { id: "devices", label: "Devices", href: spaPaths.devices(), icon: ComputerDesktopIcon },
  {
    id: "account",
    label: "Account audit",
    href: spaPaths.account(),
    icon: ClipboardDocumentListIcon,
  },
];

function NavItems({
  current,
  project,
}: {
  current: ShellDestination;
  project: CurrentProject | undefined;
}): ReactNode {
  return DESTINATIONS.map((d) =>
    d.id === "projects" && project !== undefined ? (
      <SideNavItem key={d.id} label={d.label} icon={d.icon} href={d.href} collapsible>
        <SideNavItem label={project.label} href={spaPaths.project(project.id)} isSelected />
      </SideNavItem>
    ) : (
      <SideNavItem
        key={d.id}
        label={d.label}
        icon={d.icon}
        href={d.href}
        isSelected={d.id === current}
      />
    ),
  );
}

function DashboardSideNav({
  current,
  project,
  me,
  onSignOut,
}: {
  current: ShellDestination;
  project: CurrentProject | undefined;
  me: Me;
  onSignOut: () => void;
}): ReactNode {
  return (
    <SideNav
      collapsible
      header={
        <SideNavHeading
          heading="maruhi"
          icon={
            <img
              src={LOGO_INVERTED_SRC}
              alt=""
              width={SIDE_NAV_LOGO_PX}
              height={SIDE_NAV_LOGO_PX}
            />
          }
          headingHref={spaPaths.dashboard()}
        />
      }
      footer={
        <SideNavSection title="Account" isHeaderHidden>
          {}
          <SideNavItem
            label={me.userId}
            icon={UserCircleIcon}
            href={spaPaths.account()}
            isSelected={current === "account"}
            data-testid="signed-in-user"
          />
          <SideNavItem
            label="Sign out"
            icon={ArrowRightStartOnRectangleIcon}
            onClick={onSignOut}
            data-testid="sign-out"
          />
        </SideNavSection>
      }
    >
      <SideNavSection title="Navigation" isHeaderHidden>
        <NavItems current={current} project={project} />
      </SideNavSection>
    </SideNav>
  );
}

function SignInScreen({ signedOutNow }: { signedOutNow: boolean }): ReactNode {
  useDocumentTitle("Sign in");
  const headingRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (signedOutNow) headingRef.current?.focus();
  }, [signedOutNow]);
  return (
    <Center axis="both" padding={6} minHeight="100dvh" role="main">
      <VStack gap={4} align="center" width="100%" maxWidth={400}>
        <VStack gap={2} align="center">
          <img src={LOGO_INVERTED_SRC} alt="" width={SIGN_IN_LOGO_PX} height={SIGN_IN_LOGO_PX} />
          <Text type="body" weight="bold" size="lg">
            maruhi
          </Text>
        </VStack>
        <Card padding={8} width="100%" data-testid="login-card">
          <VStack gap={4} align="stretch">
            <VStack gap={1} align="center">
              <Heading level={1} ref={headingRef} tabIndex={-1} data-testid="sign-in-heading">
                Sign in
              </Heading>
              <Text type="body" color="secondary" size="sm" justify="center">
                Your projects' metadata, as reported by the server.
              </Text>
            </VStack>
            {signedOutNow ? (
              <Banner role="status" status="info" title="You are signed out." container="card" />
            ) : null}
            {/* The return marker (ruling BU): after OAuth completes, returns to /dashboard via S1 */}
            <Button
              label="Sign in with GitHub"
              variant="primary"
              size="lg"
              href={apiPaths.githubStart()}
              onClick={markResumeToDashboard}
              data-testid="sign-in-link"
            />
            <Text type="supporting" color="secondary" justify="center">
              Secrets never appear here — values live on your own machines and are handled by the
              CLI.
            </Text>
          </VStack>
        </Card>
      </VStack>
    </Center>
  );
}

function PageHeader({
  backLink,
  crumb,
  title,
  intro,
  tabs,
}: {
  backLink: BackLink | undefined;
  crumb: string;
  title: string;
  intro: ReactNode;
  tabs: ReactNode;
}): ReactNode {
  return (
    <VStack gap={3}>
      <VStack gap={1}>
        {backLink === undefined ? null : (
          <Breadcrumbs variant="supporting">
            <BreadcrumbItem href={backLink.href}>{backLink.label}</BreadcrumbItem>
            <BreadcrumbItem isCurrent>{crumb}</BreadcrumbItem>
          </Breadcrumbs>
        )}
        <Heading level={1}>{title}</Heading>
        {intro}
      </VStack>
      {tabs}
    </VStack>
  );
}

function useSession(): {
  auth: AuthState;
  reload: () => void;
  signOut: () => void;
  expire: () => void;
} {
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
  const expire = useCallback(() => setAuth({ status: "signed-out", signedOutNow: true }), []);
  return { auth, reload, signOut, expire };
}

interface PageProps {
  destination: ShellDestination;
  project?: CurrentProject | undefined;
  backLink?: BackLink;
  title: string;
  intro?: ReactNode;
  tabs?: ReactNode;
  children: ReactNode;
}

function StatusFrame({ title, children }: { title: string; children: ReactNode }): ReactNode {
  useDocumentTitle(title);
  return (
    <Center axis="both" padding={6} minHeight="100dvh" role="main">
      <VStack width="100%" maxWidth={480}>
        {children}
      </VStack>
    </Center>
  );
}

export function DashboardLayout(): ReactNode {
  const { auth, reload, signOut, expire } = useSession();
  if (auth.status === "loading") {
    return (
      <StatusFrame title="Checking your session">
        <LoadingRow label="Checking your session" />
      </StatusFrame>
    );
  }
  if (auth.status === "signed-out") return <SignInScreen signedOutNow={auth.signedOutNow} />;
  if (auth.status === "failed") {
    return (
      <StatusFrame title="Session check failed">
        <FailureNotice failure={auth.failure} onRetry={reload} />
      </StatusFrame>
    );
  }
  return (
    <SessionExpiredContext.Provider value={expire}>
      <SignedInFrame me={auth.me} onSignOut={signOut} />
    </SessionExpiredContext.Provider>
  );
}

function SignedInFrame({ me, onSignOut }: { me: Me; onSignOut: () => void }): ReactNode {
  const [nav, setNav] = useState<ShellNav>({ destination: "projects", project: undefined });
  return (
    <ShellNavContext.Provider value={setNav}>
      <AppShell
        contentPadding={0}
        sideNav={
          <DashboardSideNav
            current={nav.destination}
            project={nav.project}
            me={me}
            onSignOut={onSignOut}
          />
        }
      >
        <Outlet />
      </AppShell>
    </ShellNavContext.Provider>
  );
}

export function DashboardShell({
  destination,
  project,
  backLink,
  title,
  intro,
  tabs,
  children,
}: PageProps): ReactNode {
  useShellNav(destination, project);
  useDocumentTitle(title);
  return (
    <Layout
      height="auto"
      contentWidth={CONTENT_WIDTH}
      padding={6}
      header={
        <LayoutHeader>
          <PageHeader
            backLink={backLink}
            crumb={project?.label ?? title}
            title={title}
            intro={intro}
            tabs={tabs}
          />
        </LayoutHeader>
      }
      content={
        <LayoutContent>
          {}
          <VStack gap={SECTION_GAP} paddingBlockStart={6}>
            {children}
            <ServerReportedNote />
          </VStack>
        </LayoutContent>
      }
    />
  );
}
