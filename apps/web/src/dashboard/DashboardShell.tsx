"use client";

// The app shell (DP3 ruling A amendment 1 — docs/notes/web-design-pass.md
// §5). Every authenticated screen (S4–S9, S11) renders inside this shell.
// The shape follows the Astryx templates:
//
// - Frame = `astryx template shell-side-nav` / `AppShellSideNavOnly`:
//   AppShell + SideNav (header = ㊙ logo + maruhi, body = destinations,
//   footer = account [user id → Account audit, Sign out]). collapsible.
//   At mobile width (AppShell's md) the SideNav moves into the
//   AppShell-generated drawer (the skip link and the main landmark are
//   also AppShell's)
// - Page = `table-page` / `LayoutHeaderWithActions`: a back link + h1 +
//   description (+ tabs) in Layout(auto)'s header slot, the body in the
//   content slot. The whole page scrolls (the header is not fixed —
//   DP3 amendment 5: separate heading from body with whitespace, not a
//   line. An unfixed header would overlap the body and be unreadable, so
//   the fixing goes too)
// - Sign-in = `astryx template login`: Center (full viewport height) +
//   logo + Card (heading, description, primary button)
//
// The session state (`GET /auth/me`) is held in one place by the shell.
// A 401 lands every screen on the same sign-in screen, and the body
// renders only when ok (children fetch after me is confirmed — accepting
// the one-round-trip serialization to avoid a shape where the body
// flashes in and disappears on a 401). Sign-out is POST /auth/logout +
// the CSRF header (api.ts attaches it uniformly). The display-
// discipline caveat (ServerReportedNote) is placed once by the shell at
// the bottom of the page. All wording is English (ADR-0017).
//
// Two-layer structure (DP3 amendment 11): `DashboardLayout` is the
// component of the pathless parent route (routes.ts's
// dashboardShellRoute); it holds session state + AppShell + SideNav and
// renders child routes into `Outlet`. Never remounting across screen
// transitions means no /auth/me re-fetch, no re-appearance of "Checking
// your session", and no loss of the sidebar's collapsed state.
// `DashboardShell` is the page frame each screen uses (Layout's header
// = heading, content = body). Each screen declares the sidebar's
// current location and the project child item via `destination` /
// `project`, raised to the parent through context (a `useLocation`
// derived from the URL is not used because Location's `.hash` would
// enter the bundle and trip the AUTH_SPEC §15-3 tripwire [the word
// "hash" is banned]).
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
import { markResumeToDashboard } from "./resume.ts";
import { spaPaths } from "./routes.ts";
import { SessionExpiredContext } from "./session-expiry.ts";
import { FailureNotice, LoadingRow, SECTION_GAP, ServerReportedNote } from "./shared.tsx";
import type { Me } from "./types.ts";

/** The sidebar's destinations (selection state = aria-current="page"). The project screen sits under Projects. */
type ShellDestination = "projects" | "tokens" | "devices" | "account";

/** The parent level (the head of the breadcrumbs. The current location is the project's shortened ID or the title — moved to `Breadcrumbs` in amendment 7). */
interface BackLink {
  label: string;
  href: string;
}

// Brand assets (DP1 — apps/web/public). The inverted version = the ㊙
// mark in white on a vermilion disc = same shape as the favicon.
// The sidebar heading and the sign-in screen share the same file. The
// color does not follow the theme — pinned to vermilion (looking the
// same as the favicon on the browser tab)
const LOGO_INVERTED_SRC = "/logo-inverted.svg";
// 24px, balancing the heading's character height (bold 16px). Sign-in
// places it above the heading, so 40px
const SIDE_NAV_LOGO_PX = 24;
const SIGN_IN_LOGO_PX = 40;

// The body's max width (one value shared by every page — it does not
// vary per page). Astryx's `settings` template is 1440, `detail-page`
// is 1000. 1200 exactly fills a 1440px notebook (region 1180) and sits
// centered at 1920px
const CONTENT_WIDTH = 1200;

// The separator discipline (DP3 amendment 5 — ruling O): boundaries
// between heading, section, and body are marked by whitespace
// (SECTION_GAP), not lines. Lines appear only inside a collection
// (table rows, the audit rows' hairlines) and on the tab row (TabList
// hasDivider — the tab underline doubles as the only boundary between
// header and body)

/** The open project (shown as the current location under the sidebar's Projects child item). */
interface CurrentProject {
  id: string;
  label: string;
}

/** The sidebar's state (current location + the open project). Each screen declares it; the parent shell holds it. */
interface ShellNav {
  destination: ShellDestination;
  project: CurrentProject | undefined;
}

// The declaration path from a child route (screen) to the parent
// (shell). The value is a useState setter (stable identity)
const ShellNavContext = createContext<((nav: ShellNav) => void) | undefined>(undefined);

/**
 * A screen declares its destination and project to the shell. Applied
 * before paint (layout effect) so the first frame after a transition
 * never retains the previous screen's selection state.
 */
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

// The static shell's (Root.tsx) <title>. Restored when leaving the
// dashboard (an SPA transition to the RSC Home)
const BASE_DOCUMENT_TITLE = "maruhi";

/**
 * The per-screen document.title (`<screen name> — maruhi`). Because an
 * SPA transition never changes the static shell's <title>, it is set
 * on the client side so assistive tech, tabs, and history can tell
 * screens apart.
 * On unmount it restores the static shell's value (within one commit
 * the old screen's cleanup runs before the new screen's setup, so the
 * destination's value is never overwritten).
 */
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

// The destination catalog (in display order). Paths go only through
// routes.ts's spaPaths (ruling CA)
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

/** The sidebar (the `shell-side-nav` template's shape: header / destinations / account footer). */
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
          {/* Displays the internal user_id (ULID). Doubles as the destination for Account audit (the self axis) */}
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

/**
 * The sign-in screen (the `astryx template login` shape. Credentials
 * are GitHub OAuth only).
 * Rendered outside AppShell, so the main landmark is given to
 * Center(div) via role.
 * When `signedOutNow` (just signed out, or switched on the spot by a
 * screen's 401), the previously focused element disappears and focus
 * falls to body, so it is moved to the heading (not stolen on the
 * initial render [opened without a session]).
 */
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
              <Banner status="info" title="You are signed out." container="card" />
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

/**
 * The page heading (the `detail-page` template's PageHeader shape):
 * breadcrumbs → h1 → description → tabs. The breadcrumbs are Astryx
 * `Breadcrumbs` (parent level = link, current location = aria-current).
 * The tabs' (TabList hasDivider) underline doubles as the boundary
 * between header and body (ruling O).
 */
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

/**
 * The session state (loading / signed-out / ok / failed). me exists
 * only when ok. Sign-out falls to signed-out (signedOutNow) on either
 * success or a 401.
 */
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
  // A screen's fetch returned a 401 (session-expiry.ts). Land on the
  // same screen as just after a sign-out
  const expire = useCallback(() => setAuth({ status: "signed-out", signedOutNow: true }), []);
  return { auth, reload, signOut, expire };
}

interface PageProps {
  destination: ShellDestination;
  /** The open project (the sidebar's child item + the breadcrumbs' current location). */
  project?: CurrentProject | undefined;
  backLink?: BackLink;
  title: string;
  intro?: ReactNode;
  /** Tabs (a TabList) placed at the end of the header slot. The caller owns the body switching. */
  tabs?: ReactNode;
  children: ReactNode;
}

/**
 * The frame for session-checking / failure (no nav — only the status
 * display centered). Outside AppShell, so the main landmark is given
 * to Center(div) via role. `title` is the document.title.
 */
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

/**
 * The parent of the authenticated screens (the component of the
 * pathless route `dashboardShellRoute`). Confirms the session and only
 * when ok renders the child route (`Outlet`) inside AppShell +
 * SideNav. signed-out shows the sign-in screen; loading / failed show
 * the status frame (no nav). When a screen's fetch returns a 401
 * (SessionExpiredContext — session-expiry.ts) it drops to signed-out
 * on the spot.
 */
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

/** The post-sign-in frame: the sidebar (current location as declared by the child route) + the child route. */
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

/**
 * The per-screen page frame (rendered into `DashboardLayout`'s Outlet).
 * `title` is the page's h1 (AppShell renders no heading, so the header
 * slot's heading becomes the page's h1). `backLink` is the way back to
 * the parent level, `intro` the 1–2 lines right under the heading,
 * `tabs` the TabList at the end of the header. `destination` /
 * `project` are the declaration to the sidebar (useShellNav).
 */
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
          {/* The gap from the header is whitespace, not a line (ruling O): the header's own bottom margin 16px + 24px = 40px */}
          <VStack gap={SECTION_GAP} paddingBlockStart={6}>
            {children}
            <ServerReportedNote />
          </VStack>
        </LayoutContent>
      }
    />
  );
}
