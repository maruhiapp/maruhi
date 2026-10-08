// App entry point (server component). Route definitions live in a server
// module; the page bodies (server components) are baked into the RSC
// payload at build time. The dashboard is a client component, bound with
// bindRoute against the shared route definitions (dashboard/routes.ts)
// (ruling BO — docs/notes/session-43.md).
import { Router } from "@funstack/router";
import { bindRoute } from "@funstack/router/server";

import { FocusOnNavigation } from "./components/FocusOnNavigation.tsx";
import { Providers } from "./components/Providers.tsx";
import { AccountAuditScreen } from "./dashboard/AccountAuditScreen.tsx";
import { DashboardScreen } from "./dashboard/DashboardScreen.tsx";
import { DashboardLayout } from "./dashboard/DashboardShell.tsx";
import { DevicesScreen } from "./dashboard/DevicesScreen.tsx";
import { ProjectScreen } from "./dashboard/ProjectScreen.tsx";
import {
  accountAuditRoute,
  dashboardRoute,
  dashboardShellRoute,
  devicesRoute,
  homeRoute,
  projectRoute,
  tokensRoute,
} from "./dashboard/routes.ts";
import { TokensScreen } from "./dashboard/TokensScreen.tsx";
import { HomePage } from "./pages/HomePage.tsx";

// routes.ts is the single catalog of route definitions (paths) (ruling
// BZ — a unit test checks the SPA space and run_worker_first do not
// intersect). This file only binds them
const routes = [
  bindRoute(homeRoute, { component: <HomePage /> }),
  // The authenticated screens sit under a pathless parent
  // (DashboardLayout: session + AppShell + SideNav + Outlet) so
  // navigations never remount the shell (routes.ts's dashboardShellRoute)
  bindRoute(dashboardShellRoute, {
    component: <DashboardLayout />,
    children: [
      bindRoute(dashboardRoute, { component: <DashboardScreen /> }),
      bindRoute(accountAuditRoute, { component: <AccountAuditScreen /> }),
      bindRoute(tokensRoute, { component: <TokensScreen /> }),
      bindRoute(devicesRoute, { component: <DevicesScreen /> }),
      bindRoute(projectRoute, { component: <ProjectScreen /> }),
    ],
  }),
];

export default function App() {
  return (
    <Providers>
      {/* focus moves to the page h1 after each SPA navigation (audit A-2) */}
      <FocusOnNavigation />
      {/* fallback="static": browsers without the Navigation API degrade to MPA (full page loads) */}
      <Router routes={routes} fallback="static" />
    </Providers>
  );
}
