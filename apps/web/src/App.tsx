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

const routes = [
  bindRoute(homeRoute, { component: <HomePage /> }),
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
      {}
      <FocusOnNavigation />
      {}
      <Router routes={routes} fallback="static" />
    </Providers>
  );
}
