import { route } from "@funstack/router/server";

const HOME_PATH = "/";
const DASHBOARD_PATH = "/dashboard";
const ACCOUNT_AUDIT_PATH = "/dashboard/account";
const TOKENS_PATH = "/dashboard/tokens";
const DEVICES_PATH = "/dashboard/devices";
const PROJECT_PATH = "/dashboard/projects/:projectId";

export const homeRoute = route({ id: "home", path: HOME_PATH });

export const dashboardRoute = route({ id: "dashboard", path: DASHBOARD_PATH });

export const accountAuditRoute = route({ id: "dashboard-account", path: ACCOUNT_AUDIT_PATH });

export const tokensRoute = route({ id: "dashboard-tokens", path: TOKENS_PATH });

export const devicesRoute = route({ id: "dashboard-devices", path: DEVICES_PATH });

export const projectRoute = route({ id: "dashboard-project", path: PROJECT_PATH });

export const dashboardShellRoute = route({ id: "dashboard-shell" });

export const spaPaths = {
  home: () => HOME_PATH,
  dashboard: () => DASHBOARD_PATH,
  account: () => ACCOUNT_AUDIT_PATH,
  tokens: () => TOKENS_PATH,
  devices: () => DEVICES_PATH,
  project: (projectId: string) => PROJECT_PATH.replace(":projectId", projectId),
} as const;

export const SPA_ROUTES = [
  homeRoute,
  dashboardRoute,
  accountAuditRoute,
  tokensRoute,
  devicesRoute,
  projectRoute,
];
