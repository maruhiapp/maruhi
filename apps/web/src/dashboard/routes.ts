// The dashboard's route definitions (a shared module — ruling BO:
// docs/notes/session-43.md).
//
// The path space is pinned to the /dashboard prefix, plainly separated
// from the API's path space (the /auth, /projects prefixes — the
// server's run_worker_first enumeration). App.tsx binds each component
// with bindRoute; the client side imports this module to get the
// useRouteParams types (funstack-router's partial route definitions).
//
// The path strings' single home is the constants below (ruling CA —
// session-43 §13): route() and the spaPaths builders read the same
// constants, so a rename propagates to every link and every navigation
// at once (the SPA-side counterpart to apiPaths in endpoints.ts).
import { route } from "@funstack/router/server";

const HOME_PATH = "/";
const DASHBOARD_PATH = "/dashboard";
const ACCOUNT_AUDIT_PATH = "/dashboard/account";
const TOKENS_PATH = "/dashboard/tokens";
const DEVICES_PATH = "/dashboard/devices";
const PROJECT_PATH = "/dashboard/projects/:projectId";

/** S1 landing (static, unauthenticated). */
export const homeRoute = route({ id: "home", path: HOME_PATH });

/** S3 login / S4 project list (auth-state adaptive). */
export const dashboardRoute = route({ id: "dashboard", path: DASHBOARD_PATH });

/** S6 self axis: the signed-in user's account events. */
export const accountAuditRoute = route({ id: "dashboard-account", path: ACCOUNT_AUDIT_PATH });

/** S9 token management (user axis — ruling CP, docs/notes/session-45.md). */
export const tokensRoute = route({ id: "dashboard-tokens", path: TOKENS_PATH });

/** S11 device registry (user axis — DK K5, design record dk-design.md §10 K5-7). */
export const devicesRoute = route({ id: "dashboard-devices", path: DEVICES_PATH });

/** S5 overview / S6 project audit / S7 rotation flags for one project. */
export const projectRoute = route({ id: "dashboard-project", path: PROJECT_PATH });

/**
 * The parent route of the authenticated screens (S4–S9) (pathless —
 * consumes no path segment). App.tsx binds `DashboardLayout` (session
 * state + AppShell + SideNav + Outlet) to it and makes the five routes
 * above its children. The shell mounts once across navigations — no
 * `GET /auth/me` re-fetch and no sidebar regeneration happens. Having
 * no path, it is not listed in SPA_ROUTES (the catalog for the
 * non-intersection sweep — every entry has a path).
 */
export const dashboardShellRoute = route({ id: "dashboard-shell" });

/**
 * The path builders for internal navigation (ruling CA). Every screen
 * href / navigateTo goes through here — the source tripwire
 * (test/unit/endpoints.test.ts) excludes any /dashboard-prefixed
 * literal outside this module.
 */
export const spaPaths = {
  home: () => HOME_PATH,
  dashboard: () => DASHBOARD_PATH,
  account: () => ACCOUNT_AUDIT_PATH,
  tokens: () => TOKENS_PATH,
  devices: () => DEVICES_PATH,
  project: (projectId: string) => PROJECT_PATH.replace(":projectId", projectId),
} as const;

/**
 * All SPA routes (ruling BZ — docs/notes/session-43.md §12). A unit
 * test collates this enumeration against wrangler.jsonc's
 * run_worker_first and verifies, derived from the real route
 * definitions, that "the SPA's route space is not swallowed by the
 * Worker" (ruling BO's separation). Add new routes here — a route()
 * declaration outside this module is excluded by the source tripwire
 * (test/unit/endpoints.test.ts), so the only way to fall out of the
 * catalog is forgetting the SPA_ROUTES entry inside this module.
 */
export const SPA_ROUTES = [
  homeRoute,
  dashboardRoute,
  accountAuditRoute,
  tokensRoute,
  devicesRoute,
  projectRoute,
];
