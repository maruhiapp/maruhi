// The single catalog of API surfaces the dashboard consumes (ruling
// BW — docs/notes/session-43.md §11).
//
// Every path a screen fetches goes through a builder in this module,
// and the catalog (DASHBOARD_ENDPOINTS) binds each builder to its
// api-schema (group, endpoint) identifier. The unit test
// (test/unit/endpoints.test.ts) collates the catalog against the
// registered HttpApi and makes two invariants fail-loud:
//
//   1. **Path agreement**: the builder's generated path = api-schema's
//      path template (a rename or typo fails in a test, not as a
//      runtime 404)
//   2. **Session allowance**: every consumed surface is inside the
//      SESSION_ALLOWED_ENDPOINTS (AUTH_SPEC §5) enumeration (a new
//      screen calling an unlisted API fails in a test, not as a
//      runtime 403)
//
// This is the client-side counterpart of the server-side
// serving-topology sweep (run_worker_first coverage); with api-schema
// in the middle, consumption in both directions is mechanically
// checked. This module itself is pure string builders only (no
// executable code added to the bundle).

/** The catalog's sample parameters (shared with the test's template substitution). */
export const SAMPLE_PROJECT_ID = "ab".repeat(32);
export const SAMPLE_ENVIRONMENT_ID = "production";
export const SAMPLE_INVITE_ID = "inv-sample";
export const SAMPLE_TOKEN_ID = "tok-sample";

/**
 * The cursor query names (ruling CB — session-43 §13). Because the
 * builders and the catalog read the same constants, callers never touch
 * the name (a mix-up is impossible syntactically — the same shared-
 * constant shape as ruling CA). `after` = the project listing
 * (AUTH_SPEC §11-5), `before` = audit paging (AUDIT_SPEC §7).
 */
const PROJECTS_CURSOR = "after";
const AUDIT_CURSOR = "before";

/** Assembling a cursor query (the only query-attaching point — used only inside builders). */
function withCursor(path: string, name: "after" | "before", value: string | undefined): string {
  return value === undefined ? path : `${path}?${name}=${encodeURIComponent(value)}`;
}

/** The path builders the screens use (paging surfaces take the cursor value, never the name). */
export const apiPaths = {
  /** The start of web OAuth (a navigation funnel — unauthenticated surface; AUTH_SPEC §3). */
  githubStart: () => "/auth/github/start",
  me: () => "/auth/me",
  logout: () => "/auth/logout",
  projects: (after?: string) => withCursor("/projects", PROJECTS_CURSOR, after),
  chain: (projectId: string) => `/projects/${projectId}/chain`,
  environments: (projectId: string) => `/projects/${projectId}/environments`,
  pullMetadata: (projectId: string, environmentId: string) =>
    `/projects/${projectId}/environments/${environmentId}/pull/metadata`,
  auditEvents: (projectId: string, before?: string) =>
    withCursor(`/projects/${projectId}/audit/events`, AUDIT_CURSOR, before),
  auditInvites: (projectId: string, before?: string) =>
    withCursor(`/projects/${projectId}/audit/invites`, AUDIT_CURSOR, before),
  auditSelf: (before?: string) => withCursor("/auth/audit/events", AUDIT_CURSOR, before),
  rotationFlags: (projectId: string) => `/projects/${projectId}/rotation/flags`,
  invites: (projectId: string) => `/projects/${projectId}/invites`,
  // inviteId / tokenId are server-issued opaque ids (the UI carries no
  // format check the way it does for projectId), so they go through
  // encodeURIComponent — if a hostile server's id strays off the path it
  // stays a visible 404/405 (the concrete form accompanying ruling CN —
  // docs/notes/session-45.md §5)
  inviteRevoke: (projectId: string, inviteId: string) =>
    `/projects/${projectId}/invites/${encodeURIComponent(inviteId)}`,
  tokens: () => "/auth/tokens",
  tokenRevoke: (tokenId: string) => `/auth/tokens/${encodeURIComponent(tokenId)}`,
  /** S11 device registry (AUTH_SPEC §13-11 — advisory. Read-only, session-allowed). */
  devices: () => "/auth/devices",
} as const;

/** One dashboard-consumed endpoint bound to its api-schema identity. */
export interface DashboardEndpoint {
  readonly group: string;
  readonly endpoint: string;
  /**
   * Classification of the auth surface: `session` is a fetch-consumed
   * surface that must be inside the session-allowance enumeration
   * (AUTH_SPEC §5); `unauthenticated` is an unauthenticated surface (a
   * navigation funnel — inside UNAUTHENTICATED_ENDPOINTS).
   */
  readonly access: "session" | "unauthenticated";
  /** The path materialized with the sample parameters (the test collates it against the template). */
  readonly sample: string;
  /**
   * The cursor query name withCursor attaches to this surface (ruling
   * CB — session-43 §13). The sweep checks that api-schema's query
   * Schema declares a field of this name (a parameter rename fails in a
   * test rather than as silent unresponsive paging).
   */
  readonly cursor?: "after" | "before";
}

/** Every surface the dashboard consumes (the sweep's checked target). */
export const DASHBOARD_ENDPOINTS: ReadonlyArray<DashboardEndpoint> = [
  {
    group: "auth",
    endpoint: "githubStart",
    access: "unauthenticated",
    sample: apiPaths.githubStart(),
  },
  { group: "auth", endpoint: "me", access: "session", sample: apiPaths.me() },
  { group: "auth", endpoint: "logout", access: "session", sample: apiPaths.logout() },
  {
    group: "membership",
    endpoint: "list",
    access: "session",
    sample: apiPaths.projects(),
    cursor: PROJECTS_CURSOR,
  },
  {
    group: "membership",
    endpoint: "get",
    access: "session",
    sample: apiPaths.chain(SAMPLE_PROJECT_ID),
  },
  {
    group: "environments",
    endpoint: "list",
    access: "session",
    sample: apiPaths.environments(SAMPLE_PROJECT_ID),
  },
  {
    group: "variables",
    endpoint: "pullMetadata",
    access: "session",
    sample: apiPaths.pullMetadata(SAMPLE_PROJECT_ID, SAMPLE_ENVIRONMENT_ID),
  },
  {
    group: "audit",
    endpoint: "events",
    access: "session",
    sample: apiPaths.auditEvents(SAMPLE_PROJECT_ID),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "audit",
    endpoint: "invites",
    access: "session",
    sample: apiPaths.auditInvites(SAMPLE_PROJECT_ID),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "audit",
    endpoint: "self",
    access: "session",
    sample: apiPaths.auditSelf(),
    cursor: AUDIT_CURSOR,
  },
  {
    group: "rotation",
    endpoint: "flags",
    access: "session",
    sample: apiPaths.rotationFlags(SAMPLE_PROJECT_ID),
  },
  // S8 invite management / S9 token management (the revocation
  // screens): the 4 surfaces of listing + targeted revocation
  {
    group: "invites",
    endpoint: "list",
    access: "session",
    sample: apiPaths.invites(SAMPLE_PROJECT_ID),
  },
  {
    group: "invites",
    endpoint: "revoke",
    access: "session",
    sample: apiPaths.inviteRevoke(SAMPLE_PROJECT_ID, SAMPLE_INVITE_ID),
  },
  { group: "auth", endpoint: "listTokens", access: "session", sample: apiPaths.tokens() },
  {
    group: "auth",
    endpoint: "revokeTokenById",
    access: "session",
    sample: apiPaths.tokenRevoke(SAMPLE_TOKEN_ID),
  },
  // S11 device registry (DK K5): the listing only. Registration,
  // deletion, and requests are session-denied surfaces and are not
  // consumed
  { group: "devices", endpoint: "list", access: "session", sample: apiPaths.devices() },
];
