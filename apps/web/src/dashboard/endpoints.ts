export const SAMPLE_PROJECT_ID = "ab".repeat(32);
export const SAMPLE_ENVIRONMENT_ID = "production";
export const SAMPLE_INVITE_ID = "inv-sample";
export const SAMPLE_TOKEN_ID = "tok-sample";

const PROJECTS_CURSOR = "after";
const AUDIT_CURSOR = "before";

function withCursor(path: string, name: "after" | "before", value: string | undefined): string {
  return value === undefined ? path : `${path}?${name}=${encodeURIComponent(value)}`;
}

export const apiPaths = {
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
  inviteRevoke: (projectId: string, inviteId: string) =>
    `/projects/${projectId}/invites/${encodeURIComponent(inviteId)}`,
  tokens: () => "/auth/tokens",
  tokenRevoke: (tokenId: string) => `/auth/tokens/${encodeURIComponent(tokenId)}`,
  devices: () => "/auth/devices",
} as const;

export interface DashboardEndpoint {
  readonly group: string;
  readonly endpoint: string;
  readonly access: "session" | "unauthenticated";
  readonly sample: string;
  readonly cursor?: "after" | "before";
}

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
  { group: "devices", endpoint: "list", access: "session", sample: apiPaths.devices() },
];
