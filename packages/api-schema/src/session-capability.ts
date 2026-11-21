import { AuthMiddleware } from "./auth-middleware.ts";
import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

export const SESSION_ALLOWED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "me"],
    ["auth", "logout"],
    ["auth", "recoveryStatus"],
    ["keyWraps", "status"],
    ["devices", "list"],
    ["auth", "listTokens"],
    ["auth", "revokeTokenById"],
    ["membership", "get"],
    ["membership", "list"],
    ["environments", "list"],
    ["variables", "pullMetadata"],
    ["audit", "events"],
    ["audit", "invites"],
    ["audit", "self"],
    ["rotation", "flags"],
    ["invites", "list"],
    ["invites", "revoke"],
  ];

export const UNAUTHENTICATED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "authConfig"],
    ["auth", "githubStart"],
    ["auth", "githubCallback"],
    ["authCli", "cliStart"],
    ["authCli", "cliVerify"],
    ["authCli", "cliApprove"],
    ["authCli", "cliPoll"],
    ["lease", "issue"],
    ["lease", "propose"],
    ["lease", "preflight"],
  ];

const sessionAllowed = new Set(SESSION_ALLOWED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));

export function isSessionAllowedEndpoint(group: string, endpoint: string): boolean {
  return sessionAllowed.has(`${group}.${endpoint}`);
}

interface SweepableApi {
  readonly groups: {
    readonly [group: string]: {
      readonly endpoints: {
        readonly [endpoint: string]: {
          readonly middlewares: ReadonlySet<unknown>;
        };
      };
    };
  };
}

export function assertSessionCapabilityClassified(api: SweepableApi): void {
  const unauthenticated = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
  for (const key of sessionAllowed) {
    if (unauthenticated.has(key)) {
      throw new Error(
        `session capability sweep: "${key}" is listed as both session-allowed and unauthenticated`,
      );
    }
  }
  assertListedEndpointsConsistent(api);
  assertEveryEndpointClassified(api, unauthenticated);
}

function assertListedEndpointsConsistent(api: SweepableApi): void {
  for (const [groupName, endpointName] of SESSION_ALLOWED_ENDPOINTS) {
    if (!hasAuthMiddleware(requireEndpoint(api, groupName, endpointName))) {
      throw new Error(
        `session capability sweep: "${groupName}.${endpointName}" is session-allowed but does ` +
          `not carry AuthMiddleware — a session principal cannot exist there (AUTH_SPEC §5)`,
      );
    }
  }
  for (const [groupName, endpointName] of UNAUTHENTICATED_ENDPOINTS) {
    if (hasAuthMiddleware(requireEndpoint(api, groupName, endpointName))) {
      throw new Error(
        `session capability sweep: "${groupName}.${endpointName}" is listed as unauthenticated ` +
          `but carries AuthMiddleware — remove it from UNAUTHENTICATED_ENDPOINTS (AUTH_SPEC §5)`,
      );
    }
  }
}

function assertEveryEndpointClassified(
  api: SweepableApi,
  unauthenticated: ReadonlySet<string>,
): void {
  forEachEndpoint(api, (key, endpoint) => {
    if (!hasAuthMiddleware(endpoint) && !unauthenticated.has(key)) {
      throw new Error(
        `session capability sweep: "${key}" carries no AuthMiddleware and is not classified — ` +
          `declare AuthMiddleware on it or, if it is deliberately unauthenticated, add it to ` +
          `UNAUTHENTICATED_ENDPOINTS (AUTH_SPEC §5)`,
      );
    }
  });
}

function hasAuthMiddleware(endpoint: { readonly middlewares: ReadonlySet<unknown> }): boolean {
  return endpoint.middlewares.has(AuthMiddleware);
}

function requireEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  return requireRegisteredEndpoint(api, "session capability sweep", groupName, endpointName);
}
