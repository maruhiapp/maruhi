// Declaration of session-principal capability restriction (AUTH_SPEC
// §5 — W2b).
//
// The session cookie is the credential most exposed to XSS (a
// same-origin XSS can attach the CSRF header itself), so the endpoints
// a session principal may call are restricted by an **allowlist**.
// Anything unlisted is refused wholesale by AuthMiddleware (the single
// implementation point — apps/server's authMiddlewareImpl consults this
// module's predicate) with 403 `session-not-allowed` — fail-closed: a
// new endpoint defaults to "not callable by sessions", and opening one
// to sessions requires adding it to AUTH_SPEC §5's allowlist (a spec
// revision) and to this list in the same PR.
//
// The implementation form is the same shape as §12-10 (1)'s strict
// acceptance (declaration baked into the endpoint contract + load-time
// sweep + fixed tests of the acceptance path). But no AST annotation
// carries the behavior — an annotation can silently lapse under check
// composition order (the pitfall at the top of strict.ts) — so this
// module's list is the only source of truth for the declaration and the
// middleware references it directly by (group, endpoint) identifiers.
// Effectiveness (that a 403 is actually returned) is guaranteed by
// apps/server/test/session-capability.test.ts's matrix of every
// endpoint × principal kind (mechanically derived from api-schema's
// endpoint list).

import { AuthMiddleware } from "./auth-middleware.ts";
import { forEachEndpoint, requireRegisteredEndpoint } from "./sweep.ts";

/**
 * Endpoints a session principal may call (the implemented surface of
 * AUTH_SPEC §5's allowlist) — `[group, endpoint]` pairs:
 *
 * - Auth / self-info: `auth.me` / `auth.logout` / `auth.recoveryStatus` /
 *   `devices.list` (§13-11 — DK)
 *   (the §3 flow — githubStart / githubCallback — is the
 *   unauthenticated surface and outside this list)
 * - Reads: chain fetch (§11), project list (§11-5 — W2a), environment
 *   list (§12-4), metadata-only pull (§12-7), audit read (AUDIT_SPEC
 *   §7 — the project, invite.*, and self axes), the rotation-flag view,
 *   invite list (§15-2)
 * - Revocations: invite revoke (§15-2), targeted token revoke (§6 —
 *   W3a)
 *
 * The token list (`auth.listTokens` — §6's read surface) is included
 * here too. `audit.auditHead` is unlisted (no consumer on the Web —
 * session-39 §10-4).
 */
export const SESSION_ALLOWED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "me"],
    ["auth", "logout"],
    ["auth", "recoveryStatus"],
    // The ledger's status display (§13-7 — KL3; carries no wraps or
    // segments. Register / get / delete / approve are all device-only =
    // unlisted)
    ["keyWraps", "status"],
    // Reading the device registry (§13-11 — DK; only display names,
    // key FPs, and public keys — carries no secrets. Register / update /
    // delete / add requests are all device-only = unlisted)
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

/**
 * Endpoints that deliberately run **without** `AuthMiddleware`: the
 * unauthenticated surface (the AUTH_SPEC §3 / §4 authentication flows
 * themselves, and the lease surface whose credential is an OIDC token —
 * §14-1). Outside the scope of session-capability restriction (a
 * session principal cannot form there in the first place). Every API
 * endpoint must either "carry AuthMiddleware" or "be on this list",
 * and the sweep refuses dual membership and non-membership at load
 * time — fail-closed so that a new surface that dropped its middleware
 * declaration while meaning to require authentication never silently
 * becomes unauthenticated (and outside the session gate).
 */
export const UNAUTHENTICATED_ENDPOINTS: ReadonlyArray<readonly [group: string, endpoint: string]> =
  [
    ["auth", "authConfig"],
    ["auth", "githubStart"],
    ["auth", "githubCallback"],
    // CLI login (AUTH_SPEC §4): all 4 surfaces are unauthenticated —
    // the credentials are flow credentials (flowToken / vsig /
    // single-use approval ticket), not a session (§4-1 (3) — never add
    // them to SESSION_ALLOWED_ENDPOINTS)
    ["authCli", "cliStart"],
    ["authCli", "cliVerify"],
    ["authCli", "cliApprove"],
    ["authCli", "cliPoll"],
    ["lease", "issue"],
  ];

const sessionAllowed = new Set(SESSION_ALLOWED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));

/**
 * Whether a session principal may call the endpoint (AUTH_SPEC §5). The
 * middleware consults this for every authenticated request; everything outside
 * the allow-list is rejected with 403 `session-not-allowed` (fail-closed).
 */
export function isSessionAllowedEndpoint(group: string, endpoint: string): boolean {
  return sessionAllowed.has(`${group}.${endpoint}`);
}

/** The structural slice of an `HttpApi` the sweep walks (a structural type for the same reason as strict.ts). */
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

/**
 * Load-time sweep (AUTH_SPEC §5): asserts that the session-capability
 * declaration matches the registered API —
 *
 * 1. every `SESSION_ALLOWED_ENDPOINTS` entry names a real endpoint that
 *    carries `AuthMiddleware` (refuses allowlist entries that are
 *    stale, renamed, or point at the unauthenticated surface)
 * 2. every endpoint without `AuthMiddleware` is consciously listed in
 *    `UNAUTHENTICATED_ENDPOINTS`, and no listed one carries it (drops,
 *    at load time, the shape where a new surface meant to require
 *    authentication dropped its middleware declaration)
 *
 * There is no explicit enumeration of the refused surface because the
 * middleware-side predicate structurally carries the default refusal
 * (session outside the allowlist = 403) — the matrix test guarantees
 * the refusal's effectiveness.
 */
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

/** Consistency of listed surfaces actually existing + carrying / not carrying AuthMiddleware (sweep items 1–2). */
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

/** The reverse-direction fail-closed check (latter half of sweep item 2): complete classification of the no-middleware surface. */
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

/** Existence check for a single list entry: requires the group and endpoint to exist. */
function requireEndpoint(
  api: SweepableApi,
  groupName: string,
  endpointName: string,
): SweepableApi["groups"][string]["endpoints"][string] {
  return requireRegisteredEndpoint(api, "session capability sweep", groupName, endpointName);
}
