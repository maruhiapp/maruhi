// Pinned tests for the session principal's capability restriction
// (AUTH_SPEC §5).
//
// The allow / deny matrix of every endpoint × the session principal
// is **mechanically derived** from api-schema's endpoint
// enumeration (maruhiApi.groups — method, path, whether
// AuthMiddleware is present) and verified over the real workerd
// path — no hand-written endpoint list (structurally detects an
// undeclared surface, a stale baked-in allow decision, or a newly
// added surface slipping past the gate; the same "test the denial's
// behavior, not the presence of annotations/declarations"
// discipline as the §12-10 (1) strict pin).
//
// - authenticated surfaces outside the allowed enumeration
//   (SESSION_ALLOWED_ENDPOINTS): a uniform 403
//   `session-not-allowed`, even with the CSRF header
// - surfaces inside the allowed enumeration: no session-not-allowed
//   is returned (endpoint-specific semantics — 404 / 400 etc. — are
//   covered by each existing suite)
// - token principals: no surface ever returns session-not-allowed
//   (the CLI unaffected regression)
// - classification consistency with the unauthenticated surfaces
//   (UNAUTHENTICATED_ENDPOINTS) is already checked by api-schema's
//   load-time sweep at import (this file's very import is that
//   execution)

import {
  AuthMiddleware,
  maruhiApi,
  SESSION_ALLOWED_ENDPOINTS,
  UNAUTHENTICATED_ENDPOINTS,
} from "@maruhi/api-schema";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { BASE, bearer, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import { OWNER, projectId } from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token, VAR } from "./support/data-scenario.ts";

registerDataScenario();

interface EndpointInfo {
  readonly group: string;
  readonly name: string;
  readonly method: string;
  readonly path: string;
  readonly authenticated: boolean;
}

/** Mechanical enumeration of every endpoint registered in api-schema (walks groups via the structural type). */
function listEndpoints(): EndpointInfo[] {
  const api = maruhiApi as unknown as {
    readonly groups: {
      readonly [group: string]: {
        readonly endpoints: {
          readonly [endpoint: string]: {
            readonly method: string;
            readonly path: string;
            readonly middlewares: ReadonlySet<unknown>;
          };
        };
      };
    };
  };
  const endpoints: EndpointInfo[] = [];
  for (const [group, groupValue] of Object.entries(api.groups)) {
    for (const [name, endpoint] of Object.entries(groupValue.endpoints)) {
      endpoints.push({
        group,
        name,
        method: endpoint.method,
        path: endpoint.path,
        authenticated: endpoint.middlewares.has(AuthMiddleware),
      });
    }
  }
  return endpoints;
}

/**
 * Concretizing path parameters. Uses the real project (the fixture
 * — OWNER is the chain owner) so that verifying an allowed surface
 * reaches the endpoint body rather than stopping at the scope check
 * (404). An unknown parameter name is fail-loud (a newly added
 * surface is forced to append here).
 */
/**
 * The path-parameter substitution table. Ones that need not exist
 * are fine at 404 = not session-not-allowed (tokenId / wrapId /
 * groupId = ULID shape; requestId = handoff-request id [SHA-256 hex
 * — AUTH_SPEC §13-7]; fp = device-key fingerprint [§13-11]).
 */
const PATH_PARAM_SUBSTITUTIONS: Readonly<Record<string, () => string>> = {
  projectId: () => projectId,
  environmentId: () => ENV,
  variableId: () => VAR,
  id: () => "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  tokenId: () => "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  wrapId: () => "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  groupId: () => "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  requestId: () => "ab".repeat(32),
  fp: () => "ab".repeat(16),
};

function concreteUrl(path: string): string {
  const substituted = path.replace(/:(\w+)/g, (_m, param: string) => {
    const substitute = PATH_PARAM_SUBSTITUTIONS[param];
    if (substitute === undefined) {
      throw new Error(`session-capability matrix: no substitution for path param :${param}`);
    }
    return substitute();
  });
  return `${BASE}${substituted}`;
}

function requestInit(method: string, headers: Record<string, string>): RequestInit {
  if (method === "GET" || method === "HEAD") {
    return { method, headers };
  }
  // A dummy body suffices: the capability judgment (middleware)
  // runs before payload decode, so a denied surface does not depend
  // on the body's content. For allowed / token surfaces, a 400 or
  // other non-session-not-allowed response is enough (the happy
  // paths are covered by existing suites)
  return { method, headers: { ...JSON_HEADERS, ...headers }, body: "{}" };
}

const isRevokeToken = (endpoint: EndpointInfo): boolean =>
  `${endpoint.group}.${endpoint.name}` === "auth.revokeToken";

async function isSessionDenied(response: Response): Promise<boolean> {
  if (response.status !== 403) {
    return false;
  }
  const body = (await response.json()) as { reason?: string };
  return body.reason === "session-not-allowed";
}

const allowedKeys = new Set(SESSION_ALLOWED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));
const unauthenticatedKeys = new Set(UNAUTHENTICATED_ENDPOINTS.map(([g, e]) => `${g}.${e}`));

/**
 * The implemented surfaces §5 enumerates as explicit denials (a pin
 * against the spec text). Independent of the derived matrix, this
 * pins at text level any regression where these slip into the
 * allowed enumeration.
 */
const SPEC_EXPLICIT_DENIALS: ReadonlyArray<readonly [string, string]> = [
  ["variables", "pull"], // the bulk pull carrying values (§12-7)
  ["deks", "register"], // DEK registration (§12-6)
  ["deks", "listMine"], // DEK fetching (§12-6)
  ["deks", "remove"], // DEK deletion (§12-6 — the only destructive op with no signature)
  ["membership", "init"], // chain init (§11)
  ["membership", "append"], // chain append (§11)
  ["environments", "create"],
  ["environments", "rotate"],
  ["environments", "rename"],
  ["environments", "remove"],
  ["variables", "create"],
  ["variables", "push"],
  ["variables", "activate"], // the activation composite (§12-5 — a variable mutation class)
  ["variables", "rename"],
  ["variables", "remove"],
  ["invites", "issue"], // invite issuance (§15-2)
  ["invites", "accept"], // invite acceptance (§15-2)
  ["rotation", "dismiss"], // rotation dismiss (AUDIT_SPEC §7)
  ["auth", "recoveryPut"], // recovery-blob registration (§13-2)
  ["auth", "recoveryGet"], // recovery-blob fetch (§13-2)
  ["schemaPolicy", "set"], // schemaPolicy change (§12-11 — session principals are stated to be denied)
  ["devices", "register"], // device-registry registration (§13-11 — sessions may only list)
  ["devices", "remove"],
  ["devices", "requestCreate"],
  ["devices", "requestList"],
  ["devices", "requestGet"],
  ["devices", "requestCancel"],
];

describe("the session principal's capability matrix (AUTH_SPEC §5 — mechanically derived)", () => {
  it("§5's explicitly denied surfaces are not in the allowed enumeration (a pin against the spec text)", () => {
    for (const [group, name] of SPEC_EXPLICIT_DENIALS) {
      expect(allowedKeys.has(`${group}.${name}`), `${group}.${name} must not be allowed`).toBe(
        false,
      );
    }
  });

  it("the authenticated/unauthenticated split covers every endpoint (derivation completeness)", () => {
    const endpoints = listEndpoints();
    expect(endpoints.length).toBeGreaterThan(0);
    for (const endpoint of endpoints) {
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(endpoint.authenticated, `${key} classification`).toBe(!unauthenticatedKeys.has(key));
      if (allowedKeys.has(key)) {
        expect(endpoint.authenticated, `${key} must carry AuthMiddleware`).toBe(true);
      }
    }
  });

  it("every authenticated surface outside the allowed enumeration is a uniform 403 session-not-allowed for a session principal (even with the CSRF header)", async () => {
    const denied = listEndpoints().filter(
      (endpoint) =>
        endpoint.authenticated && !allowedKeys.has(`${endpoint.group}.${endpoint.name}`),
    );
    // The fail-closed target set is not empty (detects the shape
    // where the derivation broke and collapsed to allow-all)
    expect(denied.length).toBeGreaterThanOrEqual(SPEC_EXPLICIT_DENIALS.length);
    // Reuse one session, since denied surfaces cannot revoke it
    // (every surface is denied)
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);
    for (const endpoint of denied) {
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, headers),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(response.status, `${key} must be 403 for a session principal`).toBe(403);
      const body = (await response.json()) as { reason?: string };
      expect(body.reason, `${key} must be denied by the §5 capability gate`).toBe(
        "session-not-allowed",
      );
    }
  });

  it("no surface in the allowed enumeration returns session-not-allowed to a session principal", async () => {
    const allowed = listEndpoints().filter((endpoint) =>
      allowedKeys.has(`${endpoint.group}.${endpoint.name}`),
    );
    // The load-time sweep already reconciled the allowed
    // enumeration's declaration (api-schema) against the registered
    // surfaces. Here the behavioral side: the gate must not deny an
    // allowed surface by mistake. A fresh session per surface, since
    // logout revokes the session
    expect(allowed.length).toBe(SESSION_ALLOWED_ENDPOINTS.length);
    for (const endpoint of allowed) {
      const session = await loginSession(9001);
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, sessionHeaders(session)),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(
        await isSessionDenied(response),
        `${key} must not be rejected by the §5 capability gate`,
      ).toBe(false);
      // A coarse sanity check that allowed surfaces are not all
      // failing for other reasons (a 401 would mean session
      // resolution regressed)
      expect(response.status, `${key} must authenticate the session`).not.toBe(401);
    }
  });

  it("a token principal never gets session-not-allowed on any surface (the CLI unaffected regression)", async () => {
    const authenticated = listEndpoints().filter((endpoint) => endpoint.authenticated);
    // auth.revokeToken revokes the presented token itself, so it
    // goes last and the other surfaces are verified with a live
    // token
    const endpoints = [
      ...authenticated.filter((endpoint) => !isRevokeToken(endpoint)),
      ...authenticated.filter(isRevokeToken),
    ];
    const pat = token(OWNER);
    for (const endpoint of endpoints) {
      const response = await SELF.fetch(
        concreteUrl(endpoint.path),
        requestInit(endpoint.method, bearer(pat)),
      );
      const key = `${endpoint.group}.${endpoint.name}`;
      expect(
        await isSessionDenied(response),
        `${key} must not apply the session gate to a token principal`,
      ).toBe(false);
    }
  });

  it("the capability judgment precedes the CSRF check (a denied surface is session-not-allowed even without the header)", async () => {
    const session = await loginSession(9001);
    const cookieOnly = { cookie: sessionHeaders(session)["cookie"] ?? "" };
    // A denied surface (a write): a uniform session-not-allowed even
    // without the CSRF header
    const deniedWrite = await SELF.fetch(
      concreteUrl("/projects/:projectId/rotation/dismissals"),
      requestInit("POST", cookieOnly),
    );
    expect(deniedWrite.status).toBe(403);
    expect(((await deniedWrite.json()) as { reason?: string }).reason).toBe("session-not-allowed");
    // On an allowed surface (a write = logout) the CSRF check is
    // alive (not removed)
    const allowedWrite = await SELF.fetch(`${BASE}/auth/logout`, {
      method: "POST",
      headers: cookieOnly,
    });
    expect(allowedWrite.status).toBe(403);
    expect(((await allowedWrite.json()) as { reason?: string }).reason).toBe(
      "csrf-header-required",
    );
  });

  it("representative allowed surfaces (reads) actually succeed under a session (positive control)", async () => {
    const session = await loginSession(9001);
    const headers = sessionHeaders(session);
    // Chain fetch (§11) — the fixture's OWNER is a chain-derived member
    const chain = await SELF.fetch(concreteUrl("/projects/:projectId/chain"), { headers });
    expect(chain.status).toBe(200);
    // Project list (§11-5)
    const projectList = await SELF.fetch(`${BASE}/projects`, { headers });
    expect(projectList.status).toBe(200);
    // Environment list (§12-4)
    const environments = await SELF.fetch(concreteUrl("/projects/:projectId/environments"), {
      headers,
    });
    expect(environments.status).toBe(200);
    // Rotation-needed flags (AUDIT_SPEC §4.1)
    const flags = await SELF.fetch(concreteUrl("/projects/:projectId/rotation/flags"), {
      headers,
    });
    expect(flags.status).toBe(200);
    // fixture.head is readable (a session read takes the same shape
    // as a token's)
    const body = (await chain.json()) as { headSeq: number };
    expect(body.headSeq).toBe(fixture.head.seq);
  });
});
