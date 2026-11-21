import {
  AuthMiddleware,
  maruhiApi,
  SESSION_ALLOWED_ENDPOINTS,
  UNAUTHENTICATED_ENDPOINTS,
} from "@maruhi/api-schema";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

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
  proposalId: () => "00112233445566778899aabbccddeeff",
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

const SPEC_EXPLICIT_DENIALS: ReadonlyArray<readonly [string, string]> = [
  ["variables", "pull"],
  ["deks", "register"],
  ["deks", "listMine"],
  ["deks", "remove"],
  ["membership", "init"],
  ["membership", "append"],
  ["environments", "create"],
  ["environments", "rotate"],
  ["environments", "rename"],
  ["environments", "remove"],
  ["variables", "create"],
  ["variables", "push"],
  ["variables", "activate"],
  ["variables", "rename"],
  ["variables", "remove"],
  ["invites", "issue"],
  ["invites", "accept"],
  ["rotation", "dismiss"],
  ["auth", "recoveryPut"],
  ["auth", "recoveryGet"],
  ["schemaPolicy", "set"],
  ["devices", "register"],
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
    expect(denied.length).toBeGreaterThanOrEqual(SPEC_EXPLICIT_DENIALS.length);
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
      expect(response.status, `${key} must authenticate the session`).not.toBe(401);
    }
  });

  it("a token principal never gets session-not-allowed on any surface (the CLI unaffected regression)", async () => {
    const authenticated = listEndpoints().filter((endpoint) => endpoint.authenticated);
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
    const deniedWrite = await SELF.fetch(
      concreteUrl("/projects/:projectId/rotation/dismissals"),
      requestInit("POST", cookieOnly),
    );
    expect(deniedWrite.status).toBe(403);
    expect(((await deniedWrite.json()) as { reason?: string }).reason).toBe("session-not-allowed");
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
    const chain = await SELF.fetch(concreteUrl("/projects/:projectId/chain"), { headers });
    expect(chain.status).toBe(200);
    const projectList = await SELF.fetch(`${BASE}/projects`, { headers });
    expect(projectList.status).toBe(200);
    const environments = await SELF.fetch(concreteUrl("/projects/:projectId/environments"), {
      headers,
    });
    expect(environments.status).toBe(200);
    const flags = await SELF.fetch(concreteUrl("/projects/:projectId/rotation/flags"), {
      headers,
    });
    expect(flags.status).toBe(200);
    const body = (await chain.json()) as { headSeq: number };
    expect(body.headSeq).toBe(fixture.head.seq);
  });
});
