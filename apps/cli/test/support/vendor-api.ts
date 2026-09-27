// "Honest" in-memory mocks of the vendor APIs (the targets of `maruhi sync`'s
// http driver): accepted upserts / deletions advance the state and are
// reflected in the next list / next write. Responses are not hand-assembled —
// they come back in the real wire shapes (verified against wrangler 4.128.0 /
// Vercel CLI 59.11.7 / the public REST docs).
//
// For assertions, the accepted requests (headers + body) and the stored values
// are exposed — evidence for tests to state that "the value only appears at
// fixed positions in the body, never in URLs, headers, or logs".

import type { MockHandler, MockRequest, MockResponse } from "./server.ts";

/** An injected response (undefined = accept normally). Switched by call count. */
export type VendorOverride = (
  call: number,
  request: MockRequest,
) =>
  | { readonly status: number; readonly json?: unknown; readonly headers?: Record<string, string> }
  | undefined;

/** The fake Cloudflare Workers API (`PATCH …/secrets-bulk`). */
export interface FakeCloudflare {
  readonly handlers: readonly MockHandler[];
  /** account → script → secret name → value. */
  readonly secrets: Map<string, Map<string, string>>;
  readonly requests: MockRequest[];
}

const CF_BULK = /^\/client\/v4\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/secrets-bulk$/;

/** Cloudflare's envelope. */
function envelope(success: boolean, result: unknown, errors: { code: number; message: string }[]) {
  return { success, errors, messages: [], result };
}

export function makeFakeCloudflare(input: {
  readonly token: string;
  /** Existing Workers (account/script). Writes to a missing script get 10007. */
  readonly scripts: readonly string[];
  readonly override?: VendorOverride;
}): FakeCloudflare {
  const secrets = new Map<string, Map<string, string>>();
  for (const script of input.scripts) {
    secrets.set(script, new Map());
  }
  const requests: MockRequest[] = [];
  let calls = 0;
  const handlers: MockHandler[] = [
    (request) => {
      const match = request.path.match(CF_BULK);
      if (request.method !== "PATCH" || match === null) {
        return null;
      }
      requests.push(request);
      calls += 1;
      const rejected = cloudflarePreflight(request, input.token, input.override?.(calls, request));
      if (rejected !== null) {
        return rejected;
      }
      const store = secrets.get(`${match[1]}/${match[2]}`);
      if (store === undefined) {
        return {
          status: 404,
          json: envelope(false, null, [
            { code: 10007, message: "workers.api.error.script_not_found" },
          ]),
        };
      }
      return { status: 200, json: envelope(true, applyMergePatch(store, request.body), []) };
    },
  ];
  return { handlers, secrets, requests };
}

/** Preliminaries: injected response, auth, Content-Type (null = pass). */
function cloudflarePreflight(
  request: MockRequest,
  token: string,
  forced: ReturnType<VendorOverride>,
): MockResponse | null {
  if (forced !== undefined) {
    return {
      status: forced.status,
      json: forced.json ?? envelope(false, null, [{ code: 0, message: "forced" }]),
      headers: forced.headers ?? {},
    };
  }
  if (request.headers["authorization"] !== `Bearer ${token}`) {
    return {
      status: 400,
      json: envelope(false, null, [{ code: 6003, message: "Invalid request headers" }]),
    };
  }
  if (!String(request.headers["content-type"]).startsWith("application/merge-patch+json")) {
    return { status: 415, json: envelope(false, null, [{ code: 0, message: "bad content type" }]) };
  }
  return null;
}

/** Applies a merge-patch's `secrets` to the stored state (null = delete). The result is name → meta. */
function applyMergePatch(store: Map<string, string>, body: unknown): Record<string, unknown> {
  const patch = body as { secrets?: Record<string, { text?: string } | null> };
  const result: Record<string, unknown> = {};
  for (const [name, entry] of Object.entries(patch.secrets ?? {})) {
    if (entry === null) {
      store.delete(name);
    } else {
      store.set(name, String(entry.text));
      result[name] = { name, type: "secret_text" };
    }
  }
  return result;
}

/** One Vercel variable (the sync destination's stored shape). */
export interface FakeVercelEnv {
  readonly id: string;
  readonly key: string;
  readonly value: string;
  readonly type: string;
  readonly target: readonly string[];
  readonly gitBranch?: string;
}

/** The fake Vercel API (`POST /v10/projects/{id}/env?upsert=true`, list, delete). */
export interface FakeVercel {
  readonly handlers: readonly MockHandler[];
  readonly envs: FakeVercelEnv[];
  readonly requests: MockRequest[];
}

const VERCEL_ENV = /^\/v10\/projects\/([^/]+)\/env$/;
const VERCEL_ENV_ID = /^\/v10\/projects\/([^/]+)\/env\/([^/]+)$/;

interface VercelEnvItem {
  readonly key: string;
  readonly value: string;
  readonly type: string;
  readonly target: string[];
  readonly gitBranch?: string;
}

interface VercelFailure {
  readonly error: { readonly code: string; readonly message: string; readonly key: string };
}

/** Preliminaries: injected response, auth (null = pass). */
function vercelPreflight(
  authorized: boolean,
  forced: ReturnType<VendorOverride>,
): MockResponse | null {
  if (forced !== undefined) {
    return {
      status: forced.status,
      json: forced.json ?? { error: { code: "forced", message: "forced" } },
      headers: forced.headers ?? {},
    };
  }
  return authorized
    ? null
    : { status: 403, json: { error: { code: "forbidden", message: "Not authorized" } } };
}

/** List (filtered by target / gitBranch). Returns values (except sensitive) — evidence that the driver does not read values. */
function listEnvs(
  envs: readonly FakeVercelEnv[],
  query: Readonly<Record<string, string>>,
): readonly Record<string, unknown>[] {
  const target = query["target"];
  const gitBranch = query["gitBranch"];
  return envs
    .filter((env) => target === undefined || env.target.includes(target))
    .filter((env) => gitBranch === undefined || env.gitBranch === gitBranch)
    .map((env) => ({ ...env, value: env.type === "sensitive" ? undefined : env.value }));
}

/** One request's worth of upserts (array / single item). */
function upsertAll(
  envs: FakeVercelEnv[],
  items: readonly VercelEnvItem[],
  policy: { readonly upsert: boolean; readonly rejectKeys: readonly string[] },
  nextId: () => string,
): { readonly created: FakeVercelEnv[]; readonly failed: VercelFailure[] } {
  const created: FakeVercelEnv[] = [];
  const failed: VercelFailure[] = [];
  for (const item of items) {
    const outcome = upsertEnv(envs, item, policy, nextId);
    if (outcome.kind === "created") {
      created.push(outcome.env);
    } else {
      failed.push(outcome.failure);
    }
  }
  return { created, failed };
}

/** A single upsert (update if it exists, create otherwise; rejected names go to failed). */
function upsertEnv(
  envs: FakeVercelEnv[],
  item: VercelEnvItem,
  policy: { readonly upsert: boolean; readonly rejectKeys: readonly string[] },
  nextId: () => string,
):
  | { readonly kind: "created"; readonly env: FakeVercelEnv }
  | { readonly kind: "failed"; readonly failure: VercelFailure } {
  if (policy.rejectKeys.includes(item.key)) {
    return {
      kind: "failed",
      failure: {
        error: {
          code: "INVALID_VALUE",
          message: `value rejected for ${item.key}: ${item.value}`,
          key: item.key,
        },
      },
    };
  }
  const index = envs.findIndex(
    (env) =>
      env.key === item.key &&
      env.gitBranch === item.gitBranch &&
      env.target.some((t) => item.target.includes(t)),
  );
  if (index >= 0) {
    if (!policy.upsert) {
      return {
        kind: "failed",
        failure: {
          error: { code: "ENV_ALREADY_EXISTS", message: "already exists", key: item.key },
        },
      };
    }
    const existing = envs[index] as FakeVercelEnv;
    const updated = { ...existing, value: item.value, type: item.type, target: item.target };
    envs[index] = updated;
    return { kind: "created", env: updated };
  }
  const env: FakeVercelEnv = {
    id: nextId(),
    key: item.key,
    value: item.value,
    type: item.type,
    target: item.target,
    ...(item.gitBranch === undefined ? {} : { gitBranch: item.gitBranch }),
  };
  envs.push(env);
  return { kind: "created", env };
}

export function makeFakeVercel(input: {
  readonly token: string;
  readonly projectId: string;
  readonly teamId?: string;
  readonly initial?: readonly FakeVercelEnv[];
  readonly override?: VendorOverride;
  /** Names to fail within one request (reproduces partial success). */
  readonly rejectKeys?: readonly string[];
  /** Claims the list has a continuation (`pagination.next` — reproduces the fail-closed path). */
  readonly paginated?: boolean;
}): FakeVercel {
  const envs: FakeVercelEnv[] = [...(input.initial ?? [])];
  const requests: MockRequest[] = [];
  let calls = 0;
  let nextId = envs.length + 1;
  const authorized = (request: MockRequest) =>
    request.headers["authorization"] === `Bearer ${input.token}` &&
    (input.teamId === undefined || request.query["teamId"] === input.teamId);
  /** Whether it targets `/v10/projects/{id}/env` (includes the recording / injection / auth preliminaries; null = pass). */
  const envCollection = (request: MockRequest, method: string): MockResponse | null | "skip" => {
    const match = request.path.match(VERCEL_ENV);
    if (request.method !== method || match === null || match[1] !== input.projectId) {
      return "skip";
    }
    requests.push(request);
    calls += 1;
    return vercelPreflight(authorized(request), input.override?.(calls, request));
  };
  const rejectKeys = input.rejectKeys ?? [];
  const handlers: MockHandler[] = [
    (request) => {
      const rejected = envCollection(request, "GET");
      if (rejected !== null) {
        return rejected === "skip" ? null : rejected;
      }
      return {
        status: 200,
        json: {
          envs: listEnvs(envs, request.query),
          ...(input.paginated === true
            ? { pagination: { count: envs.length, next: 1_700_000_000_000, prev: null } }
            : {}),
        },
      };
    },
    (request) => {
      const rejected = envCollection(request, "POST");
      if (rejected !== null) {
        return rejected === "skip" ? null : rejected;
      }
      const batch = Array.isArray(request.body);
      const { created, failed } = upsertAll(
        envs,
        (batch ? request.body : [request.body]) as VercelEnvItem[],
        { upsert: request.query["upsert"] === "true", rejectKeys },
        () => {
          nextId += 1;
          return `env_${nextId - 1}`;
        },
      );
      // created echoes the value (same as the real API) — evidence that the driver does not display it
      return { status: 201, json: { created: batch ? created : created[0], failed } };
    },
    (request) => {
      const match = request.path.match(VERCEL_ENV_ID);
      if (request.method !== "DELETE" || match === null || match[1] !== input.projectId) {
        return null;
      }
      requests.push(request);
      if (!authorized(request)) {
        return { status: 403, json: { error: { code: "forbidden", message: "Not authorized" } } };
      }
      const index = envs.findIndex((env) => env.id === match[2]);
      if (index < 0) {
        return { status: 404, json: { error: { code: "not_found", message: "no such env" } } };
      }
      const [removed] = envs.splice(index, 1);
      return { status: 200, json: removed };
    },
  ];
  return { handlers, envs, requests };
}

/** One context's value of one Netlify variable (the sync destination's stored shape). */
export interface FakeNetlifyValue {
  readonly id: string;
  readonly value: string;
  readonly context: string;
  readonly context_parameter?: string;
}

/** One Netlify variable (`envVar` — key / scopes / values / is_secret). */
export interface FakeNetlifyVar {
  readonly key: string;
  readonly scopes: readonly string[];
  readonly values: FakeNetlifyValue[];
  readonly is_secret: boolean;
}

/**
 * The fake Netlify API (shapes verified against swagger 2.57.1 and
 * netlify-cli):
 * `GET /api/v1/accounts/{account_id}/env?site_id=` (array), `POST …/env?site_id=`
 * (creates from an array. **An existing key is a 422** — the wording is the
 * real response reported in Netlify Support Forums #88738; not in swagger),
 * `PATCH …/env/{key}?site_id=` (creates / updates one context's value of an
 * existing key; missing key is 404),
 * `DELETE …/env/{key}?site_id=` (whole key), `DELETE …/env/{key}/value/{id}?site_id=`.
 * List / create / update responses echo values (secret is empty — the real API
 * "does not return" it).
 */
export interface FakeNetlify {
  readonly handlers: readonly MockHandler[];
  /** key → variable (belonging to this site). */
  readonly vars: Map<string, FakeNetlifyVar>;
  readonly requests: MockRequest[];
}

const NETLIFY_ENV = /^\/api\/v1\/accounts\/([^/]+)\/env$/;
const NETLIFY_KEY = /^\/api\/v1\/accounts\/([^/]+)\/env\/([^/]+)$/;
const NETLIFY_VALUE = /^\/api\/v1\/accounts\/([^/]+)\/env\/([^/]+)\/value\/([^/]+)$/;

function netlifyError(status: number, message: string): MockResponse {
  return { status, json: { code: status, message } };
}

/** The list / response shape (secret values are masked — the real API doesn't return them). */
function netlifyView(variable: FakeNetlifyVar): Record<string, unknown> {
  return {
    ...variable,
    values: variable.values.map((value) => ({
      ...value,
      value: variable.is_secret && value.context !== "dev" ? "" : value.value,
    })),
  };
}

export function makeFakeNetlify(input: {
  readonly token: string;
  readonly accountId: string;
  readonly siteId: string;
  readonly initial?: readonly FakeNetlifyVar[];
  readonly override?: VendorOverride;
  /** Names for which creation (POST) fails (reproduces partial success). */
  readonly rejectKeys?: readonly string[];
  /** Returns 503 **after** storing the first accepted create (POST) (reproduces a lost response). */
  readonly loseFirstCreateResponse?: boolean;
}): FakeNetlify {
  const vars = new Map<string, FakeNetlifyVar>();
  for (const variable of input.initial ?? []) {
    vars.set(variable.key, { ...variable, values: [...variable.values] });
  }
  const requests: MockRequest[] = [];
  let calls = 0;
  let nextId = 1;
  let loseCreate = input.loseFirstCreateResponse === true;
  const newId = () => {
    nextId += 1;
    return `val_${nextId - 1}`;
  };
  /** Preliminaries: recording, injection, auth, site_id (null = pass). */
  const preflight = (request: MockRequest, accountId: string): MockResponse | null => {
    requests.push(request);
    calls += 1;
    const forced = input.override?.(calls, request);
    if (forced !== undefined) {
      return {
        status: forced.status,
        json: forced.json ?? { code: forced.status, message: "forced" },
        headers: forced.headers ?? {},
      };
    }
    if (request.headers["authorization"] !== `Bearer ${input.token}`) {
      return netlifyError(401, "Access Denied: Bad token");
    }
    if (accountId !== input.accountId || request.query["site_id"] !== input.siteId) {
      return netlifyError(404, "Not Found");
    }
    return null;
  };
  const handlers: MockHandler[] = [
    (request) => {
      const match = request.path.match(NETLIFY_ENV);
      if (match === null || (request.method !== "GET" && request.method !== "POST")) {
        return null;
      }
      const rejected = preflight(request, match[1] as string);
      if (rejected !== null) {
        return rejected;
      }
      if (request.method === "GET") {
        return { status: 200, json: [...vars.values()].map(netlifyView) };
      }
      const created = createVars(vars, request.body, input.rejectKeys ?? [], newId);
      if (created.status === 201 && loseCreate) {
        loseCreate = false;
        return {
          status: 503,
          json: { code: 503, message: "upstream timeout" },
          headers: { "retry-after": "0" },
        };
      }
      return created;
    },
    (request) => {
      const match = request.path.match(NETLIFY_KEY);
      if (match === null || (request.method !== "PATCH" && request.method !== "DELETE")) {
        return null;
      }
      const rejected = preflight(request, match[1] as string);
      if (rejected !== null) {
        return rejected;
      }
      const key = decodeURIComponent(match[2] as string);
      const variable = vars.get(key);
      if (variable === undefined) {
        return netlifyError(404, "Not Found");
      }
      if (request.method === "DELETE") {
        vars.delete(key);
        return { status: 204 };
      }
      return setValue(variable, request.body, newId);
    },
    (request) => {
      const match = request.path.match(NETLIFY_VALUE);
      if (match === null || request.method !== "DELETE") {
        return null;
      }
      const rejected = preflight(request, match[1] as string);
      if (rejected !== null) {
        return rejected;
      }
      const variable = vars.get(decodeURIComponent(match[2] as string));
      const index = variable?.values.findIndex((value) => value.id === match[3]) ?? -1;
      if (variable === undefined || index < 0) {
        return netlifyError(404, "Not Found");
      }
      variable.values.splice(index, 1);
      return { status: 204 };
    },
  ];
  return { handlers, vars, requests };
}

interface NetlifyCreateItem {
  readonly key: string;
  readonly scopes?: string[];
  readonly values: { value: string; context: string; context_parameter?: string }[];
  readonly is_secret?: boolean;
}

/** Reasons to refuse creation (existing key, rejected name). null = pass. */
function rejectCreate(
  vars: ReadonlyMap<string, FakeNetlifyVar>,
  item: NetlifyCreateItem,
  rejectKeys: readonly string[],
): MockResponse | null {
  if (vars.has(item.key)) {
    // The real wording (the response reported in Netlify Support Forums #88738; not in swagger)
    return netlifyError(
      422,
      "Environment variable with the same key name already exists on this site. Try a different key or edit the existing variable.",
    );
  }
  if (rejectKeys.includes(item.key)) {
    return netlifyError(422, `Value for ${item.key} is invalid: ${item.values[0]?.value ?? ""}`);
  }
  return null;
}

/** `POST …/env`: creates from an array (existing key = 422 [the reported real response], rejected name = 422; rejects the whole request). */
function createVars(
  vars: Map<string, FakeNetlifyVar>,
  body: unknown,
  rejectKeys: readonly string[],
  newId: () => string,
): MockResponse {
  if (!Array.isArray(body)) {
    return netlifyError(400, "expected an array of environment variables");
  }
  const items = body as NetlifyCreateItem[];
  for (const item of items) {
    const rejected = rejectCreate(vars, item, rejectKeys);
    if (rejected !== null) {
      return rejected;
    }
  }
  const created: FakeNetlifyVar[] = [];
  for (const item of items) {
    const variable: FakeNetlifyVar = {
      key: item.key,
      // Omitted scopes = Netlify's default (all scopes; the real spelling is post_processing)
      scopes: item.scopes ?? ["builds", "functions", "runtime", "post_processing"],
      values: item.values.map((value) => ({ ...value, id: newId() })),
      is_secret: item.is_secret ?? false,
    };
    vars.set(item.key, variable);
    created.push(variable);
  }
  return { status: 201, json: created.map(netlifyView) };
}

/** `PATCH …/env/{key}`: creates / replaces one context's value (the response echoes the whole variable). */
function setValue(variable: FakeNetlifyVar, body: unknown, newId: () => string): MockResponse {
  const patch = body as { context?: string; context_parameter?: string; value?: string };
  if (typeof patch.context !== "string" || typeof patch.value !== "string") {
    return netlifyError(400, "context and value are required");
  }
  if (patch.context === "branch" && typeof patch.context_parameter !== "string") {
    return netlifyError(400, "context_parameter is required for the branch context");
  }
  const index = variable.values.findIndex(
    (value) =>
      value.context === patch.context && value.context_parameter === patch.context_parameter,
  );
  const next: FakeNetlifyValue = {
    id: index >= 0 ? (variable.values[index] as FakeNetlifyValue).id : newId(),
    value: patch.value,
    context: patch.context,
    ...(patch.context_parameter === undefined
      ? {}
      : { context_parameter: patch.context_parameter }),
  };
  if (index >= 0) {
    variable.values[index] = next;
  } else {
    variable.values.push(next);
  }
  return { status: 201, json: netlifyView(variable) };
}
