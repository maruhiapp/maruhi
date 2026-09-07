// ベンダー API(`maruhi sync` の http ドライバの宛先)の「正直な」インメモリ
// モック: 受理した upsert / 削除で状態を進め、次の一覧・次の書き込みに反映する。
// 応答を手で組み替えず、実物の wire 形(2026-09-07 に wrangler 4.128.0 / Vercel
// CLI 59.11.7 / 公開 REST docs で確かめた形)で返す。
//
// 検査用に、受理したリクエスト(ヘッダー・本文)と保存された値を公開する —
// 「値は本文の決まった位置にだけ現れ、URL・ヘッダー・ログには現れない」を
// テストが断言する材料。

import type { MockHandler, MockRequest, MockResponse } from "./server.ts";

/** 差し込み応答(undefined = 正常受理)。呼び出し回数で切り替える。 */
export type VendorOverride = (
  call: number,
  request: MockRequest,
) =>
  | { readonly status: number; readonly json?: unknown; readonly headers?: Record<string, string> }
  | undefined;

/** Cloudflare Workers の偽 API(`PATCH …/secrets-bulk`)。 */
export interface FakeCloudflare {
  readonly handlers: readonly MockHandler[];
  /** アカウント → スクリプト → 秘密名 → 値。 */
  readonly secrets: Map<string, Map<string, string>>;
  readonly requests: MockRequest[];
}

const CF_BULK = /^\/client\/v4\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/secrets-bulk$/;

/** Cloudflare の envelope。 */
function envelope(success: boolean, result: unknown, errors: { code: number; message: string }[]) {
  return { success, errors, messages: [], result };
}

export function makeFakeCloudflare(input: {
  readonly token: string;
  /** 存在する Worker(account/script)。無いスクリプトへの書き込みは 10007。 */
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

/** 差し込み応答・認証・Content-Type の前段(通れば null)。 */
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

/** merge-patch の `secrets` を保存状態へ適用する(null = 削除)。結果は名前 → メタ。 */
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

/** Vercel の 1 変数(同期先側の保存形)。 */
export interface FakeVercelEnv {
  readonly id: string;
  readonly key: string;
  readonly value: string;
  readonly type: string;
  readonly target: readonly string[];
  readonly gitBranch?: string;
}

/** Vercel の偽 API(`POST /v10/projects/{id}/env?upsert=true`、一覧、削除)。 */
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

/** 差し込み応答・認証の前段(通れば null)。 */
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

/** 一覧(target / gitBranch で絞る)。値を返す(sensitive 以外)— ドライバが値を読まないことの材料。 */
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

/** 1 リクエストぶんの upsert(配列 / 1 件)。 */
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

/** 1 件の upsert(既存があれば update、無ければ create。拒否名は failed)。 */
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
  /** 1 リクエストのうち失敗させる名前(部分成功の再現)。 */
  readonly rejectKeys?: readonly string[];
  /** 一覧に続きがあると申告する(`pagination.next` — fail-closed の再現)。 */
  readonly paginated?: boolean;
}): FakeVercel {
  const envs: FakeVercelEnv[] = [...(input.initial ?? [])];
  const requests: MockRequest[] = [];
  let calls = 0;
  let nextId = envs.length + 1;
  const authorized = (request: MockRequest) =>
    request.headers["authorization"] === `Bearer ${input.token}` &&
    (input.teamId === undefined || request.query["teamId"] === input.teamId);
  /** `/v10/projects/{id}/env` 宛か(記録・差し込み・認証の前段込み。通れば null)。 */
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
      // created は値を echo する(実物と同じ) — ドライバが表示しないことの材料
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
