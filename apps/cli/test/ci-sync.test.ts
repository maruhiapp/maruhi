// `maruhi ci sync <target>`(SY2 第 2 段 — 裁定 D)のテスト: OIDC リース(ci-lease.ts —
// `ci run` と同じ前段)→ 復号 → ドライバ(exec / http)。レシートは読まない・書かない
// (CI は §4.1 の署名鍵を持たない): 選択した変数の全件再適用で、削除は生まれない。
//
// リースは環境単位。http ドライバのトークンが別の環境にあれば 2 環境を **1 本の
// OIDC トークン・1 つの一時鍵**でリースする(AUTH_SPEC §14-1)。
// lease の偽装は ci-run.test.ts と同じ姿勢(実 crypto でリクエストの一時鍵へラップ)。

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  computeLeaseClaimsDigest,
  encodeHex,
  importEncryptionPublicKey,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { cliError } from "../src/errors.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer } from "./support/server.ts";
import { makeFakeCloudflare, makeFakeNetlify } from "./support/vendor-api.ts";

const SOURCE_ENV = "prod";
const TOKENS_ENV = "tokens";
const ISSUER = "https://token.actions.githubusercontent.com";
const RUNNER_TOKEN = "runner-request-token-value";
const ALPHA_VALUE = "alpha-value-ci";
const CF_TOKEN = "cf-token-ci-0123456789";
const CF_ACCOUNT = "acc42";

interface PullEntry {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

let owner: TestUser;
let built: BuiltChain;
const deks = new Map<string, Uint8Array>();
const envStatements = new Map<string, WireDistributedEnvironmentStatement>();
const entries = new Map<string, PullEntry[]>();
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  deks.set(SOURCE_ENV, crypto.getRandomValues(new Uint8Array(32)));
  deks.set(TOKENS_ENV, crypto.getRandomValues(new Uint8Array(32)));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(SOURCE_ENV, deks.get(SOURCE_ENV) as Uint8Array),
    },
    {
      actor: owner,
      operation: createEnvironmentOp(TOKENS_ENV, deks.get(TOKENS_ENV) as Uint8Array),
    },
    {
      actor: owner,
      operation: await grantServerOp(
        [SOURCE_ENV, TOKENS_ENV],
        [{ issuerUrl: ISSUER, audience: "https://maruhi.example", claimConstraints: [] }],
      ),
    },
  ]);
  const head = headOf(built, built.entries.length);
  const genesisHead = { seq: 1, hashHex: built.projectId };
  for (const environment of [SOURCE_ENV, TOKENS_ENV]) {
    envStatements.set(
      environment,
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: environment,
        name: environment,
        author: owner,
        head: genesisHead,
      }),
    );
  }
  const entry = async (
    environment: string,
    variableId: string,
    name: string,
    plaintext: string,
    version: number,
  ) => ({
    variableId,
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: environment,
      variableId,
      name,
      author: owner,
      head: genesisHead,
    }),
    value: await encryptValueFor({
      dek: deks.get(environment) as Uint8Array,
      projectId: built.projectId,
      environmentId: environment,
      epoch: 1,
      variableId,
      version,
      plaintext,
      writer: owner,
      head,
    }),
  });
  entries.set(SOURCE_ENV, [
    await entry(SOURCE_ENV, "va", "ALPHA", ALPHA_VALUE, 3),
    await entry(SOURCE_ENV, "vb", "BETA", "beta-value-ci", 1),
  ]);
  entries.set(TOKENS_ENV, [await entry(TOKENS_ENV, "tc", "CF_API_TOKEN", CF_TOKEN, 1)]);
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function fakeJwt(payload: Record<string, unknown>): string {
  return `${base64UrlJson({ alg: "RS256", kid: "k1" })}.${base64UrlJson(payload)}.c2lnbmF0dXJl`;
}

function jwtPayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1] ?? "";
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

/** GitHub Actions の OIDC 発行エンドポイントの偽装。 */
function oidcHandler(state: { issued: number }): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== "/oidc/token") {
      return null;
    }
    if (request.headers["authorization"] !== `Bearer ${RUNNER_TOKEN}`) {
      return { status: 401, json: { message: "bad runner token" } };
    }
    state.issued += 1;
    return {
      status: 200,
      json: {
        value: fakeJwt({
          iss: ISSUER,
          sub: `repo:acme/app:ref:refs/heads/main/run/${state.issued}`,
          aud: request.query["audience"] ?? "",
          jti: state.issued,
        }),
      },
    };
  };
}

async function leaseWrapFor(
  environment: string,
  body: { oidcToken: string; ephemeralPubHex: string },
) {
  const payload = jwtPayload(body.oidcToken);
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: String(payload["iss"]),
    subject: String(payload["sub"]),
    audience: String(payload["aud"]),
  });
  const publicKey = await importEncryptionPublicKey(hexBytes(body.ephemeralPubHex));
  if (!digest.ok || !publicKey.ok) {
    throw new Error("lease fixture failed");
  }
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: publicKey.value,
    dek: deks.get(environment) as Uint8Array,
    context: {
      projectId: built.projectId,
      environmentId: environment,
      epoch: 1,
      claimsDigestHex: digest.value,
    },
  });
  if (!wrapped.ok) {
    throw new Error("lease wrap failed");
  }
  return {
    suite: "maruhi/v1",
    epoch: 1,
    encHex: encodeHex(wrapped.value.enc),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

/** 環境ごとの lease ハンドラ(実 crypto でリクエストの一時鍵へラップ)。 */
function leaseHandler(environment: string, leased: { keys: string[] }): MockHandler {
  return async (request) => {
    if (
      request.method !== "POST" ||
      request.path !== `/projects/${built.projectId}/environments/${environment}/lease`
    ) {
      return null;
    }
    const body = request.body as { oidcToken: string; ephemeralPubHex: string };
    leased.keys.push(body.ephemeralPubHex);
    const variables = entries.get(environment) ?? [];
    return {
      status: 200,
      json: {
        projectId: built.projectId,
        environmentId: environment,
        currentEpoch: 1,
        chain: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
        statement: envStatements.get(environment),
        variables,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: built.projectId,
          environmentId: environment,
          epoch: 1,
          issuer: owner,
          head: headOf(built, built.entries.length),
          envStatement: envStatements.get(environment) as WireDistributedEnvironmentStatement,
          statements: variables.map((entry) => entry.statement),
        }),
        leases: [await leaseWrapFor(environment, body)],
      },
    };
  };
}

interface CiFixture {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly configPath: string;
  readonly leased: { keys: string[] };
  readonly oidc: { issued: number };
}

/** CI 環境: ログインも config もシードしない(CI モードの非依存はこの構成が固定する)。 */
async function startCi(input: {
  readonly targets: Record<string, unknown>;
  readonly environments: readonly string[];
  readonly vendorHandlers?: readonly MockHandler[];
}): Promise<CiFixture> {
  const oidc = { issued: 0 };
  const leased = { keys: [] as string[] };
  const server = await MockServer.start([
    oidcHandler(oidc),
    ...input.environments.map((environment) => leaseHandler(environment, leased)),
    ...(input.vendorHandlers ?? []),
  ]);
  servers.push(server);
  const env = await makeTestEnv();
  env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/token`);
  env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, RUNNER_TOKEN);
  env.setVendorOrigin("api.cloudflare.com", server.origin);
  env.setVendorOrigin("api.netlify.com", server.origin);
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-ci-sync-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  await writeFile(
    configPath,
    JSON.stringify({
      version: 1,
      receipts: { environment: "sync-receipts" },
      targets: input.targets,
    }),
  );
  return { env, server, configPath, leased, oidc };
}

function ciSync(fixture: CiFixture, target: string, ...extra: string[]): Promise<number> {
  return runCli(
    [
      "ci",
      "sync",
      target,
      "--server",
      fixture.server.origin,
      "--project",
      built.projectId,
      "--config",
      fixture.configPath,
      ...extra,
    ],
    fixture.env.layer,
  );
}

function expectNoSecretLeak(env: TestEnv, requests: readonly MockRequest[] = []): void {
  const shown = [
    ...env.logs,
    ...env.errors,
    ...requests.flatMap((request) => [request.path, JSON.stringify(request.query)]),
  ].join("\n");
  for (const secret of [ALPHA_VALUE, "beta-value-ci", CF_TOKEN, RUNNER_TOKEN]) {
    expect(shown).not.toContain(secret);
  }
}

describe("maruhi ci sync", () => {
  it("http(Workers): 同期元とトークン環境を 1 本のトークン・1 つの一時鍵でリースし、全件を書き、レシートは書かない・消さない", async () => {
    const cf = makeFakeCloudflare({ token: CF_TOKEN, scripts: [`${CF_ACCOUNT}/my-worker`] });
    const fixture = await startCi({
      environments: [SOURCE_ENV, TOKENS_ENV],
      targets: {
        worker: {
          preset: "cloudflare-workers",
          driver: "http",
          environment: SOURCE_ENV,
          variables: "all",
          token: { environment: TOKENS_ENV, name: "CF_API_TOKEN" },
          options: { accountId: CF_ACCOUNT, name: "my-worker" },
        },
      },
      vendorHandlers: cf.handlers,
    });
    expect(await ciSync(fixture, "worker", "--yes"), fixture.env.errors.join("\n")).toBe(0);
    // 2 環境のリース = 同じ一時鍵、OIDC トークンの発行は 1 回
    expect(fixture.leased.keys).toHaveLength(2);
    expect(new Set(fixture.leased.keys).size).toBe(1);
    expect(fixture.oidc.issued).toBe(1);
    expect((cf.requests[0] as MockRequest).body).toEqual({
      secrets: {
        ALPHA: { name: "ALPHA", text: ALPHA_VALUE, type: "secret_text" },
        BETA: { name: "BETA", text: "beta-value-ci", type: "secret_text" },
      },
    });
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("Last delivery: not tracked in CI (no receipt");
    expect(out).toContain("+ ALPHA\tversion 3 (new)");
    expect(out).toContain(
      "Applied to target worker: 2 variables written (no receipt is kept in CI, and nothing is deleted)",
    );
    // maruhi サーバーへの書き込み(レシート)は一切無い。読み取りも lease だけ
    const maruhiWrites = fixture.server.requests.filter(
      (request) =>
        request.method !== "GET" &&
        !request.path.endsWith("/lease") &&
        !request.path.includes("/secrets-bulk"),
    );
    expect(maruhiWrites).toEqual([]);
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env, cf.requests);
  });

  it("http(Netlify): 一覧で有無を引き、無い名前は POST・ある名前は PATCH を 1 変数ずつ。レシートは書かない・消さない", async () => {
    const netlify = makeFakeNetlify({
      token: CF_TOKEN,
      accountId: "my-team",
      siteId: "site-1",
      initial: [
        {
          key: "BETA",
          scopes: ["builds", "functions", "runtime"],
          values: [{ id: "v1", value: "old", context: "production" }],
          is_secret: true,
        },
      ],
    });
    const fixture = await startCi({
      environments: [SOURCE_ENV, TOKENS_ENV],
      targets: {
        site: {
          preset: "netlify",
          environment: SOURCE_ENV,
          variables: "all",
          token: { environment: TOKENS_ENV, name: "CF_API_TOKEN" },
          options: { accountId: "my-team", siteId: "site-1", context: "production" },
        },
      },
      vendorHandlers: netlify.handlers,
    });
    expect(await ciSync(fixture, "site", "--yes"), fixture.env.errors.join("\n")).toBe(0);
    expect(netlify.requests.map((request) => [request.method, request.path])).toEqual([
      ["GET", "/api/v1/accounts/my-team/env"],
      ["POST", "/api/v1/accounts/my-team/env"],
      ["PATCH", "/api/v1/accounts/my-team/env/BETA"],
    ]);
    expect(netlify.requests[1]?.body).toEqual([
      {
        key: "ALPHA",
        is_secret: true,
        scopes: ["builds", "functions", "runtime"],
        values: [{ context: "production", value: ALPHA_VALUE }],
      },
    ]);
    expect(netlify.vars.get("BETA")?.values).toEqual([
      { id: "v1", value: "beta-value-ci", context: "production" },
    ]);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target site: 2 variables written (no receipt is kept in CI, and nothing is deleted)",
    );
    expectNoSecretLeak(fixture.env, netlify.requests);
  });

  it("exec: リースした値をベンダー CLI の stdin に渡す(wrangler が CI に導入済みの形)", async () => {
    const fixture = await startCi({
      environments: [SOURCE_ENV],
      targets: {
        worker: {
          preset: "cloudflare-workers",
          environment: SOURCE_ENV,
          variables: ["ALPHA"],
          options: { environment: "staging" },
        },
      },
    });
    expect(await ciSync(fixture, "worker"), fixture.env.errors.join("\n")).toBe(0);
    expect(fixture.leased.keys).toHaveLength(1);
    expect(fixture.env.execCalls).toHaveLength(1);
    expect(fixture.env.execCalls[0]?.command).toEqual([
      "wrangler",
      "secret",
      "bulk",
      "--env",
      "staging",
    ]);
    expect(new TextDecoder().decode(fixture.env.execCalls[0]?.stdin)).toBe(
      JSON.stringify({ ALPHA: ALPHA_VALUE }),
    );
    expectNoSecretLeak(fixture.env);
  });

  it("exec(GitHub Actions): リースした値を `gh secret set` の stdin に渡す(ランナー同梱の gh。認証は step の GH_TOKEN が gh に届く形)", async () => {
    const fixture = await startCi({
      environments: [SOURCE_ENV],
      targets: {
        actions: {
          preset: "github-actions",
          environment: SOURCE_ENV,
          variables: ["ALPHA"],
          options: { environment: "staging" },
        },
      },
    });
    expect(await ciSync(fixture, "actions"), fixture.env.errors.join("\n")).toBe(0);
    expect(fixture.leased.keys).toHaveLength(1);
    expect(fixture.env.execCalls).toHaveLength(1);
    expect(fixture.env.execCalls[0]?.command).toEqual([
      "gh",
      "secret",
      "set",
      "ALPHA",
      "--env",
      "staging",
    ]);
    expect(new TextDecoder().decode(fixture.env.execCalls[0]?.stdin)).toBe(ALPHA_VALUE);
    // 子に足すのはテレメトリ off だけ(GH_TOKEN は step の env から継承 — live.ts の
    // buildChildEnvironment が MARUHI_* 以外を通す)
    expect(fixture.env.execCalls[0]?.extraEnv).toEqual({
      GH_TELEMETRY: "false",
      DO_NOT_TRACK: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      GH_PROMPT_DISABLED: "1",
    });
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target actions: 1 variable written (no receipt is kept in CI, and nothing is deleted)",
    );
    expectNoSecretLeak(fixture.env);
  });

  it("exec: 2 つ目の起動失敗はその呼び出しの失敗として届いた分を報告し、re-run を案内する(レシートは元々無い)", async () => {
    const fixture = await startCi({
      environments: [SOURCE_ENV],
      targets: {
        actions: {
          preset: "github-actions",
          environment: SOURCE_ENV,
          variables: "all",
          options: { environment: "staging" },
        },
      },
    });
    fixture.env.setExecHandler((_call, index) =>
      index === 0
        ? { exitCode: 0, output: "" }
        : cliError("Cannot start gh (ENOENT): is it installed and on PATH"),
    );
    expect(await ciSync(fixture, "actions")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "gh could not be started while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("  gh: Cannot start gh (ENOENT): is it installed and on PATH");
    expect(errors).toContain("re-run the job (every selected variable is written again)");
    expect(fixture.env.execCalls).toHaveLength(2);
    expectNoSecretLeak(fixture.env);
  });

  it("production ターゲットは --yes が無ければ plan だけを出して何も送らない", async () => {
    const fixture = await startCi({
      environments: [SOURCE_ENV],
      targets: {
        worker: { preset: "cloudflare-workers", environment: SOURCE_ENV, variables: "all" },
      },
    });
    expect(await ciSync(fixture, "worker")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Target worker is a production target, so apply needs an explicit --yes. Review the plan above, then re-run `maruhi ci sync worker --yes`",
    );
    expect(fixture.env.execCalls).toEqual([]);
  });

  it("フラグの欠落・設定の project との食い違いは書き方の誤り(2)で、ネットワークに行かない", async () => {
    const fixture = await startCi({
      environments: [SOURCE_ENV],
      targets: {
        worker: { preset: "cloudflare-workers", environment: SOURCE_ENV, variables: "all" },
      },
    });
    expect(
      await runCli(
        ["ci", "sync", "worker", "--project", built.projectId, "--config", fixture.configPath],
        fixture.env.layer,
      ),
    ).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "ci sync requires --server (CI mode reads no config file except the sync config — pass --server and --project explicitly in the workflow; the environment comes from the target)",
    );
    await writeFile(
      fixture.configPath,
      JSON.stringify({
        version: 1,
        project: "1".repeat(64),
        receipts: { environment: "sync-receipts" },
        targets: {
          worker: { preset: "cloudflare-workers", environment: SOURCE_ENV, variables: "all" },
        },
      }),
    );
    expect(await ciSync(fixture, "worker", "--yes")).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "--project does not match the `project` in the sync config",
    );
    expect(fixture.server.requests).toEqual([]);
  });

  it("トークン環境がリースポリシーの外(404 一様応答)なら lease の案内で止め、何も送らない", async () => {
    const fixture = await startCi({
      // tokens 環境の lease は一様な 404(AUTH_SPEC §14-1 の存在秘匿の形)
      environments: [SOURCE_ENV],
      vendorHandlers: [
        (request) =>
          request.method === "POST" &&
          request.path === `/projects/${built.projectId}/environments/${TOKENS_ENV}/lease`
            ? { status: 404, json: { _tag: "ProjectNotFound", projectId: built.projectId } }
            : null,
      ],
      targets: {
        worker: {
          preset: "cloudflare-workers",
          driver: "http",
          environment: SOURCE_ENV,
          variables: "all",
          token: { environment: TOKENS_ENV, name: "CF_API_TOKEN" },
          options: { accountId: CF_ACCOUNT, name: "my-worker" },
        },
      },
    });
    expect(await ciSync(fixture, "worker", "--yes")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("The server answered 404 for the lease");
    expect(
      fixture.server.requests.filter((request) => request.path.includes("secrets-bulk")),
    ).toEqual([]);
  });
});
