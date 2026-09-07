// `maruhi sync` の http ドライバ(SY2 第 2 段)のテスト: 宣言的プリセットの
// 組み立て(値は本文のエントリにしか置けない — sync-http.ts)と、偽ベンダー API
// (test/support/vendor-api.ts — 状態つき)に対する `sync apply` の通し。
//
// 固定する性質: 値とトークンが URL・ヘッダー(Authorization 以外)・stdout・stderr・
// エラー文面に出ない、リクエスト本文の形(Workers = merge-patch の secrets /
// Vercel = 配列 + upsert)、削除の表現(Workers = null / Vercel = 一覧 → DELETE)、
// 429 / 5xx のリトライ、失敗応答の伏せ字化(値・トークンの echo)、Worker 不在
// (10007)の案内、部分成功(Vercel の failed)を名前で割ってレシートに残す、
// 統合トークンは同期先へ運ばない、plan はベンダー API に触れない。

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { parseSyncConfig, type SyncTarget } from "../src/sync-config.ts";
import { buildBatches, HTTP_PRESETS, type PathToken } from "../src/sync-http.ts";
import { receiptVariableName } from "../src/sync-receipt.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockRequest, MockServer } from "./support/server.ts";
import { makeValueEnvironmentServer, type StoredVariable } from "./support/value-env.ts";
import { makeFakeCloudflare, makeFakeVercel, type VendorOverride } from "./support/vendor-api.ts";

const SOURCE_ENV = "prod";
const TOKENS_ENV = "tokens";
const RECEIPTS_ENV = "sync-receipts";
const ALPHA_VALUE = "alpha-value-3";
const BETA_VALUE = "beta line 1\nbeta line 2\n";
const CF_TOKEN = "cf-token-0123456789abcdef";
const VERCEL_TOKEN = "vercel-token-fedcba9876543210";
const SECRETS = [ALPHA_VALUE, "beta line 1", "beta line 2", CF_TOKEN, VERCEL_TOKEN];

let owner: TestUser;
let built: BuiltChain;
const deks = new Map<string, Uint8Array>();
const wraps = new Map<string, WireRecipientDek>();
const statements = new Map<string, WireDistributedEnvironmentStatement>();
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  for (const environment of [SOURCE_ENV, TOKENS_ENV, RECEIPTS_ENV]) {
    deks.set(environment, crypto.getRandomValues(new Uint8Array(32)));
  }
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
      operation: createEnvironmentOp(RECEIPTS_ENV, deks.get(RECEIPTS_ENV) as Uint8Array),
    },
  ]);
  for (const environment of [SOURCE_ENV, TOKENS_ENV, RECEIPTS_ENV]) {
    wraps.set(
      environment,
      await wrapDekFor({
        projectId: built.projectId,
        recipient: owner,
        signer: owner,
        epoch: 1,
        environmentId: environment,
        dek: deks.get(environment) as Uint8Array,
      }),
    );
    statements.set(
      environment,
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: environment,
        name: environment,
        author: owner,
        head: { seq: 1, hashHex: built.projectId },
      }),
    );
  }
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function variable(input: {
  readonly environment: string;
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
}): Promise<StoredVariable> {
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: input.environment,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await encryptValueFor({
    dek: deks.get(input.environment) as Uint8Array,
    projectId: built.projectId,
    environmentId: input.environment,
    epoch: 1,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    // 全環境が作られた後のヘッド(環境ごとの作成位置 2 / 3 / 4 を跨ぐ)
    head: headOf(built, built.entries.length),
  });
  return { variableId: input.variableId, statement, value };
}

async function receiptVariable(input: {
  readonly target: string;
  readonly preset: "vercel" | "cloudflare-workers";
  readonly variables: Readonly<Record<string, number>>;
}): Promise<StoredVariable> {
  return variable({
    environment: RECEIPTS_ENV,
    variableId: `receipt-${input.target}`,
    name: receiptVariableName(input.target),
    version: 1,
    plaintext: JSON.stringify({
      version: 1,
      target: input.target,
      preset: input.preset,
      syncedAt: "2026-09-05T00:00:00.000Z",
      variables: input.variables,
    }),
  });
}

interface Fixture {
  readonly env: TestEnv;
  readonly configPath: string;
  readonly maruhi: MockServer;
  readonly receipts: ReturnType<typeof makeValueEnvironmentServer>["state"];
}

const CF_ACCOUNT = "acc0123456789";

function cloudflareTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "cloudflare-workers",
    driver: "http",
    environment: SOURCE_ENV,
    variables: "all",
    token: { environment: TOKENS_ENV, name: "CF_API_TOKEN" },
    options: { accountId: CF_ACCOUNT, name: "my-worker", environment: "staging" },
    ...overrides,
  };
}

function vercelTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    driver: "http",
    environment: SOURCE_ENV,
    variables: ["ALPHA", "BETA"],
    token: { environment: TOKENS_ENV, name: "VERCEL_TOKEN" },
    options: { environment: "preview", projectId: "prj_123", teamId: "team_9" },
    ...overrides,
  };
}

async function startFixture(input: {
  readonly targets: Record<string, unknown>;
  readonly sourceVariables?: readonly StoredVariable[];
  readonly tokenVariables?: readonly StoredVariable[];
  readonly receipts?: readonly StoredVariable[];
  readonly vendorHandlers: readonly Parameters<typeof MockServer.start>[0][number][];
  readonly vendorHosts: readonly string[];
}): Promise<Fixture> {
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: statements.get(SOURCE_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(SOURCE_ENV) as WireRecipientDek,
    initialVariables:
      input.sourceVariables ??
      (await Promise.all([
        variable({
          environment: SOURCE_ENV,
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        variable({
          environment: SOURCE_ENV,
          variableId: "vb",
          name: "BETA",
          version: 1,
          plaintext: BETA_VALUE,
        }),
      ])),
  });
  const tokens = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: TOKENS_ENV,
    envStatement: statements.get(TOKENS_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(TOKENS_ENV) as WireRecipientDek,
    initialVariables:
      input.tokenVariables ??
      (await Promise.all([
        variable({
          environment: TOKENS_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: CF_TOKEN,
        }),
        variable({
          environment: TOKENS_ENV,
          variableId: "tv",
          name: "VERCEL_TOKEN",
          version: 2,
          plaintext: VERCEL_TOKEN,
        }),
      ])),
  });
  const receipts = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: RECEIPTS_ENV,
    envStatement: statements.get(RECEIPTS_ENV) as WireDistributedEnvironmentStatement,
    wrap: wraps.get(RECEIPTS_ENV) as WireRecipientDek,
    initialVariables: input.receipts ?? [],
  });
  const maruhi = await MockServer.start([
    ...source.handlers,
    ...tokens.handlers,
    ...receipts.handlers,
  ]);
  const vendor = await MockServer.start(input.vendorHandlers);
  servers.push(maruhi, vendor);
  const env = await makeTestEnv();
  for (const host of input.vendorHosts) {
    env.setVendorOrigin(host, vendor.origin);
  }
  seedSession(env, maruhi.origin, owner);
  await seedConfig(env, { server: maruhi.origin, defaultProject: built.projectId });
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-http-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  await writeFile(
    configPath,
    JSON.stringify({ version: 1, receipts: { environment: RECEIPTS_ENV }, targets: input.targets }),
  );
  return { env, configPath, maruhi, receipts: receipts.state };
}

function sync(fixture: Fixture, ...args: string[]): Promise<number> {
  return runCli(["sync", ...args, "--config", fixture.configPath], fixture.env.layer);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

/** 値とトークンが stdout / stderr / URL / ヘッダー(Authorization 以外)に出ない。 */
function expectNoSecretLeak(env: TestEnv, requests: readonly MockRequest[]): void {
  const shown = [
    allOutput(env),
    ...requests.flatMap((request) => [
      request.path,
      JSON.stringify(request.query),
      ...Object.entries(request.headers)
        .filter(([name]) => name !== "authorization")
        .map(([, value]) => String(value)),
    ]),
  ].join("\n");
  for (const secret of SECRETS) {
    expect(shown).not.toContain(secret);
  }
}

const decoder = new TextDecoder();

async function decryptReceipt(fixture: Fixture, target: string): Promise<Record<string, unknown>> {
  const stored = fixture.receipts.variables.find(
    (entry) => entry.statement.name === receiptVariableName(target),
  );
  expect(stored).toBeDefined();
  const value = stored?.value as WireEncryptedPayload;
  const result = await decryptVariable({
    dek: deks.get(RECEIPTS_ENV) as Uint8Array,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("receipt decrypt failed in test");
  }
  return JSON.parse(decoder.decode(result.value)) as Record<string, unknown>;
}

/** 1 変数の書き込み材料(バッチ分割の検査用)。 */
function write(name: string) {
  return {
    name,
    value: Redacted.make(new TextEncoder().encode(`v-${name}`), { label: "variable-value" }),
  };
}

/** 1 ターゲットの設定を厳格なパーサに通す(結果 or 理由)。 */
function base(target: Record<string, unknown>) {
  return parseSyncConfig(
    JSON.stringify({ version: 1, receipts: { environment: "r" }, targets: { t: target } }),
    "/repo",
  );
}

/** パーサの結果からターゲット t を取り出す(理由の文字列ならテストの前提違い)。 */
function targetOf(parsed: ReturnType<typeof base>): SyncTarget {
  if (typeof parsed === "string") {
    throw new Error(parsed);
  }
  return parsed.targets.get("t") as SyncTarget;
}

/** 最初の 1 回だけ 429(Retry-After: 0)を返す差し込み。 */
const rateLimitedOnce: VendorOverride = (call) =>
  call === 1 ? { status: 429, headers: { "retry-after": "0" } } : undefined;

describe("http プリセットの宣言", () => {
  it("パス・クエリのトークンに値と名前は存在しない(型で禁止 — 宣言を走査して確かめる)", () => {
    for (const preset of Object.values(HTTP_PRESETS)) {
      const tokens: PathToken[] = [
        ...preset.write.path,
        ...Object.values(preset.write.query),
        ...(preset.delete.kind === "lookup"
          ? [
              ...preset.delete.list.path,
              ...Object.values(preset.delete.list.query),
              ...preset.delete.remove.path,
              ...Object.values(preset.delete.remove.query),
            ]
          : []),
      ];
      for (const token of tokens) {
        if (typeof token === "string") {
          expect(token).not.toMatch(/value|secret=|text=/i);
        } else {
          expect(["option", "id"]).toContain(token.kind);
        }
      }
      // ホストは固定(設定で差し替えられない)
      expect(preset.host).toMatch(/^api\.(cloudflare|vercel)\.com$/);
    }
  });

  it("buildBatches: Workers は削除を書き込みに同居させて 100 件ごと、Vercel は 25 件ごと + 削除は 1 件ずつ", () => {
    const writes = Array.from({ length: 120 }, (_, index) => write(`V${index}`));
    const workers = buildBatches({
      preset: HTTP_PRESETS["cloudflare-workers"],
      writes,
      deletes: ["GONE"],
    });
    expect(workers.map((batch) => [batch.kind, batch.names.length])).toEqual([
      ["write", 100],
      ["write", 21],
    ]);
    expect(workers[1]?.deletes).toEqual(["GONE"]);
    const vercel = buildBatches({ preset: HTTP_PRESETS.vercel, writes, deletes: ["GONE", "OLD"] });
    expect(vercel.map((batch) => [batch.kind, batch.names.length])).toEqual([
      ["write", 25],
      ["write", 25],
      ["write", 25],
      ["write", 25],
      ["write", 20],
      ["delete", 1],
      ["delete", 1],
    ]);
  });

  it("設定: http は token 必須・cwd / command 不可、exec は token 不可。トークン変数は運ばない", () => {
    expect(base(cloudflareTarget({ token: undefined }))).toContain(
      "targets.t.token is required for the http driver",
    );
    expect(base(cloudflareTarget({ cwd: "x" }))).toContain(
      "targets.t.cwd applies only to the exec driver",
    );
    expect(base(cloudflareTarget({ driver: "exec", options: {} }))).toContain(
      "targets.t.token applies only to the http driver",
    );
    expect(base(cloudflareTarget({ driver: "ftp" }))).toContain('targets.t.driver must be "exec"');
    expect(base(cloudflareTarget({ options: { name: "w" } }))).toContain(
      "targets.t.options.accountId is required for the cloudflare-workers preset with the http driver",
    );
    expect(base(vercelTarget({ options: { environment: "preview", project: "x" } }))).toContain(
      "targets.t.options has unknown keys (project)",
    );
    // 同じ環境のトークンは "all" から黙って除き、明示リストにあれば設定の誤り
    const sameEnvAll = base(
      cloudflareTarget({ token: { environment: SOURCE_ENV, name: "CF_API_TOKEN" } }),
    );
    expect(typeof sameEnvAll).not.toBe("string");
    expect(targetOf(sameEnvAll).exclude).toEqual(["CF_API_TOKEN"]);
    expect(
      base(
        vercelTarget({
          variables: ["ALPHA", "VERCEL_TOKEN"],
          token: { environment: SOURCE_ENV, name: "VERCEL_TOKEN" },
        }),
      ),
    ).toContain("targets.t.variables lists the token variable");
    // 第 1 段の設定(driver 無し)はそのまま読める(後方互換)
    const legacy = base({
      preset: "vercel",
      environment: "p",
      variables: ["A"],
      options: { environment: "production" },
    });
    expect(typeof legacy).not.toBe("string");
    expect(targetOf(legacy).driver.kind).toBe("exec");
  });
});

describe("maruhi sync apply (http, Cloudflare Workers)", () => {
  it("merge-patch の secrets に値を置き、名前付き環境はスクリプト名に合成し、トークンは Authorization だけに載り、レシートを作る", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker"), fixture.env.errors.join("\n")).toBe(0);
    expect(cf.requests).toHaveLength(1);
    const request = cf.requests[0] as MockRequest;
    expect(request.path).toBe(
      `/client/v4/accounts/${CF_ACCOUNT}/workers/scripts/my-worker-staging/secrets-bulk`,
    );
    expect(request.headers["content-type"]).toBe("application/merge-patch+json");
    expect(request.headers["user-agent"]).toMatch(/^maruhi-cli\//);
    expect(request.body).toEqual({
      secrets: {
        ALPHA: { name: "ALPHA", text: ALPHA_VALUE, type: "secret_text" },
        BETA: { name: "BETA", text: BETA_VALUE, type: "secret_text" },
      },
    });
    expect(cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.get("BETA")).toBe(BETA_VALUE);
    expect(fixture.env.logs.join("\n")).toContain(
      "Sending to api.cloudflare.com with the token from variable CF_API_TOKEN in environment tokens",
    );
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target worker: 2 variables written, 0 deleted",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env, cf.requests);
    const receipt = await decryptReceipt(fixture, "worker");
    expect(receipt).toMatchObject({
      preset: "cloudflare-workers",
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("削除は同じリクエストの null で運び、plan はベンダー API に触れない", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.set("OLD", "old");
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      receipts: [
        await receiptVariable({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, OLD: 1 },
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "plan", "worker")).toBe(0);
    expect(cf.requests).toEqual([]);
    expect(fixture.env.logs.join("\n")).toContain(
      "- OLD\t(no longer synced; last delivered version 1)",
    );
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect((cf.requests[0] as MockRequest).body).toEqual({
      secrets: { BETA: { name: "BETA", text: BETA_VALUE, type: "secret_text" }, OLD: null },
    });
    expect(cf.secrets.get(`${CF_ACCOUNT}/my-worker-staging`)?.has("OLD")).toBe(false);
    expect(await decryptReceipt(fixture, "worker")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("Worker が無い(10007)なら draft を作らず、デプロイを案内して exit 1。値は伏せる", async () => {
    const cf = makeFakeCloudflare({ token: CF_TOKEN, scripts: [] });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "No Worker named my-worker-staging exists in this account. maruhi does not create one",
    );
    expect(errors).toContain("the Cloudflare API refused the request while writing ALPHA, BETA");
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env, cf.requests);
  });

  it("429 は Retry-After で待って再送し、5xx が続けば試行を使い切って exit 1(応答の echo は伏せる)", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
      override: rateLimitedOnce,
    });
    const fixture = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(cf.requests).toHaveLength(2);
    const echoing: VendorOverride = () => ({
      status: 503,
      json: {
        success: false,
        errors: [
          { code: 7000, message: `overloaded while storing ${ALPHA_VALUE} with ${CF_TOKEN}` },
        ],
        messages: [],
      },
      headers: { "retry-after": "0" },
    });
    const down = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
      override: echoing,
    });
    const fixture2 = await startFixture({
      targets: { worker: cloudflareTarget() },
      vendorHandlers: down.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture2, "apply", "worker")).toBe(1);
    expect(down.requests).toHaveLength(3);
    expect(fixture2.env.errors.join("\n")).toContain(
      "the Cloudflare API answered 503 (3 attempts)",
    );
    expectNoSecretLeak(fixture2.env, down.requests);
  });

  it("トークン変数が無い・改行を含むと送らずに止める(文面は変数名だけ)", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const missing = await startFixture({
      targets: { worker: cloudflareTarget({ token: { environment: TOKENS_ENV, name: "NOPE" } }) },
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(missing, "apply", "worker")).toBe(1);
    expect(missing.env.errors.join("\n")).toContain(
      "The token variable NOPE does not exist in environment tokens",
    );
    const newline = await startFixture({
      targets: { worker: cloudflareTarget() },
      tokenVariables: [
        await variable({
          environment: TOKENS_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: `${CF_TOKEN}\n`,
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(newline, "apply", "worker")).toBe(1);
    expect(newline.env.errors.join("\n")).toContain(
      "The token variable CF_API_TOKEN contains a newline or control character",
    );
    expect(cf.requests).toEqual([]);
    expectNoSecretLeak(newline.env, cf.requests);
  });

  it("トークンが同期元と同じ環境にあっても同期先へ運ばない", async () => {
    const cf = makeFakeCloudflare({
      token: CF_TOKEN,
      scripts: [`${CF_ACCOUNT}/my-worker-staging`],
    });
    const fixture = await startFixture({
      targets: {
        worker: cloudflareTarget({ token: { environment: SOURCE_ENV, name: "CF_API_TOKEN" } }),
      },
      sourceVariables: [
        await variable({
          environment: SOURCE_ENV,
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await variable({
          environment: SOURCE_ENV,
          variableId: "tc",
          name: "CF_API_TOKEN",
          version: 1,
          plaintext: CF_TOKEN,
        }),
      ],
      vendorHandlers: cf.handlers,
      vendorHosts: ["api.cloudflare.com"],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(Object.keys((cf.requests[0] as MockRequest).body as Record<string, unknown>)).toEqual([
      "secrets",
    ]);
    expect((cf.requests[0] as MockRequest).body).toEqual({
      secrets: { ALPHA: { name: "ALPHA", text: ALPHA_VALUE, type: "secret_text" } },
    });
  });
});

describe("maruhi sync apply (http, Vercel)", () => {
  it("配列 + upsert=true で一括、type は preview = sensitive、teamId はクエリ、削除は一覧 → DELETE", async () => {
    const vercel = makeFakeVercel({
      token: VERCEL_TOKEN,
      projectId: "prj_123",
      teamId: "team_9",
      initial: [
        { id: "env_old", key: "OLD", value: "old", type: "encrypted", target: ["preview"] },
        { id: "env_prod", key: "OLD", value: "keep", type: "encrypted", target: ["production"] },
      ],
    });
    const fixture = await startFixture({
      targets: { web: vercelTarget() },
      receipts: [
        await receiptVariable({ target: "web", preset: "vercel", variables: { ALPHA: 2, OLD: 1 } }),
      ],
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(0);
    const [upsert, list, remove] = vercel.requests as [MockRequest, MockRequest, MockRequest];
    expect(upsert.method).toBe("POST");
    expect(upsert.path).toBe("/v10/projects/prj_123/env");
    expect(upsert.query).toEqual({ upsert: "true", teamId: "team_9" });
    expect(upsert.body).toEqual([
      { key: "ALPHA", value: ALPHA_VALUE, type: "sensitive", target: ["preview"] },
      { key: "BETA", value: BETA_VALUE, type: "sensitive", target: ["preview"] },
    ]);
    expect(list.method).toBe("GET");
    expect(list.query).toEqual({ target: "preview", teamId: "team_9" });
    expect(remove.method).toBe("DELETE");
    // preview の OLD だけを消す(production の同名は残す)
    expect(remove.path).toBe("/v10/projects/prj_123/env/env_old");
    expect(vercel.envs.map((env) => env.key).toSorted()).toEqual(["ALPHA", "BETA", "OLD"]);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    expectNoSecretLeak(fixture.env, vercel.requests);
  });

  it("development と sensitive: false は encrypted で送る", async () => {
    const vercel = makeFakeVercel({ token: VERCEL_TOKEN, projectId: "prj_123" });
    const fixture = await startFixture({
      targets: {
        dev: vercelTarget({ options: { environment: "development", projectId: "prj_123" } }),
        plain: vercelTarget({
          options: { environment: "production", projectId: "prj_123", sensitive: false },
        }),
      },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "dev")).toBe(0);
    expect(await sync(fixture, "apply", "plain", "--yes")).toBe(0);
    const types = vercel.requests.map((request) =>
      (request.body as { type: string }[]).map((item) => item.type),
    );
    expect(types).toEqual([
      ["encrypted", "encrypted"],
      ["encrypted", "encrypted"],
    ]);
  });

  it("部分成功(failed)は届いた名前だけレシートに残し、失敗応答の値の echo は伏せて exit 1", async () => {
    const vercel = makeFakeVercel({
      token: VERCEL_TOKEN,
      projectId: "prj_123",
      rejectKeys: ["BETA"],
    });
    const fixture = await startFixture({
      targets: { web: vercelTarget({ options: { environment: "preview", projectId: "prj_123" } }) },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "the Vercel API refused the request while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("error INVALID_VALUE (BETA): value rejected for BETA: [redacted]");
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expectNoSecretLeak(fixture.env, vercel.requests);
  });

  it("同期先で既に消えていた名前の削除は一覧に無ければ消えた扱い(レシートが詰まらない)", async () => {
    const vercel = makeFakeVercel({ token: VERCEL_TOKEN, projectId: "prj_123" });
    const fixture = await startFixture({
      targets: {
        web: vercelTarget({
          variables: ["ALPHA"],
          options: { environment: "preview", projectId: "prj_123" },
        }),
      },
      receipts: [
        await receiptVariable({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, GONE: 1 },
        }),
      ],
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(0);
    expect(vercel.requests.map((request) => request.method)).toEqual(["GET"]);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target web: 0 variables written, 1 deleted",
    );
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
  });

  it("トークンが拒否されれば(403)何も届かず、レシートは書かれない", async () => {
    const vercel = makeFakeVercel({ token: "another-token", projectId: "prj_123" });
    const fixture = await startFixture({
      targets: { web: vercelTarget({ options: { environment: "preview", projectId: "prj_123" } }) },
      vendorHandlers: vercel.handlers,
      vendorHosts: ["api.vercel.com"],
    });
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("HTTP 403");
    expect(fixture.env.errors.join("\n")).toContain("error forbidden: Not authorized");
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env, vercel.requests);
  });
});
