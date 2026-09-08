// `maruhi sync plan` / `sync apply`(SY2 第 1 段)のテスト: リポジトリ設定 →
// レシート環境の読み → 同期元の検証(plan は復号しない)→ ベンダー CLI の駆動
// (値は stdin だけ)→ レシートの書き込み(§4.1 の署名つき push)。
//
// 固定する性質: 値が argv / stdout / stderr / エラー文面に出ない、stdin の形式
// (wrangler = JSON 1 つ、Vercel = 値そのもの)、テレメトリ off の環境変数、
// production の既定 = plan のみ(`--yes`)、レシートの差分だけを書く、失敗時は
// 届いた分だけレシートに残す、ブロックされる値は何も送らない、設定の検証。
// ベンダー CLI は偽の ProcessRunner(argv / cwd / env / stdin を記録)。

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decryptVariable } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { cliError } from "../src/errors.ts";
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
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import {
  type ExecCall,
  makeTestEnv,
  seedConfig,
  seedSession,
  type TestEnv,
} from "./support/env.ts";
import { MockServer } from "./support/server.ts";
import {
  makeValueEnvironmentServer,
  type StoredVariable,
  type ValueEnvironmentState,
} from "./support/value-env.ts";

const SOURCE_ENV = "prod";
const RECEIPTS_ENV = "sync-receipts";
const ALPHA_VALUE = "alpha-value-3";
const BETA_VALUE = "beta line 1\nbeta line 2\n";
const SECRETS = [ALPHA_VALUE, "beta line 1", "beta line 2"];

let owner: TestUser;
let built: BuiltChain;
let dekSource: Uint8Array;
let dekReceipts: Uint8Array;
let wrapSource: WireRecipientDek;
let wrapReceipts: WireRecipientDek;
let sourceStatement: WireDistributedEnvironmentStatement;
let receiptsStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dekSource = crypto.getRandomValues(new Uint8Array(32));
  dekReceipts = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(SOURCE_ENV, dekSource) },
    { actor: owner, operation: createEnvironmentOp(RECEIPTS_ENV, dekReceipts) },
  ]);
  const common = { projectId: built.projectId, recipient: owner, signer: owner, epoch: 1 };
  wrapSource = await wrapDekFor({ ...common, environmentId: SOURCE_ENV, dek: dekSource });
  wrapReceipts = await wrapDekFor({ ...common, environmentId: RECEIPTS_ENV, dek: dekReceipts });
  const head = { seq: 1, hashHex: built.projectId };
  sourceStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    name: SOURCE_ENV,
    author: owner,
    head,
  });
  receiptsStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    name: RECEIPTS_ENV,
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** 同期元の 1 変数(ステートメント + 値。version と required を指定)。 */
async function sourceVariable(input: {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string | Uint8Array;
  readonly required?: boolean;
}): Promise<StoredVariable> {
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
    ...(input.required === undefined
      ? {}
      : { schema: { varType: "", required: input.required, description: "" } }),
  });
  const value = await encryptValueFor({
    dek: dekSource,
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    epoch: 1,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    head: headOf(built, 2),
  });
  return { variableId: input.variableId, statement, value };
}

/** レシート環境に置かれた既存レシート(前回の同期の結果)。 */
async function storedReceipt(input: {
  readonly target: string;
  readonly preset: "vercel" | "cloudflare-workers" | "github-actions";
  readonly variables: Readonly<Record<string, number>>;
  readonly version?: number;
}): Promise<StoredVariable> {
  const variableId = `receipt-${input.target}`;
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    variableId,
    name: receiptVariableName(input.target),
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const value = await encryptValueFor({
    dek: dekReceipts,
    projectId: built.projectId,
    environmentId: RECEIPTS_ENV,
    epoch: 1,
    variableId,
    version: input.version ?? 1,
    plaintext: JSON.stringify({
      version: 1,
      target: input.target,
      preset: input.preset,
      syncedAt: "2026-09-05T00:00:00.000Z",
      variables: input.variables,
    }),
    writer: owner,
    head: headOf(built, 3),
  });
  return { variableId, statement, value };
}

interface Fixture {
  readonly env: TestEnv;
  readonly source: ValueEnvironmentState;
  readonly receipts: ValueEnvironmentState;
  readonly configDir: string;
  readonly configPath: string;
}

/** 既定の設定(Vercel production ターゲット `web` と Workers staging ターゲット `worker`)。 */
function defaultConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    receipts: { environment: RECEIPTS_ENV },
    targets: {
      web: {
        preset: "vercel",
        environment: SOURCE_ENV,
        variables: ["ALPHA", "BETA"],
        options: { environment: "production" },
      },
      worker: {
        preset: "cloudflare-workers",
        environment: SOURCE_ENV,
        variables: "all",
        cwd: "apps/worker",
        options: { environment: "staging", name: "my-worker" },
      },
    },
    ...overrides,
  };
}

async function startFixture(input: {
  readonly sourceVariables?: readonly StoredVariable[];
  readonly declared?: readonly WireDistributedVariableStatement[];
  readonly receipts?: readonly StoredVariable[];
  readonly config?: Record<string, unknown> | string;
}): Promise<Fixture> {
  const sourceVariables =
    input.sourceVariables ??
    (await Promise.all([
      sourceVariable({ variableId: "va", name: "ALPHA", version: 3, plaintext: ALPHA_VALUE }),
      sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
    ]));
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: sourceStatement,
    wrap: wrapSource,
    initialVariables: sourceVariables,
    initialDeclared: input.declared ?? [],
  });
  const receipts = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: RECEIPTS_ENV,
    envStatement: receiptsStatement,
    wrap: wrapReceipts,
    initialVariables: input.receipts ?? [],
  });
  const server = await MockServer.start([...source.handlers, ...receipts.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  const config = input.config ?? defaultConfig();
  await writeFile(configPath, typeof config === "string" ? config : JSON.stringify(config));
  return { env, source: source.state, receipts: receipts.state, configDir, configPath };
}

function sync(fixture: Fixture, ...args: string[]): Promise<number> {
  return runCli(["sync", ...args, "--config", fixture.configPath], fixture.env.layer);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

/** 値(と複数行値の各行)が stdout / stderr / argv のどこにも出ていない。 */
function expectNoSecretLeak(env: TestEnv): void {
  const shown = [
    allOutput(env),
    ...env.execCalls.flatMap((call) => [...call.command, ...Object.values(call.extraEnv)]),
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
    dek: dekReceipts,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("receipt decrypt failed in test");
  }
  return JSON.parse(decoder.decode(result.value)) as Record<string, unknown>;
}

function stdinText(call: ExecCall): string {
  return decoder.decode(call.stdin);
}

describe("maruhi sync plan", () => {
  it("初回(レシートなし): 全変数を new として名前と version だけ示し、復号もベンダー CLI の起動もしない", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain(
      "Sync plan for target web (environment prod -> vercel production via exec): 2 to add, 0 to update, 0 to delete, 0 unchanged, 0 blocked",
    );
    expect(out).toContain("Last delivery: none");
    expect(out).toContain("+ ALPHA\tversion 3 (new)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
    expect(fixture.env.execCalls).toEqual([]);
    // production の既定 = plan のみ(apply には --yes)を案内する
    expect(fixture.env.errors.join("\n")).toContain("`maruhi sync apply web` needs --yes");
    expectNoSecretLeak(fixture.env);
    // 変数の書き込み API は一切呼ばない(plan は読むだけ。ヘッド申告の PUT は
    // 前段の同期の一部で、値・メタには触れない)
    const server = servers[0] as MockServer;
    expect(
      server.requests.filter(
        (request) => request.method !== "GET" && request.path.includes("/variables"),
      ),
    ).toEqual([]);
  });

  it("レシートと version を突合し、update / unchanged / delete を示す(同期先は読み戻さない)", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 2, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("0 to add, 1 to update, 1 to delete, 1 unchanged, 0 blocked");
    expect(out).toContain("~ ALPHA\tversion 2 -> 3");
    expect(out).toContain("= BETA\tversion 1 (unchanged)");
    expect(out).toContain("- OLD_NAME\t(no longer synced; last delivered version 4)");
    expect(out).toContain("Last delivery: 2026-09-05T00:00:00.000Z (receipt sync-receipt:web)");
    expect(fixture.env.execCalls).toEqual([]);
  });

  it("ブロックされる値(Vercel: 空・16 KiB 超)は ! で示し、exit 1(apply は何も送らない)", async () => {
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({ variableId: "ve", name: "EMPTY", version: 1, plaintext: "" }),
        await sourceVariable({
          variableId: "vl",
          name: "LARGE",
          version: 2,
          plaintext: "x".repeat(16 * 1024 + 1),
        }),
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
      ],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "EMPTY", "LARGE"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("! EMPTY\tversion 1 (cannot be synced: empty value");
    expect(out).toContain(
      "! LARGE\tversion 2 (cannot be synced: 16385 bytes, above the 16384-byte limit",
    );
    expect(out).toContain("+ ALPHA\tversion 3 (new)");
    expect(fixture.env.errors.join("\n")).toContain(
      "2 variables cannot be synced with this driver",
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("設定の明示リストに無い名前は何も運ばずに止める", async () => {
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "MISSING"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "The target lists variables that do not exist in environment prod: MISSING",
    );
  });

  it("required の宣言だけで値が無い変数が選択にあれば run と同じ規則で止め、required の active が選択に無ければ警告する", async () => {
    const declared = await statementFor({
      projectId: built.projectId,
      environmentId: SOURCE_ENV,
      variableId: "vd",
      name: "DECLARED_REQUIRED",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "", required: true, description: "" },
    });
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
          required: true,
        }),
        await sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
      ],
      declared: [declared],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["BETA", "DECLARED_REQUIRED"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("Required variables are declared but have no value yet");
    expect(errors).toContain("DECLARED_REQUIRED");
    expect(errors).toContain("required variables are not part of this target: ALPHA");
  });

  it("未知のターゲットは書き方の誤り(2)、壊れた設定・無い設定は実行の失敗(1)", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "plan", "nope")).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "Unknown sync target (targets in the config: web, worker)",
    );
    const broken = await startFixture({ config: '{"version": 1, "targets": {}}' });
    expect(await sync(broken, "plan", "web")).toBe(1);
    expect(broken.env.errors.join("\n")).toContain("is invalid: receipts must be an object");
    const missing = await startFixture({});
    expect(
      await runCli(
        ["sync", "plan", "web", "--config", join(missing.configDir, "nope.json")],
        missing.env.layer,
      ),
    ).toBe(1);
    expect(missing.env.errors.join("\n")).toContain("Cannot read the sync config");
    // 設定の project とフラグの食い違いは書き方の誤り(2)。ネットワークには行かない
    const mismatched = await startFixture({
      config: defaultConfig({ project: "1".repeat(64) }),
    });
    expect(
      await runCli(
        ["sync", "plan", "web", "--config", mismatched.configPath, "--project", "2".repeat(64)],
        mismatched.env.layer,
      ),
    ).toBe(2);
    expect(mismatched.env.errors.join("\n")).toContain("--project does not match");
  });

  it("レシート変数が version 上限に近づいたら警告する(1,000 version / 変数)", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, BETA: 1 },
          version: 900,
        }),
      ],
    });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the receipt variable sync-receipt:web is at version 900 of the 1000-version limit",
    );
  });
});

describe("maruhi sync apply", () => {
  it("production ターゲットは --yes が無ければ plan だけを出して何も送らない", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "web")).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain("+ ALPHA\tversion 3 (new)");
    expect(fixture.env.errors.join("\n")).toContain(
      "Target web is a production target, so apply needs an explicit --yes",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("Vercel: 名前ごとに 1 プロセス、値は stdin そのもの、argv は名前とオプションだけ、テレメトリ off、レシートを作成する", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "production", "--force", "--non-interactive"],
      ["vercel", "env", "add", "BETA", "production", "--force", "--non-interactive"],
    ]);
    expect(calls.map(stdinText)).toEqual([ALPHA_VALUE, BETA_VALUE]);
    for (const call of calls) {
      expect(call.extraEnv).toEqual({ VERCEL_TELEMETRY_DISABLED: "1" });
      // cwd は設定ファイルの置き場(cwd 未指定)
      expect(call.cwd).toBe(fixture.configDir);
    }
    expectNoSecretLeak(fixture.env);
    // レシート = 名前 → version の写像(値由来のダイジェストなし)。作成 push 1 回
    expect(fixture.receipts.writes.map((write) => write.kind)).toEqual(["create"]);
    const receipt = await decryptReceipt(fixture, "web");
    expect(receipt).toMatchObject({
      version: 1,
      target: "web",
      preset: "vercel",
      variables: { ALPHA: 3, BETA: 1 },
    });
    expect(JSON.stringify(receipt)).not.toContain(ALPHA_VALUE);
    expect(fixture.env.logs.join("\n")).toContain(`Running vercel in ${fixture.configDir}`);
    expect(fixture.env.logs.join("\n")).toContain(
      "Applied to target web: 2 variables written, 0 deleted. Receipt saved as version 1 of sync-receipt:web in environment sync-receipts",
    );

    // 2 回目: 差分なし → 何も送らず、レシートも書かない
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(0);
    expect(fixture.env.execCalls).toHaveLength(2);
    expect(fixture.receipts.writes).toHaveLength(1);
    expect(fixture.env.logs.join("\n")).toContain("Nothing to apply");
    // plan も全件 unchanged
    expect(await sync(fixture, "plan", "web")).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("= ALPHA\tversion 3 (unchanged)");
  });

  it("Cloudflare Workers: 全変数を JSON 1 つで 1 プロセス、名前付き環境は production 扱いでなく --yes 不要、cwd は設定からの相対", async () => {
    const fixture = await startFixture({});
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls).toHaveLength(1);
    expect(calls[0]?.command).toEqual([
      "wrangler",
      "secret",
      "bulk",
      "--name",
      "my-worker",
      "--env",
      "staging",
    ]);
    expect(JSON.parse(stdinText(calls[0] as ExecCall))).toEqual({
      ALPHA: ALPHA_VALUE,
      BETA: BETA_VALUE,
    });
    expect(calls[0]?.extraEnv).toEqual({ WRANGLER_SEND_METRICS: "false", DO_NOT_TRACK: "1" });
    expect(calls[0]?.cwd).toBe(join(fixture.configDir, "apps/worker"));
    expectNoSecretLeak(fixture.env);
    expect(await decryptReceipt(fixture, "worker")).toMatchObject({
      preset: "cloudflare-workers",
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it("更新と削除: 変わった変数だけを書き、選択から外れた名前を消す(wrangler は null、Vercel は env rm)", async () => {
    const vercel = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 2, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(vercel, "apply", "web", "--yes")).toBe(0);
    expect(vercel.env.execCalls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "production", "--force", "--non-interactive"],
      ["vercel", "env", "rm", "OLD_NAME", "production", "--yes", "--non-interactive"],
    ]);
    expect(vercel.env.execCalls.map(stdinText)).toEqual([ALPHA_VALUE, ""]);
    // 既存レシートへの新 version(作成ではない)
    expect(vercel.receipts.writes.map((write) => write.kind)).toEqual(["version"]);
    expect(await decryptReceipt(vercel, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
    expect(JSON.stringify(await decryptReceipt(vercel, "web"))).not.toContain("OLD_NAME");

    const workers = await startFixture({
      receipts: [
        await storedReceipt({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, BETA: 1, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(workers, "apply", "worker")).toBe(0);
    expect(workers.env.execCalls).toHaveLength(1);
    expect(JSON.parse(stdinText(workers.env.execCalls[0] as ExecCall))).toEqual({ OLD_NAME: null });
    expect(await decryptReceipt(workers, "worker")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1 },
    });
  });

  it('variables: "all" + exclude は除外名を運ばず、除外された既存レシート名を削除にする', async () => {
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          worker: {
            preset: "cloudflare-workers",
            environment: SOURCE_ENV,
            variables: "all",
            exclude: ["BETA"],
            options: { environment: "staging" },
          },
        },
      }),
      receipts: [
        await storedReceipt({
          target: "worker",
          preset: "cloudflare-workers",
          variables: { ALPHA: 3, BETA: 1 },
        }),
      ],
    });
    expect(await sync(fixture, "apply", "worker")).toBe(0);
    expect(JSON.parse(stdinText(fixture.env.execCalls[0] as ExecCall))).toEqual({ BETA: null });
  });

  it("ベンダー CLI の失敗: 届いた分だけレシートに残し、出力は値を伏せた末尾だけを見せて exit 1", async () => {
    const fixture = await startFixture({});
    fixture.env.setExecHandler((call, index) =>
      index === 0
        ? { exitCode: 0, output: `Added ${ALPHA_VALUE} to project\n` }
        : {
            exitCode: 1,
            output: `Error: rejected ${stdinText(call)} and line beta line 2 here\nsecond line\n`,
          },
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toHaveLength(2);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "maruhi: vercel exited with code 1 while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("  vercel: Error: rejected [redacted] and line [redacted] here");
    expect(errors).toContain("  vercel: second line");
    expectNoSecretLeak(fixture.env);
    // 成功した ALPHA だけがレシートに載る → 次の plan は BETA だけを示す
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("= ALPHA\tversion 3 (unchanged)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
  });

  it("削除の失敗(同期先で既に消されていた形)はレシートの作り直しを案内し、レシートにその名前を残す", async () => {
    const fixture = await startFixture({
      receipts: [
        await storedReceipt({
          target: "web",
          preset: "vercel",
          variables: { ALPHA: 3, BETA: 1, GONE: 2, GONE_TOO: 5 },
        }),
      ],
    });
    fixture.env.setExecHandler((call) =>
      call.command[2] === "rm"
        ? { exitCode: 1, output: "Error: Environment Variable was not found\n" }
        : { exitCode: 0, output: "" },
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("vercel exited with code 1 while deleting GONE");
    expect(errors).toContain(
      "reset the receipt with `maruhi var rm sync-receipt:web --env sync-receipts` and apply again",
    );
    // 最初の削除で止まるので 2 つ目は未試行 — レシートを作り直すと忘れるので名指しする
    expect(errors).toContain("remove these at the target yourself first: GONE_TOO");
    // 未試行の削除は呼ばれていない(1 つ目で止まる)
    expect(fixture.env.execCalls.filter((call) => call.command[2] === "rm")).toHaveLength(1);
    // 消せていない名前はレシートに残す(黙って「消えた」ことにしない)
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("末尾改行 1 つで終わる 1 行の値は Vercel には送れない(送る前に全件検査して止める)", async () => {
    const fixture = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await sourceVariable({
          variableId: "vn",
          name: "NEWLINE",
          version: 1,
          plaintext: "one line\n",
        }),
      ],
      config: defaultConfig({
        targets: {
          web: {
            preset: "vercel",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "NEWLINE"],
            options: { environment: "production" },
          },
        },
      }),
    });
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Variable NEWLINE is a single line ending with a newline, which the vercel CLI strips from stdin",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    // 同じ値は wrangler(JSON)へは運べる
    const workers = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "vn",
          name: "NEWLINE",
          version: 1,
          plaintext: "one line\n",
        }),
      ],
    });
    expect(await sync(workers, "apply", "worker")).toBe(0);
    expect(JSON.parse(stdinText(workers.env.execCalls[0] as ExecCall))).toEqual({
      NEWLINE: "one line\n",
    });
  });

  it("GitHub Actions: 名前ごとに `gh secret set` 1 プロセス、値は stdin だけ、-R / --app は argv、gh のテレメトリ off、リポジトリ secrets は --yes、削除は `gh secret delete`", async () => {
    const config = defaultConfig({
      targets: {
        actions: {
          preset: "github-actions",
          environment: SOURCE_ENV,
          variables: ["ALPHA"],
          options: { repo: "acme/app", app: "dependabot" },
        },
      },
    });
    const fixture = await startFixture({ config });
    // リポジトリ secrets(Environment なし)は production 扱い
    expect(await sync(fixture, "apply", "actions")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Target actions is a production target, so apply needs an explicit --yes",
    );
    expect(fixture.env.execCalls).toEqual([]);

    expect(await sync(fixture, "apply", "actions", "--yes")).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["gh", "secret", "set", "ALPHA", "--repo", "acme/app", "--app", "dependabot"],
    ]);
    expect(calls.map(stdinText)).toEqual([ALPHA_VALUE]);
    expect(calls[0]?.extraEnv).toEqual({
      GH_TELEMETRY: "false",
      DO_NOT_TRACK: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      GH_PROMPT_DISABLED: "1",
    });
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expectNoSecretLeak(fixture.env);
    expect(fixture.env.logs.join("\n")).toContain(`Running gh in ${fixture.configDir}`);
    // ヘッダー行はプリセットの describeOptions(repo / environment / app)で同期先を名指す
    expect(fixture.env.logs.join("\n")).toContain(
      "Sync plan for target actions (environment prod -> github-actions acme/app dependabot via exec)",
    );
    expect(await decryptReceipt(fixture, "actions")).toMatchObject({
      preset: "github-actions",
      variables: { ALPHA: 3 },
    });

    // 選択から外れた名前は `gh secret delete`(名前で消す — 一覧は読まない)
    const deleting = await startFixture({
      config,
      receipts: [
        await storedReceipt({
          target: "actions",
          preset: "github-actions",
          variables: { ALPHA: 3, OLD_NAME: 4 },
        }),
      ],
    });
    expect(await sync(deleting, "apply", "actions", "--yes")).toBe(0);
    expect(deleting.env.execCalls.map((call) => call.command)).toEqual([
      ["gh", "secret", "delete", "OLD_NAME", "--repo", "acme/app", "--app", "dependabot"],
    ]);
    expect(deleting.env.execCalls.map(stdinText)).toEqual([""]);
    expect(await decryptReceipt(deleting, "actions")).toMatchObject({ variables: { ALPHA: 3 } });
  });

  it("GitHub Actions: 末尾改行で終わる値(複数行でも)と小文字の名前は送る前に止める(Nothing was sent)", async () => {
    // 既定の BETA は末尾改行つきの複数行(Vercel には運べ、gh には運べない)
    const fixture = await startFixture({
      config: defaultConfig({
        targets: {
          actions: {
            preset: "github-actions",
            environment: SOURCE_ENV,
            variables: ["ALPHA", "BETA"],
            options: { environment: "staging" },
          },
        },
      }),
    });
    expect(await sync(fixture, "apply", "actions")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "Variable BETA ends with a newline, which the gh CLI strips from stdin (every trailing CR or LF, from a single-line and a multi-line value alike). Push the value without the trailing newline (`printf %s` instead of `echo`), or leave this variable out of the target. Nothing was sent",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(fixture.receipts.writes).toEqual([]);
    expectNoSecretLeak(fixture.env);

    const lower = await startFixture({
      sourceVariables: [
        await sourceVariable({
          variableId: "va",
          name: "ALPHA",
          version: 3,
          plaintext: ALPHA_VALUE,
        }),
        await sourceVariable({ variableId: "vl", name: "apiKey", version: 1, plaintext: "k" }),
      ],
      config: defaultConfig({
        targets: {
          actions: {
            preset: "github-actions",
            environment: SOURCE_ENV,
            variables: "all",
            options: { environment: "staging" },
          },
        },
      }),
    });
    // 名前の規則は平文が要らないので plan の段階で ! になる(apply の検査は防衛線)
    expect(await sync(lower, "plan", "actions")).toBe(1);
    expect(lower.env.logs.join("\n")).toContain(
      "! apiKey\tversion 1 (cannot be synced: a name the gh CLI cannot store as is: GitHub stores secret names in uppercase and accepts only uppercase letters, digits, and _, not starting with a digit or with GITHUB_)",
    );
    expect(await sync(lower, "apply", "actions")).toBe(1);
    expect(lower.env.errors.join("\n")).toContain(
      "1 variable cannot be synced with this driver (marked ! above): apiKey. Leave them out of the target, rename them, or push values the gh CLI can carry (each line above says which). Nothing was sent",
    );
    expect(lower.env.execCalls).toEqual([]);
  });

  it("ベンダー CLI が起動できなければ失敗(取りに行かない)。1 つ目の起動失敗 = 届いた分ゼロならレシートを書かない", async () => {
    // exit 127 相当(コマンド不在をシェルが返す形)も失敗として扱われる
    const fixture = await startFixture({});
    fixture.env.setExecHandler(() => ({ exitCode: 127, output: "vercel: command not found\n" }));
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("vercel exited with code 127");
    // 何も届いていない初回の失敗では、空のレシートを書かない(version を無駄にしない)
    expect(fixture.receipts.writes).toEqual([]);

    // 起動そのものの失敗(型付きエラー — live.ts の execStartFailure の形。本番の文面は
    // live-exec.test.ts で固定)はその呼び出しの失敗になり、同じくレシートを書かない
    const missing = await startFixture({});
    missing.env.setExecHandler(() =>
      cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await sync(missing, "apply", "web", "--yes")).toBe(1);
    const errors = missing.env.errors.join("\n");
    expect(errors).toContain(
      "maruhi: vercel could not be started while writing ALPHA (delivered before that: 0 variables written, 0 deleted)",
    );
    expect(errors).toContain("  vercel: Cannot start vercel (ENOENT): is it installed and on PATH");
    expect(missing.env.execCalls).toHaveLength(1);
    expect(missing.receipts.writes).toEqual([]);
  });

  it("2 つ目のベンダー CLI が起動できなくても、先に届いた分はレシートに残る(起動失敗 = その呼び出しの失敗)", async () => {
    const fixture = await startFixture({});
    fixture.env.setExecHandler((_call, index) =>
      index === 0
        ? { exitCode: 0, output: "" }
        : cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await sync(fixture, "apply", "web", "--yes")).toBe(1);
    expect(fixture.env.execCalls).toHaveLength(2);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain(
      "maruhi: vercel could not be started while writing BETA (delivered before that: 1 variable written, 0 deleted)",
    );
    expect(errors).toContain("  vercel: Cannot start vercel (ENOENT)");
    expectNoSecretLeak(fixture.env);
    // 成功した ALPHA だけがレシートに載る → 次の plan は BETA だけを示す
    expect(await decryptReceipt(fixture, "web")).toMatchObject({ variables: { ALPHA: 3 } });
    expect(await sync(fixture, "plan", "web")).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("= ALPHA\tversion 3 (unchanged)");
    expect(out).toContain("+ BETA\tversion 1 (new)");
  });

  it("壊れたレシート変数は fail-closed(直し方を添える)", async () => {
    const receiptId = "receipt-web";
    const statement = await statementFor({
      projectId: built.projectId,
      environmentId: RECEIPTS_ENV,
      variableId: receiptId,
      name: receiptVariableName("web"),
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
    });
    const value = await encryptValueFor({
      dek: dekReceipts,
      projectId: built.projectId,
      environmentId: RECEIPTS_ENV,
      epoch: 1,
      variableId: receiptId,
      version: 1,
      plaintext: "not json",
      writer: owner,
      head: headOf(built, 3),
    });
    const fixture = await startFixture({ receipts: [{ variableId: receiptId, statement, value }] });
    expect(await sync(fixture, "plan", "web")).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      "The receipt variable sync-receipt:web in environment sync-receipts is not a valid sync receipt (not valid JSON). Remove it with `maruhi var rm sync-receipt:web --env sync-receipts`",
    );
  });
});
