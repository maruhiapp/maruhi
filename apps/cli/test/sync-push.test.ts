// `maruhi push` 直後の同期(SY2 第 3 段 — sync-push.ts)のテスト: リポジトリ設定の
// `onPush` を持つターゲットへ、push の後始末として直接 apply する(値は stdin だけ・
// レシートが進む)か、`gh workflow run` で CI を起動する(値も変数名も argv に
// 載らない・レシートは触らない)。
//
// 固定する性質: push の報告が先・後始末の失敗は警告で終了コードは push のまま・
// 証拠だけは失敗・`--no-sync` は設定を読まない・production は直接 apply されない
// (設定で拒む)・別プロジェクトの設定(明示 = 2 / 既定パス = 何もしない)・
// 同期元でない環境 / 運ばない変数の push は何もしない・二重起動なし。

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
const BETA_VALUE = "beta-value-1";
const NEW_VALUE = "alpha-value-4-pushed";
const SECRETS = [ALPHA_VALUE, BETA_VALUE, NEW_VALUE];
const OTHER_PROJECT = "f".repeat(64);

let owner: TestUser;
let built: BuiltChain;
let dekSource: Uint8Array;
let dekReceipts: Uint8Array;
let wrapSource: WireRecipientDek;
let wrapReceipts: WireRecipientDek;
let sourceStatement: WireDistributedEnvironmentStatement;
let receiptsStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];
const originalCwd = process.cwd();

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
  process.chdir(originalCwd);
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function sourceVariable(input: {
  readonly variableId: string;
  readonly name: string;
  readonly version: number;
  readonly plaintext: string;
}): Promise<StoredVariable> {
  const statement = await statementFor({
    projectId: built.projectId,
    environmentId: SOURCE_ENV,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
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

async function storedReceipt(input: {
  readonly target: string;
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
      preset: "vercel",
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
  readonly server: MockServer;
}

/** preview ターゲット `web`(直接 apply)。`project` は push 時同期に必須。 */
function previewTarget(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    preset: "vercel",
    environment: SOURCE_ENV,
    variables: ["ALPHA", "BETA"],
    options: { environment: "preview" },
    onPush: "apply",
    ...overrides,
  };
}

function config(
  targets: Record<string, unknown>,
  root: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    version: 1,
    project: built.projectId,
    receipts: { environment: RECEIPTS_ENV },
    targets,
    ...root,
  };
}

async function startFixture(input: {
  readonly config: Record<string, unknown>;
  readonly receipts?: readonly StoredVariable[];
}): Promise<Fixture> {
  const source = makeValueEnvironmentServer({
    chain: built,
    owner,
    environmentId: SOURCE_ENV,
    envStatement: sourceStatement,
    wrap: wrapSource,
    initialVariables: await Promise.all([
      sourceVariable({ variableId: "va", name: "ALPHA", version: 3, plaintext: ALPHA_VALUE }),
      sourceVariable({ variableId: "vb", name: "BETA", version: 1, plaintext: BETA_VALUE }),
    ]),
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
  const configDir = await mkdtemp(join(tmpdir(), "maruhi-sync-push-test-"));
  const configPath = join(configDir, "maruhi.sync.json");
  await writeFile(configPath, JSON.stringify(input.config));
  return { env, source: source.state, receipts: receipts.state, configDir, configPath, server };
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** `printf %s "$VALUE" | maruhi push ALPHA --env prod [...args]`。 */
function push(fixture: Fixture, value: string, ...args: string[]): Promise<number> {
  return pushNamed(fixture, "ALPHA", value, ...args);
}

function pushNamed(
  fixture: Fixture,
  name: string,
  value: string,
  ...args: string[]
): Promise<number> {
  fixture.env.setStdin(encoder.encode(value));
  return runCli(["push", name, "--env", SOURCE_ENV, ...args], fixture.env.layer);
}

function pushWithConfig(fixture: Fixture, value: string, ...args: string[]): Promise<number> {
  return push(fixture, value, "--config", fixture.configPath, ...args);
}

function allOutput(env: TestEnv): string {
  return [...env.logs, ...env.errors].join("\n");
}

/** 値が stdout / stderr / argv / 環境変数のどこにも出ていない(stdin は検査対象外)。 */
function expectNoSecretLeak(env: TestEnv): void {
  const shown = [
    allOutput(env),
    ...env.execCalls.flatMap((call) => [...call.command, ...Object.values(call.extraEnv)]),
  ].join("\n");
  for (const secret of SECRETS) {
    expect(shown).not.toContain(secret);
  }
}

function stdinText(call: ExecCall): string {
  return decoder.decode(call.stdin);
}

/** レシート環境へのリクエスト(後始末が読み書きしたか)。 */
function receiptsRequests(fixture: Fixture): number {
  return fixture.server.requests.filter((request) =>
    request.path.includes(`/environments/${RECEIPTS_ENV}/`),
  ).length;
}

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

const PUSHED_LINE = "Pushed ALPHA (version=4, epoch=1)";

describe("maruhi push → direct apply (onPush: apply)", () => {
  it("push の報告の後に、今 push した変数だけをベンダー CLI の stdin へ書き、レシートを進める(unchanged の行は省く)", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const out = fixture.env.logs.join("\n");
    // 順序: push の報告 → 後始末
    expect(out.indexOf(PUSHED_LINE)).toBeGreaterThanOrEqual(0);
    expect(out.indexOf("Syncing target web after the push")).toBeGreaterThan(
      out.indexOf(PUSHED_LINE),
    );
    expect(out).toContain(`Syncing target web after the push (onPush in ${fixture.configPath})`);
    expect(out).toContain("0 to add, 1 to update, 0 to delete, 1 unchanged, 0 blocked");
    expect(out).toContain("~ ALPHA\tversion 3 -> 4");
    expect(out).not.toContain("= BETA");
    expect(out).toContain(
      "Applied to target web: 1 variable written, 0 deleted. Receipt saved as version 2 of sync-receipt:web in environment sync-receipts",
    );
    // ベンダー CLI は 1 回、値は stdin そのもの、argv は名前とオプションだけ
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "ALPHA", "preview", "--force", "--non-interactive"],
    ]);
    expect(calls.map(stdinText)).toEqual([NEW_VALUE]);
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expectNoSecretLeak(fixture.env);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      target: "web",
      variables: { ALPHA: 4, BETA: 1 },
    });
    expect(fixture.env.errors.join("\n")).not.toContain("Warning");
  });

  it("cwd の既定パス(maruhi.sync.json)を黙って読む(`project` が一致するとき)", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(
      "Syncing target web after the push (onPush in maruhi.sync.json)",
    );
    expect(fixture.env.execCalls).toHaveLength(1);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 4, BETA: 1 },
    });
  });

  it("初回の変数(新規の名前)の push: plan は + で、値は 1 回だけ stdin へ、レシートに version 1 が載る", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget({ variables: ["ALPHA", "BETA", "GAMMA"] }) }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    expect(await pushNamed(fixture, "GAMMA", NEW_VALUE, "--config", fixture.configPath)).toBe(0);
    const out = fixture.env.logs.join("\n");
    expect(out).toContain("Pushed GAMMA (version=1, epoch=1)");
    expect(out).toContain("1 to add, 0 to update, 0 to delete, 2 unchanged, 0 blocked");
    expect(out).toContain("+ GAMMA\tversion 1 (new)");
    expect(fixture.env.execCalls.map((call) => call.command)).toEqual([
      ["vercel", "env", "add", "GAMMA", "preview", "--force", "--non-interactive"],
    ]);
    expect(fixture.env.execCalls.map(stdinText)).toEqual([NEW_VALUE]);
    expect(await decryptReceipt(fixture, "web")).toMatchObject({
      variables: { ALPHA: 3, BETA: 1, GAMMA: 1 },
    });
    expectNoSecretLeak(fixture.env);
  });

  it("--no-sync と --config の併用は書き方の誤り(2)で、push は送られない", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    expect(await pushWithConfig(fixture, NEW_VALUE, "--no-sync")).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain("--no-sync and --config cannot be combined");
    expect(fixture.source.writes).toEqual([]);
  });

  it("--no-sync: 設定を読まず push だけを行う(ベンダー CLI 0・レシート環境へのリクエスト 0)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE, "--no-sync")).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.logs.join("\n")).not.toContain("Syncing");
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
  });

  it("設定が cwd に無ければ従来どおりの push(何も読まない・何も言わない)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    // cwd は repo ルート(maruhi.sync.json は無い)
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
    // 同期についての note / 警告は無い(床・checkpoint の既存 note は push 自身のもの)
    expect(fixture.env.errors.join("\n")).not.toMatch(/sync config|synced|Warning/);
  });

  it("明示した --config が別プロジェクトのものなら書き方の誤り(2)で、push は送られない", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }, { project: OTHER_PROJECT }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(2);
    expect(fixture.env.errors.join("\n")).toContain(
      "The sync config belongs to a different project",
    );
    expect(fixture.source.writes).toEqual([]);
    expect(fixture.env.execCalls).toEqual([]);
  });

  it("cwd の既定パスが別プロジェクトのものなら、push はそのまま行い note で何もしない", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }, { project: OTHER_PROJECT }),
    });
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain(
      "Note: the sync config maruhi.sync.json belongs to a different project, so nothing was synced after the push",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);
  });

  it("onPush を 1 つも持たない設定は project を見ない(別プロジェクトでも 2 にならず、何も言わない)", async () => {
    const fixture = await startFixture({
      config: config({ manual: previewTarget({ onPush: undefined }) }, { project: OTHER_PROJECT }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    // 明示 --config なので「同期する対象が無い」の note は出るが、別プロジェクトの話はしない
    expect(fixture.env.errors.join("\n")).toContain("no target in the sync config copies");
    expect(fixture.env.errors.join("\n")).not.toContain("different project");
  });

  it("壊れた既定パスの設定は push の前に落とす(黙って飛ばさない)", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    await writeFile(fixture.configPath, "{ not json");
    process.chdir(fixture.configDir);
    expect(await push(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain("The sync config maruhi.sync.json is invalid");
    expect(fixture.source.writes).toEqual([]);
  });

  it("push 先の環境から運ぶ onPush ターゲットが無ければ何もしない(明示 --config なら note)", async () => {
    const fixture = await startFixture({
      config: config({
        // 別の環境を同期元にするターゲットと、この変数を運ばないターゲット
        other: previewTarget({ environment: "staging" }),
        beta: previewTarget({ variables: ["BETA"] }),
        // onPush の無いターゲット(手動のみ)
        manual: previewTarget({ onPush: undefined }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain(
      "Note: no target in the sync config copies this variable from environment prod on push, so nothing was synced",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expect(receiptsRequests(fixture)).toBe(0);

    // 既定パスなら note も出ない
    const quiet = await startFixture({
      config: config({ manual: previewTarget({ onPush: undefined }) }),
    });
    process.chdir(quiet.configDir);
    expect(await push(quiet, NEW_VALUE)).toBe(0);
    expect(quiet.env.errors.join("\n")).not.toMatch(/sync config|synced|Warning/);
  });

  it("production ターゲットは onPush のままでは push されない(設定の段階で apply を拒む)", async () => {
    const fixture = await startFixture({
      config: config({
        web: previewTarget({ options: { environment: "production" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.errors.join("\n")).toContain(
      'targets.web.onPush cannot be "apply" for a production target',
    );
    expect(fixture.source.writes).toEqual([]);
  });

  it("ベンダー CLI の失敗は警告で、push の終了コードは 0 のまま(レシートは進まない)", async () => {
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [await storedReceipt({ target: "web", variables: { ALPHA: 3, BETA: 1 } })],
    });
    fixture.env.setExecHandler(() => ({ exitCode: 1, output: `nope ${NEW_VALUE}\n` }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(errors).toContain(
      "Warning: the push is done, but target web could not be synced (vercel exited with code 1 while writing ALPHA",
    );
    expect(errors).toContain(
      "The next `maruhi sync plan web` shows the pushed variable as pending; `maruhi sync apply web` or CI delivers it",
    );
    // ベンダーの出力は伏せてから見せる
    expect(errors).toContain("  vercel: nope [redacted]");
    expectNoSecretLeak(fixture.env);
    expect(fixture.receipts.writes).toEqual([]);

    // 印 = レシートの遅れ: 次の plan が pending と示す
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    expect(fixture.env.logs.join("\n")).toContain("~ ALPHA\tversion 3 -> 4");
  });

  it("ベンダー CLI が無い(起動失敗)も警告で 0", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    fixture.env.setExecHandler(() =>
      cliError("Cannot start vercel (ENOENT): is it installed and on PATH"),
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but target web could not be synced (Cannot start vercel (ENOENT)",
    );
  });

  it("運べない値(Vercel の末尾改行)は警告で、値は送られない", async () => {
    const fixture = await startFixture({ config: config({ web: previewTarget() }) });
    // push は末尾改行を 1 つ落とすので、届く値は「1 行 + 改行 1 つ」= Vercel が落とす形
    expect(await pushWithConfig(fixture, `${NEW_VALUE}\n\n`)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but target web could not be synced (Variable ALPHA is a single line ending with a newline",
    );
    expect(fixture.env.execCalls).toEqual([]);
    expectNoSecretLeak(fixture.env);
  });

  it("レシート環境の検証拒否(証拠)は警告に畳まず失敗として通す(push の報告は先に出ている)", async () => {
    const newer = await storedReceipt({
      target: "web",
      variables: { ALPHA: 3, BETA: 1 },
      version: 2,
    });
    const older = await storedReceipt({ target: "web", variables: { ALPHA: 3 }, version: 1 });
    const fixture = await startFixture({
      config: config({ web: previewTarget() }),
      receipts: [newer],
    });
    // 先に plan でレシート環境の床を確立し、サーバーが古い version を配り直す(巻き戻し)
    expect(
      await runCli(["sync", "plan", "web", "--config", fixture.configPath], fixture.env.layer),
    ).toBe(0);
    const stored = fixture.receipts.variables[0];
    if (stored === undefined) throw new Error("receipt missing");
    stored.value = older.value;
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(1);
    expect(fixture.env.logs.join("\n")).toContain(PUSHED_LINE);
    expect(fixture.env.errors.join("\n")).toContain("value-version rollback");
    expect(fixture.env.errors.join("\n")).not.toContain("could not be synced");
    expect(fixture.env.execCalls).toEqual([]);
  });
});

describe("maruhi push → CI trigger (onPush: workflow)", () => {
  const workflowTarget = (overrides: Record<string, unknown> = {}) =>
    previewTarget({
      options: { environment: "production" },
      onPush: "workflow",
      workflow: { file: "maruhi-sync.yml" },
      ...overrides,
    });

  it("gh workflow run の argv はターゲット名と workflow だけ(値も変数名も載らない)、stdin は空、テレメトリ off、レシートは触らない", async () => {
    const fixture = await startFixture({
      config: config({
        web: workflowTarget({ workflow: { file: "maruhi-sync.yml", ref: "main" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const calls = fixture.env.execCalls;
    expect(calls.map((call) => call.command)).toEqual([
      ["gh", "workflow", "run", "maruhi-sync.yml", "-f", "target=web", "--ref", "main"],
    ]);
    expect(calls[0]?.cwd).toBe(fixture.configDir);
    expect(calls[0]?.extraEnv).toEqual({
      GH_TELEMETRY: "false",
      DO_NOT_TRACK: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
      GH_PROMPT_DISABLED: "1",
    });
    expect(calls[0]?.stdin).toHaveLength(0);
    expect(calls[0]?.command.join(" ")).not.toContain("ALPHA");
    expectNoSecretLeak(fixture.env);
    const out = fixture.env.logs.join("\n");
    expect(out.indexOf("Triggered workflow")).toBeGreaterThan(out.indexOf(PUSHED_LINE));
    expect(out).toContain(
      `Triggered workflow maruhi-sync.yml for target web (\`gh workflow run\` in ${fixture.configDir}). CI applies it with \`maruhi ci sync\` and keeps no receipt, so the next local \`maruhi sync plan web\` still shows the pushed variable as pending`,
    );
    // 一方通行: レシート環境は読まず書かず、結果も待たない
    expect(receiptsRequests(fixture)).toBe(0);
    expect(fixture.receipts.writes).toEqual([]);
  });

  it("--ref 無し(既定 = gh がリポジトリの既定ブランチを選ぶ)と command の上書き", async () => {
    const fixture = await startFixture({
      config: config({
        web: workflowTarget({ workflow: { file: "maruhi-sync.yml", command: "tools/gh" } }),
      }),
    });
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.execCalls.map((call) => call.command)).toEqual([
      ["tools/gh", "workflow", "run", "maruhi-sync.yml", "-f", "target=web"],
    ]);
  });

  it("gh の終了コード 4 = 未ログインを名指しし、警告で 0", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() => ({ exitCode: 4, output: "" }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but workflow maruhi-sync.yml was not triggered for target web: gh is not signed in (run `gh auth login`, or trigger the workflow yourself). The next `maruhi sync plan web` shows the pushed variable as pending",
    );
  });

  it("gh の非 0(workflow 不在・dispatch 無し)は出力の末尾を添えて警告で 0", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() => ({
      exitCode: 1,
      output: "could not find any workflows named maruhi-sync.yml\n\u001b[31mred\u001b[0m\n",
    }));
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    const errors = fixture.env.errors.join("\n");
    expect(errors).toContain("  gh: could not find any workflows named maruhi-sync.yml");
    expect(errors).not.toContain("\u001b");
    expect(errors).toContain(
      'Warning: the push is done, but workflow maruhi-sync.yml was not triggered for target web (gh exited with code 1; its output is shown above). Check that the workflow exists on the branch gh dispatches to and has a workflow_dispatch trigger with a "target" input',
    );
  });

  it("gh が無い(起動失敗)は警告で 0", async () => {
    const fixture = await startFixture({ config: config({ web: workflowTarget() }) });
    fixture.env.setExecHandler(() =>
      cliError("Cannot start gh (ENOENT): is it installed and on PATH"),
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.errors.join("\n")).toContain(
      "Warning: the push is done, but target web could not be synced (Cannot start gh (ENOENT)",
    );
  });

  it("同じ環境の複数ターゲット: 直接 apply と CI 起動が設定の順に 1 回ずつ。1 つの失敗で残りは止まらない", async () => {
    const fixture = await startFixture({
      config: config({
        preview: previewTarget(),
        web: workflowTarget(),
      }),
      receipts: [await storedReceipt({ target: "preview", variables: { ALPHA: 3, BETA: 1 } })],
    });
    fixture.env.setExecHandler((call) =>
      call.command[0] === "vercel" ? { exitCode: 1, output: "" } : { exitCode: 0, output: "" },
    );
    expect(await pushWithConfig(fixture, NEW_VALUE)).toBe(0);
    expect(fixture.env.execCalls.map((call) => call.command[0])).toEqual(["vercel", "gh"]);
    expect(fixture.env.errors.join("\n")).toContain("target preview could not be synced");
    expect(fixture.env.logs.join("\n")).toContain(
      "Triggered workflow maruhi-sync.yml for target web",
    );
  });
});
