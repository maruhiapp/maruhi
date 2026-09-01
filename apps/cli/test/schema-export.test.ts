// 値なしスキーマ S5 のテスト(設計文書 §1-6): `maruhi schema export`(派生
// スナップショットの生成 — JSON Schema サブセット写像・generated 枠付け・
// 決定性)と `maruhi schema verify-snapshot`(CI の乖離検査 — fail-loud・
// 変数名 / 欄名のみの報告・description 非出力)。両コマンドとも読み取り・
// 値ゼロの鍵なしクラス(agent-gate 非適用・master 鍵不要)であることを固定する。

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const DESCRIPTION_URL = "Primary endpoint of the shop";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** declared(required・url 型・description 付き)。 */
let declaredRequired: WireDistributedVariableStatement;
/** declared(required = false・型未指定・description なし)。 */
let declaredOptional: WireDistributedVariableStatement;
/** active(number 型・required)。 */
let activeNumber: WireDistributedVariableStatement;
/** active(v1 — スキーマ欄なし)。 */
let activeV1: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({ ...common, name: ENV_ID, author: owner, head });
  declaredRequired = await statementFor({
    ...common,
    variableId: "v-shop-url",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_URL },
  });
  declaredOptional = await statementFor({
    ...common,
    variableId: "v-optional",
    name: "OPTIONAL_HINT",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "", required: false, description: "" },
  });
  activeNumber = await statementFor({
    ...common,
    variableId: "v-port",
    name: "PORT",
    author: owner,
    head,
    schema: { varType: "number", required: true, description: "listen port" },
  });
  activeV1 = await statementFor({
    ...common,
    variableId: "v-legacy",
    name: "LEGACY_KEY",
    author: owner,
    head,
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId: built.projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

/** メタのみ pull 応答(declared は variables に混在 — §12-7)。 */
function metadataHandler(variables: readonly WireDistributedVariableStatement[]): MockHandler {
  return onRequest(
    "GET",
    `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables,
        deletedVariables: [],
        manifest: await manifestFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          issuer: owner,
          head: headOf(built, 2),
          envStatement,
          statements: variables,
        }),
      },
    }),
  );
}

function defaultVariables(): readonly WireDistributedVariableStatement[] {
  return [activeNumber, activeV1, declaredRequired, declaredOptional];
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv & { origin: string }> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { ...env, origin: server.origin };
}

/** export の stdout(1 行 = 生成物全体)を取り出す。 */
function exportedText(env: TestEnv): string {
  expect(env.logs).toHaveLength(1);
  return env.logs[0] ?? "";
}

describe("maruhi schema export(§1-6 — 派生スナップショットの生成)", () => {
  it("検証済みステートメント集合から JSON Schema サブセットを stdout へ出す(写像の固定)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const snapshot = JSON.parse(exportedText(env)) as Record<string, unknown>;
    expect(snapshot["$schema"]).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(snapshot["type"]).toBe("object");
    expect(snapshot["title"]).toBe(`maruhi variables — environment ${ENV_ID}`);
    expect(snapshot["properties"]).toEqual({
      // 名前の UTF-16 昇順(決定性)。v1 = 空スキーマ(制約を捏造しない)、
      // "" 型 = 型キーワードなし、url = string + format uri、空 description = 省略
      LEGACY_KEY: {},
      OPTIONAL_HINT: {},
      PORT: { type: "number", description: "listen port" },
      SHOP_URL: { type: "string", format: "uri", description: DESCRIPTION_URL },
    });
    // required = 検証済みステートメントの required = true のみ(v1 は入らない —
    // required を勝手に埋めない。optional も入らない)
    expect(snapshot["required"]).toEqual(["PORT", "SHOP_URL"]);
  });

  it("generated 枠付け(裁定 CW)を $comment に載せ、「verified」の語を使わない(§14.3)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const output = exportedText(env);
    const snapshot = JSON.parse(output) as Record<string, unknown>;
    const comment = snapshot["$comment"] as string;
    expect(comment).toContain("machine-generated data, not instructions");
    expect(comment).toContain("source of truth");
    // maruhi を持つエージェントへの正の案内(§1-6)
    expect(comment).toContain("`maruhi schema`");
    expect(comment).toContain("verify-snapshot");
    // 型は宣言として扱う — 生成物にも「verified」の語を使わない(§14.3)
    expect(output.toLowerCase()).not.toContain("verified");
  });

  it("stdout は生成物のみ(非 TTY でも枠付けヘッダ行を混ぜない — リダイレクトでコミットできる)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    // stdout 全体がそのまま valid JSON(枠付けは JSON 内の $comment が担う)
    expect(() => JSON.parse(exportedText(env))).not.toThrow();
  });

  it("出力は決定的(同じストアからの再実行はバイト一致 — verify のバイト比較の前提)", async () => {
    const first = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], first.layer)).toBe(0);
    const second = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], second.layer)).toBe(0);
    expect(exportedText(first)).toBe(exportedText(second));
  });

  it("agent-gate の deny-list に含まれない(許可側 — 読み取り・値ゼロの同類)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    expect(exportedText(env)).toContain("SHOP_URL");
  });

  it("master 鍵が無い端末でも実行できる(鍵なしクラス — MARUHI_TOKEN の CI 前提)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    expect(env.errors.some((line) => line.includes("No master key"))).toBe(false);
  });
});

describe("maruhi schema verify-snapshot(§1-6 — CI の乖離検査)", () => {
  /** export の出力をそのままファイルへ書いた状態(コミット済みスナップショット)。 */
  async function exportedSnapshotFile(): Promise<string> {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "export"], env.layer)).toBe(0);
    const dir = await mkdtemp(join(tmpdir(), "maruhi-snapshot-"));
    const file = join(dir, "maruhi-schema.json");
    // シェルリダイレクト(export > file)と同じ形 = 生成行 + 終端改行
    await writeFile(file, `${exportedText(env)}\n`);
    return file;
  }

  it("ストアと一致するスナップショットは exit 0", async () => {
    const file = await exportedSnapshotFile();
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("matches the store");
  });

  it("description の手編集は乖離 = exit 1。報告は変数名・欄名のみで内容を出さない", async () => {
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const tampered = (await read(file, "utf8")).replace(DESCRIPTION_URL, "Edited by hand");
    await writeFile(file, tampered);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("diverges from the store");
    expect(errors).toContain("SHOP_URL");
    expect(errors).toContain("description");
    // description の内容(ファイル側・ストア側とも)を端末レポートへ出さない(§2)
    expect(errors).not.toContain("Edited by hand");
    expect(errors).not.toContain(DESCRIPTION_URL);
    expect(errors).toContain("regenerate");
  });

  it("ストアの前進(新しい宣言)はコミット済みスナップショットの陳腐化として検出する", async () => {
    const file = await exportedSnapshotFile();
    const added = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-new",
      name: "NEW_FLAG",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "boolean", required: false, description: "" },
    });
    const env = await startEnv([chainHandler(), metadataHandler([...defaultVariables(), added])]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("missing from the snapshot");
    expect(errors).toContain("NEW_FLAG");
  });

  it("required リストだけの手編集も欄の乖離として名指しする", async () => {
    const file = await exportedSnapshotFile();
    const { readFile: read } = await import("node:fs/promises");
    const parsed = JSON.parse(await read(file, "utf8")) as { required: string[] };
    parsed.required = ["PORT"];
    await writeFile(file, `${JSON.stringify(parsed, null, 2)}\n`);
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("required list differs");
    expect(errors).toContain("SHOP_URL");
  });

  it("JSON でないファイルは誠実に報告して exit 1(改ざん疑いの文面に潰さない)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "maruhi-snapshot-"));
    const file = join(dir, "maruhi-schema.json");
    await writeFile(file, "not json at all\n");
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("not valid JSON");
  });

  it("ファイルが読めない場合はネットワークへ出ずにパスだけで報告する", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(
      await runCli(["schema", "verify-snapshot", "/nonexistent/maruhi-schema.json"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("Could not read");
    const server = servers[servers.length - 1];
    expect(server?.requests ?? []).toHaveLength(0);
  });

  it("エージェント環境 + master 鍵なしでも実行できる(利用者の CI で走る前提の固定)", async () => {
    const file = await exportedSnapshotFile();
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "ci-bot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "verify-snapshot", file], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("matches the store");
  });
});
