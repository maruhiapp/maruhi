// 値なしスキーマ S5 のテスト(設計文書 §1-7): `maruhi schema lint` — ソースの
// env 参照の静的走査とストア側スキーマの突合。best-effort の位置づけ(注意書きの
// 常時出力)・レポートは変数名のみ(description 非出力)・終了コードの非対称
// (undeclared = exit 1 / unread のみ = exit 0)・鍵なしクラスを固定する。

import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import { scanEnvReferences } from "../src/schema-lint.ts";
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
const SECRET_DESCRIPTION = "Endpoint description that must never reach the lint report";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** declared(url 型・description 付き)— コードが読む側。 */
let declaredShopUrl: WireDistributedVariableStatement;
/** active(v1 — スキーマ欄なし)— 名前はストアに存在する。 */
let activeV1: WireDistributedVariableStatement;
/** declared — コードのどこからも読まれない側。 */
let declaredUnread: WireDistributedVariableStatement;
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
  declaredShopUrl = await statementFor({
    ...common,
    variableId: "v-shop-url",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: SECRET_DESCRIPTION },
  });
  activeV1 = await statementFor({
    ...common,
    variableId: "v-legacy",
    name: "LEGACY_KEY",
    author: owner,
    head,
  });
  declaredUnread = await statementFor({
    ...common,
    variableId: "v-unread",
    name: "UNREAD_FLAG",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "boolean", required: false, description: "" },
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
  return [declaredShopUrl, activeV1, declaredUnread];
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

/** 一時ディレクトリへソースツリーを書く(パス → 内容)。ルートのパスを返す。 */
async function sourceTree(files: Readonly<Record<string, string>>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "maruhi-lint-"));
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path);
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, content);
  }
  return root;
}

describe("scanEnvReferences(走査器 — 実装裁定の逐語形)", () => {
  it("主要ランタイムの静的な逐語 env 参照を拾う", () => {
    const found = scanEnvReferences(
      [
        "const a = process.env.SHOP_URL;",
        'const b = process.env["BRACKET_VAR"];',
        "const c = import.meta.env.VITE_FLAG;",
        "const d = Bun.env.BUN_VAR;",
        'const e = Deno.env.get("DENO_VAR");',
        'x = os.environ["PY_BRACKET"]',
        'y = os.environ.get("PY_GET", "default")',
        'z = os.getenv("PY_GETENV")',
        'v, ok := os.LookupEnv("GO_LOOKUP")',
        'w := os.Getenv("GO_VAR")',
        'r = ENV["RUBY_VAR"]',
        's = ENV.fetch("RUBY_FETCH")',
        'let t = std::env::var("RUST_VAR")?;',
        'let u = env::var_os("RUST_OS_VAR");',
      ].join("\n"),
    );
    expect([...found].toSorted()).toEqual([
      "BRACKET_VAR",
      "BUN_VAR",
      "DENO_VAR",
      "GO_LOOKUP",
      "GO_VAR",
      "PY_BRACKET",
      "PY_GET",
      "PY_GETENV",
      "RUBY_FETCH",
      "RUBY_VAR",
      "RUST_OS_VAR",
      "RUST_VAR",
      "SHOP_URL",
      "VITE_FLAG",
    ]);
  });

  it("動的アクセスは拾わない(best-effort の線 — 検出できると偽らない)", () => {
    const found = scanEnvReferences(
      ["const name = 'DYNAMIC';", "const v = process.env[name];", "const w = os.environ[key]"].join(
        "\n",
      ),
    );
    expect(found.size).toBe(0);
  });
});

describe("maruhi schema lint(§1-7 — コード契約の突合)", () => {
  it("コードが読むがストアに宣言がない名前を検出して exit 1(fail-loud)", async () => {
    const root = await sourceTree({
      "src/config.ts":
        "export const url = process.env.SHOP_URL;\nconst k = process.env.MISSING_VAR;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(1);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Read by the scanned code but not declared in environment ${ENV_ID}: 1`,
    );
    expect(output).toContain("MISSING_VAR");
    // 宣言済みの参照は undeclared に出ない(v1 変数も名前はストアに存在する)
    expect(output).not.toContain("  SHOP_URL");
    const errors = env.errors.join("\n");
    expect(errors).toContain("not declared in environment");
    expect(errors).toContain("--ignore");
  });

  it("宣言済みだが読まれない名前は報告のみで exit 0(動的アクセス・別リポジトリ消費がありうる)", async () => {
    const root = await sourceTree({
      "src/config.ts":
        "export const url = process.env.SHOP_URL;\nconst legacy = process.env.LEGACY_KEY;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Declared in environment ${ENV_ID} but not read by the scanned code: 1`,
    );
    expect(output).toContain("UNREAD_FLAG");
  });

  it("レポートは変数名のみ — description をどの行にも出さない(§1-7 / §2)", async () => {
    const root = await sourceTree({
      "src/config.ts": "export const url = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const all = [...env.logs, ...env.errors].join("\n");
    expect(all).not.toContain(SECRET_DESCRIPTION);
    // 型は宣言 — レポートに「verified」の語を使わない(§14.3)
    expect(all.toLowerCase()).not.toContain("verified");
  });

  it("best-effort の注意書きを結論に依らず常に stderr へ出す(検査の欠落 ≠ 保証の欠落)", async () => {
    const clean = await sourceTree({
      "src/config.ts": "export const url = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", clean], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("best-effort static scan");
    expect(env.errors.join("\n")).toContain("not a guarantee");
  });

  it("--ignore は undeclared 検査から名前を除外する(maruhi 管理外のランタイム変数)", async () => {
    const root = await sourceTree({
      "src/config.ts": "const mode = process.env.NODE_ENV;\nconst u = process.env.SHOP_URL;\n",
    });
    const failing = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], failing.layer)).toBe(1);
    const passing = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root, "--ignore", "NODE_ENV"], passing.layer)).toBe(0);
    expect(passing.logs.join("\n")).not.toContain("NODE_ENV");
  });

  it("node_modules・.git など依存/生成物ディレクトリは走査しない", async () => {
    const root = await sourceTree({
      "src/app.ts": "const u = process.env.SHOP_URL;\n",
      "node_modules/pkg/index.js": "const x = process.env.DEP_ONLY_VAR;\n",
      ".git/hooks/sample.py": 'x = os.getenv("GIT_HOOK_VAR")\n',
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).not.toContain("DEP_ONLY_VAR");
    expect(output).not.toContain("GIT_HOOK_VAR");
  });

  it("件数行は 0 件でも必ず出す(出力の形を実行ごとに変えない)", async () => {
    const root = await sourceTree({
      "src/app.ts":
        "const a = process.env.SHOP_URL;\nconst b = process.env.LEGACY_KEY;\nconst c = process.env.UNREAD_FLAG;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain(
      `Read by the scanned code but not declared in environment ${ENV_ID}: 0`,
    );
    expect(output).toContain(
      `Declared in environment ${ENV_ID} but not read by the scanned code: 0`,
    );
  });

  it("存在しないパスはネットワークの前に走査エラーで報告する", async () => {
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    expect(await runCli(["schema", "lint", "/nonexistent/source-dir"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Could not scan");
    // 走査の失敗はサーバーへの往復より前(リクエストが 1 件もない)
    const server = servers[servers.length - 1];
    expect(server?.requests ?? []).toHaveLength(0);
  });

  it("エージェント環境 + master 鍵なしでも実行できる(agent-gate 非適用の固定 — CI 前提)", async () => {
    const root = await sourceTree({
      "src/app.ts": "const u = process.env.SHOP_URL;\n",
    });
    const env = await startEnv([chainHandler(), metadataHandler(defaultVariables())]);
    env.setAgent({ isAgent: true, name: "ci-bot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    env.keychain.delete(masterKeyEntryName(env.origin, owner.userId));
    expect(await runCli(["schema", "lint", root], env.layer)).toBe(0);
  });
});
