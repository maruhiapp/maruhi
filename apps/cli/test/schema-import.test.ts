// `maruhi schema import`(S4 — 設計文書 §1-3)のテスト。
//
// 固定する不変条件:
//  1. **儀式系 deny(ADR-0016 決定 7 の類型)**: 既知エージェント検出と非対話
//     端末は型付きエラーで拒否し、一括 --yes は存在しない。ゲートはファイル
//     読み取り・通信より前
//  2. **値を送信しない**: 値は型推論(形の観察)にだけ使い、平文が送信・表示・
//     ログに現れない。唯一の例外は利用者が変数ごとに明示選択した activation の
//     値 push(E2EE — 平文はワイヤに現れない)
//  3. 変数ごとの対話承認(編集可)・既存名の既定スキップ・名前の受理制約に
//     満たない行の理由つきスキップ
//  4. エントロピー警告(裁定 CW)は description 候補への検査で、そのまま
//     承認するには専用の明示確認が要る。警告文面は検出値そのものを運ばない
//  5. 登録は変数ごとの複合 × マニフェスト CAS の直列(O(N) 往復 — 発見 F′)
//  6. 完了時の削除提案は既定 no(明示の y でだけ消える)

import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { observeValue, parseEnvFile } from "../src/env-file.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  makeTestUser,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import { MockServer } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let built: BuiltChain;
let dek1: Uint8Array;
let wrap1: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  wrap1 = await wrapDekFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    dek: dek1,
    recipient: owner,
    signer: owner,
  });
  envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startImportEnv(options?: {
  readonly initialVariables?: Parameters<typeof makeMetaEnvironmentServer>[0]["initialVariables"];
  readonly schemaPolicy?: "disabled" | "enabled" | "locked";
}): Promise<{ env: TestEnv; state: MetaEnvironmentState }> {
  const { state, handlers } = makeMetaEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    initialVariables: options?.initialVariables ?? [],
    wrap: wrap1,
    ...(options?.schemaPolicy === undefined ? {} : { schemaPolicy: options.schemaPolicy }),
  });
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return { env, state };
}

/** テスト用の .env ファイルを一時ディレクトリへ書く。 */
async function writeEnvFile(content: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-import-test-"));
  const path = join(dir, ".env.example");
  await writeFile(path, content);
  return path;
}

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/** observeValue の観察だけを検査する短縮形(値は包んで渡す)。 */
function observe(text: string): ReturnType<typeof observeValue> {
  return observeValue(Redacted.make(text));
}

describe("parseEnvFile(最小 .env パーサ — env-file.ts)", () => {
  it("KEY=VALUE・export 接頭辞・引用符・直前コメント → description 候補を解釈する", () => {
    const parsed = parseEnvFile(
      [
        "# Primary endpoint",
        "# of the shop",
        "SHOP_URL=https://shop.example",
        "",
        "# far away comment",
        "",
        'export QUOTED="hello world"',
        "PLAIN=v",
      ].join("\n"),
    );
    expect(parsed.skipped).toEqual([]);
    expect(parsed.entries.map((entry) => entry.name)).toEqual(["SHOP_URL", "QUOTED", "PLAIN"]);
    // 連続コメントは結合して候補になり、空行で切れる(離れたコメントは付かない)
    expect(parsed.entries[0]?.descriptionCandidate).toBe("Primary endpoint of the shop");
    expect(parsed.entries[1]?.descriptionCandidate).toBe("");
    // 値は Redacted(表示・ログの既定経路に平文が現れない)
    expect(String(parsed.entries[0]?.value)).not.toContain("shop.example");
    expect(Redacted.value(parsed.entries[1]!.value)).toBe("hello world");
  });

  it("受理できない行は行番号と理由だけでスキップする(内容は運ばない)", () => {
    const parsed = parseEnvFile(
      ["just some text", "1BAD=x", "GOOD=1", "GOOD=2", "lower-case=x"].join("\n"),
    );
    expect(parsed.entries.map((entry) => entry.name)).toEqual(["GOOD"]);
    expect(parsed.skipped).toEqual([
      { line: 1, reason: "not-an-assignment" },
      { line: 2, reason: "invalid-name" },
      { line: 4, reason: "duplicate-name", name: "GOOD" },
      { line: 5, reason: "invalid-name" },
    ]);
  });

  it("observeValue は形の観察だけを返す(boolean / number / url / 未指定・実値らしさ)", () => {
    expect(observe("true")).toEqual({ varType: "boolean", looksReal: true });
    expect(observe("8080")).toEqual({ varType: "number", looksReal: true });
    expect(observe("https://shop.example")).toEqual({ varType: "url", looksReal: true });
    expect(observe("some-opaque-token")).toEqual({ varType: "", looksReal: true });
    // 空・プレースホルダ慣用形は実値扱いしない(push の提案自体を出さない)
    expect(observe("")).toEqual({ varType: "", looksReal: false });
    expect(observe("changeme")).toEqual({ varType: "", looksReal: false });
    expect(observe("<your key here>")).toEqual({ varType: "", looksReal: false });
    expect(observe("${SECRET}")).toEqual({ varType: "", looksReal: false });
    expect(observe("your_api_key")).toEqual({ varType: "", looksReal: false });
  });
});

describe("儀式系 deny(ADR-0016 決定 7 の類型 — ゲートは読み取り・通信より前)", () => {
  it("既知エージェント検出時は型付きエラーで拒否する(ファイルにも通信にも触れない)", async () => {
    const { env } = await startImportEnv();
    env.setAgent({ isAgent: true, name: "testbot" });
    // 実在しないパス: ゲートがファイル読み取りより前なら file エラーは出ない
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI agent environment was detected: testbot");
    expect(errors).toContain("maruhi schema");
    expect(errors).not.toContain("Could not read");
    expect(lastServer().requests).toEqual([]);
  });

  it("非対話環境(stdout 非端末)は拒否し、--yes 相当の迂回は存在しない", async () => {
    const { env } = await startImportEnv();
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("requires an interactive terminal");
    expect(lastServer().requests).toEqual([]);
  });

  it("stdin 非端末(パイプ)も同じく拒否する", async () => {
    const { env } = await startImportEnv();
    env.setTerminal({ stdin: false });
    expect(await runCli(["schema", "import", "/nonexistent/.env"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("requires an interactive terminal");
  });
});

describe("承認 → declared 登録(値は送信しない)", () => {
  it("承認分を declared として登録する(型候補・required 既定 true・コメント由来 description)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(
      ["# Primary endpoint of the shop", "SHOP_URL=https://shop.example", "", "PORT=8080"].join(
        "\n",
      ),
    );
    // SHOP_URL: 承認 → 値 push は断る / PORT: 承認 → 断る / 削除提案: 既定(no)
    env.setPromptResponses(["y", "n", "y", "n", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create"]);
    const first = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
      value?: unknown;
      manifest: Record<string, unknown>;
    };
    // 値は同梱しない(declared 作成 — §12-5)。型は値の形の観察から
    expect(first.value).toBeUndefined();
    expect(first.statement["status"]).toBe("declared");
    expect(first.statement["metaVersion"]).toBe(1);
    expect(first.statement["layoutVersion"]).toBe(2);
    expect(first.statement["name"]).toBe("SHOP_URL");
    expect(first.statement["varType"]).toBe("url");
    expect(first.statement["required"]).toBe(true);
    expect(first.statement["description"]).toBe("Primary endpoint of the shop");
    const second = state.mutations[1]?.request.body as { statement: Record<string, unknown> };
    expect(second.statement["name"]).toBe("PORT");
    expect(second.statement["varType"]).toBe("number");
    expect(second.statement["description"]).toBe("");
    // 値そのものはどのリクエストにも現れない(観察のみで送信しない)
    expect(JSON.stringify(lastServer().requests)).not.toContain("shop.example");
    const output = env.logs.join("\n");
    expect(output).toContain("Declared SHOP_URL");
    expect(output).toContain("Declared PORT");
    expect(output).toContain(
      "Import finished: 2 variables declared (0 with a value pushed), 0 candidates skipped",
    );
    // 値・値の断片は stdout / stderr にも現れない
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("shop.example");
    expect(existsSync(file)).toBe(true);
  });

  it("既存の active / declared と同名の候補は既定でスキップして表示する", async () => {
    const existing = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "SHOP_URL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "url", required: true, description: "" },
    });
    const { env, state } = await startImportEnv({ initialVariables: [existing] });
    const file = await writeEnvFile(["SHOP_URL=x", "NEW_ONE="].join("\n"));
    env.setPromptResponses(["y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "Skipped SHOP_URL (line 1): a variable with this name already exists",
    );
    expect(state.mutations.map((m) => m.kind)).toEqual(["create"]);
    const created = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
    };
    expect(created.statement["name"]).toBe("NEW_ONE");
  });

  it("編集(e)で名前・型・required・description を変えてから承認できる", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile("db_url=\n");
    // db_url は小文字でも POSIX 環境変数名としては valid — e で編集して
    // 名前 DATABASE_URL・型 url・optional・説明を設定してから承認する
    env.setPromptResponses([
      "e",
      "DATABASE_URL",
      "url",
      "n",
      "Postgres connection string",
      "y",
      "",
    ]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["name"]).toBe("DATABASE_URL");
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(false);
    expect(body.statement["description"]).toBe("Postgres connection string");
  });

  it("スキップ(s)は登録せず、q は以降の候補を処理しない(削除提案も出ない)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["A=", "B=", "C="].join("\n"));
    env.setPromptResponses(["s", "q"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations).toEqual([]);
    const output = env.logs.join("\n");
    expect(output).toContain("stopped before the end");
    // q の後は C のプロンプトも削除提案も出ない(キューが枯れてもエラーに
    // ならない = 追加のプロンプトが要求されていない)
    expect(env.prompts).toHaveLength(2);
    expect(existsSync(file)).toBe(true);
  });
});

describe("値 push(activation)の明示選択", () => {
  it("実値らしい値は変数ごとの明示 y でだけ push され、平文はワイヤに現れない", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile("TOKEN=real-secret-value-xyz\n");
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "activate"]);
    const activate = state.mutations[1]?.request.body as {
      statement: Record<string, unknown>;
      value: { aad: Record<string, unknown>; ciphertextHex: string };
    };
    // activation 複合(§12-5): 値 version 1 + status active(metaVersion + 1)
    expect(activate.value.aad["version"]).toBe(1);
    expect(activate.statement["status"]).toBe("active");
    expect(activate.statement["metaVersion"]).toBe(2);
    // 平文はどのリクエスト・どの出力にも現れない(E2EE)
    expect(JSON.stringify(lastServer().requests)).not.toContain("real-secret-value-xyz");
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("real-secret-value-xyz");
    expect(env.logs.join("\n")).toContain("Pushed the value of TOKEN (version=1, epoch=1)");
  });

  it("空・プレースホルダの値では push の提案自体を出さない(既定は常に送信しない)", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["EMPTY=", "PLACEHOLDER=changeme"].join("\n"));
    // 承認 2 回 + 削除提案 1 回だけ(push プロンプトは存在しない)
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create"]);
    expect(env.prompts).toHaveLength(3);
  });
});

describe("エントロピー警告(裁定 CW — description 候補への適用)", () => {
  // 実値らしく見えるダミー(実在のシークレットではない)
  const FAKE_TOKEN = "x7Gh2kQ9pLmA3vB8nC4dE5fJ6hK7iL8m";

  it("検出時の承認には専用の明示確認が要り、警告文面は検出値を運ばない", async () => {
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile([`# token ${FAKE_TOKEN} here`, "API_HINT=changeme"].join("\n"));
    env.setPromptResponses([
      "y", // 承認しようとする → 明示確認へ
      "no", // 確認を断る → 承認ループへ戻る
      "e", // 編集で description から実値らしき列を取り除く
      "", // 名前は維持
      "", // 型は維持
      "", // required は維持
      "API hint only", // description を差し替え
      "y", // 警告なしで承認
      "", // 削除提案(既定 no)
    ]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["description"]).toBe("API hint only");
    const warningLines = env.errors.filter((line) => line.includes("secret-like high-entropy"));
    expect(warningLines.length).toBeGreaterThan(0);
    // 警告そのものは検出値(秘密でありうる)を運ばない — 長さと種別のみ
    for (const line of warningLines) {
      expect(line).not.toContain(FAKE_TOKEN);
      expect(line).toContain("32-character");
    }
    // 実値らしき列はワイヤに現れない(編集で取り除かれた)
    expect(JSON.stringify(lastServer().requests)).not.toContain(FAKE_TOKEN);
  });
});

describe("完了時の削除提案(既定は削除しない)", () => {
  it("既定(空応答)ではファイルを残し、案内を出す", async () => {
    const { env } = await startImportEnv();
    const file = await writeEnvFile("A=\n");
    env.setPromptResponses(["y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(existsSync(file)).toBe(true);
    expect(env.errors.join("\n")).toContain("was kept");
  });

  it("明示の y でだけ元ファイルを削除する", async () => {
    const { env } = await startImportEnv();
    const file = await writeEnvFile("A=\n");
    env.setPromptResponses(["y", "y"]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(existsSync(file)).toBe(false);
    expect(env.logs.join("\n")).toContain("Deleted");
  });
});

describe("受理面の周辺(advisory・直列 O(N) — 発見 F′)", () => {
  it("disabled advisory の案内は import 全体で一度だけ出す", async () => {
    const { env } = await startImportEnv({ schemaPolicy: "disabled" });
    const file = await writeEnvFile(["A=", "B="].join("\n"));
    env.setPromptResponses(["y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    const notices = env.errors.filter((line) => line.includes("schema policy as disabled"));
    expect(notices).toHaveLength(1);
  });

  it("登録は変数ごとの複合の直列で、宣言 1 件あたり 3 往復(解決 + 複合 + 効果確認)", async () => {
    // 発見 F′ の実測の固定形: N 宣言 = 初回解決 1 + N × (解決 1 + create 1 +
    // 効果確認 1)。一括複合受理は実装しない(オーナー判断待ち — PR 本文の報告)
    const { env, state } = await startImportEnv();
    const file = await writeEnvFile(["A=", "B=", "C="].join("\n"));
    env.setPromptResponses(["y", "y", "y", ""]);
    expect(await runCli(["schema", "import", file], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["create", "create", "create"]);
    const requests = lastServer().requests;
    expect(requests.filter((request) => request.path.endsWith("/chain"))).toHaveLength(1);
    expect(requests.filter((request) => request.path.endsWith("/pull/metadata"))).toHaveLength(
      1 + 3 * 2,
    );
    expect(
      requests.filter(
        (request) => request.method === "POST" && request.path.endsWith("/variables"),
      ),
    ).toHaveLength(3);
  });
});
