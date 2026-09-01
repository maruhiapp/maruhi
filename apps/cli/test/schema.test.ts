// 値なしスキーマ S3 のテスト(設計文書 §1-1 / §1-2 / §1-4・CRYPTO_SPEC §4.2 /
// §6.3・AUTH_SPEC §12-7): `maruhi schema`(表示 — agent-gate 許可の固定込み)、
// `maruhi schema set`(部分更新・宣言作成・locked 事前検査・エントロピー
// fail-closed)、declared を含む配布の検証(ダイジェスト算入・値配布要求)、
// run の fail-fast(presence 硬 / type 柔)、push の activation、v3 レイアウトの
// 誠実な破壊様式(session-46 §8 第 5 周のテスト要件)。

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { findHighEntropySubstring } from "../src/entropy.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let built: BuiltChain;
let dek1: Uint8Array;
let wrap1: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
/** declared(required・url 型・description 付き — §4.2 レイアウト v2)。 */
let declaredRequired: WireDistributedVariableStatement;
/** declared(required = false・型未指定)。 */
let declaredOptional: WireDistributedVariableStatement;
/** v2 の active ステートメント(number 型)と値。 */
let activeV2: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
/** v1 の active ステートメントと値(スキーマ欄なし — 従来形)。 */
let activeV1: {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
};
let servers: MockServer[] = [];

const DESCRIPTION_REQUIRED = "Primary endpoint of the shop";

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    ...common,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: built.projectId },
  });
  const head = { seq: 1, hashHex: built.projectId };
  declaredRequired = await statementFor({
    ...common,
    variableId: "v-declared",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION_REQUIRED },
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
  activeV2 = {
    variableId: "v-port",
    statement: await statementFor({
      ...common,
      variableId: "v-port",
      name: "PORT",
      author: owner,
      head,
      schema: { varType: "number", required: true, description: "listen port" },
    }),
    value: await encryptValueFor({
      ...common,
      dek: dek1,
      epoch: 1,
      variableId: "v-port",
      version: 1,
      plaintext: "8080",
      writer: owner,
      head: headOf(built, 2),
    }),
  };
  activeV1 = {
    variableId: "v-legacy",
    statement: await statementFor({
      ...common,
      variableId: "v-legacy",
      name: "LEGACY_KEY",
      author: owner,
      head,
    }),
    value: await encryptValueFor({
      ...common,
      dek: dek1,
      epoch: 1,
      variableId: "v-legacy",
      version: 1,
      plaintext: "legacy-value",
      writer: owner,
      head: headOf(built, 2),
    }),
  };
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

function deksHandler(): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/deks`, () => ({
    status: 200,
    json: { deks: [wrap1] },
  }));
}

/** 配布集合(active の entry と declared / deleted の statement)→ digest 入力。 */
function digestStatementsOf(input: {
  readonly variables?: readonly { statement: WireDistributedVariableStatement }[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
}): readonly WireDistributedVariableStatement[] {
  return [
    ...(input.variables ?? []).map((entry) => entry.statement),
    ...(input.declaredVariables ?? []),
    ...(input.deletedVariables ?? []),
  ];
}

/** 値付き pull 応答(declaredVariables 同梱 — §12-7)。 */
function pullHandler(overrides?: {
  readonly variables?: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly declaredVariables?: readonly WireDistributedVariableStatement[];
  /** ダイジェスト入力の上書き(配布とダイジェストを意図的にずらす negative 用)。 */
  readonly digestStatements?: readonly WireDistributedVariableStatement[];
}): MockHandler {
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, async () => {
    const variables = overrides?.variables ?? [activeV2, activeV1];
    const declaredVariables = overrides?.declaredVariables ?? [declaredRequired, declaredOptional];
    const manifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements:
        overrides?.digestStatements ?? digestStatementsOf({ variables, declaredVariables }),
    });
    return {
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch: 1,
        statement: envStatement,
        variables,
        deletedVariables: [],
        ...(declaredVariables.length === 0 ? {} : { declaredVariables }),
        deks: [wrap1],
        manifest,
      },
    };
  });
}

interface MetadataOverrides {
  readonly variables?: readonly WireDistributedVariableStatement[];
  readonly schemaPolicy?: "disabled" | "enabled" | "locked";
  /**
   * 受理済みメタ操作の echo(§12-10 (3) の効果確認の材料): 受理後は
   * base + 受理ステートメント + 受理マニフェスト(issuer 帰属付き)を配る。
   */
  readonly echo?: {
    body: { statement: WireDistributedVariableStatement; manifest: WireDistributedManifest } | null;
    readonly base: readonly WireDistributedVariableStatement[];
  };
}

function metadataPolicyField(overrides?: MetadataOverrides): Record<string, unknown> {
  return overrides?.schemaPolicy === undefined ? {} : { schemaPolicy: overrides.schemaPolicy };
}

/** 受理済みメタ操作の配布(base + 受理ステートメント + 受理マニフェスト)。 */
function echoMetadataJson(
  echo: NonNullable<MetadataOverrides["echo"]> & {
    body: NonNullable<NonNullable<MetadataOverrides["echo"]>["body"]>;
  },
  overrides?: MetadataOverrides,
): unknown {
  const accepted = {
    ...echo.body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  };
  return {
    environmentId: ENV_ID,
    currentEpoch: 1,
    statement: envStatement,
    variables: [
      ...echo.base.filter((statement) => statement.variableId !== accepted.variableId),
      accepted,
    ],
    deletedVariables: [],
    manifest: {
      ...echo.body.manifest,
      issuerUserId: owner.userId,
      issuerKeyFingerprintHex: owner.fingerprintHex,
    },
    ...metadataPolicyField(overrides),
  };
}

async function defaultMetadataJson(overrides?: MetadataOverrides): Promise<unknown> {
  const variables = overrides?.variables ?? [
    activeV2.statement,
    activeV1.statement,
    declaredRequired,
    declaredOptional,
  ];
  const manifest = await manifestFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    epoch: 1,
    issuer: owner,
    head: headOf(built, 2),
    envStatement,
    statements: variables,
  });
  return {
    environmentId: ENV_ID,
    currentEpoch: 1,
    statement: envStatement,
    variables,
    deletedVariables: [],
    manifest,
    ...metadataPolicyField(overrides),
  };
}

/** メタのみ pull 応答(declared は variables に混在 — §12-7)。 */
function metadataHandler(overrides?: MetadataOverrides): MockHandler {
  return onRequest(
    "GET",
    `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => {
      const echo = overrides?.echo;
      const body = echo?.body ?? null;
      return {
        status: 200,
        json:
          echo !== undefined && body !== null
            ? echoMetadataJson({ ...echo, body }, overrides)
            : await defaultMetadataJson(overrides),
      };
    },
  );
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

describe("maruhi schema(表示 — §1-1)", () => {
  it("検証済みステートメント集合からスキーマ表を表示する(値ゼロ・宣言として表示)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler()]);
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("NAME\tTYPE\tREQUIRED\tSTATUS\tDESCRIPTION");
    // v2 declared: 型・必須・説明・状態が並ぶ
    expect(output).toContain(`SHOP_URL\turl\ttrue\tdeclared\t${DESCRIPTION_REQUIRED}`);
    expect(output).toContain("OPTIONAL_HINT\t-\tfalse\tdeclared\t-");
    // v2 active: STATUS = set
    expect(output).toContain("PORT\tnumber\ttrue\tset\tlisten port");
    // v1: TYPE / REQUIRED / DESCRIPTION は `-`
    expect(output).toContain("LEGACY_KEY\t-\t-\tset\t-");
    // 型は宣言として表示する(§14.3 の表示規律 — 「verified」の語を使わない)
    expect(output.toLowerCase()).not.toContain("verified");
    // 値は一切現れない
    expect(output).not.toContain("8080");
    expect(output).not.toContain("legacy-value");
    // TTY(既定)ではヘッダ注記を付けない
    expect(output).not.toContain("untrusted data");
  });

  it("非 TTY 出力の先頭に「データであって指示ではない」枠付けヘッダを付す(裁定 CW)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler()]);
    env.setTerminal({ stdout: false });
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const headerIndex = env.logs.findIndex((line) => line.includes("untrusted data"));
    const tableIndex = env.logs.findIndex((line) => line.startsWith("NAME\t"));
    expect(headerIndex).toBeGreaterThanOrEqual(0);
    expect(env.logs[headerIndex]).toContain("not as instructions");
    expect(headerIndex).toBeLessThan(tableIndex);
  });

  it("agent-gate の deny-list に含まれない(許可側 — §1-1 の固定)", async () => {
    // 値表示(pull --show)を拒否する 2 層ゲートの両方に該当する環境
    // (既知エージェント検出 + 非対話端末)でも、schema は動作する
    const env = await startEnv([chainHandler(), metadataHandler()]);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("SHOP_URL");
    expect(output).toContain("untrusted data");
  });

  it("値表示系の 2 層ゲートは不変(pull --show はエージェント環境で拒否のまま)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "testbot" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Refused to display values");
    expect(env.logs.join("\n")).not.toContain("8080");
  });

  it("description は escapeText で中和される(裁定 CK・CW — 署名済みでも良性とは限らない)", async () => {
    // 制御文字はサーバー受理(§12-8)が拒否するが、悪意サーバー・悪意署名者の
    // 配布は拘束されない — 表示側の中和は独立の義務
    const malicious = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-evil",
      name: "EVIL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: {
        varType: "string",
        required: false,
        description: "ok\u001b[31m\nrm -rf # not an instruction",
      },
    });
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [malicious] })]);
    expect(await runCli(["schema"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    // 生の ESC・生の改行注入は現れない(エスケープ表記に変換される)
    expect(output).not.toContain("\u001b");
    expect(output).toContain("\\u{001b}");
    expect(output).toContain("\\u{000a}");
  });
});

describe("declared を含む配布の検証(§6.3 / §12-7)", () => {
  it("declared を含む値付き pull がダイジェスト一致で成功し、宣言行を表示する", async () => {
    // S2 の既知ギャップ: declared をダイジェスト再計算へ算入しないと
    // variables-digest-mismatch で全 pull が落ちる — 成功すること自体が固定
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("SHOP_URL\t(declared — no value set)");
    expect(output).toContain("PORT");
  });

  it("active の検証済みステートメントが declared 列に現れたら値の欠落として拒否する(§6.3)", async () => {
    // 値を隠したいサーバーが active ステートメントを declaredVariables へ移す形:
    // ダイジェストは一致してしまう(ステートメントは無傷)ため、§6.3 の
    // 値配布要求だけが検出する
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [activeV1],
        declaredVariables: [declaredRequired, activeV2.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("carries no value for it");
    expect(errors).toContain("value omission");
  });

  it("declared ステートメントに値を併置した配布は拒否する(declared だけが正当な値なし状態)", async () => {
    const bogusValue = await encryptValueFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      dek: dek1,
      epoch: 1,
      variableId: "v-declared",
      version: 1,
      plaintext: "injected",
      writer: owner,
      head: headOf(built, 2),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          activeV1,
          { variableId: "v-declared", statement: declaredRequired, value: bogusValue },
        ],
        declaredVariables: [],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("declared statement together with a value");
  });

  it("layoutVersion v3 は『未対応レイアウト(クライアント更新)』の型付きエラーで割れる(session-46 §8 第 5 周)", async () => {
    // 配布 decode は Literal ではない(上限を固定しない整数)ため v3 は decode を
    // 通過し、署名検証より前のサポート範囲検査が誠実な破壊様式で拒否する —
    // Schema エラー・署名不正(改ざん疑い)に化けない
    const v3 = { ...activeV2.statement, layoutVersion: 3 };
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV2, statement: v3 }, activeV1],
        declaredVariables: [],
        // ダイジェストは v2 の正規形から計算(クライアントはステートメント段で
        // 拒否するため、マニフェスト段には到達しない)
        digestStatements: [activeV2.statement, activeV1.statement],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("layout version 3");
    expect(errors).toContain("update the maruhi CLI");
    expect(errors).toContain("not a tampering indication");
    expect(errors).not.toContain("forged");
    expect(errors).not.toContain("signature");
  });

  it("v2 フィールドの部分的な配布(全欠揃い違反)は拒否する(§12-2)", async () => {
    const partial: Record<string, unknown> = { ...declaredRequired };
    delete partial["description"];
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [activeV1],
        declaredVariables: [partial as unknown as WireDistributedVariableStatement],
        digestStatements: [activeV1.statement, declaredRequired],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("only part of the layout-v2 field set");
  });
});

describe("maruhi run の fail-fast(§1-4 — presence 硬 / type 柔)", () => {
  it("required = true の declared があれば子プロセスを起動せず型付きエラー(description 非出力)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(1);
    expect(env.runnerCalls).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Required variables are declared but have no value yet");
    expect(errors).toContain("SHOP_URL");
    expect(errors).toContain("The command was not started");
    // エラー文面に description を含めない(ログ経由の注入面 — session-46 §8 第 3 周)
    expect(errors).not.toContain(DESCRIPTION_REQUIRED);
  });

  it("required = false の declared は注入せず情報表示のみで実行する", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ declaredVariables: [declaredOptional] }),
    ]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv).not.toHaveProperty("OPTIONAL_HINT");
    expect(env.errors.join("\n")).toContain("declared variables without values were not injected");
  });

  it("型不一致は advisory 警告のみで実行は続行する(§14.3-7 — 値は文面に出さない)", async () => {
    const badPort = await encryptValueFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      dek: dek1,
      epoch: 1,
      variableId: "v-port",
      version: 1,
      plaintext: "not-a-number",
      writer: owner,
      head: headOf(built, 2),
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ ...activeV2, value: badPort }, activeV1],
        declaredVariables: [],
      }),
    ]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.extraEnv["PORT"]).toBe("not-a-number");
    const errors = env.errors.join("\n");
    expect(errors).toContain('does not match its declared type "number"');
    expect(errors).not.toContain("not-a-number");
  });

  it("型一致・v1(型なし)は警告しない", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ declaredVariables: [] })]);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).not.toContain("declared type");
  });
});

/** create / rename の受理 body を捕まえて echo(効果確認の配布)へ流す箱。 */
interface MutationEcho {
  body: { statement: WireDistributedVariableStatement; manifest: WireDistributedManifest } | null;
  readonly base: readonly WireDistributedVariableStatement[];
}

function captureCreate(echo: MutationEcho, calls: MockRequest[]): MockHandler {
  return onRequest(
    "POST",
    `/projects/${built.projectId}/environments/${ENV_ID}/variables`,
    (request) => {
      calls.push(request);
      echo.body = request.body as MutationEcho["body"];
      const body = request.body as {
        statement: WireDistributedVariableStatement;
        value?: unknown;
      };
      return {
        status: 200,
        json: {
          variableId: body.statement.variableId,
          version: body.value === undefined ? 0 : 1,
          epoch: 1,
        },
      };
    },
  );
}

function captureRename(echo: MutationEcho, calls: MockRequest[], variableId: string): MockHandler {
  return onRequest(
    "PATCH",
    `/projects/${built.projectId}/environments/${ENV_ID}/variables/${variableId}`,
    (request) => {
      calls.push(request);
      echo.body = request.body as MutationEcho["body"];
      return { status: 204, bodyText: "" };
    },
  );
}

describe("maruhi schema set(§1-2)", () => {
  it("未存在の名前は宣言(declared・metaVersion 1)として作成する(既定 required = true)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], echo }),
      captureCreate(echo, createCalls),
    ]);
    expect(await runCli(["schema", "set", "DATABASE_URL", "--type", "url"], env.layer)).toBe(0);
    expect(createCalls).toHaveLength(1);
    const body = createCalls[0]?.body as {
      statement: Record<string, unknown>;
      value?: unknown;
      manifest: Record<string, unknown>;
    };
    // 値は同梱しない(declared 作成 — §12-5)
    expect(body.value).toBeUndefined();
    expect(body.statement["status"]).toBe("declared");
    expect(body.statement["metaVersion"]).toBe(1);
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    // 作成既定: required = true(§1-2 — 宣言は環境の契約)・description = ""
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe("");
    expect(body.statement["name"]).toBe("DATABASE_URL");
    expect(body.manifest["manifestVersion"]).toBe(2);
    const output = env.logs.join("\n");
    expect(output).toContain("Declared DATABASE_URL (type=url, required=true)");
    expect(output).toContain("maruhi push DATABASE_URL");
  });

  it("既存変数のスキーマ再発行は部分更新(未指定の欄は直前ステートメントを引き継ぐ)", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      captureRename(echo, renameCalls, "v-declared"),
    ]);
    expect(
      await runCli(["schema", "set", "SHOP_URL", "--description", "New words"], env.layer),
    ).toBe(0);
    expect(renameCalls).toHaveLength(1);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    // --description だけの実行で型・必須が黙って落ちない(全置換の禁止 — §1-2)
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe("New words");
    // 状態・名前は不変(スキーマ再発行 — declared のまま)
    expect(body.statement["status"]).toBe("declared");
    expect(body.statement["name"]).toBe("SHOP_URL");
    expect(body.statement["metaVersion"]).toBe(2);
    expect(body.statement["prevMetaSigHashHex"]).not.toBe("");
    expect(env.logs.join("\n")).toContain("Updated the schema of SHOP_URL");
  });

  it("--optional / --type none / --clear-description で欄を明示的に下げ・空へ戻せる", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const renameCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      captureRename(echo, renameCalls, "v-declared"),
    ]);
    expect(
      await runCli(
        ["schema", "set", "SHOP_URL", "--optional", "--type", "none", "--clear-description"],
        env.layer,
      ),
    ).toBe(0);
    const body = renameCalls[0]?.body as { statement: Record<string, unknown> };
    expect(body.statement["varType"]).toBe("");
    expect(body.statement["required"]).toBe(false);
    expect(body.statement["description"]).toBe("");
  });

  it("locked の advisory 下では --type 未指定の作成を署名・送信前にローカルで拒否する(§1-2)", async () => {
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], schemaPolicy: "locked" }),
    ]);
    expect(await runCli(["schema", "set", "NEW_VAR"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("schema policy is locked");
    expect(errors).toContain("--type");
    // 署名・送信は行われていない(POST が 1 件もない)
    expect(lastServer().requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("disabled の advisory は事前案内を出す(SHOULD — 送信は行う: 受理の正はサーバー)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], schemaPolicy: "disabled", echo }),
      captureCreate(echo, createCalls),
    ]);
    expect(await runCli(["schema", "set", "NEW_VAR"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("schema policy as disabled");
    expect(createCalls).toHaveLength(1);
  });

  it("--required と --optional の併用は usage エラー", async () => {
    const env = await startEnv([chainHandler()]);
    expect(await runCli(["schema", "set", "X", "--required", "--optional"], env.layer)).toBe(2);
    expect(lastServer().requests).toHaveLength(0);
  });
});

describe("エントロピー警告(裁定 CW — fail-closed)", () => {
  // 実値らしく見えるダミー(実在のシークレットではない)
  const FAKE_SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA0K11";

  it("検出器: 秘密らしき列を検出し、通常の英文・識別子は通す", () => {
    expect(findHighEntropySubstring(FAKE_SECRET)).not.toBeNull();
    // API キー風の混在トークン(ダミー)は文中でも検出する
    expect(
      findHighEntropySubstring("token is x7Gh2kQ9pLmA3vB8nC4dE5fJ6hK7iL8m here"),
    ).not.toBeNull();
    // 反復パターンは高エントロピーではない(検出しない — 実値らしさの根拠は乱雑さ)
    expect(findHighEntropySubstring(`token is ${"a1B2".repeat(10)}`)).toBeNull();
    // 64 hex(ダミーの乱数風)も検出する
    expect(
      findHighEntropySubstring("0f8e2d1c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"),
    ).not.toBeNull();
    expect(findHighEntropySubstring("Primary endpoint of the shop frontend")).toBeNull();
    expect(findHighEntropySubstring("DATABASE_URL")).toBeNull();
    expect(findHighEntropySubstring("MY_SUPER_LONG_VARIABLE_NAME_2024")).toBeNull();
    expect(findHighEntropySubstring("PostgresConnectionPoolingEndpoint")).toBeNull();
    expect(findHighEntropySubstring("")).toBeNull();
  });

  it("非対話環境では明示フラグなしに型付きエラーで拒否する(通信・署名より前)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [] })]);
    env.setTerminal({ stdout: false });
    expect(
      await runCli(["schema", "set", "API_HINT", "--description", FAKE_SECRET], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("secret-like high-entropy");
    expect(errors).toContain("--allow-high-entropy");
    // 入力そのものはエラーへ出さない(秘密でありうる)
    expect(errors).not.toContain(FAKE_SECRET);
    // ネットワークへ一切出ていない(fail-closed は入力時 — 事故の前)
    expect(lastServer().requests).toHaveLength(0);
  });

  it("対話環境では警告 + 明示確認(拒否の応答で中断する)", async () => {
    const env = await startEnv([chainHandler(), metadataHandler({ variables: [] })]);
    env.setPromptResponses(["no"]);
    expect(
      await runCli(["schema", "set", "API_HINT", "--description", FAKE_SECRET], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("secret-like high-entropy");
    expect(env.prompts.join("\n")).toContain("Continue anyway?");
    expect(lastServer().requests).toHaveLength(0);
  });

  it("--allow-high-entropy は確認なしで続行する(事実は警告として可視化)", async () => {
    const echo: MutationEcho = { body: null, base: [] };
    const createCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      metadataHandler({ variables: [], echo }),
      captureCreate(echo, createCalls),
    ]);
    env.setTerminal({ stdout: false });
    expect(
      await runCli(
        ["schema", "set", "API_HINT", "--description", FAKE_SECRET, "--allow-high-entropy"],
        env.layer,
      ),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain("--allow-high-entropy was given");
    expect(createCalls).toHaveLength(1);
  });
});

describe("maruhi push の activation(declared への最初の値 push — §12-5)", () => {
  it("declared に解決された push は activation 複合を組む(スキーマ欄・名前を引き継ぐ)", async () => {
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    const activateCalls: MockRequest[] = [];
    const env = await startEnv([
      chainHandler(),
      deksHandler(),
      metadataHandler({ variables: [declaredRequired], echo }),
      onRequest(
        "POST",
        `/projects/${built.projectId}/environments/${ENV_ID}/variables/v-declared/activate`,
        (request) => {
          activateCalls.push(request);
          echo.body = request.body as MutationEcho["body"];
          return { status: 200, json: { variableId: "v-declared", version: 1, epoch: 1 } };
        },
      ),
    ]);
    env.setStdin(new TextEncoder().encode("https://shop.example"));
    expect(await runCli(["push", "SHOP_URL"], env.layer)).toBe(0);
    expect(activateCalls).toHaveLength(1);
    const body = activateCalls[0]?.body as {
      statement: Record<string, unknown>;
      value: { aad: Record<string, unknown> };
      manifest: Record<string, unknown>;
    };
    // 値は version 1(declared の latest は常に 0)
    expect(body.value.aad["version"]).toBe(1);
    // activation ステートメント: status active・metaVersion + 1・スキーマ欄と
    // 名前は宣言時の値を byte-exact に引き継ぐ
    expect(body.statement["status"]).toBe("active");
    expect(body.statement["metaVersion"]).toBe(2);
    expect(body.statement["name"]).toBe("SHOP_URL");
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe(DESCRIPTION_REQUIRED);
    expect(body.manifest["manifestVersion"]).toBe(2);
    expect(env.logs.join("\n")).toContain("Pushed SHOP_URL (version=1, epoch=1)");
  });

  it("並行 declare に負けた create は 409 duplicate-name から activation へ切り替える", async () => {
    // 1 回目の解決 = 未存在 → create、サーバーは 409(並行 declare が先に着地)、
    // 再解決 = declared → activation 複合(§12-5 の再試行 = 再取得 → 再署名)
    const echo: MutationEcho = { body: null, base: [declaredRequired] };
    let metadataCalls = 0;
    const activateCalls: MockRequest[] = [];
    const emptyManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [],
    });
    // 再解決の集合(declared が着地した後)は manifestVersion 2 で、prev を
    // 1 回目のマニフェストへ実際に連鎖させる(隣接版の prev 検証 — M1-A1)
    const declaredManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [declaredRequired],
      manifestVersion: 2,
      prevManifestSigHashHex: await manifestHashOf(built.projectId, emptyManifest),
    });
    const env = await startEnv([
      chainHandler(),
      deksHandler(),
      onRequest(
        "GET",
        `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => {
          if (echo.body !== null) {
            return {
              status: 200,
              json: {
                environmentId: ENV_ID,
                currentEpoch: 1,
                statement: envStatement,
                variables: [
                  {
                    ...echo.body.statement,
                    authorUserId: owner.userId,
                    authorKeyFingerprintHex: owner.fingerprintHex,
                  },
                ],
                deletedVariables: [],
                manifest: {
                  ...echo.body.manifest,
                  issuerUserId: owner.userId,
                  issuerKeyFingerprintHex: owner.fingerprintHex,
                },
              },
            };
          }
          metadataCalls += 1;
          const first = metadataCalls === 1;
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: first ? [] : [declaredRequired],
              deletedVariables: [],
              manifest: first ? emptyManifest : declaredManifest,
            },
          };
        },
      ),
      onRequest("POST", `/projects/${built.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "v-declared", reason: "duplicate-name" },
      })),
      onRequest(
        "POST",
        `/projects/${built.projectId}/environments/${ENV_ID}/variables/v-declared/activate`,
        (request) => {
          activateCalls.push(request);
          echo.body = request.body as MutationEcho["body"];
          return { status: 200, json: { variableId: "v-declared", version: 1, epoch: 1 } };
        },
      ),
    ]);
    env.setStdin(new TextEncoder().encode("https://shop.example"));
    expect(await runCli(["push", "SHOP_URL"], env.layer)).toBe(0);
    expect(activateCalls).toHaveLength(1);
  });
});
