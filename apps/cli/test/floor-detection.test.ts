// ローカル床の結線テスト(CRYPTO_SPEC §6.3 規則 (a)(b)(c) — session-12 §8-5 の
// 床項目)。同一 TestEnv(= 同一の床ファイル)に対してモックサーバーを差し替え、
// セッション(プロセス実行)を跨ぐ巻き戻し・欠落・前進注入の永続検出を検査する。
//
// フェーズ 1 は常に正直な応答で床を確立し、フェーズ 2 以降で改竄された配布を
// 与える。改竄はすべて正規鍵の有効署名付き(署名検証は通る)— 床だけが検出
// できる攻撃面であることを固定する。

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { decodeProjectFloor, type ProjectFloor } from "../src/floor.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  rotateEpochOp,
  statementFor,
  type TestUser,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

let owner: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** chain1 = [genesis, create_environment](epoch 1)。 */
let chain1: BuiltChain;
/** chain2 = chain1 + rotate_epoch(2)(決定的ビルドにより chain1 の厳密な延長)。 */
let chain2: BuiltChain;
/** chainB = genesis は同一だが seq 2 から分岐した別チェーン。 */
let chainB: BuiltChain;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let projectId: string;

let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const dekB = crypto.getRandomValues(new Uint8Array(32));
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ];
  chain1 = await buildChain(steps);
  chain2 = await buildChain([
    ...steps,
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  // 同一 genesis から seq 2 で分岐(create の DEK コミットメントが異なる)
  chainB = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dekB) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dekB) },
  ]);
  projectId = chain1.projectId;
  expect(chain2.projectId).toBe(projectId);
  expect(chain2.hashes[1]).toBe(chain1.hashes[1]);
  expect(chainB.projectId).toBe(projectId);
  expect(chainB.hashes[1]).not.toBe(chain1.hashes[1]);
  const common = { projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function genesisHead(): { seq: number; hashHex: string } {
  return { seq: 1, hashHex: projectId };
}

/** 変数値(epoch に応じた正しい宣言ヘッド: epoch1 = create、epoch2 = rotate)。 */
async function valueOf(input: {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: 1 | 2;
  readonly plaintext: string;
  readonly prevValueSigHashHex?: string;
}): Promise<WireDistributedValue> {
  return encryptValueFor({
    dek: input.epoch === 1 ? dek1 : dek2,
    projectId,
    environmentId: ENV_ID,
    epoch: input.epoch,
    variableId: input.variableId,
    version: input.version,
    plaintext: input.plaintext,
    writer: owner,
    head: input.epoch === 1 ? headOf(chain1, 2) : headOf(chain2, 3),
    ...(input.prevValueSigHashHex === undefined
      ? {}
      : { prevValueSigHashHex: input.prevValueSigHashHex }),
  });
}

async function statementOf(input: {
  readonly variableId: string;
  readonly name: string;
  readonly metaVersion?: number;
  readonly status?: "active" | "deleted";
  readonly prevMetaSigHashHex?: string;
}): Promise<WireDistributedVariableStatement> {
  return statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: input.variableId,
    name: input.name,
    author: owner,
    head: genesisHead(),
    ...(input.metaVersion === undefined ? {} : { metaVersion: input.metaVersion }),
    ...(input.status === undefined ? {} : { status: input.status }),
    ...(input.prevMetaSigHashHex === undefined
      ? {}
      : { prevMetaSigHashHex: input.prevMetaSigHashHex }),
  });
}

interface PullPayload {
  readonly statement?: WireDistributedEnvironmentStatement;
  readonly variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly deks: readonly WireRecipientDek[];
  readonly currentEpoch?: number;
}

function chainHandlerFor(chains: readonly BuiltChain[]): MockHandler {
  // 呼び出しごとに進む(future head の有界再同期で次のチェーンが見える)
  let call = 0;
  return onRequest("GET", `/projects/${projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
      },
    };
  });
}

function pullHandlerFor(payload: PullPayload): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: payload.currentEpoch ?? 1,
      statement: payload.statement ?? envStatement,
      variables: payload.variables,
      deletedVariables: payload.deletedVariables ?? [],
      deks: payload.deks,
    },
  }));
}

function deksHandlerFor(deks: readonly WireRecipientDek[]): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/deks`, () => ({
    status: 200,
    json: { deks },
  }));
}

/** 同一 TestEnv(= 同一の床)に対する新しいサーバーフェーズを開始する。 */
async function startPhase(env: TestEnv, handlers: readonly MockHandler[]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
  return server;
}

async function readFloorFile(env: TestEnv): Promise<ProjectFloor> {
  const raw = await readFile(join(env.floorDir, `${projectId}.json`), "utf8");
  const floor = decodeProjectFloor(raw);
  expect(floor).not.toBeNull();
  return floor as ProjectFloor;
}

/** フェーズ 1(正直な配布)で床を確立し、pull が成功することを検証する。 */
async function establishFloor(env: TestEnv, payload: PullPayload, chain = chain1): Promise<void> {
  await startPhase(env, [chainHandlerFor([chain]), pullHandlerFor(payload)]);
  expect(await runCli(["pull"], env.layer)).toBe(0);
}

describe("床の確立と fail-open(§6.3 / 床なし・破損)", () => {
  it("初回同期は床なしの注意を出し、床ファイルを作る(非機密ダイジェストのみ)", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "beta-value" });
    await establishFloor(env, {
      variables: [
        {
          variableId: "vb",
          statement: await statementOf({ variableId: "vb", name: "BETA" }),
          value: beta,
        },
      ],
      deks: [wrap1],
    });
    expect(env.errors.join("\n")).toContain("初回同期");
    const floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 2, hashHex: chain1.hashes[1] });
    const record = floor.environments[ENV_ID];
    expect(record?.pullEpoch).toBe(1);
    expect(record?.variables["vb"]).toMatchObject({ status: "active", version: 1, epoch: 1 });
    // 床ファイルに平文値・変数名を書かない(ディスクレス不変条件)
    const raw = await readFile(join(env.floorDir, `${projectId}.json`), "utf8");
    expect(raw).not.toContain("beta-value");
    expect(raw).not.toContain("BETA");
  });

  it("床ファイルの破損は初回とは異なる警告で fail-open し、次の成功 pull で作り直す", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const entry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    await establishFloor(env, { variables: [entry], deks: [wrap1] });
    await writeFile(join(env.floorDir, `${projectId}.json`), "{broken-json");
    env.errors.length = 0;
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("破損");
    expect(errors).not.toContain("初回同期");
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 1 });
  });
});

describe("巻き戻しの永続検出(§6.3 規則 (a) / session-12 §8-5)", () => {
  it("version の後退を拒否し、両 signed bytes ハッシュと宣言ヘッドを証拠として出す", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "old" });
    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 1,
      plaintext: "new",
      prevValueSigHashHex: await valueHashOf(v1, owner.userId),
    });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v2 }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value: v1 }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("値バージョンの巻き戻し");
    // fork 証拠: 床側と配布側の signed bytes ハッシュ・宣言ヘッド・座標
    expect(errors).toContain(await valueHashOf(v2, owner.userId));
    expect(errors).toContain(await valueHashOf(v1, owner.userId));
    expect(errors).toContain(`variable=vb`);
    expect(errors).toContain(`宣言ヘッド: seq=2`);
    // 平文値は証拠に含まれない
    expect(errors).not.toContain("old");
    expect(errors).not.toContain("new");
  });

  it("拒否された pull は床を前進させない(更新順序の規範 — 検査は前回基準)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "old" });
    const v2 = await valueOf({ variableId: "vb", version: 2, epoch: 1, plaintext: "new" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v2 }],
      deks: [wrap1],
    });
    const before = await readFloorFile(env);

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value: v1 }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const after = await readFloorFile(env);
    expect(after.environments[ENV_ID]).toEqual(before.environments[ENV_ID]);
  });

  it("変数 metaVersion の後退を拒否する", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const metaV2 = await statementOf({ variableId: "vb", name: "BETA", metaVersion: 2 });
    const metaV1 = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: metaV2, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: metaV1, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("メタステートメントの巻き戻し");
  });

  it("環境 metaVersion の後退を拒否する", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const envMetaV2 = await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: "prod-renamed",
      author: owner,
      head: genesisHead(),
      metaVersion: 2,
    });
    await establishFloor(env, {
      statement: envMetaV2,
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: envStatement,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("メタステートメントの巻き戻し");
  });

  it("環境メタの同一 metaVersion への異なる signed bytes(環境名の付け替え)を拒否する", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    // 同一 metaVersion 1 で name だけ異なる環境ステートメント(有効署名)
    const swapped = await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: "prod-swapped",
      author: owner,
      head: genesisHead(),
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: swapped,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("metaVersion への異なる signed bytes");
    // 環境メタの証拠座標は環境まで(variable= を含まない)
    expect(errors).toContain(`座標: project=${projectId} environment=${ENV_ID}\n`);
  });

  it("エポックの後退(前進 version への床エポック未満の配布)を拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "va", name: "ALPHA" });
    const v3e2 = await valueOf({ variableId: "va", version: 3, epoch: 2, plaintext: "cur" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "va", statement, value: v3e2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    // version 4 > 床 3 だが epoch 1 < 床の epoch 2(§4.1 単調性違反)
    const v4e1 = await valueOf({ variableId: "va", version: 4, epoch: 1, plaintext: "regressed" });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "va", statement, value: v4e1 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("単調性違反");
  });

  it("チェーン長の後退(短縮)を拒否する(有界再同期でも解決しない場合)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    // 再同期(2 回目の chain 取得)でも chain1 のまま = 真の短縮
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("チェーンの短縮");
    expect(errors).toContain(`seq=3 hash=${chain2.hashes[2]}`);
    expect(errors).toContain(`seq=2 hash=${chain1.hashes[1]}`);
  });

  it("床ヘッドが自ビューより先の正直なレース(兄弟プロセスの前進)は有界再同期で解決する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    // 床は chain2(seq 3)まで確立済み
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    // 1 回目の同期は古いビュー(chain1)を掴む(同期と床ロードの間に兄弟が床を
    // 前進させた形のレース)→ 短縮を即時証拠にせず 1 回だけ再同期して解決する
    await startPhase(env, [
      chainHandlerFor([chain1, chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });
});

describe("欠落の永続検出(§6.3 規則 (a) / session-12 §8-5)", () => {
  async function twoVariablePhases(env: TestEnv): Promise<void> {
    const alpha = await valueOf({ variableId: "va", version: 1, epoch: 1, plaintext: "a" });
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const alphaEntry = {
      variableId: "va",
      statement: await statementOf({ variableId: "va", name: "ALPHA" }),
      value: alpha,
    };
    const betaEntry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    await establishFloor(env, { variables: [alphaEntry, betaEntry], deks: [wrap1] });
    // フェーズ 2: BETA を配布から落とす(選択的な応答の切り詰め)
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [alphaEntry], deks: [wrap1] }),
      deksHandlerFor([wrap1]),
    ]);
  }

  it("pull: 検証済み変数の欠落を拒否する", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("欠落");
    expect(errors).toContain("variable=vb");
  });

  it("run: 欠落した配布ではコマンドを実行しない(非ゼロ終了)", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    expect(await runCli(["run", "--", "printenv"], env.layer)).toBe(1);
    expect(env.runnerCalls).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("欠落");
  });

  it("push: 欠落した配布では push しない(解決 pull で床検査が発火)", async () => {
    const env = await makeTestEnv();
    await twoVariablePhases(env);
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "ALPHA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("欠落");
  });

  it("tombstone の欠落(削除記録の隠蔽)を拒否する", async () => {
    const env = await makeTestEnv();
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const betaEntry = {
      variableId: "vb",
      statement: await statementOf({ variableId: "vb", name: "BETA" }),
      value: beta,
    };
    const tombstone = await statementOf({
      variableId: "vd",
      name: "DELETED_VAR",
      metaVersion: 2,
      status: "deleted",
    });
    await establishFloor(env, {
      variables: [betaEntry],
      deletedVariables: [tombstone],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [betaEntry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("欠落");
    expect(errors).toContain("variable=vd");
  });
});

describe("前進注入の床検出と誤拒否なし(§6.3 規則 (c) / session-12 §12 ループ 2 の両縁)", () => {
  it("ローテーション前の正当な旧エポック新版は受理し、基準前進後の旧エポック新版は拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "v1" });
    // フェーズ 1: epoch 1 のチェーンで pull(基準 = 1)
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    // フェーズ 2: rotate 済みチェーン(現エポック 2)だが、rotate 前に正当に
    // push された v2(epoch 1)が最新のまま = 再暗号化完了前の正当な状態。
    // 基準は前回 pull の 1 なので誤拒否しない(規則 (c) の誤拒否側の縁)
    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 1,
      plaintext: "v2",
      prevValueSigHashHex: await valueHashOf(v1, owner.userId),
    });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    // 検証成功後、基準は変数床と原子的に 2 へ前進している
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(2);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 1 });

    // フェーズ 3: 基準 2 の下で、床の version より新しい v3 が epoch 1 のまま =
    // 旧エポック鍵による前進注入の形(規則 (c) の検出側の縁)
    const v3 = await valueOf({
      variableId: "vb",
      version: 3,
      epoch: 1,
      plaintext: "v3",
      prevValueSigHashHex: await valueHashOf(v2, owner.userId),
    });
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v3 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("前進注入");
    expect(errors).toContain("pull 時点エポック基準=2");
  });

  it("床にない新規変数にも規則 (c) を適用する(基準未満のエポックの新規配布は注入の形)", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const beta = await valueOf({ variableId: "vb", version: 1, epoch: 2, plaintext: "b" });
    // 基準 2 の床を確立(rotate 済みチェーン)
    await establishFloor(
      env,
      {
        variables: [{ variableId: "vb", statement, value: beta }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      },
      chain2,
    );

    // 前回 pull 以降に「作られた」ことになっている新規変数が epoch 1 = 基準未満
    // (正当な作成は作成時点の現エポック ≥ 基準でしか起きない)
    const injected = await valueOf({ variableId: "vc", version: 1, epoch: 1, plaintext: "x" });
    const injectedEntry = {
      variableId: "vc",
      statement: await statementOf({ variableId: "vc", name: "GAMMA" }),
      value: injected,
    };
    const betaEntry = { variableId: "vb", statement, value: beta };
    await startPhase(env, [
      chainHandlerFor([chain2]),
      pullHandlerFor({
        variables: [betaEntry, injectedEntry],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("前進注入");
    expect(errors).toContain("variable=vc");
    expect(errors).toContain("version=0(0 = 床に記録なし)");
  });
});

describe("同一座標の signed bytes 相違の証拠化(§6.3 規則 (b) / §14.2-5)", () => {
  it("同一 version への異なる signed bytes の配布を equivocation の証拠として拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const original = await valueOf({
      variableId: "vb",
      version: 1,
      epoch: 1,
      plaintext: "original",
    });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: original }],
      deks: [wrap1],
    });

    // 同一 version 1 に別内容(fresh nonce・別平文)— 署名は正規鍵で有効
    const replaced = await valueOf({
      variableId: "vb",
      version: 1,
      epoch: 1,
      plaintext: "replaced",
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: replaced }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("equivocation");
    expect(errors).toContain(await valueHashOf(original, owner.userId));
    expect(errors).toContain(await valueHashOf(replaced, owner.userId));
  });

  it("同一 metaVersion への異なる signed bytes(名前の付け替え)を拒否する", async () => {
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const original = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: original, value }],
      deks: [wrap1],
    });

    const renamed = await statementOf({ variableId: "vb", name: "BETA_SWAPPED" });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: renamed, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("metaVersion への異なる signed bytes");
  });
});

describe("削除の床意味論(§6.3 規則 (a) / session-15 §2-2 の終端状態)", () => {
  const tombstoneOf = () =>
    statementOf({ variableId: "vb", name: "BETA", metaVersion: 2, status: "deleted" });

  it("正当な削除(metaVersion 前進の tombstone)は受理し、床を deleted へ進める", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [], deletedVariables: [await tombstoneOf()], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({
      status: "deleted",
      metaVersion: 2,
    });
  });

  it.each([
    ["metaVersion 前進", 3],
    ["同一 metaVersion", 2],
    ["metaVersion 後退", 1],
  ])(
    "削除の無断取り消し(deleted 記録済みの active 配布 — %s)を拒否する",
    async (_label, metaVersion) => {
      const env = await makeTestEnv();
      await establishFloor(env, {
        variables: [],
        deletedVariables: [await tombstoneOf()],
        deks: [wrap1],
      });

      // 削除済み variableId が active として配布される(metaVersion の値に依らず
      // 拒否 — deleted は終端状態で正当な再 active 化が存在しない)
      const revived = await statementOf({ variableId: "vb", name: "BETA", metaVersion });
      const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
      await startPhase(env, [
        chainHandlerFor([chain1]),
        pullHandlerFor({
          variables: [{ variableId: "vb", statement: revived, value }],
          deks: [wrap1],
        }),
      ]);
      expect(await runCli(["pull"], env.layer)).toBe(1);
      expect(env.errors.join("\n")).toContain("削除の無断取り消し");
    },
  );

  it("tombstone の差し替え(deleted は終端状態 — 床との厳密一致を要求)を拒否する", async () => {
    const env = await makeTestEnv();
    await establishFloor(env, {
      variables: [],
      deletedVariables: [await tombstoneOf()],
      deks: [wrap1],
    });

    const forged = await statementOf({
      variableId: "vb",
      name: "BETA",
      metaVersion: 3,
      status: "deleted",
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [], deletedVariables: [forged], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("tombstone の差し替え");
  });
});

describe("分岐 2 種の区別(§6.3-2 / session-12 §8-5)", () => {
  it("床 seq 以下のハッシュ不一致(同一 genesis の別分岐)は即時証拠として拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    // chainB は genesis 同一・seq 2 から分岐・長さは床より先(3)= 短縮ではなく分岐
    await startPhase(env, [chainHandlerFor([chainB]), pullHandlerFor({ variables: [], deks: [] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("異なる分岐の配布");
    expect(errors).toContain(chain1.hashes[1] as string);
    expect(errors).toContain(chainB.hashes[1] as string);
  });

  it("床より先の宣言ヘッドは有界再同期で解決し、延長なら受理して床を前進させる", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    // 値の宣言ヘッドが seq 3(rotate 後)= 自ビュー(chain1)より先 → 再同期で
    // chain2(chain1 の延長)が見え、正常受理される
    const v2 = await valueOf({
      variableId: "vb",
      version: 2,
      epoch: 2,
      plaintext: "b2",
      prevValueSigHashHex: await valueHashOf(v1, owner.userId),
    });
    await startPhase(env, [
      chainHandlerFor([chain1, chain2]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: v2 }],
        deks: [wrap1, wrap2],
        currentEpoch: 2,
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 3, hashHex: chain2.hashes[2] });
    // 規則 (c) 基準は応答取得**前**のビュー(chain1 = エポック 1)から導出する:
    // 再同期(チェーン同期)で知ったエポック 2 を基準へ昇格させると、応答生成と
    // 再同期の間に rotate が挟まった場合に「ローテーション後・再暗号化完了前」の
    // 正当な旧エポック最新値を次回 pull で誤拒否する(§6.3 の「チェーン同期単独で
    // 基準を前進させない」規範の再同期経路への適用 — レビュー②)
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 2 });
  });

  it("床より先の宣言ヘッドが再同期でも解決しなければ証拠として拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value: v1 }],
      deks: [wrap1],
    });

    // 宣言ヘッド seq 3 は chain1 より先だが、再同期しても chain1 のまま =
    // 存在しないヘッドへの束縛(分岐または偽造の証拠)
    const forged = await encryptValueFor({
      dek: dek1,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vb",
      version: 2,
      plaintext: "forged",
      writer: owner,
      head: { seq: 3, hashHex: "ef".repeat(32) },
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement, value: forged }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("分岐または偽造の証拠");
  });
});

describe("push 受理後の床前進(§6.3 — 自分の書き込みの巻き戻し検出)", () => {
  it("push が床を前進させ、直後の古い配布の pull を拒否する", async () => {
    const env = await makeTestEnv();
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    const v1 = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const entry = { variableId: "vb", statement, value: v1 };
    // フェーズ 1: push(解決 pull は v1 → v2 を受理)
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
      deksHandlerFor([wrap1]),
      onRequest(
        "POST",
        `/projects/${projectId}/environments/${ENV_ID}/variables/vb/versions`,
        () => ({ status: 200, json: { variableId: "vb", version: 2, epoch: 1 } }),
      ),
    ]);
    env.setStdin(new TextEncoder().encode("updated"));
    expect(await runCli(["push", "BETA"], env.layer)).toBe(0);
    const floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 2, epoch: 1 });
    // 規則 (c) 基準は push では動かない(pull 時点のまま)
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);

    // フェーズ 2: サーバーが push 前の v1 を配布(自分の書き込みの巻き戻し)
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [entry], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("値バージョンの巻き戻し");
  });
});

describe("メタの前進注入は床でも検出されない(§14.3-5 — 非保証の明示)", () => {
  it("前進 metaVersion の注入(名前の付け替え)は床があっても受理される(既知の残余)", async () => {
    // メタステートメントはエポックアンカーを持たず(§4.2)、値の規則 (c) に
    // 相当する検出は構造的に存在しない。床の保証は巻き戻し検出のみであり、
    // このテストは「検出済み」と誤認しないための非保証の固定である。
    // 閉包は Phase 2 の環境マニフェスト / チェックポイント(未決 #12)の責務
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const original = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement: original, value }],
      deks: [wrap1],
    });

    // 実最新(metaVersion 1)の次の metaVersion 2 を偽造(正規鍵の有効署名 —
    // 在籍区間内の鍵 + サーバー共謀の形)。巻き戻しも欠落もないため床は発火しない
    const injected = await statementOf({
      variableId: "vb",
      name: "BETA_INJECTED",
      metaVersion: 2,
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        variables: [{ variableId: "vb", statement: injected, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("BETA_INJECTED");
  });

  it("環境メタの前進注入も床では検出されない(§14.3-5 — 任意の変数・環境のメタに成立)", async () => {
    // §14.3-5: 前進注入は攻撃鍵が在籍区間中に author 資格を持っていた任意の
    // 変数・環境のメタに成立する。変数側と同様、環境側も非検出を固定する
    const env = await makeTestEnv();
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await establishFloor(env, {
      variables: [{ variableId: "vb", statement, value }],
      deks: [wrap1],
    });

    const injectedEnvMeta = await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: "prod-injected",
      author: owner,
      head: genesisHead(),
      metaVersion: 2,
    });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({
        statement: injectedEnvMeta,
        variables: [{ variableId: "vb", statement, value }],
        deks: [wrap1],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });
});

describe("commitHead のみの床(project verify 先行)との相互作用", () => {
  it("verify で作られたヘッドのみの床から、後続 pull が環境床を確立できる", async () => {
    const env = await makeTestEnv();
    // フェーズ 1: project verify(チェーン床検査 + ヘッド前進のみ。環境床なし)
    await startPhase(env, [chainHandlerFor([chain1])]);
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    let floor = await readFloorFile(env);
    expect(floor.chainHead).toEqual({ seq: 2, hashHex: chain1.hashes[1] });
    expect(floor.environments[ENV_ID]).toBeUndefined();

    // フェーズ 2: pull が環境床(規則 (c) 基準込み)を確立する
    const value = await valueOf({ variableId: "vb", version: 1, epoch: 1, plaintext: "b" });
    const statement = await statementOf({ variableId: "vb", name: "BETA" });
    await startPhase(env, [
      chainHandlerFor([chain1]),
      pullHandlerFor({ variables: [{ variableId: "vb", statement, value }], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    floor = await readFloorFile(env);
    expect(floor.environments[ENV_ID]?.pullEpoch).toBe(1);
    expect(floor.environments[ENV_ID]?.variables["vb"]).toMatchObject({ version: 1 });
  });
});
