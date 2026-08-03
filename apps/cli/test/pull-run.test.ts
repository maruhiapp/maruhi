// pull(§5.1 配布時検証 + §12-7 全エポック DEK)と run(メモリ注入)、
// AI エージェント検出の線引き(値表示は拒否 / run は許可)のテスト。

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  type BuiltChain,
  encryptValueFor,
  genesisOp,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  type WireEncryptedPayload,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";

interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly wraps: readonly WireRecipientDek[];
  readonly valueAlpha: WireEncryptedPayload;
  readonly valueBeta: WireEncryptedPayload;
}

let fixture: Fixture;
let servers: MockServer[] = [];

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2) },
  ]);
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
  // 最新バージョンのエポックは変数ごとに異なる(§12-7): ALPHA は epoch 2、
  // BETA はローテーション後も再暗号化されていない epoch 1 のまま
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
  });
  const valueBeta = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
  });
  fixture = { owner, built, dek1, dek2, wraps, valueAlpha, valueBeta };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(): MockHandler {
  const { built } = fixture;
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

function pullHandler(overrides?: {
  readonly deks?: readonly unknown[];
  readonly variables?: readonly unknown[];
}): MockHandler {
  const { built, wraps, valueAlpha, valueBeta } = fixture;
  return onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      name: ENV_ID,
      currentEpoch: 2,
      variables: overrides?.variables ?? [
        { variableId: "va", name: "ALPHA", value: valueAlpha },
        { variableId: "vb", name: "BETA", value: valueBeta },
      ],
      deks: overrides?.deks ?? wraps,
    },
  }));
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, fixture.owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: fixture.built.projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

describe("maruhi pull", () => {
  it("同期 + §5.1 検証 + 復号し、メタデータのみ表示する(値は出さない)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    expect(output).toContain("ALPHA");
    expect(output).toContain("version=3");
    expect(output).toContain("epoch=2");
    expect(output).toContain("BETA");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
  });

  it("--show は人間には値を表示する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    expect(env.logs).toContain("ALPHA=alpha-value");
    expect(env.logs).toContain("BETA=beta-value");
  });

  it("AI エージェント検出時、--show は拒否される", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("AI エージェント環境を検出");
    expect(env.logs.join("\n")).not.toContain("alpha-value");
  });

  it("署名者を偽装したラップ(signerUserId の虚偽申告)を拒否する", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const spoofed = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    // サーバーが signer を owner と虚偽申告する(署名は stranger のまま)
    const lying = {
      ...spoofed,
      signerUserId: fixture.owner.userId,
      signerKeyFingerprintHex: fixture.owner.fingerprintHex,
    };
    const env = await startEnv([chainHandler(), pullHandler({ deks: [lying, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("登録署名が検証できません");
  });

  it("チェーン履歴に存在しない署名者のラップを拒否する", async () => {
    const stranger = await makeTestUser("user-stranger-9999");
    const foreign = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: stranger,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [foreign, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("署名者がチェーン履歴に存在しません");
  });

  it("署名 bit 反転を拒否する", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const flipped = `${wrap.signatureHex.slice(0, -1)}${wrap.signatureHex.endsWith("0") ? "1" : "0"}`;
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [{ ...wrap, signatureHex: flipped }, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("登録署名が検証できません");
  });

  it("申告エポックの DEK が配布されていない変数はエラーになる", async () => {
    const env = await startEnv([chainHandler(), pullHandler({ deks: [fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("DEK が配布されていません");
  });

  it("別変数の暗号文の差し替え(メタデータと AAD の不一致)は復号失敗に落ちる", async () => {
    // BETA の暗号文を ALPHA のスロットで配る。申告 aad は信用せず自前の座標
    // (variableId = 応答メタデータの ID)で復号するため必ず失敗する
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [{ variableId: "va", name: "ALPHA", value: fixture.valueBeta }],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("復号できません");
  });

  it("変数名の重複(サーバー応答の不整合)を拒否する", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({
        variables: [
          { variableId: "va", name: "ALPHA", value: fixture.valueAlpha },
          { variableId: "vb", name: "ALPHA", value: fixture.valueBeta },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("変数名が重複");
  });
});

describe("maruhi run", () => {
  it("復号した値を子プロセス環境変数としてメモリ注入する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "printenv", "ALPHA"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv).toEqual({
      ALPHA: "alpha-value",
      BETA: "beta-value",
    });
  });

  it("AI エージェント検出時でも run は許可される(線引き)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("子プロセスの終了コードを伝播する", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setRunnerExitCode(3);
    expect(await runCli(["run", "--", "false"], env.layer)).toBe(3);
  });

  it("コマンド未指定はエラーになる", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("`--` の後に指定");
  });
});
