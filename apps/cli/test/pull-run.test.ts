// pull(§5.1 配布時検証 + §12-7 全エポック DEK)と run(メモリ注入)、
// AI エージェント検出の線引き(値表示は拒否 / run は許可)のテスト。

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  genesisOp,
  makeTestUser,
  removeMemberOp,
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
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // チェーンには実 DEK のコミットメントが載る(§5.2 — pull の照合まで実データ)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
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

  it("--show は値の ANSI/制御シーケンスを中和し、改行は保持する", async () => {
    // 悪意ある共同編集者が保存した値(ESC + BEL)+ 正当な複数行(PEM 風)
    const evil = "sk-\u001b[31mFAKE\u0007\nline2";
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vs",
      version: 1,
      plaintext: evil,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ variableId: "vs", name: "SECRET", value }] }),
    ]);
    expect(await runCli(["pull", "--show"], env.layer)).toBe(0);
    const output = env.logs.join("\n");
    // ESC / BEL は端末へ生で流れない
    expect(output).not.toContain("\u001b");
    expect(output).not.toContain("\u0007");
    // 改行は保持(複数行シークレットが壊れない)
    expect(output).toContain("SECRET=sk-\uFFFD[31mFAKE\uFFFD\nline2");
  });

  it("AI エージェント検出時、--show は拒否される(run を迂回策として勧めない)", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    env.setAgent({ isAgent: true, name: "cursor" });
    expect(await runCli(["pull", "--show"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("AI エージェント環境を検出");
    // 値表示の迂回になる run を勧めない(エージェントに迂回レシピを渡さない)
    expect(errors).not.toContain("maruhi run");
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

  it("チェーン現エポックを超えるラップ(ファントムエポック)を拒否する", async () => {
    // 正規メンバー(owner)署名でも、チェーンに rotate_epoch がない epoch 3 の
    // ラップは受理しない(§12-6 のクライアント側 — サーバー不信の本線)
    const phantom = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      dek: crypto.getRandomValues(new Uint8Array(32)),
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [...fixture.wraps, phantom] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("現エポック(2)を超えるエポック 3");
  });

  it("チェーン現エポックを超える申告エポックの変数を拒否する", async () => {
    const phantomValue = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 3,
      variableId: "vp",
      version: 1,
      plaintext: "phantom",
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ variableId: "vp", name: "PHANTOM", value: phantomValue }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("現エポック(2)を超えています");
  });

  it("チェーン上のコミットメントと一致しない DEK(毒ラップ = 偽 DEK 注入)を拒否する(§5.2)", async () => {
    // 正規メンバー(owner)が §5.1 署名した実在エポック宛のラップでも、中身が
    // チェーン掲載のコミットメントと一致しない DEK なら使用前に拒否する
    // (悪意サーバー + チェーン履歴上の鍵保持者の共謀による偽 DEK 注入の遮断 —
    // CRYPTO_SPEC §14.2-1。セッション 11 の既知残余を閉じる本 PR の本丸)
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([chainHandler(), pullHandler({ deks: [poison, fixture.wraps[1]] })]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("コミットメントと一致しません");
  });

  it("push 前(listMine 経由)でもコミットメント不一致の DEK を拒否する(§5.2 の機密性側)", async () => {
    // §5.2 の (2): 偽 DEK での暗号化(攻撃者が読める push)の誘導を、DEK 使用前の
    // 照合で遮断する。listMine の配布に毒ラップを混ぜる
    const forgedDek = crypto.getRandomValues(new Uint8Array(32));
    const poison = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      dek: forgedDek,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler(),
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/${ENV_ID}/deks`,
        () => ({
          status: 200,
          json: { deks: [fixture.wraps[0], poison] },
        }),
      ),
    ]);
    env.setStdin(new TextEncoder().encode("new-value"));
    expect(await runCli(["push", "GAMMA"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("コミットメントと一致しません");
  });

  it("チェーンに create_environment がない環境(ファントム環境)の配布を拒否する", async () => {
    // 「未観測なら epoch 1」の既定値は廃止(§6.2): チェーンが知らない環境の
    // 配布はサーバー応答とチェーンの矛盾として全体を拒否する
    const ghostValue = await encryptValueFor({
      dek: fixture.dek1,
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      variableId: "vg",
      version: 1,
      plaintext: "ghost",
    });
    const ghostWrap = await wrapDekFor({
      projectId: fixture.built.projectId,
      environmentId: "ghost",
      epoch: 1,
      dek: fixture.dek1,
      recipient: fixture.owner,
      signer: fixture.owner,
    });
    const env = await startEnv([
      chainHandler(),
      onRequest(
        "GET",
        `/projects/${fixture.built.projectId}/environments/ghost/pull`,
        () => ({
          status: 200,
          json: {
            environmentId: "ghost",
            name: "ghost",
            currentEpoch: 1,
            variables: [{ variableId: "vg", name: "GHOST", value: ghostValue }],
            deks: [ghostWrap],
          },
        }),
      ),
    ]);
    expect(await runCli(["pull", "--env", "ghost"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("チェーン上に存在しません");
  });

  it("署名者 FP がチェーン履歴のどの鍵とも一致しないラップを拒否する", async () => {
    const wrap = fixture.wraps[0];
    if (wrap === undefined) {
      throw new Error("fixture");
    }
    const wrongFp = { ...wrap, signerKeyFingerprintHex: "00".repeat(16) };
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [wrongFp, fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("署名者がチェーン履歴に存在しません");
  });

  it("同一エポックの DEK ラップの重複を拒否する", async () => {
    const env = await startEnv([
      chainHandler(),
      pullHandler({ deks: [fixture.wraps[0], fixture.wraps[0], fixture.wraps[1]] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("重複しています");
  });

  it("別環境の座標で暗号化された暗号文の差し替えは復号失敗に落ちる", async () => {
    // environmentId だけ他所(other-env)の値を prod として配布 → 自前の座標
    // (URL に使った environmentId)で復号するため必ず失敗する
    const crossEnv = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: "other-env",
      epoch: 2,
      variableId: "va",
      version: 3,
      plaintext: "cross",
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ variableId: "va", name: "ALPHA", value: crossEnv }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("復号できません");
  });

  it("削除→新鍵で再追加されたメンバーの過去署名は当時の鍵で検証できる(§5.1)", async () => {
    // signer は在籍当時の鍵一式(keysetA)で署名し、その後削除 → 同一 user_id が
    // 新鍵(keysetB)で再追加された。keyHistory は 2 束縛を持ち、FP 一致で
    // 当時の鍵が選ばれる(チェーンは append-only — CRYPTO_SPEC §5.1)
    const oldKeys = await makeTestUser("user-rotated-5555");
    const newKeys = await makeTestUser("user-rotated-5555");
    const owner = fixture.owner;
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(oldKeys, "member") },
      { actor: oldKeys, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: removeMemberOp(oldKeys) },
      { actor: owner, operation: addMemberOp(newKeys, "member") },
    ]);
    const wrap = await wrapDekFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      dek,
      recipient: owner,
      signer: oldKeys,
    });
    const value = await encryptValueFor({
      dek,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vr",
      version: 1,
      plaintext: "historic",
    });
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          name: ENV_ID,
          currentEpoch: 1,
          variables: [{ variableId: "vr", name: "HISTORIC", value }],
          deks: [wrap],
        },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("HISTORIC");
  });

  it("トークン・秘密鍵素材は出力に現れない", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("maruhi_pat_");
    expect(output).not.toContain(fixture.owner.encSkHex);
    expect(output).not.toContain(fixture.owner.sigSkSeedHex);
  });

  it("変数名の制御文字(ANSI・改行)は端末出力でサニタイズされる", async () => {
    const evilName = "EVIL\u001b[2J\nNAME";
    const value = await encryptValueFor({
      dek: fixture.dek2,
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "ve",
      version: 1,
      plaintext: "v",
    });
    const env = await startEnv([
      chainHandler(),
      pullHandler({ variables: [{ variableId: "ve", name: evilName, value }] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    // 生の ESC がそのまま端末へ流れない(制御文字は置換される)
    expect(output).not.toContain("\u001b");
    expect(output).toContain("EVIL\uFFFD[2J\uFFFDNAME");
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

  it("値は子プロセス環境のみに現れ、端末出力には出ない", async () => {
    const env = await startEnv([chainHandler(), pullHandler()]);
    expect(await runCli(["run", "--", "true"], env.layer)).toBe(0);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).not.toContain("alpha-value");
    expect(output).not.toContain("beta-value");
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
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
