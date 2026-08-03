// push(§12-5 CAS)のテスト: create / 新バージョン、409 リトライ
// (VersionConflict / EpochConflict = 再同期 → 再暗号化 → 再試行)、
// スキーマ外の素の 413 分岐(session-07 §5 申し送りの決着)。

import { decryptVariable } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  type BuiltChain,
  encryptValueFor,
  genesisOp,
  hexBytes,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  type WireEncryptedPayload,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let chainV1: BuiltChain;
let chainV2: BuiltChain;
let dek1: Uint8Array;
let dek2: Uint8Array;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  chainV1 = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
  // 同一 genesis(同一プロジェクト)にローテーションが積まれた形
  chainV2 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2) },
  ]);
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const common = { projectId: chainV1.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandlerOf(chains: readonly BuiltChain[]): MockHandler {
  // 呼び出しごとに進む(EpochConflict 再同期で新チェーンが見える)。最後で止まる
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chainV1.projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
      },
    };
  });
}

function deksHandlerOf(sets: readonly (readonly WireRecipientDek[])[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`, () => {
    const deks = sets[Math.min(call, sets.length - 1)] ?? [];
    call += 1;
    return { status: 200, json: { deks } };
  });
}

function pullHandlerOf(
  variables: readonly { variableId: string; name: string; value: WireEncryptedPayload }[],
  deks: readonly WireRecipientDek[],
): MockHandler {
  return onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: { environmentId: ENV_ID, name: ENV_ID, currentEpoch: 1, variables, deks },
  }));
}

async function startEnv(handlers: readonly MockHandler[], stdin: string): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: chainV1.projectId,
    defaultEnvironment: ENV_ID,
  });
  env.setStdin(new TextEncoder().encode(stdin));
  return env;
}

interface CreateBody {
  readonly variableId: string;
  readonly name: string;
  readonly value: WireEncryptedPayload;
}

async function decryptWire(dek: Uint8Array, value: WireEncryptedPayload): Promise<string> {
  const result = await decryptVariable({
    dek,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("decrypt failed in test");
  }
  return new TextDecoder().decode(result.value);
}

describe("maruhi push", () => {
  it("新規変数は create(version 1)。stdin の値が現エポックで暗号化される", async () => {
    const createCalls: CreateBody[] = [];
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullHandlerOf([], [wrap1]),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request: MockRequest) => {
          const body = request.body as CreateBody;
          createCalls.push(body);
          return {
            status: 200,
            json: {
              variableId: body.variableId,
              version: body.value.aad.version,
              epoch: body.value.aad.epoch,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("secret-value\n"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createCalls).toHaveLength(1);
    const body = createCalls[0] as CreateBody;
    expect(body.name).toBe("API_KEY");
    expect(body.value.aad).toEqual({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: body.variableId,
      version: 1,
    });
    // 末尾改行 1 つは除去され、値は現エポック DEK で復号できる
    expect(await decryptWire(dek1, body.value)).toBe("secret-value");
    expect(env.logs.join("\n")).toContain("version=1");
  });

  it("VersionConflict(409)は currentVersion + 1 で再暗号化して再試行する", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
    });
    const pushBodies: WireEncryptedPayload[] = [];
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullHandlerOf([{ variableId: "v-existing", name: "API_KEY", value: existing }], [wrap1]),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        (request) => {
          const body = request.body as { value: WireEncryptedPayload };
          pushBodies.push(body.value);
          if (pushBodies.length === 1) {
            // 競合: 実は誰かが version 7 まで進めていた
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } };
          }
          return {
            status: 200,
            json: { variableId: "v-existing", version: body.value.aad.version, epoch: 1 },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("new-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pushBodies).toHaveLength(2);
    expect(pushBodies[0]?.aad.version).toBe(5);
    expect(pushBodies[1]?.aad.version).toBe(8);
    // 再試行は新 version で再暗号化されている(nonce も新しい)
    expect(pushBodies[0]?.nonceHex).not.toBe(pushBodies[1]?.nonceHex);
    expect(await decryptWire(dek1, pushBodies[1] as WireEncryptedPayload)).toBe("new-value");
  });

  it("EpochConflict(409)は再同期 → 新エポック DEK 取得 → 再暗号化して再試行する(エポックの真実源はチェーン)", async () => {
    // push.test は「同一 genesis の 2 状態」を前提にする(Ed25519 の決定論署名 +
    // 固定 timestamp により成立)
    expect(chainV2.projectId).toBe(chainV1.projectId);
    const createBodies: CreateBody[] = [];
    const server = await MockServer.start([
      // 初回同期はローテーション前(epoch 1)、再同期でローテーション後が見える
      chainHandlerOf([chainV1, chainV2]),
      deksHandlerOf([[wrap1], [wrap1, wrap2]]),
      pullHandlerOf([], [wrap1]),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          const body = request.body as CreateBody;
          createBodies.push(body);
          if (createBodies.length === 1) {
            // サーバー申告の currentEpoch は嘘(5)。真実源はチェーン導出値(2)
            // であることを固定する(申告値を使う退行は aad.epoch=5 になり検出)
            return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 5 } };
          }
          return {
            status: 200,
            json: { variableId: body.variableId, version: 1, epoch: body.value.aad.epoch },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("rotated-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createBodies).toHaveLength(2);
    expect(createBodies[0]?.value.aad.epoch).toBe(1);
    // 再試行はチェーン導出の新エポック(2。申告の 5 ではない)+ 新 DEK で
    // 暗号化されている。再同期でチェーンが 2 回取得されている
    expect(createBodies[1]?.value.aad.epoch).toBe(2);
    expect(await decryptWire(dek2, (createBodies[1] as CreateBody).value)).toBe("rotated-value");
    expect(
      server.requests.filter((r) => r.path === `/projects/${chainV1.projectId}/chain`),
    ).toHaveLength(2);
    // 平文値は出力に現れない
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("rotated-value");
  });

  it("EpochConflict 申告がチェーンと矛盾する(再同期しても現エポック不変)なら即時報告する", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullHandlerOf([], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("サーバー応答とチェーンの矛盾");
  });

  it("EpochConflict 後に新エポックの DEK が自分宛にない場合は明示エラーになる", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1, chainV2]),
        deksHandlerOf([[wrap1], [wrap1]]),
        pullHandlerOf([], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("現エポック 2 の DEK が自分宛に登録されていません");
  });

  it("create の競合(並行作成)は名前から再解決して push 経路へ切り替える", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-racer",
      version: 1,
      plaintext: "raced",
    });
    let pullCalls = 0;
    let pushed: WireEncryptedPayload | null = null;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, () => {
        pullCalls += 1;
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            name: ENV_ID,
            currentEpoch: 1,
            // 初回解決では変数なし(create 経路)、競合後の再解決では
            // 並行作成された v-racer が見える
            variables:
              pullCalls === 1 ? [] : [{ variableId: "v-racer", name: "API_KEY", value: existing }],
            deks: [wrap1],
          },
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "ignored", reason: "duplicate-name" },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-racer/versions`,
        (request) => {
          pushed = (request.body as { value: WireEncryptedPayload }).value;
          return { status: 200, json: { variableId: "v-racer", version: 2, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("after-race"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pullCalls).toBe(2);
    const body = pushed as WireEncryptedPayload | null;
    expect(body?.aad.variableId).toBe("v-racer");
    expect(body?.aad.version).toBe(2);
  });

  it("スキーマ外の素の 413 は「値が大きすぎる」として報告する", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullHandlerOf([], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 413, bodyText: "Payload Too Large" }),
        ),
      ],
      "big-value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("HTTP 413");
    expect(env.errors.join("\n")).toContain("大きすぎます");
  });

  it("create 経路への VersionConflict(異常応答)も名前から再解決して自壊しない", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-late",
      version: 1,
      plaintext: "late",
    });
    let pullCalls = 0;
    let pushedVersion = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, () => {
        pullCalls += 1;
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            name: ENV_ID,
            currentEpoch: 1,
            variables:
              pullCalls === 1 ? [] : [{ variableId: "v-late", name: "API_KEY", value: existing }],
            deks: [wrap1],
          },
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        // create にはスキーマ上返しうるが通常起きない応答。乱数 ID のまま
        // push 経路へ落ちる退行(存在しない ID への push)をしないこと
        status: 409,
        json: { _tag: "VersionConflict", currentVersion: 1 },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-late/versions`,
        (request) => {
          pushedVersion = (request.body as { value: WireEncryptedPayload }).value.aad.version;
          return { status: 200, json: { variableId: "v-late", version: pushedVersion, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pullCalls).toBe(2);
    expect(pushedVersion).toBe(2);
  });

  it("名前解決で変数名が重複していたら拒否する(恣意的な 1 件へ束縛しない)", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-a",
      version: 1,
      plaintext: "a",
    });
    const other = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-b",
      version: 1,
      plaintext: "b",
    });
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullHandlerOf(
          [
            { variableId: "v-a", name: "API_KEY", value: existing },
            { variableId: "v-b", name: "API_KEY", value: other },
          ],
          [wrap1],
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("変数名が重複しています");
  });

  it("競合が解消しない場合は試行上限で中断する", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 1,
      plaintext: "old",
    });
    let attempts = 0;
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullHandlerOf([{ variableId: "v-existing", name: "API_KEY", value: existing }], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
          () => {
            attempts += 1;
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: attempts } };
          },
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(attempts).toBe(5);
    expect(env.errors.join("\n")).toContain("競合が解消しません");
  });
});
