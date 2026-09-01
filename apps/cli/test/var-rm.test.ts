// `maruhi var rm`(S4 — 変数削除)のテスト。
//
// 固定する不変条件:
//  1. **v2 変数の削除はスキーマ欄・レイアウトの直前 byte-exact 保持**
//     (CRYPTO_SPEC §4.2 の削除規約)、**v1 変数の削除は v1 形のまま**
//     (v2 フィールドを持たない — レイアウトを勝手に上げない)
//  2. 削除は終端: active の削除は対話の明示確認(変数名の再入力)を必須にし、
//     非対話では --force なしに拒否(fail-closed)。declared も黙っては消さない
//  3. メタ操作の既存規律: 3-F intent(journal-before-send)+ 1-E′ 効果確認
//     (tombstone の検証済み配布)+ 床の tombstone 前進
//  4. 削除済み・未存在の名前は署名・送信より前に型付きエラー

import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import type { ProjectFloor } from "../src/floor.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { makeMetaEnvironmentServer, type MetaEnvironmentState } from "./support/meta-server.ts";
import { type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";
const DESCRIPTION = "Primary endpoint of the shop";

let owner: TestUser;
let built: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
/** v2 declared(url 型・required・description 付き)。 */
let declaredV2: WireDistributedVariableStatement;
/** v2 active(スキーマ欄付き)。 */
let activeV2: WireDistributedVariableStatement;
/** v1 active(スキーマ欄なし — 従来形)。 */
let activeV1: WireDistributedVariableStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    {
      actor: owner,
      operation: createEnvironmentOp(ENV_ID, crypto.getRandomValues(new Uint8Array(32))),
    },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  const head = { seq: 1, hashHex: built.projectId };
  envStatement = await environmentStatementFor({ ...common, name: ENV_ID, author: owner, head });
  declaredV2 = await statementFor({
    ...common,
    variableId: "v-declared",
    name: "SHOP_URL",
    author: owner,
    head,
    status: "declared",
    schema: { varType: "url", required: true, description: DESCRIPTION },
  });
  activeV2 = await statementFor({
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

async function startRmEnv(options?: {
  readonly initialVariables?: readonly WireDistributedVariableStatement[];
  readonly initialTombstones?: readonly WireDistributedVariableStatement[];
  readonly ignoreRemovals?: boolean;
}): Promise<{ env: TestEnv; state: MetaEnvironmentState }> {
  const { state, handlers } = makeMetaEnvironmentServer({
    chain: built,
    owner,
    environmentId: ENV_ID,
    envStatement,
    initialVariables: options?.initialVariables ?? [declaredV2, activeV2, activeV1],
    initialTombstones: options?.initialTombstones ?? [],
    ...(options?.ignoreRemovals === undefined ? {} : { ignoreRemovals: options.ignoreRemovals }),
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

function lastServer(): MockServer {
  const server = servers[servers.length - 1];
  if (server === undefined) {
    throw new Error("no mock server started");
  }
  return server;
}

/** 床(観測ログの fold)を読む。 */
async function loadFloor(env: TestEnv): Promise<ProjectFloor> {
  const loaded = await Effect.runPromise(makeFileFloorStore(env.floorDir).load(built.projectId));
  expect(loaded.floor).not.toBeNull();
  return loaded.floor as ProjectFloor;
}

describe("maruhi var rm(削除ステートメントの形)", () => {
  it("v2 declared の削除はスキーマ欄・レイアウトを byte-exact に保持する(§4.2)", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    const body = state.mutations[0]?.request.body as {
      statement: Record<string, unknown>;
      manifest: Record<string, unknown>;
    };
    expect(body.statement["status"]).toBe("deleted");
    expect(body.statement["metaVersion"]).toBe(2);
    // name は直前の名前をそのまま保持(削除で空にしない — §4.2)
    expect(body.statement["name"]).toBe("SHOP_URL");
    // スキーマ欄・レイアウトは直前ステートメントの値を byte-exact に保持
    expect(body.statement["layoutVersion"]).toBe(2);
    expect(body.statement["varType"]).toBe("url");
    expect(body.statement["required"]).toBe(true);
    expect(body.statement["description"]).toBe(DESCRIPTION);
    expect(body.statement["prevMetaSigHashHex"]).not.toBe("");
    // マニフェストは tombstone を含む集合で再発行される(§4.3)
    expect(body.manifest["manifestVersion"]).toBe(2);
    const output = env.logs.join("\n");
    expect(output).toContain("Deleted SHOP_URL");
    expect(output).toContain("declared only");
    // 床は tombstone へ前進する(削除の無断取り消しの検出材料)
    const floor = await loadFloor(env);
    expect(floor.environments[ENV_ID]?.variables["v-declared"]).toMatchObject({
      status: "deleted",
      metaVersion: 2,
    });
  });

  it("v1 変数の削除は v1 形のまま(v2 フィールドを持たない)", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["LEGACY_KEY"]);
    expect(await runCli(["var", "rm", "LEGACY_KEY"], env.layer)).toBe(0);
    const body = state.mutations[0]?.request.body as { statement: Record<string, unknown> };
    expect(body.statement["status"]).toBe("deleted");
    expect(body.statement["name"]).toBe("LEGACY_KEY");
    expect(body.statement).not.toHaveProperty("layoutVersion");
    expect(body.statement).not.toHaveProperty("varType");
    expect(body.statement).not.toHaveProperty("required");
    expect(body.statement).not.toHaveProperty("description");
    expect(env.logs.join("\n")).toContain("every stored version) was deleted");
  });
});

describe("削除の明示確認(fail-closed)", () => {
  it("対話環境では変数名の再入力を要求し、不一致なら署名・送信しない", async () => {
    const { env, state } = await startRmEnv();
    env.setPromptResponses(["WRONG_NAME"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the typed name did not match");
    expect(state.mutations).toEqual([]);
    // 確認前に何も送っていない(解決の metadata pull と chain 同期だけ)
    expect(lastServer().requests.filter((request) => request.method === "DELETE")).toHaveLength(0);
  });

  it("削除の帰結(active = 全バージョン消滅・終端)を確認前に明示する", async () => {
    const { env } = await startRmEnv();
    env.setPromptResponses(["PORT"]);
    expect(await runCli(["var", "rm", "PORT"], env.layer)).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("every stored version) is deleted immediately");
    expect(errors).toContain("Deletion is terminal");
  });

  it("非対話環境では --force なしに拒否する", async () => {
    const { env, state } = await startRmEnv();
    env.setTerminal({ stdout: false });
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Re-run with --force");
    expect(state.mutations).toEqual([]);
  });

  it("--force は確認を省くが、事実は可視化する(非対話でも通る)", async () => {
    const { env, state } = await startRmEnv();
    env.setTerminal({ stdin: false, stdout: false });
    expect(await runCli(["var", "rm", "SHOP_URL", "--force"], env.layer)).toBe(0);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    expect(env.prompts).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("without confirmation (--force)");
  });
});

describe("対象の解決(署名・送信より前の型付きエラー)", () => {
  it("削除済みの名前は「already deleted(終端)」で拒否する", async () => {
    const tombstone = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-gone",
      name: "GONE",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "deleted",
      metaVersion: 2,
    });
    const { env, state } = await startRmEnv({
      initialVariables: [activeV1],
      initialTombstones: [tombstone],
    });
    expect(await runCli(["var", "rm", "GONE", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("already deleted (deletion is terminal");
    expect(state.mutations).toEqual([]);
  });

  it("存在しない名前は明示エラー", async () => {
    const { env, state } = await startRmEnv();
    expect(await runCli(["var", "rm", "NO_SUCH", "--force"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist in this environment");
    expect(state.mutations).toEqual([]);
  });
});

describe("CAS リトライと確認済み対象の束縛", () => {
  it("再解決が別の variableId を返したら型付きエラーで止まる(確認していない変数を消さない)", async () => {
    // 確認後の 409(並行メタ操作)→ 再解決で、同じ名前に**別の変数**が載って
    // いる形(並行削除 + 同名の新規作成)。確認は variableId を束縛するので、
    // このリトライは進んではならない(pullfrog レビュー対応)
    const replacement = await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "v-replacement",
      name: "SHOP_URL",
      author: owner,
      head: { seq: 1, hashHex: built.projectId },
      status: "declared",
      schema: { varType: "url", required: true, description: "" },
    });
    const firstManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [declaredV2],
    });
    // 2 回目以降の配布は「置き換え後」の集合(マニフェストは prev 連鎖で前進 —
    // 同版異ハッシュの equivocation 拒否と混同させない)
    const secondManifest = await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      issuer: owner,
      head: headOf(built, 2),
      envStatement,
      statements: [replacement],
      manifestVersion: 2,
      prevManifestSigHashHex: await manifestHashOf(built.projectId, firstManifest),
    });
    let metadataCalls = 0;
    const deleteCalls: MockRequest[] = [];
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
      onRequest("GET", `/projects/${built.projectId}/environments/${ENV_ID}/pull/metadata`, () => {
        metadataCalls += 1;
        const first = metadataCalls === 1;
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch: 1,
            statement: envStatement,
            variables: first ? [declaredV2] : [replacement],
            deletedVariables: [],
            manifest: first ? firstManifest : secondManifest,
          },
        };
      }),
      (request) => {
        if (request.method !== "DELETE") {
          return null;
        }
        deleteCalls.push(request);
        return { status: 409, json: { _tag: "MetaVersionConflict", currentMetaVersion: 2 } };
      },
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: built.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("different variable than the one you confirmed");
    // 409 で拒否された 1 回だけ — 別 variableId への DELETE は送っていない
    expect(deleteCalls).toHaveLength(1);
    expect(deleteCalls[0]?.path.endsWith("/variables/v-declared")).toBe(true);
  });
});

describe("効果確認(1-E′ — §12-10 (3))", () => {
  it("204 を受けても tombstone が検証済み配布に現れなければ失敗し、床は前進しない", async () => {
    const { env, state } = await startRmEnv({ ignoreRemovals: true });
    env.setPromptResponses(["SHOP_URL"]);
    expect(await runCli(["var", "rm", "SHOP_URL"], env.layer)).toBe(1);
    expect(state.mutations.map((m) => m.kind)).toEqual(["remove"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("variable deletion");
    expect(errors).toContain("unconfirmed");
    // 床は tombstone へ前進していない(自分の思い込みを床に書かない)
    const floor = await loadFloor(env);
    expect(floor.environments[ENV_ID]?.variables["v-declared"]).toBeUndefined();
  });
});
