// `maruhi member list`(2026-09-15 ES K4 — 設計録 es-design.md 裁定 M / K4-E)の統合テスト。
//
// 固定する性質:
//  1. 検証済みチェーンから user id・role・scope(all / 環境 id 列 / no environments)・
//     鍵 FP を表示する(user id 昇順)。`--json` は 1 文書
//  2. 値ゼロなので agent-gate 非適用: エージェント検出 + 非 TTY でも成功する
//     (`maruhi schema` と同じ許可側)。master 鍵も要求しない(鍵なしクラス)
//  3. `project verify` の member 行にも同じ scope 列が出る

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import {
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let devMember: TestUser;
let noneReader: TestUser;
let built: BuiltChain;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  devMember = await makeTestUser("user-dev-2222");
  noneReader = await makeTestUser("user-none-3333");
  const dek = crypto.getRandomValues(new Uint8Array(32));
  built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp("env-staging", dek) },
    { actor: owner, operation: createEnvironmentOp("env-dev", dek) },
    { actor: owner, operation: addScopedMemberOp(devMember, "member", ["env-staging", "env-dev"]) },
    { actor: owner, operation: addScopedMemberOp(noneReader, "reader", []) },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
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

async function startEnv(user: TestUser): Promise<TestEnv & { readonly server: MockServer }> {
  const server = await MockServer.start([chainHandler()]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return { ...env, server };
}

describe("maruhi member list", () => {
  it("検証済みチェーンのメンバーを user id・role・scope・鍵 FP で表示する(id 昇順)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["member", "list"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("Members (3) — verified chain head seq=5:");
    expect(logs).toContain(
      `${devMember.userId}\tmember\tscope=env-dev, env-staging\tdevices=1\tfp=${devMember.fingerprintHex}`,
    );
    expect(logs).toContain(
      `${noneReader.userId}\treader\tscope=no environments\tdevices=1\tfp=${noneReader.fingerprintHex}`,
    );
    expect(logs).toContain(
      `${owner.userId}\towner\tscope=all environments\tdevices=1\tfp=${owner.fingerprintHex}`,
    );
    expect(logs.indexOf(devMember.userId)).toBeLessThan(logs.indexOf(noneReader.userId));
    expect(logs.indexOf(noneReader.userId)).toBeLessThan(logs.indexOf(owner.userId));
  });

  it("--json は 1 文書(userId / role / scope / devices / deviceKeyFingerprintsHex)を stdout に出す", async () => {
    const env = await startEnv(devMember);
    expect(await runCli(["member", "list", "--json"], env.layer)).toBe(0);
    const document = JSON.parse(env.logs.join("\n")) as {
      members: {
        userId: string;
        role: string;
        scope: unknown;
        devices: { keyFingerprintHex: string; roleCap: string; scope: unknown }[];
        deviceKeyFingerprintsHex: string[];
      }[];
    };
    expect(document.members.map((member) => member.userId)).toEqual([
      devMember.userId,
      noneReader.userId,
      owner.userId,
    ]);
    expect(document.members[0]?.scope).toEqual({
      kind: "listed",
      environmentIds: ["env-dev", "env-staging"],
    });
    expect(document.members[1]?.scope).toEqual({ kind: "listed", environmentIds: [] });
    expect(document.members[2]?.scope).toEqual({ kind: "all" });
    // 端末一覧(DK K4-20): FP + cap。連結した keyFingerprintHex は撤去
    expect(document.members[2]?.devices).toEqual([
      { keyFingerprintHex: owner.fingerprintHex, roleCap: "owner", scope: { kind: "all" } },
    ]);
    expect(document.members[2]).not.toHaveProperty("keyFingerprintHex");
    expect(document.members[2]?.deviceKeyFingerprintsHex).toEqual([owner.fingerprintHex]);
  });

  it("値ゼロなので agent-gate は掛からない: エージェント検出 + 非 TTY + 鍵なしでも成功する", async () => {
    const env = await startEnv(noneReader);
    env.setAgent({ isAgent: true, name: "testbot" });
    env.setTerminal({ stdin: false, stdout: false, stderr: false });
    // master 鍵なし(MARUHI_TOKEN 実行相当 — 鍵なしクラスで動く)
    env.keychain.delete(masterKeyEntryName(env.server.origin, noneReader.userId));
    expect(await runCli(["member", "list", "--json"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(`"userId": "${owner.userId}"`);
    expect(env.errors.join("\n")).not.toContain("Refused to display values");
  });

  it("project verify の member 行にも scope 列が出る(裁定 M)", async () => {
    const env = await startEnv(owner);
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `${devMember.userId}\tmember\tscope=env-dev, env-staging\tdevices=1\tfp=`,
    );
    expect(logs).toContain(`${owner.userId}\towner\tscope=all environments\tdevices=1\tfp=`);
  });
});
