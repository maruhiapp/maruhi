// 招待リンクアンカーの機械照合(CRYPTO_SPEC §6.3 帯域外アンカー (a) / §6.5 —
// context.ts の attachProject / project verify)の統合テスト。
//
// 固定する性質:
//  1. add_member 後の初回同期で、ピン留めした「ヘッド包含 + 招待者 FP の在籍」を
//     機械照合し、成功時は verifiedAtSeq を永続化する(以後も検査は継続)
//  2. ヘッド不包含(巻き戻し・fork 配布)・招待者 FP 不一致(偽造リンク /
//     偽造チェーン)は硬い証拠として拒否する
//  3. ピンファイルの破損は fail-open(警告 + 検査なしで続行 — 床と同じ線引き)

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let inviter: TestUser;
let acceptor: TestUser;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function chainHandler(built: BuiltChain): MockHandler {
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

/** 受諾済みチェーン(genesis → acceptor の add_member)と受諾者セッション。 */
async function memberEnv(built: BuiltChain): Promise<TestEnv> {
  const server = await MockServer.start([chainHandler(built)]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, acceptor);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return env;
}

async function seedAnchor(
  env: TestEnv,
  projectId: string,
  anchor: Readonly<Record<string, unknown>>,
): Promise<void> {
  await mkdir(env.pinsDir, { recursive: true });
  await writeFile(
    join(env.pinsDir, `${projectId}.json`),
    JSON.stringify({ v: 1, anchor, issued: {} }),
  );
}

describe("招待リンクアンカーの機械照合(first sync — §6.3 (a) / §6.5)", () => {
  it("ヘッド包含 + 招待者 FP の在籍が一致すれば照合成功し、verifiedAtSeq を永続化する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 1,
      headHashHex: built.hashes[0],
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("Invite-link anchor check passed");

    const pins = JSON.parse(
      await readFile(join(env.pinsDir, `${built.projectId}.json`), "utf8"),
    ) as { anchor: { verifiedAtSeq: number | null } };
    expect(pins.anchor.verifiedAtSeq).toBe(2);

    // 2 回目は成功メッセージを繰り返さない(検査自体は毎回走る)
    env.logs.length = 0;
    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).not.toContain("Invite-link anchor check passed");
  });

  it("ピン留めヘッドを含まないチェーン(巻き戻し・fork 配布)を拒否する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 2,
      // 実際の seq 2 とは異なるハッシュ = 招待者が見ていた履歴が配布に含まれない
      headHashHex: "9a".repeat(32),
      inviterUserId: inviter.userId,
      inviterKeyFingerprintHex: inviter.fingerprintHex,
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "does not contain the verified head pinned in the invite link (seq=2)",
    );
  });

  it("招待者 FP がピン留めヘッド時点の在籍と一致しないチェーンを拒否する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await seedAnchor(env, built.projectId, {
      headSeq: 1,
      headHashHex: built.hashes[0],
      inviterUserId: inviter.userId,
      // リンクの if= が別の鍵を指していた(偽造リンク / チェーン偽造)形
      inviterKeyFingerprintHex: "7b".repeat(16),
      verifiedAtSeq: null,
    });

    expect(await runCli(["project", "verify"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the chain member at the pinned head");
  });

  it("ピンファイルの破損は fail-open(警告 + アンカー検査なしで続行)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const env = await memberEnv(built);
    await mkdir(env.pinsDir, { recursive: true });
    await writeFile(join(env.pinsDir, `${built.projectId}.json`), "{broken");

    expect(await runCli(["project", "verify"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("cannot read the invite-pin file (it is corrupt)");
  });
});
