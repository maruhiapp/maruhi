// クライアント同期検査(§6.3)のテスト: verifyChain 委譲・genesis ハッシュ =
// プロジェクト ID 検証・ヘッド整合・鍵履歴索引(削除済みメンバー含む)。

import { Effect, Exit } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { syncProject } from "../src/sync.ts";
import {
  addMemberOp,
  type BuiltChain,
  buildChain,
  genesisOp,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
} from "./support/crypto.ts";
import { type MockResponse, MockServer, onRequest } from "./support/server.ts";

let owner: TestUser;
let member: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startServer(handlers: Parameters<typeof MockServer.start>[0]): Promise<MockServer> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  return server;
}

function chainResponse(projectId: string, built: BuiltChain): MockResponse {
  return {
    status: 200,
    json: {
      projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  };
}

function runSync(origin: string, projectId: string) {
  return Effect.runPromiseExit(
    Effect.gen(function* () {
      const client = yield* makeApiClient({ baseUrl: origin, token: "maruhi_pat_test" });
      return yield* syncProject(client, projectId);
    }).pipe(Effect.provide(FetchHttpClient.layer)),
  );
}

function failureMessage(exit: Awaited<ReturnType<typeof runSync>>): string {
  return JSON.stringify(exit);
}

describe("syncProject (§6.3)", () => {
  it("有効なチェーンを検証し、削除済みメンバーの鍵も履歴索引に残す", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: member, operation: rotateEpochOp("prod", 2) },
      { actor: owner, operation: removeMemberOp(member) },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () =>
        chainResponse(built.projectId, built),
      ),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isSuccess(exit)).toBe(true);
    if (!Exit.isSuccess(exit)) {
      return;
    }
    const verified = exit.value;
    // 現メンバーは owner のみ(member は削除済み)
    expect([...verified.state.members.keys()]).toEqual([owner.userId]);
    expect(verified.state.environmentEpochs.get("prod")).toBe(2);
    // §5.1 の鍵履歴: 削除済みメンバーの当時の鍵が引ける(append-only)
    const bindings = verified.keyHistory.get(member.userId);
    expect(bindings).toHaveLength(1);
    expect(bindings?.[0]?.sigPubHex).toBe(member.sigPubHex);
    expect(bindings?.[0]?.keyFingerprintHex).toBe(member.fingerprintHex);
  });

  it("署名改竄チェーンを拒否する(verifyChain 委譲)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const second = built.entries[1];
    if (second === undefined) {
      throw new Error("fixture");
    }
    const tampered = [built.entries[0], { ...second, timestampMs: second.timestampMs + 1 }];
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: tampered,
          headSeq: 2,
          headHashHex: built.hashes[1],
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("チェーン検証に失敗");
  });

  it("genesis ハッシュがプロジェクト ID と一致しない差し替えを拒否する(§6.4)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // 有効だが「別プロジェクト」(member が作成者の genesis)のチェーンを、
    // 要求したプロジェクト ID で配布する = サーバーによる差し替え
    const other = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    expect(other.projectId).not.toBe(built.projectId);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () =>
        chainResponse(built.projectId, other),
      ),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("genesis ハッシュ");
  });

  it("サーバー申告ヘッドと導出ヘッドの不一致を拒否する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: 1,
          headHashHex: built.hashes[0],
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("チェーンヘッド");
  });

  it("seq は正しいがハッシュだけ虚偽の申告ヘッドも拒否する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
    ]);
    const server = await startServer([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: "ab".repeat(32),
        },
      })),
    ]);
    const exit = await runSync(server.origin, built.projectId);
    expect(Exit.isFailure(exit)).toBe(true);
    expect(failureMessage(exit)).toContain("チェーンヘッド");
  });
});
