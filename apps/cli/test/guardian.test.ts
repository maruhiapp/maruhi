// `maruhi guardian add / list / remove / wards`(CRYPTO_SPEC §8.3 / AUTH_SPEC §13-7 —
// KL3)の統合テスト。ラップ・分片の封印は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質:
//  1. add は保護者の鍵をチェーン導出の現メンバーから取り、§6.5 の読み上げ儀式
//     (最終語の再入力)を保護者ごとに立ててから登録する。登録した分片は保護者の
//     秘密鍵で開け、any は 1 片で、all は全片の XOR で B を復号できる(roundtrip)
//  2. 非メンバー・自分自身・重複・all の 1 人は送信前に落ちる
//  3. エージェント環境では儀式を拒否する(鍵素材の封印先を非対話で決めさせない)
//  4. list --project はチェーンの現鍵と食い違う保護者を STALE と表示する

import {
  decodeHex,
  fingerprintToWords,
  joinGuardianShares,
  openGuardianShare,
  unwrapMasterBlob,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { masterKeyEntryName } from "../src/keychain.ts";
import { chainHandlerOf } from "./support/chain-handler.ts";
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

let ward: TestUser;
let alice: TestUser;
let bob: TestUser;
let built: BuiltChain;

const servers: MockServer[] = [];

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  alice = await makeTestUser("user-alice-0002");
  bob = await makeTestUser("user-bob-00003");
  built = await buildChain([
    { actor: ward, operation: genesisOp(ward) },
    { actor: ward, operation: addMemberOp(alice, "member") },
    { actor: ward, operation: addMemberOp(bob, "member") },
  ]);
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface ShareBody {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

interface CreateBody {
  readonly groupId: string;
  readonly mode: "any" | "all";
  readonly wrap: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  };
  readonly shares: readonly ShareBody[];
}

function createHandler(record: (body: CreateBody) => void): MockHandler {
  return onRequest("POST", "/auth/key-wraps/guardians", (request) => {
    const body = request.body as CreateBody;
    record(body);
    return { status: 200, json: { groupId: body.groupId } };
  });
}

interface Started {
  readonly env: TestEnv;
  readonly server: MockServer;
}

async function startEnv(handlers: readonly MockHandler[], user: TestUser): Promise<Started> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
  return { env, server };
}

/** 登録の送信回数(送信前に落ちる検査用)。 */
function createCount(server: MockServer): number {
  return server.requests.filter(
    (request) => request.method === "POST" && request.path === "/auth/key-wraps/guardians",
  ).length;
}

/** 保護者の指紋の最終語(§6.5 の儀式応答)。 */
async function lastWordOf(user: TestUser): Promise<string> {
  const bytes = decodeHex(user.fingerprintHex);
  if (bytes === null) throw new Error("fingerprint hex");
  const words = await fingerprintToWords(bytes);
  if (!words.ok) throw new Error("fingerprint words");
  return words.value[words.value.length - 1] ?? "";
}

const hex = (value: string): Uint8Array => {
  const bytes = decodeHex(value);
  if (bytes === null) throw new Error("hex");
  return bytes;
};

/** 保護者 `user` が自分宛の分片を開く(サーバー側の分片配布と同じ形)。 */
async function openShareAs(user: TestUser, body: CreateBody): Promise<Uint8Array> {
  const share = body.shares.find((entry) => entry.guardianUserId === user.userId);
  if (share === undefined) throw new Error("share missing");
  const opened = await openGuardianShare({
    guardianKeyPair: user.encKeyPair,
    wrapped: { enc: hex(share.encHex), ciphertext: hex(share.ciphertextHex) },
    context: {
      userId: ward.userId,
      groupId: body.groupId,
      mode: body.mode,
      shareIndex: share.shareIndex,
      guardianUserId: user.userId,
    },
  });
  if (!opened.ok) throw new Error("share did not open");
  return opened.value;
}

async function unwrapWith(kek: Uint8Array, body: CreateBody): Promise<string> {
  const unwrapped = await unwrapMasterBlob({
    kek,
    wrapped: { nonce: hex(body.wrap.nonceHex), ciphertext: hex(body.wrap.ciphertextHex) },
    context: { userId: ward.userId, kind: "guardian", wrapRef: body.groupId, mode: body.mode },
  });
  if (!unwrapped.ok) throw new Error("blob did not unwrap");
  return new TextDecoder().decode(unwrapped.value);
}

describe("maruhi guardian add", () => {
  it("any: 儀式を経て登録し、保護者 1 人の分片で B を復号できる(roundtrip)", async () => {
    let created: CreateBody | null = null;
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    env.setPromptResponses([await lastWordOf(alice)]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(0);
    const body = created as CreateBody | null;
    expect(body?.mode).toBe("any");
    expect(body?.groupId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(body?.shares.map((share) => share.guardianUserId)).toEqual([alice.userId]);
    expect(body?.shares[0]?.guardianKeyFingerprintHex).toBe(alice.fingerprintHex);
    if (body === null) throw new Error("no registration");
    // any: 分片 = KEK そのもの
    const share = await openShareAs(alice, body);
    expect(await unwrapWith(share, body)).toBe(
      env.keychain.get(masterKeyEntryName(server.origin, ward.userId)),
    );
    // 儀式の表示は語リスト(stdout)、鍵素材はどこにも出ない
    expect(env.logs.join("\n")).toContain(`Guardian ${alice.userId} — key fingerprint:`);
    expect(env.logs.join("\n")).toContain("Registered guardian group");
  });

  it("all: 全保護者の分片の XOR でだけ B を復号できる", async () => {
    let created: CreateBody | null = null;
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    env.setPromptResponses([await lastWordOf(alice), await lastWordOf(bob)]);
    expect(
      await runCli(["guardian", "add", "--mode", "all", alice.userId, bob.userId], env.layer),
    ).toBe(0);
    const body = created as CreateBody | null;
    if (body === null) throw new Error("no registration");
    expect(body.mode).toBe("all");
    expect(body.shares.map((share) => share.shareIndex)).toEqual([1, 2]);
    const shareA = await openShareAs(alice, body);
    const shareB = await openShareAs(bob, body);
    const joined = joinGuardianShares({ mode: "all", shares: [shareA, shareB], expectedCount: 2 });
    if (!joined.ok) throw new Error("join");
    expect(await unwrapWith(joined.value, body)).toBe(
      env.keychain.get(masterKeyEntryName(server.origin, ward.userId)),
    );
    // 1 片だけでは開けない
    await expect(unwrapWith(shareA, body)).rejects.toThrow();
  });

  it("儀式に失敗すると登録せず、鍵素材を送らない", async () => {
    let createSeen = false;
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        createHandler(() => {
          createSeen = true;
        }),
      ],
      ward,
    );
    env.setPromptResponses(["wrong", "wrong", "wrong"]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(createSeen).toBe(false);
    expect(env.errors.join("\n")).toContain("Guardian key fingerprint confirmation failed");
  });

  it("非メンバー・自分自身・重複・all の 1 人は送信前に落ちる", async () => {
    const { env, server } = await startEnv([chainHandlerOf(built), createHandler(() => {})], ward);
    expect(await runCli(["guardian", "add", "--mode", "any", "user-stranger"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("is not a current member of project");
    expect(await runCli(["guardian", "add", "--mode", "any", ward.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("You cannot be your own guardian");
    expect(
      await runCli(["guardian", "add", "--mode", "any", alice.userId, alice.userId], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("The same user was given more than once");
    expect(await runCli(["guardian", "add", "--mode", "all", alice.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Mode all needs at least 2 guardians");
    expect(await runCli(["guardian", "add", "--mode", "some", alice.userId], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify --mode (any | all)");
    expect(createCount(server)).toBe(0);
  });

  it("AI エージェント環境では儀式を拒否する", async () => {
    let createSeen = false;
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        createHandler(() => {
          createSeen = true;
        }),
      ],
      ward,
    );
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(createSeen).toBe(false);
    expect(env.errors.join("\n")).toContain("an AI agent environment was detected");
  });
});

function statusHandler(groups: readonly unknown[]): MockHandler {
  return onRequest("GET", "/auth/key-wraps", () => ({
    status: 200,
    json: {
      recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
      passkeys: [],
      guardianGroups: groups,
    },
  }));
}

const GROUP_ID = "01J9Z8Y7X6W5V4T3S2R1Q0P9N8";

describe("maruhi guardian list / remove / wards", () => {
  it("list --project はチェーンの現鍵と食い違う保護者を STALE と表示する", async () => {
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        statusHandler([
          {
            groupId: GROUP_ID,
            mode: "all",
            createdAtMs: 1754006400000,
            guardians: [
              {
                shareIndex: 1,
                guardianUserId: alice.userId,
                guardianKeyFingerprintHex: alice.fingerprintHex,
              },
              {
                shareIndex: 2,
                guardianUserId: bob.userId,
                guardianKeyFingerprintHex: "00".repeat(16),
              },
            ],
          },
        ]),
      ],
      ward,
    );
    expect(await runCli(["guardian", "list", "--project", built.projectId], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`${GROUP_ID}  mode all  2 guardians`);
    expect(logs).toContain(`1. ${alice.userId} (key fingerprint ${alice.fingerprintHex})`);
    expect(logs).not.toContain(
      `1. ${alice.userId} (key fingerprint ${alice.fingerprintHex})  STALE`,
    );
    expect(logs).toContain(`2. ${bob.userId} (key fingerprint ${"00".repeat(16)})  STALE`);
    expect(env.errors.join("\n")).toContain("this all-mode group can no longer restore your key");
  });

  it("list はグループが無ければ add を案内する", async () => {
    const { env } = await startEnv([statusHandler([])], ward);
    expect(await runCli(["guardian", "list"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("No guardian groups");
  });

  it("remove は 204 で成功、404 は一覧を案内する", async () => {
    let deletes = 0;
    const { env } = await startEnv(
      [
        onRequest("DELETE", `/auth/key-wraps/guardians/${GROUP_ID}`, () => {
          deletes += 1;
          return deletes === 1
            ? { status: 204 }
            : { status: 404, json: { _tag: "KeyWrapNotFound" } };
        }),
      ],
      ward,
    );
    expect(await runCli(["guardian", "remove", GROUP_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(`Removed guardian group ${GROUP_ID}`);
    expect(await runCli(["guardian", "remove", GROUP_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No guardian group with that ID");
  });

  it("wards は自分が保護者である ward を並べる", async () => {
    const { env } = await startEnv(
      [
        onRequest("GET", "/auth/guardian/wards", () => ({
          status: 200,
          json: {
            wards: [
              {
                wardUserId: ward.userId,
                wardLogin: "ward-login",
                groupId: GROUP_ID,
                mode: "any",
                shareIndex: 1,
                createdAtMs: 1754006400000,
              },
            ],
          },
        })),
      ],
      alice,
    );
    expect(await runCli(["guardian", "wards"], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `ward-login (${ward.userId})  group ${GROUP_ID}  mode any  share 1`,
    );
  });
});
