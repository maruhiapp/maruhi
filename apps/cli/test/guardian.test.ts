// `maruhi guardian add / list / remove / wards`(CRYPTO_SPEC §8.3 / AUTH_SPEC §13-7 —
// KL3)の統合テスト。ラップ・分片の封印は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質(2026-09-19 DK K4 — ラップ対象 B は端末鍵ではなく**予備鍵**):
//  1. add は保護者の鍵をチェーン導出の現メンバーの**各端末**から取り、§6.5 の読み上げ
//     儀式(最終語の再入力)を端末ごとに立て、次にリカバリーコードで台帳を開封して
//     から登録する。登録した分片は保護者の秘密鍵で開け、any は 1 片で、all は全片の
//     XOR で B(= 台帳の予備鍵レコード。ward の端末鍵ではない)を復号できる(roundtrip)
//  2. 非メンバー・自分自身・重複・all の 1 人は送信前に落ちる
//  3. エージェント環境では儀式を拒否する(鍵素材の封印先を非対話で決めさせない)
//  4. list --project はチェーンの現端末集合と食い違う分片行を STALE と表示する

import {
  decodeHex,
  fingerprintToWords,
  joinGuardianShares,
  openGuardianShare,
  unwrapMasterBlob,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  serializeStoredMasterKey,
  type StoredMasterKey,
} from "../src/keychain.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
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
/** ward の予備鍵(台帳が封印する B — 端末鍵 `ward` とは別の鍵)。 */
let reserve: TestUser;
let alice: TestUser;
let bob: TestUser;
let built: BuiltChain;

const servers: MockServer[] = [];

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  reserve = await makeTestUser("user-ward-0001");
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

/** 台帳 / 予備鍵のレコード(seedSession と同じ形)。 */
function recordOf(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
    // テストの `reserve` は CLI が生成した予備鍵(印つき — DK K16)。それ以外は端末鍵
    ...(user === reserve ? { kind: "reserve" as const } : {}),
  };
}

/** 直列化した予備鍵レコード(ラップの平文 = ラップを開いた結果と一致すべき値)。 */
function serializedReserve(): string {
  return serializeStoredMasterKey(recordOf(reserve));
}

/**
 * `GET /auth/recovery`: ward の予備鍵レコードをリカバリーコードでラップした台帳
 * (`guardian add` は台帳を開封してから分片を封印する — K4-2)。
 */
async function recoveryHandler(): Promise<{ handler: MockHandler; code: string }> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapMasterSecret({
    recoverySecret: secret,
    userId: ward.userId,
    // JSON.stringify(record) は使えない — 秘密側が伏字でラップされる(recovery.ts と同じ罠)
    masterSecretBlob: new TextEncoder().encode(serializedReserve()),
  });
  if (!wrapped.ok) throw new Error("test wrap failed");
  const handler = onRequest("GET", "/auth/recovery", () => ({
    status: 200,
    json: {
      suite: "maruhi/v1",
      nonceHex: Buffer.from(wrapped.value.nonce).toString("hex"),
      ciphertextHex: Buffer.from(wrapped.value.ciphertext).toString("hex"),
      updatedAtMs: 1754006400000,
    },
  }));
  return { handler, code: Redacted.value(formatRecoveryCode(Redacted.make(secret))) };
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
  it("any: 儀式と台帳の開封を経て登録し、保護者 1 人の分片で B(予備鍵)を復号できる(roundtrip)", async () => {
    let created: CreateBody | null = null;
    const ledger = await recoveryHandler();
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    // 儀式(保護者の端末ごとの最終語)→ 台帳の開封(リカバリーコード)の順
    env.setPromptResponses([await lastWordOf(alice), ledger.code]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(0);
    const body = created as CreateBody | null;
    expect(body?.mode).toBe("any");
    expect(body?.groupId).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    // 分片行は保護者の端末ごとに 1 行(フィクスチャの保護者は 1 端末)
    expect(body?.shares.map((share) => share.guardianUserId)).toEqual([alice.userId]);
    expect(body?.shares[0]?.guardianKeyFingerprintHex).toBe(alice.fingerprintHex);
    expect(body?.shares[0]?.guardianEncPubHex).toBe(alice.encPubHex);
    if (body === null) throw new Error("no registration");
    // any: 分片 = KEK そのもの。ラップの中身は台帳の予備鍵であり、ward の端末鍵ではない
    const share = await openShareAs(alice, body);
    const unwrapped = await unwrapWith(share, body);
    expect(unwrapped).toBe(serializedReserve());
    expect(unwrapped).not.toBe(env.keychain.get(masterKeyEntryName(server.origin, ward.userId)));
    expect(unwrapped).not.toContain(ward.encSkHex);
    // 台帳の開封は 1 回(GET /auth/recovery)
    expect(
      server.requests.filter((r) => r.method === "GET" && r.path === "/auth/recovery"),
    ).toHaveLength(1);
    // 儀式の表示は語リスト(stdout)、鍵素材・コードはどこにも出ない
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Guardian ${alice.userId} — device key fingerprint:`);
    expect(logs).toContain("Registered guardian group");
    expect(logs).toContain(`1. ${alice.userId} (1 device: ${alice.fingerprintHex})`);
    expect(env.errors.join("\n")).toContain(
      `opened the reserve key (fingerprint ${reserve.fingerprintHex}) for this change`,
    );
    expect(logs).not.toContain(reserve.encSkHex);
    expect(env.errors.join("\n")).not.toContain(reserve.encSkHex);
    expect(logs).not.toContain(ledger.code);
    expect(env.errors.join("\n")).not.toContain(ledger.code);
  });

  it("all: 全保護者の分片の XOR でだけ B を復号できる", async () => {
    let created: CreateBody | null = null;
    const ledger = await recoveryHandler();
    const { env } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
        createHandler((body) => {
          created = body;
        }),
      ],
      ward,
    );
    env.setPromptResponses([await lastWordOf(alice), await lastWordOf(bob), ledger.code]);
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
    expect(await unwrapWith(joined.value, body)).toBe(serializedReserve());
    // 1 片だけでは開けない
    await expect(unwrapWith(shareA, body)).rejects.toThrow();
  });

  it("儀式に失敗すると台帳を開かず、登録せず、鍵素材を送らない", async () => {
    let createSeen = false;
    const ledger = await recoveryHandler();
    const { env, server } = await startEnv(
      [
        chainHandlerOf(built),
        ledger.handler,
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
    // 儀式が通らなければ台帳の開封(コード入力)まで進まない
    expect(server.requests.some((r) => r.path === "/auth/recovery")).toBe(false);
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

  it("AI エージェント環境・非端末では儀式を拒否する(ハンドオフと同じゲート)", async () => {
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
    expect(env.errors.join("\n")).toContain("an AI agent environment was detected");
    // パイプした stdin で儀式のプロンプトを埋める形(非端末)も拒否する
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([await lastWordOf(alice)]);
    expect(await runCli(["guardian", "add", "--mode", "any", alice.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("only allowed on an interactive terminal");
    expect(createSeen).toBe(false);
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
  it("list --project はチェーンの現端末集合と食い違う分片行を STALE と表示する", async () => {
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
    expect(logs).toContain(`  1. ${alice.userId} (1 device: ${alice.fingerprintHex})`);
    expect(logs).not.toContain(`  1. ${alice.userId} (1 device: ${alice.fingerprintHex})  STALE`);
    expect(logs).toContain(`  2. ${bob.userId} (1 device: ${"00".repeat(16)})  STALE`);
    expect(env.errors.join("\n")).toContain(
      `${bob.userId} has none of these devices on the chain any more, so their share cannot be opened — this all-mode group can no longer restore your reserve key. Remove the group and add it again`,
    );
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
