// 鍵のハンドオフ(CRYPTO_SPEC §8.4 / AUTH_SPEC §13-7 — KL3)の統合テスト:
// `maruhi key recover --handoff`(要求者)と `maruhi key approve <code>`(承認者)。
// 一時鍵・分片・KEK_h の封印と復号は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質:
//  1. 要求者はコード(E.pub のコード化 = 公開情報)を stderr に出し、承認が揃うと
//     B を復号してキーチェーンへ保存する(端末移行 = 同送ラップ、保護者 = 台帳の
//     ラップ)。E.pub はサーバーへ送らない(request_id だけ)
//  2. 承認者(旧端末)は乱数 KEK_h で B をラップし、KEK_h を E.pub へ封印する。
//     承認者(保護者)は自分宛の分片を開いて E.pub へ再封印する。どちらも
//     一時鍵の秘密鍵でだけ開ける
//  3. yes 以外は何も送らない。エージェント環境・非端末では要求も承認も拒否する

import {
  computeHandoffRequestId,
  decodeHandoffCode,
  decodeHex,
  encodeHandoffCode,
  encodeHex,
  type EncryptionKeyPair,
  exportEncryptionPublicKey,
  generateEncryptionKeyPair,
  generateMasterWrapKek,
  importEncryptionPublicKey,
  openHandoffValue,
  sealGuardianShare,
  sealHandoffValue,
  unwrapMasterBlob,
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { makeTestUser, type TestUser } from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let ward: TestUser;
let alice: TestUser;

const servers: MockServer[] = [];
const GROUP_ID = "01J9Z8Y7X6W5V4T3S2R1Q0P9N8";
const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  alice = await makeTestUser("user-alice-0002");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

const hex = (value: string): Uint8Array => {
  const bytes = decodeHex(value);
  if (bytes === null) throw new Error("hex");
  return bytes;
};

/** 旧端末 / 台帳が持つ master 鍵レコード(seedSession と同じ形)。 */
function recordOf(user: TestUser): StoredMasterKey {
  return {
    suite: "maruhi/v1",
    encPubHex: user.encPubHex,
    encSkHex: Redacted.make(user.encSkHex),
    sigPubHex: user.sigPubHex,
    sigSkSeedHex: Redacted.make(user.sigSkSeedHex),
  };
}

interface Started {
  readonly env: TestEnv;
  readonly server: MockServer;
}

async function start(handlers: readonly MockHandler[]): Promise<Started> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  await seedConfig(env, { server: server.origin });
  return { env, server };
}

/** 鍵を持たない新端末(トークンだけ)。 */
function seedTokenOnly(env: TestEnv, origin: string, user: TestUser): void {
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId: user.userId, tokenId: "tok_1" }),
  );
}

/** 要求者が stderr に出したハンドオフコード(4 文字 × 15 群 = 58 記号 + 区切り)。 */
function displayedCode(env: TestEnv): string {
  const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{2,4}){14}$/.test(entry));
  if (line === undefined) {
    throw new Error("handoff code line not found in stderr output");
  }
  return line.trim();
}

/** コードから E.pub と request_id を戻す(承認者側と同じ導出)。 */
async function decodeDisplayed(env: TestEnv): Promise<{
  readonly publicKey: Uint8Array;
  readonly requestId: string;
}> {
  const decoded = await decodeHandoffCode(displayedCode(env));
  if (!decoded.ok) throw new Error("code did not decode");
  const requestId = await computeHandoffRequestId(decoded.value);
  if (!requestId.ok) throw new Error("request id");
  return { publicKey: decoded.value, requestId: requestId.value };
}

interface ApprovalWire {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly blob: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  } | null;
  readonly createdAtMs: number;
}

/** 旧端末の承認をサーバー側で組む(E.pub は要求者の表示から読む = 人が運ぶ)。 */
async function deviceApprovalFor(env: TestEnv, owner: TestUser): Promise<ApprovalWire> {
  const { publicKey, requestId } = await decodeDisplayed(env);
  const kek = generateMasterWrapKek();
  const blob = new TextEncoder().encode(serializeStoredMasterKey(recordOf(owner)));
  const wrapped = await wrapMasterBlob({
    kek,
    masterSecretBlob: blob,
    context: { userId: owner.userId, kind: "device", wrapRef: requestId },
  });
  const ephemeral = await importEncryptionPublicKey(publicKey);
  if (!wrapped.ok || !ephemeral.ok) throw new Error("wrap");
  const sealed = await sealHandoffValue({
    ephemeralPublicKey: ephemeral.value,
    value: kek,
    context: {
      userId: owner.userId,
      requestId,
      source: "device",
      shareIndex: 0,
      approverUserId: owner.userId,
    },
  });
  if (!sealed.ok) throw new Error("seal");
  return {
    source: "device",
    shareIndex: 0,
    approverUserId: owner.userId,
    approverKeyFingerprintHex: owner.fingerprintHex,
    encHex: encodeHex(sealed.value.enc),
    ciphertextHex: encodeHex(sealed.value.ciphertext),
    blob: {
      suite: "maruhi/v1",
      nonceHex: encodeHex(wrapped.value.nonce),
      ciphertextHex: encodeHex(wrapped.value.ciphertext),
    },
    createdAtMs: Date.now(),
  };
}

function statusHandler(groups: readonly unknown[]): MockHandler {
  return onRequest("GET", "/auth/key-wraps", () => ({
    status: 200,
    json: {
      recoveryCode: { registered: false, updatedAtMs: null },
      passkeys: [],
      guardianGroups: groups,
    },
  }));
}

/** `POST /auth/handoff` — request_id だけを受ける(E.pub は載らない)。 */
function createHandler(record: (body: { requestId: string }) => void): MockHandler {
  return onRequest("POST", "/auth/handoff", (request) => {
    record(request.body as { requestId: string });
    return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
  });
}

/** `GET /auth/handoff/:id/approvals` — path の request_id を問わず組んだ承認を返す。 */
function approvalsHandler(build: () => Promise<readonly ApprovalWire[]>): MockHandler {
  return (request) =>
    request.method === "GET" && /^\/auth\/handoff\/[0-9a-f]{64}\/approvals$/.test(request.path)
      ? build().then((approvals) => ({ status: 200, json: { approvals } }))
      : null;
}

const cancelHandler: MockHandler = (request) =>
  request.method === "DELETE" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
    ? { status: 204 }
    : null;

describe("maruhi key recover --handoff(要求者)", () => {
  it("端末移行: 同送ラップを KEK_h で復号し、master 鍵をキーチェーンへ保存する", async () => {
    let createBody: { requestId: string } | null = null;
    const { env, server } = await start([
      createHandler((body) => {
        createBody = body;
      }),
      statusHandler([]),
      approvalsHandler(async () => [await deviceApprovalFor(env, ward)]),
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(0);
    // request_id はコードの導出値と一致し、E.pub 自体は送られていない
    const { publicKey, requestId } = await decodeDisplayed(env);
    expect((createBody as { requestId: string } | null)?.requestId).toBe(requestId);
    expect(JSON.stringify(server.requests.map((r) => r.body))).not.toContain(encodeHex(publicKey));
    // 復元した鍵は旧端末と同じ
    const stored = env.keychain.get(masterKeyEntryName(server.origin, ward.userId));
    expect(stored).toBeDefined();
    expect(stored).toContain(ward.encPubHex);
    expect(stored).toContain(ward.encSkHex);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Handoff code (this is a public key, not a secret)");
    const logs = env.logs.join("\n");
    expect(logs).toContain("Restored the master key via handoff");
    expect(logs).toContain(`approved by ${ward.userId} (your own device`);
    // 役目を終えた要求は消す
    expect(server.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("保護者(any): 分片で台帳のラップを復号する", async () => {
    // 台帳: ward の B を KEK でラップ、KEK(= any の分片)を alice へ封印済み
    const kek = generateMasterWrapKek();
    const wrapped = await wrapMasterBlob({
      kek,
      masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(recordOf(ward))),
      context: { userId: ward.userId, kind: "guardian", wrapRef: GROUP_ID, mode: "any" },
    });
    if (!wrapped.ok) throw new Error("wrap");
    const { env, server } = await start([
      createHandler(() => {}),
      statusHandler([
        {
          groupId: GROUP_ID,
          mode: "any",
          createdAtMs: 1754006400000,
          guardians: [
            {
              shareIndex: 1,
              guardianUserId: alice.userId,
              guardianKeyFingerprintHex: alice.fingerprintHex,
            },
          ],
        },
      ]),
      // alice の承認: 分片(= KEK)を E.pub へ再封印したもの
      approvalsHandler(async () => {
        const { publicKey, requestId } = await decodeDisplayed(env);
        const ephemeral = await importEncryptionPublicKey(publicKey);
        if (!ephemeral.ok) throw new Error("ephemeral");
        const sealed = await sealHandoffValue({
          ephemeralPublicKey: ephemeral.value,
          value: kek,
          context: {
            userId: ward.userId,
            requestId,
            source: GROUP_ID,
            shareIndex: 1,
            approverUserId: alice.userId,
          },
        });
        if (!sealed.ok) throw new Error("seal");
        return [
          {
            source: GROUP_ID,
            shareIndex: 1,
            approverUserId: alice.userId,
            approverKeyFingerprintHex: alice.fingerprintHex,
            encHex: encodeHex(sealed.value.enc),
            ciphertextHex: encodeHex(sealed.value.ciphertext),
            blob: null,
            createdAtMs: Date.now(),
          },
        ];
      }),
      onRequest("GET", `/auth/key-wraps/guardians/${GROUP_ID}`, () => ({
        status: 200,
        json: {
          groupId: GROUP_ID,
          mode: "any",
          wrap: {
            suite: "maruhi/v1",
            nonceHex: encodeHex(wrapped.value.nonce),
            ciphertextHex: encodeHex(wrapped.value.ciphertext),
          },
          createdAtMs: 1754006400000,
        },
      })),
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(0);
    const stored = env.keychain.get(masterKeyEntryName(server.origin, ward.userId));
    expect(stored).toContain(ward.encSkHex);
    expect(env.errors.join("\n")).toContain(
      `Registered guardian groups: ${GROUP_ID} (any, 1 guardians)`,
    );
    expect(env.logs.join("\n")).toContain(
      `approved by ${alice.userId} (guardian, group ${GROUP_ID}`,
    );
  });

  it("要求の文脈と合わない承認は復号に失敗し、鍵を保存しない", async () => {
    const { env, server } = await start([
      createHandler(() => {}),
      statusHandler([]),
      // 別人(alice)の承認を device として横流し: info の approver が違う → 開けない
      approvalsHandler(async () => [
        { ...(await deviceApprovalFor(env, ward)), approverUserId: alice.userId },
      ]),
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Cannot open the approval from");
    expect(env.keychain.get(masterKeyEntryName(server.origin, ward.userId))).toBeUndefined();
  });

  it("鍵が既にある端末では要求を拒否する", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedSession(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("A master key already exists on this device");
    expect(server.requests).toHaveLength(0);
  });

  it("エージェント環境・非端末では要求を拒否する", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedTokenOnly(env, server.origin, ward);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Refused to request a key handoff");
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("only allowed on an interactive terminal");
    expect(server.requests).toHaveLength(0);
  });
});

/** 要求者の一時鍵とコード(テストが要求者役を演じる)。 */
async function makeRequester(): Promise<{
  readonly keyPair: EncryptionKeyPair;
  readonly code: string;
  readonly requestId: string;
}> {
  const keyPair = await generateEncryptionKeyPair();
  const publicKey = await exportEncryptionPublicKey(keyPair.publicKey);
  const code = await encodeHandoffCode(publicKey);
  const requestId = await computeHandoffRequestId(publicKey);
  if (!code.ok || !requestId.ok) throw new Error("code");
  return { keyPair, code: code.value, requestId: requestId.value };
}

interface ApproveBody {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly blob?: {
    readonly suite: string;
    readonly nonceHex: string;
    readonly ciphertextHex: string;
  };
}

function lookupHandler(requestId: string, json: unknown): MockHandler {
  return onRequest("GET", `/auth/handoff/${requestId}`, () => ({ status: 200, json }));
}

function approveHandler(requestId: string, record: (body: ApproveBody) => void): MockHandler {
  return onRequest("POST", `/auth/handoff/${requestId}/approvals`, (request) => {
    record(request.body as ApproveBody);
    return { status: 204 };
  });
}

describe("maruhi key approve <code>(承認者)", () => {
  it("旧端末: KEK_h を E.pub へ封印し、同送ラップを KEK_h で開ける", async () => {
    const requester = await makeRequester();
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, {
        wardUserId: ward.userId,
        wardLogin: "ward-login",
        expiresAtMs: FAR_FUTURE_MS,
        roles: ["device"],
      }),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, ward);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["key", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
    expect(body.source).toBe("device");
    expect(body.shareIndex).toBe(0);
    expect(body.approverKeyFingerprintHex).toBe(ward.fingerprintHex);
    // 要求者の秘密鍵で KEK_h を開き、同送ラップから B を復号できる
    const kek = await openHandoffValue({
      ephemeralKeyPair: requester.keyPair,
      wrapped: { enc: hex(body.encHex), ciphertext: hex(body.ciphertextHex) },
      context: {
        userId: ward.userId,
        requestId: requester.requestId,
        source: "device",
        shareIndex: 0,
        approverUserId: ward.userId,
      },
    });
    if (!kek.ok || body.blob === undefined) throw new Error("kek");
    const blob = await unwrapMasterBlob({
      kek: kek.value,
      wrapped: { nonce: hex(body.blob.nonceHex), ciphertext: hex(body.blob.ciphertextHex) },
      context: { userId: ward.userId, kind: "device", wrapRef: requester.requestId },
    });
    if (!blob.ok) throw new Error("blob");
    expect(new TextDecoder().decode(blob.value)).toBe(
      env.keychain.get(masterKeyEntryName(server.origin, ward.userId)),
    );
    expect(env.logs.join("\n")).toContain(
      "Handoff request from your own account (device migration)",
    );
    // 鍵素材(KEK_h・B)は出力に出ない
    expect(env.logs.join("\n")).not.toContain(ward.encSkHex);
    expect(env.errors.join("\n")).not.toContain(ward.encSkHex);
  });

  it("保護者: 自分宛の分片を開いて E.pub へ再封印する(any)", async () => {
    const requester = await makeRequester();
    // 台帳の分片: KEK を alice へ封印したもの
    const kek = generateMasterWrapKek();
    const alicePub = await importEncryptionPublicKey(hex(alice.encPubHex));
    if (!alicePub.ok) throw new Error("alice pub");
    const share = await sealGuardianShare({
      guardianPublicKey: alicePub.value,
      share: kek,
      context: {
        userId: ward.userId,
        groupId: GROUP_ID,
        mode: "any",
        shareIndex: 1,
        guardianUserId: alice.userId,
      },
    });
    if (!share.ok) throw new Error("share");
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, {
        wardUserId: ward.userId,
        wardLogin: null,
        expiresAtMs: FAR_FUTURE_MS,
        roles: [{ groupId: GROUP_ID, mode: "any", shareIndex: 1 }],
      }),
      onRequest("GET", `/auth/guardian/shares/${GROUP_ID}`, () => ({
        status: 200,
        json: {
          groupId: GROUP_ID,
          wardUserId: ward.userId,
          mode: "any",
          shareIndex: 1,
          encHex: encodeHex(share.value.enc),
          ciphertextHex: encodeHex(share.value.ciphertext),
        },
      })),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["key", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
    expect(body.source).toBe(GROUP_ID);
    expect(body.shareIndex).toBe(1);
    expect(body.blob).toBeUndefined();
    const opened = await openHandoffValue({
      ephemeralKeyPair: requester.keyPair,
      wrapped: { enc: hex(body.encHex), ciphertext: hex(body.ciphertextHex) },
      context: {
        userId: ward.userId,
        requestId: requester.requestId,
        source: GROUP_ID,
        shareIndex: 1,
        approverUserId: alice.userId,
      },
    });
    if (!opened.ok) throw new Error("open");
    expect(opened.value).toEqual(kek);
    expect(env.logs.join("\n")).toContain(
      `Handoff request from ${ward.userId} — you are their guardian`,
    );
    expect(env.logs.join("\n")).toContain(`Approved share 1 of group ${GROUP_ID}`);
  });

  it("yes 以外は何も送らない / 不明な要求は案内する / 不正なコードは拒否する", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([
      lookupHandler(requester.requestId, {
        wardUserId: ward.userId,
        wardLogin: null,
        expiresAtMs: FAR_FUTURE_MS,
        roles: ["device"],
      }),
      approveHandler(requester.requestId, () => {}),
      (request) =>
        request.method === "GET" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
          ? { status: 404, json: { _tag: "HandoffNotFound" } }
          : null,
    ]);
    seedSession(env, server.origin, ward);
    env.setPromptResponses(["no"]);
    expect(await runCli(["key", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The handoff approval was cancelled (nothing was sent)",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);

    const other = await makeRequester();
    expect(await runCli(["key", "approve", other.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No pending handoff request matches this code");

    expect(await runCli(["key", "approve", requester.code.slice(0, -1)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("The handoff code is malformed");
  });

  it("エージェント環境では承認を拒否する", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([approveHandler(requester.requestId, () => {})]);
    seedSession(env, server.origin, ward);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Refused to approve a key handoff");
    expect(server.requests).toHaveLength(0);
  });
});
