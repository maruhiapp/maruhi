// 予備鍵のハンドオフ(CRYPTO_SPEC §8.4 / AUTH_SPEC §13-7 — KL3、2026-09-19 DK K4)の
// 統合テスト: `maruhi key recover --handoff`(要求者)と `maruhi guardian approve <code>`
// (承認者)。一時鍵・分片の封印と復号は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質:
//  1. 要求者はコード(E.pub のコード化 = 公開情報)を stderr に出し、保護者の承認が
//     揃うと台帳のグループラップから予備鍵 B を復号し、**保存せず**この端末の新しい
//     端末鍵を発行する(復元の後段 — key-recover.ts)。E.pub はサーバーへ送らない
//     (request_id だけ)。旧端末の承認経路(端末移行)は K4 で削除された
//  2. 承認者(保護者)は自分の端末鍵へ封印された分片行(`deviceShares`)を開いて
//     E.pub へ再封印する。一時鍵の秘密鍵でだけ開ける。承認に blob 列は無い
//  3. yes 以外は何も送らない。自分の要求は承認できない。エージェント環境・非端末では
//     要求も承認も拒否する

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
  wrapMasterBlob,
} from "@maruhi/crypto";
import { Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  masterKeyEntryName,
  parseStoredMasterKey,
  serializeStoredMasterKey,
  type StoredMasterKey,
  tokenEntryName,
} from "../src/keychain.ts";
import { appendableProjectHandlers, projectListHandlerOf } from "./support/chain-handler.ts";
import {
  addOwnerDeviceOp,
  buildChain,
  genesisOp,
  makeTestUser,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

let ward: TestUser;
/** ward の予備鍵(台帳が封印する B — 端末鍵とは別の鍵)。 */
let reserve: TestUser;
let alice: TestUser;

const servers: MockServer[] = [];
const GROUP_ID = "01J9Z8Y7X6W5V4T3S2R1Q0P9N8";
const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

beforeAll(async () => {
  ward = await makeTestUser("user-ward-0001");
  reserve = await makeTestUser("user-ward-0001");
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

/** 台帳が持つ鍵レコード(seedSession と同じ形)。 */
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

/** 承認の配布形(HandoffApprovalResult — blob 列は無い)。 */
interface ApprovalWire {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverUserId: string;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  readonly createdAtMs: number;
}

/** 台帳のグループラップ(ward の予備鍵 B を KEK でラップ — any: KEK = 唯一の分片)。 */
async function wrappedReserve(kek: Uint8Array): Promise<{
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}> {
  const wrapped = await wrapMasterBlob({
    kek,
    masterSecretBlob: new TextEncoder().encode(serializeStoredMasterKey(recordOf(reserve))),
    context: { userId: ward.userId, kind: "guardian", wrapRef: GROUP_ID, mode: "any" },
  });
  if (!wrapped.ok) throw new Error("wrap");
  return {
    nonceHex: encodeHex(wrapped.value.nonce),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

/**
 * 保護者 `approver` の承認をサーバー側で組む: 分片(= KEK)を要求者の表示から読んだ
 * E.pub へ再封印する(E.pub は人が運ぶ)。`sealedAs` は封印文脈の approver(既定は
 * `approver` 自身 — 別人を入れると文脈不一致の承認になる)。
 */
async function guardianApprovalFor(
  env: TestEnv,
  approver: TestUser,
  kek: Uint8Array,
  sealedAs: TestUser = approver,
): Promise<ApprovalWire> {
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
      approverUserId: sealedAs.userId,
    },
  });
  if (!sealed.ok) throw new Error("seal");
  return {
    source: GROUP_ID,
    shareIndex: 1,
    approverUserId: approver.userId,
    approverKeyFingerprintHex: approver.fingerprintHex,
    encHex: encodeHex(sealed.value.enc),
    ciphertextHex: encodeHex(sealed.value.ciphertext),
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

/** alice 1 人の any グループ(台帳の状態 — 分片行は端末ごと)。 */
function aliceAnyGroup(): unknown {
  return {
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
  };
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

/** `GET /auth/key-wraps/guardians/:groupId` — 台帳のグループラップ(分片は運ばない)。 */
function groupHandler(wrap: {
  readonly nonceHex: string;
  readonly ciphertextHex: string;
}): MockHandler {
  return onRequest("GET", `/auth/key-wraps/guardians/${GROUP_ID}`, () => ({
    status: 200,
    json: {
      groupId: GROUP_ID,
      mode: "any",
      wrap: { suite: "maruhi/v1", ...wrap },
      createdAtMs: 1754006400000,
    },
  }));
}

/** `GET /projects` — 復元の後段が走査するプロジェクト一覧(空 = 登録先なし)。 */
const noProjectsHandler: MockHandler = onRequest("GET", "/projects", () => ({
  status: 200,
  json: { projects: [] },
}));

const cancelHandler: MockHandler = (request) =>
  request.method === "DELETE" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
    ? { status: 204 }
    : null;

describe("maruhi key recover --handoff(要求者)", () => {
  it("保護者(any): 分片で台帳のラップを開き、予備鍵は保存せず新しい端末鍵を発行する", async () => {
    // 台帳: ward の予備鍵 B を KEK でラップ、KEK(= any の分片)を alice へ封印済み
    const kek = generateMasterWrapKek();
    const chain = await buildChain([
      { actor: ward, operation: genesisOp(ward) },
      { actor: ward, operation: addOwnerDeviceOp(reserve) },
    ]);
    let createBody: { requestId: string } | null = null;
    const { env, server } = await start([
      createHandler((body) => {
        createBody = body;
      }),
      statusHandler([aliceAnyGroup()]),
      approvalsHandler(async () => [await guardianApprovalFor(env, alice, kek)]),
      groupHandler(await wrappedReserve(kek)),
      projectListHandlerOf([chain]),
      ...appendableProjectHandlers(chain),
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    // 復元の後段の確認の 1 問(予備鍵は ward の端末が add_device で足した鍵 — DK K14)
    env.setPromptResponses(["yes"]);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(0);
    // request_id はコードの導出値と一致し、E.pub 自体は送られていない
    const { publicKey, requestId } = await decodeDisplayed(env);
    expect((createBody as { requestId: string } | null)?.requestId).toBe(requestId);
    expect(JSON.stringify(server.requests.map((r) => r.body))).not.toContain(encodeHex(publicKey));
    // キーチェーンには**新しい端末鍵**が入る。台帳の予備鍵(B)は保存されない
    const stored = env.keychain.get(masterKeyEntryName(server.origin, ward.userId));
    expect(stored).toBeDefined();
    expect(stored).not.toContain(reserve.encSkHex);
    expect(stored).not.toContain(reserve.encPubHex);
    expect(stored).not.toContain(ward.encSkHex);
    const restored = parseStoredMasterKey(stored ?? "");
    if (restored === null) throw new Error("expected a device-key record in the keychain");
    expect(restored.encPubHex).not.toBe(reserve.encPubHex);
    const errors = env.errors.join("\n");
    expect(errors).toContain("Handoff code (this is a public key, not a secret)");
    expect(errors).toContain(`Registered guardian groups: ${GROUP_ID} (any, 1 guardians)`);
    expect(errors).toContain(
      "the reserve key was discarded from memory; it stays sealed in the recovery ledger only. This device now signs with its own key",
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `approved by ${alice.userId} (guardian, group ${GROUP_ID}; device key fingerprint ${alice.fingerprintHex})`,
    );
    expect(logs).toContain(
      `Opened key ${reserve.fingerprintHex} from the recovery ledger. It is used only to register this machine's new device key, then discarded`,
    );
    expect(logs).toContain("Generated this device's key");
    expect(logs).toMatch(/key fingerprint: [0-9a-f]{32}/);
    expect(logs).not.toContain(`key fingerprint: ${reserve.fingerprintHex}`);
    // 予備鍵の印がある鍵は問わずに記録する(DK K16-3 / K16-6)
    expect(env.prompts).toEqual([]);
    expect(errors).toContain(
      `Note: recorded ${reserve.fingerprintHex} on this machine as your reserve key (its ledger record carries the mark maruhi writes when it creates a reserve key)`,
    );
    // 鍵素材は出力に出ない
    expect(logs).not.toContain(reserve.encSkHex);
    expect(errors).not.toContain(reserve.encSkHex);
    // 台帳のラップは取りに行き、役目を終えた要求は消す
    expect(
      server.requests.some(
        (r) => r.method === "GET" && r.path === `/auth/key-wraps/guardians/${GROUP_ID}`,
      ),
    ).toBe(true);
    expect(server.requests.some((r) => r.method === "DELETE")).toBe(true);
  });

  it("要求の文脈と合わない承認は復号に失敗し、鍵を保存しない", async () => {
    const kek = generateMasterWrapKek();
    const { env, server } = await start([
      createHandler(() => {}),
      statusHandler([aliceAnyGroup()]),
      // 封印文脈の approver(ward)と申告の approver(alice)が違う → 開けない
      approvalsHandler(async () => [await guardianApprovalFor(env, alice, kek, ward)]),
      groupHandler(await wrappedReserve(kek)),
      noProjectsHandler,
      cancelHandler,
    ]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Cannot open the approval from ${alice.userId}: it was not sealed to this request's key, or its context was altered in transit. The handoff was aborted — re-run and hand the new code to the guardians again`,
    );
    expect(env.keychain.get(masterKeyEntryName(server.origin, ward.userId))).toBeUndefined();
    // 台帳のラップまで進まない
    expect(server.requests.some((r) => r.path === `/auth/key-wraps/guardians/${GROUP_ID}`)).toBe(
      false,
    );
  });

  it("保護者がいなければ要求を作らず、別の開封手段を案内する", async () => {
    const { env, server } = await start([createHandler(() => {}), statusHandler([])]);
    seedTokenOnly(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "You have no guardians registered, so nobody can approve a handoff. Open the reserve key with your recovery code (`maruhi key recover`) or a passkey (`--passkey`) instead",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("鍵が既にある端末では要求を拒否する", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedSession(env, server.origin, ward);
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "A device key already exists on this machine, so there is nothing to recover here. To add this machine as another device of yours, run `maruhi device add` and approve it from a registered device; if an earlier `maruhi key recover` was interrupted before every project registered this device, re-run with --resume",
    );
    expect(server.requests).toHaveLength(0);
  });

  it("エージェント環境・非端末では要求を拒否する", async () => {
    const { env, server } = await start([createHandler(() => {})]);
    seedTokenOnly(env, server.origin, ward);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to request a key handoff because an AI agent environment was detected (the restored reserve key would land in the agent's session; run this yourself on a human interactive terminal)",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdout: false });
    expect(await runCli(["key", "recover", "--handoff"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key handoff requests are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
    );
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

/** 承認の payload(HandoffApproval — blob 列は無い)。 */
interface ApproveBody {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

/** 照会の応答(`roles` は保護者分片の形だけ — 旧 "device" は無い)。 */
function lookupOf(wardUser: TestUser, wardLogin: string | null): unknown {
  return {
    wardUserId: wardUser.userId,
    wardLogin,
    expiresAtMs: FAR_FUTURE_MS,
    roles: [{ groupId: GROUP_ID, mode: "any", shareIndex: 1 }],
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

/** 台帳の分片(KEK を保護者 `guardian` の端末鍵へ封印したもの)。 */
async function sealedShareFor(
  guardian: TestUser,
  kek: Uint8Array,
): Promise<{ readonly encHex: string; readonly ciphertextHex: string }> {
  const publicKey = await importEncryptionPublicKey(hex(guardian.encPubHex));
  if (!publicKey.ok) throw new Error("guardian pub");
  const share = await sealGuardianShare({
    guardianPublicKey: publicKey.value,
    share: kek,
    context: {
      userId: ward.userId,
      groupId: GROUP_ID,
      mode: "any",
      shareIndex: 1,
      guardianUserId: guardian.userId,
    },
  });
  if (!share.ok) throw new Error("share");
  return { encHex: encodeHex(share.value.enc), ciphertextHex: encodeHex(share.value.ciphertext) };
}

/**
 * `GET /auth/guardian/shares/:groupId`(GuardianShareResult): 先頭行のフィールドと
 * `deviceShares`(自分の全端末行 — K3-10)。`deviceShares` を省くと旧サーバーの形。
 */
function myShareHandler(
  rows: readonly {
    readonly guardianKeyFingerprintHex: string;
    readonly guardianEncPubHex: string;
    readonly encHex: string;
    readonly ciphertextHex: string;
  }[],
  options: { readonly legacy?: boolean } = {},
): MockHandler {
  const head = rows[0];
  if (head === undefined) throw new Error("at least one row");
  return onRequest("GET", `/auth/guardian/shares/${GROUP_ID}`, () => ({
    status: 200,
    json: {
      groupId: GROUP_ID,
      wardUserId: ward.userId,
      mode: "any",
      shareIndex: 1,
      encHex: head.encHex,
      ciphertextHex: head.ciphertextHex,
      ...(options.legacy === true ? {} : { deviceShares: rows }),
    },
  }));
}

describe("maruhi guardian approve <code>(承認者)", () => {
  it("保護者: 自分の端末宛の分片行を開いて E.pub へ再封印する(any)", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    // 台帳の分片行: alice の端末鍵宛の行と、別端末(失効済み等)宛のダミー行
    const mine = await sealedShareFor(alice, kek);
    const other = await sealedShareFor(ward, kek);
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      myShareHandler([
        {
          guardianKeyFingerprintHex: "00".repeat(16),
          guardianEncPubHex: ward.encPubHex,
          ...other,
        },
        {
          guardianKeyFingerprintHex: alice.fingerprintHex,
          guardianEncPubHex: alice.encPubHex,
          ...mine,
        },
      ]),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
    expect(body.source).toBe(GROUP_ID);
    expect(body.shareIndex).toBe(1);
    expect(body.approverKeyFingerprintHex).toBe(alice.fingerprintHex);
    expect(body).not.toHaveProperty("blob");
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
    const logs = env.logs.join("\n");
    expect(logs).toContain(`Handoff request from ${ward.userId} — you are their guardian`);
    expect(logs).toContain(`  groups: ${GROUP_ID} (any, share 1)`);
    expect(logs).toContain(`Approved share 1 of group ${GROUP_ID}`);
    expect(env.prompts).toContain(`Type yes to approve the handoff for ${ward.userId}: `);
    expect(env.errors.join("\n")).toContain(
      "the approval was sealed to the requester's one-time key and nothing was stored on this device",
    );
    // 分片・KEK・秘密鍵は出力に出ない
    expect(logs).not.toContain(encodeHex(kek));
    expect(logs).not.toContain(alice.encSkHex);
    expect(env.errors.join("\n")).not.toContain(alice.encSkHex);
  });

  it("保護者: 旧サーバー(deviceShares 無し)は先頭行をこの端末の分片として開く", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    let approved: ApproveBody | null = null;
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, "ward-login")),
      myShareHandler(
        [
          {
            guardianKeyFingerprintHex: alice.fingerprintHex,
            guardianEncPubHex: alice.encPubHex,
            ...(await sealedShareFor(alice, kek)),
          },
        ],
        { legacy: true },
      ),
      approveHandler(requester.requestId, (body) => {
        approved = body;
      }),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(0);
    const body = approved as ApproveBody | null;
    if (body === null) throw new Error("no approval");
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
      `Handoff request from ward-login (${ward.userId}) — you are their guardian`,
    );
  });

  it("保護者: この端末宛の分片行が無ければ何も送らない", async () => {
    const requester = await makeRequester();
    const kek = generateMasterWrapKek();
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      // alice の別端末宛の行だけ(この端末の FP の行が無い)
      myShareHandler([
        {
          guardianKeyFingerprintHex: "00".repeat(16),
          guardianEncPubHex: alice.encPubHex,
          ...(await sealedShareFor(alice, kek)),
        },
      ]),
      approveHandler(requester.requestId, () => {}),
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Your share of group ${GROUP_ID} is not sealed to this device (fingerprint ${alice.fingerprintHex}). Approve from one of your devices it was sealed to, or ask ${ward.userId} to re-add the group after this device was registered`,
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("自分の要求は承認できない(端末移行はハンドオフを通らない)", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([
      // サーバーが ward 本人に要求を見せてしまっても、手元で拒む
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      approveHandler(requester.requestId, () => {}),
    ]);
    seedSession(env, server.origin, ward);
    env.setPromptResponses(["yes"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "This handoff request is your own. Only your guardians can approve it (device migration no longer goes through a handoff — register a new device with `maruhi device add` / `maruhi device approve`)",
    );
    expect(env.prompts).toHaveLength(0);
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("yes 以外は何も送らない / 不明な要求は案内する / 不正なコードは拒否する", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([
      lookupHandler(requester.requestId, lookupOf(ward, null)),
      approveHandler(requester.requestId, () => {}),
      (request) =>
        request.method === "GET" && /^\/auth\/handoff\/[0-9a-f]{64}$/.test(request.path)
          ? { status: 404, json: { _tag: "HandoffNotFound" } }
          : null,
    ]);
    seedSession(env, server.origin, alice);
    env.setPromptResponses(["no"]);
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The handoff approval was cancelled (nothing was sent)",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);

    const other = await makeRequester();
    expect(await runCli(["guardian", "approve", other.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "No pending handoff request matches this code (it is unknown, expired, or you are not one of the requester's guardians)",
    );

    expect(await runCli(["guardian", "approve", requester.code.slice(0, -1)], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The handoff code is malformed (58 characters in groups of 4; hyphens, spaces, and letter case are ignored). Copy it again from the requesting device",
    );
    expect(server.requests.filter((r) => r.method === "POST")).toHaveLength(0);
  });

  it("エージェント環境・非端末では承認を拒否する", async () => {
    const requester = await makeRequester();
    const { env, server } = await start([approveHandler(requester.requestId, () => {})]);
    seedSession(env, server.origin, alice);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a key handoff because an AI agent environment was detected (approving hands out key material; run this yourself on a human interactive terminal)",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    expect(await runCli(["guardian", "approve", requester.code], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Key handoff approvals are only allowed on an interactive terminal (stdin, stdout, and stderr must all be terminals; pipes, redirects, CI, and AI agents are refused)",
    );
    expect(server.requests).toHaveLength(0);
  });
});
