// `maruhi device add / approve / list / revoke` と初回同期の端末登録(CRYPTO_SPEC §3 /
// §6.2 / §7、AUTH_SPEC §13-11 — 2026-09-19 DK K4。設計録 dk-design.md §9)の統合テスト。
// 端末 op の署名・検証は実 crypto、サーバーはワイヤレベルモック。
//
// 固定する性質:
//  1. `device approve` は儀式ゲート(TTY + 非エージェント)を要求一覧の取得より前に置き、
//     要求行の公開鍵から FP を再計算して照合する(申告 FP は使わない — K4-6)。承認は
//     各プロジェクトの `add_device` + バックフィル + ローカル記録(approved)+ 登録簿の PUT
//  2. 初回同期(鍵ありの前段)は、ローカル記録の 3 出所(reserve / approved / observed)だけを
//     チェーンへ足し、登録簿(`GET /auth/devices`)は読まない・書かない(K4-3)。失効した
//     記録は足さない。チェーンで観測した端末は出所つきで記録する(K4-4)
//  3. ラップ完全集合の期待数はサーバーと同じ述語(実効 scope × 端末、保存キー粒度)
//  4. `device revoke` は FP で確定し、最後の端末は失効できない(last-device-protected)
//  5. `device add` は鍵のある端末で既定拒否(`--replace` で作り直す — K4-18)、承認の合図は
//     登録簿、完了の確認はチェーン(K4-5)
//  6. 旧端末経路の承認(`source: "device"`)はワイヤ型が受け付けない(撤去の固定)

import { readFile } from "node:fs/promises";

import { HandoffApprovalSchema, HandoffLookupSchema } from "@maruhi/api-schema";
import {
  type ChainEntry,
  type ChainOperation,
  computeChainEntryHash,
  computeUserKeyFingerprint,
  encodeHex,
  fingerprintToWords,
  verifyChainWithHistory,
  wrapMasterSecret,
} from "@maruhi/crypto";
import { Effect, Exit, Redacted, Schema } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { expectedWrapRecipientCount } from "../src/dek-wrap.ts";
import { masterKeyEntryName, serializeStoredMasterKey, tokenEntryName } from "../src/keychain.ts";
import {
  makeFileOwnDeviceStore,
  type OwnDeviceEntry,
  type OwnDeviceSource,
  ownDevicesPathOf,
} from "../src/own-devices.ts";
import { formatRecoveryCode } from "../src/recovery-code.ts";
import { rotationMandates } from "../src/rotation-sweep.ts";
import type { VerifiedProject } from "../src/sync.ts";
import {
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app";
const FAR_FUTURE_MS = Date.now() + 10 * 60 * 1000;

let owner: TestUser;
/** owner の 2 台目(承認される新端末 / 失効される端末)。 */
let dev2: TestUser;
/** owner の予備鍵(公開側だけローカル記録に載る)。 */
let reserve: TestUser;
let member: TestUser;
let dek: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-0001");
  dev2 = await makeTestUser("user-owner-0001");
  reserve = await makeTestUser("user-owner-0001");
  member = await makeTestUser("user-member-0002");
  dek = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** `add_device`(cap 付き — CRYPTO_SPEC §6.2)。actor は同じ人の有効な端末。 */
function addDeviceOp(
  device: TestUser,
  cap: { roleCap: "owner" | "admin" | "member" | "reader"; environmentIds?: readonly string[] } = {
    roleCap: "owner",
  },
): ChainOperation {
  return {
    op: "add_device",
    payload: {
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: cap.roleCap,
      scopeKind: cap.environmentIds === undefined ? "all" : "listed",
      scopeEnvironmentIds: cap.environmentIds === undefined ? [] : [...cap.environmentIds],
    },
  };
}

function revokeDeviceOp(target: TestUser, devices: readonly TestUser[]): ChainOperation {
  return {
    op: "revoke_device",
    payload: {
      targetUserId: target.userId,
      deviceFingerprintsHex: devices.map((device) => device.fingerprintHex).toSorted(),
    },
  };
}

interface ServerState {
  readonly handlers: MockHandler[];
  readonly appended: ChainEntry[];
  readonly registered: { environmentId: string; deks: readonly Record<string, unknown>[] }[];
  readonly registry: {
    keyFingerprintHex: string;
    encPubHex: string;
    sigPubHex: string;
    label: string;
    createdAtMs: number;
  }[];
  readonly registryPuts: { fp: string; body: Record<string, unknown> }[];
  readonly registryDeletes: string[];
  readonly requestCancels: string[];
  readonly paths: () => readonly string[];
}

/**
 * チェーン(追記可)+ 環境 1 つ(owner 宛の epoch 1 ラップ)+ 端末登録簿 + 要求一覧 +
 * プロジェクト一覧のモック。
 */
async function makeServer(input: {
  readonly built: BuiltChain;
  readonly withEnvironment: boolean;
  readonly requests?: readonly Record<string, unknown>[];
  readonly registryRows?: readonly ServerState["registry"][number][];
  readonly tokensStatus?: number;
  /** 追加のハンドラ(MockServer は起動時に列を写すので、後から push できない)。 */
  readonly extra?: readonly MockHandler[];
  /** 環境一覧 GET の応答コード(既定 200。500 = 受理後の sweep を失敗させる)。 */
  readonly environmentsStatus?: number;
  /**
   * `POST /auth/devices/requests` の応答: 期限と、合図(登録簿の行)を即座に立てるか。
   * `conflict` を置くと(合図を立てた後に)409 を返す。
   */
  readonly requestCreate?: {
    readonly expiresAtMs: number;
    readonly signal: boolean;
    readonly conflict?: "request-exists" | "device-registered";
  };
}): Promise<{ server: MockServer; state: ServerState }> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appended: ChainEntry[] = [];
  const registered: ServerState["registered"] = [];
  const registry: ServerState["registry"] = [...(input.registryRows ?? [])];
  const registryPuts: ServerState["registryPuts"] = [];
  const registryDeletes: string[] = [];
  const requestCancels: string[] = [];
  const ownWrap: WireRecipientDek | null = input.withEnvironment
    ? await wrapDekFor({
        projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek,
        recipient: owner,
        signer: owner,
      })
    : null;
  const envStatement = input.withEnvironment
    ? await environmentStatementFor({
        projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(input.built, 2),
      })
    : null;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appended.push(body.entry);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    onRequest("GET", `/projects/${projectId}/environments`, () =>
      input.environmentsStatus !== undefined && input.environmentsStatus !== 200
        ? { status: input.environmentsStatus, json: { _tag: "Internal" } }
        : {
            status: 200,
            json: {
              environments:
                envStatement === null
                  ? []
                  : [{ environmentId: ENV_ID, currentEpoch: 1, statement: envStatement }],
            },
          },
    ),
    (request: MockRequest) => {
      const base = `/projects/${projectId}/environments/${ENV_ID}/deks`;
      if (request.path !== base) {
        return null;
      }
      if (request.method === "GET") {
        return { status: 200, json: { deks: ownWrap === null ? [] : [ownWrap] } };
      }
      if (request.method === "POST") {
        const body = request.body as { readonly deks: readonly Record<string, unknown>[] };
        registered.push({ environmentId: ENV_ID, deks: body.deks });
        return { status: 204 };
      }
      return null;
    },
    onRequest("GET", "/projects", () => ({
      status: 200,
      json: { projects: [{ projectId, role: "owner" }] },
    })),
    onRequest("GET", "/auth/devices", () => ({ status: 200, json: { devices: registry } })),
    (request: MockRequest) => {
      const match = /^\/auth\/devices\/([0-9a-f]{32})$/.exec(request.path);
      if (match === null) {
        return null;
      }
      const fp = match[1] ?? "";
      if (request.method === "PUT") {
        registryPuts.push({ fp, body: request.body as Record<string, unknown> });
        const body = request.body as { encPubHex: string; sigPubHex: string; label: string };
        registry.push({ keyFingerprintHex: fp, ...body, createdAtMs: Date.now() });
        return { status: 204 };
      }
      if (request.method === "DELETE") {
        registryDeletes.push(fp);
        return { status: 204 };
      }
      return null;
    },
    onRequest("GET", "/auth/devices/requests", () => ({
      status: 200,
      json: { requests: input.requests ?? [] },
    })),
    (request: MockRequest) => {
      const match = /^\/auth\/devices\/requests\/([0-9a-f]{32})$/.exec(request.path);
      if (match === null) {
        return null;
      }
      if (request.method === "DELETE") {
        requestCancels.push(match[1] ?? "");
        return { status: 204 };
      }
      return { status: 404, json: { _tag: "DeviceNotFound" } };
    },
    onRequest("GET", "/auth/tokens", () =>
      input.tokensStatus === 403
        ? { status: 403, json: { _tag: "Forbidden", reason: "insufficient-scope" } }
        : { status: 200, json: { tokens: [] } },
    ),
    async (request: MockRequest) => {
      if (
        request.method !== "POST" ||
        request.path !== "/auth/devices/requests" ||
        input.requestCreate === undefined
      ) {
        return null;
      }
      const body = request.body as { encPubHex: string; sigPubHex: string; label: string };
      if (input.requestCreate.signal) {
        // 承認側が最後に行う登録簿 PUT の代わり: 要求の公開鍵から FP を計算して合図を立てる
        const fp = await computeUserKeyFingerprint(
          hexBytes(body.encPubHex),
          hexBytes(body.sigPubHex),
        );
        if (!fp.ok) throw new Error("fp");
        registry.push({ keyFingerprintHex: encodeHex(fp.value), ...body, createdAtMs: Date.now() });
      }
      if (input.requestCreate.conflict !== undefined) {
        return {
          status: 409,
          json: { _tag: "DeviceRegistryConflict", reason: input.requestCreate.conflict },
        };
      }
      return { status: 200, json: { expiresAtMs: input.requestCreate.expiresAtMs } };
    },
    ...(input.extra ?? []),
  ];
  const server = await MockServer.start(handlers);
  servers.push(server);
  return {
    server,
    state: {
      handlers,
      appended,
      registered,
      registry,
      registryPuts,
      registryDeletes,
      requestCancels,
      paths: () => server.requests.map((request) => `${request.method} ${request.path}`),
    },
  };
}

async function startEnv(origin: string, projectId: string, user: TestUser): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, origin, user);
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

function requestRowOf(device: TestUser, label = "laptop"): Record<string, unknown> {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label,
    expiresAtMs: FAR_FUTURE_MS,
  };
}

async function readOwnDevices(env: TestEnv, origin: string): Promise<readonly OwnDeviceEntry[]> {
  const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
  const loaded = await Effect.runPromise(store.load(origin, owner.userId));
  return loaded.state === "loaded" ? loaded.devices : [];
}

async function recordOwnDevice(
  env: TestEnv,
  origin: string,
  device: TestUser,
  source: OwnDeviceSource,
  revokedAtMs: number | null = null,
): Promise<void> {
  const store = makeFileOwnDeviceStore(ownDevicesPathOf(env.configPath));
  await Effect.runPromise(
    store.record(origin, owner.userId, {
      keyFingerprintHex: device.fingerprintHex,
      encPubHex: device.encPubHex,
      sigPubHex: device.sigPubHex,
      roleCap: "owner",
      scope: { kind: "all" },
      source,
      label: source === "reserve" ? "reserve" : null,
      addedByFingerprintHex: null,
      observedProjectId: null,
      recordedAtMs: 1_700_000_000_000,
      revokedAtMs,
    }),
  );
}

/** 鍵ありの前段を通るコマンド(invite create)の発行 POST。 */
function inviteHandler(built: BuiltChain): MockHandler {
  return onRequest("POST", `/projects/${built.projectId}/invites`, () => ({
    status: 200,
    json: { expiresAtMs: FAR_FUTURE_MS },
  }));
}

async function chainWithEnvironment(): Promise<BuiltChain> {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
  ]);
}

describe("maruhi device approve", () => {
  it("儀式ゲート: エージェント環境・非端末では要求一覧を取る前に拒否する(K4-6 反例 3)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a device: an AI agent environment was detected",
    );
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "Refused to approve a device: stdin is not an interactive terminal",
    );
    expect(state.paths().filter((path) => path.includes("/auth/devices"))).toEqual([]);
    expect(state.appended).toEqual([]);
  });

  it("全長 FP で照合し、add_device → バックフィル → ローカル記録 → 登録簿 PUT → 要求の取消の順に進む", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex.toUpperCase()], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    // add_device(既定 cap = owner / all)を owner の端末が署名して追記した
    expect(state.appended).toHaveLength(1);
    const entry = state.appended[0]!;
    expect(entry.op).toBe("add_device");
    expect(entry.actor).toEqual({ userId: owner.userId, keyFingerprintHex: owner.fingerprintHex });
    expect(entry.payload).toEqual({
      encPubHex: dev2.encPubHex,
      sigPubHex: dev2.sigPubHex,
      roleCap: "owner",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    // バックフィル: env-app の epoch 1 が新端末の enc 鍵宛に登録された
    expect(state.registered).toHaveLength(1);
    expect(
      state.registered[0]?.deks.map((wrap) => [
        wrap["recipientUserId"],
        wrap["recipientEncPubHex"],
        wrap["epoch"],
      ]),
    ).toEqual([[owner.userId, dev2.encPubHex, 1]]);
    // ローカル記録(approved — 承認した端末の FP が出所)
    const recorded = await readOwnDevices(env, server.origin);
    const row = recorded.find((candidate) => candidate.keyFingerprintHex === dev2.fingerprintHex);
    expect(row).toMatchObject({
      source: "approved",
      label: "laptop",
      addedByFingerprintHex: owner.fingerprintHex,
      revokedAtMs: null,
    });
    // 登録簿の PUT(合図 — 最後)と要求の取消
    expect(state.registryPuts).toEqual([
      {
        fp: dev2.fingerprintHex,
        body: { encPubHex: dev2.encPubHex, sigPubHex: dev2.sigPubHex, label: "laptop" },
      },
    ]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    const paths = state.paths();
    expect(paths.indexOf(`PUT /auth/devices/${dev2.fingerprintHex}`)).toBeGreaterThan(
      paths.lastIndexOf(`POST /projects/${built.projectId}/chain/entries`),
    );
    expect(env.logs.join("\n")).toContain("registered the device (backfilled 1 DEK wrap");
  });

  it("12 語でも照合でき、`--cap` / `--env` は端末の cap になる(K4-6)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    const words = await fingerprintToWords(hexBytes(dev2.fingerprintHex));
    if (!words.ok) throw new Error("words");
    expect(
      await runCli(
        ["device", "approve", words.value.join(" "), "--cap", "reader", "--env", ENV_ID],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended[0]?.payload).toMatchObject({
      roleCap: "reader",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_ID],
    });
    expect(env.logs.join("\n")).toContain(`cap reader/${ENV_ID}`);
  });

  it("要求行の申告 FP が公開鍵と食い違えば無視し、一致する要求が無ければ失敗する(サーバーの差し込み)", async () => {
    const built = await chainWithEnvironment();
    const forged = { ...requestRowOf(dev2), keyFingerprintHex: "00".repeat(16) };
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [forged],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", "00".repeat(16)], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "claims fingerprint 00000000000000000000000000000000 but its public keys compute to",
    );
    expect(errors).toContain("No pending device-add request matches that fingerprint");
    expect(state.appended).toEqual([]);
    // 接頭辞や 11 語は受けない(§3 の切り詰め禁止)
    expect(await runCli(["device", "approve", dev2.fingerprintHex.slice(0, 16)], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain(
      "must be the full 32-character fingerprint or its 12 words",
    );
  });
  it("全プロジェクトが skipped でも(この端末が未登録など)終了コードは 1 で、要求は残す", async () => {
    // session は member(チェーンに居ない)→ 唯一のプロジェクトで skipped
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, member);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("skipped — you are not a member of this project");
    expect(errors).toContain("the device was not registered on any project");
    expect(state.appended).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("同じ鍵の要求が複数あれば黙って選ばず、ラベルを示して止まる", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2, "laptop"), requestRowOf(dev2, "desk")],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `2 pending device-add requests carry the same key fingerprint ${dev2.fingerprintHex} (labels: laptop, desk)`,
    );
    expect(state.appended).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });

  it("どのプロジェクトにも載らなければ、ローカル記録・登録簿 PUT・要求の取消を行わない(再実行できる)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // 存在しない環境を scope に指定 → 唯一のプロジェクトで failed(通信前判定)
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--env", "env-missing"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("does not exist on this project's chain");
    expect(errors).toContain(
      "the device was not registered on any project, so nothing was recorded and the request was left in place",
    );
    expect(state.appended).toEqual([]);
    // 記録されるのは初回同期の観測(この端末)だけで、approved の行は書かれない
    expect((await readOwnDevices(env, server.origin)).map((row) => row.source)).toEqual([
      "observed",
    ]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
  });
});

describe("初回同期の端末登録(device-sync — K4-3 / K4-4 / K4-9)", () => {
  for (const source of ["reserve", "approved", "observed"] as const) {
    it(`ローカル記録の出所 ${source} はチェーンに無ければ add_device + バックフィルされ、登録簿は読まれない`, async () => {
      const built = await chainWithEnvironment();
      const { server, state } = await makeServer({
        built,
        withEnvironment: true,
        extra: [inviteHandler(built)],
        registryRows: [
          {
            keyFingerprintHex: dev2.fingerprintHex,
            encPubHex: dev2.encPubHex,
            sigPubHex: dev2.sigPubHex,
            label: "planted",
            createdAtMs: 1,
          },
        ],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      const device = source === "reserve" ? reserve : dev2;
      await recordOwnDevice(env, server.origin, device, source);
      // 鍵ありの前段を通るコマンド(invite create)— 同期の付随で登録が走る
      expect(
        await runCli(["invite", "create", "--role", "member"], env.layer),
        env.errors.join("\n"),
      ).toBe(0);
      expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
      expect(state.appended[0]?.payload).toMatchObject({
        encPubHex: device.encPubHex,
        sigPubHex: device.sigPubHex,
        roleCap: "owner",
        scopeKind: "all",
      });
      expect(state.registered[0]?.deks.map((wrap) => wrap["recipientEncPubHex"])).toEqual([
        device.encPubHex,
      ]);
      expect(env.errors.join("\n")).toContain(
        `registered your device ${device.fingerprintHex} (${source}`,
      );
      // 登録簿は判断の入力にならない: 読まれもしない(登録簿だけにある端末は足されない)
      expect(state.paths().filter((path) => path.startsWith("GET /auth/devices"))).toEqual([]);
      // 予備鍵の不在の警告(K4-9)は「自分の端末がこの端末だけ、かつ記録に予備鍵が無い」
      // ときだけ: reserve は記録があり、approved / observed は登録後に端末が 2 つになる
      expect(env.errors.join("\n")).not.toContain("no reserve key is registered");
    });
  }

  it("失効と記録した端末は足さず、登録簿にしか無い端末も足さない(negative)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      extra: [inviteHandler(built)],
      registryRows: [
        {
          keyFingerprintHex: reserve.fingerprintHex,
          encPubHex: reserve.encPubHex,
          sigPubHex: reserve.sigPubHex,
          label: "planted",
          createdAtMs: 1,
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved", 1_700_000_000_000);
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toEqual([]);
    expect(state.registered).toEqual([]);
    // この端末だけ・予備鍵の記録なし → K4-9 の警告
    expect(env.errors.join("\n")).toContain(
      "no reserve key is registered for you on this project (only this device's key). Run `maruhi key recovery`",
    );
  });

  it("チェーンで観測した端末は出所(誰の端末が seq いくつで足したか)つきで記録し、失効の観測は記録に写す", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
      { actor: owner, operation: revokeDeviceOp(owner, [reserve]) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [inviteHandler(built)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // reserve は以前ここで記録されていた(active)— チェーンの失効を記録に写す
    await recordOwnDevice(env, server.origin, reserve, "reserve");
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const recorded = await readOwnDevices(env, server.origin);
    expect(recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)).toMatchObject({
      source: "observed",
      addedByFingerprintHex: owner.fingerprintHex,
      observedProjectId: built.projectId,
      revokedAtMs: null,
    });
    // 自分の端末自身も記録される(Note は出ない)
    expect(recorded.find((row) => row.keyFingerprintHex === owner.fingerprintHex)).toMatchObject({
      source: "observed",
      addedByFingerprintHex: null,
    });
    expect(
      recorded.find((row) => row.keyFingerprintHex === reserve.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `observed your device ${dev2.fingerprintHex} (cap owner/all) on project ${built.projectId}: added by device ${owner.fingerprintHex} at seq 2`,
    );
    expect(errors).toContain(
      `device ${reserve.fingerprintHex} is revoked on project ${built.projectId}; marked as revoked`,
    );
    expect(errors).not.toContain(`observed your device ${owner.fingerprintHex}`);
    // 失効した端末は再登録されない
    expect(state.appended).toEqual([]);
  });
});

describe("ラップ完全集合の期待数(サーバーと同じ述語 — R(E) の端末展開)", () => {
  it("実効 scope に E を含む (人, 端末) の対と grant を保存キー粒度で数える", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      // owner の 2 台目は env-b だけを持つ cap
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "member", environmentIds: ["env-b"] }),
      },
      // member は env-a だけの scope(端末は 1 つ・cap 無し)
      { actor: owner, operation: addScopedMemberOp(member, "member", ["env-a"]) },
    ]);
    const verified = await verifyChainWithHistory(built.entries);
    if (!verified.ok) throw new Error("chain");
    const view = { state: verified.value.state } as VerifiedProject;
    // env-a: owner の 1 台目(all)+ member = 2。owner の 2 台目は env-a を持たない
    expect(expectedWrapRecipientCount(view, "env-a")).toBe(2);
    // env-b: owner の 1 台目 + 2 台目 = 2。member は scope 外
    expect(expectedWrapRecipientCount(view, "env-b")).toBe(2);
  });
});

describe("sweep 第 5 種 device-revoked の義務(rotation-sweep — K4-8)", () => {
  it("失効直前(seq−1)の端末の実効 scope を義務にする(seq 時点では端末が消えているので ALL に倒れない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "owner", environmentIds: ["env-a"] }),
      },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const verified = await verifyChainWithHistory(built.entries);
    if (!verified.ok) throw new Error("chain");
    const view = {
      state: verified.value.state,
      history: verified.value.history,
      applied: built.entries.map((entry, index) => ({
        seq: index + 1,
        operation: { op: entry.op, payload: entry.payload },
        actorUserId: entry.actor.userId,
        viaProposalSeq: null,
      })),
    } as unknown as VerifiedProject;
    const mandates = rotationMandates(view);
    expect(mandates).toEqual([
      {
        kind: "device-revoked",
        target: owner.userId,
        seq: 5,
        environmentIds: ["env-a"],
        deviceFingerprintsHex: [dev2.fingerprintHex],
      },
    ]);
  });
  it("部分的に収束した義務(env-a は rotate 済み・env-b は未)は後の同期でも env-b だけを未収束として警告する(持ち越し)", async () => {
    // dev2(owner / all)を失効 → env-a だけ rotate 済み。env-b の義務は残ったまま
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
      {
        actor: owner,
        operation: rotateEpochOp("env-a", 2, crypto.getRandomValues(new Uint8Array(32))),
      },
    ]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("there are unconverged rotation mandates");
    expect(errors).toMatch(
      new RegExp(`device-revoked \\(target=${owner.userId}, seq=5\\): environments env-b —`),
    );
    expect(errors).not.toMatch(/device-revoked[^\n]*environments env-a/);
  });
  it("失効する端末の実効 scope が署名端末の scope 外なら、その環境は rotate せず outOfScope として注記する", async () => {
    // 署名端末 dev2 = (owner, listed {})。失効対象 reserve = (owner, all) → 義務 env-a / env-b
    // はどちらも dev2 の scope 外 = rotate できない(注記して常時警告に委ねる)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("env-a", dek) },
      { actor: owner, operation: createEnvironmentOp("env-b", dek) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "owner", environmentIds: [] }) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(
      await runCli(["device", "revoke", reserve.fingerprintHex, "--yes"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(env.errors.join("\n")).toContain(
      "2 environments with a pending rotation mandate are outside your scope and cannot be rotated by you (env-a, env-b)",
    );
  });
});

describe("maruhi device revoke", () => {
  it("受理後の sweep が失敗しても失効は成功として扱い、ローカル記録と登録簿の後段を飛ばさない", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    // 環境一覧 GET が 500 → 受理後の sweep(削除済み環境の検証)が失敗する
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      environmentsStatus: 500,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "laptop",
          createdAtMs: Date.now(),
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "revoke", dev2.fingerprintHex, "--yes"], env.layer)).toBe(1);
    expect(state.appended.map((entry) => entry.op)).toEqual(["revoke_device"]);
    expect(env.logs.join("\n")).toContain(`revoked ${dev2.fingerprintHex}`);
    const errors = env.errors.join("\n");
    expect(errors).toContain("the rotation sweep after the revocation failed");
    expect(errors).not.toContain(": revocation failed —");
    // 後段は走る: ローカル記録は失効、登録簿の行は削除
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    expect(state.registryDeletes).toEqual([dev2.fingerprintHex]);
  });

  it("FP の接頭辞で確定し、revoke_device を追記してローカル記録と登録簿に反映する(--yes)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "old-laptop",
          createdAtMs: 1,
        },
      ],
      tokensStatus: 403,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved");
    expect(
      await runCli(["device", "revoke", dev2.fingerprintHex.slice(0, 8), "--yes"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.appended[0]?.op).toBe("revoke_device");
    expect(state.appended[0]?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [dev2.fingerprintHex],
    });
    expect(state.registryDeletes).toEqual([dev2.fingerprintHex]);
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === dev2.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const logs = env.logs.join("\n");
    expect(logs).toContain(`revoke  ${dev2.fingerprintHex} (cap owner/all)`);
    expect(logs).toContain(`${built.projectId}: revoked ${dev2.fingerprintHex}`);
    // トークンの目録が読めなければ事実だけ伝える(K4-13)
    expect(env.errors.join("\n")).toContain("revoking a device does not revoke its API token");
    expect(env.prompts).toEqual([]);
  });

  it("登録簿の表示名でも参照でき、確認表に FP を併記して yes を待つ。yes 以外は何も送らない", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: dev2.fingerprintHex,
          encPubHex: dev2.encPubHex,
          sigPubHex: dev2.sigPubHex,
          label: "old-laptop",
          createdAtMs: 1,
        },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    env.setPromptResponses(["no"]);
    expect(await runCli(["device", "revoke", "old-laptop"], env.layer), env.errors.join("\n")).toBe(
      1,
    );
    expect(env.logs.join("\n")).toContain(
      `revoke  ${dev2.fingerprintHex} (cap owner/all) — matched registry label "old-laptop"`,
    );
    expect(env.errors.join("\n")).toContain("Cancelled: nothing was revoked");
    expect(state.appended).toEqual([]);
  });

  it("最後の端末は失効できない(last-device-protected)。短い接頭辞は usage エラー", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "revoke", owner.fingerprintHex, "--yes"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain(
      "it would revoke the last device (last-device-protected",
    );
    expect(state.appended).toEqual([]);
    expect(await runCli(["device", "revoke", "abc", "--yes"], env.layer)).toBe(2);
  });
});

describe("maruhi device add", () => {
  it("鍵がある端末は既定で拒否し、--replace で作り直して要求を出す。合図の後にチェーンで確認する(K4-18 / K4-5)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("This machine already has a device key");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );

    // --replace: 新しい鍵を生成 → 要求 → 登録簿に自分の行が現れたら(合図)チェーンで確認
    const before = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(
      await runCli(["device", "add", "--label", "phone", "--replace"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const after = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
    expect(after).toBeDefined();
    expect(after).not.toBe(before);
    const requestBody = server.requests.find(
      (request) => request.method === "POST" && request.path === "/auth/devices/requests",
    )?.body as { label: string; encPubHex: string } | undefined;
    expect(requestBody?.label).toBe("phone");
    expect(after).toContain(requestBody?.encPubHex ?? "never");
    expect(env.errors.join("\n")).toContain(
      "removed the copied key from this machine's keychain (--replace)",
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain("This device's key fingerprint:");
    expect(logs).toContain("fp words:");
    // 真実はチェーン: 合図の後に同期し、まだ載っていないプロジェクトを数える
    expect(logs).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain)",
    );
    expect(env.errors.join("\n")).toContain(`not registered yet on ${built.projectId}`);
  });

  it("409 request-exists の再開で要求の照会に失敗したら、その失敗を伝える(「失効」と誤案内しない)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 409,
          json: { _tag: "DeviceRegistryConflict", reason: "request-exists" },
        })),
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // 既定のモックは GET /auth/devices/requests/:fp に 404 を返す
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("expired before it was approved");
    expect(errors).toContain("DeviceNotFound");
  });

  it("409 device-registered なら登録簿の行を合図として待機の 1 巡目で拾い、チェーンで確認へ進む", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true, conflict: "device-registered" },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain)",
    );
    // 要求行は無いので approve の案内・期限は出さず、登録簿に載っている旨を出す
    expect(logs).toContain("This key is already in your device registry (no pending request)");
    expect(logs).not.toContain("The request expires at");
    expect(logs).not.toContain("Waiting for approval");
    // 要求の照会には行かない(登録簿の行が合図)
    expect(
      state.paths().some((path) => /^GET \/auth\/devices\/requests\/[0-9a-f]{32}$/.test(path)),
    ).toBe(false);
  });

  it("鍵があり登録簿に載っている端末の再実行は「要求を待つ」とは言わず、登録簿の旨だけを出す", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [
        {
          keyFingerprintHex: owner.fingerprintHex,
          encPubHex: owner.encPubHex,
          sigPubHex: owner.sigPubHex,
          label: "laptop",
          createdAtMs: Date.now(),
        },
      ],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "and it is in your device registry — verifying it on each project's chain",
    );
    expect(errors).not.toContain("resuming the wait for its approval");
    expect(env.logs.join("\n")).toContain(
      "This key is already in your device registry (no pending request)",
    );
  });

  it("要求が失効していれば TTL の案内で終わる(合図なし)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: Date.now() - 1, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The device-add request expired before it was approved (requests live 15 minutes)",
    );
    // 鍵は生成済み(再実行は同じ鍵で要求を作り直す)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeDefined();
  });
});

describe("maruhi key reserve rotate(再実行 — Bugbot 指摘)", () => {
  it("前回が台帳の差し替えで中断していても、記録上の旧予備鍵をまとめて失効させる", async () => {
    // 前回の中断: 台帳は N1(= reserve)に差し替わり、元の予備鍵 O(= dev2)は記録に
    // revoked の印が付いたが、チェーンにはまだ O も N1 も載っている(環境は無し —
    // 失効後の掃除〔rotate〕はここでは見ない)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const wrapped = await wrapMasterSecret({
      recoverySecret: secret,
      userId: owner.userId,
      masterSecretBlob: new TextEncoder().encode(
        serializeStoredMasterKey({
          suite: "maruhi/v1",
          encPubHex: reserve.encPubHex,
          encSkHex: Redacted.make(reserve.encSkHex),
          sigPubHex: reserve.sigPubHex,
          sigSkSeedHex: Redacted.make(reserve.sigSkSeedHex),
        }),
      ),
    });
    if (!wrapped.ok) throw new Error("wrap");
    const ledgerPuts: unknown[] = [];
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("GET", "/auth/recovery", () => ({
          status: 200,
          json: {
            suite: "maruhi/v1",
            nonceHex: encodeHex(wrapped.value.nonce),
            ciphertextHex: encodeHex(wrapped.value.ciphertext),
            updatedAtMs: 1754006400000,
          },
        })),
        onRequest("GET", "/auth/recovery/status", () => ({
          status: 200,
          json: { registered: true, updatedAtMs: 1754006400000 },
        })),
        onRequest("PUT", "/auth/recovery", (request) => {
          ledgerPuts.push(request.body);
          return { status: 204 };
        }),
        onRequest("GET", "/auth/key-wraps", () => ({
          status: 200,
          json: {
            recoveryCode: { registered: true, updatedAtMs: 1754006400000 },
            passkeys: [],
            guardianGroups: [],
          },
        })),
      ],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "reserve", 1_700_000_001_000);
    await recordOwnDevice(env, server.origin, reserve, "reserve");
    env.setPromptResponses([
      Redacted.value(formatRecoveryCode(Redacted.make(secret))),
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);
    expect(await runCli(["key", "reserve", "rotate"], env.layer), env.errors.join("\n")).toBe(0);
    expect(ledgerPuts).toHaveLength(1);
    // revoke_device は O と N1 の両方を対象にする(N1 だけではない)
    const revoke = state.appended.find((entry) => entry.op === "revoke_device");
    expect(revoke?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [dev2.fingerprintHex, reserve.fingerprintHex].toSorted(),
    });
    const added = state.appended.find((entry) => entry.op === "add_device");
    expect(added).toBeDefined();
    expect(env.logs.join("\n")).toContain(
      `revoking the previous reserve key ${reserve.fingerprintHex} (and 1 earlier reserve key still recorded on this machine, if any is still active) on every project`,
    );
    // ローカル記録: O と N1 は失効、新鍵だけが有効な予備鍵
    const recorded = await readOwnDevices(env, server.origin);
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect([dev2.fingerprintHex, reserve.fingerprintHex]).not.toContain(
      active[0]?.keyFingerprintHex,
    );
    // 予備鍵の秘密はキーチェーンに残らない
    const keychain = [...env.keychain.values()].join("\n");
    expect(keychain).not.toContain(reserve.encSkHex);
    expect(keychain).toContain(owner.encPubHex);
  });
});

describe("旧端末経路の撤去(ワイヤ型)", () => {
  it('HandoffApprovalSchema は source "device" / blob を受け付けず、HandoffLookupSchema の roles は分片だけ', async () => {
    const approval = {
      source: "device",
      shareIndex: 0,
      approverKeyFingerprintHex: "22".repeat(16),
      encHex: "aa".repeat(32),
      ciphertextHex: "bb".repeat(48),
    };
    const rejected = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(HandoffApprovalSchema)(approval),
    );
    expect(Exit.isFailure(rejected)).toBe(true);
    const lookup = {
      wardUserId: "user-ward",
      wardLogin: null,
      expiresAtMs: FAR_FUTURE_MS,
      roles: ["device"],
    };
    const rejectedLookup = await Effect.runPromiseExit(
      Schema.decodeUnknownEffect(HandoffLookupSchema)(lookup),
    );
    expect(Exit.isFailure(rejectedLookup)).toBe(true);
    // 予備鍵の秘密はローカル記録に載らない(公開側だけ — K4-1)
    const env = await makeTestEnv();
    await recordOwnDevice(env, "https://example.test", reserve, "reserve");
    const json = await readFile(ownDevicesPathOf(env.configPath), "utf8");
    expect(json).toContain(reserve.encPubHex);
    expect(json).not.toContain(reserve.encSkHex);
    expect(json).not.toContain(reserve.sigSkSeedHex);
  });
});
