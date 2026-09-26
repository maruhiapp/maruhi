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

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  DEVICE_ADD_REQUEST_TTL_MS,
  HandoffApprovalSchema,
  HandoffLookupSchema,
} from "@maruhi/api-schema";
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
import { DEVICE_ADD_WAIT_HINT_AFTER_MS } from "../src/device.ts";
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
  /** すべてのプロジェクト(`extraProjects` を含む)への追記(プロジェクト id つき)。 */
  readonly appendedTo: { readonly projectId: string; readonly entry: ChainEntry }[];
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
   * 登録簿 PUT の応答コードを呼び出し順に(429 = 行の上限、500 = 一時的な失敗)。
   * 尽きたら 204(DK K9-1: 失敗した回の後の再実行を成功させる)。
   */
  readonly registryPutStatuses?: readonly number[];
  /**
   * `POST /auth/devices/requests` の応答: 期限と、合図(登録簿の行)を即座に立てるか。
   * `conflict` を置くと(合図を立てた後に)409 を返す。
   */
  readonly requestCreate?: {
    readonly expiresAtMs: number;
    readonly signal: boolean;
    readonly conflict?: "request-exists" | "device-registered";
  };
  /** 同じ人が属する他のプロジェクト(チェーンの GET / 追記と空の環境一覧だけを配る — DK K10)。 */
  readonly extraProjects?: readonly BuiltChain[];
  /** DEK ラップ登録(POST)の応答コード(既定 204。500 = バックフィルの失敗 — DK K11)。 */
  readonly dekRegisterStatus?: number;
  /**
   * 自分宛 DEK の GET の応答(既定: owner 宛の epoch 1 の 1 行)。`status` を置くとその
   * コードで失敗させる(DK K12 — 新端末の鍵の到達の確認)。
   */
  readonly listMine?:
    | { readonly rows: readonly Record<string, unknown>[] }
    | { readonly status: number };
  /** `GET /auth/devices/requests/:fp` が返す生きた要求(FP が一致するもの — 既定は 404)。 */
  readonly pendingRequests?: readonly Record<string, unknown>[];
  /** プロジェクト一覧 GET の応答コード(既定 200 — DK K13 の一覧の失敗)。 */
  readonly projectsStatus?: number;
  /**
   * 一覧に載るが同期できないプロジェクト(DK K13-3): `unavailable` = チェーン GET が 500、
   * `tampered` = ヘッドの申告がエントリと食い違う(検証の矛盾 — `evidence`)。
   */
  readonly brokenProjects?: readonly {
    readonly built: BuiltChain;
    readonly mode: "unavailable" | "tampered";
  }[];
}): Promise<{ server: MockServer; state: ServerState }> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appended: ChainEntry[] = [];
  const appendedTo: ServerState["appendedTo"] = [];
  const registered: ServerState["registered"] = [];
  const registry: ServerState["registry"] = [...(input.registryRows ?? [])];
  const registryPuts: ServerState["registryPuts"] = [];
  const registryDeletes: string[] = [];
  const requestCancels: string[] = [];
  const registryPutStatuses = [...(input.registryPutStatuses ?? [])];
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
      appendedTo.push({ projectId, entry: body.entry });
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
        return listMineResponse(input.listMine, ownWrap);
      }
      if (request.method === "POST") {
        if (input.dekRegisterStatus !== undefined) {
          return { status: input.dekRegisterStatus, json: { _tag: "Internal" } };
        }
        const body = request.body as { readonly deks: readonly Record<string, unknown>[] };
        registered.push({ environmentId: ENV_ID, deks: body.deks });
        return { status: 204 };
      }
      return null;
    },
    onRequest("GET", "/projects", () =>
      input.projectsStatus !== undefined && input.projectsStatus !== 200
        ? { status: input.projectsStatus, json: { _tag: "Internal" } }
        : {
            status: 200,
            json: {
              projects: [
                input.built,
                ...(input.extraProjects ?? []),
                ...(input.brokenProjects ?? []).map((broken) => broken.built),
              ].map((built) => ({ projectId: built.projectId, role: "owner" })),
            },
          },
    ),
    ...(input.brokenProjects ?? []).map((broken) =>
      onRequest("GET", `/projects/${broken.built.projectId}/chain`, () =>
        broken.mode === "unavailable"
          ? { status: 500, json: { _tag: "Internal" } }
          : {
              status: 200,
              json: {
                projectId: broken.built.projectId,
                entries: broken.built.entries,
                headSeq: broken.built.entries.length + 1,
                headHashHex: broken.built.hashes[broken.built.hashes.length - 1],
              },
            },
      ),
    ),
    ...(input.extraProjects ?? []).flatMap((built) => extraProjectHandlers(built, appendedTo)),
    onRequest("GET", "/auth/devices", () => ({ status: 200, json: { devices: registry } })),
    (request: MockRequest) => {
      const match = /^\/auth\/devices\/([0-9a-f]{32})$/.exec(request.path);
      if (match === null) {
        return null;
      }
      const fp = match[1] ?? "";
      if (request.method === "PUT") {
        registryPuts.push({ fp, body: request.body as Record<string, unknown> });
        const status = registryPutStatuses.shift() ?? 204;
        if (status === 429) {
          return {
            status,
            json: { _tag: "DeviceRegistryLimit", reason: "device-rows", limit: 32 },
          };
        }
        if (status !== 204) {
          return { status, json: { _tag: "Internal" } };
        }
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
      const pending = input.pendingRequests?.find((row) => row["keyFingerprintHex"] === match[1]);
      return pending === undefined
        ? { status: 404, json: { _tag: "DeviceNotFound" } }
        : { status: 200, json: pending };
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
      appendedTo,
      registered,
      registry,
      registryPuts,
      registryDeletes,
      requestCancels,
      paths: () => server.requests.map((request) => `${request.method} ${request.path}`),
    },
  };
}

/** 自分宛 DEK の GET の応答(`makeServer` の `listMine` — 既定は owner 宛の epoch 1 の 1 行)。 */
function listMineResponse(
  listMine:
    | { readonly rows: readonly Record<string, unknown>[] }
    | { readonly status: number }
    | undefined,
  ownWrap: WireRecipientDek | null,
): { status: number; json: unknown } {
  if (listMine === undefined) {
    return { status: 200, json: { deks: ownWrap === null ? [] : [ownWrap] } };
  }
  return "status" in listMine
    ? { status: listMine.status, json: { _tag: "Internal" } }
    : { status: 200, json: { deks: listMine.rows } };
}

/** 他のプロジェクトのチェーン(GET / 追記)と空の環境一覧(`makeServer` の `extraProjects`)。 */
function extraProjectHandlers(
  built: BuiltChain,
  appendedTo: ServerState["appendedTo"],
): MockHandler[] {
  const { projectId } = built;
  const entries: ChainEntry[] = [...built.entries];
  const hashes: string[] = [...built.hashes];
  return [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedTo.push({ projectId, entry: body.entry });
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: { environments: [] },
    })),
  ];
}

/** ある端末鍵の `add_device` の追記(全プロジェクト — プロジェクト id と cap の role)。 */
function addsOf(
  state: ServerState,
  device: TestUser,
): { readonly projectId: string; readonly roleCap: string }[] {
  return state.appendedTo.flatMap(({ projectId, entry }) =>
    entry.op === "add_device" && entry.payload.encPubHex === device.encPubHex
      ? [{ projectId, roleCap: entry.payload.roleCap }]
      : [],
  );
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
  it("バックフィルの失敗は、承認の再実行でなく兄弟端末の pull を案内する(DK K11-5)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      dekRegisterStatus: 500,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    // 端末はチェーンに載り、後段(記録・登録簿・取消)は走る — 欠けは pull が補う
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`${built.projectId}: backfill of environment ${ENV_ID} failed (`);
    expect(errors).toContain(
      `A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("Re-run `maruhi device approve`");
  });

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
    const approveLogs = env.logs.join("\n");
    expect(approveLogs).toContain("registered the device (backfilled 1 DEK wrap");
    // FP の出所の規律(K7-7): label / 12 語の直後に、追加する機械の画面と見比べよと 1 文
    // (要求を置けるのはアカウント全域の admin トークン — `ensureKeyMaterialAccess`)
    expect(approveLogs).toContain(
      "Compare them with the screen of the machine you are adding, never with a fingerprint sent to you: a request can be placed by anyone holding an account-wide admin API token of yours",
    );
    expect(approveLogs.indexOf("fp words:")).toBeLessThan(
      approveLogs.indexOf("Compare them with the screen"),
    );
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

  it("この端末がチェーンに居ないプロジェクトは skipped で、要求なしの承認でなく同期の経路を案内する(DK K10-5)", async () => {
    // dev2 は owner と同じ人の端末鍵だが、このプロジェクトのチェーンには居ない
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(reserve)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "approve", reserve.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `skipped — this machine's key is not one of your registered devices here, so it cannot register devices here. A device of yours that is registered here adds the new device (and this machine) when it runs a keyed command on this project at a terminal (\`maruhi pull --project ${built.projectId}\`, for instance)`,
    );
    // 従えない手順(要求なしの承認)を案内しない
    expect(errors).not.toContain("approve this machine first");
    expect(state.appendedTo).toEqual([]);
  });

  it("手元の鍵がチェーンに無いときの案内は、待機中の要求の承認と同期の経路を分けて言う(DK K10-5)", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({ built, withEnvironment: true });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "If `maruhi device add` is still waiting on this machine, approve it from a registered device with `maruhi device approve`. If this device is registered on other projects of yours, a device of yours that is registered here adds it when it runs a keyed command on this project at a terminal",
    );
    expect(errors).not.toContain("run `maruhi device approve` for this machine");
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

  it("登録簿 PUT が 429 なら要求を取り消さず(DK K9-1)、rows を消した後の再実行が already → PUT → 取消で収束する", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [429],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // チェーンには載ったので失敗ではない(終了コード 0 — K8-5 第 3 巡)
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.registryPuts).toHaveLength(1);
    // 合図を出せなかったので、合図を出し直す材料(要求)は残す
    expect(state.requestCancels).toEqual([]);
    const note = env.errors.join("\n");
    expect(note).toContain("the device registry is full (32 rows)");
    // docs(`devices.mdx`)が引用する 2 文は、両方の分岐で隣り合う(PR #196 pullfrog)
    expect(note).toContain(
      "will not see the completion signal. The request is left in place until",
    );
    // 打ち直すコマンドは同じ cap を運ぶ(DK K10-1 — フラグなしの再実行は既定の owner / all)
    expect(note).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap owner --all-envs\` before then to list it`,
    );
    expect(note).toContain("unlisted in your device registry");
    // 承認側が rows を消して再実行: 全プロジェクト already(追記なし)→ PUT → 取消
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.registryPuts.map((put) => put.fp)).toEqual([
      dev2.fingerprintHex,
      dev2.fingerprintHex,
    ]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
    expect(env.logs.join("\n")).toContain("already registered");
  });

  it("429 以外の PUT 失敗(一時的な 500)でも要求を残し、同じ再実行の案内を出す(DK K9-2)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [500],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appended).toHaveLength(1);
    expect(state.requestCancels).toEqual([]);
    const note = env.errors.join("\n");
    expect(note).toContain("could not update the device registry (");
    expect(note).toContain("the device is registered on the chains above regardless");
    expect(note).toContain(
      "will not see the completion signal. The request is left in place until",
    );
    expect(note).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap owner --all-envs\` before then to list it`,
    );
    expect(note).not.toContain("registry is full");
  });

  it("PUT 失敗の Note の打ち直しは今回の cap と --project を運ぶ(DK K10-1)", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
      registryPutStatuses: [500],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(
      await runCli(
        [
          "device",
          "approve",
          dev2.fingerprintHex,
          "--cap",
          "member",
          "--env",
          ENV_ID,
          "--project",
          built.projectId,
        ],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.errors.join("\n")).toContain(
      `re-run \`maruhi device approve ${dev2.fingerprintHex} --cap member --env ${ENV_ID} --project ${built.projectId}\` before then to list it`,
    );
  });

  it("チェーンに別の cap で載っている鍵の再実行は、何も追記・記録せず要求を残して拒否し、同じ cap のコマンドを出す(DK K10-1)", async () => {
    // 前回の承認(member / env-app)が PUT の失敗か中断で要求を残した状態
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      {
        actor: owner,
        operation: addDeviceOp(dev2, { roleCap: "member", environmentIds: [ENV_ID] }),
      },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      requests: [requestRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    // フラグなし = 既定の owner / all(K9 の Note をフラグなしで打った人 — 広げる向き)
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Device ${dev2.fingerprintHex} is already registered with cap member/${ENV_ID} on ${built.projectId}, and this approval asks for owner/all: a device's cap is set when it is first approved and cannot be changed later, so this approval appended nothing, recorded nothing and left the request in place`,
    );
    expect(errors).toContain(
      `Re-run it with that cap: \`maruhi device approve ${dev2.fingerprintHex} --cap member --env ${ENV_ID}\`.`,
    );
    // 足し直しの手順は 1 関数の字面(DK K12-7): 失効した鍵は戻らないので新しい鍵 + 承認
    expect(errors).toContain(
      "To give the device another cap, revoke it, then run `maruhi device add --replace` on that machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device with the cap you want",
    );
    expect(errors).not.toContain("re-add it instead");
    expect(state.appendedTo).toEqual([]);
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    // 記録は承認で上書きされない(同期の観測がチェーンの cap で書いた行のまま)
    const before = (await readOwnDevices(env, server.origin)).find(
      (row) => row.keyFingerprintHex === dev2.fingerprintHex,
    );
    expect(before).toMatchObject({ source: "observed", roleCap: "member" });
    // 出されたコマンドで打ち直すと収束する(already → 記録 → PUT → 取消)
    expect(
      await runCli(
        ["device", "approve", dev2.fingerprintHex, "--cap", "member", "--env", ENV_ID],
        env.layer,
      ),
      env.errors.join("\n"),
    ).toBe(0);
    expect(state.appendedTo).toEqual([]);
    const after = (await readOwnDevices(env, server.origin)).find(
      (row) => row.keyFingerprintHex === dev2.fingerprintHex,
    );
    expect(after).toMatchObject({
      source: "approved",
      roleCap: "member",
      scope: { kind: "listed", environmentIds: [ENV_ID] },
    });
    expect(state.registryPuts.map((put) => put.fp)).toEqual([dev2.fingerprintHex]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
  });

  it("別のプロジェクトに未登録でも、どこかのチェーンの cap と食い違えばどこにも今回の cap で足さない(DK K10-4 の 2 相)", async () => {
    // P1 には member / all で載っている。P2(genesis の端末が別 = 別のプロジェクト id)には無い
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "member" }) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(owner) },
    ]);
    const { server, state } = await makeServer({
      built: p1,
      withEnvironment: false,
      requests: [requestRowOf(dev2)],
      extraProjects: [p2],
    });
    const env = await startEnv(server.origin, p1.projectId, owner);
    expect(await runCli(["device", "approve", dev2.fingerprintHex], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Device ${dev2.fingerprintHex} is already registered with cap member/all on ${p1.projectId}`,
    );
    // 今回の cap(owner / all)の add_device はどのプロジェクトにも出ない(同期の観測 → 登録が
    // P2 に足すことはあるが、それはチェーンの cap = member)
    expect(addsOf(state, dev2).map((add) => add.roleCap)).not.toContain("owner");
    expect(
      (await readOwnDevices(env, server.origin)).find(
        (row) => row.keyFingerprintHex === dev2.fingerprintHex,
      )?.source,
    ).not.toBe("approved");
    expect(state.registryPuts).toEqual([]);
    expect(state.requestCancels).toEqual([]);
    // 同じ cap の打ち直しは両方のプロジェクトに member で載せて収束する
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--cap", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(addsOf(state, dev2)).toEqual([{ projectId: p2.projectId, roleCap: "member" }]);
    expect(state.requestCancels).toEqual([dev2.fingerprintHex]);
  });

  it("鍵のチェーン上の cap がプロジェクトごとに既に違えば、--project で 1 つずつ打ち直すよう案内する(DK K10-2)", async () => {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2, { roleCap: "member" }) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(owner) },
      { actor: reserve, operation: addDeviceOp(dev2, { roleCap: "admin" }) },
    ]);
    const { server, state } = await makeServer({
      built: p1,
      withEnvironment: false,
      requests: [requestRowOf(dev2)],
      extraProjects: [p2],
    });
    const env = await startEnv(server.origin, p1.projectId, owner);
    expect(
      await runCli(["device", "approve", dev2.fingerprintHex, "--cap", "member"], env.layer),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("member/all on ");
    expect(errors).toContain("admin/all on ");
    expect(errors).toContain(
      "Its cap differs between those projects, so re-run it once per project with `--project <id>` and the cap shown for that project.",
    );
    // dev2 はどこにも足されない(同期が他の端末〔genesis の予備鍵〕を足すのは別の経路)
    expect(addsOf(state, dev2)).toEqual([]);
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
      // 記録の cap が働く時点で、足した cap を出す(DK K10-3)
      expect(env.errors.join("\n")).toContain(`with cap owner/all on project ${built.projectId}`);
      // 登録簿は判断の入力にならない: 読まれもしない(登録簿だけにある端末は足されない)
      expect(state.paths().filter((path) => path.startsWith("GET /auth/devices"))).toEqual([]);
      // 予備鍵の不在の警告(K4-9)は「自分の端末がこの端末だけ、かつ記録に予備鍵が無い」
      // ときだけ: reserve は記録があり、approved / observed は登録後に端末が 2 つになる
      expect(env.errors.join("\n")).not.toContain("no reserve key is registered");
    });
  }

  it("登録した端末のバックフィルの失敗は、次の同期でなく pull を案内する(DK K11-5)", async () => {
    const built = await chainWithEnvironment();
    const { server, state } = await makeServer({
      built,
      withEnvironment: true,
      extra: [inviteHandler(built)],
      dekRegisterStatus: 500,
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved");
    expect(await runCli(["invite", "create", "--role", "member"], env.layer)).toBe(0);
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `; the backfill failed for 1 environment (${ENV_ID}) — a registered device of yours whose cap covers it fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    expect(errors).not.toContain("retried on the next sync");
  });

  it("エージェント環境・非端末では記録からの登録を行わない(儀式ゲート — K4-37)", async () => {
    for (const mode of ["agent", "non-tty"] as const) {
      const built = await chainWithEnvironment();
      const { server, state } = await makeServer({
        built,
        withEnvironment: true,
        extra: [inviteHandler(built)],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      // 仕込まれた行(署名されていないファイル)— 出所は approved を装う
      await recordOwnDevice(env, server.origin, dev2, "approved");
      if (mode === "agent") {
        env.setAgent({ isAgent: true, name: "test-agent" });
      } else {
        env.setTerminal({ stdin: false });
      }
      // 鍵ありの前段(初回同期)は走るが、登録は飛ばす
      await runCli(["invite", "create", "--role", "member"], env.layer);
      expect(state.appended).toEqual([]);
      expect(state.registered).toEqual([]);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        `1 device key recorded on this machine (${dev2.fingerprintHex}) is not registered on project`,
      );
      expect(errors).toContain(
        mode === "agent"
          ? "an AI agent environment was detected (test-agent)"
          : "stdin is not an interactive terminal",
      );
      // 前段は 1 コマンド 1 プロジェクトなので、このプロジェクトを対象にしたコマンドを出す(DK K10-5)
      expect(errors).toContain(`for example \`maruhi pull --project ${built.projectId}\``);
    }
  });

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

  it("失効と記録した端末がチェーンで有効なら、従えない『承認し直せ』でなく失効か足し直しを案内する(DK K10-5)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [inviteHandler(built)],
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    await recordOwnDevice(env, server.origin, dev2, "approved", 1_700_000_000_000);
    expect(
      await runCli(["invite", "create", "--role", "member"], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `device ${dev2.fingerprintHex} was revoked from this machine's records but is active on project ${built.projectId}`,
    );
    expect(errors).toContain(
      "It is not re-added to other projects from here (a revoked record is never cleared by syncing). If it should not be active, revoke it with",
    );
    expect(errors).toContain(
      "if that machine should be on more projects, revoke it, then run `maruhi device add --replace` on that machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device",
    );
    expect(errors).not.toContain("approve it explicitly");
    expect(state.appendedTo).toEqual([]);
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
  it("最初の鍵を持つ端末は 2 択で拒否し(要求を作らない)、--replace は新しい鍵の要求の後で差し替える(K13-2 / K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: true },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    // genesis の鍵 = 最初の鍵: この端末そのものか pre-DK の複製かは機械に分からない(K13-2)
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${owner.fingerprintHex}) is your first key on ${built.projectId} (the key you created or joined that project with), and it has no pending device-add request. maruhi cannot tell whether this machine is the device that key belongs to or holds a copy of it from an install before device keys. If this machine is that device, nothing is needed: it is already registered. If it holds a copy, re-run with --replace: it generates a new key for this machine and prints its fingerprint to approve from a registered device (the machine the copy came from keeps its key). Do not pass --replace if this is your only device`,
    );
    // 既存の鍵は要求を作りに行かない(サーバーの 1 時間 5 回の窓を消費しない)
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );

    // --replace: 捨てる鍵の立場を表示 → 新しい鍵を生成 → 要求 → 差し替え → 合図 → チェーンで確認
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
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: replacing this machine's key ${owner.fingerprintHex}, which is registered on ${built.projectId} as your first key there. Once the new key is approved, revoke the previous key where it is still registered unless another machine holds it (\`maruhi device revoke ${owner.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).toContain("replaced the previous key in this machine's keychain (--replace)");
    const logs = env.logs.join("\n");
    expect(logs).toContain("This device's key fingerprint:");
    expect(logs).toContain("fp words:");
    // 真実はチェーン: 合図の後に同期し、まだ載っていないプロジェクトを数える
    expect(logs).toContain(
      "Approved: this device is registered on 0 projects (verified on each project's chain)",
    );
    // 不足分の案内(K7-2): 承認側の作業は終わっている・要求は使い切り・登録するのは
    // cap が覆う端末の次の鍵付きコマンド(「承認側の再実行」「まだ作業中」とは言わない)
    const missingNote = env.errors.find((line) => line.includes("not registered yet on"));
    expect(missingNote).toContain(`not registered yet on ${built.projectId}`);
    expect(missingNote).toContain("skipped or failed on them");
    expect(missingNote).toContain("The request is used up");
    // 前段は 1 コマンド 1 プロジェクトなので「そのプロジェクトを対象にした」鍵付きコマンド(DK K10-5)
    expect(missingNote).toContain(
      "when it runs a keyed command on that project at a terminal (`maruhi pull --project <id>`, for instance)",
    );
    expect(missingNote).not.toContain("may still be working");
    expect(missingNote).not.toContain("Re-run `maruhi device approve`");
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
    expect(errors).not.toContain("expired before this machine saw the completion signal");
    expect(errors).toContain("DeviceNotFound");
  });

  it("新しい鍵の 409 device-registered(FP の衝突でしか起きない)では待たず「Approved」とも言わず、チェーンの立場で報告する(K13-3 — 穴 5 の防御)", async () => {
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
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const logs = env.logs.join("\n");
    expect(logs).not.toContain("Approved:");
    expect(logs).not.toContain("The request expires at");
    expect(logs).not.toContain("Waiting for approval");
    expect(env.errors.join("\n")).not.toContain("still waiting (");
    // 新しい鍵はどのチェーンにも無い — 範囲つきで「失うものは無い」と言う
    expect(env.errors.join("\n")).toContain(
      "has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there",
    );
    // 要求の照会には行かない(新しい鍵に生きた要求は無い)
    expect(
      state.paths().some((path) => /^GET \/auth\/devices\/requests\/[0-9a-f]{32}$/.test(path)),
    ).toBe(false);
  });

  it("登録簿の行は分岐に使わない: 行があっても最初の鍵なら 2 択で止まり、「登録簿にある」を再開の理由にしない(K13-9)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(owner)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, owner);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`is your first key on ${built.projectId}`);
    expect(errors).not.toContain("in your device registry — verifying it");
    expect(errors).not.toContain("resuming the wait for its approval");
    expect(env.logs.join("\n")).not.toContain("Approved:");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
  });

  it("要求の作成から TTL の 1/3 が経っても合図が無ければ、承認側の出力を確認せよと 1 度だけ出す(K7-3)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // 要求は 6 分前に作られたことにする(期限 = 作成 + 15 分)。合図はまだ無い
    const requestedAtMs = Date.now() - DEVICE_ADD_WAIT_HINT_AFTER_MS - 60 * 1000;
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      requestCreate: { expiresAtMs: requestedAtMs + DEVICE_ADD_REQUEST_TTL_MS, signal: false },
    });
    const env = await makeTestEnv();
    env.keychain.set(
      tokenEntryName(server.origin),
      JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
    );
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // 1 巡目(合図なし → 案内)の後、承認側の PUT に相当する行を置く: 2 巡目で合図を拾う
    const run = runCli(["device", "add", "--label", "phone"], env.layer);
    const rowPlaced = new Promise<void>((resolve) => {
      const tick = (): void => {
        const stored = env.keychain.get(masterKeyEntryName(server.origin, owner.userId));
        const hinted = env.errors.some((line) => line.includes("still waiting ("));
        if (stored !== undefined && hinted) {
          const record = JSON.parse(stored) as { encPubHex: string; sigPubHex: string };
          void computeUserKeyFingerprint(
            hexBytes(record.encPubHex),
            hexBytes(record.sigPubHex),
          ).then((fp) => {
            if (!fp.ok) throw new Error("fp");
            state.registry.push({
              keyFingerprintHex: encodeHex(fp.value),
              encPubHex: record.encPubHex,
              sigPubHex: record.sigPubHex,
              label: "phone",
              createdAtMs: Date.now(),
            });
            resolve();
          });
          return;
        }
        setTimeout(tick, 20);
      };
      tick();
    });
    await rowPlaced;
    expect(await run, env.errors.join("\n")).toBe(0);
    const hints = env.errors.filter((line) => line.includes("still waiting ("));
    expect(hints).toHaveLength(1);
    // 経過は実測(再開した待機では閾値より大きい)— ここでは閾値 + 1 分
    expect(hints[0]).toContain("6 minutes since the request");
    expect(hints[0]).toContain("this key is not in your device registry yet");
    expect(hints[0]).toContain(
      "failed on every project, or could not list this device in your device registry, the cause is in its output",
    );
    expect(env.logs.join("\n")).toContain("Approved: this device is registered on 0 projects");
  }, 15_000);

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
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "The device-add request expired before this machine saw the completion signal (requests live 15 minutes)",
    );
    // 案内は実装どおり(K7-1): 再実行は拒否される(K4-21)ので `--replace` を、承認側が
    // 何も登録していないことを条件に案内する。「同じ鍵で作り直す」とは言わない
    expect(expired).toContain("if it registered nothing, run `maruhi device add --replace`");
    expect(expired).not.toContain("it reuses this key");
    // K9-3 の T3: 承認側が登録したが登録簿に載せられず、期限までに再実行しなかったとき、
    // 鍵はチェーンに載っている — `--replace` で捨てさせない分岐を持つ
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    // この時点のチェーンの事実(K13-4 — 条件は保ったまま足す)
    expect(expired).toContain(
      "On the project chains right now, this key is on no project the server lists for you (1 listed). If the approving device is still working, re-running `maruhi device add` on this machine later shows whether it registered this key, without a new request",
    );
    // 鍵は生成済みのまま(捨てるのは人が `--replace` を打ったとき)
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeDefined();
  });
});

/**
 * 新端末 dev2 の `device add` の再実行(登録簿の行が合図 — 要求なし)の足場: チェーンは
 * genesis → 環境(epoch 1)→ rotate(epoch 2)→ dev2 の `add_device`(cap は引数)。
 * 手元の鍵は dev2。自分宛 DEK の GET の応答は `listMine`(DK K12)。
 */
async function deviceAddReachFixture(input: {
  readonly cap?: Parameters<typeof addDeviceOp>[1];
  /** dev2 の生きた要求を置く(待機の再開 → 合図 → 「Approved」の経路 — DK K13-2)。 */
  readonly pending?: boolean;
  readonly listMine: (
    projectId: string,
  ) => Promise<{ readonly rows: readonly Record<string, unknown>[] } | { readonly status: number }>;
}): Promise<{ readonly env: TestEnv; readonly state: ServerState; readonly built: BuiltChain }> {
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: addDeviceOp(dev2, input.cap) },
  ]);
  reachDeks.set(built.projectId, [dek, dek2]);
  const { server, state } = await makeServer({
    built,
    withEnvironment: true,
    registryRows: [registryRowOf(dev2)],
    requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    listMine: await input.listMine(built.projectId),
    pendingRequests: input.pending === true ? [requestRowOf(dev2)] : [],
  });
  const env = await startEnv(server.origin, built.projectId, dev2);
  return { env, state, built };
}

/** `deviceAddReachFixture` のチェーンの各エポックの DEK(プロジェクトごと)。 */
const reachDeks = new Map<string, readonly Uint8Array[]>();

function registryRowOf(device: TestUser): ServerState["registry"][number] {
  return {
    keyFingerprintHex: device.fingerprintHex,
    encPubHex: device.encPubHex,
    sigPubHex: device.sigPubHex,
    label: "laptop",
    createdAtMs: Date.now(),
  };
}

/** 端末宛の配布行(新サーバーの形 — `recipientEncPubHex` つき、owner の登録署名)。 */
async function deviceRowsOf(
  projectId: string,
  device: TestUser,
  epochs: readonly number[],
): Promise<Record<string, unknown>[]> {
  const deks = reachDeks.get(projectId) ?? [];
  return Promise.all(
    epochs.map(async (epoch) => ({
      ...(await wrapDekFor({
        projectId,
        environmentId: ENV_ID,
        epoch,
        dek: deks[epoch - 1] ?? new Uint8Array(32),
        recipient: device,
        signer: owner,
      })),
      recipientEncPubHex: device.encPubHex,
    })),
  );
}

function listMineGets(state: ServerState, projectId: string): number {
  return state
    .paths()
    .filter((path) => path === `GET /projects/${projectId}/environments/${ENV_ID}/deks`).length;
}

describe("maruhi device add — 合図の後の鍵の到達と失効(DK K12)", () => {
  it("この端末宛のエポックが欠けていれば、pull と同じ警告を実 id の経路つきで出し、終了コードは 0 で何も登録しない", async () => {
    // dev2 宛は epoch 1 だけ(兄弟の owner 宛は 1 と 2 — 他の端末宛の行は数えない)。
    // 生きた要求の待機を再開し(要求は作らない)、合図(登録簿の行)の後に確かめる
    const { env, state, built } = await deviceAddReachFixture({
      pending: true,
      listMine: async (projectId) => ({
        rows: [
          ...(await deviceRowsOf(projectId, dev2, [1])),
          ...(await deviceRowsOf(projectId, owner, [1, 2])),
        ],
      }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const warning = env.errors.find((line) => line.includes("no DEK wraps for you exist"));
    expect(warning).toContain(
      `Warning: ${built.projectId}: environment ${ENV_ID}: no DEK wraps for you exist at epochs 2 (inconsistent with the CRYPTO_SPEC §7 all-epoch distribution)`,
    );
    expect(warning).toContain(
      "If this machine was added as a device, the backfill to it may not have completed instead.",
    );
    expect(warning).toContain(
      `A registered device of yours whose cap covers environment ${ENV_ID} and that holds its keys fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
    // 新端末は欠けた DEK を持たないので補わない(補うのは兄弟端末の pull — K11)
    expect(state.registered).toEqual([]);
    expect(env.errors.join("\n")).toContain("resuming the wait for its approval");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
    expect(env.errors.join("\n")).not.toContain("not registered yet");
  });

  it("全エポックが届いていれば何も足さない(確認は走っている — GET は 1 回)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      listMine: async (projectId) => ({ rows: await deviceRowsOf(projectId, dev2, [1, 2]) }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("この端末の cap の外の環境は確かめない(受信者でない環境を欠けとも確認の失敗とも言わない)", async () => {
    const { env, state, built } = await deviceAddReachFixture({
      cap: { roleCap: "owner", environmentIds: [] },
      listMine: async () => ({ rows: [] }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(listMineGets(state, built.projectId)).toBe(0);
    // 欠けとも、確認の失敗(cap の外で開けない)とも言わない — 列挙に入らない
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).not.toContain("could not check");
  });

  it("確かめられなかった環境は欠けと言わず、原因つきの Note で終了コード 0", async () => {
    const { env, built } = await deviceAddReachFixture({
      listMine: async () => ({ status: 500 }),
    });
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("no DEK wraps for you exist");
    expect(errors).toContain(
      `Note: ${built.projectId}: could not check that the keys of environment ${ENV_ID} reached this device (`,
    );
    expect(errors).toContain(
      `\`maruhi pull --project ${built.projectId} --env ${ENV_ID}\` on this machine reports any missing epochs`,
    );
  });

  it("全プロジェクトで失効した鍵は、登録簿の行が残っていても待たず、失効と足し直しで止まる(K13-2 — 諮る点 (2) の回収)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    // 「Approved: … 0 projects」は構造上出ない(登録簿の行を合図に待つ経路が無い)
    expect(env.logs.join("\n")).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) is revoked on ${built.projectId} and registered on no project the server lists for you (1 listed), and it has no pending device-add request. To add this machine back, run \`maruhi device add --replace\` on this machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device — you choose its cap again when approving`,
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("loses nothing");
    expect(state.paths().filter((path) => path.startsWith("POST /auth/devices/requests"))).toEqual(
      [],
    );
  });

  it("一部のプロジェクトでだけ失効した鍵は、足し直しの後で残りのプロジェクトの鍵を失効させるよう言う(K12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    // 別のプロジェクト(genesis の鍵を変えて別の id にする — 同じ人)では dev2 は有効
    const other = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
      requestCreate: { expiresAtMs: FAR_FUTURE_MS, signal: false, conflict: "device-registered" },
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    // 有効なプロジェクトがあり、そこでは add_device 出所 → 使える鍵(exit 0 — K13-2)。承認は
    // 起きていないので「Approved」とは言わない(K13-3)
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: this key was revoked on ${built.projectId},`);
    expect(errors).toContain(
      `. This keychain then no longer holds this key, so revoke it on ${other.projectId}, where it is still registered (\`maruhi device revoke ${dev2.fingerprintHex}\` from a registered device)`,
    );
    expect(errors).not.toContain("not registered yet");
  });
});

/** 鍵なしの端末(トークンだけ — `device add` が鍵を生成する)。 */
async function startEnvWithoutKey(origin: string, projectId: string): Promise<TestEnv> {
  const env = await makeTestEnv();
  env.keychain.set(
    tokenEntryName(origin),
    JSON.stringify({ token: "maruhi_pat_stored", userId: owner.userId, tokenId: "tok_1" }),
  );
  await seedConfig(env, { server: origin, defaultProject: projectId });
  return env;
}

function requestPosts(state: ServerState): readonly string[] {
  return state.paths().filter((path) => path === "POST /auth/devices/requests");
}

describe("maruhi device add — 既存の鍵のチェーン上の立場(DK K13)", () => {
  it("どのプロジェクトでも add_device 出所の有効な鍵は、要求を作らずに登録済みを報告して 0。登録簿の行が無ければ補足する(T3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      "This key is registered on 1 project (verified on each project's chain)",
    );
    expect(logs).not.toContain("Approved:");
    expect(env.errors.join("\n")).toContain(
      "Note: this key has no row in your device registry (an approval whose registry write failed leaves it so). The registry only labels devices, so nothing else is needed",
    );
    expect(requestPosts(state)).toEqual([]);

    // 登録簿に行があれば補足しない(補足は行が無いときだけ)
    const withRow = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
    });
    const env2 = await startEnv(withRow.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    expect(env2.errors.join("\n")).not.toContain("has no row in your device registry");
  });

  it("承認が起きていない経路で無いプロジェクトは、承認側の筋書きでなく中立の文で言う(K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const other = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extraProjects: [other],
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `Note: this key is not registered on ${other.projectId}. A device of yours whose cap covers them registers it on each of them when it runs a keyed command on that project at a terminal (\`maruhi pull --project <id>\`, for instance), once it has synced a project that has this key`,
    );
    expect(errors).not.toContain("the approving device skipped or failed");
    expect(errors).not.toContain("The request is used up");
  });

  it("穴 1: 別のプロジェクトで add_device 出所でも、どこか 1 つで最初の鍵なら 2 択で 1(観測の記録からの登録は承認の証拠にならない)", async () => {
    // P1 では dev2 の鍵が genesis(最初の鍵)、P2 では観測の記録から add_device された
    const p1 = await buildChain([{ actor: dev2, operation: genesisOp(dev2) }]);
    const p2 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const { server, state } = await makeServer({
      built: p2,
      withEnvironment: false,
      extraProjects: [p1],
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, p2.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) is your first key on ${p1.projectId} (the key you created or joined that project with)`,
    );
    expect(errors).toContain("If it holds a copy, re-run with --replace");
    expect(errors).not.toContain(`is your first key on ${p2.projectId}`);
    expect(env.logs.join("\n")).not.toContain("This key is registered on");
    expect(requestPosts(state)).toEqual([]);
  });

  it("有効ゼロで全件を同期でき、どこにも無ければ、一覧の件数つきで「失うものは無い」と言う", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server, state } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request and is on no project the server lists for you (1 listed), each chain synced and verified, so replacing it loses nothing there: re-run with --replace — it discards this key, generates a new one and prints its fingerprint to approve from a registered device`,
    );
    expect(env.errors.join("\n")).not.toContain("local records of");
    expect(requestPosts(state)).toEqual([]);
  });

  it("案 B: 床にあって一覧に無いプロジェクトは情報として添えるだけで、判定(どこにも無い)を止めない", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    const unlisted = "ab".repeat(32);
    await mkdir(env.floorDir, { recursive: true });
    await writeFile(join(env.floorDir, `${unlisted}.jsonl`), "");
    // ID の形でないもの・付随ファイルは数えない
    await writeFile(join(env.floorDir, `${"cd".repeat(32)}.attested.json`), "{}");
    await writeFile(join(env.floorDir, "notes.jsonl"), "");
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("so replacing it loses nothing there");
    expect(errors).toContain(
      `. This machine also has local records of 1 project that list does not include (${unlisted}); those records are not separated by server or account, so they may not be yours here — if one is, check it with \`maruhi project verify --project <id>\` before replacing`,
    );
    expect(errors).not.toContain("could not check every project");
  });

  it("同期できないプロジェクトがあれば「無い」と言わず断言もしない。検証の矛盾は改ざんの兆候として Warning", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const tampered = await buildChain([{ actor: member, operation: genesisOp(member) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      brokenProjects: [
        { built: down, mode: "unavailable" },
        { built: tampered, mode: "tampered" },
      ],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `This machine's device key (${dev2.fingerprintHex}) has no pending device-add request, and maruhi could not check every project it may be registered on: `,
    );
    expect(errors).toContain(`${down.projectId} could not be synced (`);
    expect(errors).toContain(`It is not on ${built.projectId}. `);
    expect(errors).toContain(
      "Nothing is decided from a project that was not checked, so this does not say the key is unused",
    );
    expect(errors).not.toContain("loses nothing");
    const warnings = env.errors.filter((line) => line.startsWith("Warning:"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`Warning: ${tampered.projectId}: `);
    expect(warnings[0]).toContain(
      "— a sign of tampering rather than a network error, so nothing about this key is decided from that project",
    );
    expect(requestPosts(state)).toEqual([]);
  });

  it("プロジェクト一覧が取れなくても落ちず、同期できずとして断言しない(穴 6)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false, projectsStatus: 500 });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "and maruhi could not check every project it may be registered on: your projects could not be listed (",
    );
    expect(errors).not.toContain("loses nothing");
    expect(errors).not.toContain("is revoked on");
  });

  it("合図の後: 同期できないプロジェクトは「not registered yet」に混ぜず、一覧の失敗では 0 を数えない(K13-3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    const down = await buildChain([{ actor: reserve, operation: genesisOp(reserve) }]);
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      brokenProjects: [{ built: down, mode: "unavailable" }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.logs.join("\n")).toContain(
      "Approved: this device is registered on 1 project (verified on each project's chain)",
    );
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Note: ${down.projectId}: could not sync this project (`);
    expect(errors).toContain(
      "so whether this key is registered there is unknown; `maruhi device list` checks again",
    );
    expect(errors).not.toContain("not registered yet");
    expect(errors).not.toContain("Warning:");
    // 生きた要求の再開は要求を作らない(窓を消費しない — 穴 5 の経路も無い)
    expect(requestPosts(state)).toEqual([]);

    const listDown = await makeServer({
      built,
      withEnvironment: false,
      registryRows: [registryRowOf(dev2)],
      pendingRequests: [requestRowOf(dev2)],
      projectsStatus: 500,
    });
    const env2 = await startEnv(listDown.server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env2.layer), env2.errors.join("\n")).toBe(0);
    const logs2 = env2.logs.join("\n");
    expect(logs2).toContain(
      "Approved: the approving device gave the completion signal (this device is listed in your device registry)",
    );
    expect(logs2).not.toContain("registered on 0 projects");
    expect(env2.errors.join("\n")).toContain("Note: your projects could not be listed (");
  });

  it("期限切れには、承認側の出力の条件を保ったまま、この時点のチェーンの事実を足す(K13-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(dev2) },
    ]);
    // 登録簿の行は無い(T3 — 承認側の PUT が落ちた)まま、要求は期限切れ
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      pendingRequests: [{ ...requestRowOf(dev2), expiresAtMs: Date.now() - 1 }],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    const expired = env.errors.join("\n");
    expect(expired).toContain(
      "If it registered this device but could not list it in your device registry, keep this key",
    );
    expect(expired).toContain(
      `On the project chains right now, this key is registered on ${built.projectId} — keep it; re-running \`maruhi device add\` on this machine confirms that without a new request`,
    );
  });

  it("--replace は要求の作成が失敗(上限・満杯)すれば何も置き換えず、古い鍵が残る(K13-8)", async () => {
    for (const reason of ["add-requests", "device-rows"] as const) {
      const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
      const { server } = await makeServer({
        built,
        withEnvironment: false,
        extra: [
          onRequest("POST", "/auth/devices/requests", () => ({
            status: 429,
            json: {
              _tag: "DeviceRegistryLimit",
              reason,
              limit: reason === "add-requests" ? 5 : 32,
            },
          })),
        ],
      });
      const env = await startEnv(server.origin, built.projectId, owner);
      const entry = masterKeyEntryName(server.origin, owner.userId);
      const before = env.keychain.get(entry);
      expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
      expect(env.keychain.get(entry), reason).toBe(before);
      const errors = env.errors.join("\n");
      expect(errors).toContain(
        "nothing was replaced: the previous key is still in this machine's keychain (--replace replaces it only once the new key's request exists)",
      );
      expect(errors).not.toContain("replaced the previous key in this machine's keychain");
      expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    }
  });

  it("鍵の無い端末も「生成 → 要求 → 保存」の順: 要求が失敗すれば鍵を残さない(K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => ({
          status: 429,
          json: { _tag: "DeviceRegistryLimit", reason: "add-requests", limit: 5 },
        })),
      ],
    });
    const env = await startEnvWithoutKey(server.origin, built.projectId);
    expect(await runCli(["device", "add"], env.layer)).toBe(1);
    expect(env.keychain.get(masterKeyEntryName(server.origin, owner.userId))).toBeUndefined();
    expect(env.errors.join("\n")).not.toContain("nothing was replaced");
  });

  it("ガードつき差し替えは、要求の作成の間に別のプロセスが書いた鍵を上書きせず、FP も出さない(K13-8)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let env: TestEnv | null = null;
    let entry = "";
    // 別のプロセスが書いた値(ガードは値の一致だけを見る)
    const intruder = "written-by-another-process";
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
        onRequest("POST", "/auth/devices/requests", () => {
          // 要求の作成の間に別のプロセスがキーチェーンを書き換える
          env?.keychain.set(entry, intruder);
          return { status: 200, json: { expiresAtMs: FAR_FUTURE_MS } };
        }),
      ],
    });
    env = await startEnv(server.origin, built.projectId, owner);
    entry = masterKeyEntryName(server.origin, owner.userId);
    expect(await runCli(["device", "add", "--replace"], env.layer)).toBe(1);
    expect(env.keychain.get(entry)).toBe(intruder);
    expect(env.errors.join("\n")).toContain(
      "Another process changed this machine's device key while `maruhi device add --replace` was running, so the new key was not stored and the key now in the keychain was left as it is",
    );
    expect(env.logs.join("\n")).not.toContain("This device's key fingerprint:");
    expect(env.errors.join("\n")).not.toContain(
      "replaced the previous key in this machine's keychain",
    );
  });
});

describe("失効した鍵の普段のコマンドと device list(DK K13-5 / K13-6)", () => {
  /** P1 で失効・P2 で有効(一部のプロジェクトだけの失効)。手元の鍵は dev2。 */
  async function partlyRevoked(): Promise<{
    readonly env: TestEnv;
    readonly p1: BuiltChain;
    readonly p2: BuiltChain;
  }> {
    const p1 = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek) },
      { actor: owner, operation: addDeviceOp(dev2) },
      { actor: owner, operation: revokeDeviceOp(owner, [dev2]) },
    ]);
    const p2 = await buildChain([
      { actor: reserve, operation: genesisOp(reserve) },
      { actor: reserve, operation: addDeviceOp(dev2) },
    ]);
    const { server } = await makeServer({ built: p1, withEnvironment: true, extraProjects: [p2] });
    const env = await startEnv(server.origin, p1.projectId, dev2);
    return { env, p1, p2 };
  }

  it("このプロジェクトで失効した鍵は、未登録の経路でなく足し直し(新しい鍵)と残りのプロジェクトの後始末を言う", async () => {
    const { env } = await partlyRevoked();
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `The key on this machine (${dev2.fingerprintHex}) was revoked on this project's chain (member ${owner.userId}), and a revoked key is never registered again. To use this machine here again, run \`maruhi device add --replace\` on this machine (a revoked key is never registered again, so it generates a new key) and approve the fingerprint it prints from a registered device. If this key is still registered on other projects of yours, revoke it there once the new key is approved (\`maruhi device list\` shows where it is still registered)`,
    );
    expect(errors).not.toContain("has not been registered here yet");
    expect(errors).not.toContain("If `maruhi device add` is still waiting on this machine");
  });

  it("失効していない未登録の鍵は従来の経路で、偽の選択肢「or it was revoked」を言わない", async () => {
    const built = await chainWithEnvironment();
    const { server } = await makeServer({ built, withEnvironment: true });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["pull", "--env", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "is not one of your active device keys on this project's chain (member user-owner-0001). This device has not been registered here yet. If `maruhi device add` is still waiting on this machine",
    );
    expect(errors).not.toContain("or it was revoked");
    expect(errors).not.toContain("was revoked on this project's chain");
  });

  it("device list は失効したプロジェクトを行で示し、委ねた問い(どこに残っているか)に答える", async () => {
    const { env, p1, p2 } = await partlyRevoked();
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`${dev2.fingerprintHex}\tthis machine`);
    expect(logs).toContain(`  ${p1.projectId}: revoked (a revoked key is never registered again)`);
    expect(logs).toContain(
      `  ${p2.projectId}: cap=owner/all seq=2 added by ${reserve.fingerprintHex}`,
    );
  });

  it("device list はどのチェーンにも無いこの端末の鍵も出し、--project では表示した範囲を言う", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({ built, withEnvironment: false });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (not on any synced project chain)`,
    );
    env.logs.length = 0;
    expect(
      await runCli(["device", "list", "--project", built.projectId], env.layer),
      env.errors.join("\n"),
    ).toBe(0);
    expect(env.logs.join("\n")).toContain(
      `${dev2.fingerprintHex}\tthis machine\n  (not on the chain of project ${built.projectId}, the only project shown)`,
    );
  });

  it("device list はプロジェクト一覧が取れなくても落ちず、登録簿と記録を出す", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const { server } = await makeServer({
      built,
      withEnvironment: false,
      projectsStatus: 500,
      registryRows: [registryRowOf(dev2)],
    });
    const env = await startEnv(server.origin, built.projectId, dev2);
    expect(await runCli(["device", "list"], env.layer), env.errors.join("\n")).toBe(0);
    expect(env.errors.join("\n")).toContain("Note: your projects could not be listed (");
    expect(env.logs.join("\n")).toContain(
      `${dev2.fingerprintHex}\tthis machine, label "laptop" (server-reported)`,
    );
  });
});

/**
 * 予備鍵 rotate の足場: 前回が台帳の差し替えで中断した状態(台帳は N1 = reserve、元の予備鍵
 * O = dev2 は記録に revoked の印、チェーンには O も N1 も載っている)。
 */
async function reserveRotateFixture(options: {
  readonly withEnvironment: boolean;
  readonly dekRegisterStatus?: number;
  /** 旧予備鍵(dev2 / reserve)をチェーンに載せるか(既定 true。false = 失効も掃除も起きない)。 */
  readonly retiringOnChain?: boolean;
}): Promise<{
  readonly env: TestEnv;
  readonly state: ServerState;
  readonly origin: string;
  readonly ledgerPuts: unknown[];
  readonly built: BuiltChain;
}> {
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    ...(options.withEnvironment
      ? [{ actor: owner, operation: createEnvironmentOp(ENV_ID, dek) }]
      : []),
    ...(options.retiringOnChain === false
      ? []
      : [
          { actor: owner, operation: addDeviceOp(dev2) },
          { actor: owner, operation: addDeviceOp(reserve) },
        ]),
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
    withEnvironment: options.withEnvironment,
    ...(options.dekRegisterStatus === undefined
      ? {}
      : { dekRegisterStatus: options.dekRegisterStatus }),
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
  return { env, state, origin: server.origin, ledgerPuts, built };
}

describe("maruhi key reserve rotate(再実行 — Bugbot 指摘)", () => {
  it("前回が台帳の差し替えで中断していても、記録上の旧予備鍵をまとめて失効させる", async () => {
    // 前回の中断: 台帳は N1(= reserve)に差し替わり、元の予備鍵 O(= dev2)は記録に
    // revoked の印が付いたが、チェーンにはまだ O も N1 も載っている(環境は無し —
    // 失効後の掃除〔rotate〕はここでは見ない)
    const { env, state, origin, ledgerPuts } = await reserveRotateFixture({
      withEnvironment: false,
    });
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
      `revoking the previous reserve keys ${[dev2.fingerprintHex, reserve.fingerprintHex].toSorted().join(", ")} on every project`,
    );
    // ローカル記録: O と N1 は失効、新鍵だけが有効な予備鍵
    const recorded = await readOwnDevices(env, origin);
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

  it("新しい予備鍵へのバックフィルの失敗を報告し、pull の経路を名指す(DK K11 の G9)", async () => {
    // 旧予備鍵をチェーンに載せない = 失効も失効後の掃除(rotate)も起きない。終了コードは
    // バックフィルの失敗だけで決まる(承認・復元と同じく 1 — K11-14 の所有者裁定)
    const { env, built } = await reserveRotateFixture({
      withEnvironment: true,
      dekRegisterStatus: 500,
      retiringOnChain: false,
    });
    expect(await runCli(["key", "reserve", "rotate"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      `${built.projectId}: backfill of environment ${ENV_ID} to the new reserve key failed (`,
    );
    expect(errors).toContain(
      `fills the missing epochs when it runs \`maruhi pull --project ${built.projectId} --env ${ENV_ID}\``,
    );
  });
});

describe("maruhi key recovery --replace(台帳を開かずに置換 — K4-38)", () => {
  it("記録にある旧予備鍵を各プロジェクトで失効させ、新予備鍵を登録する", async () => {
    // チェーン: owner の端末 + 旧予備鍵(reserve)。台帳は開けない(コード紛失)
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addDeviceOp(reserve) },
    ]);
    const ledgerPuts: unknown[] = [];
    const { server, state } = await makeServer({
      built,
      withEnvironment: false,
      extra: [
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
    await recordOwnDevice(env, server.origin, reserve, "reserve");
    env.setPromptResponses([
      () => {
        const line = env.errors.find((entry) => /^ {4}[A-Z2-7]{4}(-[A-Z2-7]{4}){12}$/.test(entry));
        const groups = (line ?? "").trim().split("-");
        return groups[groups.length - 1] ?? "";
      },
    ]);
    expect(await runCli(["key", "recovery", "--replace"], env.layer), env.errors.join("\n")).toBe(
      0,
    );
    // 台帳は読まずに差し替える
    expect(state.paths()).not.toContain("GET /auth/recovery");
    expect(ledgerPuts).toHaveLength(1);
    // 新予備鍵の add_device と旧予備鍵の revoke_device
    expect(state.appended.map((entry) => entry.op)).toEqual(["add_device", "revoke_device"]);
    expect(state.appended[1]?.payload).toEqual({
      targetUserId: owner.userId,
      deviceFingerprintsHex: [reserve.fingerprintHex],
    });
    // 記録: 旧予備鍵は失効、新予備鍵だけが有効
    const recorded = await readOwnDevices(env, server.origin);
    expect(
      recorded.find((row) => row.keyFingerprintHex === reserve.fingerprintHex)?.revokedAtMs,
    ).not.toBeNull();
    const active = recorded.filter((row) => row.source === "reserve" && row.revokedAtMs === null);
    expect(active).toHaveLength(1);
    expect(active[0]?.keyFingerprintHex).not.toBe(reserve.fingerprintHex);
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
