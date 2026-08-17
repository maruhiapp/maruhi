// `maruhi server grant`(CRYPTO_SPEC §9 / AUTH_SPEC §12-6 — Wave 2 A1)の統合テスト。
// サーバー鍵確認の儀式・grant_server 追記(4 フィールド payload)・全環境 ×
// 全エポックのバックフィル・中断復旧(409 = 登録済み)を wire レベルで固定する。

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeServerKeyFingerprint,
  encodeHex,
  fingerprintToWords,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  buildChain,
  createEnvironmentOp,
  genesisOp,
  makeTestUser,
  rotateEpochOp,
  type TestUser,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

// デプロイメントのサーバー鍵(公開面のみ — grant はサーバー秘密鍵を要しない)
const SERVER_ENC_PUB_HEX = "5a".repeat(32);
let serverFpHex: string;
let serverFpWords: readonly string[];

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const fp = await computeServerKeyFingerprint(Uint8Array.from({ length: 32 }, () => 0x5a));
  if (!fp.ok) throw new Error("server fingerprint failed");
  serverFpHex = encodeHex(fp.value);
  const words = await fingerprintToWords(fp.value);
  if (!words.ok) throw new Error("server fingerprint words failed");
  serverFpWords = words.value;
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface GrantServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly registerBodies: { readonly environmentId: string; readonly deks: readonly unknown[] }[];
  readonly registerResponder: {
    respond:
      | ((body: { readonly deks: readonly unknown[] }) => { status: number; json: unknown } | null)
      | null;
  };
}

/**
 * grant フロー用の状態つきモック: チェーン(追記受理)・/auth/config・
 * 環境ごとの listMine(自分宛ラップ)・deks 登録(捕捉 + 応答差し替え)。
 */
async function makeGrantServer(input: {
  readonly built: Awaited<ReturnType<typeof buildChain>>;
  readonly deksByEnvironment: Readonly<
    Record<string, readonly Awaited<ReturnType<typeof wrapDekFor>>[]>
  >;
  readonly authConfig?: Record<string, unknown>;
}): Promise<GrantServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const registerBodies: GrantServerState["registerBodies"] = [];
  const registerResponder: GrantServerState["registerResponder"] = { respond: null };

  const handlers: MockHandler[] = [
    onRequest("GET", "/auth/config", () => ({
      status: 200,
      json: input.authConfig ?? {
        githubClientId: "dummy-client-id",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: SERVER_ENC_PUB_HEX,
      },
    })),
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
      },
    })),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    (request) => {
      const match = /^\/projects\/[^/]+\/environments\/([^/]+)\/deks$/.exec(request.path);
      if (match === null) {
        return null;
      }
      const environmentId = match[1] ?? "";
      if (request.method === "GET") {
        return {
          status: 200,
          json: { deks: input.deksByEnvironment[environmentId] ?? [] },
        };
      }
      if (request.method === "POST") {
        const body = request.body as { readonly deks: readonly unknown[] };
        registerBodies.push({ environmentId, deks: body.deks });
        const injected = registerResponder.respond?.(body);
        return injected ?? { status: 204, json: undefined };
      }
      return null;
    },
  ];
  return { handlers, appendedEntries, registerBodies, registerResponder };
}

async function startGrantEnv(
  state: GrantServerState,
  projectId: string,
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

/** 正規チェーン: create(epoch 1)→ rotate(epoch 2)。バックフィル対象 2 エポック。 */
async function builtWithTwoEpochs() {
  return buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
}

async function ownWraps(projectId: string) {
  const common = { projectId, environmentId: ENV_ID, recipient: owner, signer: owner };
  return [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1 }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2 }),
  ];
}

describe("maruhi server grant", () => {
  it("儀式(--expect-fingerprint)→ grant_server 追記(4 フィールド)→ 全エポックのバックフィルを行う", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(0);

    // 追記された grant_server payload(§6.2 の 4 フィールド構造化形)
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.serverEncPubHex).toBe(SERVER_ENC_PUB_HEX);
    expect(entry.payload.serverKeyFingerprintHex).toBe(serverFpHex);
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID]);
    expect(entry.payload.leasePolicy).toEqual([]);

    // バックフィル: 全エポック(1・2)のサーバー宛ラップを 1 リクエストで登録
    expect(state.registerBodies).toHaveLength(1);
    const wraps = state.registerBodies[0]?.deks as readonly {
      recipientClass?: string;
      recipientUserId: string;
      recipientEncPubHex: string;
      epoch: number;
    }[];
    expect(wraps.map((wrap) => wrap.epoch)).toEqual([1, 2]);
    expect(wraps.every((wrap) => wrap.recipientClass === "server")).toBe(true);
    expect(wraps.every((wrap) => wrap.recipientUserId === serverFpHex)).toBe(true);
    expect(wraps.every((wrap) => wrap.recipientEncPubHex === SERVER_ENC_PUB_HEX)).toBe(true);

    const logs = env.logs.join("\n");
    expect(logs).toContain("Backfill: 2 newly registered, 0 already registered");
    // §9: 開示中の常時明示 + ワード表示
    expect(logs).toContain("disclosed to the server");
    expect(logs).toContain(serverFpWords[11] ?? "");
  });

  it("中断復旧: 同一内容の有効 grant があれば追記せず、409 をエポック単位の登録済みとして収束する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      {
        actor: owner,
        operation: {
          op: "grant_server",
          payload: {
            serverEncPubHex: SERVER_ENC_PUB_HEX,
            serverKeyFingerprintHex: serverFpHex,
            scopeEnvironmentIds: [ENV_ID],
            leasePolicy: [],
          },
        },
      },
    ]);
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    // epoch 1 は登録済み(中断した前回実行の途中状態): 一括は 409、単発は
    // epoch 1 だけ 409
    state.registerResponder.respond = (body) => {
      const epochs = (body.deks as readonly { epoch: number }[]).map((wrap) => wrap.epoch);
      if (epochs.includes(1)) {
        return {
          status: 409,
          json: { _tag: "DekWrapExists", epoch: 1, recipientUserId: serverFpHex },
        };
      }
      return null;
    };
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(0);
    // 追記なし(同一内容)・一括 409 → エポック単位 2 リクエスト
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.deks.length)).toEqual([2, 1, 1]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("skipping the chain append");
    expect(logs).toContain("Backfill: 1 newly registered, 1 already registered");
  });

  it("対話の儀式: 12 語の最終語の再入力で確認する(誤入力 3 回で中止・追記なし)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    env.setPromptResponses([serverFpWords[11] ?? ""]);
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);

    // 誤入力 3 回 → 中止(追記なし)
    const state2 = await makeGrantServer({
      built: await builtWithTwoEpochs(),
      deksByEnvironment: {},
    });
    const env2 = await startGrantEnv(state2, built.projectId, owner);
    env2.setPromptResponses(["wrong", "wrong", "wrong"]);
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env2.layer)).toBe(1);
    expect(state2.appendedEntries).toHaveLength(0);
    expect(env2.errors.join("\n")).toContain("Server key fingerprint confirmation failed");
  });

  it("--expect-fingerprint の不一致は儀式で中止する(追記なし)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    const wrongFp = `${serverFpHex.slice(0, 31)}${serverFpHex[31] === "0" ? "1" : "0"}`;
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", wrongFp],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "--expect-fingerprint does not match the fingerprint of the server-provided key",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("AI エージェント環境では対話の儀式を拒否する(--expect-fingerprint を案内)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["server", "grant", "--environments", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--expect-fingerprint");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("サーバー鍵未設定(/auth/config にフィールドなし)は SELF_HOSTING を案内する", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {},
      authConfig: { githubClientId: "dummy-client-id" },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("SELF_HOSTING");
  });

  it("/auth/config の FP と enc 公開鍵の再計算 FP が一致しなければ中止する(儀式の前提の自己整合)", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {},
      // FP は本物・enc 公開鍵は別物: 悪意あるサーバーが「利用者が控えで確認済みの
      // FP」に任意の鍵を組み合わせる形。再計算照合が落とさなければ儀式が無意味になる
      authConfig: {
        githubClientId: "dummy-client-id",
        serverKeyFingerprintHex: serverFpHex,
        serverEncPubHex: "5b".repeat(32),
      },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "The server-provided enc public key does not match serverKeyFingerprintHex",
    );
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
  });

  it("複数環境のスコープは全環境 × 全エポックをバックフィルする", async () => {
    const ENV_B = "env-app-2";
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
    ]);
    const common = { projectId: built.projectId, recipient: owner, signer: owner };
    const state = await makeGrantServer({
      built,
      deksByEnvironment: {
        [ENV_ID]: [await wrapDekFor({ ...common, environmentId: ENV_ID, epoch: 1, dek: dek1 })],
        [ENV_B]: [await wrapDekFor({ ...common, environmentId: ENV_B, epoch: 1, dek: dekB })],
      },
    });
    const env = await startGrantEnv(state, built.projectId, owner);

    expect(
      await runCli(
        [
          "server",
          "grant",
          "--environments",
          `${ENV_ID},${ENV_B}`,
          "--expect-fingerprint",
          serverFpHex,
        ],
        env.layer,
      ),
    ).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID, ENV_B]);

    // 環境ごとに 1 リクエスト × 各 1 エポックのサーバー宛ラップ
    const byEnvironment = new Map(
      state.registerBodies.map((body) => [body.environmentId, body.deks]),
    );
    expect([...byEnvironment.keys()].toSorted()).toEqual([ENV_ID, ENV_B]);
    for (const deks of byEnvironment.values()) {
      const wraps = deks as readonly { recipientClass?: string; recipientUserId: string }[];
      expect(wraps).toHaveLength(1);
      expect(wraps[0]?.recipientClass).toBe("server");
      expect(wraps[0]?.recipientUserId).toBe(serverFpHex);
    }
    expect(env.logs.join("\n")).toContain("Backfill: 2 newly registered, 0 already registered");
  });

  it("owner 以外は拒否する(§6.2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      {
        actor: owner,
        operation: {
          op: "add_member",
          payload: {
            targetUserId: member.userId,
            encPubHex: member.encPubHex,
            sigPubHex: member.sigPubHex,
            role: "member",
          },
        },
      },
      { actor: member, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, member);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("Only an owner can run grant_server");
  });

  it("再 grant のスコープ縮小は revoke を案内して拒否する(二層規則 — §6.3)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      {
        actor: owner,
        operation: createEnvironmentOp("env-two-2", crypto.getRandomValues(new Uint8Array(32))),
      },
      {
        actor: owner,
        operation: {
          op: "grant_server",
          payload: {
            serverEncPubHex: SERVER_ENC_PUB_HEX,
            serverKeyFingerprintHex: serverFpHex,
            scopeEnvironmentIds: [ENV_ID, "env-two-2"],
            leasePolicy: [],
          },
        },
      },
    ]);
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--expect-fingerprint", serverFpHex],
        env.layer,
      ),
    ).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("The disclosure scope can only grow");
    expect(errors).toContain("env-two-2");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--lease-policy の JSON を正規化(制約の昇順ソート)して payload に載せる", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({
      built,
      deksByEnvironment: { [ENV_ID]: await ownWraps(built.projectId) },
    });
    const env = await startGrantEnv(state, built.projectId, owner);
    const policyPath = join(dirname(env.configPath), "lease-policy.json");
    await mkdir(dirname(policyPath), { recursive: true });
    await writeFile(
      policyPath,
      JSON.stringify([
        {
          issuerUrl: "https://token.actions.githubusercontent.com",
          audience: "https://maruhi.example.com",
          // 書いた順(repository → ref)に依らずコードポイント昇順で正規化される
          claimConstraints: { repository: "acme-dummy/app", ref: "refs/heads/main" },
        },
      ]),
    );

    expect(
      await runCli(
        [
          "server",
          "grant",
          "--environments",
          ENV_ID,
          "--lease-policy",
          policyPath,
          "--expect-fingerprint",
          serverFpHex,
        ],
        env.layer,
      ),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "grant_server") throw new Error("grant entry missing");
    expect(entry.payload.leasePolicy).toEqual([
      {
        issuerUrl: "https://token.actions.githubusercontent.com",
        audience: "https://maruhi.example.com",
        claimConstraints: [
          { claimName: "ref", claimValue: "refs/heads/main" },
          { claimName: "repository", claimValue: "acme-dummy/app" },
        ],
      },
    ]);
    expect(env.logs.join("\n")).toContain("lease_policy has 1 elements");
  });

  it("--environments は必須(最小開示の既定)・不正な JSON ファイルは usage エラー", async () => {
    const built = await builtWithTwoEpochs();
    const state = await makeGrantServer({ built, deksByEnvironment: {} });
    const env = await startGrantEnv(state, built.projectId, owner);
    expect(await runCli(["server", "grant"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("grant requires --environments");

    const badPath = join(dirname(env.configPath), "bad-policy.json");
    await mkdir(dirname(badPath), { recursive: true });
    await writeFile(badPath, "{ not json");
    expect(
      await runCli(
        ["server", "grant", "--environments", ENV_ID, "--lease-policy", badPath],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--lease-policy content is invalid: not valid JSON");
  });
});
