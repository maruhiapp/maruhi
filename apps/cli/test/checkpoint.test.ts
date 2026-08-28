// 周期チェックポイントの発行(`maruhi project checkpoint` — CRYPTO_SPEC §6.3 /
// AUTH_SPEC §16-2。2026-08-28 PR-M2)のテスト。
//
// 検証の柱:
//  1. 構築: 検証済みビュー(検証済み pull)からタプルを組み立てる — 環境 ID の
//     バイト昇順、マニフェスト参照 = 検証済みマニフェストの自計算ハッシュ、
//     values_digest = 検証済み値の自計算ハッシュ(サーバー申告値を署名しない)
//  2. 監査ヘッドの公証: 実効権限 admin(チェーン role × /auth/me の tokenScopes)
//     の事前判定 — admin 未満・write スコープでは GET /audit-head を**呼ばない**
//     (403 を踏まない — §16-2)
//  3. 再試行: 422(CheckpointStateMismatch)はビューの再取得 + 申告の取り直しで
//     有界再試行し、使い切ったら安定部分集合で 1 回だけ発行(§6.3 の退避)。
//     409(CAS)は再同期 + 再署名
//  4. 受理後照合(§12-10 (3)): 2xx でもチェーン同期で自エントリを確認できなければ
//     成功と報告しない

import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeEnvValuesDigest,
  signChainEntry,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect } from "effect";
import { FetchHttpClient } from "effect/unstable/http";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { makeApiClient } from "../src/api.ts";
import { checkpointProposal } from "../src/checkpoint.ts";
import { runCli } from "../src/cli.ts";
import { verifyChainSnapshot } from "../src/sync.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  statementFor,
  type TestUser,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, type MockResponse, onRequest } from "./support/server.ts";

// バイト昇順の判別対(alpha < dev)
const ENV_A = "alpha";
const ENV_B = "dev";

let owner: TestUser;
let member: TestUser;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-3333");
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

interface MockEnvironment {
  readonly environmentId: string;
  statement: WireDistributedEnvironmentStatement;
  manifest: WireDistributedManifest;
  variables: {
    readonly variableId: string;
    readonly statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  /** pull ごとに value を差し替える(部分集合退避テストの「忙しい環境」)。 */
  nextValues?: WireDistributedValue[];
}

interface CheckpointServerOptions {
  readonly built: BuiltChain;
  readonly environments: MockEnvironment[];
  readonly me: { readonly userId: string; readonly tokenScopes?: readonly unknown[] };
  readonly auditHeadHashHex?: string;
  /** audit-head 呼び出しごとの差し込み(undefined = 200 で申告を返す)。 */
  readonly onAuditHead?: (call: number) => MockResponse | undefined;
  /** append 呼び出しごとの差し込み(undefined = 受理して追記)。 */
  readonly onAppend?: (call: number, body: AppendBody) => MockResponse | undefined;
  /** 受理してもチェーンへ追記しない(虚偽 2xx サーバー — §12-10 (3) の検査)。 */
  readonly acceptWithoutAppending?: boolean;
}

interface AppendBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & { readonly op: "checkpoint" };
}

interface CheckpointServerState {
  readonly handlers: readonly MockHandler[];
  readonly appends: AppendBody[];
  readonly auditHeadCalls: () => number;
  readonly entries: ChainEntry[];
}

/** 発行フローに要る全エンドポイントを持つモック(受理エントリはチェーンへ反映)。 */
function makeCheckpointServer(options: CheckpointServerOptions): CheckpointServerState {
  const projectId = options.built.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const appends: AppendBody[] = [];
  let appendCalls = 0;
  let auditHeadCalls = 0;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: { projectId, entries, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: options.environments.map((environment) => ({
          environmentId: environment.environmentId,
          currentEpoch: 1,
          statement: environment.statement,
        })),
      },
    })),
    onRequest("GET", "/auth/me", () => ({
      status: 200,
      json: {
        userId: options.me.userId,
        orgs: [],
        ...(options.me.tokenScopes === undefined ? {} : { tokenScopes: options.me.tokenScopes }),
      },
    })),
    onRequest("GET", `/projects/${projectId}/audit-head`, () => {
      const injected = options.onAuditHead?.(auditHeadCalls);
      auditHeadCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      return { status: 200, json: { auditHeadHashHex: options.auditHeadHashHex ?? "" } };
    }),
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const body = request.body as AppendBody;
      appends.push(body);
      const injected = options.onAppend?.(appendCalls, body);
      appendCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      if (options.acceptWithoutAppending !== true) {
        entries.push(body.entry);
        hashes.push(await computeChainEntryHash(body.entry));
      }
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    // 環境ごとの pull(値付き — §12-7)
    ...options.environments.map((environment): MockHandler => (request) => {
      if (
        request.method !== "GET" ||
        request.path !== `/projects/${projectId}/environments/${environment.environmentId}/pull`
      ) {
        return null;
      }
      const next = environment.nextValues?.shift();
      if (next !== undefined && environment.variables[0] !== undefined) {
        environment.variables[0].value = next;
      }
      return {
        status: 200,
        json: {
          environmentId: environment.environmentId,
          currentEpoch: 1,
          statement: environment.statement,
          variables: environment.variables.map((variable) => ({
            variableId: variable.variableId,
            statement: variable.statement,
            value: variable.value,
          })),
          deletedVariables: [],
          deks: [],
          manifest: environment.manifest,
        },
      };
    }),
  ];
  return { handlers, appends, auditHeadCalls: () => auditHeadCalls, entries };
}

/** 1 環境ぶんのフィクスチャ(変数 1 本 + マニフェスト)。 */
async function makeEnvironment(input: {
  readonly built: BuiltChain;
  readonly environmentId: string;
  readonly dek: Uint8Array;
  readonly headSeq: number;
  readonly issuer: TestUser;
  readonly variableId: string;
}): Promise<MockEnvironment> {
  const head = headOf(input.built, input.headSeq);
  const statement = await environmentStatementFor({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    name: input.environmentId,
    author: input.issuer,
    head,
  });
  const variableStatement = await statementFor({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    variableId: input.variableId,
    name: `VAR_${input.environmentId.toUpperCase()}`,
    author: input.issuer,
    head,
  });
  const value = await encryptValueFor({
    dek: input.dek,
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    epoch: 1,
    variableId: input.variableId,
    version: 1,
    plaintext: "secret-alpha",
    writer: input.issuer,
    head,
  });
  const manifest = await manifestFor({
    projectId: input.built.projectId,
    environmentId: input.environmentId,
    epoch: 1,
    issuer: input.issuer,
    head,
    envStatement: statement,
    statements: [variableStatement],
    manifestVersion: 1,
  });
  return {
    environmentId: input.environmentId,
    statement,
    manifest,
    variables: [{ variableId: input.variableId, statement: variableStatement, value }],
  };
}

async function seededEnv(server: MockServer, projectId: string, user: TestUser): Promise<TestEnv> {
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

async function expectedValuesDigest(environment: MockEnvironment): Promise<string> {
  const entries = await Promise.all(
    environment.variables.map(async (variable) => ({
      variableId: variable.variableId,
      version: variable.value.aad.version,
      valueSigHashHex: await valueHashOf(variable.value, variable.value.writerUserId),
    })),
  );
  const digest = await computeEnvValuesDigest(SUITE_ID, entries);
  if (!digest.ok) {
    throw new Error("digest failed");
  }
  return digest.value;
}

describe("maruhi project checkpoint(契機 (ii) — CRYPTO_SPEC §6.3 / AUTH_SPEC §16-2)", () => {
  it("検証済みビューからタプルを構築し、バイト昇順の全環境カバー + 監査ヘッド公証で発行する", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
    ]);
    const head = "ab".repeat(32);
    const environments = [
      // 意図的に降順で並べる(発行側の昇順正規化を判別する)
      await makeEnvironment({
        built,
        environmentId: ENV_B,
        dek: dekB,
        headSeq: 3,
        issuer: owner,
        variableId: "var-b",
      }),
      await makeEnvironment({
        built,
        environmentId: ENV_A,
        dek: dekA,
        headSeq: 3,
        issuer: owner,
        variableId: "var-a",
      }),
    ];
    const state = makeCheckpointServer({
      built,
      environments,
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: head,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(1);
    const entry = state.appends[0]!.entry;
    expect(entry.op).toBe("checkpoint");
    // バイト昇順(alpha < dev)・タプルは検証済みビューの自計算値
    expect(entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([ENV_A, ENV_B]);
    const tupleA = entry.payload.environments[0]!;
    expect(tupleA.epoch).toBe(1);
    expect(tupleA.manifestVersion).toBe(1);
    expect(tupleA.manifestSigHashHex).toBe(
      await manifestHashOf(built.projectId, environments[1]!.manifest),
    );
    expect(tupleA.valuesDigestHex).toBe(await expectedValuesDigest(environments[1]!));
    // 実効権限 admin: CAS 親確定後に取得した申告の公証
    expect(entry.payload.auditHeadHashHex).toBe(head);
    expect(state.auditHeadCalls()).toBe(1);
    expect(env.logs.join("\n")).toContain("Checkpoint accepted at chain seq 4");
    expect(env.logs.join("\n")).toContain("audit head attested");
  });

  it("member role は監査ヘッドを取得せず(403 を踏まない)、空文字列で発行する", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 3,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: { userId: member.userId },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, member);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends[0]!.entry.payload.auditHeadHashHex).toBe("");
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("admin role でも write スコープのトークンは公証しない(実効権限の min — §9-2)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "write" }],
      },
      auditHeadHashHex: "ab".repeat(32),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends[0]!.entry.payload.auditHeadHashHex).toBe("");
    expect(state.auditHeadCalls()).toBe(0);
  });

  it("422(CheckpointStateMismatch)はビューと申告を取り直して有界再試行する(§16-2)", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
      onAppend: (call) =>
        call === 0
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(2);
    // 監査ヘッド申告は試行ごとに取り直す(§16-2 の再試行)
    expect(state.auditHeadCalls()).toBe(2);
  });

  /** AuditHeadNotReady 再試行テストの共通フィクスチャ(admin の 1 環境発行)。 */
  async function makeNotReadyFixture(input: {
    readonly onAuditHead?: (call: number) => MockResponse | undefined;
    readonly onAppend?: (call: number, body: AppendBody) => MockResponse | undefined;
  }): Promise<{ state: CheckpointServerState; env: TestEnv }> {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "cd".repeat(32),
      ...(input.onAuditHead === undefined ? {} : { onAuditHead: input.onAuditHead }),
      ...(input.onAppend === undefined ? {} : { onAppend: input.onAppend }),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);
    return { state, env };
  }

  const NOT_READY: MockResponse = { status: 503, json: { _tag: "AuditHeadNotReady" } };

  it("申告取得の AuditHeadNotReady(503)は有界再試行で吸収する(進捗はサーバー側に保存)", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAuditHead: (call) => (call < 2 ? NOT_READY : undefined),
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    // 2 回の 503 を吸収して 3 回目の申告で発行(発行は 1 回)
    expect(state.auditHeadCalls()).toBe(3);
    expect(state.appends.length).toBe(1);
    expect(state.appends[0]!.entry.payload).toMatchObject({ auditHeadHashHex: "cd".repeat(32) });
    expect(env.logs.join("\n")).toContain("materializing the audit-head hash column");
  });

  it("受理段の AuditHeadNotReady(503)は申告を取り直して再送する", async () => {
    const { state, env } = await makeNotReadyFixture({
      onAppend: (call) => (call === 0 ? NOT_READY : undefined),
    });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    expect(state.appends.length).toBe(2);
    // 再送では申告も取り直す(サーバーの伸長は前進済み — AUDIT_SPEC §5.1)
    expect(state.auditHeadCalls()).toBe(2);
  });

  it("AuditHeadNotReady が枯渇したら、発生条件と再実行での解消を案内して失敗する", async () => {
    const { state, env } = await makeNotReadyFixture({ onAuditHead: () => NOT_READY });
    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    // 予算 10 回で打ち切り、発行には進まない
    expect(state.auditHeadCalls()).toBe(10);
    expect(state.appends.length).toBe(0);
    const output = env.errors.join("\n");
    expect(output).toContain("still materializing the audit-head hash column");
    expect(output).toContain("re-run the command to continue where it left off");
  });

  it("再試行を使い切ったら、直近 2 回の構築で不変だった環境の部分集合で発行する(§6.3 の退避)", async () => {
    const dekA = crypto.getRandomValues(new Uint8Array(32));
    const dekB = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dekA) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dekB) },
    ]);
    const stable = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek: dekA,
      headSeq: 3,
      issuer: owner,
      variableId: "var-a",
    });
    const busy = await makeEnvironment({
      built,
      environmentId: ENV_B,
      dek: dekB,
      headSeq: 3,
      issuer: owner,
      variableId: "var-b",
    });
    // ENV_B は pull のたびに version が前進する(並行 push のモデル化)。
    // prev は直前 version の自計算ハッシュへ連鎖させる(§4.1)
    const head = headOf(built, 3);
    const nextValues: WireDistributedValue[] = [];
    let previous = busy.variables[0]!.value;
    for (let version = 2; version <= 6; version += 1) {
      const value = await encryptValueFor({
        dek: dekB,
        projectId: built.projectId,
        environmentId: ENV_B,
        epoch: 1,
        variableId: "var-b",
        version,
        plaintext: `secret-v${version}`,
        writer: owner,
        head,
        prevValueSigHashHex: await valueHashOf(previous, owner.userId),
      });
      nextValues.push(value);
      previous = value;
    }
    busy.nextValues = nextValues;
    const state = makeCheckpointServer({
      built,
      environments: [stable, busy],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      auditHeadHashHex: "ab".repeat(32),
      // ENV_B を含む発行は常に 422(受理時点一致が収束しない忙しい環境)
      onAppend: (_call, body) =>
        body.entry.payload.environments.some((tuple) => tuple.environmentId === ENV_B)
          ? {
              status: 422,
              json: { _tag: "CheckpointStateMismatch", reason: "values-digest-mismatch" },
            }
          : undefined,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(0);
    const finalAppend = state.appends[state.appends.length - 1]!;
    expect(finalAppend.entry.payload.environments.map((tuple) => tuple.environmentId)).toEqual([
      ENV_A,
    ]);
    const output = [...env.logs, ...env.errors].join("\n");
    expect(output).toContain("partial checkpoint");
    expect(output).toContain(ENV_B);
  });

  it("契機 (iii) の提案(checkpointProposal): 基準の有無・鮮度・実効権限別の基準で分岐する", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    // buildChain の timestamp は決定的な過去時刻 — チェーン上の checkpoint は
    // すべて「7 日超経過」側に落ちる。新しい基準は手署名の checkpoint
    // (timestampMs = now)を積んで作る
    const base = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const verifiedOf = (built: BuiltChain) =>
      Effect.runPromise(
        verifyChainSnapshot({
          projectId: base.projectId as never,
          entries: built.entries,
          claimedHeadSeq: built.entries.length,
          claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
        }),
      );
    const appendCheckpoint = async (
      built: BuiltChain,
      input: { readonly timestampMs: number; readonly auditHeadHashHex: string },
    ): Promise<BuiltChain> => {
      const signed = await signChainEntry({
        entry: {
          suite: SUITE_ID,
          seq: built.entries.length + 1,
          prevHashHex: built.hashes[built.hashes.length - 1] ?? "",
          op: "checkpoint",
          actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
          payload: { environments: [], auditHeadHashHex: input.auditHeadHashHex },
          timestampMs: input.timestampMs,
        },
        signingKey: owner.sigKeyPair.privateKey,
      });
      if (!signed.ok) throw new Error("sign failed");
      return {
        ...built,
        entries: [...built.entries, signed.value],
        hashes: [...built.hashes, await computeChainEntryHash(signed.value)],
      };
    };
    // /auth/me だけを持つモック(admin の実効権限判定に使う)
    const state = makeCheckpointServer({
      built: base,
      environments: [],
      me: { userId: owner.userId, tokenScopes: [{ project: base.projectId, permission: "admin" }] },
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const client = await Effect.runPromise(
      makeApiClient({ baseUrl: server.origin }).pipe(Effect.provide(FetchHttpClient.layer)),
    );
    const propose = (built: BuiltChain, signerUserId: string) =>
      verifiedOf(built).then((verified) =>
        Effect.runPromise(
          checkpointProposal({ client, verified, signerUserId, nowMs: Date.now() }),
        ),
      );

    // member: 基準なし → 提案 / 新しい基準(公証なしで足りる)→ 提案なし
    expect(await propose(base, member.userId)).toContain("maruhi project checkpoint");
    const freshPlain = await appendCheckpoint(base, {
      timestampMs: Date.now(),
      auditHeadHashHex: "",
    });
    expect(await propose(freshPlain, member.userId)).toBeNull();
    // 実効権限 admin: 公証なしの新しい基準では満たされない(公証あり基準 —
    // 第 5 ラウンド: member の発行が admin の契機を潰さない)
    expect(await propose(freshPlain, owner.userId)).toContain("notarized audit prefix");
    // 新しい公証あり基準 → 提案なし
    const freshAttested = await appendCheckpoint(base, {
      timestampMs: Date.now(),
      auditHeadHashHex: "ab".repeat(32),
    });
    expect(await propose(freshAttested, owner.userId)).toBeNull();
  });

  it("2xx でも再同期したチェーンに自エントリが無ければ成功と報告しない(§12-10 (3))", async () => {
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek) },
    ]);
    const environment = await makeEnvironment({
      built,
      environmentId: ENV_A,
      dek,
      headSeq: 2,
      issuer: owner,
      variableId: "var-a",
    });
    const state = makeCheckpointServer({
      built,
      environments: [environment],
      me: {
        userId: owner.userId,
        tokenScopes: [{ project: built.projectId, permission: "admin" }],
      },
      acceptWithoutAppending: true,
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await seededEnv(server, built.projectId, owner);

    expect(await runCli(["project", "checkpoint"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain this checkpoint entry");
  });
});
