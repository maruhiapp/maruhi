// `maruhi ci run`(A3 — CRYPTO_SPEC §9.1 / AUTH_SPEC §14)のテスト。
//
// lease エンドポイントは MockServer 偽装(実 crypto フィクスチャで応答を組み、
// リクエストの ephemeralPubHex へ動的に wrapLeaseDek する)。OIDC 発行は
// MockServer の別パス(署名はダミー — クライアントは検証しない)、env 読みは
// テスト層の setEnvVar。サーバー側の判定は apps/server/test/lease.test.ts が
// 固定済みで、ここはクライアント挙動(§9.1 の検証義務・session-24 §8 の
// 再試行規律・エラー区分の案内)に集中する。

import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ChainEntry, LeaseClaims } from "@maruhi/crypto";
import {
  computeLeaseClaimsDigest,
  encodeHex,
  importEncryptionPublicKey,
  wrapLeaseDek,
} from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { OIDC_REQUEST_TOKEN_ENV, OIDC_REQUEST_URL_ENV } from "../src/oidc-github.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";
const ISSUER = "https://token.actions.githubusercontent.com";
const SUBJECT = "repo:acme/app:ref:refs/heads/main";
const RUNNER_TOKEN = "runner-request-token-value";

interface PullEntry {
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

interface Fixture {
  readonly owner: TestUser;
  readonly built: BuiltChain;
  readonly dek1: Uint8Array;
  readonly dek2: Uint8Array;
  readonly envStatement: WireDistributedEnvironmentStatement;
  readonly entryAlpha: PullEntry;
  readonly entryBeta: PullEntry;
}

let fixture: Fixture;
let servers: MockServer[] = [];

beforeAll(async () => {
  const owner = await makeTestUser("user-owner-1111");
  const dek1 = crypto.getRandomValues(new Uint8Array(32));
  const dek2 = crypto.getRandomValues(new Uint8Array(32));
  // チェーンには実 DEK のコミットメントと grant_server(リースポリシー付き)が
  // 載る — 本番のリース対象プロジェクトと同じ形(クライアントの §9.1 検証は
  // grant の有無を検査しないが、忠実なフィクスチャにしておく)
  const built = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    {
      actor: owner,
      operation: await grantServerOp(
        [ENV_ID],
        [{ issuerUrl: ISSUER, audience: "https://maruhi.example", claimConstraints: [] }],
      ),
    },
  ]);
  const common = { projectId: built.projectId, environmentId: ENV_ID };
  // 最新バージョンのエポックは変数ごとに異なる(§12-7 と同じ形): ALPHA は
  // epoch 2、BETA はローテーション後も再暗号化されていない epoch 1 のまま
  const valueAlpha = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 3,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(built, 3),
  });
  const valueBeta = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-value",
    writer: owner,
    head: headOf(built, 2),
  });
  const genesisHead = { seq: 1, hashHex: built.projectId };
  const envStatement = await environmentStatementFor({
    projectId: built.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  const entryAlpha = {
    variableId: "va",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "va",
      name: "ALPHA",
      author: owner,
      head: genesisHead,
    }),
    value: valueAlpha,
  };
  const entryBeta = {
    variableId: "vb",
    statement: await statementFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: genesisHead,
    }),
    value: valueBeta,
  };
  fixture = { owner, built, dek1, dek2, envStatement, entryAlpha, entryBeta };
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/* -------------------------------------------------------------------------- */
/* フィクスチャ: OIDC 発行と lease 応答                                        */
/* -------------------------------------------------------------------------- */

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/** ダミー署名の compact JWS(クライアントは署名を検証しない — §14-1)。 */
function fakeJwt(payload: Record<string, unknown>): string {
  return `${base64UrlJson({ alg: "RS256", kid: "k1" })}.${base64UrlJson(payload)}.c2lnbmF0dXJl`;
}

/** サーバーと同じ経路: 提示トークンの payload から claims を読む。 */
function jwtPayload(token: string): Record<string, unknown> {
  const segment = token.split(".")[1];
  if (segment === undefined) {
    throw new Error("not a compact JWS");
  }
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
}

interface OidcIssuance {
  /** 発行要求で指定された audience(検査用)。 */
  readonly audiences: string[];
  /** 発行済みトークン数(jti に埋める — リプレイ検査でトークンを区別する)。 */
  issued: number;
}

/** GitHub Actions の OIDC 発行エンドポイントの偽装(`{ value }` を返す)。 */
function oidcHandler(state: OidcIssuance): MockHandler {
  return (request) => {
    if (request.method !== "GET" || request.path !== "/oidc/token") {
      return null;
    }
    if (request.headers["authorization"] !== `Bearer ${RUNNER_TOKEN}`) {
      return { status: 401, json: { message: "bad runner token" } };
    }
    const audience = request.query["audience"] ?? "";
    state.audiences.push(audience);
    state.issued += 1;
    // sub を発行ごとに変える: claims_digest は iss / sub / aud のみを束縛する
    // ため、jti だけの違いでは「再試行後に古いトークンの claims を使い回す」
    // 実装がすり抜ける(digest が同じになる)。sub が変われば、正しい実装
    // (2 本目のトークンの claims で digest を計算)だけが開封に成功する
    return {
      status: 200,
      json: {
        value: fakeJwt({
          iss: ISSUER,
          sub: `${SUBJECT}/run/${state.issued}`,
          aud: audience,
          jti: state.issued,
        }),
      },
    };
  };
}

interface LeaseResponseOverrides {
  /** リースラップの束縛 claims の差し替え(別ジョブ文脈向けラップの転用形)。 */
  readonly claims?: Partial<LeaseClaims>;
  /** エポックごとの DEK の差し替え(毒ラップ = コミットメント不一致)。 */
  readonly dekForEpoch?: (epoch: number, dek: Uint8Array) => Uint8Array;
  readonly entries?: readonly ChainEntry[];
  readonly declaredProjectId?: string;
  readonly currentEpoch?: number;
  readonly variables?: readonly PullEntry[];
  /** 追加のリースラップ(重複エポック・チェーン外エポックの負例用)。 */
  readonly extraLeases?: readonly { readonly epoch: number; readonly dek: Uint8Array }[];
}

/** 提示トークンの claims(サーバーと同じ経路)+ 上書き(転用形の偽装用)。 */
async function leaseClaimsDigestOf(
  oidcToken: string,
  overrides?: LeaseResponseOverrides,
): Promise<string> {
  const payload = jwtPayload(oidcToken);
  const digest = await computeLeaseClaimsDigest({
    issuerUrl: overrides?.claims?.issuerUrl ?? String(payload["iss"]),
    subject: overrides?.claims?.subject ?? String(payload["sub"]),
    audience: overrides?.claims?.audience ?? String(payload["aud"]),
  });
  if (!digest.ok) {
    throw new Error("claims digest failed");
  }
  return digest.value;
}

/** 一時鍵への実 wrapLeaseDek(CRYPTO_SPEC §9.1 の info 構成)。 */
async function leaseWrapFor(input: {
  readonly ephemeralPubHex: string;
  readonly claimsDigestHex: string;
  readonly epoch: number;
  readonly dek: Uint8Array;
}): Promise<unknown> {
  const publicKey = await importEncryptionPublicKey(hexBytes(input.ephemeralPubHex));
  if (!publicKey.ok) {
    throw new Error("ephemeral public key rejected");
  }
  const wrapped = await wrapLeaseDek({
    workloadPublicKey: publicKey.value,
    dek: input.dek,
    context: {
      projectId: fixture.built.projectId,
      environmentId: ENV_ID,
      epoch: input.epoch,
      claimsDigestHex: input.claimsDigestHex,
    },
  });
  if (!wrapped.ok) {
    throw new Error("lease wrap failed");
  }
  return {
    suite: "maruhi/v1",
    epoch: input.epoch,
    encHex: encodeHex(wrapped.value.enc),
    ciphertextHex: encodeHex(wrapped.value.ciphertext),
  };
}

/** リクエストの一時鍵へ実 crypto でリースラップした応答(AUTH_SPEC §14-2)。 */
async function leaseResponseFor(
  body: { readonly oidcToken: string; readonly ephemeralPubHex: string },
  overrides?: LeaseResponseOverrides,
): Promise<unknown> {
  const { built, dek1, dek2, envStatement, entryAlpha, entryBeta } = fixture;
  const resolved = {
    declaredProjectId: built.projectId,
    currentEpoch: 2,
    entries: built.entries,
    variables: [entryAlpha, entryBeta] as readonly PullEntry[],
    dekForEpoch: (_epoch: number, dek: Uint8Array) => dek,
    extraLeases: [] as readonly { readonly epoch: number; readonly dek: Uint8Array }[],
    ...overrides,
  };
  const claimsDigestHex = await leaseClaimsDigestOf(body.oidcToken, overrides);
  const wrapFor = (epoch: number, dek: Uint8Array) =>
    leaseWrapFor({
      ephemeralPubHex: body.ephemeralPubHex,
      claimsDigestHex,
      epoch,
      dek: resolved.dekForEpoch(epoch, dek),
    });
  return {
    projectId: resolved.declaredProjectId,
    environmentId: ENV_ID,
    currentEpoch: resolved.currentEpoch,
    chain: resolved.entries,
    headSeq: resolved.entries.length,
    headHashHex: built.hashes[built.hashes.length - 1],
    statement: envStatement,
    variables: resolved.variables,
    deletedVariables: [],
    manifest: await manifestFor({
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: resolved.currentEpoch,
      issuer: fixture.owner,
      // 宣言ヘッドは申告エポックが現エポックである位置(create = 2、rotate = 3)
      head: headOf(built, resolved.currentEpoch === 1 ? 2 : 3),
      envStatement,
      statements: resolved.variables.map((entry) => entry.statement),
    }),
    leases: [
      await wrapFor(1, dek1),
      await wrapFor(2, dek2),
      ...(await Promise.all(resolved.extraLeases.map((extra) => wrapFor(extra.epoch, extra.dek)))),
    ],
  };
}

function leasePath(projectId?: string): string {
  return `/projects/${projectId ?? fixture.built.projectId}/environments/${ENV_ID}/lease`;
}

function leaseBody(request: MockRequest): { oidcToken: string; ephemeralPubHex: string } {
  return request.body as { oidcToken: string; ephemeralPubHex: string };
}

/** 正常応答の lease ハンドラ。 */
function leaseHandler(overrides?: LeaseResponseOverrides, projectId?: string): MockHandler {
  return async (request) => {
    if (request.method !== "POST" || request.path !== leasePath(projectId)) {
      return null;
    }
    return { status: 200, json: await leaseResponseFor(leaseBody(request), overrides) };
  };
}

/* -------------------------------------------------------------------------- */
/* テスト環境                                                                  */
/* -------------------------------------------------------------------------- */

interface CiEnv {
  readonly env: TestEnv;
  readonly server: MockServer;
  readonly oidc: OidcIssuance;
}

/**
 * CI 実行の環境: **ログインも config もシードしない**(CI モードのキーチェーン・
 * config 非依存はこの構成自体が固定する — 依存があればコマンドは失敗する)。
 */
async function startCiEnv(handlers: readonly MockHandler[]): Promise<CiEnv> {
  const oidc: OidcIssuance = { audiences: [], issued: 0 };
  const server = await MockServer.start([oidcHandler(oidc), ...handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  // ランナー供給の発行エンドポイント(既存クエリ付き = & 連結の分岐も踏む)
  env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/token?api-version=2`);
  env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, RUNNER_TOKEN);
  return { env, server, oidc };
}

function ciArgs(server: MockServer, extra: readonly string[] = []): string[] {
  return [
    "ci",
    "run",
    "--server",
    server.origin,
    "--project",
    fixture.built.projectId,
    "--env",
    ENV_ID,
    ...extra,
    "--",
    "printenv",
    "ALPHA",
  ];
}

/** 平文・トークンが出力に混ざっていないことの共通検査。 */
function expectNoSecretLeak(env: TestEnv): void {
  const output = [...env.logs, ...env.errors].join("\n");
  expect(output).not.toContain("alpha-value");
  expect(output).not.toContain("beta-value");
  expect(output).not.toContain(RUNNER_TOKEN);
  // fakeJwt の payload セグメント(トークン本体)も出さない
  expect(output).not.toContain(base64UrlJson({ alg: "RS256", kid: "k1" }));
}

/* -------------------------------------------------------------------------- */
/* 正常系                                                                      */
/* -------------------------------------------------------------------------- */

describe("maruhi ci run(正常系)", () => {
  it("1 回の lease 呼び出しで検証・復号し、子プロセス env へ注入する", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);

    // 注入(メモリのみ — ProcessRunner の extraEnv)
    expect(env.runnerCalls).toHaveLength(1);
    expect(env.runnerCalls[0]?.command).toEqual(["printenv", "ALPHA"]);
    expect(env.runnerCalls[0]?.extraEnv["ALPHA"]).toBe("alpha-value");
    expect(env.runnerCalls[0]?.extraEnv["BETA"]).toBe("beta-value");

    // 応答は自己完結(§14-2): 呼んだのは OIDC 発行と lease の 2 つだけ
    // (チェーン API・pull API を呼ばない)
    expect(server.requests.map((request) => request.path)).toEqual(["/oidc/token", leasePath()]);
    // audience の既定はサーバー origin(AUTH_SPEC §14-1 の推奨値)
    expect(oidc.audiences).toEqual([server.origin]);
    // 一時鍵は 32 バイト hex で送られる
    const sent = leaseBody(server.requests[1] as MockRequest);
    expect(sent.ephemeralPubHex).toMatch(/^[0-9a-f]{64}$/);

    // キーチェーン・config 非依存(シードしていない環境で成功している)
    expect(env.keychain.size).toBe(0);
    // 検証の成立は stderr に残す(stdout は子プロセスのために空ける)
    expect(env.logs).toEqual([]);
    expect(env.errors.join("\n")).toContain("Lease verified");
    expectNoSecretLeak(env);
  });

  it("--audience が発行要求の audience を上書きする", async () => {
    const { env, server, oidc } = await startCiEnv([leaseHandler()]);
    const code = await runCli(ciArgs(server, ["--audience", "https://maruhi.example"]), env.layer);
    expect(code).toBe(0);
    expect(oidc.audiences).toEqual(["https://maruhi.example"]);
  });
});

/* -------------------------------------------------------------------------- */
/* §9.1 の検証義務(負例)                                                     */
/* -------------------------------------------------------------------------- */

describe("maruhi ci run(検証義務の負例 — CRYPTO_SPEC §9.1)", () => {
  it("(1) 改竄チェーンを拒否する(署名検証)", async () => {
    const entries = fixture.built.entries.map((entry, index) =>
      index === 1 ? ({ ...entry, timestampMs: entry.timestampMs + 1 } as ChainEntry) : entry,
    );
    const { env, server } = await startCiEnv([leaseHandler({ entries })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Chain verification failed");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("(1) genesis が事前固定の projectId と一致しない配布を拒否する", async () => {
    // 別プロジェクト ID を固定した CI 設定に、元プロジェクトのチェーンを配布する
    // 差し替え形。応答の申告 projectId は要求どおりに偽装する(申告整合は通る)
    const pinned = "22".repeat(32);
    const { env, server } = await startCiEnv([leaseHandler({ declaredProjectId: pinned }, pinned)]);
    const args = [
      "ci",
      "run",
      "--server",
      server.origin,
      "--project",
      pinned,
      "--env",
      ENV_ID,
      "--",
      "printenv",
      "ALPHA",
    ];
    expect(await runCli(args, env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("genesis hash does not match the project ID");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("(3) コミットメント不一致(毒ラップ)を拒否し、値を復号しない", async () => {
    const poison = crypto.getRandomValues(new Uint8Array(32));
    const { env, server } = await startCiEnv([
      leaseHandler({ dekForEpoch: (epoch, dek) => (epoch === 2 ? poison : dek) }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not match the commitment");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("(4) 値署名の不正(暗号文の差し替え)を拒否する", async () => {
    const tampered: PullEntry = {
      ...fixture.entryAlpha,
      value: {
        ...fixture.entryAlpha.value,
        ciphertextHex: fixture.entryBeta.value.ciphertextHex,
      },
    };
    const { env, server } = await startCiEnv([
      leaseHandler({ variables: [tampered, fixture.entryBeta] }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value signature");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("claims_digest 不一致(別ジョブ文脈向けラップの転用)は開封で落ちる", async () => {
    // サーバーが別の sub(別リポジトリのジョブ)向けに作ったラップを転用する形。
    // HPKE info の claims_digest が食い違い、復号失敗になる(設計原則 3)
    const { env, server } = await startCiEnv([
      leaseHandler({ claims: { subject: "repo:evil/other:ref:refs/heads/main" } }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("claims-digest mismatch");
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("申告 currentEpoch がチェーン導出と食い違う応答を拒否する", async () => {
    const { env, server } = await startCiEnv([leaseHandler({ currentEpoch: 1 })]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("the chain derives epoch 2");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("(4) 同梱チェーンより先のヘッドを宣言する値は再同期せず即時拒否する", async () => {
    // pull は future head を有界再同期で解消できる(§6.3-2b — 自分のチェーンが
    // 古いだけの可能性がある)が、lease はチェーンが**同じ応答に**同梱される
    // (§14-2)ため、その説明が存在しない = 応答の自己矛盾として即時拒否する。
    // これは verifyLeaseDistribution を pull と分ける唯一の挙動差
    const { built, owner, dek2 } = fixture;
    const futureValue = await encryptValueFor({
      dek: dek2,
      projectId: built.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 4,
      plaintext: "alpha-future",
      writer: owner,
      head: { seq: built.entries.length + 1, hashHex: "ee".repeat(32) },
    });
    const { env, server } = await startCiEnv([
      leaseHandler({
        variables: [{ ...fixture.entryAlpha, value: futureValue }, fixture.entryBeta],
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain included in the same response");
    expect(env.runnerCalls).toHaveLength(0);
    // 再同期に相当する追加取得をしない(OIDC 発行と lease の 1 回ずつだけ)
    expect(server.requests.map((request) => request.path)).toEqual(["/oidc/token", leasePath()]);
  });

  it("同一エポックの重複リースラップを拒否する", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({ extraLeases: [{ epoch: 1, dek: fixture.dek1 }] }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Duplicate leased DEKs");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("チェーン導出現エポックを超えるエポックのリースラップを拒否する", async () => {
    const { env, server } = await startCiEnv([
      leaseHandler({
        extraLeases: [{ epoch: 3, dek: crypto.getRandomValues(new Uint8Array(32)) }],
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("beyond the chain's current epoch");
    expect(env.runnerCalls).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* token-replayed / 429 / 503(session-24 §8 / AUTH_SPEC §14-3)               */
/* -------------------------------------------------------------------------- */

/** 先頭 `failures` 回だけ指定エラーを返し、以後は正常応答する lease ハンドラ。 */
function flakyLeaseHandler(
  failures: number,
  error: { readonly status: number; readonly json: unknown },
): MockHandler {
  let calls = 0;
  return async (request) => {
    if (request.method !== "POST" || request.path !== leasePath()) {
      return null;
    }
    calls += 1;
    if (calls <= failures) {
      return { status: error.status, json: error.json };
    }
    return { status: 200, json: await leaseResponseFor(leaseBody(request)) };
  };
}

const TOKEN_REPLAYED = {
  status: 401,
  json: { _tag: "LeaseUnauthorized", reason: "token-replayed" },
};

describe("maruhi ci run(token-replayed / レート制限 / 503)", () => {
  it("token-replayed は新規トークンで 1 回だけ自動再試行し、同一の一時鍵を提示する", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(1, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("Minting a fresh token and retrying once");

    const leases = server.requests.filter((request) => request.path === leasePath());
    expect(leases).toHaveLength(2);
    const [first, second] = [
      leaseBody(leases[0] as MockRequest),
      leaseBody(leases[1] as MockRequest),
    ];
    // 新規トークン(jti が違う)+ 同一の一時鍵(§14-1 の束縛はトークン単位 —
    // 鍵をローテーションしない)
    expect(first.oidcToken).not.toBe(second.oidcToken);
    expect(first.ephemeralPubHex).toBe(second.ephemeralPubHex);
    expect(oidc.issued).toBe(2);
    expect(env.runnerCalls).toHaveLength(1);
  });

  it("token-replayed が新規トークンでも続くなら 1 回で打ち切る(3 回目を送らない)", async () => {
    const { env, server, oidc } = await startCiEnv([flakyLeaseHandler(99, TOKEN_REPLAYED)]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("token-replayed again with a freshly minted token");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(2);
    expect(oidc.issued).toBe(2);
    expect(env.runnerCalls).toHaveLength(0);
    expectNoSecretLeak(env);
  });

  it("token-replayed 以外の 401 は再試行せず理由コードを案内する", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 401,
        json: { _tag: "LeaseUnauthorized", reason: "unsupported-issuer" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("unsupported-issuer");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
  });

  it("429 は再試行せず、残り秒数と再実行の案内を出す", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 429,
        json: { _tag: "LeaseRateLimited", retryAfterSeconds: 1800 },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("Retry after 1800 seconds");
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("503 oidc-jwks-unavailable は一過性(資格情報の異常ではない)と案内する", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "oidc-jwks-unavailable" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("transient");
    expect(output).toContain("retry the job later");
    expect(output).not.toContain("Log in again");
  });

  it("503 server-key-unconfigured はデプロイ設定の欠落としてセットアップへ誘導する", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "server-key-unconfigured" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("docs/SELF_HOSTING.md");
  });

  it("503 server-wraps-missing は管理者のローテーション / バックフィルへ誘導する", async () => {
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 503,
        json: { _tag: "LeaseUnavailable", reason: "server-wraps-missing" },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("maruhi env rotate / maruhi server grant");
  });

  it("404 は lease 特有の一様応答として直し先(座標 / grant / ポリシー)を案内する", async () => {
    // §14-1 の存在秘匿: 未知プロジェクト・grant なし・ポリシー不一致・スコープ外は
    // すべて同じ 404。メンバー向けの「Project not found — check the ID and your
    // access」ではなく、CI で最も起きやすいポリシー不一致まで並べて案内する
    const { env, server } = await startCiEnv([
      flakyLeaseHandler(99, {
        status: 404,
        json: { _tag: "ProjectNotFound", projectId: fixture.built.projectId },
      }),
    ]);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    const output = env.errors.join("\n");
    expect(output).toContain("lease-policy mismatch");
    expect(output).toContain("maruhi server grant --lease-policy");
    // 再試行しない(資格情報でも一過性でもない)
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(1);
    expect(env.runnerCalls).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* OIDC 発行(GitHub Actions 環境)                                            */
/* -------------------------------------------------------------------------- */

describe("maruhi ci run(OIDC 発行)", () => {
  it("発行エンドポイントの env が無ければ、通信前に id-token: write の要件を名指しする", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, undefined);
    env.setEnvVar(OIDC_REQUEST_TOKEN_ENV, undefined);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("permissions: id-token: write");
    expect(server.requests).toHaveLength(0);
  });

  it("aud が複数のトークンは往復前に拒否する(claims digest が一意に決まらない)", async () => {
    const { env, server } = await startCiEnv([
      // 発行エンドポイントが複数 audience のトークンを返す異常形(既定の
      // oidcHandler と衝突しない別パスに置き、env で差し向ける)
      (request) =>
        request.path === "/oidc/multi"
          ? {
              status: 200,
              json: { value: fakeJwt({ iss: ISSUER, sub: SUBJECT, aud: ["a", "b"] }) },
            }
          : null,
      leaseHandler(),
    ]);
    env.setEnvVar(OIDC_REQUEST_URL_ENV, `${server.origin}/oidc/multi`);
    expect(await runCli(ciArgs(server), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("multiple audiences");
    // lease エンドポイントには到達しない
    expect(server.requests.filter((request) => request.path === leasePath())).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* リポジトリアンカー(§6.3 (b) — 検証義務 (2))                               */
/* -------------------------------------------------------------------------- */

async function anchorFile(contents: unknown): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "maruhi-anchor-"));
  const path = join(dir, "maruhi-anchor.json");
  await writeFile(path, `${JSON.stringify(contents)}\n`);
  return path;
}

function validAnchor(): Record<string, unknown> {
  return {
    version: 1,
    projectId: fixture.built.projectId,
    headSeq: fixture.built.entries.length,
    headHashHex: fixture.built.hashes[fixture.built.hashes.length - 1],
    environments: { [ENV_ID]: 2 },
  };
}

describe("maruhi ci run --anchor(リポジトリアンカー — CRYPTO_SPEC §6.3 (b))", () => {
  it("包含 + エポック非後退を満たすアンカーで成功する", async () => {
    const path = await anchorFile(validAnchor());
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("repository anchor");
  });

  it("ピン留めヘッドを含まないチェーンを拒否する", async () => {
    const path = await anchorFile({ ...validAnchor(), headHashHex: "ab".repeat(32) });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the anchored head");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("アンカー未満へのエポック後退(ローテーション前ビューの配布)を拒否する", async () => {
    const path = await anchorFile({ ...validAnchor(), environments: { [ENV_ID]: 3 } });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("below the anchored epoch");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("チェーン長を超える seq のピン留めヘッド(古いビューの配布)を拒否する", async () => {
    const path = await anchorFile({
      ...validAnchor(),
      headSeq: fixture.built.entries.length + 5,
    });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the anchored head");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("アンカー済み環境がチェーンに無い配布(作成以前への巻き戻し)を拒否する", async () => {
    const path = await anchorFile({ ...validAnchor(), environments: { ghost: 1 } });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on the distributed chain");
    expect(env.runnerCalls).toHaveLength(0);
  });

  it("壊れたアンカーファイルは通信より前に落とす(再生成の導線つき)", async () => {
    const path = await anchorFile({ version: 2 });
    const { env, server } = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(server, ["--anchor", path]), env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("maruhi project anchor");
    expect(server.requests).toHaveLength(0);
  });
});

/* -------------------------------------------------------------------------- */
/* 引数層(ADR-0016)                                                          */
/* -------------------------------------------------------------------------- */

describe("maruhi ci run(引数層 — ADR-0016)", () => {
  it("--server / --project / --env の欠落は CI 特有の直し方を言う(exit 2)", async () => {
    for (const args of [
      ["ci", "run", "--", "true"],
      ["ci", "run", "--server", "https://maruhi.example", "--", "true"],
      [
        "ci",
        "run",
        "--server",
        "https://maruhi.example",
        "--project",
        "11".repeat(32),
        "--",
        "true",
      ],
    ]) {
      const env = await makeTestEnv();
      expect(await runCli(args, env.layer), args.join(" ")).toBe(2);
      expect(env.errors.join("\n")).toContain("CI mode reads no config file");
    }
  });

  it("--project の形式(genesis ハッシュ)はネットワークより前に検査する", async () => {
    const { env, server } = await startCiEnv([leaseHandler()]);
    const args = [
      "ci",
      "run",
      "--server",
      server.origin,
      "--project",
      "not-a-genesis",
      "--env",
      ENV_ID,
      "--",
      "true",
    ];
    expect(await runCli(args, env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("genesis hash");
    expect(server.requests).toHaveLength(0);
  });

  it("`--` の無い実行・実行対象なしは書き方の誤り(exit 2)", async () => {
    const env = await makeTestEnv();
    expect(await runCli(["ci", "run"], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("Specify the command to run");
  });
});

/* -------------------------------------------------------------------------- */
/* maruhi project anchor(生成側)                                             */
/* -------------------------------------------------------------------------- */

describe("maruhi project anchor", () => {
  it("検証済みビューからアンカー JSON を stdout へ出す(ci run --anchor で通る形)", async () => {
    const { built, owner } = fixture;
    const server = await MockServer.start([
      onRequest("GET", `/projects/${built.projectId}/chain`, () => ({
        status: 200,
        json: {
          projectId: built.projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      })),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["project", "anchor"], env.layer)).toBe(0);
    const anchor: unknown = JSON.parse(env.logs.join("\n"));
    expect(anchor).toEqual({
      version: 1,
      projectId: built.projectId,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
      environments: { [ENV_ID]: 2 },
    });

    // 出力したアンカーはそのまま ci run --anchor の検査を通る(往復の整合)
    const path = await anchorFile(anchor);
    const ci = await startCiEnv([leaseHandler()]);
    expect(await runCli(ciArgs(ci.server, ["--anchor", path]), ci.env.layer)).toBe(0);
  });
});
