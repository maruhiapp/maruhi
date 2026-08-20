// push(§12-5 CAS)のテスト: create / 新バージョン、409 リトライ
// (VersionConflict / EpochConflict = 再同期 → 再暗号化 → 再試行)、
// スキーマ外の素の 413 分岐(session-07 §5 申し送りの決着)。

import { decryptVariable } from "@maruhi/crypto";
import { Effect } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { makeFileFloorStore } from "../src/floor-log.ts";
import {
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  statementFor,
  variablesDigestOf,
  type TestUser,
  valueHashOf,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedVariableStatement,
  type WireEncryptedPayload,
  wrapDekFor,
  type WireRecipientDek,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockRequest, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

let owner: TestUser;
let chainV1: BuiltChain;
let chainV2: BuiltChain;
let dek1: Uint8Array;
let dek2: Uint8Array;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

/** pull 応答の 1 変数(検証済みステートメント + 値)。宣言ヘッドは genesis。 */
async function entryOf(
  variableId: string,
  name: string,
  value: WireEncryptedPayload,
): Promise<{
  variableId: string;
  statement: WireDistributedVariableStatement;
  value: WireEncryptedPayload;
}> {
  return {
    variableId,
    statement: await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId,
      name,
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
    }),
    value,
  };
}

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  chainV1 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  // 同一 genesis(同一プロジェクト)にローテーションが積まれた形
  chainV2 = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  const common = { projectId: chainV1.projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: chainV1.projectId },
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandlerOf(chains: readonly BuiltChain[]): MockHandler {
  // 呼び出しごとに進む(EpochConflict 再同期で新チェーンが見える)。最後で止まる
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/chain`, () => {
    const built = chains[Math.min(call, chains.length - 1)] as BuiltChain;
    call += 1;
    return {
      status: 200,
      json: {
        projectId: chainV1.projectId,
        entries: built.entries,
        headSeq: built.entries.length,
        headHashHex: built.hashes[built.hashes.length - 1],
      },
    };
  });
}

function deksHandlerOf(sets: readonly (readonly WireRecipientDek[])[]): MockHandler {
  let call = 0;
  return onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`, () => {
    const deks = sets[Math.min(call, sets.length - 1)] ?? [];
    call += 1;
    return { status: 200, json: { deks } };
  });
}

/**
 * 配布集合そのものから計算したマニフェスト(§12-7)。Ed25519 は決定的なので、
 * 同一集合の再計算は byte-exact に一致する(equivocation にならない)。
 */
async function manifestOf(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return manifestFor({
    projectId: chainV1.projectId,
    environmentId: ENV_ID,
    epoch: currentEpoch,
    issuer: owner,
    head: currentEpoch === 1 ? headOf(chainV1, 2) : headOf(chainV2, 3),
    envStatement,
    statements,
    manifestVersion,
    ...(prevManifestSigHashHex === undefined ? {} : { prevManifestSigHashHex }),
  });
}

/** 値付き pull(§12-7)の応答 JSON(マニフェスト同梱)。 */
async function pullJsonOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
  currentEpoch = 1,
  /** メタ集合が変わる応答は次 version を渡す(同 version の集合差は equivocation)。 */
  manifestVersion = 1,
  /** version > 1 の prev(直前マニフェストの hash — 隣接 prev 検証 M1-A1 の連鎖)。 */
  prevManifestSigHashHex?: string,
): Promise<unknown> {
  return {
    environmentId: ENV_ID,
    currentEpoch,
    statement: envStatement,
    variables,
    deletedVariables: [],
    deks,
    manifest: await manifestOf(
      variables.map((variable) => variable.statement),
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    ),
  };
}

/** 指定集合・版のマニフェストの signed-bytes ハッシュ(次版の prev の材料)。 */
async function manifestHashAt(
  statements: readonly WireDistributedVariableStatement[],
  currentEpoch = 1,
  manifestVersion = 1,
  prevManifestSigHashHex?: string,
): Promise<string> {
  return manifestHashOf(
    chainV1.projectId,
    (await manifestOf(
      statements,
      currentEpoch,
      manifestVersion,
      prevManifestSigHashHex,
    )) as WireDistributedManifest,
  );
}

function pullHandlerOf(
  variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireEncryptedPayload;
  }[],
  deks: readonly WireRecipientDek[],
): MockHandler {
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`,
    async () => ({
      status: 200,
      json: await pullJsonOf(variables, deks),
    }),
  );
}

/**
 * 変数作成の受理を記録する箱(§12-10 (3) の効果確認 pull が、受理済みの
 * ステートメント + マニフェストの配布を模すための共有状態)。
 */
interface CreateEcho {
  body: CreateBody | null;
  /** 作成の issueBase になった variant(配布集合 = variant + 作成ステートメント)。 */
  baseVariant: readonly WireDistributedVariableStatement[];
}

/** 発行形 → 配布形(§12-2 — サーバーが呼び出し主体の帰属を付ける)。 */
function distributedStatementOf(body: CreateBody): WireDistributedVariableStatement {
  return {
    ...body.statement,
    authorUserId: owner.userId,
    authorKeyFingerprintHex: owner.fingerprintHex,
  } as WireDistributedVariableStatement;
}

/**
 * メタデータのみ pull(§12-7)の応答。呼び出しごとに variants を進む(最後で
 * 止まる)。variant 間のマニフェストは prev を実際に連鎖させる(隣接版の prev
 * 検証 — M1-A1 — を満たす正当な「他メンバーのメタ操作」のモデル化)。
 * `echo` が受理済み作成を持つ場合は、その配布(variant + 作成ステートメント +
 * 受理したマニフェスト)を返す — 効果確認(§12-10 (3))の材料。
 */
function pullMetadataHandlerOf(
  variants: readonly (readonly WireDistributedVariableStatement[])[],
  currentEpoch = 1,
  echo?: CreateEcho,
): MockHandler {
  let call = 0;
  const manifests: WireDistributedManifest[] = [];
  const manifestAt = async (index: number): Promise<WireDistributedManifest> => {
    for (let position = manifests.length; position <= index; position += 1) {
      const previous = manifests[position - 1];
      manifests[position] = (await manifestOf(
        variants[position] ?? [],
        currentEpoch,
        position + 1,
        previous === undefined ? undefined : await manifestHashOf(chainV1.projectId, previous),
      )) as WireDistributedManifest;
    }
    return manifests[index] as WireDistributedManifest;
  };
  return onRequest(
    "GET",
    `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
    async () => {
      if (echo !== undefined && echo.body !== null) {
        // 受理済み: 配布形 = issueBase の集合 + 作成ステートメント、マニフェスト =
        // 受理した発行形 + issuer 帰属(env-rotate.test.ts の acceptRotate と同型)
        return {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            statement: envStatement,
            variables: [...echo.baseVariant, distributedStatementOf(echo.body)],
            deletedVariables: [],
            manifest: {
              ...echo.body.manifest,
              issuerUserId: owner.userId,
              issuerKeyFingerprintHex: owner.fingerprintHex,
            },
          },
        };
      }
      const index = Math.min(call, variants.length - 1);
      const variables = variants[index] ?? [];
      call += 1;
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch,
          statement: envStatement,
          variables,
          deletedVariables: [],
          // variant の前進 = 他メンバーのメタ操作 1 回のモデル化。manifestVersion も
          // 一緒に進める(床の単調性と整合する)
          manifest: await manifestAt(index),
        },
      };
    },
  );
}

async function startEnv(handlers: readonly MockHandler[], stdin: string): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: chainV1.projectId,
    defaultEnvironment: ENV_ID,
  });
  env.setStdin(new TextEncoder().encode(stdin));
  return env;
}

interface CreateBody {
  readonly statement: WireDistributedVariableStatement;
  readonly value: WireEncryptedPayload;
  /** 同梱マニフェスト(§12-4 — 変数作成もマニフェストを再発行する)。 */
  readonly manifest: {
    readonly environmentId: string;
    readonly epoch: number;
    readonly manifestVersion: number;
    readonly variablesDigestHex: string;
    readonly envMetaVersion: number;
    readonly envMetaSigHashHex: string;
    readonly prevManifestSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
}

async function decryptWire(dek: Uint8Array, value: WireEncryptedPayload): Promise<string> {
  const result = await decryptVariable({
    dek,
    context: value.aad,
    nonce: hexBytes(value.nonceHex),
    ciphertext: hexBytes(value.ciphertextHex),
  });
  if (!result.ok) {
    throw new Error("decrypt failed in test");
  }
  return new TextDecoder().decode(result.value);
}

describe("maruhi push", () => {
  it("新規変数は create(version 1)。stdin の値が現エポックで暗号化される", async () => {
    const createCalls: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request: MockRequest) => {
          const body = request.body as CreateBody;
          createCalls.push(body);
          // 受理: 以後の metadata pull(効果確認 — §12-10 (3))が配布する
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: body.value.aad.version,
              epoch: body.value.aad.epoch,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("secret-value\n"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createCalls).toHaveLength(1);
    const body = createCalls[0] as CreateBody;
    // 作成は metaVersion 1 のステートメントを同梱する(§12-5): author 署名付き・
    // prev 空・宣言ヘッド = 最後に検証したchain head
    expect(body.statement.name).toBe("API_KEY");
    expect(body.statement.status).toBe("active");
    expect(body.statement.metaVersion).toBe(1);
    expect(body.statement.prevMetaSigHashHex).toBe("");
    expect(body.statement.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.statement.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(body.value.aad).toEqual({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: body.statement.variableId,
      version: 1,
    });
    // 値署名ブロック(§4.1): 新規変数は prev 空、宣言ヘッド = 最後に検証した
    // chain head、writer = 自分(署名は master sig 鍵)
    expect(body.value.prevValueSigHashHex).toBe("");
    expect(body.value.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.value.chainHeadHashHex).toBe(headOf(chainV1, chainV1.entries.length).hashHex);
    expect(body.value.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    // 末尾改行 1 つは除去され、値は現エポック DEK で復号できる
    expect(await decryptWire(dek1, body.value)).toBe("secret-value");
    // 同梱マニフェスト(§12-4): 直前(サーバー配布の v1)の次 = v2、prev は
    // 検証済み直前マニフェストの signed bytes ハッシュ、ダイジェストは作成後の
    // 全変数集合(= 新規ステートメント 1 件)からの再計算値
    expect(body.manifest.manifestVersion).toBe(2);
    expect(body.manifest.prevManifestSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(body.manifest.epoch).toBe(1);
    expect(body.manifest.chainHeadSeq).toBe(chainV1.entries.length);
    expect(body.manifest.variablesDigestHex).toBe(
      await variablesDigestOf(chainV1.projectId, [
        { ...body.statement, authorUserId: owner.userId },
      ]),
    );
    expect(body.manifest.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    expect(env.logs.join("\n")).toContain("version=1");
    // 新規作成の名前解決はメタデータのみ pull(§12-7)で行い、値付き pull を
    // 一切呼ばない = サーバー側で var.read が記録されない経路(session-11 裁定 3)
    const paths = server.requests.map((request) => request.path);
    expect(paths).toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`);
    expect(paths).not.toContain(`/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`);
  });

  it("intent(3-F)の追記に失敗したら変数作成を送信しない(journal-before-send の fail-closed)", async () => {
    let createCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]]),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => {
        createCalls += 1;
        return { status: 200, json: { variableId: "vx", version: 1, epoch: 1 } };
      }),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    env.failFloorIntentAppends();

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    // 確認義務の記録なしに security-critical mutation を飛ばさない
    expect(createCalls).toBe(0);
    expect(env.errors.join("\n")).toContain("intent");
  });

  it("旧サーバー相当(manifest を黙って捨てて 200)では、受理後照合が失敗し床のマニフェストを前進させない(1-E′ — §12-10 (3))", async () => {
    // strict 受理(§12-10 (1))未導入の旧サーバーの形: 変数作成の 200 は返すが
    // 同梱マニフェストを保存せず、以後も旧マニフェスト(v1・作成前の集合)を
    // 配布し続ける。成功の定義 = 検証可能な配布物での効果確認なので、CLI は
    // 成功と言わず、自己発行マニフェストを床に書かない(M1-A2 の受理後照合)
    let created: CreateBody | null = null;
    let metadataCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest(
        "GET",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => {
          metadataCalls += 1;
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              // 受理後もステートメントは保存済み(値・メタは旧サーバーでも保存
              // される)が、マニフェストは v1(作成前の空集合)のまま = 黙殺の形
              variables: created === null ? [] : [distributedStatementOf(created)],
              deletedVariables: [],
              manifest: await manifestOf([], 1, 1),
            },
          };
        },
      ),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          created = request.body as CreateBody;
          return {
            status: 200,
            json: {
              variableId: (request.body as CreateBody).statement.variableId,
              version: 1,
              epoch: 1,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 効果確認の失敗として報告する(2xx を成功と読ませない)
    expect(errors).toContain("post-acceptance confirmation");
    expect(errors).toContain("success is defined by the confirmed effect");
    // 確認の metadata pull は実際に行われた(受理後照合)
    expect(metadataCalls).toBeGreaterThanOrEqual(2);
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
    );
    const record = loaded.floor?.environments[ENV_ID];
    // 自己発行マニフェスト(v2)は床に書かれない — 記録されるのは検証済み観測
    // (解決 pull の v1)のみ。旧サーバーへ「保存されていないマニフェスト」を
    // 床に固定して以後の欠落を omission と誤判定する事故(M1-A2)を作らない
    expect(record?.manifest?.manifestVersion).toBe(1);
    // **変数床も書かれない**(§12-10 (3) — 床への記録は確認通過後のみ)。
    // 2xx だけを根拠に自分の書き込みを床へ植えると、サーバーが実際には保存して
    // いなかった場合に、以後の全 pull が variable-omitted で恒久拒否される
    // (未確認の思い込みが equivocation 証拠に化ける — Bugbot 指摘の固定)
    const body = created as CreateBody | null;
    expect(record?.variables[body?.statement.variableId ?? ""]).toBeUndefined();
    // 確認義務の記録(intent — 3-F)は未解決のまま残る
    expect(loaded.floor?.intents).toHaveLength(1);
  });

  it("同版の別マニフェストが配布されたら hash 不一致として失敗する(1-E′ — §12-10 (3))", async () => {
    // サーバーは 200 を返すが、発行した manifestVersion に**別内容**の検証可能な
    // マニフェスト(自分の変数 + 注入された変数を覆う)を配布する。デジェストは
    // 配布集合と整合するため §4.3 検証は通る — 自己発行 (version, hash) との
    // 照合だけがこれを検出する
    const extraStatement = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-injected",
      name: "INJECTED",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
    });
    let created: CreateBody | null = null;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      onRequest(
        "GET",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull/metadata`,
        async () => {
          if (created === null) {
            return {
              status: 200,
              json: {
                environmentId: ENV_ID,
                currentEpoch: 1,
                statement: envStatement,
                variables: [],
                deletedVariables: [],
                manifest: await manifestOf([], 1, 1),
              },
            };
          }
          const statements = [distributedStatementOf(created), extraStatement];
          return {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch: 1,
              statement: envStatement,
              variables: statements,
              deletedVariables: [],
              // 同じ manifestVersion(2)だが別集合を覆う = 別の signed bytes。
              // prev は正しく v1 へ連鎖させる(M1-A1 は通る形 — hash 照合の固定)
              manifest: await manifestOf(statements, 1, 2, await manifestHashAt([])),
            },
          };
        },
      ),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          created = request.body as CreateBody;
          return {
            status: 200,
            json: {
              variableId: (request.body as CreateBody).statement.variableId,
              version: 1,
              epoch: 1,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("distributes a different manifest at the issued manifestVersion");
    const loaded = await Effect.runPromise(
      makeFileFloorStore(env.floorDir).load(chainV1.projectId),
    );
    // 発行したマニフェストは保存されていないことを確認済み = intent は
    // not-accepted で閉じる(検証済みの配布側 v2' は観測として床に残る)
    expect(loaded.floor?.intents).toEqual([]);
    expect(loaded.floor?.environments[ENV_ID]?.manifest?.manifestVersion).toBe(2);
  });

  it("VersionConflict(409)は再取得した winner を検証し、その hash へ prev を付け替えて再試行する", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head,
    });
    // 実際に勝った version 7(409 後の再取得で見える)
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 7,
      plaintext: "winner",
      writer: owner,
      head,
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const pushBodies: WireEncryptedPayload[] = [];
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      // listMine ハンドラを置かない: 既存変数への push は値付き pull の同梱 DEK を
      // 使い、listMine との二重取得をしない(session-11 裁定 3)。呼べば 404 で落ちる
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? existing : winner }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        (request) => {
          const body = request.body as { value: WireEncryptedPayload };
          pushBodies.push(body.value);
          if (pushBodies.length === 1) {
            // 競合: 実は誰かが version 7 まで進めていた
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } };
          }
          return {
            status: 200,
            json: { variableId: "v-existing", version: body.value.aad.version, epoch: 1 },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("new-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(pushBodies).toHaveLength(2);
    expect(pushBodies[0]?.aad.version).toBe(5);
    expect(pushBodies[1]?.aad.version).toBe(8);
    // prev は検証済みの現行最新 → 409 後は再取得・検証した winner の
    // signed-bytes hash(自計算 — サーバー申告のハッシュではない)へ付け替わる
    expect(pushBodies[0]?.prevValueSigHashHex).toBe(await valueHashOf(existing, owner.userId));
    expect(pushBodies[1]?.prevValueSigHashHex).toBe(await valueHashOf(winner, owner.userId));
    // 再試行は新 version で再暗号化されている(nonce も新しい)
    expect(pushBodies[0]?.nonceHex).not.toBe(pushBodies[1]?.nonceHex);
    expect(await decryptWire(dek1, pushBodies[1] as WireEncryptedPayload)).toBe("new-value");
    // DEK は値付き pull の同梱分のみで賄われ、listMine は一度も呼ばれない
    expect(
      server.requests.filter(
        (request) =>
          request.method === "GET" &&
          request.path === `/projects/${chainV1.projectId}/environments/${ENV_ID}/deks`,
      ),
    ).toHaveLength(0);
  });

  it("409 の申告が検証済み latest より古い(巻き戻し)なら拒否する(レビューループ 1 [高])", async () => {
    // クライアントは v4 を検証済み。悪意サーバーは v2 まで巻き戻した 409 を返し、
    // 再取得でも巻き戻しビュー(v2 = 単体では全検証を通る古い正規値)を配布する。
    // セッション内で保持している検証済み latest(v4)からの後退として拒否する
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    const rolledBack = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 2,
      plaintext: "old-regular",
      writer: owner,
      head,
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", v4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? v4 : rolledBack }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    // セッション 16 以降は初回 pull がコミットした床の規則が先に検出する
    // (floor-check.ts の文言)
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("409 後の winner の prev が検証済み直前 version と連鎖しなければ拒否する(レビューループ 1 [中])", async () => {
    // クライアントは v4 を検証済み。winner は v5 だが prev が v4 でなく別の
    // 履歴(fork)に連鎖している → 隣接 predecessor の §6.3-6 検査で拒否する
    const head = headOf(chainV1, chainV1.entries.length);
    const v4 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    // v5 だが prev はダミー(v4 の hash ではない = 分岐した履歴への連鎖)
    const forkedV5 = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "forked",
      writer: owner,
      head,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", v4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? v4 : forkedV5 }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 5 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "prev that does not match the verified predecessor version",
    );
  });

  it("409 後の winner が版番号ギャップ越しにエポック後退していたら拒否する(レビューループ 2 [低])", async () => {
    // known = epoch 2 の v4(検証済み)。winner は version 6(ギャップ 2 で prev
    // 隣接検査は対象外)だが epoch 1 = 旧エポックへ後退している(削除済みメンバーの
    // 旧エポック署名の版番号ずらし注入の形)。セッション 16 以降は初回 pull が
    // コミットした床の規則 (a) が再取得 pull の時点で先に検出する(winner 検査は
    // 床が使えない場合の防衛層として残る)
    const head3 = headOf(chainV2, 3); // rotate(epoch 2 が現)を含むヘッド
    const head2 = headOf(chainV2, 2); // create(epoch 1 が現)のヘッド
    const knownV4 = await encryptValueFor({
      dek: dek2,
      projectId: chainV2.projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "v-existing",
      version: 4,
      plaintext: "current-epoch2",
      writer: owner,
      head: head3,
    });
    const regressedV6 = await encryptValueFor({
      dek: dek1,
      projectId: chainV2.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 6,
      plaintext: "regressed-epoch1",
      writer: owner,
      head: head2,
      prevValueSigHashHex: "ab".repeat(32),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", knownV4);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV2]),
      deksHandlerOf([[wrap1, wrap2]]),
      pullMetadataHandlerOf([[entryExisting.statement]], 2),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? knownV4 : regressedV6 }],
            [wrap1, wrap2],
            2,
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 6 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("monotonicity violation");
  });

  it("409 後の再取得が申告 currentVersion より古ければ不整合として拒否する", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        // 再取得しても version 4 のまま(409 の申告 7 より古い)
        pullHandlerOf([entryExisting], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
          () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "older than the known latest version (7) — inconsistent",
    );
  });

  it("409 後の再取得で winner が欠落していたら拒否する(床の欠落検出が先に発火)", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(pullCalls === 1 ? [entryExisting] : [], [wrap1]),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 7 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("omission of a verified variable");
  });

  it("409 後の再取得が同一 version で異なる signed bytes を返したら equivocation として拒否する", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const coordinates = {
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      writer: owner,
      head,
    } as const;
    const existing = await encryptValueFor({ ...coordinates, plaintext: "old" });
    // 同一座標(version 4)で内容の異なる有効署名(§14.2-5 の証拠の形)
    const forked = await encryptValueFor({ ...coordinates, plaintext: "forked" });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [{ ...entryExisting, value: pullCalls === 1 ? existing : forked }],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        // currentVersion 4 = 検証済み latest と同じ version を申告する 409
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 4 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("equivocation");
  });

  it("EpochConflict(409)は再同期 → 新エポック DEK 取得 → 再暗号化して再試行する(エポックの真実源はチェーン)", async () => {
    // push.test は「同一 genesis の 2 状態」を前提にする(Ed25519 の決定論署名 +
    // 固定 timestamp により成立)
    expect(chainV2.projectId).toBe(chainV1.projectId);
    const createBodies: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      // first syncはローテーション前(epoch 1)、再同期でローテーション後が見える
      chainHandlerOf([chainV1, chainV2]),
      deksHandlerOf([[wrap1], [wrap1, wrap2]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          const body = request.body as CreateBody;
          createBodies.push(body);
          if (createBodies.length === 1) {
            // サーバー申告の currentEpoch は嘘(5)。真実源はチェーン導出値(2)
            // であることを固定する(申告値を使う退行は aad.epoch=5 になり検出)
            return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 5 } };
          }
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: 1,
              epoch: body.value.aad.epoch,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("rotated-value"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    expect(createBodies).toHaveLength(2);
    expect(createBodies[0]?.value.aad.epoch).toBe(1);
    // 再試行はチェーン導出の新エポック(2。申告の 5 ではない)+ 新 DEK で
    // 暗号化されている。再同期でチェーンが 2 回取得されている
    expect(createBodies[1]?.value.aad.epoch).toBe(2);
    expect(await decryptWire(dek2, (createBodies[1] as CreateBody).value)).toBe("rotated-value");
    expect(
      server.requests.filter((r) => r.path === `/projects/${chainV1.projectId}/chain`),
    ).toHaveLength(2);
    // 平文値は出力に現れない
    expect([...env.logs, ...env.errors].join("\n")).not.toContain("rotated-value");
  });

  it("EpochConflict 申告がチェーンと矛盾する(再同期しても現エポック不変)なら試行回数に関わらず矛盾として報告する", async () => {
    // サーバーが毎回 EpochConflict を返し続ける = 試行上限まで到達するが、
    // 汎用の「競合が解消しません」でなく定的な矛盾エラーを報告する
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("the server response contradicts the chain");
    expect(errors).not.toContain("did not resolve");
  });

  it("EpochConflict 後に新エポックの DEK が自分宛にない場合は明示エラーになる", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1, chainV2]),
        deksHandlerOf([[wrap1], [wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 2 } }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("No DEK for the current epoch 2 is registered for you");
  });

  it("create の競合(並行作成)は名前から再解決して push 経路へ切り替える", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-racer",
      version: 1,
      plaintext: "raced",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryRacer = await entryOf("v-racer", "API_KEY", existing);
    let pullCalls = 0;
    let pushed: WireEncryptedPayload | null = null;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // 初回解決では変数なし(create 経路)、競合後の再解決では並行作成された
      // v-racer が見える(解決はメタデータのみ pull — §12-7)
      pullMetadataHandlerOf([[], [entryRacer.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // 並行作成のメタ操作がマニフェストを v2 へ進めた形(メタデータ側の
        // variant 2 と同じマニフェスト — 隣接 prev は v1 へ連鎖 M1-A1)
        return {
          status: 200,
          json: await pullJsonOf([entryRacer], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "VariableConflict", variableId: "ignored", reason: "duplicate-name" },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-racer/versions`,
        (request) => {
          pushed = (request.body as { value: WireEncryptedPayload }).value;
          return { status: 200, json: { variableId: "v-racer", version: 2, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("after-race"));

    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    // 値付き pull は再解決で既存変数になってから 1 回だけ(初回解決は
    // メタデータのみで値を読まない)
    expect(pullCalls).toBe(1);
    const body = pushed as WireEncryptedPayload | null;
    expect(body?.aad.variableId).toBe("v-racer");
    expect(body?.aad.version).toBe(2);
    // 再解決後の prev は検証済み v1(並行作成の winner)の signed-bytes hash
    expect(body?.prevValueSigHashHex).toBe(await valueHashOf(existing, owner.userId));
  });

  it("スキーマ外の素の 413 は「値が大きすぎる」として報告する", async () => {
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[]]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
          () => ({ status: 413, bodyText: "Payload Too Large" }),
        ),
      ],
      "big-value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("HTTP 413");
    expect(env.errors.join("\n")).toContain("too large");
  });

  it("create 経路への VersionConflict(異常応答)も名前から再解決して自壊しない", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-late",
      version: 1,
      plaintext: "late",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryLate = await entryOf("v-late", "API_KEY", existing);
    let pullCalls = 0;
    let pushedVersion = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // 初回解決は変数なし(create 経路)、再解決で v-late が見える
      pullMetadataHandlerOf([[], [entryLate.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // 並行作成のメタ操作がマニフェストを v2 へ進めた形(variant 2 と同一)
        return {
          status: 200,
          json: await pullJsonOf([entryLate], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        // create にはスキーマ上返しうるが通常起きない応答。乱数 ID のまま
        // push 経路へ落ちる退行(存在しない ID への push)をしないこと
        status: 409,
        json: { _tag: "VersionConflict", currentVersion: 1 },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-late/versions`,
        (request) => {
          pushedVersion = (request.body as { value: WireEncryptedPayload }).value.aad.version;
          return { status: 200, json: { variableId: "v-late", version: pushedVersion, epoch: 1 } };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    // 値付き pull は再解決後の 1 回のみ(初回解決はメタデータのみ)
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("名前解決で変数名が重複していたら拒否する(恣意的な 1 件へ束縛しない)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-a",
      version: 1,
      plaintext: "a",
      writer: owner,
      head,
    });
    const other = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-b",
      version: 1,
      plaintext: "b",
      writer: owner,
      head,
    });
    const entryA = await entryOf("v-a", "API_KEY", existing);
    const entryB = await entryOf("v-b", "API_KEY", other);
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        // 名前解決はメタデータのみ pull — 同名 active の重複はその検証で拒否される
        pullMetadataHandlerOf([[entryA.statement, entryB.statement]]),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("Multiple active statements with the same name");
  });

  it("409 後の再取得ステートメントが metaVersion 巻き戻しなら拒否する(§12-5 のメタ同型)", async () => {
    // クライアントは metaVersion 2 のステートメントを検証済み。再取得(409 後)で
    // metaVersion 1 のステートメントが配布される = メタデータ巻き戻しの証拠
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const statementV2 = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    const statementV1 = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV2]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [
              {
                variableId: "v-existing",
                statement: pullCalls === 1 ? statementV2 : statementV1,
                value: pullCalls === 1 ? existing : winner,
              },
            ],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 5 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    // セッション 16 以降は初回 pull がコミットした床の規則 (a) が先に検出する
    // (floor-check.ts の文言)
    expect(env.errors.join("\n")).toContain("rollback");
  });

  it("409 後の再取得が隣接 metaVersion で prev 不一致なら拒否する(分岐履歴への連鎖)", async () => {
    // クライアントは metaVersion 1 のステートメントを検証済み。再取得(409 後)の
    // metaVersion 2 の prev が検証済み signed bytes ハッシュと一致しない =
    // 分岐した prev 連鎖への追従を拒否する(winnerValueRegression の隣接検査の同型)
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const statementV1 = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    // prev 既定値("cd"×32)は statementV1 の signed bytes ハッシュと一致しない
    const forkedSuccessor = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[statementV1]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [
              {
                variableId: "v-existing",
                statement: pullCalls === 1 ? statementV1 : forkedSuccessor,
                value: pullCalls === 1 ? existing : winner,
              },
            ],
            [wrap1],
            1,
            // 2 回目は metaVersion 2 の勝者 = メタ操作 1 回分マニフェストも前進
            // (隣接版なので prev は v1 マニフェストへ連鎖させる — M1-A1 とは
            // 独立に、勝者ステートメントの prev 不一致だけを固定する)
            pullCalls === 1 ? 1 : 2,
            pullCalls === 1 ? undefined : await manifestHashAt([statementV1]),
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 5 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("chaining onto a diverged history");
  });

  it("409 後の再取得が同一 metaVersion で異なる signed bytes を返したら equivocation として拒否する(rename fork)", async () => {
    const head = headOf(chainV1, chainV1.entries.length);
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head,
    });
    const winner = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 5,
      plaintext: "winner",
      writer: owner,
      head,
      prevValueSigHashHex: await valueHashOf(existing, owner.userId),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    // 同一 metaVersion(1)で name が異なる有効ステートメント = rename fork の証拠
    const forkedStatement = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY_FORKED",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 1,
    });
    let pullCalls = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[entryExisting.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        return {
          status: 200,
          json: await pullJsonOf(
            [
              pullCalls === 1
                ? entryExisting
                : { ...entryExisting, statement: forkedStatement, value: winner },
            ],
            [wrap1],
          ),
        };
      }),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
        () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 5 } }),
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("equivocation");
  });

  it("create への MetaVersionConflict(409)は名前から再解決する(並行 rename との競合)", async () => {
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-meta-race",
      version: 1,
      plaintext: "raced",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryRaced = await entryOf("v-meta-race", "API_KEY", existing);
    let pullCalls = 0;
    let pushedVersion = 0;
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      // 初回解決は変数なし(create 経路)、再解決で v-meta-race が見える
      pullMetadataHandlerOf([[], [entryRaced.statement]]),
      onRequest("GET", `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`, async () => {
        pullCalls += 1;
        // 並行 rename のメタ操作がマニフェストを v2 へ進めた形(variant 2 と同一)
        return {
          status: 200,
          json: await pullJsonOf([entryRaced], [wrap1], 1, 2, await manifestHashAt([])),
        };
      }),
      onRequest("POST", `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`, () => ({
        status: 409,
        json: { _tag: "MetaVersionConflict", currentMetaVersion: 1 },
      })),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-meta-race/versions`,
        (request) => {
          pushedVersion = (request.body as { value: WireEncryptedPayload }).value.aad.version;
          return {
            status: 200,
            json: { variableId: "v-meta-race", version: pushedVersion, epoch: 1 },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(0);
    // 値付き pull は再解決後の 1 回のみ(初回解決はメタデータのみ)
    expect(pullCalls).toBe(1);
    expect(pushedVersion).toBe(2);
  });

  it("名前は署名前に NFC 正規化される(ルックアップキーとステートメントの両方 — §12-1)", async () => {
    // NFD(結合文字)の名前で push → 同梱ステートメントの name は NFC 正規形
    const nfdName = "CAFE\u0301_URL";
    const nfcName = nfdName.normalize("NFC");
    expect(nfcName).not.toBe(nfdName);
    const createCalls: CreateBody[] = [];
    const echo: CreateEcho = { body: null, baseVariant: [] };
    const server = await MockServer.start([
      chainHandlerOf([chainV1]),
      deksHandlerOf([[wrap1]]),
      pullMetadataHandlerOf([[]], 1, echo),
      onRequest(
        "POST",
        `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables`,
        (request) => {
          const body = request.body as CreateBody;
          createCalls.push(body);
          echo.body = body;
          return {
            status: 200,
            json: {
              variableId: body.statement.variableId,
              version: 1,
              epoch: body.value.aad.epoch,
            },
          };
        },
      ),
    ]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: chainV1.projectId,
      defaultEnvironment: ENV_ID,
    });
    env.setStdin(new TextEncoder().encode("value"));
    expect(await runCli(["push", nfdName], env.layer)).toBe(0);
    expect(createCalls[0]?.statement.name).toBe(nfcName);
  });

  it("競合が解消しない場合は試行上限で中断する", async () => {
    // サーバーが「検証済み latest と同じ currentVersion + 同一の値の配布」を
    // 返し続ける = 各周回の winner 検査(欠落・古い pull・equivocation)は通るが
    // 前進しない。汎用の試行上限で打ち切る
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 1,
      plaintext: "old",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    let attempts = 0;
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        deksHandlerOf([[wrap1]]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        pullHandlerOf([entryExisting], [wrap1]),
        onRequest(
          "POST",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/variables/v-existing/versions`,
          () => {
            attempts += 1;
            return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
          },
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(attempts).toBe(5);
    expect(env.errors.join("\n")).toContain("did not resolve");
  });

  it("名前解決と値取得の間に並行 rename が入ったら push を向けずに拒否する(PR #41 レビュー指摘)", async () => {
    // メタデータ解決は API_KEY → v-existing。値付き pull では同じ変数が
    // API_KEY_V2 へ改名済み(metaVersion 2)= 入力した名前と別の名前に変わった
    // 変数への push を防ぐ(単一応答で解決していた旧フローのスナップショット整合)
    const existing = await encryptValueFor({
      dek: dek1,
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "v-existing",
      version: 4,
      plaintext: "current",
      writer: owner,
      head: headOf(chainV1, chainV1.entries.length),
    });
    const entryExisting = await entryOf("v-existing", "API_KEY", existing);
    const renamedStatement = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-existing",
      name: "API_KEY_V2",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
    });
    const env = await startEnv(
      [
        chainHandlerOf([chainV1]),
        pullMetadataHandlerOf([[entryExisting.statement]]),
        // 並行 rename のメタ操作はマニフェストも v2 へ進める(§12-5 — 同版の
        // 集合差は equivocation になってしまうため、正直な rename の形で組む)
        onRequest(
          "GET",
          `/projects/${chainV1.projectId}/environments/${ENV_ID}/pull`,
          async () => ({
            status: 200,
            json: await pullJsonOf(
              [{ ...entryExisting, statement: renamedStatement }],
              [wrap1],
              1,
              2,
              await manifestHashAt([entryExisting.statement]),
            ),
          }),
        ),
      ],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("concurrent rename");
  });

  it("メタデータ解決の応答のアクティブ一覧に deleted ステートメントが混ざっていたら拒否する(§12-7)", async () => {
    // メタデータのみ pull にも値付き pull と同じ検証規律が掛かる(削除の無断
    // 取り消しの運搬形。値がない分、検証はステートメント側だけで完結する)
    const deletedStatement = await statementFor({
      projectId: chainV1.projectId,
      environmentId: ENV_ID,
      variableId: "v-dead",
      name: "API_KEY",
      author: owner,
      head: { seq: 1, hashHex: chainV1.projectId },
      metaVersion: 2,
      status: "deleted",
    });
    const env = await startEnv(
      [chainHandlerOf([chainV1]), pullMetadataHandlerOf([[deletedStatement]])],
      "value",
    );
    expect(await runCli(["push", "API_KEY"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("deleted statement in the active list");
  });
});
