// チェックポイント整合のクライアント規則 2(CRYPTO_SPEC §6.3 — 値の非後退。
// PR-M3 / session-27 §13-5 のスナップショット同梱検証)の結線テスト。
//
// 検証の柱:
//  1. 受理正例: 列挙一致・checkpoint 後の前進 version(基準 epoch 以上)・
//     tombstone で説明される消失・checkpoint 後の新規作成(新エポック)
//  2. 全拒否経路: 列挙欠落(基準あり)・digest 不一致・version 後退・同版
//     ハッシュ不一致・前進 version の旧エポック・tombstone なしの消失・
//     スナップショット外変数の旧エポック作成・locator 偽装
//  3. locator の 2 分類(裁定 S): 申告 seq > 自ヘッド = 有界再同期(pull)/
//     lease は自己矛盾として即時拒否
//  4. cross-layer(裁定 W): 規則 2 を通過する配布でも床の規則 (a) は独立に落とす
//     (チェーンの粗い基準がローカルの細かい基準を短絡しない — F4 と同型)
//  5. lease 経路: 同一実装の到達 + 基準なし環境の値付き配布での警告(SHOULD)

import type { ChainOperation } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect, Exit } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { checkCheckpointIntegrity } from "../src/checkpoint-integrity.ts";
import { runCli } from "../src/cli.ts";
import { verifyChainSnapshot } from "../src/sync.ts";
import { verifyLeaseDistribution } from "../src/values.ts";
import {
  buildChain,
  type BuiltChain,
  type ChainStep,
  checkpointSnapshotValuesOf,
  createEnvironmentOp,
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  manifestHashOf,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireCheckpointSnapshot,
  type WireDistributedEnvironmentStatement,
  type WireDistributedManifest,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "prod";
/** 基準 checkpoint の位置(baseSteps 3 エントリ + checkpoint = seq 4)。 */
const CHECKPOINT_SEQ = 4;

let owner: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** [genesis, create ENV(epoch 1), rotate(epoch 2)](checkpoint なし)。 */
let baseChain: BuiltChain;
/** baseChain + 末尾に ENV を覆う checkpoint(規則 2 の基準)。 */
let chain: BuiltChain;
let projectId: string;
let envStatement: WireDistributedEnvironmentStatement;
let stmtA: WireDistributedVariableStatement;
let stmtB: WireDistributedVariableStatement;
/** va v2 epoch 2(checkpoint 時点の最新)。 */
let valueA: WireDistributedValue;
/** vb v1 epoch 1(ローテーション後・再暗号化前の正当な状態 — §12-7)。 */
let valueB: WireDistributedValue;
/** チェーン上の checkpoint と対応する正しい列挙(サーバー保存行のモデル)。 */
let snapshot: WireCheckpointSnapshot;
/** checkpoint タプルが束縛する mv1 マニフェスト([A active, B active])。 */
let manifestMain: WireDistributedManifest;
/** ENV を覆う checkpoint op(良性競合テストが第 2 の checkpoint として再利用)。 */
let checkpointOperation: ChainOperation;
let wraps: WireRecipientDek[];
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const baseSteps: ChainStep[] = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ];
  // 2 パス構築: 署名(Ed25519)・timestamp とも決定的なので、同一 steps の
  // 再構築は同一エントリ列になる(先に base を組んで配布物のヘッド・digest を
  // 確定し、その値を焼き込んだ checkpoint を末尾に足して組み直す)
  baseChain = await buildChain(baseSteps);
  projectId = baseChain.projectId;
  const genesisHead = { seq: 1, hashHex: projectId };
  envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: genesisHead,
  });
  stmtA = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: genesisHead,
  });
  stmtB = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "vb",
    name: "BETA",
    author: owner,
    head: genesisHead,
  });
  const common = { projectId, environmentId: ENV_ID };
  valueA = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 2,
    plaintext: "alpha-2",
    writer: owner,
    head: headOf(baseChain, 3),
  });
  valueB = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "vb",
    version: 1,
    plaintext: "beta-1",
    writer: owner,
    head: headOf(baseChain, 2),
  });
  manifestMain = await manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 2,
    issuer: owner,
    head: headOf(baseChain, 3),
    envStatement,
    statements: [stmtA, stmtB],
    manifestVersion: 1,
  });
  const snapshotValues = await checkpointSnapshotValuesOf([valueA, valueB]);
  const digest = await computeEnvValuesDigest(SUITE_ID, snapshotValues);
  if (!digest.ok) throw new Error("values digest failed");
  checkpointOperation = {
    op: "checkpoint",
    payload: {
      environments: [
        {
          environmentId: ENV_ID,
          epoch: 2,
          manifestVersion: 1,
          manifestSigHashHex: await manifestHashOf(projectId, manifestMain),
          valuesDigestHex: digest.value,
        },
      ],
      auditHeadHashHex: "",
    },
  };
  chain = await buildChain([...baseSteps, { actor: owner, operation: checkpointOperation }]);
  expect(chain.projectId).toBe(projectId);
  snapshot = {
    chainSeq: CHECKPOINT_SEQ,
    entryHashHex: chain.hashes[CHECKPOINT_SEQ - 1] ?? "",
    values: snapshotValues,
  };
  wraps = [
    await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
    await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
  ];
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

function chainHandler(built: BuiltChain): MockHandler {
  return onRequest("GET", `/projects/${projectId}/chain`, () => ({
    status: 200,
    json: {
      projectId,
      entries: built.entries,
      headSeq: built.entries.length,
      headHashHex: built.hashes[built.hashes.length - 1],
    },
  }));
}

interface PullOverrides {
  readonly variables?: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly manifest?: WireDistributedManifest;
  /** null = 列挙を配らない(欠落 negative)。省略 = 正しい列挙。 */
  readonly checkpointSnapshot?: WireCheckpointSnapshot | null;
}

function pullHandler(overrides: PullOverrides = {}): MockHandler {
  const served =
    overrides.checkpointSnapshot === undefined ? snapshot : overrides.checkpointSnapshot;
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: 2,
      statement: envStatement,
      variables: overrides.variables ?? [
        { variableId: "va", statement: stmtA, value: valueA },
        { variableId: "vb", statement: stmtB, value: valueB },
      ],
      deletedVariables: overrides.deletedVariables ?? [],
      deks: wraps,
      manifest: overrides.manifest ?? manifestMain,
      ...(served === null ? {} : { checkpointSnapshot: served }),
    },
  }));
}

async function startEnv(handlers: readonly MockHandler[]): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
  return env;
}

/** 同一 TestEnv(= 同一の床)へのフェーズ切り替え(floor-detection と同じ流儀)。 */
async function startPhase(env: TestEnv, handlers: readonly MockHandler[]): Promise<void> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  seedSession(env, server.origin, owner);
  await seedConfig(env, {
    server: server.origin,
    defaultProject: projectId,
    defaultEnvironment: ENV_ID,
  });
}

/** mv2 マニフェスト(prev = mv1 の実ハッシュ。served 集合の変わる負例・正例用)。 */
async function manifestNext(
  statements: readonly WireDistributedVariableStatement[],
): Promise<WireDistributedManifest> {
  return manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: 2,
    issuer: owner,
    head: headOf(baseChain, 3),
    envStatement,
    statements,
    manifestVersion: 2,
    prevManifestSigHashHex: await manifestHashOf(projectId, manifestMain),
  });
}

describe("規則 2 の受理正例(§6.3 チェックポイント整合 2)", () => {
  it("checkpoint 時点そのままの配布 + 一致する列挙を受理する", async () => {
    const env = await startEnv([chainHandler(chain), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("checkpoint 後の前進 version(基準 epoch 以上)を受理する", async () => {
    const advanced = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vb",
      version: 2,
      plaintext: "beta-2",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: advanced },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("スナップショットの変数の消失は、検証済み tombstone で説明されれば受理する", async () => {
    const tombstoneB = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vb",
      name: "BETA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
      status: "deleted",
      metaVersion: 2,
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [{ variableId: "va", statement: stmtA, value: valueA }],
        deletedVariables: [tombstoneB],
        manifest: await manifestNext([stmtA, tombstoneB]),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("スナップショットにない新規変数は、エポックが基準以上なら checkpoint 後の作成として受理する", async () => {
    const stmtC = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vc",
      name: "GAMMA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
    });
    const valueC = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "vc",
      version: 1,
      plaintext: "gamma-1",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await startEnv([
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: valueB },
          { variableId: "vc", statement: stmtC, value: valueC },
        ],
        manifest: await manifestNext([stmtA, stmtB, stmtC]),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("基準を持たない環境(チェーンに checkpoint なし)は列挙なしをそのまま受理する", async () => {
    const env = await startEnv([
      chainHandler(baseChain),
      pullHandler({ checkpointSnapshot: null, manifest: manifestMain }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
  });

  it("申告 seq が自ヘッドより先の列挙は有界再同期で解決する(§6.3-2b と同型 — 裁定 S)", async () => {
    // チェーン取得は 1 回目 = checkpoint 未着のビュー、以後 = 延長された全体。
    // pull 応答は新しい checkpoint の列挙を運ぶ(応答生成の直前に checkpoint が
    // 着地した良性の競合のモデル化)
    let chainCalls = 0;
    const staleChain: MockHandler = (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/chain`) {
        return null;
      }
      const built = chainCalls === 0 ? baseChain : chain;
      chainCalls += 1;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    };
    const env = await startEnv([staleChain, pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(0);
    expect(chainCalls).toBeGreaterThan(1);
  });
});

describe("規則 2 の拒否経路(session-27 §13-5 — 全件が検証済みデータとチェーン公証の矛盾)", () => {
  async function expectRejected(
    overrides: PullOverrides,
    fragment: string,
    built: BuiltChain = chain,
  ): Promise<void> {
    const env = await startEnv([chainHandler(built), pullHandler(overrides)]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(fragment);
  }

  it("基準あり + 列挙なし = 拒否(MUST — 省略を規則 2 のスキップに落とさせない)", async () => {
    await expectRejected({ checkpointSnapshot: null }, "omitted the checkpoint value snapshot");
  });

  it("列挙の再計算ダイジェストがチェーンの values_digest と不一致なら拒否する", async () => {
    const first = snapshot.values[0];
    if (first === undefined) throw new Error("fixture snapshot is empty");
    await expectRejected(
      {
        checkpointSnapshot: {
          ...snapshot,
          values: [{ ...first, version: first.version + 1 }, ...snapshot.values.slice(1)],
        },
      },
      "does not match the values digest notarized by checkpoint",
    );
  });

  it("スナップショット未満への version 後退を拒否する", async () => {
    const rolledBack = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 1,
      plaintext: "alpha-old",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: rolledBack },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "a value rollback below the checkpointed state",
    );
  });

  it("同版で signed bytes が異なる配布を拒否する(checkpoint との equivocation)", async () => {
    // 同一座標 (va, v2, epoch 2) の別暗号文(nonce が変わるため signed bytes も変わる)
    const substituted = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 2,
      plaintext: "alpha-substituted",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: substituted },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "signed bytes differing from the checkpointed hash",
    );
  });

  it("前進 version の旧エポック(基準未満)を拒否する(床規則 (c) のチェックポイント版)", async () => {
    const injected = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "va",
      version: 3,
      plaintext: "alpha-forged",
      writer: owner,
      // epoch 1 が現エポックだった位置の宣言ヘッド(署名検証は通る形)
      head: headOf(baseChain, 2),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: injected },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      },
      "evidence of forward injection with an old epoch key",
    );
  });

  it("tombstone なしの消失を拒否する(checkpoint 済み値の説明のない欠落)", async () => {
    await expectRejected(
      {
        variables: [{ variableId: "va", statement: stmtA, value: valueA }],
        manifest: await manifestNext([stmtA]),
      },
      "missing from the response without a verified deletion tombstone",
    );
  });

  it("スナップショット外変数の旧エポック作成を拒否する(backdated 作成)", async () => {
    const stmtC = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vc",
      name: "GAMMA",
      author: owner,
      head: { seq: 1, hashHex: projectId },
    });
    const backdated = await encryptValueFor({
      dek: dek1,
      projectId,
      environmentId: ENV_ID,
      epoch: 1,
      variableId: "vc",
      version: 1,
      plaintext: "gamma-forged",
      writer: owner,
      head: headOf(baseChain, 2),
    });
    await expectRejected(
      {
        variables: [
          { variableId: "va", statement: stmtA, value: valueA },
          { variableId: "vb", statement: stmtB, value: valueB },
          { variableId: "vc", statement: stmtC, value: backdated },
        ],
        manifest: await manifestNext([stmtA, stmtB, stmtC]),
      },
      "evidence of a backdated creation with an old epoch key",
    );
  });

  it("locator の hash 偽装(seq ≤ 自ヘッド・チェーンと不一致)を拒否する", async () => {
    await expectRejected(
      { checkpointSnapshot: { ...snapshot, entryHashHex: "ef".repeat(32) } },
      "does not match the verified chain",
    );
  });

  it("最新包含 checkpoint と別位置を主張する列挙を拒否する", async () => {
    await expectRejected(
      {
        checkpointSnapshot: {
          ...snapshot,
          chainSeq: 2,
          entryHashHex: chain.hashes[1] ?? "",
        },
      },
      "the latest checkpoint covering environment",
    );
  });

  it("基準なしのチェーンに列挙(seq ≤ 自ヘッド)を配る応答を拒否する", async () => {
    await expectRejected(
      {
        checkpointSnapshot: { ...snapshot, chainSeq: 2, entryHashHex: baseChain.hashes[1] ?? "" },
        manifest: manifestMain,
      },
      "derives no checkpoint covering this environment",
      baseChain,
    );
  });
});

describe("良性競合の分類(PR #100 Bugbot 指摘 — 取得ビュー後の基準前進は evidence にしない)", () => {
  it("再同期の窓に第 2 の checkpoint が着地した正直な応答は、証拠ではなく retriable として拒否する", async () => {
    // fetch 時のビュー = baseChain(checkpoint なし)。応答は checkpoint(seq 4)の
    // 列挙を運ぶが、再同期後のチェーンには第 2 の checkpoint(seq 5)まで載って
    // いる — 応答の locator(4)は最新基準(5)と一致しないが、基準は取得ビュー
    // (head 3)より後に前進しており、正直な応答でも起きる形。証拠(再実行では
    // 解消しない)へ格上げせず、再 pull の案内で拒否する
    const doubleChain = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: checkpointOperation },
      { actor: owner, operation: checkpointOperation },
    ]);
    expect(doubleChain.projectId).toBe(projectId);
    let chainCalls = 0;
    const racingChain: MockHandler = (request) => {
      if (request.method !== "GET" || request.path !== `/projects/${projectId}/chain`) {
        return null;
      }
      const built = chainCalls === 0 ? baseChain : doubleChain;
      chainCalls += 1;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    };
    const env = await startEnv([racingChain, pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("retry the pull");
    expect(errors).not.toContain("stale or fabricated");
  });

  it("基準前進の分類は取得ビュー基準(fetchedAtHeadSeq)で行う(unit)", async () => {
    const verified = await Effect.runPromise(
      verifyChainSnapshot({
        projectId: projectId as never,
        entries: chain.entries,
        claimedHeadSeq: chain.entries.length,
        claimedHeadHashHex: chain.hashes[chain.hashes.length - 1] ?? "",
      }),
    );
    // 列挙なし + 基準は取得ビュー(head 3)より後に着地 → retriable
    const missingAfterFetch = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: undefined,
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: 3,
    });
    expect(missingAfterFetch).toMatchObject({ kind: "rejected", evidence: false });
    // 列挙なし + 基準は取得ビュー時点で保存済み → MUST の evidence 拒否
    const missingStored = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: undefined,
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: CHECKPOINT_SEQ,
    });
    expect(missingStored).toMatchObject({ kind: "rejected", evidence: true });
    // 旧位置の列挙 + 基準は取得ビュー時点で保存済み → stale 配布の evidence 拒否
    const staleStored = await checkCheckpointIntegrity({
      history: verified.history,
      environmentId: ENV_ID,
      snapshot: { chainSeq: 2, entryHashHex: chain.hashes[1] ?? "", values: [] },
      variables: [],
      tombstoneIds: new Set(),
      fetchedAtHeadSeq: CHECKPOINT_SEQ,
    });
    expect(staleStored).toMatchObject({ kind: "rejected", evidence: true });
  });
});

describe("cross-layer: 規則 2 は床の規則 (a) を代替しない(裁定 W — F4 と同型)", () => {
  it("checkpoint 基準以上・床未満の値配布は床が拒否する", async () => {
    // フェーズ 1: va v3(基準 v2 より前進・epoch 2)で床を確立する
    const v3 = await encryptValueFor({
      dek: dek2,
      projectId,
      environmentId: ENV_ID,
      epoch: 2,
      variableId: "va",
      version: 3,
      plaintext: "alpha-3",
      writer: owner,
      head: headOf(baseChain, 3),
    });
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain),
      pullHandler({
        variables: [
          { variableId: "va", statement: stmtA, value: v3 },
          { variableId: "vb", statement: stmtB, value: valueB },
        ],
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // フェーズ 2: checkpoint 時点の va v2 へ巻き戻す。規則 2(v2 = スナップ
    // ショットと同版・同ハッシュ)は通るが、床の規則 (a)(v3 未満)が落とす
    await startPhase(env, [chainHandler(chain), pullHandler()]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("value-version rollback");
  });
});

describe("lease 経路(§14-2 — 同一実装の到達と基準なし警告)", () => {
  async function verifiedOf(built: BuiltChain) {
    return Effect.runPromise(
      verifyChainSnapshot({
        projectId: projectId as never,
        entries: built.entries,
        claimedHeadSeq: built.entries.length,
        claimedHeadHashHex: built.hashes[built.hashes.length - 1] ?? "",
      }),
    );
  }

  type LeaseWire = Parameters<typeof verifyLeaseDistribution>[0]["wire"];

  function leaseWire(overrides: PullOverrides = {}): LeaseWire {
    const served =
      overrides.checkpointSnapshot === undefined ? snapshot : overrides.checkpointSnapshot;
    // テストの Wire* 構造型は api-schema の配布型と構造一致(support/crypto.ts)
    return {
      statement: envStatement,
      variables: overrides.variables ?? [
        { variableId: "va", statement: stmtA, value: valueA },
        { variableId: "vb", statement: stmtB, value: valueB },
      ],
      deletedVariables: overrides.deletedVariables ?? [],
      manifest: overrides.manifest ?? manifestMain,
      ...(served === null ? {} : { checkpointSnapshot: served }),
    } as LeaseWire;
  }

  async function expectLeaseRejected(
    built: BuiltChain,
    overrides: PullOverrides,
    fragment: string,
  ): Promise<void> {
    const verified = await verifiedOf(built);
    const exit = await Effect.runPromiseExit(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire(overrides),
      }),
    );
    expect(Exit.isFailure(exit)).toBe(true);
    expect(JSON.stringify(exit)).toContain(fragment);
  }

  it("基準あり + 列挙なしの lease 応答を拒否する(pull と同一規則)", async () => {
    await expectLeaseRejected(
      chain,
      { checkpointSnapshot: null },
      "omitted the checkpoint value snapshot",
    );
  });

  it("同梱チェーンより先の checkpoint を主張する列挙は自己矛盾として即時拒否する(再同期しない)", async () => {
    await expectLeaseRejected(
      baseChain,
      { manifest: manifestMain },
      "the response contradicts itself",
    );
  });

  it("基準を持たない環境の値付き lease 応答は受理しつつ警告する(§6.3 SHOULD)", async () => {
    const verified = await verifiedOf(baseChain);
    const result = await Effect.runPromise(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire({ checkpointSnapshot: null }),
      }),
    );
    expect(result.variables).toHaveLength(2);
    expect(result.warnings.join("\n")).toContain("No checkpoint on the verified chain covers");
  });

  it("基準ありで列挙が一致する lease 応答は警告なしで受理する", async () => {
    const verified = await verifiedOf(chain);
    const result = await Effect.runPromise(
      verifyLeaseDistribution({
        verified,
        environmentId: ENV_ID as never,
        wire: leaseWire(),
      }),
    );
    expect(result.variables).toHaveLength(2);
    expect(result.warnings.join("\n")).not.toContain("No checkpoint on the verified chain covers");
  });
});
