// 環境マニフェストの CLI 結線テスト(CRYPTO_SPEC §4.3 / §6.3、AUTH_SPEC §12 —
// session-27 §13-5 のマニフェスト項)。
//
// 検証の柱:
//  1. 配布時検証: 欠落 = 一律拒否・ダイジェスト再計算(変数 / tombstone の欠落)・
//     エポック整合・issuer の役割不足(crypto の共有実装への結線)
//  2. 床のマニフェスト拡張: 規則 (a) 後退・(b) 同版相違・(c) 前進 version の
//     旧エポック焼き込み(セッションを跨ぐ永続検出)
//  3. 移行経路(session-27 §14 PR-M1): マニフェスト未初期化サーバーへの操作は
//     既定で拒否され、`env rotate --init-manifest` だけが欠落を許容して
//     manifestVersion 1 を発行する(配布された場合の検証は緩和しない)

import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
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
  rotateEpochOp,
  statementFor,
  type TestUser,
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

let owner: TestUser;
/** role reader のメンバー(issuer 役割不足の negative 用)。 */
let reader: TestUser;
/** role member の第 2 メンバー(同版相違 = equivocation の別 issuer 用)。 */
let member2: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** [genesis, add reader, add member2, create ENV](epoch 1)。 */
let chain1: BuiltChain;
/** chain1 + rotate_epoch(2)(chain1 の厳密な延長)。 */
let chain2: BuiltChain;
let wrap1: WireRecipientDek;
let wrap2: WireRecipientDek;
let envStatement: WireDistributedEnvironmentStatement;
let alphaStatement: WireDistributedVariableStatement;
let alphaValue1: WireDistributedValue;
let alphaValue2: WireDistributedValue;
let projectId: string;

let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  reader = await makeTestUser("user-reader-2222");
  member2 = await makeTestUser("user-member2-3333");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  const steps = [
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: addMemberOp(reader, "reader") },
    { actor: owner, operation: addMemberOp(member2, "member") },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ];
  chain1 = await buildChain(steps);
  chain2 = await buildChain([
    ...steps,
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  projectId = chain1.projectId;
  expect(chain2.projectId).toBe(projectId);
  const common = { projectId, environmentId: ENV_ID };
  wrap1 = await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner });
  wrap2 = await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner });
  envStatement = await environmentStatementFor({
    projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  alphaStatement = await statementFor({
    projectId,
    environmentId: ENV_ID,
    variableId: "va",
    name: "ALPHA",
    author: owner,
    head: { seq: 1, hashHex: projectId },
  });
  alphaValue1 = await encryptValueFor({
    dek: dek1,
    ...common,
    epoch: 1,
    variableId: "va",
    version: 1,
    plaintext: "alpha-value",
    writer: owner,
    head: headOf(chain1, 4),
  });
  alphaValue2 = await encryptValueFor({
    dek: dek2,
    ...common,
    epoch: 2,
    variableId: "va",
    version: 2,
    plaintext: "alpha-value-2",
    writer: owner,
    head: headOf(chain2, 5),
  });
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

interface PullJson {
  readonly currentEpoch: number;
  readonly variables: readonly {
    variableId: string;
    statement: WireDistributedVariableStatement;
    value: WireDistributedValue;
  }[];
  readonly deletedVariables?: readonly WireDistributedVariableStatement[];
  readonly deks: readonly WireRecipientDek[];
  /** undefined = マニフェストを配布しない(欠落 negative 用)。 */
  readonly manifest?: WireDistributedManifest;
}

function pullHandler(payload: PullJson): MockHandler {
  return onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
    status: 200,
    json: {
      environmentId: ENV_ID,
      currentEpoch: payload.currentEpoch,
      statement: envStatement,
      variables: payload.variables,
      deletedVariables: payload.deletedVariables ?? [],
      deks: payload.deks,
      ...(payload.manifest === undefined ? {} : { manifest: payload.manifest }),
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

const alphaEntry = () => ({ variableId: "va", statement: alphaStatement, value: alphaValue1 });

/** 正直なマニフェスト(epoch 1・chain1 ヘッド・[ALPHA])。上書きで negative を作る。 */
function manifestV1(overrides?: {
  readonly statements?: readonly WireDistributedVariableStatement[];
  readonly epoch?: number;
  readonly head?: { readonly seq: number; readonly hashHex: string };
  readonly issuer?: TestUser;
  readonly manifestVersion?: number;
}): Promise<WireDistributedManifest> {
  return manifestFor({
    projectId,
    environmentId: ENV_ID,
    epoch: overrides?.epoch ?? 1,
    issuer: overrides?.issuer ?? owner,
    head: overrides?.head ?? headOf(chain1, 4),
    envStatement,
    statements: overrides?.statements ?? [alphaStatement],
    ...(overrides?.manifestVersion === undefined
      ? {}
      : { manifestVersion: overrides.manifestVersion }),
  });
}

describe("マニフェスト配布時検証(§6.3 — crypto の共有実装への結線)", () => {
  it("欠落は一律拒否し、移行手順(--init-manifest)を案内する", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({ currentEpoch: 1, variables: [alphaEntry()], deks: [wrap1] }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("did not distribute an environment manifest");
    expect(errors).toContain("manifest suppression");
    expect(errors).toContain("--init-manifest");
  });

  it("変数の欠落(ダイジェストにない変数の配布 = 逆に言えば省略の運搬形)を拒否する", async () => {
    // マニフェストは空集合のダイジェストで署名 → 配布は ALPHA を含む =
    // 再計算不一致。逆向き(配布から省く)も同じ 1 検査で覆われる
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });

  it("tombstone の欠落(削除記録を除いたダイジェスト)を拒否する", async () => {
    const tombstone = await statementFor({
      projectId,
      environmentId: ENV_ID,
      variableId: "vd",
      name: "RETIRED",
      author: owner,
      head: { seq: 1, hashHex: projectId },
      status: "deleted",
      metaVersion: 2,
    });
    // マニフェストのダイジェストは active のみ(tombstone 抜き)で署名されている
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deletedVariables: [tombstone],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [alphaStatement] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });

  it("エポック不整合(宣言ヘッド時点の現エポックでない)を拒否する", async () => {
    // rotate 後のヘッド(seq 5 = epoch 2)に epoch 1 を焼き込んだマニフェスト
    const env = await startEnv([
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [alphaEntry()],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 5) }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=epoch-not-current-at-head");
  });

  it("issuer の役割不足(reader 発行)を拒否する(発行契機はすべて member 以上 — §4.3)", async () => {
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ issuer: reader }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=issuer-role-insufficient-at-head");
  });

  it("署名 bit 反転を拒否する", async () => {
    const honest = await manifestV1();
    const flipped = `${honest.signatureHex.slice(0, -1)}${
      honest.signatureHex.endsWith("0") ? "1" : "0"
    }`;
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: { ...honest, signatureHex: flipped },
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=signature-invalid");
  });
});

describe("床のマニフェスト拡張(§6.3 規則 (a)(b)(c) のマニフェスト適用)", () => {
  it("manifestVersion の後退を拒否する(規則 (a))", async () => {
    const env = await makeTestEnv();
    // フェーズ 1: v2 のマニフェストで床を確立
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // フェーズ 2: 同一集合の v1(単体では全検証を通る古い正規マニフェスト)
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ manifestVersion: 1 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("environment-manifest rollback");
    expect(errors).toContain("manifestVersion=2");
    expect(errors).toContain("manifestVersion=1");
  });

  it("同一 manifestVersion の signed bytes 相違を拒否する(規則 (b) — equivocation)", async () => {
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1(),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // 同一 version・同一集合だが issuer が異なる = signed bytes が異なる有効署名
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ issuer: member2 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("signed bytes served for the same manifestVersion");
  });

  it("前進 manifestVersion の旧エポック焼き込みを拒否する(規則 (c) のマニフェスト適用)", async () => {
    const env = await makeTestEnv();
    // フェーズ 1: epoch 2 の床(pull 時点エポック基準 = 2)を確立
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({
          epoch: 2,
          head: headOf(chain2, 5),
          manifestVersion: 2,
        }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // フェーズ 2: version は前進(3)だが epoch 1 を焼き込んだマニフェスト
    // (旧エポック期の在籍ヘッド seq 4 を宣言すれば暗号学的には有効)
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 4), manifestVersion: 3 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("below the epoch baseline");
    expect(errors).toContain("forward meta injection");
  });

  it("規則 (c) の基準は床マニフェスト自身の epoch も含む(pullEpoch が遅れている窓 — bugbot 指摘の回帰)", async () => {
    // 有界再同期の形では pullEpoch は応答取得**前**ビュー(= 旧エポック)に
    // 据え置かれる一方、床マニフェストは epoch 2 を検証済みで知っている。
    // 基準を pullEpoch だけにすると、旧エポックを焼き込んだ前進 manifestVersion
    // (旧在籍ヘッド宣言で暗号学的には有効)が素通りする
    const env = await makeTestEnv();
    let chainCalls = 0;
    const progressiveChain: MockHandler = onRequest("GET", `/projects/${projectId}/chain`, () => {
      chainCalls += 1;
      const built = chainCalls === 1 ? chain1 : chain2;
      return {
        status: 200,
        json: {
          projectId,
          entries: built.entries,
          headSeq: built.entries.length,
          headHashHex: built.hashes[built.hashes.length - 1],
        },
      };
    });
    // フェーズ 1: 旧ビュー(chain1)から始まり、epoch 2 の値 + v2 マニフェスト
    // (head seq 5 = future)が有界再同期で受理される → 床: pullEpoch 1・
    // マニフェスト {v2, epoch 2}
    await startPhase(env, [
      progressiveChain,
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({
          epoch: 2,
          head: headOf(chain2, 5),
          manifestVersion: 2,
        }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // フェーズ 2: version は前進(3)だが epoch 1 を焼き込んだマニフェスト。
    // pullEpoch(1)基準では素通りするが、床マニフェストの epoch(2)が基準に
    // 入るため拒否される(マニフェスト連鎖のエポック非減少の推移形)
    await startPhase(env, [
      chainHandler(chain2),
      pullHandler({
        currentEpoch: 2,
        variables: [{ variableId: "va", statement: alphaStatement, value: alphaValue2 }],
        deks: [wrap1, wrap2],
        manifest: await manifestV1({ epoch: 1, head: headOf(chain2, 4), manifestVersion: 3 }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("below the epoch baseline");
    expect(errors).toContain("epoch baseline=2");
  });
});

/* -------------------------------------------------------------------------- */
/* 移行経路(session-27 §14 PR-M1 — マニフェスト導入前の環境の v1 初期化)      */
/* -------------------------------------------------------------------------- */

interface RotateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & {
    readonly op: "rotate_epoch";
    readonly payload: {
      readonly environmentId: string;
      readonly newEpoch: number;
      readonly reason: string;
      readonly dekCommitmentHex: string;
    };
  };
  readonly deks: readonly {
    readonly suite: "maruhi/v1";
    readonly epoch: number;
    readonly recipientUserId: string;
    readonly encHex: string;
    readonly ciphertextHex: string;
    readonly signatureHex: string;
  }[];
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
}

/**
 * マニフェスト導入前に作られた環境のサーバー: 保存マニフェストなし(pull は
 * manifest を同梱しない)。rotate 複合を受理したら以後は受理マニフェストを配布する。
 */
function makeLegacyServer(input: {
  readonly serveManifestAfterAccept?: boolean;
  /** 初期配布マニフェスト(undefined = 未初期化サーバー)。 */
  readonly initialManifest?: WireDistributedManifest;
}): {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: RotateBody[];
} {
  const entries: ChainEntry[] = [...chain1.entries];
  const hashes: string[] = [...chain1.hashes];
  const deks: WireRecipientDek[] = [wrap1];
  const rotateBodies: RotateBody[] = [];
  let currentEpoch = 1;
  let manifest: WireDistributedManifest | null = input.initialManifest ?? null;
  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => ({
      status: 200,
      json: {
        projectId,
        entries,
        headSeq: entries.length,
        headHashHex: hashes[hashes.length - 1],
      },
    })),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
      status: 200,
      json: {
        environmentId: ENV_ID,
        currentEpoch,
        statement: envStatement,
        variables: [],
        deletedVariables: [],
        deks,
        ...(manifest === null ? {} : { manifest }),
      },
    })),
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/environments/${ENV_ID}/rotate`
      ) {
        return null;
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      currentEpoch = body.entry.payload.newEpoch;
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== owner.userId) {
          continue;
        }
        deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: owner.userId,
          signerKeyFingerprintHex: owner.fingerprintHex,
        });
      }
      if (input.serveManifestAfterAccept !== false) {
        manifest = {
          ...body.manifest,
          issuerUserId: owner.userId,
          issuerKeyFingerprintHex: owner.fingerprintHex,
        };
      }
      return {
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
  ];
  return { handlers, rotateBodies };
}

describe("rotate 受理後の床前進(§6.3 — bugbot 指摘の回帰)", () => {
  it("受理後も旧 manifestVersion を配布し続けるサーバーは、同一実行の再走査で規則 (a) が検出する", async () => {
    // rotate は自分が署名した次 manifestVersion を受理直後に床へ昇格する。
    // これを怠ると「床は pull 時点の旧 version のまま」なので、旧マニフェストを
    // 配布し続けるサーバー(受理した v2 の握り潰し)が床検査を通ってしまう
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeLegacyServer({
      initialManifest: staleManifest,
      // 受理した v2 を保存せず、v1 を配布し続ける(巻き戻しサーバーのモデル化)
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "握り潰し"], env.layer)).toBe(1);
    // 複合自体は受理されている(拒否は受理後の再走査 pull の床検査)
    expect(state.rotateBodies).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("environment-manifest rollback");
  });

  it("床の書き込みに失敗しても、受理 version のプロセス内基準は同一実行の再走査で機能する", async () => {
    // commitManifest のディスク書き込みが失敗しても、「自分が受理させた
    // manifestVersion」を知っている事実はプロセス内の検出材料であり続ける —
    // 受理後に旧版を配布し続けるサーバーは同一実行内で rollback として落ちる
    // (永続化の欠けは警告で開示される)
    const staleManifest = await manifestV1({ statements: [] });
    const state = makeLegacyServer({
      initialManifest: staleManifest,
      serveManifestAfterAccept: false,
    });
    const env = await startEnv(state.handlers);
    // 床は事前 pull で確立しておく(rotate 中の書き込みだけを失敗させる)
    expect(await runCli(["pull"], env.layer)).toBe(0);
    env.failFloorPushCommits();
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "床故障"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("could not be recorded in the local floor");
    expect(errors).toContain("environment-manifest rollback");
  });
});

describe("--init-manifest(移行経路 — session-27 §14 PR-M1)", () => {
  it("マニフェスト未初期化サーバーへの rotate は既定で拒否される(欠落 = 拒否は移行でも例外にしない)", async () => {
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "移行前"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("did not distribute an environment manifest");
    // 拒否は複合送信より前(欠落を検出した pull の段階)
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("--init-manifest は欠落だけを許容し、manifestVersion 1(prev 空・new_epoch)を同梱する", async () => {
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "移行"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate body missing");
    // 初期化は v1・prev 空。エポックは同梱エントリ適用後 = new_epoch(§12-5 (4))、
    // 宣言ヘッドは追記前の現ヘッド(§12-4)
    expect(body.manifest.manifestVersion).toBe(1);
    expect(body.manifest.prevManifestSigHashHex).toBe("");
    expect(body.manifest.epoch).toBe(2);
    expect(body.manifest.chainHeadSeq).toBe(chain1.entries.length);
    expect(body.manifest.chainHeadHashHex).toBe(chain1.hashes[chain1.hashes.length - 1]);
    // 移行であることの明示警告(初期化後は欠落 = 拒否に入ることまで伝える)
    const errors = env.errors.join("\n");
    expect(errors).toContain("no manifest yet");
    expect(errors).toContain("initializes manifestVersion 1");
  });

  it("マニフェストが配布されている環境では --init-manifest は何も緩和しない(警告つき no-op)", async () => {
    // 既に初期化済み(v1 を配布する)サーバー
    const state = makeLegacyServer({});
    const env = await startEnv(state.handlers);
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "初期化"], env.layer),
    ).toBe(0);

    // 2 回目: v1 が配布されている状態で --init-manifest を付けても、次 version
    // (v2・prev = v1 の signed bytes ハッシュ)の通常発行になる
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "再回転"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const second = state.rotateBodies[1];
    if (second === undefined) throw new Error("second rotate body missing");
    expect(second.manifest.manifestVersion).toBe(2);
    expect(second.manifest.prevManifestSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(second.manifest.epoch).toBe(3);
    expect(env.errors.join("\n")).toContain("The flag changed nothing");
  });

  it("床にマニフェスト記録がある環境の欠落は --init-manifest でも握り潰しとして拒否する", async () => {
    // フェーズ 1: マニフェスト付き pull で床(マニフェスト記録込み)を確立
    const env = await makeTestEnv();
    await startPhase(env, [
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(await runCli(["pull"], env.layer)).toBe(0);

    // フェーズ 2: マニフェストを配布しないサーバーに --init-manifest で rotate。
    // 一度確立したマニフェスト床に対する欠落は移行許容の対象外(初期化済みの
    // マニフェストは消えない — 消えたなら握り潰しの証拠)
    const state = makeLegacyServer({});
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    seedSession(env, server.origin, owner);
    await seedConfig(env, {
      server: server.origin,
      defaultProject: projectId,
      defaultEnvironment: ENV_ID,
    });
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "握り潰し"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("omission of the environment manifest");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("配布されたマニフェストの検証は --init-manifest でも緩和されない", async () => {
    // 不正なマニフェスト(ダイジェスト不一致)を配布するサーバーに
    // --init-manifest を付けても拒否される(欠落の許容 ≠ 検証の緩和)
    const env = await startEnv([
      chainHandler(chain1),
      pullHandler({
        currentEpoch: 1,
        variables: [alphaEntry()],
        deks: [wrap1],
        manifest: await manifestV1({ statements: [] }),
      }),
    ]);
    expect(
      await runCli(["env", "rotate", ENV_ID, "--init-manifest", "--reason", "改竄"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("reason=variables-digest-mismatch");
  });
});
