// エポックローテーション(`maruhi env rotate`)のテスト。
//
// 検証の柱:
//  1. 複合リクエスト(§12-4): rotate_epoch エントリ(new_epoch = 現 + 1・reason・
//     新エポックのコミットメント — §5.2 / §6.2)+ 現メンバー集合と厳密一致する
//     ラップ完全集合。各ラップは §5.1 署名を持ち、受信者が開封した DEK は
//     エントリのコミットメントと一致する
//  2. 現在値の再暗号化(§7 / §4.1): 全アクティブ変数の最新値が新 DEK で
//     再暗号化され、実行者が writer として署名した通常 push で送られる
//  3. **中断復旧**: 複合受理後・再暗号化完了前に中断した状態(= エポックは
//     進んだが最新値の epoch が現エポック未満)を再実行が検出し、エポックを
//     進めずに残りだけを再暗号化する(冪等な再開)
//  4. CAS 競合・並行ローテーション・部分完了・認可の各分岐
//
// モックサーバーは実サーバーの状態遷移を模す(受理したエントリをチェーンへ
// 追記し、複合のラップを配布集合へ入れ、push を最新値へ反映する)— これにより
// 「1 回目でクラッシュ → 2 回目で再開」を同一フィクスチャ上で通しで検査できる。

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  decryptVariable,
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
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
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  rotateEpochOp,
  statementFor,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireDistributedValue,
  type WireDistributedVariableStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "dev";

/** rotate 複合リクエストのボディ(api-schema の environments.rotate payload)。 */
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
  readonly deks: readonly WrappedDek[];
}

/** pull 応答の 1 変数(検証済みステートメント + 配布形の値)。 */
interface PulledVariable {
  readonly variableId: string;
  readonly statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

let owner: TestUser;
let reader: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
/** genesis + create_environment(epoch 1)。 */
let chainBase: BuiltChain;
/** 同一 genesis に rotate_epoch(epoch 2、DEK = dek2)が積まれた形。 */
let chainRotated: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  reader = await makeTestUser("user-reader-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  chainBase = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  chainRotated = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  envStatement = await environmentStatementFor({
    projectId: chainBase.projectId,
    environmentId: ENV_ID,
    name: ENV_ID,
    author: owner,
    head: headOf(chainBase, 1),
  });
});

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

/** 1 変数分の pull 応答(値署名の宣言ヘッドは当該エポックが現エポックだった位置)。 */
async function variableAt(input: {
  readonly built: BuiltChain;
  readonly variableId: string;
  readonly name: string;
  readonly dek: Uint8Array;
  readonly epoch: number;
  readonly version: number;
  readonly plaintext: string;
  readonly headSeq: number;
}): Promise<PulledVariable> {
  return {
    variableId: input.variableId,
    statement: await statementFor({
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      variableId: input.variableId,
      name: input.name,
      author: owner,
      head: headOf(input.built, 1),
    }),
    value: await encryptValueFor({
      dek: input.dek,
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: input.epoch,
      variableId: input.variableId,
      version: input.version,
      plaintext: input.plaintext,
      writer: owner,
      head: headOf(input.built, input.headSeq),
    }),
  };
}

interface ServerOptions {
  readonly built: BuiltChain;
  readonly variables: PulledVariable[];
  readonly deks: WireRecipientDek[];
  readonly currentEpoch: number;
  /** rotate 呼び出しごとの差し込み応答(undefined = 正常受理)。 */
  readonly onRotate?: (call: number) => MockResponse | undefined;
  /** push 呼び出しごとの差し込み応答(undefined = 正常受理)。 */
  readonly onPush?: (call: number, variableId: string) => MockResponse | undefined;
}

interface ServerState {
  readonly handlers: readonly MockHandler[];
  readonly rotateBodies: RotateBody[];
  readonly pushes: { readonly variableId: string; readonly value: WireDistributedValue }[];
}

/**
 * 実サーバーの状態遷移を模したハンドラ群: 受理した rotate_epoch エントリを
 * チェーンへ追記し、複合の同梱ラップを配布集合へ入れ、受理した push を
 * 最新値へ反映する。これにより「クラッシュ → 再実行」が同一状態上で通る。
 */
function makeServer(options: ServerOptions): ServerState {
  const projectId = chainBase.projectId;
  const entries: ChainEntry[] = [...options.built.entries];
  const hashes: string[] = [...options.built.hashes];
  const variables = options.variables;
  const deks = options.deks;
  const rotateBodies: RotateBody[] = [];
  const pushes: { variableId: string; value: WireDistributedValue }[] = [];
  let currentEpoch = options.currentEpoch;
  let rotateCalls = 0;
  let pushCalls = 0;

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
        variables,
        deletedVariables: [],
        deks,
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
      const injected = options.onRotate?.(rotateCalls);
      rotateCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      // 受理: エントリをチェーンへ追記し、同梱ラップを配布集合へ入れる
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
    (request) => {
      const prefix = `/projects/${projectId}/environments/${ENV_ID}/variables/`;
      if (
        request.method !== "POST" ||
        !request.path.startsWith(prefix) ||
        !request.path.endsWith("/versions")
      ) {
        return null;
      }
      const variableId = request.path.slice(prefix.length, -"/versions".length);
      const body = request.body as { readonly value: WireDistributedValue };
      const injected = options.onPush?.(pushCalls, variableId);
      pushCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      // 配布形は「受理した payload + 呼び出し主体の writer 情報」(§12-2)
      const stored: WireDistributedValue = {
        ...body.value,
        writerUserId: owner.userId,
        writerKeyFingerprintHex: owner.fingerprintHex,
      };
      pushes.push({ variableId, value: stored });
      const index = variables.findIndex((variable) => variable.variableId === variableId);
      const target = variables[index];
      if (target !== undefined) {
        target.value = stored;
      }
      return {
        status: 200,
        json: {
          variableId,
          version: body.value.aad.version,
          epoch: body.value.aad.epoch,
        },
      };
    },
  ];
  return { handlers, rotateBodies, pushes };
}

async function startEnv(handlers: readonly MockHandler[], user: TestUser): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });
  return env;
}

/** 1 ラップの §5.1 署名検証 + 受信者の開封(env-create.test.ts と同型)。 */
async function verifyAndUnwrap(input: {
  readonly wrap: WrappedDek;
  readonly recipient: TestUser;
  readonly signer: TestUser;
}): Promise<Uint8Array> {
  const { wrap, recipient, signer } = input;
  const signerKey = await importSigningPublicKey(hexBytes(signer.sigPubHex));
  if (!signerKey.ok) {
    throw new Error("sig key import failed");
  }
  const verified = await verifyDekWrapSignature({
    context: {
      suite: wrap.suite,
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: wrap.epoch,
      recipientUserId: wrap.recipientUserId,
      recipientEncPubHex: wrap.recipientEncPubHex,
      encHex: wrap.encHex,
      ciphertextHex: wrap.ciphertextHex,
      signerUserId: signer.userId,
    },
    signatureHex: wrap.signatureHex,
    signerPublicKey: signerKey.value,
  });
  expect(verified.ok).toBe(true);
  const pair = await importEncryptionKeyPair({
    publicKey: hexBytes(recipient.encPubHex),
    privateKey: hexBytes(recipient.encSkHex),
  });
  if (!pair.ok) {
    throw new Error("enc key import failed");
  }
  const dek = await unwrapDek({
    recipientKeyPair: pair.value,
    wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
    context: {
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      epoch: wrap.epoch,
      recipientUserId: wrap.recipientUserId,
    },
  });
  if (!dek.ok) {
    throw new Error("unwrap failed");
  }
  return dek.value;
}

async function decryptWire(dek: Uint8Array, value: WireDistributedValue): Promise<string> {
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

/** 複合の同梱ラップから、実行者が生成した新エポック DEK を取り出す。 */
async function newEpochDekOf(body: RotateBody): Promise<Uint8Array> {
  const wrap = body.deks.find((candidate) => candidate.recipientUserId === owner.userId);
  if (wrap === undefined) {
    throw new Error("owner wrap missing");
  }
  return verifyAndUnwrap({ wrap, recipient: owner, signer: owner });
}

describe("maruhi env rotate", () => {
  it("複合リクエスト: rotate_epoch エントリ(コミットメント込み)+ ラップ完全集合を送り、現在値を新 DEK で再暗号化する", async () => {
    const member = await makeTestUser("user-member-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const head = built.hashes[built.hashes.length - 1] ?? "";
    const variables = [
      await variableAt({
        built,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
      await variableAt({
        built,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 2,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const state = makeServer({
      built,
      variables,
      deks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "退職者の削除に伴う予防的ローテーション"],
        env.layer,
      ),
    ).toBe(0);

    expect(state.rotateBodies).toHaveLength(1);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    // 親ヘッド CAS + エントリは現ヘッドの直後(seq = head + 1)に actor = 呼び出し主体
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("rotate_epoch");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    // new_epoch = 現エポック + 1、reason はチェーンへ載る(§6.2)
    expect(body.entry.payload.environmentId).toBe(ENV_ID);
    expect(body.entry.payload.newEpoch).toBe(2);
    expect(body.entry.payload.reason).toBe("退職者の削除に伴う予防的ローテーション");
    // ラップ先 = 検証済み現メンバー集合と厳密一致(§6.3)
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    expect(body.deks.every((wrap) => wrap.epoch === 2)).toBe(true);
    // 全受信者が同一の新 DEK を得て、それがエントリのコミットメント(§5.2)と一致する
    const deks: string[] = [];
    for (const wrap of body.deks) {
      const unwrapped = await verifyAndUnwrap({
        wrap,
        recipient: wrap.recipientUserId === owner.userId ? owner : member,
        signer: owner,
      });
      deks.push(Buffer.from(unwrapped).toString("hex"));
    }
    expect(new Set(deks).size).toBe(1);
    const newDek = await newEpochDekOf(body);
    const matched = await verifyDekCommitment({
      context: { suite: "maruhi/v1", projectId: built.projectId, environmentId: ENV_ID, epoch: 2 },
      dek: newDek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
    // 再暗号化: 全アクティブ変数が新エポック・次 version で push されている
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vbb"]);
    const pushedA = state.pushes.find((push) => push.variableId === "vaa");
    const pushedB = state.pushes.find((push) => push.variableId === "vbb");
    if (pushedA === undefined || pushedB === undefined) throw new Error("missing pushes");
    expect(pushedA.value.aad).toMatchObject({ epoch: 2, version: 2, variableId: "vaa" });
    expect(pushedB.value.aad).toMatchObject({ epoch: 2, version: 3, variableId: "vbb" });
    // 平文は保存されている(新 DEK で復号できる)
    expect(await decryptWire(newDek, pushedA.value)).toBe("postgres://example");
    expect(await decryptWire(newDek, pushedB.value)).toBe("key-abc");
    // prev は検証済み直前 version の signed bytes ハッシュ(§4.1 の連鎖)
    expect(pushedA.value.prevValueSigHashHex).toMatch(/^[0-9a-f]{64}$/);
    expect(env.logs.join("\n")).toContain("epoch 1 → 2");
    expect(env.logs.join("\n")).toContain("再暗号化 2 変数");
  });

  it("中断復旧: 複合受理後にクラッシュした状態から、エポックを進めず残りの再暗号化を再開する", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
      await variableAt({
        built: chainBase,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    // 2 変数目の push でサーバーが落ちる(= 再暗号化の途中でクラッシュ)
    const state = makeServer({
      built: chainBase,
      variables,
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onPush: (call) => (call === 1 ? { status: 503, bodyText: "unavailable" } : undefined),
    });
    const env = await startEnv(state.handlers, owner);

    // 1 回目: ローテーションは受理されたが、再暗号化は 1 変数で中断する
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "初回"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(1);
    const first = state.rotateBodies[0];
    if (first === undefined) throw new Error("rotate was not called");
    const newDek = await newEpochDekOf(first);

    // 2 回目(同じ設定・同じローカル床): エポックは 2 のまま、残り 1 変数だけを
    // 再暗号化する。rotate は**呼ばれない**(エポックを二重に進めない)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "再実行"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.pushes).toHaveLength(2);
    const resumed = state.pushes[1];
    if (resumed === undefined) throw new Error("resume push missing");
    expect(resumed.variableId).toBe("vbb");
    expect(resumed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, resumed.value)).toBe("key-abc");
    // 再開であることは明示される(--reason はチェーンに記録されない旨も)
    expect(env.errors.join("\n")).toContain("再暗号化が未完了");
    expect(env.logs.join("\n")).toContain("再暗号化を再開");
  });

  it("再開時に再暗号化済みの変数は対象にしない(最新値の epoch が現エポックのもの)", async () => {
    const variables = [
      // 既に epoch 2 へ再暗号化済み(宣言ヘッド = rotate エントリ自身)
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek2,
        epoch: 2,
        version: 2,
        plaintext: "postgres://example",
        headSeq: 3,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "再開"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("resume push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(dek2, pushed.value)).toBe("key-abc");
  });

  it("ChainHeadConflict(409)は再同期してエントリを再署名し、リトライする(§12-4)", async () => {
    const state = makeServer({
      built: chainBase,
      variables: [],
      deks: [
        await wrapDekFor({
          projectId: chainBase.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: owner,
          signer: owner,
        }),
      ],
      currentEpoch: 1,
      onRotate: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainBase.entries.length,
                currentHeadHashHex: chainBase.hashes[chainBase.hashes.length - 1],
              },
            }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "競合テスト"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(2);
    const [first, second] = state.rotateBodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // 再署名されている(タイムスタンプ・署名が変わる)が、生成済み DEK の
    // コミットメントとラップ集合は同一エポック向けのまま再利用される
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    expect(second.deks).toEqual(first.deks);
  });

  it("CAS リトライ中に他メンバーの並行ローテーションを検出したら、生成済み DEK を使わず中断する", async () => {
    const projectId = chainBase.projectId;
    const entries: ChainEntry[] = [...chainBase.entries];
    const hashes: string[] = [...chainBase.hashes];
    let chainCalls = 0;
    const rotateBodies: RotateBody[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${projectId}/chain`, () => {
        // 2 回目以降の同期では、他メンバーの rotate_epoch が積まれている
        if (chainCalls > 0 && entries.length === chainBase.entries.length) {
          entries.push(...chainRotated.entries.slice(chainBase.entries.length));
          hashes.push(...chainRotated.hashes.slice(chainBase.hashes.length));
        }
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 1,
          statement: envStatement,
          variables: [],
          deletedVariables: [],
          deks: [],
        },
      })),
      onRequest("POST", `/projects/${projectId}/environments/${ENV_ID}/rotate`, (request) => {
        rotateBodies.push(request.body as RotateBody);
        return {
          status: 409,
          json: {
            _tag: "ChainHeadConflict",
            currentHeadSeq: chainRotated.entries.length,
            currentHeadHashHex: chainRotated.hashes[chainRotated.hashes.length - 1],
          },
        };
      }),
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "並行"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("並行ローテーション");
    // 並行ローテーションを検出した時点で止まる(上限まで再送しない)
    expect(rotateBodies).toHaveLength(1);
  });

  it("再暗号化の VersionConflict は再取得で実態を確かめ、勝者が既に現エポックなら再暗号化不要として扱う", async () => {
    const stale = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "key-abc",
      headSeq: 2,
    });
    // 409 の後の再取得で見える「他メンバーが新エポックで書いた勝者」
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
    });
    const variables = [stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        // 並行 push の勝者が確定した状態にしてから 409 を返す
        variables[0] = winner;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "競合"], env.layer)).toBe(0);
    // 勝者は現エポックで受理済み = 再暗号化不要。上書きしに行かない
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("再暗号化不要 1 変数");
  });

  it("競合が解消しないまま残った再暗号化は、部分完了として警告し非ゼロで終わる", async () => {
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // 毎回 409。再取得しても最新値は旧エポックのまま = 再暗号化は完了しない
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "競合"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    // 「完了」の顔で終わらせない(サマリ自体が部分完了を名乗る)
    expect(env.logs.join("\n")).toContain("部分完了");
    expect(env.logs.some((line) => line.startsWith("完了:"))).toBe(false);
    const errors = env.errors.join("\n");
    expect(errors).toContain("1 変数の再暗号化が完了していません");
    // 旧エポックの DEK 保持者が現在値を読めるままであることを明示する
    expect(errors).toContain("epoch 2 未満の DEK のまま");
  });

  it("grant_server が有効なプロジェクトでは拒否する(Phase 2 未実装)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID]) },
    ]);
    const state = makeServer({ built, variables: [], deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "テスト"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("grant_server");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("reader はローテーションできない(member 以上 — §6.2)。値の取得より前に拒否する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = makeServer({ built, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "テスト"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reader");
    // pull(var.read の記録)にも到達していない
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
  });

  it("--reason 未指定は HTTP の書き込みを起こさずに拒否する", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("チェーンに存在しない環境へのローテーションは拒否する(create_environment 未観測)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", "staging", "--reason", "テスト"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("チェーン上に存在しません");
    expect(state.rotateBodies).toHaveLength(0);
  });
});
