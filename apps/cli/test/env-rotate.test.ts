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
  signChainEntry,
  SUITE_ID,
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
  valueHashOf,
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
let dek3: Uint8Array;
/** genesis + create_environment(epoch 1)。 */
let chainBase: BuiltChain;
/** 同一 genesis に rotate_epoch(epoch 2、DEK = dek2)が積まれた形。 */
let chainRotated: BuiltChain;
/** さらに rotate_epoch(epoch 3、DEK = dek3)まで積まれた形。 */
let chainRotatedTwice: BuiltChain;
let envStatement: WireDistributedEnvironmentStatement;
let servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  reader = await makeTestUser("user-reader-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  dek3 = crypto.getRandomValues(new Uint8Array(32));
  chainBase = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
  ]);
  chainRotated = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
  ]);
  chainRotatedTwice = await buildChain([
    { actor: owner, operation: genesisOp(owner) },
    { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    { actor: owner, operation: rotateEpochOp(ENV_ID, 3, dek3) },
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
  /** version > 1 の prev(既定はフィクスチャのダミー — 連鎖検査の negative 用)。 */
  readonly prevValueSigHashHex?: string;
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
      ...(input.prevValueSigHashHex === undefined
        ? {}
        : { prevValueSigHashHex: input.prevValueSigHashHex }),
    }),
  };
}

interface ServerOptions {
  readonly built: BuiltChain;
  readonly variables: PulledVariable[];
  /** 削除済み変数の tombstone(§12-5 — 保存・配布し続ける)。 */
  readonly deletedVariables?: WireDistributedVariableStatement[];
  readonly deks: WireRecipientDek[];
  readonly currentEpoch: number;
  /** rotate 呼び出しごとの差し込み応答(undefined = 正常受理)。 */
  readonly onRotate?: (call: number) => MockResponse | undefined;
  /**
   * **受理した後**に差し込む応答(応答の消失・502 のモデル化)。チェーンへの
   * 追記とラップの配布は起きるが、クライアントにはエラーだけが見える。
   */
  readonly onRotateAfterAccept?: (call: number) => MockResponse | undefined;
  /** push 呼び出しごとの差し込み応答(undefined = 正常受理)。 */
  readonly onPush?: (call: number, variableId: string) => MockResponse | undefined;
  /** pull 呼び出しごとの差し込み応答(undefined = 正常応答)。巡末の再走査を潰す用。 */
  readonly onPull?: (call: number) => MockResponse | undefined;
  /** chain 取得ごとの差し込み応答(undefined = 正常応答)。受理確認を潰す用。 */
  readonly onChain?: (call: number) => MockResponse | undefined;
  /**
   * rotate を試みた**後**に配信するチェーン(他メンバーの並行ローテーションの
   * モデル化)。timestamp は決定的なので、元のチェーンの延長として検証を通る。
   */
  readonly chainAfterRotateAttempt?: BuiltChain | undefined;
  /**
   * 受理した**後**に、さらに他メンバーのローテーションを 1 件追記する
   * (現エポックが目標エポックを追い越す形のモデル化)。
   */
  readonly appendRotateAfterAccept?: { readonly epoch: number; readonly dek: Uint8Array };
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
  const deletedVariables = options.deletedVariables ?? [];
  const deks = options.deks;
  const rotateBodies: RotateBody[] = [];
  const pushes: { variableId: string; value: WireDistributedValue }[] = [];
  let currentEpoch = options.currentEpoch;
  let rotateCalls = 0;
  let pushCalls = 0;
  let pullCalls = 0;
  let chainCalls = 0;

  /** 受理: エントリをチェーンへ追記し、同梱ラップを配布集合へ入れる。 */
  const acceptRotate = async (body: RotateBody): Promise<void> => {
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
  };

  /** 他メンバーのローテーションを 1 件、現在のチェーンの末尾へ追記する。 */
  const appendOtherRotate = async (target: {
    readonly epoch: number;
    readonly dek: Uint8Array;
  }): Promise<void> => {
    const operation = rotateEpochOp(ENV_ID, target.epoch, target.dek);
    const resolved = typeof operation === "function" ? await operation(projectId) : operation;
    const signed = await signChainEntry({
      entry: {
        ...resolved,
        suite: SUITE_ID,
        seq: entries.length + 1,
        prevHashHex: hashes[hashes.length - 1] ?? "",
        actor: { userId: owner.userId, keyFingerprintHex: owner.fingerprintHex },
        timestampMs: Date.now(),
      },
      signingKey: owner.sigKeyPair.privateKey,
    });
    if (!signed.ok) {
      throw new Error("failed to sign the concurrent rotate entry");
    }
    entries.push(signed.value);
    hashes.push(await computeChainEntryHash(signed.value));
    currentEpoch = target.epoch;
  };

  const handlers: MockHandler[] = [
    onRequest("GET", `/projects/${projectId}/chain`, () => {
      const injected = options.onChain?.(chainCalls);
      chainCalls += 1;
      return (
        injected ?? {
          status: 200,
          json: {
            projectId,
            entries,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        }
      );
    }),
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () => {
      const injected = options.onPull?.(pullCalls);
      pullCalls += 1;
      return (
        injected ?? {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            statement: envStatement,
            variables,
            deletedVariables,
            deks,
          },
        }
      );
    }),
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/environments/${ENV_ID}/rotate`
      ) {
        return null;
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      if (options.chainAfterRotateAttempt !== undefined) {
        // 他メンバーが先に(あるいは並行して)追記した形へ差し替える
        entries.splice(0, entries.length, ...options.chainAfterRotateAttempt.entries);
        hashes.splice(0, hashes.length, ...options.chainAfterRotateAttempt.hashes);
      }
      const injected = options.onRotate?.(rotateCalls);
      const injectedAfterAccept = options.onRotateAfterAccept?.(rotateCalls);
      rotateCalls += 1;
      if (injected !== undefined) {
        return injected;
      }
      await acceptRotate(body);
      if (options.appendRotateAfterAccept !== undefined) {
        await appendOtherRotate(options.appendRotateAfterAccept);
      }
      return (
        injectedAfterAccept ?? {
          status: 200,
          json: {
            environmentId: ENV_ID,
            currentEpoch,
            headSeq: entries.length,
            headHashHex: hashes[hashes.length - 1],
          },
        }
      );
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
      // vbb だけが 1 回目の実行中ずっと落ちる(巡内リトライでも回復しない)
      onPush: (call, variableId) =>
        variableId === "vbb" && call < 4 ? { status: 503, bodyText: "unavailable" } : undefined,
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
    // 再暗号化する。rotate は**呼ばれない**(エポックを二重に進めない)。
    // --reason 付き = ローテーションの要求なので、再開へ切り替わった実行は
    // 成功終了しない(スクリプトが「新エポックができた」と誤認しない)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "再実行"], env.layer)).toBe(1);
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
    // 再開は「要求されたローテーション」ではない: 新エポックを作っていない事実を
    // 完了報告が隠さない(退職者削除後の実行が成功扱いに見える形を塞ぐ)
    expect(env.logs.join("\n")).toContain("新しいエポックは作成していません");
    expect(env.errors.join("\n")).toContain("要求されたローテーションは実行していません");
    // 要求があった実行では「要求を実行せず切り替えた」と明示する
    expect(env.errors.join("\n")).toContain("要求されたローテーションは実行せず");
  });

  it("ローテーション後の push 失敗は、エポックが進んだ事実を部分完了として報告する", async () => {
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
    ];
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
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "初回"], env.layer)).toBe(1);
    // 複合は受理済み = エポックは進んでいる。生のエラーだけで終わらせず、
    // 「エポックが進み再暗号化が残っている」ことと再開手段を伝える
    expect(state.rotateBodies).toHaveLength(1);
    // 巡を使い切った(= 毎巡の再走査は通っている)ので、残数は実測である。
    // 「中断」とも「未確認を含む」とも言わない
    expect(env.logs.join("\n")).toContain("部分完了");
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
    expect(env.logs.join("\n")).not.toContain("未確認を含む");
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化が完了しませんでした");
    expect(errors).not.toContain("再暗号化が中断しました");
    expect(errors).toContain("再実行すると、エポックを進めずに残りから再開します");
  });

  it("部分完了の原因は最新の失敗を出す(解消済みの一時失敗が本当の原因を隠さない)", async () => {
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
    ];
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
      // 1 巡目は一時的な 503、以降は 404 を返し続ける(= いま塞いでいる原因)
      onPush: (call, variableId) =>
        call === 0
          ? { status: 503, bodyText: "unavailable" }
          : { status: 404, json: { _tag: "VariableNotFound", variableId } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "原因の鮮度"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain(
      "再暗号化が完了しませんでした: 変数 DATABASE_URL の再暗号化が 404 で拒否されました(並行削除の可能性)",
    );
    expect(errors).not.toContain("再暗号化が完了しませんでした: サーバー");
  });

  it("解消した一時失敗は原因として残さない(解けない競合は競合として報告する)", async () => {
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
      // vaa は 1 巡目だけ 502(2 巡目で成功)。vbb は最後まで競合し続ける
      onPush: (call, variableId) => {
        if (variableId === "vaa") {
          return call === 0 ? { status: 502, bodyText: "bad gateway" } : undefined;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "混在"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 残っているのは競合分だけなので、原因は競合である。解消済みの 502 を
    // 掲げると、調査が検証失敗・床違反の方向へ誤誘導される
    expect(errors).toContain("並行 push との競合が解消しませんでした");
    expect(errors).not.toContain("再暗号化が完了しませんでした");
    // 解消した失敗が起きた事実自体は警告として残す
    expect(errors).toContain("再暗号化の途中で失敗がありました");
  });

  it("巡末の再走査に到達できなかった場合だけ、残数を「未確認を含む」として報告する", async () => {
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
    ];
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
      onPush: () => ({ status: 503, bodyText: "unavailable" }),
      // 初回 pull は通し、巡末の再走査で落とす(= 実態を確かめられない)
      onPull: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "再走査失敗"], env.layer)).toBe(1);
    // 競合分が他メンバーの手で解決している可能性が残るので、断定しない
    expect(env.logs.join("\n")).toContain("未完了 1 変数(未確認を含む)");
    expect(env.errors.join("\n")).toContain("再暗号化が中断しました");
  });

  it("理由なしの再実行は再開だけを要求している(再暗号化済みの変数は対象にせず成功終了)", async () => {
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

    // 部分完了の案内は「再実行すると、エポックを進めずに残りから再開します」。
    // その案内どおりの実行(理由なし)は再開だけを要求しているので、やり残しが
    // なくなった時点で成功終了する(--reason 付きの実行だけが exit 1 になる)
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("resume push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(dek2, pushed.value)).toBe("key-abc");
    const errors = env.errors.join("\n");
    expect(errors).not.toContain("要求されたローテーションは実行していません");
    // 何も要求していない実行に「要求を実行せず切り替えた」と言わない
    expect(errors).toContain("再暗号化が未完了です。この再暗号化を再開します");
    expect(errors).not.toContain("要求されたローテーションは実行せず");
  });

  it("完了検証: 初回 pull 以降に他メンバーが作った変数も再暗号化してから完了とする", async () => {
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
    ];
    // 初回 pull と複合受理の窓で、他メンバーが旧エポックの変数を作成する
    const late = await variableAt({
      built: chainBase,
      variableId: "vlate",
      name: "LATE_VAR",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "late-value",
      headSeq: 2,
    });
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
      onRotate: () => {
        variables.push(late);
        return undefined;
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "窓"], env.layer)).toBe(0);
    // 対象集合になかった vlate も、完了検証の再走査で見つけて再暗号化する
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vaa", "vlate"]);
    const body = state.rotateBodies[0];
    if (body === undefined) throw new Error("rotate was not called");
    const newDek = await newEpochDekOf(body);
    const pushedLate = state.pushes.find((push) => push.variableId === "vlate");
    if (pushedLate === undefined) throw new Error("late push missing");
    expect(pushedLate.value.aad).toMatchObject({ epoch: 2, version: 2 });
    expect(await decryptWire(newDek, pushedLate.value)).toBe("late-value");
  });

  it("--new-epoch は未完了の再暗号化があっても新しいエポックを作る(§7 の全環境ローテーション用)", async () => {
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
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "退職者削除", "--new-epoch"], env.layer),
    ).toBe(0);
    // 再開ではなくローテーション: 新エポック 3 のエントリが作られ、
    // 旧エポックの値は中間エポックを経由せず一気に epoch 3 へ揃う
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3, version: 2 });
    expect(env.logs.join("\n")).toContain("epoch 2 → 3");
  });

  it("再開経路は --reason を要求しない(記録されないフィールドで復旧を阻まない)", async () => {
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
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
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
    // 409 の後の再取得で見える「他メンバーが新エポックで書いた勝者」。
    // 正直な並行 writer は検証済み version 1 へ prev を連鎖させている
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
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

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    // 勝者は現エポックで受理済み = 再暗号化不要。上書きしに行かない
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("再暗号化不要 1 変数");
  });

  it("409 の勝者が分岐した履歴へ連鎖していたら、prev を付け替えず中断する(§12-5)", async () => {
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
    // 勝者の prev が検証済み version 1 の signed bytes ハッシュを指していない
    // = 分岐した履歴(equivocation の証拠)。ここへ自分の署名で連鎖しない。
    // 勝者は現エポックなので床の規則 (c) には掛からず、かつ「再暗号化不要」の
    // 近道より前に整合検査が走ることも同時に固定する
    const forked = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-forked",
      headSeq: 3,
      prevValueSigHashHex: "ab".repeat(32),
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
        variables[0] = forked;
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 2 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "分岐"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("分岐した履歴への連鎖");
    // 中断でも収集済みの警告は失わない(床なしの但し書きは中断時こそ効く)
    expect(errors).toContain("欠落も検出できません");
    // 暗号学的証拠は「再実行で直る失敗」ではない: 部分完了 + 再開案内へ
    // 潰さず、調査を促す即時中断として出す(push 経路と同じ扱い)
    expect(errors).toContain("再実行では解消しない証拠です");
    expect(env.logs.join("\n")).not.toContain("部分完了");
  });

  it("最終巡の競合も再取得で確かめる(勝者が現エポックなら未完了と誤報しない)", async () => {
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
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
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
      // 最終巡(3 回目)の競合の直後に、他メンバーの現エポック書き込みが確定する
      onPush: (call) => {
        if (call === 2) {
          variables[0] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("再暗号化不要 1 変数");
    expect(env.errors.join("\n")).not.toContain("完了していません");
  });

  it("再暗号化中の並行削除(404)は警告して続行する(残りの変数を巻き添えにしない)", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "DOOMED",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "doomed-value",
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
    // 削除は tombstone(status deleted・metaVersion + 1)+ 全バージョン削除(§12-5)
    const tombstone = await statementFor({
      projectId: chainBase.projectId,
      environmentId: ENV_ID,
      variableId: "vaa",
      name: "DOOMED",
      author: owner,
      head: headOf(chainBase, 1),
      status: "deleted",
      metaVersion: 2,
    });
    const deletedVariables: WireDistributedVariableStatement[] = [];
    const state = makeServer({
      built: chainBase,
      variables,
      deletedVariables,
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
      onPush: (call, variableId) => {
        if (call !== 0) {
          return undefined;
        }
        // 再暗号化の直前に他メンバーが削除した
        variables.splice(
          variables.findIndex((variable) => variable.variableId === variableId),
          1,
        );
        deletedVariables.push(tombstone);
        return { status: 404, json: { _tag: "VariableNotFound", variableId } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "削除レース"], env.layer)).toBe(0);
    // 削除された変数は対象から外れ、残りは再暗号化される
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    expect(env.errors.join("\n")).toContain("並行削除");
    // 404 は中断原因として記録され、完了時は「起きたが解決した」warning になる
    // (部分完了の原因が「並行 push との競合」に化けない)
    expect(env.errors.join("\n")).toContain("404 で拒否されました");
  });

  it("404 を返し続けながら変数を配布し続けるサーバーでは、404 が部分完了の原因として出る", async () => {
    // 「404 で拒否するが、pull ではアクティブなまま配布する」= 削除でも競合でも
    // ない。原因を記録しないと部分完了の報告が既定文言(並行 push との競合)に
    // 化け、運用者が存在しない競合を追うことになる
    const variables = [
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
      onPush: (_call, variableId) => ({
        status: 404,
        json: { _tag: "VariableNotFound", variableId },
      }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "404 継続"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(env.logs.join("\n")).toContain("部分完了");
    expect(errors).toContain(
      "再暗号化が完了しませんでした: 変数 API_KEY の再暗号化が 404 で拒否されました(並行削除の可能性)",
    );
    expect(errors).not.toContain("並行 push との競合が解消しませんでした");
  });

  it("409 の申告より古い値しか配布されない応答は、勝者として採用せず中断する(§12-5)", async () => {
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
      // 「最新は version 9」と申告しながら、再取得では version 1 しか配布しない
      onPush: (call) =>
        call === 0
          ? { status: 409, json: { _tag: "VersionConflict", currentVersion: 9 } }
          : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "自己矛盾"], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("既知の最新 version");
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
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化が完了していません");
    // 旧エポックの DEK 保持者が現在値を読めるままであることを明示する
    expect(errors).toContain("epoch 2 未満の DEK のまま");
  });

  it("再開経路でも前進した検証ビューでガードを再適用する(pull 中に grant_server が有効化された場合)", async () => {
    // 4 エントリ目に grant_server。初回の同期では 3 エントリしか見えず、
    // 環境ステートメントが seq 4 を宣言する(future head)ため有界再同期が走る
    const granted = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      { actor: owner, operation: await grantServerOp([ENV_ID]) },
    ]);
    const futureEnvStatement = await environmentStatementFor({
      projectId: granted.projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: owner,
      head: headOf(granted, 4),
    });
    const common = { projectId: granted.projectId, environmentId: ENV_ID };
    const variables = [
      await variableAt({
        built: granted,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "key-abc",
        headSeq: 2,
      }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${granted.projectId}/chain`, () => {
        // 初回は grant_server を含まない 3 エントリ、再同期で 4 エントリ
        const count = chainCalls === 0 ? 3 : 4;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: granted.projectId,
            entries: granted.entries.slice(0, count),
            headSeq: count,
            headHashHex: granted.hashes[count - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${granted.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 2,
          statement: futureEnvStatement,
          variables,
          deletedVariables: [],
          deks: [],
        },
      })),
      (request) => {
        if (request.method === "POST") {
          pushPaths.push(request.path);
        }
        return null;
      },
    ];
    const server = await MockServer.start(handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: granted.projectId });
    void common;

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("grant_server");
    // 再開経路でも書き込みには進んでいない
    expect(pushPaths).toHaveLength(0);
  });

  it("サーバーの EpochConflict 申告は原因を断定せず、再走査のチェーン検証に委ねる", async () => {
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
      // チェーンは epoch 2 のままなのに、サーバーは毎回エポック競合を申告する
      onPush: () => ({ status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "申告"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 申告を鵜呑みにして「他メンバーが並行ローテーションした」と報告しない。
    // チェーン導出の現エポックが変わっていない以上、これは応答の矛盾である
    expect(errors).not.toContain("並行ローテーション");
    expect(errors).toContain("サーバー応答とチェーンの矛盾");
    expect(errors).toContain("再実行では解消しません");
  });

  it("EpochConflict の申告があっても、再走査で全変数が揃っていれば完了とする(警告は残す)", async () => {
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
    // 申告の裏で、他メンバーが**同じエポック**で書き切った
    const winner = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-def",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
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
        variables[0] = winner;
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    // 再暗号化の完否を決めるのは検証済みの実態であって、サーバーの自己申告では
    // ない。揃っている事実を「応答が矛盾している」中断で覆い隠さない
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(state.pushes).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("再暗号化不要 1 変数");
    const errors = env.errors.join("\n");
    // 矛盾した申告自体は調査対象として残す(中断はしない)
    expect(errors).toContain("サーバー応答とチェーンの矛盾");
    expect(errors).not.toContain("再実行では解消しません");
  });

  it("EpochConflict を申告された変数が解消していれば、残りは普通の部分完了として案内する", async () => {
    // 申告された vaa は他メンバーが現エポックで書き切って解消。残っているのは
    // 別理由(502)の vbb だけ — ここで「再実行では解消しません」と断じると、
    // 再実行で片付く状態なのに再開の案内も残数の報告も届かなくなる
    const staleA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "postgres://example",
      headSeq: 2,
    });
    const winnerA = await variableAt({
      built: chainRotated,
      variableId: "vaa",
      name: "DATABASE_URL",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "postgres://example",
      headSeq: 3,
      prevValueSigHashHex: await valueHashOf(staleA.value, owner.userId),
    });
    const variables = [
      staleA,
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
      onPush: (_call, variableId) => {
        if (variableId === "vaa") {
          // 申告と同時に、他メンバーの現エポック書き込みが確定する
          variables[0] = winnerA;
          return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
        }
        return { status: 502, bodyText: "bad gateway" };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 矛盾した申告自体は調査対象として残す(が、中断はしない)
    // 「揃っていることを確認した」とは言わない: 再走査が示すのは未完了集合に
    // 残っていないことだけで、現エポックで書かれたのか削除されたのかは分からない
    expect(errors).toContain("申告された変数は再走査の未完了集合に残っていない");
    // 中断していれば部分完了の報告経路へ到達しない = 残数も再開案内も出ない
    expect(env.logs.join("\n")).toContain("部分完了");
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
    expect(errors).toContain("再実行すると、エポックを進めずに残りから再開します");
  });

  it("EpochConflict でチェーンが実際に進んでいれば、矛盾ではなく並行ローテーションとして扱う", async () => {
    const rotatedTwice = chainRotatedTwice;
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
    const deks = [
      await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
      await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
    ];
    let chainCalls = 0;
    const pushPaths: string[] = [];
    const handlers: MockHandler[] = [
      onRequest("GET", `/projects/${chainBase.projectId}/chain`, () => {
        // 初回同期は epoch 2。再暗号化の途中で他メンバーが epoch 3 へ進める
        const built = chainCalls === 0 ? chainRotated : rotatedTwice;
        chainCalls += 1;
        return {
          status: 200,
          json: {
            projectId: chainBase.projectId,
            entries: built.entries,
            headSeq: built.entries.length,
            headHashHex: built.hashes[built.hashes.length - 1],
          },
        };
      }),
      onRequest("GET", `/projects/${chainBase.projectId}/environments/${ENV_ID}/pull`, () => ({
        status: 200,
        json: {
          environmentId: ENV_ID,
          currentEpoch: 2,
          statement: envStatement,
          variables,
          deletedVariables: [],
          deks,
        },
      })),
      (request) => {
        if (request.method !== "POST" || !request.path.endsWith("/versions")) {
          return null;
        }
        pushPaths.push(request.path);
        return { status: 409, json: { _tag: "EpochConflict", currentEpoch: 3 } };
      },
    ];
    const env = await startEnv(handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 強制再同期でチェーンが実際に進んでいることを確認したので、これは
    // サーバーの矛盾ではない(良性のレースを不正と誤認しない)
    expect(errors).toContain("並行ローテーション");
    expect(errors).not.toContain("サーバー応答とチェーンの矛盾");
    expect(pushPaths).toHaveLength(1);
  });

  it("--new-epoch は復号できない値があってもエポックを進める(失効を優先する — §7)", async () => {
    // 退職者削除の実行。開けない値が 1 つあるだけでエポックが 1 つも進まないと、
    // 削除されたメンバーの旧 DEK が**全変数**に対して有効なまま残る
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      // epoch 1 の自分宛ラップが無い
      deks: [await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "退職者削除", "--new-epoch"], env.layer),
    ).toBe(1);
    // **エポックは進んでいる**(失効そのものは達成される)
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(3);
    // 開ける値は新エポックへ、開けない値は未完了として報告する
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化できない値が残っています");
    expect(env.logs.join("\n")).toContain("部分完了");
  });

  it("複合の送信が失敗しても、受理されていれば「エポックは進んだ」と報告する", async () => {
    // 応答の消失(502 / タイムアウト)。DO は受理済みなのにクライアントには
    // 転送エラーしか見えない — 素のエラーで終わると「何も起きなかった」と
    // 読ませ、エポックだけ進んで再暗号化 0 件という最も危険な状態を隠す
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
    ];
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
      // 受理はする(チェーンへ追記される)が、応答は 502 で返す
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "応答消失"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("ローテーション自体は受理されています");
    expect(errors).toContain("再暗号化から再開します");
  });

  it("1 つも再暗号化できないならエポックを進めない(空回りで失効にならない)", async () => {
    // 自分宛のラップが 1 つも無いメンバー(あるいは全ラップを落とす応答)。
    // ここでエポックだけ進めると、全ての現在値が旧エポックの DEK のまま残り、
    // 失効にならないまま「ローテーションした」記録だけがチェーンに載る
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
    ];
    const state = makeServer({ built: chainBase, variables, deks: [], currentEpoch: 1 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "空回り"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化できる値が 1 つもありません");
    expect(errors).toContain("失効になりません");
  });

  it("送信失敗の裏で進んでいたのが他メンバーのローテーションなら、そう伝える", async () => {
    // epoch は目標値に達しているが、載っているのは他メンバーの DEK
    // コミットメント — 自分の失効ローテーションは受理されていない
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
      // 送信は 502。裏では別メンバーが epoch 2 へローテーション済みにする
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      chainAfterRotateAttempt: chainRotated,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "他メンバー"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("他メンバーのローテーション");
    expect(errors).toContain("この実行の分は受理されていません");
    // 自分の分が受理されたと読ませない
    expect(errors).not.toContain("このローテーション自体は受理されています");
  });

  it("受理後にさらに他メンバーが進めていても、自分の分の受理を見落とさない", async () => {
    // 受理 → 応答消失 → 確認までの間に別メンバーがさらにローテーション。
    // 現エポックの一致で判定すると「受理されていません」と誤報告してしまうが、
    // コミットメントは全エポック分が残るので自分の分は見分けられる
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
      // 受理はする(自分のエントリがチェーンに載る)が応答は 502。
      // その後さらに他メンバーが epoch 3 まで進める
      onRotateAfterAccept: () => ({ status: 502, bodyText: "bad gateway" }),
      appendRotateAfterAccept: { epoch: 3, dek: dek3 },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "追い越し"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("このローテーション自体は受理されています");
    expect(errors).toContain("再暗号化から再開します");
    expect(errors).not.toContain("受理されていません");
  });

  it("削除済み環境への rotate(404)は確定した拒否として扱い、再実行を勧めない", async () => {
    // サーバー自身のエラー本文で拒否された = 受理の有無は確定している。
    // 受理確認のプローブ(チェーンの二重取得)も要らず、§7 の中断メッセージに
    // 「そのまま再実行できます」を足してもいけない(404 は決定的で再発する)
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
      onRotate: () => ({
        status: 404,
        json: { _tag: "EnvironmentNotFound", environmentId: ENV_ID },
      }),
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    const chainCallsBefore = server.requests.filter((request) =>
      request.path.endsWith("/chain"),
    ).length;
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "削除済み"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // §7 の専用メッセージが出る(汎用の「環境が見つかりません」に潰さない)
    expect(errors).toContain("選択的なローテーション阻止の可能性");
    expect(errors).not.toContain("そのまま再実行できます");
    expect(errors).not.toContain("受理されています");
    // 受理確認のためのチェーン再取得をしていない(初回同期の 1 回だけ)
    const chainCalls = server.requests.filter((request) => request.path.endsWith("/chain")).length;
    expect(chainCalls - chainCallsBefore).toBe(1);
  });

  it("受理されたか確認できない場合は、エポックが進んだ可能性を明示する", async () => {
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
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
      // 確認のためのチェーン再取得も落ちる(通信障害が続いている)
      onChain: (call) => (call === 0 ? undefined : { status: 503, bodyText: "unavailable" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "確認不能"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("エポックが既に 2 へ進んでいる可能性があります");
    expect(errors).toContain("通信を復旧したうえで");
  });

  it("複合の送信が失敗し、受理もされていなければ「そのまま再実行できる」と伝える", async () => {
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
      onRotate: () => ({ status: 502, bodyText: "bad gateway" }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "未達"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("受理されていません");
    expect(errors).toContain("そのまま再実行できます");
  });

  it("ラップを持っているのに開けない値は、差し替えの疑いとして即時中断する", async () => {
    // 自分宛ラップはあるのに復号が失敗する = 暗号文の差し替え or 検証済みビューとの
    // 不整合。良性の「ラップ待ち」に潰して --new-epoch で踏み越えるよう案内しては
    // ならない(pull / run と同じく即時中断する)。
    // 現エポックの値だが暗号化に使われた鍵が違う(= AEAD 認証が通らない)形
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "CORRUPT",
        dek: dek1,
        epoch: 2,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 3,
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

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "通常"], env.layer)).toBe(1);
    expect(state.rotateBodies).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("サーバーによる差し替えの可能性");
    // 良性の欠落として扱わない = 踏み越える手段を案内しない
    expect(errors).not.toContain("--new-epoch を付けて実行してください");
    expect(errors).not.toContain("ラップを持つメンバーによる再実行");
  });

  it("巡の途中で現れた開けない値も、部分完了へ格下げせず証拠として中断する", async () => {
    // 上のケースは初回 pull(ローテーション前)なので、失敗させても失うのは
    // 「まだ始めていない実行」だけである。危ないのは**エポックが進んだ後**に
    // 現れた場合で、ここを再走査の一時失敗と同じ扱いにすると「未確認を含む
    // 部分完了 — 再実行すれば再開します」に化ける(差し替えの兆候が、
    // 何度でも同じ結果を返す再実行の案内に潰される)
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
    ];
    // 初回 pull には現れず、複合受理の後(= 巡末の再走査)にだけ現れる値。
    // 署名は妥当だが暗号化に使われた鍵が違う(= AEAD 認証が通らない)
    const tampered = await variableAt({
      built: chainBase,
      variableId: "vtamper",
      name: "TAMPERED",
      dek: dek3,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
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
      onRotate: () => {
        variables.push(tampered);
        return undefined;
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "巡中"], env.layer)).toBe(1);
    // 初回 pull のケースと違い、ここではローテーション自体は起きている
    expect(state.rotateBodies).toHaveLength(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("サーバーによる差し替えの可能性");
    expect(errors).toContain("再実行では解消しない証拠です");
    // 「再実行すれば片付く」系の案内へ格下げしない
    expect(errors).not.toContain("残りから再開します");
    expect(errors).not.toContain("未確認を含む");
  });

  it("復号できない値が 1 つあっても、再開は開ける分を再暗号化する(epoch は既に進んでいる)", async () => {
    // §12-7 の過渡状態にいるメンバー: epoch 2 のラップは持つが epoch 1 は持たない
    // (ローテーション後に追加された / epoch 1 の再ラップが未登録)。従来は
    // decryptTargets の全か無かで中断し、開ける値まで旧 DEK のまま残していた
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // epoch 1 の自分宛ラップが無い(epoch 2 / 3 のみ)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
    });
    const env = await startEnv(state.handlers, owner);

    // 開けなかった 1 件は未完了として報告されるが、開ける 1 件は押される
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes.map((push) => push.variableId)).toEqual(["vbb"]);
    const pushed = state.pushes[0];
    if (pushed === undefined) throw new Error("push missing");
    expect(pushed.value.aad).toMatchObject({ epoch: 3 });
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化できない値が残っています");
    expect(errors).toContain("エポック 1 の DEK が配布されていません");
    // 原因が既定文言(競合)に化けない
    expect(errors).not.toContain("並行 push との競合が解消しませんでした");
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
    // 同じ変数の警告は 1 回だけ(再開経路と巡末の再走査で文面が割れると
    // dedupeWarnings が別物として通してしまう)
    expect(
      env.errors.filter((line) => line.includes("再暗号化できない値が残っています")),
    ).toHaveLength(1);
  });

  it("409 以外の失敗で拾い直した勝者にも整合検査を適用する(分岐 prev への連鎖を防ぐ)", async () => {
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
    // 502 の後の再走査で見える「現エポックだが prev が繋がらない後継」
    const forked = await variableAt({
      built: chainRotated,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 2,
      plaintext: "key-forked",
      headSeq: 3,
      prevValueSigHashHex: "ab".repeat(32),
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
      // 409 ではなく一時的な失敗(この変数は conflicted 集合に入らない)
      onPush: (call) => {
        if (call !== 0) {
          return undefined;
        }
        variables[0] = forked;
        return { status: 502, bodyText: "bad gateway" };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    expect(state.pushes).toHaveLength(0);
    expect(env.errors.join("\n")).toContain("分岐した履歴への連鎖");
  });

  it("床のない実行では、応答から落とされた変数を検出できない旨を警告する", async () => {
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
    ];
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
    });
    const env = await startEnv(state.handlers, owner);

    // 初回同期(床なし): 対象集合の出所はサーバー応答しかなく、一貫した
    // 欠落は検出できない。失効目的のローテーションではこれを黙らない
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "床なし"], env.layer)).toBe(0);
    expect(env.errors.join("\n")).toContain("欠落も検出できません");

    // 2 回目(床あり)では出ない
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "床あり"], env.layer)).toBe(0);
    const secondRunErrors = env.errors.filter((line) => line.includes("欠落も検出できません"));
    expect(secondRunErrors).toHaveLength(1);
  });

  it("受理済みの自分の書き込みを押し戻す応答は、床に頼らず巻き戻しとして検出する", async () => {
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
    const other = await variableAt({
      built: chainRotated,
      variableId: "vcc",
      name: "OTHER",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "other-value",
      headSeq: 2,
    });
    const variables = [stale, other];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [
        await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
      ],
      currentEpoch: 2,
      // vcc は競合させて 2 巡目へ持ち込む。vbb の受理済み書き込み(version 2)は
      // 反映せず、再走査で version 1 のまま配布し続ける = 押し戻し
      onPush: (_call, variableId) => {
        if (variableId === "vbb") {
          // 受理はするが保存はしない(サーバーが自分の書き込みを握り潰す形)
          return {
            status: 200,
            json: { variableId, version: 2, epoch: 2 },
          };
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);
    // 受理済み push の床コミットだけを失敗させる: 床は SHOULD であり、書けない
    // 場合(破損・権限)でもこの検出が成立することを固定する
    env.failFloorPushCommits();

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // 床がなくても、自分が署名した version からの後退は巻き戻しの証拠
    expect(env.errors.join("\n")).toContain("既知の最新 version(2)より古く、不整合");
  });

  it("巡を跨いで同じ SHOULD 警告を重複表示しない", async () => {
    // 非 NFC 名(合成済みでない Á)は毎 pull で警告が出る — 3 巡しても 1 行
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vbb",
        name: "ÁPI_KEY",
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
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "重複"], env.layer)).toBe(1);
    const nfcWarnings = env.errors.filter((line) => line.includes("NFC 正規形ではありません"));
    expect(nfcWarnings).toHaveLength(1);
  });

  it("1 変数の恒久的な失敗が、他の変数の再暗号化を巻き添えにしない", async () => {
    const variables = [
      await variableAt({
        built: chainBase,
        variableId: "vaa",
        name: "POISON",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "poison-value",
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
      await variableAt({
        built: chainBase,
        variableId: "vcc",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
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
      // 先頭の 1 変数だけが常に失敗する(順序が安定なため、中断すると
      // 後続の変数はどの再実行でも到達できなくなる)
      onPush: (_call, variableId) =>
        variableId === "vaa" ? { status: 502, bodyText: "bad gateway" } : undefined,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "毒変数"], env.layer)).toBe(1);
    // 後続の 2 変数は新エポックへ移っている(部分完了は毒変数のみ)
    expect(state.pushes.map((push) => push.variableId).toSorted()).toEqual(["vbb", "vcc"]);
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
  });

  it("押せる対象が尽きて打ち切った巡でも、原因を競合に潰さず報告する", async () => {
    // 競合していた vbb が 2 巡目で他メンバーに書き切られ、残るのは開けない
    // vaa だけ。押せる対象が尽きるので stalledOnUndecryptable で打ち切るが、
    // このとき原因を既定文言(競合)に落とすと、存在しない並行 writer を
    // 追わせることになる(最終巡まで回る形は次のテストが担当する)
    const undecryptable = await variableAt({
      built: chainRotatedTwice,
      variableId: "vaa",
      name: "OLD_ONE",
      dek: dek1,
      epoch: 1,
      version: 1,
      plaintext: "unreadable-here",
      headSeq: 2,
    });
    const stale = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek2,
      epoch: 2,
      version: 1,
      plaintext: "key-abc",
      headSeq: 3,
    });
    const winner = await variableAt({
      built: chainRotatedTwice,
      variableId: "vbb",
      name: "API_KEY",
      dek: dek3,
      epoch: 3,
      version: 2,
      plaintext: "key-def",
      headSeq: 4,
      prevValueSigHashHex: await valueHashOf(stale.value, owner.userId),
    });
    const variables = [undecryptable, stale];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // epoch 1 の自分宛ラップが無い(= vaa は開けない)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb は競合し続けるが、2 巡目の後に他メンバーが現エポックで書き切る
      onPush: (call) => {
        if (call === 1) {
          variables[1] = winner;
        }
        return { status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } };
      },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("エポック 1 の DEK が配布されていません");
    expect(errors).not.toContain("並行 push との競合が解消しませんでした");
    expect(env.logs.join("\n")).toContain("未完了 1 変数");
  });

  it("最終巡(復号しない巡)でも、開けない値をラップの有無だけで原因として拾う", async () => {
    // 押せる対象(vbb)が最後まで競合し続けるので打ち切りは起きず、巡を使い切る。
    // 最終巡の再走査は**復号しない**(押すことのない平文を作らない)ため
    // targets は空になるが、自分宛ラップの有無は Map 参照だけで分かる —
    // ここを飛ばすと、開けない vaa が残っているのに原因が競合の既定文言に化ける
    const variables = [
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vaa",
        name: "OLD_ONE",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "unreadable-here",
        headSeq: 2,
      }),
      await variableAt({
        built: chainRotatedTwice,
        variableId: "vbb",
        name: "API_KEY",
        dek: dek2,
        epoch: 2,
        version: 1,
        plaintext: "key-abc",
        headSeq: 3,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotatedTwice,
      variables,
      // epoch 1 の自分宛ラップが無い(= vaa は開けない)
      deks: [
        await wrapDekFor({ ...common, epoch: 2, dek: dek2, recipient: owner, signer: owner }),
        await wrapDekFor({ ...common, epoch: 3, dek: dek3, recipient: owner, signer: owner }),
      ],
      currentEpoch: 3,
      // vbb は最後まで競合し続ける(= 毎巡 push する対象が残り、打ち切らない)
      onPush: () => ({ status: 409, json: { _tag: "VersionConflict", currentVersion: 1 } }),
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(1);
    // 受理された push は無い(全巡 409)。vbb は毎巡「押せる対象」として残るので
    // 打ち切りは起きず、最終巡の復号なし再走査まで到達する
    expect(state.pushes).toHaveLength(0);
    const errors = env.errors.join("\n");
    expect(errors).toContain("エポック 1 の DEK が配布されていません");
    expect(errors).not.toContain("並行 push との競合が解消しませんでした");
    expect(env.logs.join("\n")).toContain("未完了 2 変数");
  });

  it("現エポックの DEK が無くて再開できない場合、--new-epoch の逃げ道を案内する", async () => {
    // 中断されたローテーションの後に加わったメンバー: 現エポック(2)のラップが
    // まだ自分宛に無い。再開はできないが --new-epoch なら成立する(自分で新しい
    // DEK を作るので現エポックの DEK は要らない)— 案内しないと失効が詰む
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const common = { projectId: chainBase.projectId, environmentId: ENV_ID };
    const state = makeServer({
      built: chainRotated,
      variables,
      deks: [await wrapDekFor({ ...common, epoch: 1, dek: dek1, recipient: owner, signer: owner })],
      currentEpoch: 2,
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "退職者削除"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("再暗号化を再開できません");
    expect(errors).toContain("--new-epoch を付けて実行してください");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("恒久的に失敗する変数の理由は、原因欄に出なくても警告として残す", async () => {
    // 原因として掲げられるのは 1 件だけ。2 件目以降を落とすと、恒久的に失敗する
    // 変数(値が大きすぎる等)の理由がどの実行でも表に出ず、旧エポックのまま
    // 取り残され続ける
    const common = { built: chainBase, dek: dek1, epoch: 1, version: 1, headSeq: 2 } as const;
    const variables = [
      await variableAt({ ...common, variableId: "vaa", name: "TRANSIENT", plaintext: "a" }),
      await variableAt({ ...common, variableId: "vbb", name: "TOO_BIG", plaintext: "b" }),
    ];
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
      onPush: (_call, variableId) =>
        variableId === "vaa"
          ? { status: 502, bodyText: "bad gateway" }
          : { status: 413, json: { _tag: "ValueTooLarge", limitBytes: 8 } },
    });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "混在失敗"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    // 変数名つきで両方の理由が残る(原因欄に出るのは片方だけでも)
    expect(errors).toContain("変数 TRANSIENT の再暗号化に失敗しました");
    expect(errors).toContain("変数 TOO_BIG の再暗号化に失敗しました");
  });

  it("開ける現在値が 1 つも無いなら、満たせない --new-epoch を勧めない", async () => {
    // 自分宛ラップが 1 つも無い場合、--new-epoch へ進んでも
    // ensureRotationIsUseful で弾かれる。勧めると 2 つの矛盾するエラーの間で
    // 利用者を往復させることになる
    const variables = [
      await variableAt({
        built: chainRotated,
        variableId: "vaa",
        name: "DATABASE_URL",
        dek: dek1,
        epoch: 1,
        version: 1,
        plaintext: "postgres://example",
        headSeq: 2,
      }),
    ];
    const state = makeServer({ built: chainRotated, variables, deks: [], currentEpoch: 2 });
    const env = await startEnv(state.handlers, owner);

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "退職者削除"], env.layer)).toBe(1);
    const errors = env.errors.join("\n");
    expect(errors).toContain("開ける現在値が 1 つも無いため");
    expect(errors).not.toContain("--new-epoch を付けて実行してください");
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("操作に適用されないオプション・綴り間違いは黙って捨てずに拒否する", async () => {
    // 書き方そのものの誤り(未宣言オプション・boolean への値・余分な位置引数・
    // 位置引数のオプション化)は全コマンド共通の検査が持つ(args.test.ts)。
    // ここでは env 固有の適用可否と、rotate でも同じく落ちることを固定する
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // 綴り間違い(放置すると「必ず新エポック」の意図が黙って弱い再開経路へ落ちる)
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epochs"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("不明なオプション");
    // create 専用のオプションを rotate に付けた場合も拒否する(env 固有の検査)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--name", "n"], env.layer)).toBe(
      2,
    );
    expect(env.errors.join("\n")).toContain("env rotate では使えません");
    // boolean への値指定は拒否する。gunshi は値を読まずに true にするため、
    // 放置すると書いたことと逆(必ず新エポック)が起き、チェーンは append-only
    // なので取り消せない。インライン形(=)と空白区切り形の両方を塞ぐ
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch=false"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--new-epoch は値を取りません");
    // 空白区切りは「フラグ有効 + 余分な位置引数」になる(gunshi は値を消費しない)
    expect(
      await runCli(["env", "rotate", ENV_ID, "--reason", "x", "--new-epoch", "false"], env.layer),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--new-epoch は値を取りません");
    // 位置引数の名前をオプションとして書いても gunshi は値を捨てる
    // (`env rotate dev --environment-id other` は dev をローテーションする)。
    // 環境 ID はチェーン履歴全体で一意(§6.2)なので取り違えは永久に焼き付く
    const beforeSwap = server.requests.length;
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--environment-id", "other-env"],
        env.layer,
      ),
    ).toBe(2);
    expect(env.errors.join("\n")).toContain("--environment-id は位置引数です");
    // 取り違えの検査は通信より前(誤った ID で var.read を残さない)
    expect(server.requests.length).toBe(beforeSwap);
    // 操作専用でない宣言済みオプション(--project 等)は拒否しない。許可集合は
    // 引数表から導くので、手書きの一覧との二重管理で弾かれることがない
    // (「拒否されない」ではなく**成功する**ことを固定する — 検査の緩みが
    // ローテーション自体の失敗に化けても気付けるように)
    expect(
      await runCli(
        ["env", "rotate", ENV_ID, "--reason", "x", "--project", chainBase.projectId],
        env.layer,
      ),
    ).toBe(0);
    // 拒否された例では HTTP は一切起きていない(最後の 1 例だけが通信する)
    expect(server.requests.length).toBeGreaterThan(0);
  });

  it("対象環境が grant_server の開示スコープに入っていれば拒否する(Phase 2 未実装)", async () => {
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

  it("別環境だけを開示した grant_server は、この環境の失効ローテーションを止めない(§7)", async () => {
    // エポックは環境ごとに独立に進む(§3)。dev だけを開示した grant が prod の
    // ローテーションを塞ぐと、退職者削除に必要な唯一の手段が別環境の設定で
    // 止まる — スコープ(§6.2 の「対象環境の部分集合」)で判定する
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp(["other-env"]) },
    ]);
    const state = makeServer({
      built,
      variables: [],
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

    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "退職者削除"], env.layer)).toBe(0);
    expect(state.rotateBodies).toHaveLength(1);
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

  it("未完了がなく --reason もない実行は、確認だけして何も書き込まない", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // 部分完了の案内が勧める再実行の着地点。ここで --reason を要求すると、
    // 案内どおりに再実行した利用者が理由を求められ、指定すると二度目の
    // ローテーションになってしまう
    expect(await runCli(["env", "rotate", ENV_ID], env.layer)).toBe(0);
    expect(env.logs.join("\n")).toContain("確認完了");
    expect(env.logs.join("\n")).toContain("新しいエポックを作るには --reason");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("--new-epoch に --reason が無い実行は、値を取りに行く前に落とす(var.read を残さない)", async () => {
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
    ];
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
    });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // --new-epoch は必ずエントリを署名する = 理由が必須。満たしようのない
    // 引数検査のために全変数の暗号文を取りに行き、変数ごとの var.read を
    // 監査ログへ残さない(ensureRotatable と同じ規律)
    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("--reason にローテーションの理由を指定してください");
    expect(server.requests.filter((request) => request.path.endsWith("/pull"))).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("空の --reason は「確認だけ」に潰さず落とす(要求したのに何もしない成功終了を作らない)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    // `--reason "$UNSET_VAR"` の形。未指定と同一視すると、退職者削除の
    // スクリプトが「新エポックができた」と受け取ったまま何も送られない。
    // **空文字列**は gunshi が undefined に落とすので、指定の有無は
    // ctx.explicit で判定しないと未指定と区別できない(空白のみの値は
    // truthy なので通ってしまい、この経路を素通りさせていた)
    // 空文字列は共通の引数検査が usage エラー(2)で落とす(「未指定」と
    // 区別できない値を既定へフォールバックさせない — args.ts)
    for (const empty of [["--reason", ""], ["--reason="]]) {
      expect(await runCli(["env", "rotate", ENV_ID, ...empty], env.layer)).toBe(2);
      expect(env.errors.join("\n")).toContain("オプション --reason の値が空です");
      expect(env.logs.join("\n")).not.toContain("確認完了");
    }
    // 空白だけの理由は値としては非空なのでコマンド本体まで進むが、書き方の
    // 誤りであることは変わらない(終了コードは同じ 2)
    expect(await runCli(["env", "rotate", ENV_ID, "--reason", "  "], env.layer)).toBe(2);
    expect(env.errors.join("\n")).toContain("--reason が空です");
    expect(state.rotateBodies).toHaveLength(0);
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("新しいエポックを作る経路では --reason を要求する(--new-epoch 指定時も)", async () => {
    const state = makeServer({ built: chainBase, variables: [], deks: [], currentEpoch: 1 });
    const server = await MockServer.start(state.handlers);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: chainBase.projectId });

    expect(await runCli(["env", "rotate", ENV_ID, "--new-epoch"], env.layer)).toBe(1);
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
