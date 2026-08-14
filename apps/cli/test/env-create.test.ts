// 環境作成の複合リクエスト(§12-4)のテスト: create_environment エントリ
// (エポック 1 のコミットメント込み — §5.2/§6.2)の署名・親ヘッド CAS、
// ラップ集合 = 検証済み現メンバー集合との厳密一致(§6.3 ゴーストメンバー対策の
// クライアント側)、署名者 = 呼び出し主体(§5.1)、ChainHeadConflict の
// 再署名リトライ、grant_server 有効時の拒否、チェーン観測済み ID の早期拒否。

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekCommitment,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  createEnvironmentOp,
  genesisOp,
  grantServerOp,
  hexBytes,
  makeTestUser,
  removeMemberOp,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

/** 複合作成リクエストのボディ(api-schema の environments.create payload)。 */
interface CompositeCreateBody {
  readonly parentHeadHashHex: string;
  readonly entry: ChainEntry & { readonly op: "create_environment" };
  readonly statement: {
    readonly environmentId: string;
    readonly name: string;
    readonly status: string;
    readonly metaVersion: number;
    readonly prevMetaSigHashHex: string;
    readonly chainHeadHashHex: string;
    readonly chainHeadSeq: number;
    readonly signatureHex: string;
  };
  readonly deks: WrappedDek[];
}

let servers: MockServer[] = [];

afterEach(async () => {
  await Promise.all(servers.map((server) => server.close()));
  servers = [];
});

async function startEnv(
  projectId: string,
  handlers: readonly MockHandler[],
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start(handlers);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

function chainHandler(
  projectId: string,
  built: Awaited<ReturnType<typeof buildChain>>,
): MockHandler {
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

/** 1 ラップの §5.1 署名検証(署名者 = owner)と受信者側の unwrap を行い、DEK を返す。 */
async function verifyAndUnwrapWrap(input: {
  readonly wrap: WrappedDek;
  readonly projectId: string;
  readonly signer: TestUser;
  readonly recipient: TestUser;
}): Promise<Uint8Array> {
  const { wrap, projectId, signer, recipient } = input;
  expect(wrap.epoch).toBe(1);
  expect(wrap.recipientEncPubHex).toBe(recipient.encPubHex);
  const signerKey = await importSigningPublicKey(hexBytes(signer.sigPubHex));
  if (!signerKey.ok) {
    throw new Error("sig key import failed");
  }
  const verified = await verifyDekWrapSignature({
    context: {
      suite: wrap.suite,
      projectId,
      environmentId: "staging",
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
      projectId,
      environmentId: "staging",
      epoch: 1,
      recipientUserId: wrap.recipientUserId,
    },
  });
  if (!dek.ok) {
    throw new Error("unwrap failed");
  }
  return dek.value;
}

describe("maruhi env create", () => {
  it("複合リクエスト: 署名済み create_environment エントリ(コミットメント込み)+ ラップ完全集合を同梱する", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const member = await makeTestUser("user-member-2222");
    const removed = await makeTestUser("user-removed-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "reader") },
      { actor: owner, operation: addMemberOp(removed, "member") },
      { actor: owner, operation: removeMemberOp(removed) },
    ]);
    const head = built.hashes[built.hashes.length - 1] ?? "";
    let payload: CompositeCreateBody | null = null;
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, (request) => {
          payload = request.body as CompositeCreateBody;
          return {
            status: 200,
            json: {
              environmentId: payload.entry.payload.environmentId,
              currentEpoch: 1,
              headSeq: built.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging", "--name", "Staging"], env.layer)).toBe(0);
    const body = payload as CompositeCreateBody | null;
    if (body === null) throw new Error("composite create was not called");
    // 表示名は EnvironmentMetaStatement(metaVersion 1)が運ぶ(§12-4)。
    // 宣言ヘッドは追記前の現ヘッド(= 同梱エントリの prev)
    expect(body.statement.name).toBe("Staging");
    expect(body.statement.environmentId).toBe("staging");
    expect(body.statement.status).toBe("active");
    expect(body.statement.metaVersion).toBe(1);
    expect(body.statement.prevMetaSigHashHex).toBe("");
    expect(body.statement.chainHeadHashHex).toBe(head);
    expect(body.statement.chainHeadSeq).toBe(built.entries.length);
    expect(body.statement.signatureHex).toMatch(/^[0-9a-f]{128}$/);
    // 親ヘッド CAS + エントリは現ヘッドの直後(seq = head + 1)に actor = 呼び出し
    // 主体で署名されている
    expect(body.parentHeadHashHex).toBe(head);
    expect(body.entry.op).toBe("create_environment");
    expect(body.entry.seq).toBe(built.entries.length + 1);
    expect(body.entry.prevHashHex).toBe(head);
    expect(body.entry.actor.userId).toBe(owner.userId);
    expect(body.entry.payload.environmentId).toBe("staging");
    // ラップ先 = 検証済み現メンバー集合と厳密一致(削除済みメンバー宛はない)
    expect(body.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    // 各ラップは §5.1 署名(署名者 = 呼び出し主体 = owner)を持ち、受信者が復号できる。
    // 全受信者が同一の DEK を得る
    const deks: Uint8Array[] = [];
    for (const wrap of body.deks) {
      deks.push(
        await verifyAndUnwrapWrap({
          wrap,
          projectId: built.projectId,
          signer: owner,
          recipient: wrap.recipientUserId === owner.userId ? owner : member,
        }),
      );
    }
    expect(deks).toHaveLength(2);
    expect(Buffer.from(deks[0] ?? []).toString("hex")).toBe(
      Buffer.from(deks[1] ?? []).toString("hex"),
    );
    // エントリの dek_commitment_hex は同梱 DEK の §5.2 コミットメント(受信者は
    // unwrap した DEK をこの値と照合してから使う)
    const dek = deks[0];
    if (dek === undefined) throw new Error("missing dek");
    const matched = await verifyDekCommitment({
      context: {
        suite: "maruhi/v1",
        projectId: built.projectId,
        environmentId: "staging",
        epoch: 1,
      },
      dek,
      expectedCommitmentHex: body.entry.payload.dekCommitmentHex,
    });
    expect(matched.ok).toBe(true);
  });

  it("ChainHeadConflict(409)は再同期してエントリを再署名し、リトライする(§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const other = await makeTestUser("user-other-4444");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // 並行追記で伸びたチェーン(同一 genesis + add_member)
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(other, "reader") },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    let chainCalls = 0;
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      chainA.projectId,
      [
        onRequest("GET", `/projects/${chainA.projectId}/chain`, () => {
          chainCalls += 1;
          const built = chainCalls === 1 ? chainA : chainB;
          return {
            status: 200,
            json: {
              projectId: chainA.projectId,
              entries: built.entries,
              headSeq: built.entries.length,
              headHashHex: built.hashes[built.hashes.length - 1],
            },
          };
        }),
        onRequest("POST", `/projects/${chainA.projectId}/environments`, (request) => {
          bodies.push(request.body as CompositeCreateBody);
          if (bodies.length === 1) {
            // 送信と並行して他メンバーが追記していた(親ヘッド CAS 失敗)
            return {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainB.entries.length,
                currentHeadHashHex: headB,
              },
            };
          }
          return {
            status: 200,
            json: {
              environmentId: "staging",
              currentEpoch: 1,
              headSeq: chainB.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(bodies).toHaveLength(2);
    const [first, second] = bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // 再試行は新ヘッドを親にエントリを再署名している(seq / prev / 署名が変わる)
    expect(first.entry.seq).toBe(2);
    expect(second.entry.seq).toBe(3);
    expect(second.parentHeadHashHex).toBe(headB);
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.entry.signatureHex).not.toBe(first.entry.signatureHex);
    // ステートメントも**両方**再署名される(宣言ヘッド = 追記前の新ヘッド — §12-4)
    expect(second.statement.chainHeadHashHex).toBe(headB);
    expect(second.statement.chainHeadSeq).toBe(chainB.entries.length);
    expect(second.statement.signatureHex).not.toBe(first.statement.signatureHex);
    // コミットメント(= 生成済み DEK)は不変のまま
    expect(second.entry.payload.dekCommitmentHex).toBe(first.entry.payload.dekCommitmentHex);
    // メンバー集合が変わった(other が加わった)ため、ラップ集合は作り直されている
    expect(first.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(second.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, other.userId].toSorted(),
    );
    // 完了報告のメンバー数は**実際に登録したラップ集合**の大きさ(開始時のビューの
    // 1 名ではない)。作り直した集合と食い違う数を報告しない
    expect(env.logs.join("\n")).toContain("現メンバー 2 名へラップ済み");
  });

  it("ChainHeadConflict の再同期は延長検査付き(短縮・分岐チェーンへ再署名しない)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const other = await makeTestUser("user-other-4444");
    // 初回に見えるチェーン(2 エントリ)より、409 後に配られるチェーンが短い =
    // 巻き戻し。署名としては妥当でも、この状態でエントリを再署名し、巻き戻った
    // メンバー集合でラップ集合を作り直してはならない(§6.3-2b)
    const long = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(other, "reader") },
    ]);
    const short = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    let chainCalls = 0;
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      long.projectId,
      [
        onRequest("GET", `/projects/${long.projectId}/chain`, () => {
          chainCalls += 1;
          const built = chainCalls === 1 ? long : short;
          return {
            status: 200,
            json: {
              projectId: long.projectId,
              entries: built.entries,
              headSeq: built.entries.length,
              headHashHex: built.hashes[built.hashes.length - 1],
            },
          };
        }),
        onRequest("POST", `/projects/${long.projectId}/environments`, (request) => {
          bodies.push(request.body as CompositeCreateBody);
          return {
            status: 409,
            json: {
              _tag: "ChainHeadConflict",
              currentHeadSeq: short.entries.length,
              currentHeadHashHex: short.hashes[short.hashes.length - 1],
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("延長ではありません");
    // 巻き戻ったビューでの再署名は行われない(送信は初回の 1 度きり)
    expect(bodies).toHaveLength(1);
  });

  it("ChainHeadConflict リトライでメンバー集合が不変ならラップ集合を再利用する(§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const chainA = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    // 伸びたチェーンだがメンバー集合(user_id → enc 鍵)は不変(rename 等価の
    // 代わりに change_role で自分の role を owner のまま……は不可なので、
    // 「add してすぐ remove」でヘッドだけ進める)
    const passerby = await makeTestUser("user-passerby-5555");
    const chainB = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(passerby, "reader") },
      { actor: owner, operation: removeMemberOp(passerby) },
    ]);
    expect(chainB.projectId).toBe(chainA.projectId);
    const headB = chainB.hashes[chainB.hashes.length - 1] ?? "";
    let chainCalls = 0;
    const bodies: CompositeCreateBody[] = [];
    const env = await startEnv(
      chainA.projectId,
      [
        onRequest("GET", `/projects/${chainA.projectId}/chain`, () => {
          chainCalls += 1;
          const built = chainCalls === 1 ? chainA : chainB;
          return {
            status: 200,
            json: {
              projectId: chainA.projectId,
              entries: built.entries,
              headSeq: built.entries.length,
              headHashHex: built.hashes[built.hashes.length - 1],
            },
          };
        }),
        onRequest("POST", `/projects/${chainA.projectId}/environments`, (request) => {
          bodies.push(request.body as CompositeCreateBody);
          if (bodies.length === 1) {
            return {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: chainB.entries.length,
                currentHeadHashHex: headB,
              },
            };
          }
          return {
            status: 200,
            json: {
              environmentId: "staging",
              currentEpoch: 1,
              headSeq: chainB.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(bodies).toHaveLength(2);
    const [first, second] = bodies;
    if (first === undefined || second === undefined) throw new Error("missing bodies");
    // エントリは再署名される(prev が変わる)が、ラップ集合は再構築されない
    // (HPKE Seal はランダムなので、再ラップしていれば enc / ct / 署名が変わる)
    expect(second.entry.prevHashHex).toBe(headB);
    expect(second.deks).toEqual(first.deks);
  });

  it("環境 ID の positional 未指定はネットワーク前に拒否される(bogus id で create API を呼ばない)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });
    // gunshi が required positional を parse 層で弾く(usage エラー = exit 2)。
    // ハンドラ内の undefined ガードは、その前段が外れても "undefined" が
    // RESOURCE_ID_PATTERN を通らないための多層防御。いずれにせよ HTTP は起きない
    const code = await runCli(["env", "create"], env.layer);
    expect(code === 1 || code === 2).toBe(true);
    expect(server.requests).toHaveLength(0);
  });

  it("reader は環境を作成できない(member 以上 — §6.2)。ラップを作る前に拒否する", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const reader = await makeTestUser("user-reader-5555");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(reader, "reader") },
    ]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, reader);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    // サーバーの汎用 403 を待たない: 待つと DEK 生成 + 全メンバー分の HPKE
    // ラップ・署名を済ませてから拒否されることになる(env rotate と同じ規律)
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("reader は環境を作成できません");
    expect(server.requests.filter((request) => request.method === "POST")).toHaveLength(0);
  });

  it("作成する環境が grant_server の開示スコープに入っていれば、完全集合にサーバー宛ラップを含めて成功する(§12-4)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      // 未作成 ID を先回りで開示したスコープ(スコープの存在検査は合意規則にない)
      { actor: owner, operation: await grantServerOp(["staging"]) },
    ]);
    const grantEntry = built.entries[1];
    if (grantEntry?.op !== "grant_server") throw new Error("grant entry missing");
    const bodies: unknown[] = [];
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, (request) => {
          bodies.push(request.body);
          return {
            status: 200,
            json: {
              environmentId: "staging",
              currentEpoch: 1,
              headSeq: built.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const body = bodies[0] as {
      deks: readonly {
        recipientClass?: string;
        recipientUserId: string;
        recipientEncPubHex: string;
      }[];
    };
    // 完全集合 = 現メンバー(owner)+ スコープ内 grant のサーバー鍵。
    // サーバー宛は recipient 位置にサーバー鍵 FP(CRYPTO_SPEC §9)
    expect(body.deks).toHaveLength(2);
    const serverWrap = body.deks.find((wrap) => wrap.recipientClass === "server");
    expect(serverWrap?.recipientUserId).toBe(grantEntry.payload.serverKeyFingerprintHex);
    expect(serverWrap?.recipientEncPubHex).toBe(grantEntry.payload.serverEncPubHex);
  });

  it("スコープが空の grant_server はどの環境も対象にしない(サーバー宛ラップなしで作成できる)", async () => {
    // §6.2 は空スコープの意味を定めないが、完全集合の判定(§12-4)は
    // 「スコープに含まれる環境」なので空 = 対象なし。クライアントとサーバーで
    // 同じ includes 判定を使う(割れると複合が恒常的に 422 になる)
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp([]) },
    ]);
    const bodies: unknown[] = [];
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, (request) => {
          bodies.push(request.body);
          return {
            status: 200,
            json: {
              environmentId: "staging",
              currentEpoch: 1,
              headSeq: built.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const body = bodies[0] as { deks: readonly { recipientClass?: string }[] };
    expect(body.deks).toHaveLength(1);
    expect(body.deks.every((wrap) => wrap.recipientClass === undefined)).toBe(true);
  });

  it("別環境だけを開示した grant_server は、他環境の作成を止めない(§6.2 のスコープは部分集合)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp(["dev"]) },
    ]);
    let called = false;
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, () => {
          called = true;
          return {
            status: 200,
            json: {
              environmentId: "staging",
              currentEpoch: 1,
              headSeq: built.entries.length + 1,
              headHashHex: "cd".repeat(32),
            },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    expect(called).toBe(true);
  });

  it("完了報告のエポックはサーバー申告ではなく構造的な 1 を出す(§12-4)", async () => {
    // 受理後の事実をサーバーの自己申告から取ると、rotate 側で敷いた
    // 「申告を真実源にしない」規律が create 側だけ緩む。create_environment が
    // 確立するエポックは常に 1 なので、申告が何であれ 1 を出す
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, () => ({
          status: 200,
          json: {
            environmentId: "staging",
            // 嘘の申告(実サーバーは 1 を返す — composite-programs.ts)
            currentEpoch: 7,
            headSeq: built.entries.length + 1,
            headHashHex: "cd".repeat(32),
          },
        })),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("epoch=1");
    expect(logs).not.toContain("epoch=7");
  });

  it("チェーン観測済みの環境 ID は HTTP を呼ばず早期拒否する(履歴全体一意 — §6.2)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp("burned", new Uint8Array(32).fill(1)) },
    ]);
    const server = await MockServer.start([chainHandler(built.projectId, built)]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, owner);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["env", "create", "burned"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("使用済み");
    // 環境作成の HTTP 呼び出しは発生していない(チェーン取得のみ)
    expect(
      server.requests.filter((request) => request.method === "POST").map((request) => request.path),
    ).toEqual([]);
  });
});
