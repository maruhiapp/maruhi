// 環境作成(§12-4)のテスト: ラップ集合 = 検証済み現メンバー集合との厳密一致
// (§6.3 ゴーストメンバー対策のクライアント側)、署名者 = 呼び出し主体(§5.1)、
// grant_server 有効時の拒否、チェーン観測済み ID の早期拒否。

import type { WrappedDek } from "@maruhi/api-schema";
import {
  importEncryptionKeyPair,
  importSigningPublicKey,
  unwrapDek,
  verifyDekWrapSignature,
} from "@maruhi/crypto";
import { afterEach, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  genesisOp,
  grantServerOp,
  hexBytes,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

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
  it("エポック 1 のラップ完全集合(= 現メンバー集合)を署名付きで同梱する", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const member = await makeTestUser("user-member-2222");
    const removed = await makeTestUser("user-removed-3333");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "reader") },
      { actor: owner, operation: addMemberOp(removed, "member") },
      { actor: owner, operation: removeMemberOp(removed) },
    ]);
    let payload: { environmentId: string; name: string; deks: WrappedDek[] } | null = null;
    const env = await startEnv(
      built.projectId,
      [
        chainHandler(built.projectId, built),
        onRequest("POST", `/projects/${built.projectId}/environments`, (request) => {
          payload = request.body as { environmentId: string; name: string; deks: WrappedDek[] };
          return {
            status: 200,
            json: { environmentId: payload.environmentId, name: payload.name, currentEpoch: 1 },
          };
        }),
      ],
      owner,
    );

    expect(await runCli(["env", "create", "staging", "--name", "Staging"], env.layer)).toBe(0);
    const body = payload as { environmentId: string; name: string; deks: WrappedDek[] } | null;
    expect(body?.environmentId).toBe("staging");
    expect(body?.name).toBe("Staging");
    // ラップ先 = 検証済み現メンバー集合と厳密一致(削除済みメンバー宛はない)
    expect(body?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, member.userId].toSorted(),
    );
    // 各ラップは §5.1 署名(署名者 = 呼び出し主体 = owner)を持ち、受信者が復号できる。
    // 全受信者が同一の DEK を得る
    const deks: Uint8Array[] = [];
    for (const wrap of body?.deks ?? []) {
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

  it("grant_server が有効なプロジェクトでは拒否する(Phase 2 未実装)", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp(["dev"]) },
    ]);
    const env = await startEnv(built.projectId, [chainHandler(built.projectId, built)], owner);
    expect(await runCli(["env", "create", "staging"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("grant_server");
  });

  it("チェーン観測済みの環境 ID は HTTP を呼ばず早期拒否する", async () => {
    const owner = await makeTestUser("user-owner-1111");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: rotateEpochOp("burned", 2) },
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
