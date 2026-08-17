// `maruhi member add`(CRYPTO_SPEC §6.2 / §6.5 / §7、AUTH_SPEC §12-6 / §15 —
// Wave 2 B1b)の統合テスト。
//
// 固定する性質:
//  1. add_member は一覧の受諾ブロックから組む(鍵・user_id。role は招待行から)。
//     §6.5 の独立検証・発行ピン突合・FP 儀式(--expect-fingerprint / 最終語
//     再入力 / エージェント拒否)が追記の前に立つ
//  2. バックフィル: 全環境 × 全エポックを新メンバーへラップし、409 = 登録済みで
//     冪等に再開する(既に同一鍵で在籍 → 追記スキップ)
//  3. 再追加(過去在籍が別鍵)では 409 スロットを削除 → 再登録で修復する
//     (鍵履歴ゲート — 同一鍵の再実行では削除しない)
//  4. duplicate-member-key の早期検査・受諾鍵不一致の在籍検出

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  decodeHex,
  fingerprintToWords,
  signInviteAccept,
  SUITE_ID,
} from "@maruhi/crypto";
import { Effect, Redacted } from "effect";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import { tokenHashHexOf } from "../src/invite.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
  type WireDistributedEnvironmentStatement,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";
const TOKEN = "maruhi_inv_Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St9xY01";
const INVITE_ID = "inv-0001";

let inviter: TestUser;
let acceptor: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;
let tokenHashHex: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  tokenHashHex = await Effect.runPromise(tokenHashHexOf(Redacted.make(TOKEN)));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

interface Acceptance {
  readonly inviteeUserId: string;
  readonly inviteeEncPubHex: string;
  readonly inviteeSigPubHex: string;
  readonly signatureHex: string;
  readonly acceptedAtMs: number;
}

/** 受諾者本人の正規の受諾ブロック(§6.5 の自己束縛署名つき)。 */
async function acceptanceFor(projectId: string, invitee: TestUser): Promise<Acceptance> {
  const signature = await signInviteAccept({
    context: {
      suite: SUITE_ID,
      projectId,
      inviteTokenHashHex: tokenHashHex,
      inviteeUserId: invitee.userId,
      inviteeEncPubHex: invitee.encPubHex,
      inviteeSigPubHex: invitee.sigPubHex,
    },
    signingKey: invitee.sigKeyPair.privateKey,
  });
  if (!signature.ok) throw new Error("acceptance signature failed");
  return {
    inviteeUserId: invitee.userId,
    inviteeEncPubHex: invitee.encPubHex,
    inviteeSigPubHex: invitee.sigPubHex,
    signatureHex: signature.value,
    acceptedAtMs: 1755300000000,
  };
}

interface AddServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly registerBodies: {
    readonly environmentId: string;
    readonly deks: readonly WrappedDek[];
  }[];
  readonly removeBodies: {
    readonly environmentId: string;
    readonly wraps: readonly { epoch: number; recipientUserId: string }[];
  }[];
  readonly counters: { appendAttempts: number; registerAttempts: number };
}

/** dek_wraps ルート(/environments/:id/deks)のメソッド別ハンドラ。 */
function onDeksRoute(
  projectId: string,
  method: string,
  respond: (environmentId: string, request: Parameters<MockHandler>[0]) => ReturnType<MockHandler>,
): MockHandler {
  return (request) => {
    const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/deks$`).exec(
      request.path,
    );
    if (match === null || request.method !== method) {
      return null;
    }
    return respond(match[1] ?? "", request);
  };
}

/**
 * member add フロー用の状態つきモック。dek_wraps のスロット占有をシミュレート
 * する: `occupiedSlots` にある (環境:エポック:受信者) への登録は 409(§12-6 の
 * 上書き禁止)、削除はスロットを解放する。バッチ登録はどれか 1 つでも占有なら
 * 409(原子的受理)。
 */
async function makeAddServer(input: {
  readonly built: BuiltChain;
  readonly invitation: Readonly<Record<string, unknown>>;
  readonly ownDeks: readonly WireRecipientDek[];
  readonly currentEpoch?: number;
  readonly occupiedSlots?: readonly string[];
  /**
   * スロット → 保存済み受信者 enc 公開鍵(hex)。指定したスロットの 409 は
   * `storedRecipientEncPubHex` を運ぶ(AUTH_SPEC §12-6 追補後のサーバー)。
   * 未指定のスロットはフィールドなしの 409(追補以前のサーバー)。
   */
  readonly occupiedSlotEncPub?: Readonly<Record<string, string>>;
  readonly listedStatements?: readonly WireDistributedEnvironmentStatement[];
  /** チェーン追記への差し込み(409 等)。undefined = 受理。 */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** onAppend の差し込み時に、以後のチェーンをこの形へ差し替える(並行追記)。 */
  readonly chainAfterConflict?: BuiltChain;
  /** dek_wraps 登録への差し込み(呼び出し回数ベース)。undefined = 通常処理。 */
  readonly onRegister?: (call: number) => MockResponse | undefined;
}): Promise<AddServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[] = [];
  const removeBodies: {
    environmentId: string;
    wraps: readonly { epoch: number; recipientUserId: string }[];
  }[] = [];
  const counters = { appendAttempts: 0, registerAttempts: 0 };
  const occupied = new Set(input.occupiedSlots ?? []);
  const listedStatements = input.listedStatements ?? [
    await environmentStatementFor({
      projectId,
      environmentId: ENV_ID,
      name: ENV_ID,
      author: inviter,
      head: headOf(input.built, 1),
    }),
  ];

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
    async (request) => {
      if (request.method !== "POST" || request.path !== `/projects/${projectId}/chain/entries`) {
        return null;
      }
      const injected = input.onAppend?.(counters.appendAttempts);
      counters.appendAttempts += 1;
      if (injected !== undefined) {
        if (input.chainAfterConflict !== undefined) {
          entries.splice(0, entries.length, ...input.chainAfterConflict.entries);
          hashes.splice(0, hashes.length, ...input.chainAfterConflict.hashes);
        }
        return injected;
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
    onRequest("GET", `/projects/${projectId}/invites`, () => ({
      status: 200,
      json: { invitations: [input.invitation] },
    })),
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: input.currentEpoch ?? 1,
          statement,
        })),
      },
    })),
    onDeksRoute(projectId, "GET", () => ({ status: 200, json: { deks: input.ownDeks } })),
    onDeksRoute(projectId, "POST", (environmentId, request) => {
      const injected = input.onRegister?.(counters.registerAttempts);
      counters.registerAttempts += 1;
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as { readonly deks: readonly WrappedDek[] };
      const conflict = body.deks.find((wrap) =>
        occupied.has(`${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`),
      );
      if (conflict !== undefined) {
        const slot = `${environmentId}:${conflict.epoch}:${conflict.recipientUserId}`;
        const storedEncPub = input.occupiedSlotEncPub?.[slot];
        return {
          status: 409,
          json: {
            _tag: "DekWrapExists",
            epoch: conflict.epoch,
            recipientUserId: conflict.recipientUserId,
            // AUTH_SPEC §12-6 追補後のサーバーだけが載せる(省略可フィールド)
            ...(storedEncPub === undefined ? {} : { storedRecipientEncPubHex: storedEncPub }),
          },
        };
      }
      registerBodies.push({ environmentId, deks: body.deks });
      for (const wrap of body.deks) {
        occupied.add(`${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`);
      }
      return { status: 204 };
    }),
    onDeksRoute(projectId, "DELETE", (environmentId, request) => {
      const body = request.body as {
        readonly wraps: readonly { epoch: number; recipientUserId: string }[];
      };
      removeBodies.push({ environmentId, wraps: body.wraps });
      for (const wrap of body.wraps) {
        const slot = `${environmentId}:${wrap.epoch}:${wrap.recipientUserId}`;
        if (!occupied.has(slot)) {
          return {
            status: 404,
            json: {
              _tag: "DekWrapNotFound",
              epoch: wrap.epoch,
              recipientUserId: wrap.recipientUserId,
            },
          };
        }
        occupied.delete(slot);
      }
      return { status: 204 };
    }),
  ];
  return { handlers, appendedEntries, registerBodies, removeBodies, counters };
}

function invitationRow(
  projectId: string,
  acceptance: Acceptance | null,
  overrides?: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return {
    id: INVITE_ID,
    projectId,
    role: "member",
    status: acceptance === null ? "pending" : "accepted",
    inviterUserId: inviter.userId,
    tokenHashHex,
    createdAtMs: 1755200000000,
    expiresAtMs: 1755993600000,
    acceptance,
    ...overrides,
  };
}

async function startAddEnv(state: AddServerState, projectId: string): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, inviter);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

describe("maruhi member add", () => {
  it("受諾ブロックから add_member を組み、全環境 × 全エポックをバックフィルする(--expect-fingerprint)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // add_member payload = 受諾ブロックの鍵 + 招待行の role
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.payload).toEqual({
      targetUserId: acceptor.userId,
      encPubHex: acceptor.encPubHex,
      sigPubHex: acceptor.sigPubHex,
      role: "member",
    });

    // バックフィル: エポック 1〜2 を新メンバー宛にラップ(1 バッチで受理)
    expect(state.registerBodies).toHaveLength(1);
    const wraps = state.registerBodies[0]?.deks ?? [];
    expect(wraps.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual([
      [1, acceptor.userId],
      [2, acceptor.userId],
    ]);
    expect(wraps.every((wrap) => wrap.recipientEncPubHex === acceptor.encPubHex)).toBe(true);
    expect(state.removeBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "完了: 新メンバーに全環境 × 全エポックの DEK ラップを配布しました",
    );
  });

  it("ChainHeadConflict(409)は再同期して add_member を再署名し、リトライする(§12-4)", async () => {
    const passerby = await makeTestUser("user-passerby-5555");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    // 送信と並行して他メンバーの追記で伸びたチェーン(同一 prefix の延長)
    const concurrent = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(passerby, "reader") },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: concurrent.entries.length,
                currentHeadHashHex: concurrent.hashes[concurrent.hashes.length - 1] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // 追記は 2 回試行(409 → 再同期 + 再署名 → 受理)。受理エントリは新ヘッドの子
    expect(state.counters.appendAttempts).toBe(2);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.seq).toBe(concurrent.entries.length + 1);
    expect(entry.payload.targetUserId).toBe(acceptor.userId);
    // バックフィルも完了する
    expect(
      state.registerBodies.flatMap((body) => body.deks.map((wrap) => wrap.recipientUserId)),
    ).toEqual([acceptor.userId]);
  });

  it("修復経路の削除後に再登録が失敗したら、スロットが空である事実を明示して失敗する", async () => {
    // 削除 → 再登録は原子的でない: 間で失敗すると対象はそのエポックのラップを
    // 一つも持たない。汎用文言に紛れると気づけない(pullfrog レビュー反映)
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
      // 呼び出し順: 0 = 一括(409)→ 1 = epoch1 単発(409)→ 削除 → 2 = 再登録
      onRegister: (call) => (call === 2 ? { status: 500, json: {} } : undefined),
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(1);
    // 削除は実行済み = スロットは空
    expect(state.removeBodies).toEqual([
      { environmentId: ENV_ID, wraps: [{ epoch: 1, recipientUserId: acceptor.userId }] },
    ]);
    const errors = env.errors.join("\n");
    expect(errors).toContain("スロットは空のままです");
    expect(errors).toContain("maruhi member add を再実行すると続きから再開します");
  });

  it("儀式(最終語再入力)を通しても追加でき、エージェント環境ではフラグなしを拒否する", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const ownDeks = [
      await wrapDekFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];
    const acceptance = await acceptanceFor(built.projectId, acceptor);

    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks,
    });
    const env = await startAddEnv(state, built.projectId);
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(env.logs.join("\n")).toContain(`role:    member(このメンバーに付与されます)`);

    // エージェント環境: --expect-fingerprint なしは拒否(儀式を代行させない)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks,
    });
    const env2 = await startAddEnv(state2, built.projectId);
    env2.setAgent({ isAgent: true });
    expect(await runCli(["member", "add"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("儀式を実行できません");
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("中断復旧: 既に同一鍵で在籍なら追記せず、バックフィルの 409 を登録済みとして収束する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // 前回実行が登録済み(受諾鍵と同一鍵の在籍 = 修復は不要)
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies).toHaveLength(0);
    // 同一鍵の在籍では削除(修復)を発動しない — 鍵履歴ゲート
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("既に同一鍵で在籍しています");
    expect(logs).toContain("登録済み 1 件");
  });

  it("再追加(過去在籍が別鍵): 409 スロットを削除 → 再登録で新鍵へ修復する", async () => {
    // 同じ user_id の旧鍵アイデンティティ(過去在籍)
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // 旧在籍時の旧鍵ラップが epoch 1 のスロットを占有している
      occupiedSlots: [`${ENV_ID}:1:${acceptor.userId}`],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);

    // epoch 1 は削除 → 再登録(修復)、epoch 2 は通常登録
    expect(state.removeBodies).toEqual([
      { environmentId: ENV_ID, wraps: [{ epoch: 1, recipientUserId: acceptor.userId }] },
    ]);
    const registered = state.registerBodies.flatMap((body) =>
      body.deks.map((wrap) => [wrap.epoch, wrap.recipientEncPubHex] as const),
    );
    // 再登録された epoch 1 のラップは**新鍵**宛(修復の本体)
    expect(registered).toContainEqual([1, acceptor.encPubHex]);
    expect(registered).toContainEqual([2, acceptor.encPubHex]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("旧鍵宛の残存ラップが見つかった場合は修復経路");
    expect(logs).toContain("旧鍵ラップの修復 1 件");
  });

  it("B1a: 409 の保存済み enc 公開鍵が受諾鍵と一致すれば、別鍵の在籍歴があっても削除しない(誤削除の遮断)", async () => {
    // PR #69 レビューの本丸: 「過去に別鍵で在籍 + 直前の member add が現行鍵で
    // 部分完了」の再実行。鍵履歴ヒューリスティックは stale を疑う(旧判定なら
    // 誤削除)が、409 が保存済み enc 公開鍵(= 現行鍵)を運ぶため厳密比較で
    // 登録済みと判定できる(AUTH_SPEC §12-6 追補)
    const oldKeys = await makeTestUser(acceptor.userId);
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(oldKeys, "member") },
      { actor: inviter, operation: removeMemberOp(oldKeys) },
      { actor: inviter, operation: rotateEpochOp(ENV_ID, 2, dek2) },
      // 現行鍵での再追加は受理済み(前回実行の中断)— バックフィルのみの再開
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      currentEpoch: 2,
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 2,
          dek: dek2,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      // 前回実行が epoch 1 を**現行鍵で**登録済み(部分完了)
      occupiedSlots: [slot],
      occupiedSlotEncPub: { [slot]: acceptor.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    // 一致 = 登録済み(冪等)。削除(誤削除)は 1 件も発動しない
    expect(state.removeBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain("登録済み 1 件");
    expect(logs).not.toContain("旧鍵ラップの修復");
  });

  it("B1a: 409 の保存済み enc 公開鍵が受諾鍵と不一致なら、鍵履歴に関わらず修復する(フィールド優先)", async () => {
    // 鍵履歴に別鍵はない(ヒューリスティックは stale を疑わない)が、409 の
    // フィールドが別鍵を申告する形。フィールドがヒューリスティックに**優先**
    // することを固定する(比較を外して推定へ戻す変異でこのテストだけが落ちる)
    const strangerKeys = await makeTestUser("user-someone-else");
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const slot = `${ENV_ID}:1:${acceptor.userId}`;
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [
        await wrapDekFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          epoch: 1,
          dek: dek1,
          recipient: inviter,
          signer: inviter,
        }),
      ],
      occupiedSlots: [slot],
      occupiedSlotEncPub: { [slot]: strangerKeys.encPubHex },
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    // 不一致 = 修復(削除 → 再登録)。鍵履歴ゲートに依存しない
    expect(state.removeBodies).toEqual([
      { environmentId: ENV_ID, wraps: [{ epoch: 1, recipientUserId: acceptor.userId }] },
    ]);
    const registered = state.registerBodies.flatMap((body) =>
      body.deks.map((wrap) => [wrap.epoch, wrap.recipientEncPubHex] as const),
    );
    expect(registered).toContainEqual([1, acceptor.encPubHex]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("旧鍵ラップの修復 1 件");
  });

  it("completed 行は id 明示で再開でき、id なしの再実行はその導線を案内する(Cursor bot 指摘の回帰)", async () => {
    // add_member 済み(サーバーが行を completed へ更新済み)+ バックフィル中断の形
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: addMemberOp(acceptor, "member") },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);
    const completedRow = invitationRow(built.projectId, acceptance, { status: "completed" });
    const ownDeks = [
      await wrapDekFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        dek: dek1,
        recipient: inviter,
        signer: inviter,
      }),
    ];

    // id なし: completed は自動選択しない(過去メンバーの行が蓄積するため)が、
    // 再開の導線(id 明示)をエラーで案内する
    const state1 = await makeAddServer({ built, invitation: completedRow, ownDeks });
    const env1 = await startAddEnv(state1, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env1.layer),
    ).toBe(1);
    expect(env1.errors.join("\n")).toContain("maruhi member add <招待id> と id を明示して");
    expect(state1.appendedEntries).toHaveLength(0);

    // id 明示: completed 行 + 同一鍵在籍 → 追記せずバックフィルのみ再開する
    const state2 = await makeAddServer({ built, invitation: completedRow, ownDeks });
    const env2 = await startAddEnv(state2, built.projectId);
    expect(
      await runCli(
        ["member", "add", INVITE_ID, "--expect-fingerprint", acceptor.fingerprintHex],
        env2.layer,
      ),
    ).toBe(0);
    expect(state2.appendedEntries).toHaveLength(0);
    expect(
      state2.registerBodies.flatMap((body) => body.deks.map((wrap) => wrap.recipientUserId)),
    ).toEqual([acceptor.userId]);
    expect(env2.logs.join("\n")).toContain("既に同一鍵で在籍しています");
  });

  it("受諾署名の検証失敗・発行ピン不一致は追記前に中止する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);

    // 改竄された受諾ブロック(鍵すり替え — 署名は宣言鍵で検証されるため落ちる)
    const state1 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, {
        ...acceptance,
        inviteeEncPubHex: "aa".repeat(32),
      }),
      ownDeks: [],
    });
    const env1 = await startAddEnv(state1, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env1.layer),
    ).toBe(1);
    expect(env1.errors.join("\n")).toContain("受諾署名の検証に失敗しました");
    expect(state1.appendedEntries).toHaveLength(0);

    // 発行ピンと role が食い違うサーバー申告(role 改竄)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance, { role: "admin" }),
      ownDeks: [],
    });
    const env2 = await startAddEnv(state2, built.projectId);
    await mkdir(env2.pinsDir, { recursive: true });
    await writeFile(
      join(env2.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: { [INVITE_ID]: { tokenHashHex, role: "member", expiresAtMs: 1755993600000 } },
      }),
    );
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env2.layer),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain("発行時のローカル記録と一致しません");
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("受諾鍵が現メンバーの鍵と一致する場合は duplicate-member-key として追記前に拒否する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    // 攻撃者が招待者の公開鍵をそのまま宣言して受諾した形(署名は自己束縛なので
    // 招待者の秘密鍵がなければ作れない — ここでは合意規則の早期検査だけを見る
    // ため、招待者自身の鍵で署名した「鍵流用」受諾を作る)
    const signature = await signInviteAccept({
      context: {
        suite: SUITE_ID,
        projectId: built.projectId,
        inviteTokenHashHex: tokenHashHex,
        inviteeUserId: "user-sock-99999",
        inviteeEncPubHex: inviter.encPubHex,
        inviteeSigPubHex: inviter.sigPubHex,
      },
      signingKey: inviter.sigKeyPair.privateKey,
    });
    if (!signature.ok) throw new Error("signature failed");
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, {
        inviteeUserId: "user-sock-99999",
        inviteeEncPubHex: inviter.encPubHex,
        inviteeSigPubHex: inviter.sigPubHex,
        signatureHex: signature.value,
        acceptedAtMs: 1755300000000,
      }),
      ownDeks: [],
    });
    const env = await startAddEnv(state, built.projectId);
    expect(
      await runCli(["member", "add", "--expect-fingerprint", inviter.fingerprintHex], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("duplicate-member-key");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--expect-fingerprint の不一致(横取りの疑い)は追記前に中止する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor)),
      ownDeks: [],
    });
    const env = await startAddEnv(state, built.projectId);
    expect(await runCli(["member", "add", "--expect-fingerprint", "0".repeat(32)], env.layer)).toBe(
      1,
    );
    expect(env.errors.join("\n")).toContain("受諾の横取りの可能性");
    expect(state.appendedEntries).toHaveLength(0);
  });
});
