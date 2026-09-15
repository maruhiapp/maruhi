// `maruhi member add`(CRYPTO_SPEC §6.2 / §6.5 / §7、AUTH_SPEC §12-6 / §15)の統合テスト。
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

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, decodeHex, fingerprintToWords } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
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
import {
  type AcceptanceFixture,
  acceptanceFixture,
  flipHex,
  githubSigningKeysHandler,
  INVITE_ID,
  issueInviteFixture,
  type IssuedInviteFixture,
  sshLineOf,
} from "./support/invite.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let inviter: TestUser;
let acceptor: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  inviter = await makeTestUser("user-inviter-11");
  acceptor = await makeTestUser("user-acceptor-22");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

type Acceptance = AcceptanceFixture;

/**
 * プロジェクトごとの発行済み招待(招待者の発行署名つき)。invitationRow が同期的に
 * 発行文を載せられるよう、acceptanceFor / issuedFor の呼び出しで用意しておく。
 */
const issuedByProject = new Map<string, IssuedInviteFixture>();

async function issuedFor(projectId: string): Promise<IssuedInviteFixture> {
  const cached = issuedByProject.get(projectId);
  if (cached !== undefined) {
    return cached;
  }
  const issued = await issueInviteFixture({
    inviter,
    projectId,
    headHashHex: "cd".repeat(32),
    headSeq: 1,
  });
  issuedByProject.set(projectId, issued);
  return issued;
}

/** 受諾者本人の正規の受諾ブロック(§6.5 の受諾署名 + リンク署名つき)。 */
async function acceptanceFor(projectId: string, invitee: TestUser): Promise<Acceptance> {
  return acceptanceFixture({ projectId, issued: await issuedFor(projectId), invitee });
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
    scopeKind: "all",
    scopeEnvironmentIds: [],
    status: acceptance === null ? "pending" : "accepted",
    inviterUserId: inviter.userId,
    issuance: issuedByProject.get(projectId)?.issuance ?? null,
    createdAtMs: 1755200000000,
    expiresAtMs: 1755993600000,
    acceptance,
    ...overrides,
  };
}

async function startAddEnv(
  state: AddServerState,
  projectId: string,
): Promise<TestEnv & { readonly serverOrigin: string }> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, inviter);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return { ...env, serverOrigin: server.origin };
}

/** 検証済み指紋帳(KF)のファイル内容を読み出す。 */
async function readBook(
  env: TestEnv,
): Promise<Record<string, Record<string, { fingerprintHex: string; verifiedAtMs: number }>>> {
  const json = await readFile(env.fingerprintBookPath, "utf8");
  return (
    JSON.parse(json) as {
      known: Record<string, Record<string, { fingerprintHex: string; verifiedAtMs: number }>>;
    }
  ).known;
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
      // 招待行の scope(K2 の CLI は all のみ発行)で署名する — AUTH_SPEC §15-2
      scopeKind: "all",
      scopeEnvironmentIds: [],
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
      "Done: DEK wraps for every environment in the member's scope × every epoch were distributed to the new member (CRYPTO_SPEC §7)",
    );
  });

  it("listed scope の招待は招待行の scope で署名し、バックフィルを対象の scope の環境に限る(ES K4 — §7)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: inviter, operation: createEnvironmentOp("env-prod", dek2) },
    ]);
    // 発行文が scope を覆う(CRYPTO_SPEC §6.5)ので、listed の発行文で受諾ブロックを作る
    issuedByProject.set(
      built.projectId,
      await issueInviteFixture({
        inviter,
        projectId: built.projectId,
        headHashHex: "cd".repeat(32),
        headSeq: 1,
        scope: { scopeKind: "listed", scopeEnvironmentIds: [ENV_ID] },
      }),
    );
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, await acceptanceFor(built.projectId, acceptor), {
        scopeKind: "listed",
        scopeEnvironmentIds: [ENV_ID],
      }),
      currentEpoch: 1,
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
      listedStatements: [
        await environmentStatementFor({
          projectId: built.projectId,
          environmentId: ENV_ID,
          name: ENV_ID,
          author: inviter,
          head: headOf(built, 1),
        }),
        await environmentStatementFor({
          projectId: built.projectId,
          environmentId: "env-prod",
          name: "env-prod",
          author: inviter,
          head: headOf(built, 1),
        }),
      ],
    });
    const env = await startAddEnv(state, built.projectId);

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "add_member") throw new Error("add_member entry missing");
    expect(entry.payload.role).toBe("member");
    expect(entry.payload.scopeKind).toBe("listed");
    expect(entry.payload.scopeEnvironmentIds).toEqual([ENV_ID]);
    // prod は対象の scope 外 — ラップを作らない(作ればサーバーが 422 scope-out-of-range)
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_ID]);
    expect(env.logs.join("\n")).toContain("in the member's scope × every epoch");
    // 同じ手順で組んだチェーンは同じ projectId になる — listed の発行文を他テストに残さない
    issuedByProject.delete(built.projectId);
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
    // 一つも持たない。汎用文言に紛れると気づけない
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
    expect(errors).toContain("slot remains empty");
    expect(errors).toContain("re-run `maruhi member add` to resume");
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
    expect(env.logs.join("\n")).toContain(`role:    member (will be granted to this member)`);

    // エージェント環境: --expect-fingerprint なしは拒否(儀式を代行させない)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks,
    });
    const env2 = await startAddEnv(state2, built.projectId);
    env2.setAgent({ isAgent: true });
    expect(await runCli(["member", "add"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );
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
    expect(logs).toContain("already a member with the same key");
    expect(logs).toContain("1 already registered");
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
    expect(logs).toContain("If leftover wraps addressed to the old key are found, the repair path");
    expect(logs).toContain("1 old-key wrap repaired");
  });

  it("409 の保存済み enc 公開鍵が受諾鍵と一致すれば、別鍵の在籍歴があっても削除しない(誤削除の遮断)", async () => {
    // 「過去に別鍵で在籍 + 直前の member add が現行鍵で部分完了」の再実行。
    // 鍵履歴ヒューリスティックは stale を疑う(旧判定なら誤削除)が、409 が
    // 保存済み enc 公開鍵(= 現行鍵)を運ぶため厳密比較で登録済みと判定できる
    // (AUTH_SPEC §12-6 追補)
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
    expect(logs).toContain("1 already registered");
    expect(logs).not.toContain("old-key wraps repaired");
  });

  it("409 の保存済み enc 公開鍵が受諾鍵と不一致なら、鍵履歴に関わらず修復する(フィールド優先)", async () => {
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
    expect(logs).toContain("1 old-key wrap repaired");
  });

  it("completed 行は id 明示で再開でき、id なしの再実行はその導線を案内する", async () => {
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
    expect(env1.errors.join("\n")).toContain("pass it explicitly: `maruhi member add <invite-id>`");
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
    expect(env2.logs.join("\n")).toContain("already a member with the same key");
  });

  it("発行署名・リンク署名・受諾署名の検証失敗、発行ピン不一致、発行文なしは追記前に中止する", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const acceptance = await acceptanceFor(built.projectId, acceptor);

    for (const [invitation, fragment] of [
      // role の改竄(発行署名が覆う — 発行文の検証で落ちる)
      [
        invitationRow(built.projectId, acceptance, { role: "admin" }),
        "issue signature that does not verify",
      ],
      // 鍵すり替え(両署名の宣言鍵束縛が破れる — リンク署名を先に報告)
      [
        invitationRow(built.projectId, { ...acceptance, inviteeEncPubHex: "aa".repeat(32) }),
        "the link signature failed verification",
      ],
      // 受諾署名だけの改竄
      [
        invitationRow(built.projectId, {
          ...acceptance,
          signatureHex: flipHex(acceptance.signatureHex),
        }),
        "the acceptance signature failed verification",
      ],
    ] as const) {
      const state = await makeAddServer({ built, invitation, ownDeks: [] });
      const env = await startAddEnv(state, built.projectId);
      expect(
        await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
        fragment,
      ).toBe(1);
      expect(env.errors.join("\n"), fragment).toContain(fragment);
      expect(state.appendedEntries, fragment).toHaveLength(0);
    }

    // 発行ピンと link_pub が食い違うサーバー申告(行のすり替え)
    const state2 = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, acceptance),
      ownDeks: [],
    });
    const env2 = await startAddEnv(state2, built.projectId);
    await mkdir(env2.pinsDir, { recursive: true });
    await writeFile(
      join(env2.pinsDir, `${built.projectId}.json`),
      JSON.stringify({
        v: 1,
        anchor: null,
        issued: {
          [INVITE_ID]: {
            linkPubHex: "ee".repeat(32),
            role: "member",
            expiresAtMs: 1755993600000,
            expectedGithubLogin: null,
          },
        },
      }),
    );
    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env2.layer),
    ).toBe(1);
    expect(env2.errors.join("\n")).toContain("does not match the local record from issuance");
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
    const sock = await acceptanceFixture({
      projectId: built.projectId,
      issued: await issuedFor(built.projectId),
      invitee: inviter,
      inviteeUserId: "user-sock-99999",
    });
    const state = await makeAddServer({
      built,
      invitation: invitationRow(built.projectId, sock),
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
    expect(env.errors.join("\n")).toContain("The acceptance may have been hijacked");
    expect(state.appendedEntries).toHaveLength(0);
  });

  describe("裏付け元(IV2 — 充足形 4)", () => {
    /** 受諾済み招待 + 環境 1 つのサーバー状態に GitHub の署名鍵一覧の偽装を足す。 */
    async function backedState(
      built: BuiltChain,
      registeredKeys: readonly string[],
      status = 200,
    ): Promise<AddServerState> {
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
      });
      return {
        ...state,
        handlers: [...state.handlers, githubSigningKeysHandler("bob", registeredKeys, status)],
      };
    }

    async function backedEnv(
      state: AddServerState,
      projectId: string,
    ): Promise<TestEnv & { readonly serverOrigin: string }> {
      const env = await startAddEnv(state, projectId);
      env.setVendorOrigin("api.github.com", env.serverOrigin);
      return env;
    }

    async function chain(): Promise<BuiltChain> {
      return buildChain([
        { actor: inviter, operation: genesisOp(inviter) },
        { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
      ]);
    }

    it("--github の相手に受諾鍵が登録済みなら、確認入力なしに add_member へ進む(エージェント環境でも)", async () => {
      const built = await chain();
      const state = await backedState(built, [sshLineOf(acceptor)]);
      const env = await backedEnv(state, built.projectId);
      expect(await runCli(["member", "add", "--github", "bob"], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(state.appendedEntries).toHaveLength(1);
      expect(env.logs.join("\n")).toContain(
        "Acceptance key verified: it is registered as a signing key on github.com/bob",
      );
      // 機械照合の成功は帳へ記録しない(帳は人間の帯域外確認の記録 — 裁定 D ②)
      await expect(readBook(env)).rejects.toThrow();

      const state2 = await backedState(built, [sshLineOf(acceptor)]);
      const env2 = await backedEnv(state2, built.projectId);
      env2.setAgent({ isAgent: true, name: "test-agent" });
      expect(await runCli(["member", "add", "--github", "bob"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(0);
      expect(state2.appendedEntries).toHaveLength(1);
    });

    it("発行ピンの宛先 login を既定に使い、--expect-fingerprint は照合に加えて要求する", async () => {
      const built = await chain();
      const state = await backedState(built, [sshLineOf(acceptor)]);
      const env = await backedEnv(state, built.projectId);
      const issued = await issuedFor(built.projectId);
      await mkdir(env.pinsDir, { recursive: true });
      await writeFile(
        join(env.pinsDir, `${built.projectId}.json`),
        JSON.stringify({
          v: 1,
          anchor: null,
          issued: {
            [INVITE_ID]: {
              linkPubHex: issued.linkPubHex,
              role: "member",
              expiresAtMs: 1755993600000,
              expectedGithubLogin: "bob",
            },
          },
        }),
      );
      expect(await runCli(["member", "add"], env.layer)).toBe(0);
      expect(env.prompts).toHaveLength(0);
      expect(env.logs.join("\n")).toContain("The invite was issued for github.com/bob");
      expect(state.appendedEntries).toHaveLength(1);

      const state2 = await backedState(built, [sshLineOf(acceptor)]);
      const env2 = await backedEnv(state2, built.projectId);
      expect(
        await runCli(
          ["member", "add", "--github", "bob", "--expect-fingerprint", "0".repeat(32)],
          env2.layer,
        ),
      ).toBe(1);
      expect(env2.errors.join("\n")).toContain("The acceptance may have been hijacked");
      expect(state2.appendedEntries).toHaveLength(0);
    });

    it("未登録は二択で止まる(既定 = 頼んで再実行、yes = 今すぐ儀式)。取得不能は儀式へ", async () => {
      const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
      if (acceptorFpBytes === null) throw new Error("fp");
      const words = await fingerprintToWords(acceptorFpBytes);
      if (!words.ok) throw new Error("words");
      const built = await chain();

      // 未登録 + 空応答 → 追記せずに止まる
      const state = await backedState(built, [sshLineOf(inviter)]);
      const env = await backedEnv(state, built.projectId);
      env.setPromptResponses([""]);
      expect(await runCli(["member", "add", "--github", "bob"], env.layer)).toBe(1);
      expect(env.prompts[0]).toContain("Type yes to confirm the 12 words now");
      expect(env.errors.join("\n")).toContain(
        "Ask github.com/bob to register their key with `maruhi key publish`",
      );
      expect(state.appendedEntries).toHaveLength(0);

      // 未登録 + yes → 儀式(最終語)へ
      const state2 = await backedState(built, [sshLineOf(inviter)]);
      const env2 = await backedEnv(state2, built.projectId);
      env2.setPromptResponses(["yes", words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env2.layer)).toBe(0);
      expect(env2.prompts).toHaveLength(2);
      expect(env2.prompts[1]).toContain("type the last of the 12 words");
      expect(state2.appendedEntries).toHaveLength(1);

      // 取得不能(上限)→ note + 儀式(二択は出さない)
      const state3 = await backedState(built, [], 403);
      const env3 = await backedEnv(state3, built.projectId);
      env3.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env3.layer)).toBe(0);
      expect(env3.prompts).toHaveLength(1);
      expect(env3.errors.join("\n")).toContain("could not be fetched");
      expect(state3.appendedEntries).toHaveLength(1);

      // identityBacking = none → 照合しない(note + 儀式)
      const state4 = await backedState(built, [sshLineOf(acceptor)]);
      const env4 = await backedEnv(state4, built.projectId);
      await seedConfig(env4, {
        server: env4.serverOrigin,
        defaultProject: built.projectId,
        identityBacking: "none",
      });
      env4.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
      expect(await runCli(["member", "add", "--github", "bob"], env4.layer)).toBe(0);
      expect(env4.errors.join("\n")).toContain("identityBacking is none");
      expect(env4.prompts).toHaveLength(1);
    });
  });

  it("検証済み指紋帳: 儀式の成功が記録され、再実行は yes 確認のみで通る(エージェント環境は据え置き拒否)(KF)", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
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
    });
    const env = await startAddEnv(state, built.projectId);

    // 1 回目: 儀式(最終語再入力)→ 成功が帳へ記録される
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    const recorded = await readBook(env);
    expect(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprintHex).toBe(
      acceptor.fingerprintHex,
    );
    expect(env.errors.join("\n")).toContain("recorded the verified fingerprint");

    // 2 回目(在籍済み → バックフィルのみの再実行): 帳のヒットで 12 語の
    // 読み上げ再実施は免除されるが、付与そのものの明示確認(yes)は残る。
    // 読み上げ照合の指示 2 行はヒット時は出さない(指示直後に免除を言わない)
    const logsBeforeSecondRun = env.logs.length;
    env.setPromptResponses(["yes"]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(2);
    expect(env.prompts[1]).toContain("Type yes to add");
    const secondRunLogs = env.logs.slice(logsBeforeSecondRun).join("\n");
    expect(secondRunLogs).toContain("not required again");
    expect(secondRunLogs).not.toContain("reads to you out of band");

    // 3 回目(エージェント環境): 帳のヒットがあっても代行は拒否(フラグ必須)
    env.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["member", "add"], env.layer)).toBe(1);
    expect(env.prompts).toHaveLength(2);
    expect(env.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );

    // 4 回目(非対話 — stdin がパイプ): 帳のヒットがあっても yes 確認へは
    // 進めず、完全な儀式(最終語再入力)へ戻る(盲目的な `printf yes |` で
    // 通らない — 一次境界は端末)
    env.setAgent({ isAgent: false });
    env.setTerminal({ stdin: false });
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(3);
    expect(env.prompts[2]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdin is not an interactive terminal");

    // 5 回目(stdout がリダイレクト): 境界は stdin と stdout の両方(&&)—
    // 片側だけの実装ミスを固定する
    env.setTerminal({ stdin: true, stdout: false });
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(4);
    expect(env.prompts[3]).toContain("type the last of the 12 words");
    expect(env.errors.join("\n")).toContain("stdout is not an interactive terminal");
  });

  it("検証済み指紋帳: 不一致は自動で通さず警告して儀式へ戻し、成功で上書きする(KF)", async () => {
    const acceptorFpBytes = decodeHex(acceptor.fingerprintHex);
    if (acceptorFpBytes === null) throw new Error("fp");
    const words = await fingerprintToWords(acceptorFpBytes);
    if (!words.ok) throw new Error("words");

    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
    ]);
    const invitation = invitationRow(
      built.projectId,
      await acceptanceFor(built.projectId, acceptor),
    );
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
    const seedStaleBook = async (env: TestEnv & { readonly serverOrigin: string }) => {
      await writeFile(
        env.fingerprintBookPath,
        JSON.stringify({
          v: 1,
          known: {
            [env.serverOrigin]: {
              [acceptor.userId]: { fingerprintHex: "00".repeat(16), verifiedAtMs: 1700000000000 },
            },
          },
        }),
      );
    };

    // 対話環境: 警告 + 儀式は省略されない。成功で帳が新指紋へ上書きされる
    // (`maruhi key generate` による正当な鍵更新の反映)
    const state = await makeAddServer({ built, invitation, ownDeks });
    const env = await startAddEnv(state, built.projectId);
    await seedStaleBook(env);
    env.setPromptResponses([words.value[words.value.length - 1] ?? ""]);
    expect(await runCli(["member", "add"], env.layer)).toBe(0);
    expect(env.prompts).toHaveLength(1);
    expect(env.errors.join("\n")).toContain("differs from the one verified");
    const recorded = await readBook(env);
    expect(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprintHex).toBe(
      acceptor.fingerprintHex,
    );

    // エージェント環境 + 不一致 + フラグなし = 従来どおり拒否(auto-pass しない)
    const state2 = await makeAddServer({ built, invitation, ownDeks });
    const env2 = await startAddEnv(state2, built.projectId);
    await seedStaleBook(env2);
    env2.setAgent({ isAgent: true, name: "test-agent" });
    expect(await runCli(["member", "add"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain(
      "Refused to run the acceptance-key confirmation ceremony",
    );
    expect(state2.appendedEntries).toHaveLength(0);
  });

  it("検証済み指紋帳: --expect-fingerprint の一致成功も記録する(古い記録の警告はフラグ経路では出ない)(KF)", async () => {
    const built = await buildChain([
      { actor: inviter, operation: genesisOp(inviter) },
      { actor: inviter, operation: createEnvironmentOp(ENV_ID, dek1) },
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
    });
    const env = await startAddEnv(state, built.projectId);
    // 古い記録(正当な鍵更新の直後にフラグで回す形): フラグが実指紋と一致して
    // いるので「the out-of-band check is required again」を出さず、記録を上書き
    await writeFile(
      env.fingerprintBookPath,
      JSON.stringify({
        v: 1,
        known: {
          [env.serverOrigin]: {
            [acceptor.userId]: { fingerprintHex: "00".repeat(16), verifiedAtMs: 1700000000000 },
          },
        },
      }),
    );

    expect(
      await runCli(["member", "add", "--expect-fingerprint", acceptor.fingerprintHex], env.layer),
    ).toBe(0);
    expect(env.errors.join("\n")).not.toContain("differs from the one verified");
    const recorded = await readBook(env);
    expect(recorded[env.serverOrigin]?.[acceptor.userId]?.fingerprintHex).toBe(
      acceptor.fingerprintHex,
    );
  });
});
