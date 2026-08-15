// `maruhi member remove` / `maruhi member change-role`(CRYPTO_SPEC §6.2 / §7 —
// Wave 2 B1b)の統合テスト。
//
// 固定する性質:
//  1. remove_member の追記 + 全環境の強制ローテーション(reason=member-removed)。
//     新エポックのラップ完全集合に削除対象が**含まれない**
//  2. 中断復旧: 追記済み(対象が既に非メンバー)→ 追記せず sweep 再開 /
//     削除後にローテーション済みなら確認のみ(チェーン導出 — 進捗ファイルなし)
//  3. 自己削除・自己降格(member 未満)の拒否(§7 の義務の履行者が消える)
//  4. change-role: member 未満への降格は sweep(reason=role-demoted)、昇格は
//     sweep なし。最初から reader のメンバーへの no-op 再実行は義務なし
//  5. admin / owner 対象の操作は owner のみ(§6.2 の早期検査)

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash } from "@maruhi/crypto";
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
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let target: TestUser;
let admin2: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  target = await makeTestUser("user-target-2222");
  admin2 = await makeTestUser("user-admin2-3333");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

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

interface RemoveServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: RotateBody[];
  readonly counters: { appendAttempts: number };
}

/**
 * remove / change-role フロー用の状態つきモック(server-revoke テストの縮約版):
 * チェーン GET / 追記 POST・環境一覧・pull(変数なし)・rotate 複合の受理。
 */
async function makeRemoveServer(input: {
  readonly built: BuiltChain;
  readonly environments: Readonly<
    Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>
  >;
  /** チェーン追記への差し込み(409 等)。undefined = 受理。 */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** onAppend の差し込み時に、以後のチェーンをこの形へ差し替える(並行追記)。 */
  readonly chainAfterConflict?: BuiltChain;
}): Promise<RemoveServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: RotateBody[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  const listedStatements = await Promise.all(
    Object.keys(environments).map((environmentId) =>
      environmentStatementFor({
        projectId,
        environmentId,
        name: environmentId,
        author: owner,
        head: headOf(input.built, 1),
      }),
    ),
  );

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
    onRequest("GET", `/projects/${projectId}/environments`, () => ({
      status: 200,
      json: {
        environments: listedStatements.map((statement) => ({
          environmentId: statement.environmentId,
          currentEpoch: environments[statement.environmentId]?.currentEpoch ?? 1,
          statement,
        })),
      },
    })),
    (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/pull$`).exec(
        request.path,
      );
      if (match === null || request.method !== "GET") {
        return null;
      }
      const environment = environments[match[1] ?? ""];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
      }
      const statement = listedStatements.find((item) => item.environmentId === match[1]);
      return {
        status: 200,
        json: {
          environmentId: match[1],
          currentEpoch: environment.currentEpoch,
          statement,
          variables: [],
          deletedVariables: [],
          deks: environment.deks,
        },
      };
    },
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/rotate$`).exec(
        request.path,
      );
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      environment.currentEpoch = body.entry.payload.newEpoch;
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== owner.userId) {
          continue;
        }
        environment.deks.push({
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
          environmentId,
          currentEpoch: environment.currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
  ];
  return { handlers, appendedEntries, rotateBodies, counters };
}

async function startEnv(
  state: RemoveServerState,
  projectId: string,
  user: TestUser,
): Promise<TestEnv> {
  const server = await MockServer.start([...state.handlers]);
  servers.push(server);
  const env = await makeTestEnv();
  seedSession(env, server.origin, user);
  await seedConfig(env, { server: server.origin, defaultProject: projectId });
  return env;
}

async function ownerWrap(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<WireRecipientDek> {
  return wrapDekFor({ projectId, environmentId, epoch, dek, recipient: owner, signer: owner });
}

describe("maruhi member remove", () => {
  it("remove_member を追記し、全環境を reason=member-removed で強制ローテーションする(削除対象へラップしない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);

    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "remove_member") throw new Error("remove entry missing");
    expect(entry.payload.targetUserId).toBe(target.userId);

    // §7: 強制ローテーション。ラップ完全集合 = 削除後の現メンバー全員(実行者
    // だけでなく継続メンバー admin2 も含む)。削除対象は含まれない
    expect(state.rotateBodies).toHaveLength(1);
    const rotate = state.rotateBodies[0];
    if (rotate === undefined) throw new Error("rotate body missing");
    expect(rotate.entry.payload.newEpoch).toBe(2);
    expect(rotate.entry.payload.reason).toBe("member-removed");
    expect(rotate.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, admin2.userId].toSorted(),
    );

    const logs = env.logs.join("\n");
    expect(logs).toContain("remove_member をチェーンへ追記しました");
    expect(logs).toContain("完了: メンバー削除と全環境ローテーションが完了しました");
  });

  it("ChainHeadConflict(409)の再同期で並行削除を検出したら、追記せず sweep へ進む(§12-4)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    // 送信と並行して別の owner 端末が同じ対象を削除していた(延長チェーン)
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
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
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    // 追記の試行は 1 回(409)のみ — 再同期で削除済みを検出し、二重追記しない
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    // §7 の義務(sweep)は自分の分として履行する
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("対象は既に削除済みでした");
  });

  it("中断復旧: 対象が既に非メンバー(remove 記録あり)なら追記せず sweep を再開する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain("対象は既に削除済みでした");
  });

  it("中断復旧: 削除後にローテーション済み・再暗号化完了なら確認のみで何も変えない(冪等)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: removeMemberOp(target) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 2, deks: [await ownerWrap(built.projectId, ENV_ID, 2, dek2)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain("ローテーション済み(義務エントリより後のエポック");
  });

  it("自分自身の削除は拒否する(§7 の義務を本人が履行できない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", owner.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("自分自身は削除できません");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("admin による admin の削除は owner のみ・未知の対象はエラー(§6.2 の早期検査)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "admin") },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("owner のみが実行できます");
    expect(state.appendedEntries).toHaveLength(0);

    const state2 = await makeRemoveServer({ built, environments: {} });
    const env2 = await startEnv(state2, built.projectId, owner);
    expect(await runCli(["member", "remove", "user-nobody-0000"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("チェーン上に削除記録もありません");
  });
});

describe("maruhi member change-role", () => {
  it("member 未満への降格は追記 + 全環境ローテーション(reason=role-demoted)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({ targetUserId: target.userId, newRole: "reader" });
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    // 降格者は reader として新エポックのラップを受け取り続ける(§7 — 機密性では
    // なくエポックアンカーの健全性の義務)
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, target.userId].toSorted(),
    );
    expect(env.logs.join("\n")).toContain("完了: 降格と全環境ローテーションが完了しました");
  });

  it("昇格(reader → member)はローテーション義務なし", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "完了: role を変更しました(ローテーション義務はありません)",
    );
  });

  it("最初から reader のメンバーへの no-op 再実行は追記も sweep もしない", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "完了: role を変更しました(ローテーション義務はありません)",
    );
  });

  it("中断復旧: 降格エントリ追記済み・ローテーション未了なら、追記せず sweep を再開する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
      {
        actor: owner,
        operation: {
          op: "change_role",
          payload: { targetUserId: target.userId, newRole: "reader" },
        },
      },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.logs.join("\n")).toContain("対象は既に指定の role です");
  });

  it("born-reader への no-op 再実行は、他人の未収束義務があっても sweep を拾わない(対象スコープの基準)", async () => {
    // target は最初から reader(自身の降格義務なし)。他人(admin2)の remove が
    // 後段にあり、そのローテーションは未収束 — Cursor bot 指摘の回帰: 大域基準だと
    // この no-op が admin2 の義務を拾って全環境ローテーションを開始してしまう
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: addMemberOp(admin2, "member") },
      { actor: owner, operation: removeMemberOp(admin2) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: {
        [ENV_ID]: { currentEpoch: 1, deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)] },
      },
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(env.logs.join("\n")).toContain(
      "完了: role を変更しました(ローテーション義務はありません)",
    );
  });

  it("自分自身の member 未満への降格は拒否する(§7 の義務を本人が履行できない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(admin2, "owner") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", owner.userId, "--role", "reader"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("自分自身を member 未満へ降格できません");
    expect(state.appendedEntries).toHaveLength(0);
  });
});
