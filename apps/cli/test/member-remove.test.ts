// `maruhi member remove` / `maruhi member change-role`(CRYPTO_SPEC §6.2 / §7)の
// 統合テスト。
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
  addScopedMemberOp,
  buildChain,
  type BuiltChain,
  changeRoleOp,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  headOf,
  makeTestUser,
  manifestFor,
  removeMemberOp,
  rotateEpochOp,
  type TestUser,
  type WireCheckpointSnapshot,
  type WireDistributedManifest,
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
  /** 同梱マニフェスト(§12-4 — 発行形。issuer は呼び出し主体が契約)。 */
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  /** 境界 checkpoint(H+2 — §12-4 の必須同梱)。 */
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

interface RemoveServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: RotateBody[];
  /** dek_wraps 登録(change-role の拡大分バックフィル — §12-6)。 */
  readonly registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[];
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
  /** rotate 複合を送る実行者(既定 = owner)。受理したマニフェストの issuer と保存する自分宛ラップの受信者。 */
  readonly rotator?: TestUser;
}): Promise<RemoveServerState> {
  const rotator = input.rotator ?? owner;
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: RotateBody[] = [];
  const registerBodies: { environmentId: string; deks: readonly WrappedDek[] }[] = [];
  const counters = { appendAttempts: 0 };
  const environments = input.environments;
  /** 環境ごとの保存済み最新マニフェスト(初回 pull で遅延発行 → rotate 受理で置換)。 */
  const manifests = new Map<string, WireDistributedManifest>();
  /** 環境ごとの保存済みチェックポイントスナップショット(§16-2 — 変数なし = 空列挙)。 */
  const checkpointSnapshots = new Map<string, WireCheckpointSnapshot>();
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
    async (request) => {
      const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/pull$`).exec(
        request.path,
      );
      if (match === null || request.method !== "GET") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
      }
      const statement = listedStatements.find((item) => item.environmentId === match[1]);
      let manifest = manifests.get(environmentId);
      if (manifest === undefined && statement !== undefined) {
        manifest = await manifestFor({
          projectId,
          environmentId,
          epoch: environment.currentEpoch,
          issuer: owner,
          head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
          envStatement: statement,
          statements: [],
        });
        manifests.set(environmentId, manifest);
      }
      const checkpointSnapshot = checkpointSnapshots.get(environmentId);
      return {
        status: 200,
        json: {
          environmentId: match[1],
          currentEpoch: environment.currentEpoch,
          statement,
          variables: [],
          deletedVariables: [],
          deks: environment.deks,
          manifest,
          // 基準 checkpoint の保存行があれば必ず同梱(§12-7 — 規則 2 の材料)
          ...(checkpointSnapshot === undefined ? {} : { checkpointSnapshot }),
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
      // rotate + 境界 checkpoint の 2 エントリ受理(§12-4)
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      // 受理と同一トランザクションのスナップショット保存(§16-2 — 変数なし = 空)
      checkpointSnapshots.set(environmentId, {
        chainSeq: entries.length,
        entryHashHex: hashes[hashes.length - 1] ?? "",
        values: [],
      });
      environment.currentEpoch = body.entry.payload.newEpoch;
      // 受理した同梱マニフェスト(§12-4)を保存最新として配布へ回す(§12-5)
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: rotator.userId,
        issuerKeyFingerprintHex: rotator.fingerprintHex,
      });
      for (const wrap of body.deks) {
        if (wrap.recipientUserId !== rotator.userId) {
          continue;
        }
        environment.deks.push({
          suite: wrap.suite,
          epoch: wrap.epoch,
          encHex: wrap.encHex,
          ciphertextHex: wrap.ciphertextHex,
          signatureHex: wrap.signatureHex,
          signerUserId: rotator.userId,
          signerKeyFingerprintHex: rotator.fingerprintHex,
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
  // dek_wraps(自分宛の取得 = バックフィルの入力 / 登録 = 拡大分の出力)
  handlers.push((request) => {
    const match = new RegExp(`^/projects/${projectId}/environments/([^/]+)/deks$`).exec(
      request.path,
    );
    if (match === null) {
      return null;
    }
    const environment = environments[match[1] ?? ""];
    if (environment === undefined) {
      return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId: match[1] } };
    }
    if (request.method === "GET") {
      return { status: 200, json: { deks: environment.deks } };
    }
    if (request.method === "POST") {
      const body = request.body as { readonly deks: readonly WrappedDek[] };
      registerBodies.push({ environmentId: match[1] ?? "", deks: body.deks });
      return { status: 204 };
    }
    return null;
  });
  return { handlers, appendedEntries, rotateBodies, registerBodies, counters };
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
    expect(logs).toContain("Appended remove_member to the chain");
    expect(logs).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
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
    expect(env.logs.join("\n")).toContain("The target was already removed");
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
    expect(env.logs.join("\n")).toContain("The target was already removed");
    // 収束系コマンドでは未収束義務の常時警告(rotation-sweep.ts)を出さない:
    // このチェーンは同期時点で未収束(remove 後の rotate なし)だが、自分の
    // sweep 報告が同じ事実をより正確に伝えるため二重に警告しない
    expect(env.errors.join("\n")).not.toContain("unconverged rotation mandate");
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
    expect(env.logs.join("\n")).toContain("Already rotated (epoch newer than the mandate entry");
  });

  it("自分自身の削除は拒否する(§7 の義務を本人が履行できない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", owner.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot remove yourself");
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
    expect(env.errors.join("\n")).toContain(
      "Only an owner can run remove_member against an admin / owner",
    );
    expect(state.appendedEntries).toHaveLength(0);

    const state2 = await makeRemoveServer({ built, environments: {} });
    const env2 = await startEnv(state2, built.projectId, owner);
    expect(await runCli(["member", "remove", "user-nobody-0000"], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("the chain has no removal record for it");
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
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "reader",
      // K2 の CLI は対象の現 scope(all)を据え置く(--env は K4)
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    // 降格者は reader として新エポックのラップを受け取り続ける(§7 — 機密性では
    // なくエポックアンカーの健全性の義務)
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId).toSorted()).toEqual(
      [owner.userId, target.userId].toSorted(),
    );
    expect(env.logs.join("\n")).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
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
      "Done: the role / scope was changed (no rotation mandate)",
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
      "Done: the role / scope was changed (no rotation mandate)",
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
          payload: {
            targetUserId: target.userId,
            newRole: "reader",
            scopeKind: "all",
            scopeEnvironmentIds: [],
          },
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
    expect(env.logs.join("\n")).toContain("The target already has the specified role");
  });

  it("born-reader への no-op 再実行は、他人の未収束義務があっても sweep を拾わない(対象スコープの基準)", async () => {
    // target は最初から reader(自身の降格義務なし)。他人(admin2)の remove が
    // 後段にあり、そのローテーションは未収束 — 大域基準だと
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
      "Done: the role / scope was changed (no rotation mandate)",
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
    expect(env.errors.join("\n")).toContain("You cannot demote yourself below member");
    expect(state.appendedEntries).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 環境スコープ(2026-09-15 ES K4 — CRYPTO_SPEC §6.2 / §7、設計録 es-design.md §10)
// ---------------------------------------------------------------------------

const ENV_DEV = "env-dev";
const ENV_PROD = "env-prod";

/** dev / prod の 2 環境(エポック 1)を持つモックの環境集合(owner 宛ラップつき)。 */
async function twoEnvironments(
  projectId: string,
): Promise<Record<string, { currentEpoch: number; deks: WireRecipientDek[] }>> {
  return {
    [ENV_DEV]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_DEV, 1, dek1)] },
    [ENV_PROD]: { currentEpoch: 1, deks: [await ownerWrap(projectId, ENV_PROD, 1, dek2)] },
  };
}

describe("環境スコープ(ES K4): 義務の環境集合と change-role --env", () => {
  it("listed{dev} のメンバー削除は dev だけを rotate する(remove = 対象の現 scope — §7)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("member-removed");
    expect(env.logs.join("\n")).toContain(
      "Done: the member removal and the rotation of every environment in the target's scope completed",
    );
  });

  it("change-role --env で縮小すると縮小分だけを reason=scope-narrowed で rotate し、新 DEK は対象へラップしない(R(E))", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    // role は据え置き(--role 省略)、scope は全置換(§6.2)
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
    // 新エポックの完全集合 = R(prod) = { owner }(縮小した対象を含まない — §6.3)
    expect(state.rotateBodies[0]?.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(state.registerBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`scope=${ENV_DEV}`);
    expect(logs).toContain("Scope narrowed by 1 environment");
    expect(logs).toContain(
      "Done: the change and the rotation of the affected environments completed",
    );
  });

  it("change-role --all-envs で拡大すると拡大分の全エポックを対象へバックフィルし、rotate はしない(§12-6)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies).toHaveLength(0);
    // 拡大分 = prod のみ(dev は既に持つ)。受信者 = 対象、エポック 1
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.registerBodies[0]?.deks.map((wrap) => [wrap.epoch, wrap.recipientUserId])).toEqual(
      [[1, target.userId]],
    );
    const logs = env.logs.join("\n");
    expect(logs).toContain("Scope widened by 1 environment");
    expect(logs).toContain("Done: the role / scope was changed (no rotation mandate)");
  });

  it("中断復旧: 縮小エントリ追記済み・rotate 未了なら、同じフラグの再実行が追記せず縮小分だけを rotate する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "member") },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_PROD]);
    expect(env.logs.join("\n")).toContain("nothing was appended");
  });

  it("CAS リトライは据え置き側(role / scope)を再同期後のビューから解決し、並行の変更を上書きしない(Cursor Bugbot)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
    ]);
    // 送信と並行して別の owner 端末が対象を member へ昇格していた(延長チェーン)
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addMemberOp(target, "reader") },
      { actor: owner, operation: changeRoleOp(target, "member", null) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
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

    // scope だけを変える実行: 再署名は並行昇格後の role(member)を据え置く
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], env.layer),
    ).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toEqual({
      targetUserId: target.userId,
      newRole: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: [ENV_DEV],
    });
    expect(entry.seq).toBe(6);
  });

  it("入力規則: 変更なし・--env と --all-envs の併用・owner への --env は usage エラー(通信前)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "admin") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId],
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--all-envs"],
      ["member", "change-role", target.userId, "--role", "owner", "--env", ENV_DEV],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
    // 未知の環境 id はチェーン上の存在検査で止まる(unknown-environment の手前判定)
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", "env-nope"], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("does not exist on this project's chain");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("値付き pull は scope 外を通信前に拒否し、メタのみ(schema)は scope を問わない(§6.3 / §12-7 — 裁定 G-2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const server = await MockServer.start([...state.handlers]);
    servers.push(server);
    const env = await makeTestEnv();
    seedSession(env, server.origin, target);
    await seedConfig(env, { server: server.origin, defaultProject: built.projectId });

    expect(await runCli(["pull", "--env", ENV_PROD], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      `Cannot operate on environment ${ENV_PROD}: it is outside your environment scope`,
    );
    expect(env.errors.join("\n")).toContain(`your scope: ${ENV_DEV}`);
    expect(server.requests.filter((request) => request.path.includes("/pull"))).toHaveLength(0);

    // メタのみ pull(`maruhi schema`)は scope 外でも要求を出す(モックは持たないので
    // 404 で終わるが、scope の拒否文言では止まらない)
    const schemaEnv = await makeTestEnv();
    seedSession(schemaEnv, server.origin, target);
    await seedConfig(schemaEnv, { server: server.origin, defaultProject: built.projectId });
    await runCli(["schema", "--env", ENV_PROD], schemaEnv.layer);
    expect(schemaEnv.errors.join("\n")).not.toContain("outside your environment scope");
    expect(
      server.requests.filter((request) => request.path.includes(`/${ENV_PROD}/pull/metadata`)),
    ).toHaveLength(1);
  });

  it("中断復旧: 拡大バックフィルの中断後に第三者の change_role が挟まっても、履歴全体から拡大分を再導出して再開する(pullfrog)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV]) },
      // 拡大(バックフィル中断)→ 第三者が role だけを変える change_role を追記
      { actor: owner, operation: changeRoleOp(target, "member", null) },
      { actor: owner, operation: changeRoleOp(target, "admin", null) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);

    expect(await runCli(["member", "change-role", target.userId, "--all-envs"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
    expect(state.rotateBodies).toHaveLength(0);
  });

  it("自分自身の scope の縮小は拒否する(§7 の義務を本人が履行できない)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(admin2, "admin", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, admin2);
    expect(
      await runCli(["member", "change-role", admin2.userId, "--env", ENV_DEV], env.layer),
    ).toBe(1);
    expect(env.errors.join("\n")).toContain("You cannot narrow your own scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("--role owner は listed の対象でも scope を all に全置換し、拡大分をバックフィルする(§6.2 owner = all)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "owner"], env.layer),
    ).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({ newRole: "owner", scopeKind: "all" });
    expect(state.registerBodies.map((body) => body.environmentId)).toEqual([ENV_PROD]);
  });

  it("--no-envs は listed{}(環境ゼロ)へ置換し、旧 scope の全環境を縮小分として rotate する(§6.2 の空 listed)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(target, "admin", [ENV_DEV]) },
    ]);
    const state = await makeRemoveServer({
      built,
      environments: await twoEnvironments(built.projectId),
    });
    const env = await startEnv(state, built.projectId, owner);
    expect(await runCli(["member", "change-role", target.userId, "--no-envs"], env.layer)).toBe(0);
    const entry = state.appendedEntries[0];
    if (entry?.op !== "change_role") throw new Error("change_role entry missing");
    expect(entry.payload).toMatchObject({
      newRole: "admin",
      scopeKind: "listed",
      scopeEnvironmentIds: [],
    });
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("scope-narrowed");
  });

  it("change-role の --env は重複・不正形式を usage(2)で通信前に落とす", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: addMemberOp(target, "member") },
    ]);
    for (const argv of [
      ["member", "change-role", target.userId, "--env", ENV_DEV, "--env", ENV_DEV],
      ["member", "change-role", target.userId, "--env", "-bad id"],
      ["member", "change-role", target.userId, "--no-envs", "--all-envs"],
    ]) {
      const state = await makeRemoveServer({ built, environments: {} });
      const env = await startEnv(state, built.projectId, owner);
      expect(await runCli(argv, env.layer), argv.join(" ")).toBe(2);
      expect(state.appendedEntries, argv.join(" ")).toHaveLength(0);
    }
  });

  it("実行者の scope 外に残る他人の義務環境は rotate せず注記し、自分の義務は履行する(§7 — 独立レビュー S2)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    // owner が target を {dev, prod} → {dev} に縮めたが prod の rotate は未収束。dev 専任
    // admin が target を reader へ降格する(対称差 ∅・旧 ∪ 新 = {dev} ⊆ {dev})
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "member", [ENV_DEV, ENV_PROD]) },
      { actor: owner, operation: changeRoleOp(target, "member", [ENV_DEV]) },
    ]);
    // 配布される自分宛ラップは実行者(devAdmin)宛(モックは受信者で絞らないため差し替える)
    const environments = {
      [ENV_DEV]: {
        currentEpoch: 1,
        deks: [
          await wrapDekFor({
            projectId: built.projectId,
            environmentId: ENV_DEV,
            epoch: 1,
            dek: dek1,
            recipient: devAdmin,
            signer: owner,
          }),
        ],
      },
      [ENV_PROD]: { currentEpoch: 1, deks: [] },
    };
    const state = await makeRemoveServer({ built, environments, rotator: devAdmin });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "reader"], env.layer),
    ).toBe(0);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_DEV]);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("role-demoted");
    expect(env.errors.join("\n")).toContain(
      `1 environment with a pending rotation mandate is outside your scope and cannot be rotated by you (${ENV_PROD})`,
    );
  });

  it("listed の admin は自分の scope 外の対象を remove できない(原則 1 の手前判定 — pullfrog)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    const state = await makeRemoveServer({ built, environments: {} });
    const env = await startEnv(state, built.projectId, devAdmin);
    expect(await runCli(["member", "remove", target.userId], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("does not contain the target's scope");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("listed の admin は自分の scope 外に触れる change_role を追記できない(原則 1 の手前判定)", async () => {
    const devAdmin = await makeTestUser("user-devadmin-4444");
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_DEV, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_PROD, dek2) },
      { actor: owner, operation: addScopedMemberOp(devAdmin, "admin", [ENV_DEV]) },
      { actor: owner, operation: addScopedMemberOp(target, "reader", [ENV_DEV, ENV_PROD]) },
    ]);
    // 対称差 {prod} ⊄ {dev}: dev 専任 admin は prod からの縮小を署名できない
    const narrow = await makeRemoveServer({ built, environments: {} });
    const narrowEnv = await startEnv(narrow, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--env", ENV_DEV], narrowEnv.layer),
    ).toBe(1);
    expect(narrowEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(narrow.appendedEntries).toHaveLength(0);
    // role が変わる場合は 旧 ∪ 新 = {dev, prod} ⊄ {dev}
    const promote = await makeRemoveServer({ built, environments: {} });
    const promoteEnv = await startEnv(promote, built.projectId, devAdmin);
    expect(
      await runCli(["member", "change-role", target.userId, "--role", "member"], promoteEnv.layer),
    ).toBe(1);
    expect(promoteEnv.errors.join("\n")).toContain("scope-not-contained");
    expect(promote.appendedEntries).toHaveLength(0);
  });
});
