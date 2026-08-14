// `maruhi server revoke`(CRYPTO_SPEC §7 / §6.2 — Wave 2 A1)の統合テスト。
//
// 固定する性質:
//  1. revoke_server の追記(payload = 失効対象のサーバー鍵 FP)と、§7 の
//     全環境強制ローテーション(reason = "server-revoked"・forceNewEpoch)。
//     ローテーションの複合にはサーバー宛ラップが**含まれない**(失効の実効)
//  2. 中断復旧: 進捗ファイルなしで、チェーンだけから「失効後にまだ回って
//     いない環境」を導出して続きから再開する(追記済み → ローテーションのみ、
//     全て回転済み → 何もしない)
//  3. 認可・選択の分岐: owner 限定、複数 grant は --fingerprint 必須、
//     失効対象が何もなければエラー

import type { WrappedDek } from "@maruhi/api-schema";
import type { ChainEntry } from "@maruhi/crypto";
import { computeChainEntryHash, computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { runCli } from "../src/cli.ts";
import {
  addMemberOp,
  buildChain,
  type BuiltChain,
  createEnvironmentOp,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  revokeServerOp,
  rotateEpochOp,
  type TestUser,
  type WireRecipientDek,
  wrapDekFor,
} from "./support/crypto.ts";
import { makeTestEnv, seedConfig, seedSession, type TestEnv } from "./support/env.ts";
import { type MockHandler, MockServer, onRequest } from "./support/server.ts";

const ENV_ID = "env-app-1";

let owner: TestUser;
let member: TestUser;
let dek1: Uint8Array;
let dek2: Uint8Array;

// 失効対象のデプロイメントサーバー鍵(公開面のみ)。B は複数 grant の弁別用
const SERVER_ENC_PUB_A = "5a".repeat(32);
const SERVER_ENC_PUB_B = "5b".repeat(32);
let serverFpA: string;
let serverFpB: string;

const servers: MockServer[] = [];

beforeAll(async () => {
  owner = await makeTestUser("user-owner-1111");
  member = await makeTestUser("user-member-2222");
  dek1 = crypto.getRandomValues(new Uint8Array(32));
  dek2 = crypto.getRandomValues(new Uint8Array(32));
  for (const [pubHex, assign] of [
    [SERVER_ENC_PUB_A, (fp: string) => (serverFpA = fp)],
    [SERVER_ENC_PUB_B, (fp: string) => (serverFpB = fp)],
  ] as const) {
    const fp = await computeServerKeyFingerprint(hexBytes(pubHex));
    if (!fp.ok) throw new Error("server fingerprint failed");
    assign(encodeHex(fp.value));
  }
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

/** rotate 複合ボディ(api-schema の environments.rotate payload)。 */
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

interface RevokeServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  readonly rotateBodies: RotateBody[];
}

/**
 * revoke フロー用の状態つきモック: チェーン(GET / 追記 POST)・pull(変数
 * なし)・rotate 複合の受理(エントリをチェーンへ追記し、owner 宛ラップを
 * 配布集合へ反映)。受理後の再同期確認が実データで通る。
 */
async function makeRevokeServer(input: {
  readonly built: BuiltChain;
  /** pull を提供する環境(なし = pull / rotate を扱わないチェーン専用モック)。 */
  readonly environment?: {
    readonly currentEpoch: number;
    readonly deks: WireRecipientDek[];
  };
}): Promise<RevokeServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: RotateBody[] = [];
  const environment = input.environment;
  let currentEpoch = environment?.currentEpoch ?? 1;
  const statement =
    environment === undefined
      ? null
      : await environmentStatementFor({
          projectId,
          environmentId: ENV_ID,
          name: ENV_ID,
          author: owner,
          head: headOf(input.built, 1),
        });

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
      const body = request.body as { readonly entry: ChainEntry };
      appendedEntries.push(body.entry);
      entries.push(body.entry);
      hashes.push(await computeChainEntryHash(body.entry));
      return {
        status: 200,
        json: { projectId, headSeq: entries.length, headHashHex: hashes[hashes.length - 1] },
      };
    },
    onRequest("GET", `/projects/${projectId}/environments/${ENV_ID}/pull`, () =>
      environment === undefined
        ? { status: 404, json: { _tag: "EnvironmentNotFound" } }
        : {
            status: 200,
            json: {
              environmentId: ENV_ID,
              currentEpoch,
              statement,
              variables: [],
              deletedVariables: [],
              deks: environment.deks,
            },
          },
    ),
    async (request) => {
      if (
        request.method !== "POST" ||
        request.path !== `/projects/${projectId}/environments/${ENV_ID}/rotate` ||
        environment === undefined
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
          environmentId: ENV_ID,
          currentEpoch,
          headSeq: entries.length,
          headHashHex: hashes[hashes.length - 1],
        },
      };
    },
  ];
  return { handlers, appendedEntries, rotateBodies };
}

async function startRevokeEnv(
  state: RevokeServerState,
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

describe("maruhi server revoke", () => {
  it("revoke_server を追記し、全環境を reason=server-revoked で強制ローテーションする(複合にサーバー宛ラップなし)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({
      built,
      environment: {
        currentEpoch: 1,
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
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);

    // 追記された revoke_server(失効対象はサーバー鍵 FP)
    expect(state.appendedEntries).toHaveLength(1);
    const revoke = state.appendedEntries[0];
    if (revoke?.op !== "revoke_server") throw new Error("revoke entry missing");
    expect(revoke.payload.serverKeyFingerprintHex).toBe(serverFpA);

    // §7: 強制ローテーション(newEpoch 2・理由固定)。複合のラップは member
    // のみ = 失効したサーバー鍵へ新 DEK を開示しない
    expect(state.rotateBodies).toHaveLength(1);
    const rotate = state.rotateBodies[0];
    if (rotate === undefined) throw new Error("rotate body missing");
    expect(rotate.entry.payload.newEpoch).toBe(2);
    expect(rotate.entry.payload.reason).toBe("server-revoked");
    expect(rotate.deks.map((wrap) => wrap.recipientUserId)).toEqual([owner.userId]);
    expect(rotate.deks.every((wrap) => wrap.recipientClass === undefined)).toBe(true);

    const logs = env.logs.join("\n");
    expect(logs).toContain(`revoke_server をチェーンへ追記しました(FP=${serverFpA})`);
    expect(logs).toContain("完了: 失効と全環境ローテーションが完了しました");
  });

  it("中断復旧: revoke 追記済み・ローテーション未了なら、追記せずローテーションだけを再開する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
    ]);
    const state = await makeRevokeServer({
      built,
      environment: {
        currentEpoch: 1,
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
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    // 追記なし(有効 grant なし)・現エポック(開始 seq 2 < revoke seq 4)を回転
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.newEpoch).toBe(2);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("server-revoked");
    const logs = env.logs.join("\n");
    expect(logs).toContain("有効な grant はありません");
    expect(logs).toContain("完了: 失効と全環境ローテーションが完了しました");
  });

  it("中断復旧: 失効後に全環境が回転済みなら何もしない(冪等)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(`ローテーション済み(失効より後のエポック): ${ENV_ID}`);
    expect(logs).toContain("完了: 失効と全環境ローテーションが完了しました");
  });

  it("owner 以外は拒否する(§6.2)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: addMemberOp(member, "member") },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, member);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("revoke_server は owner のみが実行できます");
    expect(state.appendedEntries).toHaveLength(0);
  });

  it("有効な grant が複数あれば --fingerprint を要求し、指定された対象だけを失効する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: await grantServerOp([], [], SERVER_ENC_PUB_B) },
    ]);

    // 指定なし → エラー(どちらを失効するか曖昧)
    const state1 = await makeRevokeServer({ built });
    const env1 = await startRevokeEnv(state1, built.projectId, owner);
    expect(await runCli(["server", "revoke"], env1.layer)).toBe(1);
    expect(env1.errors.join("\n")).toContain("有効な grant が複数あります");
    expect(state1.appendedEntries).toHaveLength(0);

    // 一致しない FP → エラー
    const state2 = await makeRevokeServer({ built });
    const env2 = await startRevokeEnv(state2, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", "0".repeat(32)], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("--fingerprint に一致する有効な grant がありません");
    expect(state2.appendedEntries).toHaveLength(0);

    // B を指定 → B だけを失効(環境なし = ローテーション対象なしで完了)
    const state3 = await makeRevokeServer({ built });
    const env3 = await startRevokeEnv(state3, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", serverFpB], env3.layer)).toBe(0);
    expect(state3.appendedEntries).toHaveLength(1);
    const revoke = state3.appendedEntries[0];
    if (revoke?.op !== "revoke_server") throw new Error("revoke entry missing");
    expect(revoke.payload.serverKeyFingerprintHex).toBe(serverFpB);
    expect(env3.logs.join("\n")).toContain("完了: 失効と全環境ローテーションが完了しました");
  });

  it("有効な grant も過去の revoke_server もなければエラー(失効するものがない)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain("失効するものがありません");
    expect(state.appendedEntries).toHaveLength(0);
  });
});
