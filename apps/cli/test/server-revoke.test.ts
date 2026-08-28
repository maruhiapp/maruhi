// `maruhi server revoke`(CRYPTO_SPEC §7 / §6.2 — Wave 2 A1)の統合テスト。
//
// 固定する性質:
//  1. revoke_server の追記(payload = 失効対象のサーバー鍵 FP)と、§7 の
//     全環境強制ローテーション(reason = "server-revoked"・forceNewEpoch)。
//     ローテーションの複合にはサーバー宛ラップが**含まれない**(失効の実効)
//  2. 中断復旧: 進捗ファイルなしで、チェーンと検証済みステートメントだけから
//     続きを導出する — 追記済み → ローテーションのみ、エポックは進んだが
//     再暗号化未完 → 再開(新エポックなし)、全て完了 → 確認のみ。
//     「エポックが進んだだけの見せかけの完了」で exit 0 にしない
//  3. CAS 競合で並行 revoke を検出したら、追記せずローテーションへ継続する
//  4. 削除済み環境は**検証済みの削除ステートメント**がある場合のみスキップし、
//     1 環境の失敗は残りを止めず exit 1 で報告する(§7 — 黙ってスキップしない)
//  5. 認可・選択の分岐: owner 限定、複数 grant は --fingerprint 必須、
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
  encryptValueFor,
  environmentStatementFor,
  genesisOp,
  grantServerOp,
  headOf,
  hexBytes,
  makeTestUser,
  manifestFor,
  revokeServerOp,
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
import { type MockHandler, type MockResponse, MockServer, onRequest } from "./support/server.ts";

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
  /** 同梱マニフェスト(§12-4 — 発行形。issuer は呼び出し主体が契約)。 */
  readonly manifest: Omit<WireDistributedManifest, "issuerUserId" | "issuerKeyFingerprintHex">;
  /** 境界 checkpoint(H+2 — §12-4 の必須同梱)。 */
  readonly checkpoint: ChainEntry & { readonly op: "checkpoint" };
}

/** pull 応答の 1 変数(検証済みステートメント + 配布形の値)。 */
interface PulledVariable {
  readonly variableId: string;
  readonly statement: WireDistributedVariableStatement;
  value: WireDistributedValue;
}

interface RevokeEnvironmentFixture {
  currentEpoch: number;
  readonly deks: WireRecipientDek[];
  readonly variables?: PulledVariable[];
}

interface RevokeServerState {
  readonly handlers: readonly MockHandler[];
  readonly appendedEntries: ChainEntry[];
  /** 差し込みで拒否された試行も含む追記 POST の回数。 */
  readonly counters: { appendAttempts: number };
  readonly rotateBodies: RotateBody[];
  readonly pushes: { readonly environmentId: string; readonly variableId: string }[];
}

/**
 * revoke フロー用の状態つきモック: チェーン(GET / 追記 POST)・環境一覧
 * (署名済みステートメント)・環境ごとの pull / rotate / push。受理した
 * rotate はチェーンへ追記し owner 宛ラップを配布集合へ反映、受理した push は
 * 最新値へ反映する — 受理後の再同期・再走査が実データで通る。
 */
async function makeRevokeServer(input: {
  readonly built: BuiltChain;
  readonly environments?: Readonly<Record<string, RevokeEnvironmentFixture>>;
  /** 環境一覧のステートメント(省略 = environments の active ステートメントを合成)。 */
  readonly listedStatements?: readonly WireDistributedEnvironmentStatement[];
  /** チェーン追記への差し込み(409 等)。undefined = 受理。 */
  readonly onAppend?: (call: number) => MockResponse | undefined;
  /** onAppend の差し込み時に、以後のチェーンをこの形へ差し替える(並行 revoke)。 */
  readonly chainAfterConflict?: BuiltChain;
  /** rotate への差し込み(環境別)。undefined = 受理。 */
  readonly onRotate?: (environmentId: string) => MockResponse | undefined;
}): Promise<RevokeServerState> {
  const projectId = input.built.projectId;
  const entries: ChainEntry[] = [...input.built.entries];
  const hashes: string[] = [...input.built.hashes];
  const appendedEntries: ChainEntry[] = [];
  const rotateBodies: RotateBody[] = [];
  const pushes: { environmentId: string; variableId: string }[] = [];
  const environments = input.environments ?? {};
  const listedStatements =
    input.listedStatements ??
    (await Promise.all(
      Object.keys(environments).map((environmentId) =>
        environmentStatementFor({
          projectId,
          environmentId,
          name: environmentId,
          author: owner,
          head: headOf(input.built, 1),
        }),
      ),
    ));

  const counters = { appendAttempts: 0 };
  /** 環境ごとの保存済み最新マニフェスト(初回 pull で遅延発行 → rotate 受理で置換)。 */
  const manifests = new Map<string, WireDistributedManifest>();
  const serveManifest = async (
    environmentId: string,
    environment: RevokeEnvironmentFixture,
    statement: WireDistributedEnvironmentStatement | undefined,
  ): Promise<WireDistributedManifest | undefined> => {
    if (statement === undefined) {
      return undefined;
    }
    let manifest = manifests.get(environmentId);
    if (manifest === undefined) {
      manifest = await manifestFor({
        projectId,
        environmentId,
        epoch: environment.currentEpoch,
        issuer: owner,
        head: { seq: entries.length, hashHex: hashes[hashes.length - 1] ?? "" },
        envStatement: statement,
        statements: (environment.variables ?? []).map((variable) => variable.statement),
      });
      manifests.set(environmentId, manifest);
    }
    return manifest;
  };
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
      return {
        status: 200,
        json: {
          environmentId: match[1],
          currentEpoch: environment.currentEpoch,
          statement,
          variables: environment.variables ?? [],
          deletedVariables: [],
          deks: environment.deks,
          manifest: await serveManifest(environmentId, environment, statement),
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
      const injected = input.onRotate?.(environmentId);
      if (injected !== undefined) {
        return injected;
      }
      const body = request.body as RotateBody;
      rotateBodies.push(body);
      // rotate + 境界 checkpoint の 2 エントリ受理(§12-4)
      entries.push(body.entry, body.checkpoint);
      hashes.push(
        await computeChainEntryHash(body.entry),
        await computeChainEntryHash(body.checkpoint),
      );
      environment.currentEpoch = body.entry.payload.newEpoch;
      // 受理した同梱マニフェスト(§12-4)を保存最新として配布へ回す(§12-5)
      manifests.set(environmentId, {
        ...body.manifest,
        issuerUserId: owner.userId,
        issuerKeyFingerprintHex: owner.fingerprintHex,
      });
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
    (request) => {
      const match = new RegExp(
        `^/projects/${projectId}/environments/([^/]+)/variables/([^/]+)/versions$`,
      ).exec(request.path);
      if (match === null || request.method !== "POST") {
        return null;
      }
      const environmentId = match[1] ?? "";
      const variableId = match[2] ?? "";
      const environment = environments[environmentId];
      if (environment === undefined) {
        return { status: 404, json: { _tag: "EnvironmentNotFound", environmentId } };
      }
      const body = request.body as { readonly value: WireDistributedValue };
      pushes.push({ environmentId, variableId });
      const stored: WireDistributedValue = {
        ...body.value,
        writerUserId: owner.userId,
        writerKeyFingerprintHex: owner.fingerprintHex,
      };
      const target = (environment.variables ?? []).find(
        (variable) => variable.variableId === variableId,
      );
      if (target !== undefined) {
        target.value = stored;
      }
      return {
        status: 200,
        json: { variableId, version: body.value.aad.version, epoch: body.value.aad.epoch },
      };
    },
  ];
  return { handlers, appendedEntries, counters, rotateBodies, pushes };
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

async function ownerWrap(
  projectId: string,
  environmentId: string,
  epoch: number,
  dek: Uint8Array,
): Promise<WireRecipientDek> {
  return wrapDekFor({ projectId, environmentId, epoch, dek, recipient: owner, signer: owner });
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
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
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
    expect(logs).toContain(`Appended revoke_server to the chain (FP=${serverFpA})`);
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
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
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
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
    expect(logs).toContain("No active grant — resuming the post-revocation rotation");
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("CAS 競合で並行 revoke を検出したら、追記せずローテーションへ継続する", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
    ]);
    // 並行実行が先に revoke を積んだ形(先頭 3 エントリは決定論的に同一)
    const concurrent = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
      },
      onAppend: (call) =>
        call === 0
          ? {
              status: 409,
              json: {
                _tag: "ChainHeadConflict",
                currentHeadSeq: 4,
                currentHeadHashHex: concurrent.hashes[3] ?? "",
              },
            }
          : undefined,
      chainAfterConflict: concurrent,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    // 追記の試行は 1 回(409)・受理された追記はゼロ。ローテーションは実行される
    expect(state.counters.appendAttempts).toBe(1);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(1);
    expect(state.rotateBodies[0]?.entry.payload.reason).toBe("server-revoked");
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `The targeted grant (FP=${serverFpA}) was already revoked by a concurrent run`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("中断復旧: エポックは進んだが再暗号化未完なら、新エポックを作らず再開して完了させる", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    // epoch 1 のまま取り残された最新値(前回実行が複合受理後・再暗号化前に中断)
    const staleVariable: PulledVariable = {
      variableId: "var-stale-1",
      statement: await statementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        variableId: "var-stale-1",
        name: "STALE_VALUE",
        author: owner,
        head: headOf(built, 2),
      }),
      value: await encryptValueFor({
        dek: dek1,
        projectId: built.projectId,
        environmentId: ENV_ID,
        epoch: 1,
        variableId: "var-stale-1",
        version: 1,
        plaintext: "dummy-stale-plaintext",
        writer: owner,
        head: headOf(built, 2),
      }),
    };
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 2,
          deks: [
            await ownerWrap(built.projectId, ENV_ID, 1, dek1),
            await ownerWrap(built.projectId, ENV_ID, 2, dek2),
          ],
          variables: [staleVariable],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    // 追記なし・rotate 複合なし(エポックは進めない)。stale 値の再暗号化 push のみ
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes).toEqual([{ environmentId: ENV_ID, variableId: "var-stale-1" }]);
    const logs = env.logs.join("\n");
    expect(logs).toContain("resumed re-encryption");
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
    // 「ローテーション済み」扱いにはならない(見せかけの完了で exit 0 にしない)
    expect(logs).not.toContain("Already rotated (epoch newer than the revocation");
  });

  it("中断復旧: 失効後に全環境が回転済み・再暗号化完了なら、確認のみで何も変えない(冪等)", async () => {
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: await grantServerOp([ENV_ID], [], SERVER_ENC_PUB_A) },
      { actor: owner, operation: revokeServerOp(serverFpA) },
      { actor: owner, operation: rotateEpochOp(ENV_ID, 2, dek2) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 2,
          deks: [await ownerWrap(built.projectId, ENV_ID, 2, dek2)],
        },
      },
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(0);
    expect(state.rotateBodies).toHaveLength(0);
    expect(state.pushes).toHaveLength(0);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `Already rotated (epoch newer than the revocation, no incomplete re-encryption confirmed): ${ENV_ID}`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("削除済み環境は検証済みの削除ステートメントがある場合のみスキップし、残りをローテーションする", async () => {
    const GONE_ID = "env-gone-9";
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_ID, dek1) },
      { actor: owner, operation: createEnvironmentOp(GONE_ID, dek2) },
      { actor: owner, operation: await grantServerOp([ENV_ID, GONE_ID], [], SERVER_ENC_PUB_A) },
    ]);
    const listedStatements = [
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: ENV_ID,
        name: ENV_ID,
        author: owner,
        head: headOf(built, 1),
      }),
      // 署名済みの削除ステートメント(§12-4 — 削除も admin 水準の署名を要する)
      await environmentStatementFor({
        projectId: built.projectId,
        environmentId: GONE_ID,
        name: GONE_ID,
        author: owner,
        head: headOf(built, 4),
        status: "deleted",
        metaVersion: 2,
      }),
    ];
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_ID]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_ID, 1, dek1)],
        },
        // GONE_ID は環境フィクスチャなし = pull / rotate は 404(実サーバーの
        // tombstone と同じ)。検証済み削除によりそもそも呼ばれないことを固定する
      },
      listedStatements,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(0);
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_ID]);
    const logs = env.logs.join("\n");
    expect(logs).toContain(
      `Skipped deleted environments (signed deletion statements verified): ${GONE_ID}`,
    );
    expect(logs).toContain("Done: the revocation and the rotation of every environment completed");
  });

  it("複数環境で 1 環境のローテーションが失敗しても残りを完了し、exit 1 で失敗を報告する", async () => {
    const ENV_A = "env-aaa-1";
    const ENV_B = "env-bbb-2";
    const built = await buildChain([
      { actor: owner, operation: genesisOp(owner) },
      { actor: owner, operation: createEnvironmentOp(ENV_A, dek1) },
      { actor: owner, operation: createEnvironmentOp(ENV_B, dek2) },
      { actor: owner, operation: await grantServerOp([ENV_A, ENV_B], [], SERVER_ENC_PUB_A) },
    ]);
    const state = await makeRevokeServer({
      built,
      environments: {
        [ENV_A]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_A, 1, dek1)],
        },
        [ENV_B]: {
          currentEpoch: 1,
          deks: [await ownerWrap(built.projectId, ENV_B, 1, dek2)],
        },
      },
      onRotate: (environmentId) =>
        environmentId === ENV_B ? { status: 500, json: {} } : undefined,
    });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    // 失敗した ENV_B が ENV_A のローテーションを止めない
    expect(state.appendedEntries).toHaveLength(1);
    expect(state.rotateBodies.map((body) => body.entry.payload.environmentId)).toEqual([ENV_A]);
    const errors = env.errors.join("\n");
    expect(errors).toContain(`Warning: rotation of environment ${ENV_B} failed`);
    expect(env.logs.join("\n")).not.toContain(
      "Done: the revocation and the rotation of every environment completed",
    );
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
    expect(env.errors.join("\n")).toContain("Only an owner can run revoke_server");
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
    expect(env1.errors.join("\n")).toContain("Multiple grants are active");
    expect(state1.appendedEntries).toHaveLength(0);

    // 一致しない FP → エラー(--fingerprint の名でエラーを報告する)
    const state2 = await makeRevokeServer({ built });
    const env2 = await startRevokeEnv(state2, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", "0".repeat(32)], env2.layer)).toBe(1);
    expect(env2.errors.join("\n")).toContain("No active grant matches --fingerprint");
    expect(state2.appendedEntries).toHaveLength(0);

    // 形式不正 → --fingerprint(存在しない --expect-fingerprint ではなく)を名指し
    const state3 = await makeRevokeServer({ built });
    const env3 = await startRevokeEnv(state3, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", "XYZ"], env3.layer)).toBe(2);
    expect(env3.errors.join("\n")).toContain("--fingerprint is malformed");

    // B を指定 → B だけを失効(環境なし = ローテーション対象なしで完了)
    const state4 = await makeRevokeServer({ built });
    const env4 = await startRevokeEnv(state4, built.projectId, owner);
    expect(await runCli(["server", "revoke", "--fingerprint", serverFpB], env4.layer)).toBe(0);
    expect(state4.appendedEntries).toHaveLength(1);
    const revoke = state4.appendedEntries[0];
    if (revoke?.op !== "revoke_server") throw new Error("revoke entry missing");
    expect(revoke.payload.serverKeyFingerprintHex).toBe(serverFpB);
    expect(env4.logs.join("\n")).toContain(
      "Done: the revocation and the rotation of every environment completed",
    );
  });

  it("有効な grant も過去の revoke_server もなければエラー(失効するものがない)", async () => {
    const built = await buildChain([{ actor: owner, operation: genesisOp(owner) }]);
    const state = await makeRevokeServer({ built });
    const env = await startRevokeEnv(state, built.projectId, owner);

    expect(await runCli(["server", "revoke"], env.layer)).toBe(1);
    expect(env.errors.join("\n")).toContain(
      "There is no active grant_server and no revoke_server on the chain (nothing to revoke)",
    );
    expect(state.appendedEntries).toHaveLength(0);
  });
});
