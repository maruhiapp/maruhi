// 監査ログ(AUDIT_SPEC §3.3 データ系 / §3.4 チェーンミラー / §5.1 スキーマ)の統合テスト。
//
// - seq は単調・無欠番(§5.1 / §6)
// - チェーンミラーは actor(user_id + 鍵 FP)・chain_seq・クライアント / サーバー
//   両時刻を持つ(§3.4)
// - アイデンティティ規則(§1-2): プロバイダ情報・メールが 1 行にも現れないこと

import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { env, evictDurableObject, runInDurableObject, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { makeAuditStore } from "../src/audit-store.ts";
import { JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEnvironmentManifest, WireVariableMetaStatement } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  commitmentOf,
  createVariableStatement,
  digestOf,
  encryptValue,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  signMetaStatementAs,
  valuesDigestOf,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  dataUrl,
  deleteEnvironmentRequest,
  manifestForVariableOp,
  MEMBER,
  OWNER,
  projectId,
  READER,
  renameEnvironmentRequest,
  requestJson,
  rotateEnvironmentOk,
  setupDataProject,
  tokenOf,
} from "./support/data-fixture.ts";
import { readAuditEvents } from "./support/project-do.ts";

const ENV = "env-audit-0001";
const VAR = "var-api-key";

let fixture: DataFixture;
let varStatements: Map<string, { statement: WireVariableMetaStatement; authorUserId: string }>;

beforeEach(async () => {
  fixture = await setupDataProject();
  varStatements = new Map();
});

const token = (userId: string): string => tokenOf(fixture.tokens, userId);

async function createVariableOk(dek: Uint8Array, variableId: string, name: string): Promise<void> {
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId, version: 1 },
    `secret-${variableId}`,
    { writerUserId: MEMBER, head: fixture.head },
  );
  const statement = await createVariableStatement({
    authorUserId: MEMBER,
    projectId,
    environmentId: ENV,
    variableId,
    name,
    head: fixture.head,
  });
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: ENV,
    issuerUserId: MEMBER,
    entry: {
      variableId,
      status: "active",
      metaVersion: 1,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, MEMBER),
    },
  });
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    statement,
    value,
    manifest,
  });
  expect(response.status).toBe(200);
  varStatements.set(variableId, { statement, authorUserId: MEMBER });
  fixture.manifests.set(ENV, state);
}

/** 変数のメタ操作(rename / 削除)に同梱するマニフェスト(§12-5)を署名し、記録を進める。 */
async function manifestForNext(
  statement: WireVariableMetaStatement,
  issuerUserId: string,
): Promise<WireEnvironmentManifest> {
  const { manifest, state } = await manifestForVariableOp(fixture, {
    environmentId: ENV,
    issuerUserId,
    entry: {
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: await metaSignedBytesHashOf(projectId, statement, issuerUserId),
    },
  });
  fixture.manifests.set(ENV, state);
  return manifest;
}

/** 変数の次ステートメント(rename / 削除)を記録済み最新から署名する。 */
async function nextVariableStatement(input: {
  readonly variableId: string;
  readonly name: string;
  readonly status: "active" | "deleted";
  readonly authorUserId: string;
}): Promise<WireVariableMetaStatement> {
  const last = varStatements.get(input.variableId);
  if (last === undefined) throw new Error(`no recorded statement for ${input.variableId}`);
  const statement = await signMetaStatementAs(input.authorUserId, projectId, {
    suite: "maruhi/v1" as const,
    environmentId: ENV,
    variableId: input.variableId,
    name: input.name,
    status: input.status,
    metaVersion: last.statement.metaVersion + 1,
    prevMetaSigHashHex: await metaSignedBytesHashOf(projectId, last.statement, last.authorUserId),
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
  });
  varStatements.set(input.variableId, { statement, authorUserId: input.authorUserId });
  return statement;
}

/**
 * ライフサイクル末尾 5 行(env.renamed → var.renamed → var.deleted →
 * カスケード var.deleted → env.deleted)の author 鍵 FP の検査(AUDIT_SPEC §3.3):
 * メタステートメントを伴う操作は author の鍵 FP を写し、環境削除のカスケード
 * var.deleted は env 削除ステートメントの author FP を写す。
 */
function expectMetaAuthorFingerprints(events: readonly Record<string, unknown>[]): void {
  const tail = events.slice(-5);
  const memberFp = vectorKeyOf(MEMBER).key_fingerprint_hex;
  const ownerFp = vectorKeyOf(OWNER).key_fingerprint_hex;
  expect(tail.map((row) => [row["event"], row["actor_key_fingerprint"]])).toEqual([
    ["env.renamed", memberFp],
    ["var.renamed", memberFp],
    ["var.deleted", memberFp],
    ["var.deleted", ownerFp],
    ["env.deleted", ownerFp],
  ]);
  expect(JSON.parse(String(tail[0]?.["payload"]))).toMatchObject({ name: "App2" });
  expect(JSON.parse(String(tail[1]?.["payload"]))).toMatchObject({ name: "API_KEY_V2" });
}

/** 採番リセット検査用の最小イベント(audit-store.ts の失敗時リセットのテスト入力)。 */
const seqTestEvent = (name: string) =>
  ({ event: name, serverTs: 1, actorType: "user", actorUserId: OWNER }) as const;

describe("チェーンミラー(§3.4)", () => {
  it("mirrors accepted chain entries with actor identity, chain_seq and both timestamps", async () => {
    const events = await readAuditEvents(projectId);
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
    ]);

    const genesis = events[0];
    if (genesis === undefined) throw new Error("missing genesis mirror");
    expect(genesis["seq"]).toBe(1);
    expect(genesis["chain_seq"]).toBe(1);
    expect(genesis["actor_type"]).toBe("user");
    expect(genesis["actor_user_id"]).toBe(OWNER);
    expect(genesis["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    // §3.4: genesis の target には作成者を入れる(在籍区間の開始点)
    expect(genesis["target_user_id"]).toBe(OWNER);
    expect(genesis["client_ts"]).toBeTypeOf("number");
    expect(genesis["server_ts"]).toBeTypeOf("number");

    const addMember = events[1];
    if (addMember === undefined) throw new Error("missing add_member mirror");
    expect(addMember["target_user_id"]).toBe(MEMBER);
    expect(JSON.parse(String(addMember["payload"]))).toEqual({ role: "member" });
  });

  it("mirrors create_environment / rotate_epoch with the dek commitment (§3.4, 2026-08-03)", async () => {
    // 作成・ローテーションとも複合リクエスト(§12-4)経由でチェーンに載る。
    // ミラー payload のコミットメントは同梱 DEK の §5.2 実計算値と一致する
    // (形式だけでなく値まで固定: 別エポックの値や定数を写す変異を落とす)
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const commitment1 = await commitmentOf(projectId, ENV, 1, dek1);
    const commitment2 = await commitmentOf(projectId, ENV, 2, dek2);
    const events = await readAuditEvents(projectId);
    const rotated = events.find((event) => event["event"] === "chain.epoch_rotated");
    const created = events.find((event) => event["event"] === "chain.environment_created");
    if (rotated === undefined || created === undefined) throw new Error("missing mirrors");

    expect(created["environment_id"]).toBe(ENV);
    expect(created["epoch"]).toBe(1);
    expect(created["chain_seq"]).toBe(4);
    expect(created["actor_user_id"]).toBe(OWNER);
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
    // dek_commitment は payload に写す(AUDIT_SPEC §3.4)
    expect(JSON.parse(String(created["payload"]))).toEqual({ dekCommitmentHex: commitment1 });

    expect(rotated["event"]).toBe("chain.epoch_rotated");
    expect(rotated["environment_id"]).toBe(ENV);
    expect(rotated["epoch"]).toBe(2);
    // 複合は create / rotate(H+1)に続けて境界 checkpoint(H+2)を追記する
    // (§12-4 — 2026-08-27)ため、rotate のチェーン seq は 6
    expect(rotated["chain_seq"]).toBe(6);
    expect(JSON.parse(String(rotated["payload"]))).toEqual({
      reason: "scheduled",
      dekCommitmentHex: commitment2,
    });

    // 境界 checkpoint のミラー(chain.checkpointed — AUDIT_SPEC §3.4)は H+2 の
    // seq(作成 = 5、rotate = 7)で記録され、payload に環境タプルを写す
    const checkpoints = events.filter((event) => event["event"] === "chain.checkpointed");
    expect(checkpoints.map((event) => event["chain_seq"])).toEqual([5, 7]);
    const rotateCheckpoint = JSON.parse(String(checkpoints[1]?.["payload"])) as {
      environments: { environmentId: string; epoch: number; manifestVersion: number }[];
    };
    expect(rotateCheckpoint.environments).toHaveLength(1);
    expect(rotateCheckpoint.environments[0]).toMatchObject({
      environmentId: ENV,
      epoch: 2,
      manifestVersion: 2,
    });
  });

  it("mirrors change_role / remove_member with the target user id (§4.1 Q1 の入力)", async () => {
    await appendOperation(fixture, OWNER, {
      op: "change_role",
      payload: { targetUserId: READER, newRole: "admin" },
    });
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: MEMBER },
    });
    const events = await readAuditEvents(projectId);
    const roleChanged = events.at(-2);
    const removed = events.at(-1);
    if (roleChanged === undefined || removed === undefined) throw new Error("missing mirrors");
    expect(roleChanged["event"]).toBe("chain.role_changed");
    expect(roleChanged["target_user_id"]).toBe(READER);
    expect(JSON.parse(String(roleChanged["payload"]))).toEqual({ newRole: "admin" });
    expect(removed["event"]).toBe("chain.member_removed");
    expect(removed["target_user_id"]).toBe(MEMBER);
    expect(removed["actor_user_id"]).toBe(OWNER);
    expect(removed["chain_seq"]).toBe(5);
  });

  it("mirrors grant_server / revoke_server with the server key fingerprint (§4.1 Q6 の入力)", async () => {
    // FP = SHA-256(enc 公開鍵)[:16](CRYPTO_SPEC §9)。チェーン検証が整合を要求する
    const serverEncPubHex = "ab".repeat(32);
    const fpResult = await computeServerKeyFingerprint(hexBytes(serverEncPubHex));
    if (!fpResult.ok) throw new Error("fingerprint failed");
    const serverKeyFingerprintHex = encodeHex(fpResult.value);
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex,
        serverKeyFingerprintHex,
        scopeEnvironmentIds: [ENV],
        leasePolicy: [],
      },
    });
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex },
    });
    const events = await readAuditEvents(projectId);
    const granted = events.at(-2);
    const revoked = events.at(-1);
    if (granted === undefined || revoked === undefined) throw new Error("missing mirrors");
    expect(granted["event"]).toBe("chain.server_granted");
    expect(granted["target_key_fingerprint"]).toBe(serverKeyFingerprintHex);
    expect(granted["target_user_id"]).toBeNull();
    expect(JSON.parse(String(granted["payload"]))).toEqual({ scopeEnvironmentIds: [ENV] });
    expect(revoked["event"]).toBe("chain.server_revoked");
    expect(revoked["target_key_fingerprint"]).toBe(serverKeyFingerprintHex);
  });
});

describe("データ系イベント(§3.3)と無欠番 seq(§5.1)", () => {
  it("records the full lifecycle with gapless seq and per-variable var.read rows", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "API_KEY");
    await createVariableOk(dek, "var-second", "SECOND");

    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);

    // メタデータのみモード(AUTH_SPEC §12-7)は値を配布しないため、var.read を
    // 含む一切の監査行を追加しない(「読んでいないものを読んだと記録しない」—
    // §3.3。下の期待イベント列に本リクエスト由来の行が現れないことが検査)
    const metadataPull = await requestJson(
      "GET",
      `/environments/${ENV}/pull/metadata`,
      token(READER),
    );
    expect(metadataPull.status).toBe(200);

    const envRenamed = await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER);
    expect(envRenamed.status).toBe(204);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      await (async () => {
        const statement = await nextVariableStatement({
          variableId: VAR,
          name: "API_KEY_V2",
          status: "active",
          authorUserId: MEMBER,
        });
        return { statement, manifest: await manifestForNext(statement, MEMBER) };
      })(),
    );
    expect(renamed.status).toBe(204);
    const removedVar = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      await (async () => {
        const statement = await nextVariableStatement({
          variableId: VAR,
          // deleted の name は直前 active 名を保持する(§4.2)
          name: "API_KEY_V2",
          status: "deleted",
          authorUserId: MEMBER,
        });
        return { statement, manifest: await manifestForNext(statement, MEMBER) };
      })(),
    );
    expect(removedVar.status).toBe(204);
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);

    const events = await readAuditEvents(projectId);
    // seq は 1 始まりの無欠番(欠番 = 削除の痕跡 — §6)
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
      // 複合の環境作成(§12-4)はチェーンミラー(create + 境界 checkpoint の
      // 2 エントリ — 2026-08-27)+ env.created + 同梱ラップの dek.registered
      // (1 受信者 1 行 — §3.3)を原子的に書く
      "chain.environment_created",
      "chain.checkpointed",
      "env.created",
      "dek.registered",
      "dek.registered",
      "dek.registered",
      "var.created",
      "var.version_pushed",
      "var.created",
      "var.version_pushed",
      // 一括 pull は変数ごとに 1 行(§3.3)
      "var.read",
      "var.read",
      "env.renamed",
      "var.renamed",
      "var.deleted",
      // 環境削除は残存変数の var.deleted を伴う(§12-4)
      "var.deleted",
      "env.deleted",
    ]);

    const created = events[9];
    const pushed = events[10];
    const read = events[13];
    if (created === undefined || pushed === undefined || read === undefined) {
      throw new Error("missing audit rows");
    }
    expect(created["variable_id"]).toBe(VAR);
    expect(created["environment_id"]).toBe(ENV);
    expect(JSON.parse(String(created["payload"]))).toEqual({ name: "API_KEY" });
    // var.created / var.version_pushed は署名(CRYPTO_SPEC §4.1 / §4.2)を伴う
    // 操作なので、受理時点の chain-derived 鍵 FP を写す(AUDIT_SPEC §3.3。
    // 署名・signed bytes・hash・nonce・暗号文は監査に載せない)。作成では
    // 同梱 v1 の writer FP = ステートメントの author FP(同一主体 — §12-5)
    expect(created["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(pushed["epoch"]).toBe(1);
    expect(pushed["version"]).toBe(1);
    expect(pushed["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    expect(read["actor_user_id"]).toBe(READER);
    expect(read["epoch"]).toBe(1);
    expect(read["version"]).toBe(1);
    // var.read は署名を伴わないため FP を持たない(§3.3 の意味論)
    expect(read["actor_key_fingerprint"]).toBeNull();

    expectMetaAuthorFingerprints(events);
  });

  it("挿入失敗時は採番キャッシュを破棄し、次の追記は MAX(seq) の再読込から続く", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const baseRow = sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0];
      const base = Number(baseRow?.["m"] ?? 0);
      store.appendSync(seqTestEvent("test.one"));
      // チャンク 2(7 行目以降)の途中 seq に衝突行を直接挿入して失敗を誘発する
      sql.exec(
        "INSERT INTO audit_events (seq, server_ts, event, actor_type) VALUES (?, ?, ?, ?)",
        base + 9,
        1,
        "test.direct",
        "user",
      );
      expect(() =>
        store.appendManySync(
          Array.from({ length: 12 }, (_e, index) => seqTestEvent(`test.b${index}`)),
        ),
      ).toThrow();
      // 失敗で採番キャッシュは破棄され、次の追記は現 DB の MAX(seq)+1 から続く
      // (前進したままなら base+14 で採番され、ロールバック後の DB に対して
      // 欠番を作る)。注: 実運用ではタスク失敗がチャンク 1 も含めて
      // ロールバックする — ここは採番キャッシュの挙動のみを固定する
      store.appendSync(seqTestEvent("test.after"));
      const last = sql
        .exec("SELECT seq, event FROM audit_events ORDER BY seq DESC LIMIT 1")
        .toArray()[0];
      expect(last?.["event"]).toBe("test.after");
      expect(last?.["seq"]).toBe(base + 10);
    });
    // 直接挿入した行がこのテスト後に残らないよう DO を初期状態へ戻す
    await evictDurableObject(stub);
  });

  it("chain_seq は chain.* 以外へ追記できず、一括追記も全件を採番前に拒否する", async () => {
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await runInDurableObject(stub, (_instance, state) => {
      const sql = state.storage.sql;
      const store = makeAuditStore(sql);
      const before = Number(
        sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0]?.["m"] ?? 0,
      );
      const invalid = { ...seqTestEvent("var.read"), chainSeq: 1 };

      expect(() => store.appendSync(invalid)).toThrow("chain_seq is reserved for chain.* events");
      // 後半に違反があっても、前半の正当な行を部分追記しない
      // (APPEND_CHUNK_ROWS=5 の境界をまたぎ、違反を第2チャンクに置く)
      expect(() =>
        store.appendManySync([
          ...Array.from({ length: 6 }, (_e, index) => seqTestEvent(`test.before-invalid${index}`)),
          invalid,
        ]),
      ).toThrow("chain_seq is reserved for chain.* events");

      const after = Number(
        sql.exec("SELECT COALESCE(MAX(seq), 0) AS m FROM audit_events").toArray()[0]?.["m"] ?? 0,
      );
      expect(after).toBe(before);
    });
  });

  it("チャンク分割される一括 append と DO 再起動をまたいでも seq は無欠番(§5.1)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // multi-row INSERT の 1 文あたり行数(audit-store.ts の 6 行)を越える
    // 8 変数を作り、一括 pull の var.read 8 行が複数チャンクに割れて追記される
    for (let index = 0; index < 8; index += 1) {
      await createVariableOk(dek, `var-batch-${index}`, `BATCH_${index}`);
    }
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);

    // DO 再起動相当: インスタンスメモリの next seq を破棄し、次の追記が
    // MAX(seq) の再読込から続き番号で採番することを確認する
    const stub = env.PROJECT_CHAIN.get(env.PROJECT_CHAIN.idFromName(projectId));
    await evictDurableObject(stub);
    const renamed = await renameEnvironmentRequest(fixture, ENV, "App2", MEMBER);
    expect(renamed.status).toBe(204);

    const events = await readAuditEvents(projectId);
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.filter((event) => event["event"] === "var.read").length).toBe(8);
    expect(events[events.length - 1]?.["event"]).toBe("env.renamed");
  });

  it("attributes actors: PAT ops carry the token id, session ops carry auth_method (§2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    const envCreated = events.find((event) => event["event"] === "env.created");
    if (envCreated === undefined) throw new Error("missing env.created");
    expect(envCreated["actor_user_id"]).toBe(OWNER);
    expect(envCreated["actor_api_token_id"]).toBeTypeOf("string");
    // env.created はメタステートメント(CRYPTO_SPEC §4.2)を伴う操作なので
    // author の鍵 FP を写す(AUDIT_SPEC §3.3 — 2026-08-04 PR-3)
    expect(envCreated["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    // セッション経由の操作は auth_method を payload に持つ(§2 / §5.1)
    const session = await loginSession(9002);
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: "env-audit-0002",
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const { entry, hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: MEMBER,
      operation: {
        op: "create_environment",
        payload: {
          environmentId: "env-audit-0002",
          dekCommitmentHex: await commitmentOf(projectId, "env-audit-0002", 1, dek),
        },
      },
    });
    const sessionStatement = await createEnvironmentStatement({
      authorUserId: MEMBER,
      environmentId: "env-audit-0002",
      name: "Session",
      head: fixture.head,
    });
    const sessionManifest = await signEnvManifestAs(MEMBER, projectId, {
      suite: "maruhi/v1",
      environmentId: "env-audit-0002",
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: sessionStatement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, sessionStatement, MEMBER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // 境界 checkpoint(H+2 — §12-4 の必須同梱)
    const { entry: sessionCheckpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actorUserId: MEMBER,
      operation: checkpointOperation({
        environmentId: "env-audit-0002",
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: await manifestSignedBytesHashOf(projectId, sessionManifest, MEMBER),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const created = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...sessionHeaders(session) },
      body: JSON.stringify({
        parentHeadHashHex: fixture.head.hashHex,
        entry,
        statement: sessionStatement,
        deks,
        manifest: sessionManifest,
        checkpoint: sessionCheckpoint,
      }),
    });
    expect(created.status).toBe(200);
    const after = await readAuditEvents(projectId);
    const bySession = after.find(
      (event) => event["event"] === "env.created" && event["environment_id"] === "env-audit-0002",
    );
    if (bySession === undefined) throw new Error("missing session event");
    expect(bySession["actor_user_id"]).toBe(MEMBER);
    expect(bySession["actor_api_token_id"]).toBeNull();
    expect(JSON.parse(String(bySession["payload"]))).toEqual({
      name: "Session",
      authMethod: "github_oauth",
    });
  });

  it("records dek.registered / dek.deleted per recipient with actor, epoch and target (§3.3)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    // 環境作成時のエポック 1 の同梱分: 受信者ごとに 1 行(1 行 1 target)
    const initial = await readAuditEvents(projectId);
    const epoch1 = initial.filter((event) => event["event"] === "dek.registered");
    expect(epoch1.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch1) {
      expect(event["environment_id"]).toBe(ENV);
      expect(event["epoch"]).toBe(1);
      expect(event["actor_user_id"]).toBe(OWNER);
      // 登録署名(CRYPTO_SPEC §5.1)の署名者 FP を写す(§3.3 — 突合用)
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      // PAT 経由の登録なのでトークン id を持つ(§2 のアクター帰属)
      expect(event["actor_api_token_id"]).toBeTypeOf("string");
      expect(event["variable_id"]).toBeNull();
    }

    // 複合ローテーション(§12-4)の同梱分も同じ形で記録される
    await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);

    // 削除(§12-6 の修復経路)は dek.deleted を受信者ごとに記録する
    const removed = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      {
        wraps: [{ epoch: 2, recipientUserId: READER }],
      },
    );
    expect(removed.status).toBe(204);

    // 修復再登録(登録 API に残る経路 — §12-6)も同じ形で記録される
    const removedEpoch1 = await requestJson(
      "DELETE",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, OWNER),
      { wraps: [{ epoch: 1, recipientUserId: READER }] },
    );
    expect(removedEpoch1.status).toBe(204);
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const reRegistered = await requestJson(
      "POST",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, MEMBER),
      { deks: [reWrap] },
    );
    expect(reRegistered.status).toBe(204);

    const events = await readAuditEvents(projectId);
    const epoch2 = events.filter(
      (event) => event["event"] === "dek.registered" && event["epoch"] === 2,
    );
    expect(epoch2.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch2) {
      expect(event["actor_user_id"]).toBe(MEMBER);
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    }
    const repair = events.at(-1);
    if (repair === undefined) throw new Error("missing repair registration event");
    expect(repair["event"]).toBe("dek.registered");
    expect(repair["epoch"]).toBe(1);
    expect(repair["target_user_id"]).toBe(READER);
    expect(repair["actor_user_id"]).toBe(MEMBER);
    expect(repair["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted.length).toBe(2);
    const deletion = deleted[0];
    if (deletion === undefined) throw new Error("missing dek.deleted");
    expect(deletion["environment_id"]).toBe(ENV);
    expect(deletion["epoch"]).toBe(2);
    expect(deletion["target_user_id"]).toBe(READER);
    expect(deletion["actor_user_id"]).toBe(OWNER);
    // 削除は署名を伴わないため FP を持たない(AUDIT_SPEC §3.3)
    expect(deletion["actor_key_fingerprint"]).toBeNull();
  });

  it("never records provider identifiers or emails (§1-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    // シードした GitHub の数値 ID(provider_user_id)・login・メール形式が
    // どの列・payload にも部分文字列としても現れない(タイムスタンプ列は数値の
    // 偶然一致を避けて除外)
    for (const event of events) {
      for (const [column, value] of Object.entries(event)) {
        if (column === "server_ts" || column === "client_ts" || value === null) {
          continue;
        }
        // ランダム hex(DEK コミットメント・鍵 FP 等)は "9001" 等の数字列を偶然
        // 含み得るため、長い hex 連続は走査前に除去する(provider ID の実漏洩は
        // 短い独立値として現れるので検出力は落ちない)
        const text = String(value).replace(/[0-9a-f]{16,}/g, "");
        for (const forbidden of ["9001", "9002", "9003", "9009", "user900", "@"]) {
          expect(text).not.toContain(forbidden);
        }
      }
    }
  });
});
