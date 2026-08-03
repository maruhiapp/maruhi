// 監査ログ(AUDIT_SPEC §3.3 データ系 / §3.4 チェーンミラー / §5.1 スキーマ)の統合テスト。
//
// - seq は単調・無欠番(§5.1 / §6)
// - チェーンミラーは actor(user_id + 鍵 FP)・chain_seq・クライアント / サーバー
//   両時刻を持つ(§3.4)
// - アイデンティティ規則(§1-2): プロバイダ情報・メールが 1 行にも現れないこと

import { computeServerKeyFingerprint, encodeHex } from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  encryptValue,
  hexBytes,
  makeDek,
  vectorKeyOf,
  wrapDekForAll,
} from "./support/data-crypto.ts";
import type { DataFixture } from "./support/data-fixture.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  dataUrl,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  setupDataProject,
  tokenOf,
} from "./support/data-fixture.ts";
import { readAuditEvents } from "./support/project-do.ts";

const ENV = "env-audit-0001";
const VAR = "var-api-key";

let fixture: DataFixture;

beforeEach(async () => {
  fixture = await setupDataProject();
});

const token = (userId: string): string => tokenOf(fixture.tokens, userId);

async function createVariableOk(dek: Uint8Array, variableId: string, name: string): Promise<void> {
  const value = await encryptValue(
    dek,
    { projectId, environmentId: ENV, epoch: 1, variableId, version: 1 },
    `secret-${variableId}`,
  );
  const response = await requestJson("POST", `/environments/${ENV}/variables`, token(MEMBER), {
    variableId,
    name,
    value,
  });
  expect(response.status).toBe(200);
}

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

  it("mirrors rotate_epoch with environment id, new epoch and reason", async () => {
    await appendOperation(fixture, MEMBER, {
      op: "rotate_epoch",
      payload: { environmentId: ENV, newEpoch: 2, reason: "scheduled" },
    });
    const events = await readAuditEvents(projectId);
    const rotated = events.at(-1);
    if (rotated === undefined) throw new Error("missing rotation mirror");
    expect(rotated["event"]).toBe("chain.epoch_rotated");
    expect(rotated["environment_id"]).toBe(ENV);
    expect(rotated["epoch"]).toBe(2);
    expect(rotated["chain_seq"]).toBe(4);
    expect(JSON.parse(String(rotated["payload"]))).toEqual({ reason: "scheduled" });
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

    const envRenamed = await requestJson("PATCH", `/environments/${ENV}`, token(MEMBER), {
      name: "App2",
    });
    expect(envRenamed.status).toBe(204);
    const renamed = await requestJson(
      "PATCH",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
      { name: "API_KEY_V2" },
    );
    expect(renamed.status).toBe(204);
    const removedVar = await requestJson(
      "DELETE",
      `/environments/${ENV}/variables/${VAR}`,
      token(MEMBER),
    );
    expect(removedVar.status).toBe(204);
    const removedEnv = await requestJson("DELETE", `/environments/${ENV}`, token(OWNER));
    expect(removedEnv.status).toBe(204);

    const events = await readAuditEvents(projectId);
    // seq は 1 始まりの無欠番(欠番 = 削除の痕跡 — §6)
    expect(events.map((event) => event["seq"])).toEqual(events.map((_e, index) => index + 1));
    expect(events.map((event) => event["event"])).toEqual([
      "chain.genesis",
      "chain.member_added",
      "chain.member_added",
      "env.created",
      // 環境作成時のエポック 1 の同梱ラップも dek.registered(1 受信者 1 行 — §3.3)
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

    const created = events[7];
    const pushed = events[8];
    const read = events[11];
    if (created === undefined || pushed === undefined || read === undefined) {
      throw new Error("missing audit rows");
    }
    expect(created["variable_id"]).toBe(VAR);
    expect(created["environment_id"]).toBe(ENV);
    expect(JSON.parse(String(created["payload"]))).toEqual({ name: "API_KEY" });
    expect(pushed["epoch"]).toBe(1);
    expect(pushed["version"]).toBe(1);
    expect(read["actor_user_id"]).toBe(READER);
    expect(read["epoch"]).toBe(1);
    expect(read["version"]).toBe(1);
  });

  it("attributes actors: PAT ops carry the token id, session ops carry auth_method (§2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const events = await readAuditEvents(projectId);
    const envCreated = events.find((event) => event["event"] === "env.created");
    if (envCreated === undefined) throw new Error("missing env.created");
    expect(envCreated["actor_user_id"]).toBe(OWNER);
    expect(envCreated["actor_api_token_id"]).toBeTypeOf("string");
    // 署名を伴わないデータ操作は鍵 FP を持たない(FP を持つのはチェーンミラーと、
    // 登録署名を写す dek.registered のみ — AUDIT_SPEC §3.3)
    expect(envCreated["actor_key_fingerprint"]).toBeNull();

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
    const created = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...sessionHeaders(session) },
      body: JSON.stringify({ environmentId: "env-audit-0002", name: "Session", deks }),
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

    // 登録 API 経由(ローテーション後の完全集合)も同じ形で記録される
    await appendOperation(fixture, MEMBER, {
      op: "rotate_epoch",
      payload: { environmentId: ENV, newEpoch: 2, reason: "audit-test" },
    });
    const complete = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const registered = await requestJson(
      "POST",
      `/environments/${ENV}/deks`,
      tokenOf(fixture.tokens, MEMBER),
      {
        deks: complete,
      },
    );
    expect(registered.status).toBe(204);

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

    const events = await readAuditEvents(projectId);
    const epoch2 = events.filter(
      (event) => event["event"] === "dek.registered" && event["epoch"] === 2,
    );
    expect(epoch2.map((event) => event["target_user_id"])).toEqual([...ALL_MEMBERS]);
    for (const event of epoch2) {
      expect(event["actor_user_id"]).toBe(MEMBER);
      expect(event["actor_key_fingerprint"]).toBe(vectorKeyOf(MEMBER).key_fingerprint_hex);
    }
    const deleted = events.filter((event) => event["event"] === "dek.deleted");
    expect(deleted.length).toBe(1);
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
        const text = String(value);
        for (const forbidden of ["9001", "9002", "9003", "9009", "user900", "@"]) {
          expect(text).not.toContain(forbidden);
        }
      }
    }
  });
});
