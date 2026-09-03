// データプレーン API(AUTH_SPEC §12)の統合テスト — DEK 配布・新メンバーの
// バックフィル・修復経路(AUTH_SPEC §12-6 / CRYPTO_SPEC §7)。
// @cloudflare/vitest-plugin(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。
//
// スイートの分担(分割の動機は support/membership-scenario.ts 冒頭を参照):
// - 本ファイル: DEK 配布と新メンバーのバックフィル・修復経路
// - data-dek-signature.test.ts: DEK ラップの登録署名(§12-6 / CRYPTO_SPEC §5.1)
// - data-dek-server.test.ts: 受信者クラス server(§12-6 / CRYPTO_SPEC §9)と
//   expectedWrapRecipientCount(deepsec B10)

import type { TokenScope } from "@maruhi/core";
import {
  decryptVariable,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  unwrapDek,
} from "@maruhi/crypto";
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { MAX_DEK_WRAPS_PER_REQUEST } from "../src/policy.ts";
import { bearer, cliToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  checkpointOperation,
  digestOf,
  hexBytes,
  makeDek,
  manifestSignedBytesHashOf,
  metaSignedBytesHashOf,
  signEntryAt,
  signEnvManifestAs,
  unwrapAndDecrypt,
  valuesDigestOf,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

describe("DEK 配布と新メンバーのバックフィル(§12-6 / CRYPTO_SPEC §7)", () => {
  it("distributes only the caller's wraps", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const response = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { deks: { epoch: number }[] };
    expect(body.deks.length).toBe(1);
    expect(body.deks[0]?.epoch).toBe(1);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    // 全体では 3 人分あるが、応答には呼び出し主体宛のみ
    expect(rows[0]?.["n"]).toBe(3);
  });

  it("backfills historical epoch DEKs for a newly added member, who can then decrypt", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // 新メンバー(テスト時生成の実鍵)を add_member でチェーンに追加
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const encPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: { targetUserId: STRANGER, encPubHex, sigPubHex, role: "member" },
    });

    // 招待者(owner)が既存エポックの DEK を新メンバー宛にラップして登録(§7)
    const backfill = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: STRANGER,
      recipientEncPubHex: encPubHex,
      signerUserId: OWNER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [backfill],
    });
    expect(registered.status).toBe(204);

    // 新メンバーは pull → 自分の鍵で復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(STRANGER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    const unwrapped = await unwrapDek({
      recipientKeyPair: encPair,
      wrapped: { enc: hexBytes(wrap.encHex), ciphertext: hexBytes(wrap.ciphertextHex) },
      context: { projectId, environmentId: ENV, epoch: 1, recipientUserId: STRANGER },
    });
    if (!unwrapped.ok) throw new Error("unwrap failed");
    const decrypted = await decryptVariable({
      dek: unwrapped.value,
      context: pulled.value.aad,
      nonce: hexBytes(pulled.value.nonceHex),
      ciphertext: hexBytes(pulled.value.ciphertextHex),
    });
    if (!decrypted.ok) throw new Error("decrypt failed");
    expect(new TextDecoder().decode(decrypted.value)).toBe("postgres://alpha");
  });

  it("rejects session-principal data writes uniformly (§5 能力制限 — W2b)", async () => {
    const session = await loginSession(9001);
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const { entry, hash } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const statement = await createEnvironmentStatement({
      authorUserId: OWNER,
      environmentId: ENV,
      name: "App",
      head: fixture.head,
    });
    // 作成複合の同梱マニフェスト(manifestVersion 1・変数空集合・epoch 1 — §12-4)
    const manifest = await signEnvManifestAs(OWNER, projectId, {
      suite: "maruhi/v1",
      environmentId: ENV,
      epoch: 1,
      manifestVersion: 1,
      variablesDigestHex: await digestOf([]),
      envMetaVersion: statement.metaVersion,
      envMetaSigHashHex: await metaSignedBytesHashOf(projectId, statement, OWNER),
      prevManifestSigHashHex: "",
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    });
    // 境界 checkpoint(H+2 — §12-4 の必須同梱)
    const { entry: checkpoint } = await signEntryAt({
      seq: entry.seq + 1,
      prevHashHex: hash,
      actorUserId: OWNER,
      operation: checkpointOperation({
        environmentId: ENV,
        epoch: 1,
        manifestVersion: 1,
        manifestSigHashHex: await manifestSignedBytesHashOf(projectId, manifest, OWNER),
        valuesDigestHex: await valuesDigestOf([]),
      }),
    });
    const body = JSON.stringify({
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement,
      deks,
      manifest,
      checkpoint,
    });
    // 環境作成(§12-4)は §5 の明示拒否面(環境・変数の全 mutation): CSRF
    // ヘッダーの有無によらず一様に 403 session-not-allowed(能力判定が先行)
    const headers = sessionHeaders(session);
    const withoutCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, cookie: headers["cookie"] ?? "" },
      body,
    });
    expect(withoutCsrf.status).toBe(403);
    expect(((await withoutCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...headers },
      body,
    });
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    // 同一 body はトークン主体では受理される(拒否がセッション主体起因の証明)
    const accepted = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...bearer(token(OWNER)) },
      body,
    });
    expect(accepted.status).toBe(200);
  });
});

describe("DEK ラップの修復経路(§12-6: 削除 → 不足分再登録)", () => {
  it("deletes a poisoned wrap as admin and restores it through the append path", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");

    // owner(admin スコープ × チェーン role owner ≥ admin)が READER 宛を削除
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      "SELECT recipient_user_id FROM dek_wraps WHERE environment_id = ? ORDER BY recipient_user_id",
      ENV,
    );
    expect(rows.map((row) => row["recipient_user_id"])).toEqual([MEMBER, OWNER].toSorted());
    const emptied = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    await expect(emptied.json()).resolves.toEqual({ deks: [] });

    // 不足分の追記経路(§12-6)で正しいラップを再登録 → READER は再び復号できる
    const reWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserId: READER,
      signerUserId: MEMBER,
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [reWrap],
    });
    expect(registered.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    expect(pull.status).toBe(200);
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(pulled.value.ciphertextHex).toBe(payload.ciphertextHex);
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("requires admin token scope and chain role admin (§12-3: 環境削除と同水準)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // member のデフォルト PAT はスコープ admin だがチェーン role が member → 403
    const asMember = await requestJson("DELETE", `/environments/${ENV}/deks`, token(MEMBER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(asMember.status).toBe(403);
    expect(((await asMember.json()) as { reason: string }).reason).toBe("insufficient-role");
    // owner でもトークンスコープが write では 403(insufficient-permission)
    const writeScope: readonly TokenScope[] = [{ project: "*", permission: "write" }];
    const ownerWrite = await cliToken(9001, writeScope);
    const scoped = await requestJson("DELETE", `/environments/${ENV}/deks`, ownerWrite, {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(scoped.status).toBe(403);
    expect(((await scoped.json()) as { reason: string }).reason).toBe("insufficient-permission");
    // 非メンバーにはプロジェクト自体を秘匿(404 — §11-2)
    const concealed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(STRANGER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(concealed.status).toBe(404);
    expect(((await concealed.json()) as { projectId: string }).projectId).toBe(projectId);
  });

  it("rejects missing tuples with 404 atomically and duplicate refs with 422", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 1 件目は存在・2 件目が不存在 → 404(DekWrapNotFound)で、何も消えない
    const partial = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: "user-nobody-0404" },
      ],
    });
    expect(partial.status).toBe(404);
    await expect(partial.json()).resolves.toMatchObject({
      epoch: 1,
      recipientUserId: "user-nobody-0404",
    });
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ?",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(3);
    // 拒否された削除は監査行(dek.deleted)を一切残さない(検証と書き込みの分離)
    const audits = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(audits[0]?.["n"]).toBe(0);
    // 同一タプルの重複列挙は 422(duplicate-recipient)
    const duplicated = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: READER },
        { epoch: 1, recipientUserId: READER },
      ],
    });
    expect(duplicated.status).toBe(422);
    expect(((await duplicated.json()) as { reason: string }).reason).toBe("duplicate-recipient");
  });

  it("treats re-registration after a full epoch deletion as an initial registration (§12-6)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // エポック 1 の全ラップを削除 → 再登録は初回登録として完全一致を要求される
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const partial = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [
        await wrapDekTo({
          projectId,
          environmentId: ENV,
          epoch: 1,
          dek,
          recipientUserId: OWNER,
          signerUserId: MEMBER,
        }),
      ],
    });
    expect(partial.status).toBe(422);
    expect(((await partial.json()) as { reason: string }).reason).toBe("recipient-missing");
    // 完全集合なら受理され、受信者は再び復号できる
    const complete = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: await wrapDekForAll({
        projectId,
        environmentId: ENV,
        epoch: 1,
        dek,
        recipientUserIds: ALL_MEMBERS,
        signerUserId: MEMBER,
      }),
    });
    expect(complete.status).toBe(204);
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: { epoch: number; encHex: string; ciphertextHex: string }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    await expect(
      unwrapAndDecrypt({
        recipientUserId: READER,
        wrapped: wrap,
        projectId,
        environmentId: ENV,
        payload: pulled.value,
      }),
    ).resolves.toBe("postgres://alpha");
  });

  it("rejects deletion requests for missing environments, empty lists and oversized lists", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 空列挙は 400(Schema。監査痕跡ゼロの破壊系呼び出し形を許さない — §12-6)
    const empty = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [],
    });
    expect(empty.status).toBe(400);
    // 件数上限は登録側と同じ MAX_DEK_WRAPS_PER_REQUEST(存在検証より先に判定)
    const oversized = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: Array.from({ length: MAX_DEK_WRAPS_PER_REQUEST + 1 }, (_v, index) => ({
        epoch: 1,
        recipientUserId: `u${index}`,
      })),
    });
    expect(oversized.status).toBe(422);
    await expect(oversized.json()).resolves.toMatchObject({
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    });
    // tombstone 環境(ラップは物理削除済み)への削除は 404 EnvironmentNotFound
    const removedEnv = await deleteEnvironmentRequest(fixture, ENV, OWNER);
    expect(removedEnv.status).toBe(204);
    const gone = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(gone.status).toBe(404);
    // DekWrapNotFound({epoch, recipientUserId})ではなく EnvironmentNotFound({environmentId})
    const goneBody = (await gone.json()) as { environmentId?: string; epoch?: number };
    expect(goneBody.environmentId).toBe(ENV);
    expect(goneBody.epoch).toBeUndefined();
  });
});
