// データプレーン API(AUTH_SPEC §12)の統合テスト — DEK 配布・バックフィル・修復経路・登録署名(AUTH_SPEC §12-6 / CRYPTO_SPEC §5.1 / §7)。
// vitest-pool-workers(workerd 実環境)で SELF 経由の HttpApi と DO SQLite を検証する。
// 共有フィクスチャ・ヘルパは support/data-scenario.ts(旧 data.test.ts の分割)。

import type { TokenScope } from "@maruhi/core";
import {
  computeServerKeyFingerprint,
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
import { deviceToken, JSON_HEADERS, loginSession, sessionHeaders } from "./support/auth.ts";
import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  commitmentOf,
  hexBytes,
  makeDek,
  signEntryAt,
  signWrapAs,
  unwrapAndDecrypt,
  vectorKeyOf,
  verifyDistributedWrapSignature,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
  dataUrl,
  deleteEnvironmentRequest,
  MEMBER,
  OWNER,
  projectId,
  READER,
  requestJson,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
  STRANGER,
} from "./support/data-fixture.ts";
import {
  createVariableOk,
  ENV,
  fixture,
  registerDataScenario,
  token,
  VAR,
  wrapsFor,
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

  it("supports session-cookie auth with the CSRF header for data writes (§5)", async () => {
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
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const body = JSON.stringify({
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
      deks,
    });
    // CSRF ヘッダーなしの書き込みは 403
    const headers = sessionHeaders(session);
    const withoutCsrf = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, cookie: headers["cookie"] ?? "" },
      body,
    });
    expect(withoutCsrf.status).toBe(403);
    const accepted = await SELF.fetch(dataUrl("/environments"), {
      method: "POST",
      headers: { ...JSON_HEADERS, ...headers },
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
    const ownerWrite = await deviceToken(9001, writeScope);
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

describe("DEK ラップの登録署名(§12-6 / CRYPTO_SPEC §5.1)", () => {
  it("rejects wraps signed by someone other than the caller (422 signature-invalid, 登録 API 経路)", async () => {
    // 登録 API は修復再登録・バックフィル専用に縮退した(§12-6)。修復経路で
    // エポック 1 の全ラップを削除し、OWNER が署名した完全集合を MEMBER が
    // 持ち込む → 呼び出し主体 = 署名者の厳密一致に反するため拒否。
    // 何も挿入されず監査行も残らない
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: ALL_MEMBERS.map((recipientUserId) => ({ epoch: 1, recipientUserId })),
    });
    expect(removed.status).toBe(204);
    const auditsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const signedByOwner = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: signedByOwner,
    });
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1",
      ENV,
    );
    expect(rows.length).toBe(0);
    const auditsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(auditsAfter[0]?.["n"]).toBe(auditsBefore[0]?.["n"]);
  });

  it("rejects a transplanted signature on environment creation (422 signature-invalid, 同梱経路)", async () => {
    // 同じ署名者(OWNER)による正しい署名でも、別ラップ(別受信者)の署名の
    // 移植は signed_bytes が異なるため検証に失敗する
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const [first, second, third] = deks;
    if (first === undefined || second === undefined || third === undefined) {
      throw new Error("missing wraps");
    }
    const transplanted = [first, { ...second, signatureHex: first.signatureHex }, third];
    const response = await createEnvironmentWith(fixture, ENV, "App", transplanted);
    expect(response.status).toBe(422);
    expect(((await response.json()) as { reason: string }).reason).toBe("signature-invalid");
    // 環境は作られない(署名検証は書き込みフェーズより前)
    const list = await requestJson("GET", "/environments", token(READER));
    await expect(list.json()).resolves.toEqual({ environments: [] });
  });

  it("rejects wraps without a signature (400 Schema, 両経路)", async () => {
    const deks = await wrapsFor(ENV, ALL_MEMBERS);
    const stripped = deks.map(({ signatureHex: _signatureHex, ...rest }) => rest);
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "create_environment",
        payload: { environmentId: ENV, dekCommitmentHex: "ab".repeat(32) },
      },
    });
    const created = await requestJson("POST", "/environments", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
      statement: await createEnvironmentStatement({
        authorUserId: OWNER,
        environmentId: ENV,
        name: "App",
        head: fixture.head,
      }),
      deks: stripped,
    });
    expect(created.status).toBe(400);
    // 登録 API 経路も同じ Schema(WrappedDekSchema)で 400
    await createEnvironmentOk(fixture, ENV, "App");
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: stripped,
    });
    expect(registered.status).toBe(400);
  });

  it("rejects malformed signatures with 400 (Schema: 大文字 hex / 長さ不正 / 非 hex)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const [wrap] = await wrapsFor(ENV, [OWNER], 1, MEMBER);
    if (wrap === undefined) throw new Error("missing wrap");
    for (const signatureHex of [
      wrap.signatureHex.toUpperCase(),
      wrap.signatureHex.slice(2),
      `zz${wrap.signatureHex.slice(2)}`,
    ]) {
      const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
        deks: [{ ...wrap, signatureHex }],
      });
      expect(response.status).toBe(400);
    }
  });

  it("rejects third-party re-submission into a deleted slot (signer mismatch)", async () => {
    // CRYPTO_SPEC §5.1 の名指しシナリオ: 削除済みスロットへ「他人の署名済み
    // ラップ」を第三者が再投入する経路は署名者不一致で塞がる。
    // かつては「MEMBER の鍵一式を流用したソック垢(STRANGER)」の最強形
    // (鍵一致・user_id 不一致)をここで固定していたが、§6.2 のメンバー鍵一意性
    // (2026-08-03)により鍵重複メンバーはチェーン追記の時点で成立しなくなった
    // (下の chain-level テストと membership.test.ts の authz ベクターループが
    // 固定する)。鍵一致のまま signer_user_id だけが異なる署名の拒否は
    // ベクター negative `transplant-signer` が crypto 層で固定し続ける
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
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

    // STRANGER(自前の鍵で正規にメンバー化)が MEMBER 署名のラップをそのまま
    // 再投入 → 呼び出し主体 = 署名者の厳密一致(§12-6)に反するため 422
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: encodeHex(await exportEncryptionPublicKey(encPair.publicKey)),
        sigPubHex: encodeHex(await exportSigningPublicKey(sigPair.publicKey)),
        role: "member",
      },
    });
    const removedAgain = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removedAgain.status).toBe(204);
    const replayed = await requestJson("POST", `/environments/${ENV}/deks`, token(STRANGER), {
      deks: [reWrap],
    });
    expect(replayed.status).toBe(422);
    expect(((await replayed.json()) as { reason: string }).reason).toBe("signature-invalid");
    const rows = await queryProjectDo(
      projectId,
      "SELECT 1 FROM dek_wraps WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?",
      ENV,
      READER,
    );
    expect(rows.length).toBe(0);
  });

  it("rejects the key-reuse sock puppet at the chain layer (422 duplicate-member-key)", async () => {
    // かつて上のテストが利用していた「MEMBER の鍵一式を流用した STRANGER の
    // add_member」は、§6.2 のメンバー鍵一意性(合意規則)によりチェーン追記の
    // 時点で拒否される(帰属付け替えの根本原因の解消 — 防衛の多層化)。
    // ベクター固定チェーンに対する網羅は membership.test.ts の authz ループ
    // (authz-add-member-duplicate-key ほか 2 件)が担い、ここではデータプレーンの
    // fixture チェーンでも成立することを固定する
    const { entry } = await signEntryAt({
      seq: fixture.head.seq + 1,
      prevHashHex: fixture.head.hashHex,
      actorUserId: OWNER,
      operation: {
        op: "add_member",
        payload: {
          targetUserId: STRANGER,
          encPubHex: vectorKeyOf(MEMBER).enc_pub_hex,
          sigPubHex: vectorKeyOf(MEMBER).sig_pub_hex,
          role: "member",
        },
      },
    });
    const response = await requestJson("POST", "/chain/entries", token(OWNER), {
      parentHeadHashHex: fixture.head.hashHex,
      entry,
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as { seq: number; reason: string };
    expect(body.reason).toBe("duplicate-member-key");
    expect(body.seq).toBe(fixture.head.seq + 1);
  });

  it("accepts the original signer re-registering the identical wrap and signature (§5.1 の意味論の対)", async () => {
    // 署名は帰属であり鮮度証明ではない: 削除後、元署名者自身による同一内容 +
    // 同一署名の再登録は有効(タイムスタンプ・ノンスを含めない設計の positive 側)
    const dek = makeDek();
    const deks = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 1,
      dek,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: OWNER,
    });
    const created = await createEnvironmentWith(fixture, ENV, "App", deks);
    expect(created.status).toBe(200);
    const readerWrap = deks.find((wrap) => wrap.recipientUserId === READER);
    if (readerWrap === undefined) throw new Error("missing reader wrap");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    const restored = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [readerWrap],
    });
    expect(restored.status).toBe(204);
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(READER));
    const body = (await mine.json()) as { deks: { signatureHex: string }[] };
    expect(body.deks[0]?.signatureHex).toBe(readerWrap.signatureHex);
  });

  it("rejects an empty registration list with 400 (§12-6: 削除側の空列挙と同じ規律)", async () => {
    // 空の deks: [] はかつて 204 の silent no-op だった(session-08/09 の
    // 申し送り)。呼び出し形として意味のあるユースケースがなく、silent no-op は
    // クライアントバグ(空配列の送信を登録完了と誤認)を隠すため、削除側の
    // 空 wraps 400 と同じ minItems 1 の Schema 検証で拒否する(2026-08-03 統一)
    await createEnvironmentOk(fixture, ENV, "App");
    const before = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [],
    });
    expect(response.status).toBe(400);
    const after = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.registered'",
    );
    expect(after[0]?.["n"]).toBe(before[0]?.["n"]);
  });

  it("distributes the signature and signer identity, verifiable client-side (§12-2)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    for (const path of [`/environments/${ENV}/deks`, `/environments/${ENV}/pull`] as const) {
      const response = await requestJson("GET", path, token(READER));
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        deks: {
          suite: string;
          epoch: number;
          encHex: string;
          ciphertextHex: string;
          signatureHex: string;
          signerUserId: string;
          signerKeyFingerprintHex: string;
        }[];
      };
      const wrap = body.deks[0];
      if (wrap === undefined) throw new Error("missing distributed wrap");
      expect(wrap.signerUserId).toBe(OWNER);
      expect(wrap.signerKeyFingerprintHex).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
      // クライアント検証(CRYPTO_SPEC §5.1): 自分の座標 + 署名者のチェーン鍵で検証
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(true);
      // 座標を偽ると検証失敗(クライアント側の移植検出)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: "env-forged-0001",
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap,
        }),
      ).resolves.toBe(false);
      // サーバーが署名者を偽って申告しても検証失敗(signer_user_id も署名対象 —
      // CRYPTO_SPEC §5.1。ベクター transplant-signer の統合レベルの対)
      await expect(
        verifyDistributedWrapSignature({
          projectId,
          environmentId: ENV,
          recipientUserId: READER,
          recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
          wrap: { ...wrap, signerUserId: MEMBER },
        }),
      ).resolves.toBe(false);
    }
  });

  it("accepts a caller-signed poison wrap: 署名は帰属であり内容検証ではない(§5.1 の意味論)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
    // 中身が復号不能なフェイクでも、呼び出し主体(MEMBER)の署名が正しければ
    // 受理される(サーバーはラップの中身を検証できない — E2EE)。ただし帰属は
    // 署名 + dek.registered の FP でサーバー不信のまま MEMBER に固定される
    const poison = await signWrapAs(MEMBER, projectId, ENV, {
      suite: "maruhi/v1",
      epoch: 1,
      recipientUserId: READER,
      recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
      encHex: "cd".repeat(32),
      ciphertextHex: "ef".repeat(48),
    });
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(MEMBER), {
      deks: [poison],
    });
    expect(registered.status).toBe(204);
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]?.["signer_user_id"]).toBe(MEMBER);
  });

  it("attributes repair-path re-registration via the signer fingerprint (削除 → 署名付き再登録 → 突合)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    const payload = await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // admin(owner)が毒ラップ想定の READER 宛を削除 → MEMBER が自署名で再登録
    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: READER }],
    });
    expect(removed.status).toBe(204);
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

    // 保存行の署名者は MEMBER(user_id + FP)
    const rows = await queryProjectDo(
      projectId,
      `SELECT signer_user_id, signer_key_fingerprint FROM dek_wraps
       WHERE environment_id = ? AND epoch = 1 AND recipient_user_id = ?`,
      ENV,
      READER,
    );
    expect(rows[0]).toEqual({
      signer_user_id: MEMBER,
      signer_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
    });

    // dek.registered の署名者 FP で帰属を突合できる(AUDIT_SPEC §3.3):
    // 初回登録(環境作成の同梱 = OWNER 署名)→ 再登録(MEMBER 署名)の順
    const audits = await queryProjectDo(
      projectId,
      `SELECT actor_user_id, actor_key_fingerprint FROM audit_events
       WHERE event = 'dek.registered' AND target_user_id = ? ORDER BY seq`,
      READER,
    );
    expect(audits).toEqual([
      {
        actor_user_id: OWNER,
        actor_key_fingerprint: vectorKeyOf(OWNER).key_fingerprint_hex,
      },
      {
        actor_user_id: MEMBER,
        actor_key_fingerprint: vectorKeyOf(MEMBER).key_fingerprint_hex,
      },
    ]);

    // READER は再登録されたラップの署名を検証してから復号できる
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(READER));
    const body = (await pull.json()) as {
      variables: { value: WireEncryptedPayload }[];
      deks: {
        suite: string;
        epoch: number;
        encHex: string;
        ciphertextHex: string;
        signatureHex: string;
        signerUserId: string;
      }[];
    };
    const wrap = body.deks[0];
    const pulled = body.variables[0];
    if (wrap === undefined || pulled === undefined) throw new Error("missing pull data");
    expect(wrap.signerUserId).toBe(MEMBER);
    await expect(
      verifyDistributedWrapSignature({
        projectId,
        environmentId: ENV,
        recipientUserId: READER,
        recipientEncPubHex: vectorKeyOf(READER).enc_pub_hex,
        wrap,
      }),
    ).resolves.toBe(true);
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
});

// デプロイメントのサーバー enc 公開鍵(ダミー。X25519 公開鍵は任意の 32 バイトで
// 形式上有効 — サーバーはラップの中身を検証できず、受理判定は同定と署名のみ)
const SERVER_ENC_PUB_HEX = "5a".repeat(32);

async function serverFingerprintHex(encPubHex = SERVER_ENC_PUB_HEX): Promise<string> {
  const fp = await computeServerKeyFingerprint(hexBytes(encPubHex));
  if (!fp.ok) throw new Error("server fingerprint failed");
  return encodeHex(fp.value);
}

describe("受信者クラス server(AUTH_SPEC §12-6 / CRYPTO_SPEC §9 — 2026-08-12)", () => {
  /** owner が grant_server を追記する(汎用チェーン API — AUTH_SPEC §6 の admin op)。 */
  async function grantServer(scope: readonly string[]): Promise<string> {
    const fpHex = await serverFingerprintHex();
    await appendOperation(fixture, OWNER, {
      op: "grant_server",
      payload: {
        serverEncPubHex: SERVER_ENC_PUB_HEX,
        serverKeyFingerprintHex: fpHex,
        scopeEnvironmentIds: scope,
        leasePolicy: [],
      },
    });
    return fpHex;
  }

  async function serverWrap(input: {
    readonly epoch: number;
    readonly dek: Uint8Array;
    readonly fpHex: string;
    readonly encPubHex?: string;
    readonly signerUserId?: string;
    readonly environmentId?: string;
  }) {
    return wrapDekToServer({
      projectId,
      environmentId: input.environmentId ?? ENV,
      epoch: input.epoch,
      dek: input.dek,
      serverKeyFingerprintHex: input.fpHex,
      serverEncPubHex: input.encPubHex ?? SERVER_ENC_PUB_HEX,
      signerUserId: input.signerUserId ?? OWNER,
    });
  }

  it("backfills server wraps for all existing epochs right after the grant (§12-6 の grant 直後バックフィル)", async () => {
    // grant 前に epoch 1 / 2 を確立(完全集合はメンバーのみ)→ grant → owner が
    // スコープ内全エポックのサーバー宛ラップを追記経路で一括登録する
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const dek2 = await rotateEnvironmentOk(fixture, MEMBER, ENV, 2);
    const fpHex = await grantServer([ENV]);
    const wraps = [
      await serverWrap({ epoch: 1, dek: dek1, fpHex }),
      await serverWrap({ epoch: 2, dek: dek2, fpHex }),
    ];
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: wraps,
    });
    expect(response.status).toBe(204);

    // 保存行は recipient_class = 'server'、識別子列にはサーバー鍵 FP
    const rows = await queryProjectDo(
      projectId,
      "SELECT epoch, recipient_user_id FROM dek_wraps WHERE environment_id = ? AND recipient_class = 'server' ORDER BY epoch",
      ENV,
    );
    expect(rows.map((row) => [row["epoch"], row["recipient_user_id"]])).toEqual([
      [1, fpHex],
      [2, fpHex],
    ]);

    // dek.registered は受信者ごとに 1 行、server 行は target_key_fingerprint に FP
    // (user_id 列に鍵識別子を混ぜない — AUDIT_SPEC §3.3 / §2)
    const events = await queryProjectDo(
      projectId,
      "SELECT epoch, target_user_id, target_key_fingerprint, actor_key_fingerprint FROM audit_events WHERE event = 'dek.registered' AND target_key_fingerprint IS NOT NULL ORDER BY epoch",
    );
    expect(events.length).toBe(2);
    expect(events[0]?.["target_user_id"]).toBeNull();
    expect(events[0]?.["target_key_fingerprint"]).toBe(fpHex);
    expect(events[0]?.["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);

    // 配布(listMine)に server 行は混ざらない(配布は本人宛のみ — §12-6)
    const mine = await requestJson("GET", `/environments/${ENV}/deks`, token(OWNER));
    const body = (await mine.json()) as { deks: readonly { epoch: number }[] };
    expect(body.deks.length).toBe(2);
  });

  it("rejects a duplicate server wrap with 409 (上書き禁止はクラス共通)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const first = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(first.status).toBe(204);
    const second = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(second.status).toBe(409);
    const body = (await second.json()) as Record<string, unknown>;
    expect(body["_tag"]).toBe("DekWrapExists");
  });

  it("rejects a server wrap for an out-of-scope environment with 422 (scope-out-of-range)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    // grant 後に作る環境はスコープ外なので複合の完全集合はメンバーのみ(§12-4)
    const outDek = await createEnvironmentOk(fixture, "env-out-0002", "Out");
    const wrap = await serverWrap({
      environmentId: "env-out-0002",
      epoch: 1,
      dek: outDek,
      fpHex,
    });
    const response = await requestJson("POST", `/environments/env-out-0002/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("scope-out-of-range");
  });

  it("rejects a server wrap without a matching grant with 422 (recipient-not-granted)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await serverFingerprintHex(); // grant は追記しない
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-not-granted");
  });

  it("rejects a server wrap whose enc pub differs from the grant with 422 (recipient-key-mismatch)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    // FP は grant と一致・enc 公開鍵だけ別(FP + enc pub の両方一致の要求 — §12-6)
    const wrap = await serverWrap({
      epoch: 1,
      dek: dek1,
      fpHex,
      encPubHex: "6b".repeat(32),
    });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-key-mismatch");
  });

  it("requires the server key in the composite complete set once granted (§12-4)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const dek2 = makeDek();
    const memberWraps = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    // サーバー鍵宛を欠いた完全集合は 422 recipient-missing
    const missing = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: memberWraps,
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(missing.status).toBe(422);
    const body = (await missing.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-missing");

    // サーバー鍵宛を含めた完全集合は受理される(ローテーション実行者が署名 — §7)
    const full = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: [
        ...memberWraps,
        await serverWrap({ epoch: 2, dek: dek2, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(full.status).toBe(200);
  });

  it("rejects a cross-class recipient collision with 422 duplicate-recipient, not a defect (セキュリティレビュー A-1)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);

    // add_member の対象 user_id は意図的に存在検証されない自由文字列(AUTH_SPEC
    // §11-1)なので、admin は「user_id = 有効 grant のサーバー鍵 FP」という
    // メンバーをチェーンに追加できる(鍵は別物なのでメンバー鍵一意性にも
    // 触れない)。以降この環境の完全集合は member としての fpHex 宛と server と
    // しての fpHex 宛の両方を要求するが、保存行の主キーは (environment, epoch,
    // recipient_user_id) なので両方は書けない
    const encPair = await generateEncryptionKeyPair();
    const sigPair = await generateSigningKeyPair();
    const sockEncPubHex = encodeHex(await exportEncryptionPublicKey(encPair.publicKey));
    const sockSigPubHex = encodeHex(await exportSigningPublicKey(sigPair.publicKey));
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: fpHex,
        encPubHex: sockEncPubHex,
        sigPubHex: sockSigPubHex,
        role: "member",
      },
    });

    const dek2 = makeDek();
    const memberWraps = await wrapDekForAll({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserIds: ALL_MEMBERS,
      signerUserId: MEMBER,
    });
    const sockWrap = await wrapDekTo({
      projectId,
      environmentId: ENV,
      epoch: 2,
      dek: dek2,
      recipientUserId: fpHex,
      recipientEncPubHex: sockEncPubHex,
      signerUserId: MEMBER,
    });
    // 受理前の検査で 422(duplicate-recipient)に倒れること。修正前は受理段を
    // 通過して書き込みフェーズの主キー違反 = defect(500)になっていた
    const response = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: [
        ...memberWraps,
        sockWrap,
        await serverWrap({ epoch: 2, dek: dek2, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("duplicate-recipient");

    // 受理段で倒れるため書き込みフェーズには入らない(epoch 2 の行は 1 行も
    // 作られない)。なお衝突が存在する限り完全集合は本質的に充足不能なので、
    // ローテーション自体は塞がったまま — これは下の運用復旧で解く
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = 2",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(0);

    // 運用復旧(レビュー A-1 の「影響と緩和要素」): 衝突メンバーを
    // remove_member すれば完全集合が再び充足可能になり、ローテーションが通る
    await appendOperation(fixture, OWNER, {
      op: "remove_member",
      payload: { targetUserId: fpHex },
    });
    const recovered = await rotateEnvironmentComposite(fixture, {
      environmentId: ENV,
      newEpoch: 2,
      deks: [
        ...memberWraps,
        await serverWrap({ epoch: 2, dek: dek2, fpHex, signerUserId: MEMBER }),
      ],
      dekCommitmentHex: await commitmentOf(projectId, ENV, 2, dek2),
      actorUserId: MEMBER,
    });
    expect(recovered.status).toBe(200);
  });

  it("repairs a server wrap through delete → re-register (§12-6 の修復経路)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    expect(
      (
        await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
          deks: [wrap],
        })
      ).status,
    ).toBe(204);

    const removed = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientClass: "server", recipientUserId: fpHex }],
    });
    expect(removed.status).toBe(204);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT target_user_id, target_key_fingerprint FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted.length).toBe(1);
    expect(deleted[0]?.["target_user_id"]).toBeNull();
    expect(deleted[0]?.["target_key_fingerprint"]).toBe(fpHex);

    // 追記経路での再登録(エポックにメンバー宛が残っているため初回完全一致ではない)
    const reRegistered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(reRegistered.status).toBe(204);
  });

  it("rejects a server wrap for a revoked grant with 422 (失効済み grant は not-granted)", async () => {
    const dek1 = await createEnvironmentOk(fixture, ENV, "App");
    const fpHex = await grantServer([ENV]);
    await appendOperation(fixture, OWNER, {
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: fpHex },
    });
    const wrap = await serverWrap({ epoch: 1, dek: dek1, fpHex });
    const response = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [wrap],
    });
    expect(response.status).toBe(422);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body["reason"]).toBe("recipient-not-granted");
  });

  it("rejects a wrap deletion whose recipientClass does not match the stored row (監査列の操縦を塞ぐ)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // member のラップを server クラスで指す削除: 保存行の class と不一致 = 404。
    // 素通しにすると member の ULID が target_key_fingerprint 列へ載り、
    // (target_user_id, seq) 索引からこの削除が消える(AUDIT_SPEC §1-2)
    const crossClass = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientClass: "server", recipientUserId: OWNER }],
    });
    expect(crossClass.status).toBe(404);
    expect(((await crossClass.json()) as Record<string, unknown>)["_tag"]).toBe("DekWrapNotFound");

    // 逆方向: server のラップを member クラス(省略時既定)で指す削除も 404
    const fpHex = await grantServer([ENV]);
    const registered = await requestJson("POST", `/environments/${ENV}/deks`, token(OWNER), {
      deks: [await serverWrap({ epoch: 1, dek: makeDek(), fpHex })],
    });
    expect(registered.status).toBe(204);
    const reverse = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [{ epoch: 1, recipientUserId: fpHex }],
    });
    expect(reverse.status).toBe(404);

    // どちらの試行も削除・監査行を残していない(検証フェーズで全体が拒否される)
    const deleted = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted[0]?.["n"]).toBe(0);
    const rows = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE environment_id = ? AND epoch = 1",
      ENV,
    );
    expect(rows[0]?.["n"]).toBe(ALL_MEMBERS.length + 1);
  });

  it("rejects class-only-differing refs in one deletion request (1 行に監査 2 行を積ませない)", async () => {
    await createEnvironmentOk(fixture, ENV, "App");
    // 同一 (epoch, recipient) を member / server の両クラスで指す: 重複検出は
    // クラス込みキーで通過するが、server 側が保存行と不一致 = 404 で全体拒否
    const response = await requestJson("DELETE", `/environments/${ENV}/deks`, token(OWNER), {
      wraps: [
        { epoch: 1, recipientUserId: OWNER },
        { epoch: 1, recipientClass: "server", recipientUserId: OWNER },
      ],
    });
    expect(response.status).toBe(404);
    const deleted = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM audit_events WHERE event = 'dek.deleted'",
    );
    expect(deleted[0]?.["n"]).toBe(0);
  });
});
