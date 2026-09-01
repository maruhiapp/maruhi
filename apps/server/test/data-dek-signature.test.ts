// データプレーン API(AUTH_SPEC §12)の統合テスト — DEK ラップの登録署名
// (AUTH_SPEC §12-6 / CRYPTO_SPEC §5.1)。スイート全体の分担は
// data-dek.test.ts 冒頭を参照。

import {
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import type { WireEncryptedPayload } from "./support/data-crypto.ts";
import {
  commitmentOf,
  makeDek,
  signEntryAt,
  signWrapAs,
  unwrapAndDecrypt,
  vectorKeyOf,
  verifyDistributedWrapSignature,
  wrapDekForAll,
  wrapDekTo,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  createEnvironmentStatement,
  createEnvironmentWith,
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
  wrapsFor,
} from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

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
    await expect(list.json()).resolves.toEqual({ environments: [], schemaPolicy: "disabled" });
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
    // 正例はラップした DEK 自身のコミットメントを渡す(session-31 M1-T1)
    const created = await createEnvironmentWith(
      fixture,
      ENV,
      "App",
      deks,
      await commitmentOf(projectId, ENV, 1, dek),
    );
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
