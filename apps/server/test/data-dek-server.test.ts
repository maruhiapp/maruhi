// データプレーン API(AUTH_SPEC §12)の統合テスト — 受信者クラス server
// (AUTH_SPEC §12-6 / CRYPTO_SPEC §9)と expectedWrapRecipientCount(deepsec
// B10)。スイート全体の分担は data-dek.test.ts 冒頭を参照。

import type { ChainState } from "@maruhi/crypto";
import {
  computeServerKeyFingerprint,
  encodeHex,
  exportEncryptionPublicKey,
  exportSigningPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
} from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { expectedWrapRecipientCount } from "../src/dek-wraps.ts";
import {
  commitmentOf,
  hexBytes,
  makeDek,
  vectorKeyOf,
  wrapDekForAll,
  wrapDekTo,
  wrapDekToServer,
} from "./support/data-crypto.ts";
import {
  ALL_MEMBERS,
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  rotateEnvironmentComposite,
  rotateEnvironmentOk,
} from "./support/data-fixture.ts";
import { ENV, fixture, registerDataScenario, token } from "./support/data-scenario.ts";
import { queryProjectDo } from "./support/project-do.ts";

registerDataScenario();

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

const memberOf = (userId: string) =>
  [
    userId,
    {
      userId,
      role: "member",
      encPubHex: "11".repeat(32),
      sigPubHex: "22".repeat(32),
      keyFingerprintHex: "33".repeat(16),
    },
  ] as const;
const grantOf = (fingerprintHex: string, scope: readonly string[]) =>
  [
    fingerprintHex,
    {
      serverKeyFingerprintHex: fingerprintHex,
      serverEncPubHex: "44".repeat(32),
      grantSeq: 1,
      scopeEnvironmentIds: scope,
      leasePolicy: [],
    },
  ] as const;

describe("expectedWrapRecipientCount(deepsec B10)", () => {
  it("member user_id と in-scope サーバー鍵 FP の重複除去済み和集合で数える", () => {
    // add_member の対象 user_id は存在検証されない自由文字列(AUTH_SPEC §11-1)
    // なので、サーバー鍵 FP と同じ文字列の member が作れる。保存キーはクラスを
    // 含まないため、この 2 受信者は 1 スロット — 期待数もクラス別の単純和でなく
    // 和集合で数えないと、環境作成・ローテーションの完全集合検査が恒久に失敗する
    const collidingFp = "ab".repeat(16);
    const otherFp = "cd".repeat(16);
    const state: ChainState = {
      members: new Map([memberOf("user-1"), memberOf(collidingFp)]),
      serverGrants: new Map([
        grantOf(collidingFp, ["env-a"]),
        grantOf(otherFp, ["env-a", "env-b"]),
      ]),
      environments: new Map(),
      checkpoints: new Map(),
      headSeq: 1,
      headHashHex: "00".repeat(32),
    };
    // env-a: {user-1, collidingFp, otherFp} — collidingFp は member と grant の
    // 双方に現れるが 1 と数える(単純和なら 4 で、受理不能な期待数になる)
    expect(expectedWrapRecipientCount(state, "env-a")).toBe(3);
    // env-b: in-scope な grant は otherFp のみ
    expect(expectedWrapRecipientCount(state, "env-b")).toBe(3);
    // スコープ外の環境は member のみ
    expect(expectedWrapRecipientCount(state, "env-c")).toBe(2);
  });
});
