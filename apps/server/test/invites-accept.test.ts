// 招待 API(AUTH_SPEC §15 — IV 改訂)の統合テスト。認可・存在秘匿・受諾の判定順
// (404 → 410 → 422 link → 422 accept → CAS)、共同署名(CRYPTO_SPEC §6.5 v2)の
// 実データ検証、invite.* 監査(AUDIT_SPEC §3.2)の同一 batch 書き込みと CAS 敗北時の
// ガードを固定する。

import {
  deriveInviteLinkKeyPair,
  generateInviteLinkSeed,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { env, SELF } from "cloudflare:test";
import { Context, Effect } from "effect";
import { describe, expect, it } from "vitest";

import { InviteRepo, makeDbServices } from "../src/db.package/index.ts";
import { BASE, bearer, cliToken, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  appendOperation,
  MEMBER,
  OWNER,
  projectId,
  STRANGER,
  tokenOf,
} from "./support/data-fixture.ts";
import type { AuditRow } from "./support/invites-scenario.ts";
import {
  acceptAs,
  acceptRequest,
  errorTag,
  firstAudit,
  fixture,
  inviteAuditRows,
  inviteRow,
  issueInvite,
  makeInviteeKeys,
  mustRow,
  payloadOf,
  registerInviteScenario,
  signAcceptance,
  signingKeyPairOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("invite accept", () => {
  it("accepts with both signatures and records invite.accepted in the same batch", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const response = await acceptAs(fixture, STRANGER, keys, issued);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { id: string; projectId: string; role: string };
    expect(body).toEqual({ id: issued.id, projectId, role: "member" });

    const row = mustRow(await inviteRow(issued.id));
    expect(row.status).toBe("accepted");
    expect(row.invitee_user_id).toBe(STRANGER);
    expect(row.invitee_enc_pub).toBe(keys.encPubHex);
    expect(row.invitee_sig_pub).toBe(keys.sigPubHex);
    expect(row.accept_signature).not.toBeNull();
    expect(row.link_signature).not.toBeNull();

    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
    const audit = firstAudit(accepted, "invite.accepted");
    expect(audit.actor_user_id).toBe(STRANGER);
    expect(audit.target_user_id).toBe(STRANGER);
    expect(audit.project_id).toBe(projectId);
    // payload は不変(AUDIT_SPEC §3.2 — IV 改訂): 招待 id + 受諾鍵 FP のみ。
    // リンク公開鍵・署名・裏付け元の login は書かない
    expect(payloadOf(audit)).toEqual({
      inviteId: issued.id,
      inviteeKeyFingerprintHex: keys.fingerprintHex,
    });
  });

  it("is single-use: the losing accept gets 410 accepted and no extra audit row", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // 正規受諾者の再試行も、別人の後着も同じ 410 accepted(うるさい競合の顕在化)
    const retry = await acceptAs(fixture, STRANGER, keys, issued);
    expect(retry.status).toBe(410);
    expect((await retry.json()) as object).toMatchObject({ reason: "accepted" });
    const memberKeys = await makeInviteeKeys();
    const late = await acceptAs(fixture, MEMBER, memberKeys, issued);
    expect(late.status).toBe(410);
    // CAS 敗北で監査行は増えない(changes() ガード)
    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
  });

  it("a lost CAS writes no audit row (changes() guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // 「pending を読んでから CAS までの間に他者の受諾が確定した」並行敗者は、
    // HTTP 経路では事前読みの 410 が先に立つため、リポジトリ直呼びで決定的に
    // 再現する(同一 batch 内の changes() ガードそのものの検証)
    const invites = Context.get(makeDbServices(env.DB), InviteRepo);
    const lateKeys = await makeInviteeKeys();
    const won = await Effect.runPromise(
      invites.acceptCas(
        {
          inviteId: issued.id,
          inviteeUserId: MEMBER,
          inviteeEncPubHex: lateKeys.encPubHex,
          inviteeSigPubHex: lateKeys.sigPubHex,
          acceptSignatureHex: "ab".repeat(64),
          linkSignatureHex: "cd".repeat(64),
          inviteeKeyFingerprintHex: lateKeys.fingerprintHex,
        },
        Date.now(),
        { userId: MEMBER },
      ),
    );
    expect(won).toBe(false);
    // 敗者の監査行は書かれず、行は勝者の受諾内容のまま
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(1);
    expect(mustRow(await inviteRow(issued.id)).invitee_user_id).toBe(STRANGER);

    // revoke 側の CAS 敗北も同じガード: completed 行への失効は監査を書かない
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const revoked = await Effect.runPromise(
      invites.revokeCas(projectId, completed.id, { role: "member" }, Date.now(), {
        userId: OWNER,
      }),
    );
    expect(revoked).toBe(false);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(0);
  });

  it("unknown link pub is 404 InviteNotFound; malformed fields are schema 400", async () => {
    const keys = await makeInviteeKeys();
    const unknownLink = await deriveInviteLinkKeyPair(generateInviteLinkSeed());
    if (!unknownLink.ok) {
      throw new Error("link key derivation failed");
    }
    const unknown = await acceptAs(fixture, STRANGER, keys, {
      linkPubHex: Buffer.from(unknownLink.value.publicKeyRaw).toString("hex"),
      linkKey: unknownLink.value,
    });
    expect(unknown.status).toBe(404);
    expect(await errorTag(unknown)).toBe("InviteNotFound");

    const malformed = await acceptRequest(bearer(tokenOf(fixture.tokens, STRANGER)), {
      linkPubHex: "not-a-key",
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: "ab".repeat(64),
      linkSignatureHex: "cd".repeat(64),
    });
    expect(malformed.status).toBe(400);
    // 旧ワイヤ形(token フィールド)は strict 受理で 400(互換経路なし)
    const legacy = await acceptRequest(bearer(tokenOf(fixture.tokens, STRANGER)), {
      token: `maruhi_inv_${"A".repeat(43)}`,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      signatureHex: "ab".repeat(64),
    });
    expect(legacy.status).toBe(400);
  });

  it("unusable invites are 410 with a reason (status precedes expiry)", async () => {
    const keys = await makeInviteeKeys();
    // revoked(かつ期限切れ)→ revoked が先(判定順の固定)
    const revoked = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'revoked', expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, revoked.id)
      .run();
    const revokedResponse = await acceptAs(fixture, STRANGER, keys, revoked);
    expect(revokedResponse.status).toBe(410);
    expect((await revokedResponse.json()) as object).toMatchObject({ reason: "revoked" });

    // completed → completed
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await acceptAs(fixture, STRANGER, keys, completed);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    // pending のまま期限切れ → expired
    const expired = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, expired.id)
      .run();
    const expiredResponse = await acceptAs(fixture, STRANGER, keys, expired);
    expect(expiredResponse.status).toBe(410);
    expect((await expiredResponse.json()) as object).toMatchObject({ reason: "expired" });
  });

  it("rejects invalid signatures with 422 (link first, then accept)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const otherKeys = await makeInviteeKeys();
    const auth = bearer(tokenOf(fixture.tokens, STRANGER));
    const valid = await signAcceptance(keys, issued, STRANGER);

    // (a) 受諾署名バイトの改竄 → which=accept
    const tamperedAccept = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: flip(valid.acceptSignatureHex),
      linkSignatureHex: valid.linkSignatureHex,
    });
    expect(tamperedAccept.status).toBe(422);
    expect((await tamperedAccept.json()) as object).toMatchObject({
      _tag: "InviteSignatureInvalid",
      which: "accept",
    });

    // (b) リンク署名バイトの改竄 → which=link(判定順で先)
    const tamperedLink = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: flip(valid.acceptSignatureHex),
      linkSignatureHex: flip(valid.linkSignatureHex),
    });
    expect(tamperedLink.status).toBe(422);
    expect((await tamperedLink.json()) as object).toMatchObject({ which: "link" });

    // (c) 別のリンク鍵で作ったリンク署名(サーバー偽造の形 — 正規のリンク秘密鍵を
    //     持たない者は有効なリンク署名を作れない)
    const forgedLink = await deriveInviteLinkKeyPair(generateInviteLinkSeed());
    if (!forgedLink.ok) {
      throw new Error("link key derivation failed");
    }
    const forged = await signAcceptance(
      keys,
      { linkPubHex: issued.linkPubHex, linkKey: forgedLink.value },
      STRANGER,
    );
    const forgedResponse = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      ...forged,
    });
    expect(forgedResponse.status).toBe(422);
    expect((await forgedResponse.json()) as object).toMatchObject({ which: "link" });

    // (d) リンク改竄: 別プロジェクトの座標で署名(サーバーは保存行から再構成)
    const wrongProject = await acceptAs(fixture, STRANGER, keys, issued, {
      projectId: "0".repeat(64),
    });
    expect(wrongProject.status).toBe(422);

    // (e) 別人向けに署名した受諾の持ち込み(呼び出し主体 = 署名対象の invitee)
    const wrongInvitee = await acceptAs(fixture, STRANGER, keys, issued, {
      inviteeUserId: MEMBER,
    });
    expect(wrongInvitee.status).toBe(422);

    // (f) 宣言 sig 鍵と署名鍵の不一致(鍵すり替え): リンク署名は宣言鍵に対して
    //     正しく作れてしまう(攻撃者はリンクを持つ)が、受諾署名が落ちる
    const swapped = await signAcceptance(keys, issued, STRANGER, {
      inviteeSigPubHex: otherKeys.sigPubHex,
    });
    const swappedResponse = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: otherKeys.sigPubHex,
      ...swapped,
    });
    expect(swappedResponse.status).toBe(422);
    expect((await swappedResponse.json()) as object).toMatchObject({ which: "accept" });

    // どの失敗経路でも行は pending のまま・監査は invite.created のみ
    const row = await inviteRow(issued.id);
    expect(row?.status).toBe("pending");
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(0);
  });

  it("requires the key-material token condition (§13-2 と同水準)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const narrow = await cliToken(9009, [{ project: projectId, permission: "admin" }]);
    const signatures = await signAcceptance(keys, issued, STRANGER);
    const response = await acceptRequest(bearer(narrow), {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      ...signatures,
    });
    expect(response.status).toBe(403);
    expect((await response.json()) as object).toMatchObject({
      reason: "insufficient-permission",
    });
  });

  it("rejects a session principal even with the CSRF header (§5 能力制限 — §15-2 の反転)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const session = await loginSession(9009);
    const signatures = await signAcceptance(keys, issued, STRANGER);
    const body = {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      ...signatures,
    };
    // 受諾は CLI のみ(§15-3)でセッションの正当な導線がなく、セッション XSS +
    // 漏洩招待リンクで攻撃者鍵を被害者 user_id に束縛する複合を手前で塞ぐ
    // (§15-2)。CSRF ヘッダーの有無によらず一様に拒否
    const noCsrf = await acceptRequest({ cookie: `__Host-maruhi_session=${session}` }, body);
    expect(noCsrf.status).toBe(403);
    expect(((await noCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await acceptRequest(sessionHeaders(session), body);
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    // 行は pending のまま(拒否が受諾 CAS より前に確定している)
    expect((await inviteRow(issued.id))?.status).toBe("pending");
  });
});

/** 署名 hex の末尾 1 文字を変える(改竄の模擬)。 */
const flip = (hex: string) => `${hex.slice(0, -1)}${hex.endsWith("0") ? "1" : "0"}`;

const revoke = (id: string) =>
  SELF.fetch(`${BASE}/projects/${projectId}/invites/${id}`, {
    method: "DELETE",
    headers: bearer(tokenOf(fixture.tokens, OWNER)),
  });

describe("invite list / revoke", () => {
  it("lists issuance + acceptance; the inviter client re-verifies all three signatures", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, OWNER)),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      invitations: readonly {
        id: string;
        projectId: string;
        role: string;
        status: string;
        issuance: {
          linkPubHex: string;
          headHashHex: string;
          headSeq: number;
          issueSignatureHex: string;
        } | null;
        acceptance: {
          inviteeUserId: string;
          inviteeEncPubHex: string;
          inviteeSigPubHex: string;
          signatureHex: string;
          linkSignatureHex: string;
        } | null;
      }[];
    };
    const listed = body.invitations.find((entry) => entry.id === issued.id);
    expect(listed?.status).toBe("accepted");
    expect(listed?.issuance).toEqual({
      linkPubHex: issued.linkPubHex,
      headHashHex: issued.headHashHex,
      headSeq: issued.headSeq,
      issueSignatureHex: issued.issueSignatureHex,
    });
    // 旧 token_hash は一覧に出ない(発行文に置き換わった)
    expect(listed).not.toHaveProperty("tokenHashHex");
    const acceptance = listed?.acceptance;
    const issuance = listed?.issuance;
    if (listed === undefined || !acceptance || !issuance) {
      throw new Error("accepted invitation missing from list");
    }
    // 招待者クライアントの再検証(CRYPTO_SPEC §6.5): (1) 発行文が自分の鍵で
    // 検証できる(自分が発行した行 — 発行ピン不要)、(2) 受諾署名、(3) リンク署名
    const owner = await signingKeyPairOf(OWNER);
    const issueVerified = await verifyInviteIssueSignature({
      context: {
        suite: SUITE_ID,
        inviteId: listed.id,
        projectId: listed.projectId,
        linkPubHex: issuance.linkPubHex,
        headHashHex: issuance.headHashHex,
        headSeq: issuance.headSeq,
        role: listed.role,
        inviterUserId: OWNER,
        inviterEncPubHex: owner.encPubHex,
        inviterSigPubHex: owner.sigPubHex,
      },
      signatureHex: issuance.issueSignatureHex,
    });
    expect(issueVerified.ok).toBe(true);
    const context = {
      suite: SUITE_ID,
      projectId: listed.projectId,
      linkPubHex: issuance.linkPubHex,
      inviteeUserId: acceptance.inviteeUserId,
      inviteeEncPubHex: acceptance.inviteeEncPubHex,
      inviteeSigPubHex: acceptance.inviteeSigPubHex,
    };
    expect(
      (await verifyInviteAcceptSignature({ context, signatureHex: acceptance.signatureHex })).ok,
    ).toBe(true);
    expect(
      (await verifyInviteLinkSignature({ context, linkSignatureHex: acceptance.linkSignatureHex }))
        .ok,
    ).toBe(true);
  });

  it("list requires chain role admin: member 403, non-member 404", async () => {
    const member = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, MEMBER)),
    });
    expect(member.status).toBe(403);
    const stranger = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(fixture.tokens, STRANGER)),
    });
    expect(stranger.status).toBe(404);
  });

  it("revokes pending and accepted invites; terminal states are 410 / unknown 404", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const first = await revoke(issued.id);
    expect(first.status).toBe(204);
    expect((await inviteRow(issued.id))?.status).toBe("revoked");
    const revokedAudits = (await inviteAuditRows()).filter((r) => r.event === "invite.revoked");
    expect(revokedAudits).toHaveLength(1);
    expect(payloadOf(revokedAudits[0] ?? ({} as AuditRow))).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });

    // 受諾は 410 revoked
    const keys = await makeInviteeKeys();
    const late = await acceptAs(fixture, STRANGER, keys, issued);
    expect(late.status).toBe(410);
    expect((await late.json()) as object).toMatchObject({ reason: "revoked" });

    // 再失効は 410 revoked(黙って成功させない)+ 監査は増えない
    const again = await revoke(issued.id);
    expect(again.status).toBe(410);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(1);

    // accepted の失効は可(照合不一致の発見時に殺す経路)
    const accepted = await issueInvite(fixture, OWNER, "member");
    const acceptedKeys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, acceptedKeys, accepted)).status).toBe(200);
    expect((await revoke(accepted.id)).status).toBe(204);

    // completed は 410 completed
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await revoke(completed.id);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    // 未知 id は 404
    expect((await revoke("01ARZ3NDEKTSV4RRFFQ69G5FAV")).status).toBe(404);
  });

  it("session principals can list and revoke (§5 の許可列挙 — 読み取り + 失効系)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const session = await loginSession(9001);

    // 一覧(読み取り)— チェーン role admin 以上のセッションは可(§15-2)
    const listed = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: sessionHeaders(session),
    });
    expect(listed.status).toBe(200);

    // 失効(資格を減らす方向の mutation — ADR-0018 改訂 2 の境界原則)。
    // セッション actor の監査帰属は auth_method(トークン id なし — AUDIT_SPEC §2)
    const revoked = await SELF.fetch(`${BASE}/projects/${projectId}/invites/${issued.id}`, {
      method: "DELETE",
      headers: sessionHeaders(session),
    });
    expect(revoked.status).toBe(204);
    expect((await inviteRow(issued.id))?.status).toBe("revoked");
    const audits = (await inviteAuditRows()).filter((r) => r.event === "invite.revoked");
    expect(audits).toHaveLength(1);
    const audit = audits[0] ?? ({} as AuditRow);
    expect(audit.actor_user_id).toBe(OWNER);
    expect(audit.actor_api_token_id).toBeNull();
    expect(payloadOf(audit)).toMatchObject({ authMethod: "github_oauth" });
  });

  it("marks the key-matched accepted invite completed when add_member is accepted", async () => {
    const matched = await issueInvite(fixture, OWNER, "member");
    const otherPending = await issueInvite(fixture, OWNER, "reader");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, matched)).status).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
      },
    });

    // 鍵一致の accepted 招待だけが completed へ突合される(§15-2)
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    // 受諾されていない招待は据え置き
    expect((await inviteRow(otherPending.id))?.status).toBe("pending");
    // completed への更新は独立イベントを書かない(§15-4 — chain.member_added が証跡)
    const audits = await inviteAuditRows();
    expect(audits.filter((r) => r.event === "invite.completed")).toHaveLength(0);
  });

  it("add_member still succeeds when the reconciliation write fails (catchDefect guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // 突合の D1 書き込みを決定的に失敗させる(テーブルを一時退避)。ガードを
    // 外すと確定済み append が 500 になり appendOperation 内の 200 expect が落ちる
    await env.DB.prepare("ALTER TABLE invitations RENAME TO invitations_hidden").run();
    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
      },
    });
    await env.DB.prepare("ALTER TABLE invitations_hidden RENAME TO invitations").run();
    // 突合は欠落し、招待は accepted のまま残る(可視・失効で修復できる状態 —
    // handlers-membership.ts のコメントが宣言する「欠落側に倒す」の実挙動)
    expect(mustRow(await inviteRow(issued.id)).status).toBe("accepted");
  });

  it("leaves an accepted invite untouched when add_member carries different keys", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const differentKeys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);

    await appendOperation(fixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: differentKeys.encPubHex,
        sigPubHex: differentKeys.sigPubHex,
        role: "member",
      },
    });

    // 別鍵での add_member はこの受諾を成就させない — accepted のまま一覧に残り、
    // 管理者の失効対象として可視
    expect((await inviteRow(issued.id))?.status).toBe("accepted");
  });
});
