import {
  deriveInviteLinkKeyPair,
  generateInviteLinkSeed,
  SUITE_ID,
  verifyInviteAcceptSignature,
  verifyInviteIssueSignature,
  verifyInviteLinkSignature,
} from "@maruhi/crypto";
import { testEnvironmentId, testProjectId, testUserId } from "@maruhi/test-kit";
import { env, SELF } from "cloudflare:test";
import { Context, Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";

import { InviteRepo, makeDbServices } from "../src/db.package/index.ts";
import { BASE, bearer, cliToken, loginSession, sessionHeaders } from "./support/auth.ts";
import {
  appendOperation,
  createEnvironmentOk,
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
  inviteFixture,
  inviteAuditRows,
  inviteRow,
  issueInvite,
  issueInviteRequest,
  makeInviteeKeys,
  makeIssuePayload,
  mustRow,
  payloadOf,
  registerInviteScenario,
  signAcceptance,
  signingKeyPairOf,
} from "./support/invites-scenario.ts";

registerInviteScenario();

describe("invite accept", () => {
  it("accepts with both signatures and records invite.accepted in the same batch", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const response = await acceptAs(inviteFixture, STRANGER, keys, issued);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { id: string; projectId: string; role: string };
    expect(body).toEqual({
      id: issued.id,
      projectId,
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });

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
    expect(payloadOf(audit)).toEqual({
      inviteId: issued.id,
      inviteeKeyFingerprintHex: keys.fingerprintHex,
    });
  });

  it("is single-use: the losing accept gets 410 accepted and no extra audit row", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, issued)).status).toBe(200);
    const retry = await acceptAs(inviteFixture, STRANGER, keys, issued);
    expect(retry.status).toBe(410);
    expect((await retry.json()) as object).toMatchObject({ reason: "accepted" });
    const memberKeys = await makeInviteeKeys();
    const late = await acceptAs(inviteFixture, MEMBER, memberKeys, issued);
    expect(late.status).toBe(410);
    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
  });

  it("a lost CAS writes no audit row (changes() guard)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, issued)).status).toBe(200);
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
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(1);
    expect(mustRow(await inviteRow(issued.id)).invitee_user_id).toBe(STRANGER);

    const completed = await issueInvite(inviteFixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const revoked = await Effect.runPromise(
      invites.revokeCas(testProjectId(projectId), completed.id, { role: "member" }, Date.now(), {
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
    const unknown = await acceptAs(inviteFixture, STRANGER, keys, {
      linkPubHex: Buffer.from(unknownLink.value.publicKeyRaw).toString("hex"),
      linkKey: unknownLink.value,
    });
    expect(unknown.status).toBe(404);
    expect(await errorTag(unknown)).toBe("InviteNotFound");

    const malformed = await acceptRequest(bearer(tokenOf(inviteFixture.tokens, STRANGER)), {
      linkPubHex: "not-a-key",
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: "ab".repeat(64),
      linkSignatureHex: "cd".repeat(64),
    });
    expect(malformed.status).toBe(400);
  });

  it("unusable invites are 410 with a reason (status precedes expiry)", async () => {
    const keys = await makeInviteeKeys();
    const revoked = await issueInvite(inviteFixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'revoked', expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, revoked.id)
      .run();
    const revokedResponse = await acceptAs(inviteFixture, STRANGER, keys, revoked);
    expect(revokedResponse.status).toBe(410);
    expect((await revokedResponse.json()) as object).toMatchObject({ reason: "revoked" });

    const completed = await issueInvite(inviteFixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await acceptAs(inviteFixture, STRANGER, keys, completed);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    const expired = await issueInvite(inviteFixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET expires_at = ? WHERE id = ?")
      .bind(Date.now() - 1000, expired.id)
      .run();
    const expiredResponse = await acceptAs(inviteFixture, STRANGER, keys, expired);
    expect(expiredResponse.status).toBe(410);
    expect((await expiredResponse.json()) as object).toMatchObject({ reason: "expired" });
  });

  it("rejects invalid signatures with 422 (link first, then accept)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const otherKeys = await makeInviteeKeys();
    const auth = bearer(tokenOf(inviteFixture.tokens, STRANGER));
    const valid = await signAcceptance(keys, issued, STRANGER);

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

    const tamperedLink = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: flip(valid.acceptSignatureHex),
      linkSignatureHex: flip(valid.linkSignatureHex),
    });
    expect(tamperedLink.status).toBe(422);
    expect((await tamperedLink.json()) as object).toMatchObject({ which: "link" });

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

    const wrongProject = await acceptAs(inviteFixture, STRANGER, keys, issued, {
      projectId: testProjectId("0".repeat(64)),
    });
    expect(wrongProject.status).toBe(422);

    const wrongInvitee = await acceptAs(inviteFixture, STRANGER, keys, issued, {
      inviteeUserId: MEMBER,
    });
    expect(wrongInvitee.status).toBe(422);

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

    const row = await inviteRow(issued.id);
    expect(row?.status).toBe("pending");
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(0);
  });

  it("requires the key-material token condition (the §13-2 level)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const narrow = await cliToken(9009, [
      { project: testProjectId(projectId), permission: "admin" },
    ]);
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

  it("rejects a session principal even with the CSRF header (the §5 capability restriction — the §15-2 inversion)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const session = await loginSession(9009);
    const signatures = await signAcceptance(keys, issued, STRANGER);
    const body = {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      ...signatures,
    };
    const noCsrf = await acceptRequest({ cookie: `__Host-maruhi_session=${session}` }, body);
    expect(noCsrf.status).toBe(403);
    expect(((await noCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await acceptRequest(sessionHeaders(session), body);
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    expect((await inviteRow(issued.id))?.status).toBe("pending");
  });
});

const flip = (hex: string) => `${hex.slice(0, -1)}${hex.endsWith("0") ? "1" : "0"}`;

const revoke = (id: string) =>
  SELF.fetch(`${BASE}/projects/${projectId}/invites/${id}`, {
    method: "DELETE",
    headers: bearer(tokenOf(inviteFixture.tokens, OWNER)),
  });

describe("invite list / revoke", () => {
  it("lists issuance + acceptance; the inviter client re-verifies all three signatures", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, issued)).status).toBe(200);

    const response = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(inviteFixture.tokens, OWNER)),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      invitations: readonly {
        id: string;
        projectId: string;
        role: string;
        scopeKind: "all" | "listed";
        scopeEnvironmentIds: readonly string[];
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
    expect(listed).not.toHaveProperty("tokenHashHex");
    const acceptance = listed?.acceptance;
    const issuance = listed?.issuance;
    if (listed === undefined || !acceptance || !issuance) {
      throw new Error("accepted invitation missing from list");
    }
    const owner = await signingKeyPairOf(OWNER);
    const issueVerified = await verifyInviteIssueSignature({
      context: {
        suite: SUITE_ID,
        inviteId: listed.id,
        projectId: testProjectId(listed.projectId),
        linkPubHex: issuance.linkPubHex,
        headHashHex: issuance.headHashHex,
        headSeq: issuance.headSeq,
        role: listed.role,
        inviterUserId: OWNER,
        inviterEncPubHex: owner.encPubHex,
        inviterSigPubHex: owner.sigPubHex,
        scopeKind: listed.scopeKind,
        scopeEnvironmentIds: listed.scopeEnvironmentIds.map(testEnvironmentId),
      },
      signatureHex: issuance.issueSignatureHex,
    });
    expect(issueVerified.ok).toBe(true);
    const context = {
      suite: SUITE_ID,
      projectId: testProjectId(listed.projectId),
      linkPubHex: issuance.linkPubHex,
      inviteeUserId: testUserId(acceptance.inviteeUserId),
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
      headers: bearer(tokenOf(inviteFixture.tokens, MEMBER)),
    });
    expect(member.status).toBe(403);
    const stranger = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: bearer(tokenOf(inviteFixture.tokens, STRANGER)),
    });
    expect(stranger.status).toBe(404);
  });

  it("revokes pending and accepted invites; terminal states are 410 / unknown 404", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const first = await revoke(issued.id);
    expect(first.status).toBe(204);
    expect((await inviteRow(issued.id))?.status).toBe("revoked");
    const revokedAudits = (await inviteAuditRows()).filter((r) => r.event === "invite.revoked");
    expect(revokedAudits).toHaveLength(1);
    expect(payloadOf(revokedAudits[0] ?? ({} as AuditRow))).toMatchObject({
      inviteId: issued.id,
      role: "member",
    });

    const keys = await makeInviteeKeys();
    const late = await acceptAs(inviteFixture, STRANGER, keys, issued);
    expect(late.status).toBe(410);
    expect((await late.json()) as object).toMatchObject({ reason: "revoked" });

    const again = await revoke(issued.id);
    expect(again.status).toBe(410);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(1);

    const accepted = await issueInvite(inviteFixture, OWNER, "member");
    const acceptedKeys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, acceptedKeys, accepted)).status).toBe(200);
    expect((await revoke(accepted.id)).status).toBe(204);

    const completed = await issueInvite(inviteFixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await revoke(completed.id);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    expect((await revoke("01ARZ3NDEKTSV4RRFFQ69G5FAV")).status).toBe(404);
  });

  it("session principals can list and revoke (§5's permitted set — reads + revocations)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const session = await loginSession(9001);

    const listed = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: sessionHeaders(session),
    });
    expect(listed.status).toBe(200);

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
    const matched = await issueInvite(inviteFixture, OWNER, "member");
    const otherPending = await issueInvite(inviteFixture, OWNER, "reader");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, matched)).status).toBe(200);

    await appendOperation(inviteFixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    expect((await inviteRow(matched.id))?.status).toBe("completed");
    expect((await inviteRow(otherPending.id))?.status).toBe("pending");
    const audits = await inviteAuditRows();
    expect(audits.filter((r) => r.event === "invite.completed")).toHaveLength(0);
  });

  it("completes only the accepted invite whose role and scope match add_member (same invitee, same keys)", async () => {
    const matched = await issueInvite(inviteFixture, OWNER, "member");
    const roleMismatch = await issueInvite(inviteFixture, OWNER, "reader");
    const scopePayload = await makeIssuePayload(inviteFixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: [testEnvironmentId("env-dev-0002")],
    });
    const scopeIssued = await issueInviteRequest(inviteFixture, OWNER, "member", scopePayload);
    expect(scopeIssued.status).toBe(200);
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, matched)).status).toBe(200);
    expect((await acceptAs(inviteFixture, STRANGER, keys, roleMismatch)).status).toBe(200);
    expect((await acceptAs(inviteFixture, STRANGER, keys, scopePayload)).status).toBe(200);

    await appendOperation(inviteFixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    expect((await inviteRow(matched.id))?.status).toBe("completed");
    expect((await inviteRow(roleMismatch.id))?.status).toBe("accepted");
    expect((await inviteRow(scopePayload.id))?.status).toBe("accepted");
    expect((await revoke(scopePayload.id)).status).toBe(204);
    expect((await inviteRow(scopePayload.id))?.status).toBe("revoked");
  });

  it("completes a listed invite whose stored scope order differs from add_member (scope is a set); set-different scopes stay accepted", async () => {
    const envA = "env-dev-0001";
    const envB = "env-dev-0002";
    await createEnvironmentOk(inviteFixture, envA, "Dev A");
    await createEnvironmentOk(inviteFixture, envB, "Dev B");

    const reordered = await makeIssuePayload(inviteFixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: [testEnvironmentId(envB), testEnvironmentId(envA)],
    });
    expect((await issueInviteRequest(inviteFixture, OWNER, "member", reordered)).status).toBe(200);
    const subset = await makeIssuePayload(inviteFixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: [testEnvironmentId(envA)],
    });
    expect((await issueInviteRequest(inviteFixture, OWNER, "member", subset)).status).toBe(200);
    const different = await makeIssuePayload(inviteFixture, OWNER, "member", {
      scopeKind: "listed",
      scopeEnvironmentIds: [testEnvironmentId(envA), testEnvironmentId("env-dev-0003")],
    });
    expect((await issueInviteRequest(inviteFixture, OWNER, "member", different)).status).toBe(200);

    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, reordered)).status).toBe(200);
    expect((await acceptAs(inviteFixture, STRANGER, keys, subset)).status).toBe(200);
    expect((await acceptAs(inviteFixture, STRANGER, keys, different)).status).toBe(200);
    expect(JSON.parse(String(mustRow(await inviteRow(reordered.id)).scope_environments))).toEqual([
      envB,
      envA,
    ]);

    await appendOperation(inviteFixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: [testEnvironmentId(envA), testEnvironmentId(envB)],
      },
    });

    expect((await inviteRow(reordered.id))?.status).toBe("completed");
    expect((await inviteRow(subset.id))?.status).toBe("accepted");
    expect((await inviteRow(different.id))?.status).toBe("accepted");
  });

  it("add_member still succeeds when the reconciliation write fails (catchDefect guard)", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, issued)).status).toBe(200);
    await env.DB.prepare("ALTER TABLE invitations RENAME TO invitations_hidden").run();
    await appendOperation(inviteFixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    await env.DB.prepare("ALTER TABLE invitations_hidden RENAME TO invitations").run();
    expect(mustRow(await inviteRow(issued.id)).status).toBe("accepted");
  });

  it("leaves an accepted invite untouched when add_member carries different keys", async () => {
    const issued = await issueInvite(inviteFixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    const differentKeys = await makeInviteeKeys();
    expect((await acceptAs(inviteFixture, STRANGER, keys, issued)).status).toBe(200);

    await appendOperation(inviteFixture, OWNER, {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: differentKeys.encPubHex,
        sigPubHex: differentKeys.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    expect((await inviteRow(issued.id))?.status).toBe("accepted");
  });
});
