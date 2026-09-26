// Integration tests for the invite API (AUTH_SPEC §15 — IV
// revision). They pin authorization, existence hiding, the
// acceptance judgment order (404 → 410 → 422 link → 422 accept →
// CAS), real-data verification of the joint signatures
// (CRYPTO_SPEC §6.5 v2), the invite.* audit (AUDIT_SPEC §3.2)'s
// same-batch writes, and the guard on CAS loss.

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
    // The payload is invariant (AUDIT_SPEC §3.2 — IV revision): only
    // the invite id + the acceptance key FP. No link public key,
    // signatures, or backing-source login are written
    expect(payloadOf(audit)).toEqual({
      inviteId: issued.id,
      inviteeKeyFingerprintHex: keys.fingerprintHex,
    });
  });

  it("is single-use: the losing accept gets 410 accepted and no extra audit row", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // Both the legitimate acceptor's retry and a different person's
    // late arrival get the same 410 accepted (surface a noisy
    // conflict)
    const retry = await acceptAs(fixture, STRANGER, keys, issued);
    expect(retry.status).toBe(410);
    expect((await retry.json()) as object).toMatchObject({ reason: "accepted" });
    const memberKeys = await makeInviteeKeys();
    const late = await acceptAs(fixture, MEMBER, memberKeys, issued);
    expect(late.status).toBe(410);
    // A lost CAS adds no audit row (the changes() guard)
    const accepted = (await inviteAuditRows()).filter((r) => r.event === "invite.accepted");
    expect(accepted).toHaveLength(1);
  });

  it("a lost CAS writes no audit row (changes() guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // The concurrent loser whose "another acceptance finalized
    // between reading pending and the CAS" case is deterministically
    // reproduced via a direct repository call, since over HTTP the
    // pre-read 410 fires first (verifying the same-batch changes()
    // guard itself)
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
    // The loser's audit row is never written; the row stays as the winner's acceptance
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(1);
    expect(mustRow(await inviteRow(issued.id)).invitee_user_id).toBe(STRANGER);

    // A lost CAS on the revoke side is the same guard: revoking a completed row writes no audit
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
    // The old wire shape (the token field) is a strict-acceptance 400 (no compatibility path)
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
    // revoked (and expired) → revoked wins (pin the judgment order)
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

    // still pending and expired → expired
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

    // (a) tampered acceptance-signature bytes → which=accept
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

    // (b) tampered link-signature bytes → which=link (earlier in the judgment order)
    const tamperedLink = await acceptRequest(auth, {
      linkPubHex: issued.linkPubHex,
      encPubHex: keys.encPubHex,
      sigPubHex: keys.sigPubHex,
      acceptSignatureHex: flip(valid.acceptSignatureHex),
      linkSignatureHex: flip(valid.linkSignatureHex),
    });
    expect(tamperedLink.status).toBe(422);
    expect((await tamperedLink.json()) as object).toMatchObject({ which: "link" });

    // (c) a link signature made under a different link key (a
    //     server-forgery shape — a party without the legitimate link
    //     private key cannot produce a valid link signature)
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

    // (d) link tampering: signed at a different project's coordinates
    //     (the server reconstructs from the stored row)
    const wrongProject = await acceptAs(fixture, STRANGER, keys, issued, {
      projectId: "0".repeat(64),
    });
    expect(wrongProject.status).toBe(422);

    // (e) presenting an acceptance signed for someone else (the
    //     calling principal = the signed invitee)
    const wrongInvitee = await acceptAs(fixture, STRANGER, keys, issued, {
      inviteeUserId: MEMBER,
    });
    expect(wrongInvitee.status).toBe(422);

    // (f) declared-sig-key vs signing-key mismatch (a key swap): the
    //     link signature can be made correctly against the declared
    //     key (the attacker holds the link), but the acceptance
    //     signature fails
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

    // On every failure path the row stays pending and the audit holds only invite.created
    const row = await inviteRow(issued.id);
    expect(row?.status).toBe("pending");
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.accepted")).toHaveLength(0);
  });

  it("requires the key-material token condition (the §13-2 level)", async () => {
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

  it("rejects a session principal even with the CSRF header (the §5 capability restriction — the §15-2 inversion)", async () => {
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
    // Acceptance is CLI-only (§15-3) with no legitimate session
    // path; this cuts off in front a composite where a session XSS +
    // leaked invite link binds an attacker key to the victim's
    // user_id (§15-2). Rejected uniformly with or without the CSRF
    // header
    const noCsrf = await acceptRequest({ cookie: `__Host-maruhi_session=${session}` }, body);
    expect(noCsrf.status).toBe(403);
    expect(((await noCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    const withCsrf = await acceptRequest(sessionHeaders(session), body);
    expect(withCsrf.status).toBe(403);
    expect(((await withCsrf.json()) as { reason: string }).reason).toBe("session-not-allowed");
    // The row stays pending (the rejection settles before the acceptance CAS)
    expect((await inviteRow(issued.id))?.status).toBe("pending");
  });
});

/** Flip the last character of a signature hex (a tamper simulation). */
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
    // The old token_hash no longer appears in the list (replaced by the issuance document)
    expect(listed).not.toHaveProperty("tokenHashHex");
    const acceptance = listed?.acceptance;
    const issuance = listed?.issuance;
    if (listed === undefined || !acceptance || !issuance) {
      throw new Error("accepted invitation missing from list");
    }
    // The inviter client's re-verification (CRYPTO_SPEC §6.5): (1)
    // the issuance document verifies under one's own key (a row one
    // issued oneself — no issuance pin needed), (2) the acceptance
    // signature, (3) the link signature
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
        scopeKind: listed.scopeKind,
        scopeEnvironmentIds: listed.scopeEnvironmentIds,
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

    // Acceptance is 410 revoked
    const keys = await makeInviteeKeys();
    const late = await acceptAs(fixture, STRANGER, keys, issued);
    expect(late.status).toBe(410);
    expect((await late.json()) as object).toMatchObject({ reason: "revoked" });

    // Re-revoking is 410 revoked (no silent success) + audit does not grow
    const again = await revoke(issued.id);
    expect(again.status).toBe(410);
    expect((await inviteAuditRows()).filter((r) => r.event === "invite.revoked")).toHaveLength(1);

    // Revoking an accepted invite is allowed (the path for killing it when a mismatch is discovered)
    const accepted = await issueInvite(fixture, OWNER, "member");
    const acceptedKeys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, acceptedKeys, accepted)).status).toBe(200);
    expect((await revoke(accepted.id)).status).toBe(204);

    // completed is 410 completed
    const completed = await issueInvite(fixture, OWNER, "member");
    await env.DB.prepare("UPDATE invitations SET status = 'completed' WHERE id = ?")
      .bind(completed.id)
      .run();
    const completedResponse = await revoke(completed.id);
    expect(completedResponse.status).toBe(410);
    expect((await completedResponse.json()) as object).toMatchObject({ reason: "completed" });

    // An unknown id is 404
    expect((await revoke("01ARZ3NDEKTSV4RRFFQ69G5FAV")).status).toBe(404);
  });

  it("session principals can list and revoke (§5's permitted set — reads + revocations)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const session = await loginSession(9001);

    // Listing (a read) — allowed for a session with chain role admin
    // or above (§15-2)
    const listed = await SELF.fetch(`${BASE}/projects/${projectId}/invites`, {
      headers: sessionHeaders(session),
    });
    expect(listed.status).toBe(200);

    // Revocation (a mutation in the direction of reducing
    // credentials — ADR-0018 revision 2's boundary principle). A
    // session actor's audit attribution is auth_method (no token id —
    // AUDIT_SPEC §2)
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
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    // Only the accepted invite whose keys match is reconciled to completed (§15-2)
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    // An unaccepted invite is kept as-is
    expect((await inviteRow(otherPending.id))?.status).toBe("pending");
    // The update to completed writes no separate event (§15-4 —
    // chain.member_added is the evidence)
    const audits = await inviteAuditRows();
    expect(audits.filter((r) => r.event === "invite.completed")).toHaveLength(0);
  });

  it("add_member still succeeds when the reconciliation write fails (catchDefect guard)", async () => {
    const issued = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, issued)).status).toBe(200);
    // Make the reconciliation's D1 write fail deterministically (the
    // table is temporarily stashed). Without the guard the committed
    // append would 500 and appendOperation's 200 expect would fail
    await env.DB.prepare("ALTER TABLE invitations RENAME TO invitations_hidden").run();
    await appendOperation(fixture, OWNER, {
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
    // The reconciliation is dropped and the invite stays accepted
    // (a state recoverable via visibility and revocation — the
    // actual behavior of "fail on the drop side" that the
    // handlers-membership.ts comment declares)
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
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });

    // An add_member under a different key does not fulfill this
    // acceptance — it stays listed as accepted, visible as a
    // revocation target for admins
    expect((await inviteRow(issued.id))?.status).toBe("accepted");
  });
});
