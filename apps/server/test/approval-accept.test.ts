// ES + PF1 K5 — the four-eyes acceptance surface (CRYPTO_SPEC §6.4
// "acceptance of scope and four-eyes" / AUTH_SPEC §11-1 / §12-8 /
// §15-2 / AUDIT_SPEC §3.4. Design record docs/notes/es-design.md
// §11).
//
// Rules pinned:
//   - acceptance policy (DO — appendProgram): the `expires_at_ms`
//     upper bound (server clock at acceptance + 30 days) → the
//     pending cap of 32 (expired ones do not count; withdraw frees a
//     slot). Typed 422 `ProposalLimit` (reason + limit). Expired
//     proposals are not rejected (K5-C)
//   - a completed approve's acceptance side effects are identical to
//     accepting the inner op directly, in the same acceptance task:
//     rotation-needed detection (trigger = the inner op,
//     triggerChainSeq = the approve's seq), attestation-row deletion,
//     invite completed matching, and membership projection
//   - an incomplete approve / propose / withdraw /
//     set_approval_policy carries no side effects

import type { ApprovalTargetOp, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { importSigningKeyPair, signHeadAttestation } from "@maruhi/crypto";
import { vectorKeys } from "@maruhi/crypto/test-support";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

import { MAX_PENDING_PROPOSALS, MAX_PROPOSAL_LIFETIME_MS } from "../src/policy.ts";
import { addMemberOperation, hexBytes, signEntryAt, vectorKeyOf } from "./support/data-crypto.ts";
import {
  appendOperation,
  createEnvironmentOk,
  MEMBER,
  OWNER,
  projectId,
  requestJson,
  seedMemberToken,
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
import { acceptAs, inviteRow, issueInvite, makeInviteeKeys } from "./support/invites-scenario.ts";
import { queryProjectDo, readAuditEvents } from "./support/project-do.ts";

registerDataScenario();

/** The second owner (vector key user-owner-0014). Four-eyes enablement requires owner ≥ required. */
const OWNER2 = "user-owner-0014";
const DAY_MS = 24 * 60 * 60 * 1000;

interface WireRotationFlag {
  readonly environmentId: string;
  readonly variableId: string;
  readonly basis: "read" | "readable";
  readonly targetUserId?: string;
  readonly triggerChainSeq: number;
  readonly trigger?: string;
}

async function readFlags(): Promise<readonly WireRotationFlag[]> {
  const response = await requestJson("GET", "/rotation/flags", token(OWNER));
  expect(response.status).toBe(200);
  return ((await response.json()) as { flags: readonly WireRotationFlag[] }).flags;
}

/** Sign + generic append (the variant where the caller judges acceptance). Advances the fixture head on acceptance. */
async function appendRaw(
  actorUserId: string,
  operation: ChainOperation,
): Promise<{ readonly response: Response; readonly hash: string }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actorUserId,
    operation,
  });
  const response = await requestJson("POST", "/chain/entries", token(actorUserId), {
    parentHeadHashHex: fixture.head.hashHex,
    entry,
  });
  if (response.status === 200) {
    fixture.head = { seq: entry.seq, hashHex: hash };
  }
  return { response, hash };
}

/** Establish two owners + a policy (ops, required = 2). */
async function enableFourEyes(ops: readonly ApprovalTargetOp[]): Promise<void> {
  await seedMemberToken(fixture, OWNER2, 9014);
  await appendOperation(fixture, OWNER, addMemberOperation(OWNER2, "owner"));
  await appendOperation(fixture, OWNER, {
    op: "set_approval_policy",
    payload: { ops, requiredApprovals: 2 },
  });
}

const proposeOp = (inner: ProposableOperation, expiresAtMs: number): ChainOperation => ({
  op: "propose",
  payload: { inner, expiresAtMs },
});

const removeMemberOp = (targetUserId: string): ProposableOperation => ({
  op: "remove_member",
  payload: { targetUserId },
});

/** Get a proposal accepted and return the proposal entry's hash (the reference approve / withdraw point at). */
async function propose(actorUserId: string, inner: ProposableOperation, expiresAtMs: number) {
  const { response, hash } = await appendRaw(actorUserId, proposeOp(inner, expiresAtMs));
  expect(response.status).toBe(200);
  return hash;
}

const approveOp = (proposalHashHex: string): ChainOperation => ({
  op: "approve",
  payload: { proposalHashHex },
});

const withdrawOp = (proposalHashHex: string): ChainOperation => ({
  op: "withdraw",
  payload: { proposalHashHex },
});

type AuditRow = Record<string, unknown>;

const payloadOf = (row: AuditRow): Record<string, unknown> =>
  JSON.parse(String(row["payload"])) as Record<string, unknown>;

/** The nth row for a chain_seq (fails if absent). */
function rowAt(rows: readonly AuditRow[], chainSeq: number, nth = 0): AuditRow {
  const row = rows.filter((candidate) => candidate["chain_seq"] === chainSeq)[nth];
  if (row === undefined) throw new Error(`no audit row #${nth} for chain_seq=${chainSeq}`);
  return row;
}

/** The audit-row shape among a completed approve's side effects (order: chain.approved + applied row + detection row). */
function expectAppliedRemoval(
  rows: readonly AuditRow[],
  input: { readonly proposalSeq: number; readonly approveSeq: number },
): void {
  expect(
    rows.filter((row) => row["chain_seq"] === input.proposalSeq).map((row) => row["event"]),
  ).toEqual(["chain.proposed"]);
  const approvedRow = rowAt(rows, input.approveSeq, 0);
  const appliedRow = rowAt(rows, input.approveSeq, 1);
  expect(approvedRow["event"]).toBe("chain.approved");
  expect(approvedRow["actor_user_id"]).toBe(OWNER2);
  expect(payloadOf(approvedRow)).toEqual({ proposalChainSeq: input.proposalSeq, completed: true });
  expect(appliedRow["event"]).toBe("chain.member_removed");
  expect(appliedRow["actor_user_id"]).toBe(OWNER);
  expect(appliedRow["actor_key_fingerprint"]).toBe(vectorKeyOf(OWNER).key_fingerprint_hex);
  expect(appliedRow["target_user_id"]).toBe(MEMBER);
  expect(appliedRow["chain_seq"]).toBe(input.approveSeq);
  expect(payloadOf(appliedRow)).toEqual({ viaProposalSeq: input.proposalSeq });
  // The detection row (rotation.recommended) is written after the mirror row → the applied row (same acceptance task)
  const recommended = rows.find((row) => row["event"] === "rotation.recommended");
  if (recommended === undefined) throw new Error("no rotation.recommended row");
  expect(Number(recommended["seq"])).toBeGreaterThan(Number(appliedRow["seq"]));
  expect(payloadOf(recommended)).toMatchObject({ trigger: "remove_member" });
}

/** Sign and submit a §6.6 attestation with the attester's key (the same material as attestation.test.ts). */
async function submitAttestation(attesterUserId: string): Promise<void> {
  const keys = vectorKeys[attesterUserId];
  if (keys === undefined) throw new Error(`no vector keys for ${attesterUserId}`);
  const pair = await importSigningKeyPair({
    publicKey: hexBytes(keys.sig_pub_hex),
    privateSeed: hexBytes(keys.sig_sk_seed_hex),
  });
  if (!pair.ok) throw new Error("key import failed");
  const signed = await signHeadAttestation({
    context: {
      suite: "maruhi/v1",
      projectId,
      attesterUserId,
      chainHeadHashHex: fixture.head.hashHex,
      chainHeadSeq: fixture.head.seq,
    },
    signingKey: pair.value.privateKey,
  });
  if (!signed.ok) throw new Error("attestation signing failed");
  const response = await requestJson("PUT", "/head-attestation", token(attesterUserId), {
    suite: "maruhi/v1",
    chainHeadHashHex: fixture.head.hashHex,
    chainHeadSeq: fixture.head.seq,
    signatureHex: signed.value,
  });
  expect(response.status).toBe(204);
}

async function attestationRowsFor(attesterUserId: string): Promise<number> {
  const rows = await queryProjectDo(
    projectId,
    "SELECT COUNT(*) AS n FROM head_attestations WHERE attester_user_id = ?",
    attesterUserId,
  );
  return Number(rows[0]?.["n"] ?? 0);
}

async function projectionRowsFor(userId: string): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND user_id = ?",
  )
    .bind(projectId, userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

describe("propose's acceptance policy (AUTH_SPEC §12-8 — upper bound → pending cap)", () => {
  it("rejects an expiry beyond the server clock + 30 days with 422 ProposalLimit (proposal-lifetime) before CAS / verifyChain", async () => {
    await enableFourEyes(["remove_member"]);
    const head = { ...fixture.head };
    const { response } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + MAX_PROPOSAL_LIFETIME_MS + DAY_MS),
    );
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toEqual({
      _tag: "ProposalLimit",
      reason: "proposal-lifetime",
      limit: MAX_PROPOSAL_LIFETIME_MS,
    });
    // A pre-acceptance rejection — the head does not move and no mirror row is added
    expect(fixture.head).toEqual(head);
    const rows = await readAuditEvents(projectId);
    expect(rows.filter((row) => row["event"] === "chain.proposed")).toHaveLength(0);
    // Inside the bound it is accepted (the exact-equality boundary is pinned in proposal-policy.test.ts)
    const { response: atBound } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + MAX_PROPOSAL_LIFETIME_MS - DAY_MS),
    );
    expect(atBound.status).toBe(200);
  });

  it("leaves no trace of a rejected propose: the next append succeeds and the pending set is unchanged", async () => {
    await enableFourEyes(["remove_member"]);
    const live = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const head = { ...fixture.head };
    const { response: rejected } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + MAX_PROPOSAL_LIFETIME_MS + DAY_MS),
    );
    expect(rejected.status).toBe(422);
    expect(fixture.head).toEqual(head);
    // The rejection precedes CAS / verifyChain and leaves no trace in
    // derived or stored state: the next append on the same parent head
    // passes, and pending stays at the original 1 (the approve
    // completes)
    const { response: approved } = await appendRaw(OWNER2, approveOp(live));
    expect(approved.status).toBe(200);
    const chain = (await (await requestJson("GET", "/chain", token(OWNER))).json()) as {
      entries: readonly { readonly op: string }[];
    };
    expect(chain.entries.filter((entry) => entry.op === "propose")).toHaveLength(1);
    expect(await projectionRowsFor(MEMBER)).toBe(0);
  });

  it("caps live pending proposals at 32 (expired ones do not count; withdraw frees a slot)", async () => {
    await enableFourEyes(["remove_member"]);
    // A proposal already expired at creation (expires_at_ms in the
    // past) is accepted (K5-C) but does not count toward the cap —
    // nobody can approve it and it occupies no slot
    const expired = await propose(OWNER, removeMemberOp(MEMBER), 1);
    for (let index = 0; index < MAX_PENDING_PROPOSALS; index += 1) {
      await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    }
    const { response: overflow } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(overflow.status).toBe(422);
    await expect(overflow.json()).resolves.toEqual({
      _tag: "ProposalLimit",
      reason: "pending-proposals",
      limit: MAX_PENDING_PROPOSALS,
    });
    // Closing the expired proposal frees no slot (it was never counted)
    const { response: withdrawExpired } = await appendRaw(OWNER, withdrawOp(expired));
    expect(withdrawExpired.status).toBe(200);
    const { response: stillFull } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(stillFull.status).toBe(422);
    // Withdrawing one in-term proposal frees one slot (the
    // immediately-preceding acceptance was a withdraw, so the in-term
    // proposal's hash is resolved from the chain)
    const proposedRows = (await readAuditEvents(projectId)).filter(
      (row) => row["event"] === "chain.proposed",
    );
    expect(proposedRows).toHaveLength(MAX_PENDING_PROPOSALS + 1);
    const chain = (await (await requestJson("GET", "/chain", token(OWNER))).json()) as {
      entries: readonly { readonly seq: number; readonly op: string }[];
    };
    const lastPropose = chain.entries.filter((entry) => entry.op === "propose").at(-1);
    if (lastPropose === undefined) throw new Error("no propose on chain");
    const hashes = await queryProjectDo(
      projectId,
      "SELECT entry_hash_hex FROM chain_entries WHERE seq = ?",
      lastPropose.seq,
    );
    const { response: withdrawLive } = await appendRaw(
      OWNER,
      withdrawOp(String(hashes[0]?.["entry_hash_hex"])),
    );
    expect(withdrawLive.status).toBe(200);
    const { response: admitted } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(admitted.status).toBe(200);
  });
});

describe("a completed approve's acceptance side effects (CRYPTO_SPEC §6.4 / AUDIT_SPEC §3.4 / §4.1)", () => {
  it("applies remove_member at the approve seq: rotation detection, attestation cleanup, projection removal, applied mirror row", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER reads the value (grounds for basis = read) and holds a head attestation
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
    expect(pull.status).toBe(200);
    await submitAttestation(MEMBER);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

    await enableFourEyes(["remove_member"]);
    // A direct append is rejected with approval-required (a consensus rule) — four-eyes is in effect
    const direct = await appendRaw(OWNER, removeMemberOp(MEMBER));
    expect(direct.response.status).toBe(422);
    await expect(direct.response.json()).resolves.toMatchObject({ reason: "approval-required" });

    const proposalHash = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const proposalSeq = fixture.head.seq;
    // Nothing happens at proposal time (pre-application — rulings P7 / P21)
    expect(await readFlags()).toHaveLength(0);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

    // An owner's proposal = 1 vote. The second owner's approve reaches quorum 2 = application
    const { response: approved } = await appendRaw(OWNER2, approveOp(proposalHash));
    expect(approved.status).toBe(200);
    const approveSeq = fixture.head.seq;

    const flags = await readFlags();
    expect(flags).toHaveLength(1);
    expect(flags).toMatchObject([
      {
        environmentId: ENV,
        variableId: VAR,
        basis: "read",
        targetUserId: MEMBER,
        triggerChainSeq: approveSeq,
        trigger: "remove_member",
      },
    ]);
    expect(await attestationRowsFor(MEMBER)).toBe(0);
    expect(await projectionRowsFor(MEMBER)).toBe(0);
    // The removed member can no longer read (§11-2)
    const denied = await requestJson("GET", "/chain", token(MEMBER));
    expect(denied.status).toBe(404);

    expectAppliedRemoval(await readAuditEvents(projectId), { proposalSeq, approveSeq });
  });

  it("completes the key-matched accepted invite and inserts the projection row when add_member is applied via a proposal", async () => {
    await enableFourEyes(["add_member"]);
    const matched = await issueInvite(fixture, OWNER, "member");
    const keys = await makeInviteeKeys();
    expect((await acceptAs(fixture, STRANGER, keys, matched)).status).toBe(200);
    expect((await inviteRow(matched.id))?.status).toBe("accepted");

    const addStranger: ProposableOperation = {
      op: "add_member",
      payload: {
        targetUserId: STRANGER,
        encPubHex: keys.encPubHex,
        sigPubHex: keys.sigPubHex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const proposalHash = await propose(OWNER, addStranger, Date.now() + 7 * DAY_MS);
    // At proposal time neither the match nor the projection happens
    expect((await inviteRow(matched.id))?.status).toBe("accepted");
    expect(await projectionRowsFor(STRANGER)).toBe(0);

    const { response } = await appendRaw(OWNER2, approveOp(proposalHash));
    expect(response.status).toBe(200);
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    expect(await projectionRowsFor(STRANGER)).toBe(1);
    // The new member can read the chain (application = membership starts at the approve's seq)
    const asStranger = await requestJson("GET", "/chain", token(STRANGER));
    expect(asStranger.status).toBe(200);
    const applied = (await readAuditEvents(projectId)).filter(
      (row) => row["chain_seq"] === fixture.head.seq,
    );
    expect(applied.map((row) => row["event"])).toEqual(["chain.approved", "chain.member_added"]);
    expect(payloadOf(rowAt(applied, fixture.head.seq, 1))).toEqual({
      role: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
      viaProposalSeq: fixture.head.seq - 1,
    });
  });

  it("cleans the stale-key wraps of a member re-added via a proposal (dek.deleted with triggerChainSeq = approve seq)", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER holds the epoch-1 wrap (addressed to the current key).
    // The removal (a direct append since the policy is off) does not
    // erase the wrap (§12-6 — kept for a return under the same key)
    await appendOperation(fixture, OWNER, removeMemberOp(MEMBER));
    const wrapsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsBefore[0]?.["n"])).toBe(1);

    await enableFourEyes(["add_member"]);
    // A proposal to re-add MEMBER under a different key (borrowing vector key user-prodreader-0012)
    const rekeyed = vectorKeyOf("user-prodreader-0012");
    const readd: ProposableOperation = {
      op: "add_member",
      payload: {
        targetUserId: MEMBER,
        encPubHex: rekeyed.enc_pub_hex,
        sigPubHex: rekeyed.sig_pub_hex,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const proposalHash = await propose(OWNER, readd, Date.now() + 7 * DAY_MS);
    // No sweeping at proposal time
    const wrapsPending = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsPending[0]?.["n"])).toBe(1);

    const { response } = await appendRaw(OWNER2, approveOp(proposalHash));
    expect(response.status).toBe(200);
    const approveSeq = fixture.head.seq;
    const wrapsAfter = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsAfter[0]?.["n"])).toBe(0);
    const deleted = (await readAuditEvents(projectId)).filter(
      (row) => row["event"] === "dek.deleted",
    );
    expect(deleted).toHaveLength(1);
    const row = deleted[0];
    if (row === undefined) throw new Error("unreachable");
    expect(row["actor_type"]).toBe("system");
    expect(row["target_user_id"]).toBe(MEMBER);
    expect(row["environment_id"]).toBe(ENV);
    expect(payloadOf(row)).toEqual({ cause: "member-readded", triggerChainSeq: approveSeq });
    // The sweep runs after the applied row (chain.member_added) (same acceptance task)
    const applied = rowAt(await readAuditEvents(projectId), approveSeq, 1);
    expect(applied["event"]).toBe("chain.member_added");
    expect(Number(row["seq"])).toBeGreaterThan(Number(applied["seq"]));
  });

  it("does nothing for a withdrawn proposal and for a set_approval_policy entry", async () => {
    await enableFourEyes(["remove_member"]);
    const proposalHash = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const { response } = await appendRaw(OWNER, withdrawOp(proposalHash));
    expect(response.status).toBe(200);
    expect(await projectionRowsFor(MEMBER)).toBe(1);
    expect(await readFlags()).toHaveLength(0);
    const rows = await readAuditEvents(projectId);
    // One row per entry (no applied rows)
    const chainSeqs = rows
      .map((row) => row["chain_seq"])
      .filter((seq): seq is number => typeof seq === "number");
    expect(new Set(chainSeqs).size).toBe(chainSeqs.length);
    expect(rows.filter((row) => row["event"] === "chain.member_removed")).toHaveLength(0);
  });
});
