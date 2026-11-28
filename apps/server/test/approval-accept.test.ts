import type { ApprovalTargetOp, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { importSigningKeyPair, signHeadAttestation } from "@maruhi/crypto";
import { testUserId, vectorKeys } from "@maruhi/crypto/test-support";
import { addMemberOp, hexBytes, signEntryAt, testProjectId } from "@maruhi/test-kit";
import { env } from "cloudflare:test";
import { describe, expect, it } from "vite-plus/test";

import { MAX_PENDING_PROPOSALS, MAX_PROPOSAL_LIFETIME_MS } from "../src/policy.ts";
import { identityOf, vectorKeyOf } from "./support/data-crypto.ts";
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

async function appendRaw(
  actorUserId: string,
  operation: ChainOperation,
): Promise<{ readonly response: Response; readonly hash: string }> {
  const { entry, hash } = await signEntryAt({
    seq: fixture.head.seq + 1,
    prevHashHex: fixture.head.hashHex,
    actor: identityOf(actorUserId),
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

async function enableFourEyes(ops: readonly ApprovalTargetOp[]): Promise<void> {
  await seedMemberToken(fixture, OWNER2, 9014);
  await appendOperation(fixture, OWNER, addMemberOp(identityOf(OWNER2), "owner"));
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
  payload: { targetUserId: testUserId(targetUserId) },
});

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

function rowAt(rows: readonly AuditRow[], chainSeq: number, nth = 0): AuditRow {
  const row = rows.filter((candidate) => candidate["chain_seq"] === chainSeq)[nth];
  if (row === undefined) throw new Error(`no audit row #${nth} for chain_seq=${chainSeq}`);
  return row;
}

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
  const recommended = rows.find((row) => row["event"] === "rotation.recommended");
  if (recommended === undefined) throw new Error("no rotation.recommended row");
  expect(Number(recommended["seq"])).toBeGreaterThan(Number(appliedRow["seq"]));
  expect(payloadOf(recommended)).toMatchObject({ trigger: "remove_member" });
}

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
      projectId: testProjectId(projectId),
      attesterUserId: testUserId(attesterUserId),
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
    expect(fixture.head).toEqual(head);
    const rows = await readAuditEvents(projectId);
    expect(rows.filter((row) => row["event"] === "chain.proposed")).toHaveLength(0);
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
    const { response: withdrawExpired } = await appendRaw(OWNER, withdrawOp(expired));
    expect(withdrawExpired.status).toBe(200);
    const { response: stillFull } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(stillFull.status).toBe(422);
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
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
    expect(pull.status).toBe(200);
    await submitAttestation(MEMBER);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

    await enableFourEyes(["remove_member"]);
    const direct = await appendRaw(OWNER, removeMemberOp(MEMBER));
    expect(direct.response.status).toBe(422);
    await expect(direct.response.json()).resolves.toMatchObject({ reason: "approval-required" });

    const proposalHash = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const proposalSeq = fixture.head.seq;
    expect(await readFlags()).toHaveLength(0);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

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
    expect((await inviteRow(matched.id))?.status).toBe("accepted");
    expect(await projectionRowsFor(STRANGER)).toBe(0);

    const { response } = await appendRaw(OWNER2, approveOp(proposalHash));
    expect(response.status).toBe(200);
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    expect(await projectionRowsFor(STRANGER)).toBe(1);
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
    await appendOperation(fixture, OWNER, removeMemberOp(MEMBER));
    const wrapsBefore = await queryProjectDo(
      projectId,
      "SELECT COUNT(*) AS n FROM dek_wraps WHERE recipient_user_id = ?",
      MEMBER,
    );
    expect(Number(wrapsBefore[0]?.["n"])).toBe(1);

    await enableFourEyes(["add_member"]);
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
    const chainSeqs = rows
      .map((row) => row["chain_seq"])
      .filter((seq): seq is number => typeof seq === "number");
    expect(new Set(chainSeqs).size).toBe(chainSeqs.length);
    expect(rows.filter((row) => row["event"] === "chain.member_removed")).toHaveLength(0);
  });
});
