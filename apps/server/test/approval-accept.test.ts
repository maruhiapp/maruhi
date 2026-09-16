// ES + PF1 K5 — 四眼の受理面(CRYPTO_SPEC §6.4「スコープと四眼の受理」/ AUTH_SPEC
// §11-1 / §12-8 / §15-2 / AUDIT_SPEC §3.4。設計録 docs/notes/es-design.md §11)。
//
// 固定する規則:
//   - 受理ポリシー(DO — appendProgram): `expires_at_ms` の上界(受理時サーバー時計 +
//     30 日)→ pending 上限 32(期限切れは数えない・withdraw で解放)。型付き 422
//     `ProposalLimit`(reason + limit)。失効済み提案の拒否はしない(K5-C)
//   - 完成した approve の受理副作用は内側 op を直接受理した場合と同一・同一受理
//     タスク: 要ローテーション検出(trigger = 内側 op・triggerChainSeq = approve の
//     seq)、申告行の削除、招待の completed 突合、membership 投影
//   - 未完成の approve / propose / withdraw / set_approval_policy は副作用を持たない

import type { ChainOperation } from "@maruhi/crypto";
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

/** 2 人目の owner(ベクター鍵 user-owner-0014)。四眼の有効化条件 = owner ≥ required。 */
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

/** 署名 + 汎用追記(受理可否を呼び出し側で判定する版)。受理時は fixture のヘッドを進める。 */
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

/** owner 2 名 + 方針(ops, required = 2)を確立する。 */
async function enableFourEyes(ops: readonly string[]): Promise<void> {
  await seedMemberToken(fixture, OWNER2, 9014);
  await appendOperation(fixture, OWNER, addMemberOperation(OWNER2, "owner"));
  await appendOperation(fixture, OWNER, {
    op: "set_approval_policy",
    payload: { ops: [...ops], requiredApprovals: 2 },
  } as ChainOperation);
}

const proposeOp = (inner: ChainOperation, expiresAtMs: number): ChainOperation =>
  ({ op: "propose", payload: { inner, expiresAtMs } }) as ChainOperation;

const removeMemberOp = (targetUserId: string): ChainOperation => ({
  op: "remove_member",
  payload: { targetUserId },
});

/** 提案を受理させ、提案エントリの hash(approve / withdraw の参照先)を返す。 */
async function propose(actorUserId: string, inner: ChainOperation, expiresAtMs: number) {
  const { response, hash } = await appendRaw(actorUserId, proposeOp(inner, expiresAtMs));
  expect(response.status).toBe(200);
  return hash;
}

const approveOp = (proposalHashHex: string): ChainOperation =>
  ({ op: "approve", payload: { proposalHashHex } }) as ChainOperation;

type AuditRow = Record<string, unknown>;

const payloadOf = (row: AuditRow): Record<string, unknown> =>
  JSON.parse(String(row["payload"])) as Record<string, unknown>;

/** chain_seq の nth 行(無ければ失敗)。 */
function rowAt(rows: readonly AuditRow[], chainSeq: number, nth = 0): AuditRow {
  const row = rows.filter((candidate) => candidate["chain_seq"] === chainSeq)[nth];
  if (row === undefined) throw new Error(`no audit row #${nth} for chain_seq=${chainSeq}`);
  return row;
}

/** 完成した approve の副作用のうち、監査行の形(chain.approved + 適用行 + 検出行の順)。 */
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
  // 検出(rotation.recommended)はミラー行 → 適用行の後に書かれる(同一受理タスク)
  const recommended = rows.find((row) => row["event"] === "rotation.recommended");
  if (recommended === undefined) throw new Error("no rotation.recommended row");
  expect(Number(recommended["seq"])).toBeGreaterThan(Number(appliedRow["seq"]));
  expect(payloadOf(recommended)).toMatchObject({ trigger: "remove_member" });
}

/** attester の鍵で §6.6 の申告を署名して提出する(attestation.test.ts と同じ材料)。 */
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

describe("propose の受理ポリシー(AUTH_SPEC §12-8 — 上界 → pending 上限)", () => {
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
    // 受理前の拒否 — ヘッドは動かず、ミラー行も増えない
    expect(fixture.head).toEqual(head);
    const rows = await readAuditEvents(projectId);
    expect(rows.filter((row) => row["event"] === "chain.proposed")).toHaveLength(0);
    // 上界ちょうど(等号)は受理する
    const { response: atBound } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + MAX_PROPOSAL_LIFETIME_MS - DAY_MS),
    );
    expect(atBound.status).toBe(200);
  });

  it("caps live pending proposals at 32 (expired ones do not count; withdraw frees a slot)", async () => {
    await enableFourEyes(["remove_member"]);
    // 作成時点で失効済みの提案(expires_at_ms が過去)は受理され(K5-C)、上限には
    // 数えない — 誰も承認できず枠も占有しない
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
    // 失効済み提案を閉じても枠は空かない(数えていなかった)
    const { response: withdrawExpired } = await appendRaw(OWNER, {
      op: "withdraw",
      payload: { proposalHashHex: expired },
    } as ChainOperation);
    expect(withdrawExpired.status).toBe(200);
    const { response: stillFull } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(stillFull.status).toBe(422);
    // 期限内の提案を 1 つ withdraw すると 1 枠空く(直前の受理は withdraw なので、
    // 期限内の提案の hash はチェーンから引く)
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
    const { response: withdrawLive } = await appendRaw(OWNER, {
      op: "withdraw",
      payload: { proposalHashHex: String(hashes[0]?.["entry_hash_hex"]) },
    } as ChainOperation);
    expect(withdrawLive.status).toBe(200);
    const { response: admitted } = await appendRaw(
      OWNER,
      proposeOp(removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS),
    );
    expect(admitted.status).toBe(200);
  });
});

describe("完成した approve の受理副作用(CRYPTO_SPEC §6.4 / AUDIT_SPEC §3.4 / §4.1)", () => {
  it("applies remove_member at the approve seq: rotation detection, attestation cleanup, projection removal, applied mirror row", async () => {
    const dek = await createEnvironmentOk(fixture, ENV, "App");
    await createVariableOk(dek, VAR, "DATABASE_URL", "postgres://alpha");
    // MEMBER が値を読む(basis = read の根拠)+ ヘッド申告を持つ
    const pull = await requestJson("GET", `/environments/${ENV}/pull`, token(MEMBER));
    expect(pull.status).toBe(200);
    await submitAttestation(MEMBER);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

    await enableFourEyes(["remove_member"]);
    // 直接追記は approval-required(合意規則)で拒否される — 四眼が効いている
    const direct = await appendRaw(OWNER, removeMemberOp(MEMBER));
    expect(direct.response.status).toBe(422);
    await expect(direct.response.json()).resolves.toMatchObject({ reason: "approval-required" });

    const proposalHash = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const proposalSeq = fixture.head.seq;
    // 提案時点では何も起きない(適用前 — 裁定 P7 / P21)
    expect(await readFlags()).toHaveLength(0);
    expect(await attestationRowsFor(MEMBER)).toBe(1);
    expect(await projectionRowsFor(MEMBER)).toBe(1);

    // owner の提案 = 1 票。2 人目の owner の approve で定足数 2 に到達 = 適用
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
    // 削除されたメンバーはもう読めない(§11-2)
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

    const addStranger: ChainOperation = {
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
    // 提案時点では突合も投影もしない
    expect((await inviteRow(matched.id))?.status).toBe("accepted");
    expect(await projectionRowsFor(STRANGER)).toBe(0);

    const { response } = await appendRaw(OWNER2, approveOp(proposalHash));
    expect(response.status).toBe(200);
    expect((await inviteRow(matched.id))?.status).toBe("completed");
    expect(await projectionRowsFor(STRANGER)).toBe(1);
    // 新メンバーはチェーンを読める(適用 = approve の seq で在籍開始)
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

  it("does nothing for a withdrawn proposal and for a set_approval_policy entry", async () => {
    await enableFourEyes(["remove_member"]);
    const proposalHash = await propose(OWNER, removeMemberOp(MEMBER), Date.now() + 7 * DAY_MS);
    const { response } = await appendRaw(OWNER, {
      op: "withdraw",
      payload: { proposalHashHex: proposalHash },
    } as ChainOperation);
    expect(response.status).toBe(200);
    expect(await projectionRowsFor(MEMBER)).toBe(1);
    expect(await readFlags()).toHaveLength(0);
    const rows = await readAuditEvents(projectId);
    // 各エントリ 1 行(適用行なし)
    const chainSeqs = rows
      .map((row) => row["chain_seq"])
      .filter((seq): seq is number => typeof seq === "number");
    expect(new Set(chainSeqs).size).toBe(chainSeqs.length);
    expect(rows.filter((row) => row["event"] === "chain.member_removed")).toHaveLength(0);
  });
});
