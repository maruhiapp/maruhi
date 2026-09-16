// チェーンミラーの写像(AUDIT_SPEC §3.4)— 提案索引の完成導出と四眼の行(K5)。
//
// 固定する規則: `indexProposals` の完成判定「最終状態で pending でなく withdraw も
// されていない提案は、それを名指しした最後の approve が完成させた」は、crypto の
// 検証器が pending 集合から要素を消すのが定足数到達と withdraw の 2 箇所だけで、
// **期限切れの提案は pending に残る**ことに依存する。ここでは導出側の各分岐
// (pending のまま / withdraw / 完成 / 完成前の 1 票)を、署名を持たない最小の
// エントリ列で直接固定する(独立レビュー should-fix 3)。

import type { ChainEntry, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { chainMirrorEvents, indexProposals } from "../src/audit.ts";

const PROPOSER = { userId: "user-owner-0001", keyFingerprintHex: "aa".repeat(16) };
const APPROVER = { userId: "user-owner-0014", keyFingerprintHex: "bb".repeat(16) };
const INNER: ProposableOperation = {
  op: "remove_member",
  payload: { targetUserId: "user-member-0002" },
};

/** seq のダミーハッシュ(決定的 — 索引の参照先に使う)。 */
const hashOf = (seq: number): string => seq.toString(16).padStart(64, "0");

function entry(seq: number, actor: typeof PROPOSER, operation: ChainOperation): ChainEntry {
  return {
    ...operation,
    suite: "maruhi/v1",
    seq,
    prevHashHex: hashOf(seq - 1),
    actor,
    timestampMs: 1_000 + seq,
    signatureHex: "00".repeat(64),
  };
}

const propose = (seq: number): ChainEntry =>
  entry(seq, PROPOSER, { op: "propose", payload: { inner: INNER, expiresAtMs: 5_000 } });
const approve = (seq: number, proposalSeq: number): ChainEntry =>
  entry(seq, APPROVER, { op: "approve", payload: { proposalHashHex: hashOf(proposalSeq) } });
const withdraw = (seq: number, proposalSeq: number): ChainEntry =>
  entry(seq, PROPOSER, { op: "withdraw", payload: { proposalHashHex: hashOf(proposalSeq) } });

const index = (entries: readonly ChainEntry[], pendingSeqs: readonly number[]) =>
  indexProposals(entries, hashOf, new Set(pendingSeqs.map(hashOf)));

describe("indexProposals(完成判定の導出)", () => {
  it("keeps a proposal with one vote uncompleted while it is still pending (expired or not)", () => {
    const entries = [propose(1), approve(2, 1)];
    // 期限切れでも pending に残る(検証器は期限切れで pending から消さない)
    const proposal = index(entries, [1]).get(hashOf(1));
    expect(proposal?.entry.seq).toBe(1);
    expect(proposal?.completedAtSeq).toBeNull();
  });

  it("never marks a withdrawn proposal completed, even after an approve", () => {
    const entries = [propose(1), approve(2, 1), withdraw(3, 1)];
    expect(index(entries, []).get(hashOf(1))?.completedAtSeq).toBeNull();
  });

  it("marks the last approve naming a proposal absent from the pending set as the completing entry", () => {
    const entries = [propose(1), approve(2, 1), approve(3, 1)];
    expect(index(entries, []).get(hashOf(1))?.completedAtSeq).toBe(3);
  });

  it("indexes proposals independently (one completed, one pending)", () => {
    const entries = [propose(1), propose(2), approve(3, 2), approve(4, 1)];
    const built = index(entries, [2]);
    expect(built.get(hashOf(1))?.completedAtSeq).toBe(4);
    expect(built.get(hashOf(2))?.completedAtSeq).toBeNull();
  });
});

describe("chainMirrorEvents(四眼の行 — AUDIT_SPEC §3.4)", () => {
  it("writes proposalChainSeq / completed and the applied inner-op row for the completing approve only", () => {
    const entries = [propose(1), approve(2, 1), approve(3, 1)];
    const built = index(entries, []);
    const first = chainMirrorEvents(approve(2, 1), 9_000, built);
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({
      event: "chain.approved",
      chainSeq: 2,
      actorUserId: APPROVER.userId,
      payload: { proposalChainSeq: 1, completed: false },
    });
    const completing = chainMirrorEvents(approve(3, 1), 9_000, built);
    expect(completing.map((row) => row.event)).toEqual(["chain.approved", "chain.member_removed"]);
    expect(completing[0]?.payload).toEqual({ proposalChainSeq: 1, completed: true });
    // 適用行: actor = 提案者、chain_seq / client_ts = approve のもの、viaProposalSeq
    expect(completing[1]).toEqual({
      event: "chain.member_removed",
      serverTs: 9_000,
      clientTs: 1_003,
      chainSeq: 3,
      actorType: "user",
      actorUserId: PROPOSER.userId,
      actorKeyFingerprintHex: PROPOSER.keyFingerprintHex,
      targetUserId: "user-member-0002",
      payload: { viaProposalSeq: 1 },
    });
    const withdrawn = chainMirrorEvents(withdraw(4, 1), 9_000, built);
    expect(withdrawn).toHaveLength(1);
    expect(withdrawn[0]?.payload).toEqual({ proposalChainSeq: 1 });
  });

  it("does not copy the inner payload into the propose row", () => {
    const rows = chainMirrorEvents(propose(1), 9_000, index([propose(1)], [1]));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.payload).toEqual({ innerOp: "remove_member", expiresAtMs: 5_000 });
  });
});
