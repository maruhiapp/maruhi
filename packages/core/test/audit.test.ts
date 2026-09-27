// The chain-mirror mapping (AUDIT_SPEC §3.4) — the proposal index's
// completion derivation and the four-eyes rows (K5).
//
// The rule being pinned: `indexProposals`' completion judgement "a
// proposal that is neither pending nor withdrawn in the final state was
// completed by the last approve naming it" depends on crypto's
// verifier removing an element from the pending set in exactly two
// places — reaching quorum and withdraw — so **an expired proposal
// stays pending**. Here, each branch of the derivation (still pending /
// withdrawn / completed / one pre-completion vote) is pinned directly
// with a minimal, signature-less entry list (independent review
// should-fix 3).

import type { ChainEntry, ChainOperation, ProposableOperation } from "@maruhi/crypto";
import { describe, expect, it } from "vitest";

import { chainMirrorEvents, indexProposals } from "../src/audit.ts";

const PROPOSER = { userId: "user-owner-0001", keyFingerprintHex: "aa".repeat(16) };
const APPROVER = { userId: "user-owner-0014", keyFingerprintHex: "bb".repeat(16) };
const INNER: ProposableOperation = {
  op: "remove_member",
  payload: { targetUserId: "user-member-0002" },
};

/** Dummy hash of a seq (deterministic — used as the index's reference target). */
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

describe("indexProposals (completion-judgement derivation)", () => {
  it("keeps a proposal with one vote uncompleted while it is still pending (expired or not)", () => {
    const entries = [propose(1), approve(2, 1)];
    // Stays pending even when expired (the verifier does not remove it from pending on expiry)
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

describe("chainMirrorEvents (four-eyes rows — AUDIT_SPEC §3.4)", () => {
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
    // The applied row: actor = the proposer; chain_seq / client_ts = the approve's; viaProposalSeq
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
