// chain-view(S5 の表示用畳み込み — 検証ではない)のユニットテスト。
// 入力は api-schema のワイヤ型に適合するフィクスチャ(型は tsc が拘束する)。
import { describe, expect, it } from "vitest";

import { deriveReportedView } from "../../src/dashboard/chain-view.ts";
import type { ChainEntry } from "../../src/dashboard/types.ts";

const HEX64 = "12".repeat(32);
const SIG = "34".repeat(64);
const FP = "56".repeat(16);

let seqCounter = 0;

function base(): {
  suite: string;
  seq: number;
  prevHashHex: string;
  actor: { userId: string; keyFingerprintHex: string };
  timestampMs: number;
  signatureHex: string;
} {
  seqCounter += 1;
  return {
    suite: "maruhi/v1",
    seq: seqCounter,
    prevHashHex: HEX64,
    actor: { userId: "user_owner", keyFingerprintHex: FP },
    timestampMs: 1_756_000_000_000 + seqCounter,
    signatureHex: SIG,
  };
}

const genesis: ChainEntry = {
  ...base(),
  op: "genesis",
  payload: { encPubHex: HEX64, sigPubHex: HEX64 },
};

function addMember(userId: string, role: "owner" | "admin" | "member" | "reader"): ChainEntry {
  return {
    ...base(),
    op: "add_member",
    payload: {
      targetUserId: userId,
      encPubHex: HEX64,
      sigPubHex: HEX64,
      role,
      scopeKind: "all",
      scopeEnvironmentIds: [],
    },
  };
}

describe("deriveReportedView", () => {
  it("returns empty sets for an empty entry list", () => {
    expect(deriveReportedView([])).toEqual({
      members: [],
      servers: [],
      policy: null,
      proposals: [],
    });
  });

  it("folds genesis into an owner member", () => {
    const view = deriveReportedView([genesis]);
    expect(view.members).toEqual([
      {
        userId: "user_owner",
        role: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
        sinceSeq: genesis.seq,
      },
    ]);
  });

  it("applies add / change_role / remove in reported order", () => {
    const add = addMember("user_a", "reader");
    const change: ChainEntry = {
      ...base(),
      op: "change_role",
      payload: {
        targetUserId: "user_a",
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const addB = addMember("user_b", "member");
    const removeB: ChainEntry = {
      ...base(),
      op: "remove_member",
      payload: { targetUserId: "user_b" },
    };
    const view = deriveReportedView([genesis, add, change, addB, removeB]);
    expect(view.members.map((m) => [m.userId, m.role])).toEqual([
      ["user_owner", "owner"],
      ["user_a", "admin"],
    ]);
    // role を更新したエントリの seq が sinceSeq に反映される
    expect(view.members[1]?.sinceSeq).toBe(change.seq);
  });

  it("folds the environment scope of add_member / change_role (ES K4 — reported, not verified)", () => {
    const add = addMember("user_a", "member");
    const narrow: ChainEntry = {
      ...base(),
      op: "change_role",
      payload: {
        targetUserId: "user_a",
        newRole: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["dev", "staging"],
      },
    };
    const before = deriveReportedView([genesis, add]);
    expect(before.members[1]).toMatchObject({ scopeKind: "all", scopeEnvironmentIds: [] });
    const after = deriveReportedView([genesis, add, narrow]);
    expect(after.members[1]).toMatchObject({
      role: "member",
      scopeKind: "listed",
      scopeEnvironmentIds: ["dev", "staging"],
      sinceSeq: narrow.seq,
    });
  });

  it("ignores change_role for an unknown member (as reported — no invention)", () => {
    const change: ChainEntry = {
      ...base(),
      op: "change_role",
      payload: {
        targetUserId: "user_ghost",
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    expect(deriveReportedView([genesis, change]).members).toHaveLength(1);
  });

  it("folds grant_server / revoke_server into the server set", () => {
    const grant: ChainEntry = {
      ...base(),
      op: "grant_server",
      payload: {
        serverEncPubHex: HEX64,
        serverKeyFingerprintHex: FP,
        scopeEnvironmentIds: ["production"],
        leasePolicy: [],
      },
    };
    const granted = deriveReportedView([genesis, grant]);
    expect(granted.servers).toEqual([
      { keyFingerprintHex: FP, scopeEnvironmentIds: ["production"], sinceSeq: grant.seq },
    ]);
    const revoke: ChainEntry = {
      ...base(),
      op: "revoke_server",
      payload: { serverKeyFingerprintHex: FP },
    };
    expect(deriveReportedView([genesis, grant, revoke]).servers).toEqual([]);
  });

  it("ignores a hostile op name without touching the prototype chain", () => {
    // 敵対的サーバーが op: "__proto__" 等を名乗ってもプロトタイプ鎖の値を
    // 呼び出して throw しない
    const hostile = { ...base(), op: "__proto__", payload: {} } as unknown as ChainEntry;
    const view = deriveReportedView([genesis, hostile]);
    expect(view.members).toHaveLength(1);
  });

  it("leaves membership untouched for data-plane ops", () => {
    const createEnv: ChainEntry = {
      ...base(),
      op: "create_environment",
      payload: { environmentId: "production", dekCommitmentHex: HEX64 },
    };
    const rotate: ChainEntry = {
      ...base(),
      op: "rotate_epoch",
      payload: {
        environmentId: "production",
        newEpoch: 2,
        reason: "manual",
        dekCommitmentHex: HEX64,
      },
    };
    const view = deriveReportedView([genesis, createEnv, rotate]);
    expect(view.members).toHaveLength(1);
    expect(view.servers).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 四眼(PF1 K6 — 設計録 es-design.md §12 K6-J): 方針と pending 提案の畳み込み。
// hash はエントリ i + 1 の prevHashHex(末尾は headHashHex)から引き、票数は再集計する
// ---------------------------------------------------------------------------

const FP_A = "aa".repeat(16);
const FP_B = "bb".repeat(16);
const FP_B2 = "b2".repeat(16);
const HASH_P = "77".repeat(32);

/** 指定した actor で署名した形のエントリ(as reported — 署名は検証しない)。 */
function signedBy(userId: string, fp: string): ReturnType<typeof base> {
  return { ...base(), actor: { userId, keyFingerprintHex: fp } };
}

function policyEntry(
  requiredApprovals: number,
  ops: ReadonlyArray<"remove_member" | "change_role">,
): ChainEntry {
  return {
    ...signedBy("user_owner", FP),
    op: "set_approval_policy",
    payload: { ops: [...ops], requiredApprovals },
  };
}

function proposeRemove(userId: string, fp: string, target: string): ChainEntry {
  return {
    ...signedBy(userId, fp),
    op: "propose",
    payload: {
      inner: { op: "remove_member", payload: { targetUserId: target } },
      expiresAtMs: 4_000_000_000_000,
    },
  };
}

function approve(userId: string, fp: string, hash: string): ChainEntry {
  return { ...signedBy(userId, fp), op: "approve", payload: { proposalHashHex: hash } };
}

/** 提案の hash を次のエントリの prevHashHex に置く(応答はエントリごとの hash を運ばない)。 */
function linked(entries: ChainEntry[], proposalIndex: number, hash: string): ChainEntry[] {
  return entries.map((entry, index) =>
    index === proposalIndex + 1 ? ({ ...entry, prevHashHex: hash } as ChainEntry) : entry,
  );
}

describe("deriveReportedView — four-eyes policy and pending proposals (K6)", () => {
  it("folds set_approval_policy (required 0 = off)", () => {
    expect(deriveReportedView([genesis]).policy).toBeNull();
    expect(deriveReportedView([genesis, policyEntry(2, ["remove_member"])]).policy).toEqual({
      requiredApprovals: 2,
      ops: ["remove_member"],
    });
    expect(
      deriveReportedView([genesis, policyEntry(2, ["remove_member"]), policyEntry(0, [])]).policy,
    ).toBeNull();
  });

  it("lists a pending proposal with its hash taken from the next entry's prevHashHex, recounting the proposer's vote", () => {
    const ownerA = addMember("user_a", "owner");
    const member = addMember("user_m", "member");
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const tail: ChainEntry = {
      ...base(),
      op: "create_environment",
      payload: { environmentId: "dev", dekCommitmentHex: HEX64 },
    };
    const entries = linked(
      [genesis, ownerA, member, policyEntry(2, ["remove_member"]), proposal, tail],
      4,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    expect(view.proposals).toEqual([
      {
        proposalHashHex: HASH_P,
        proposalSeq: proposal.seq,
        proposerUserId: "user_owner",
        proposerRoleAtProposal: "owner",
        innerOp: "remove_member",
        innerSummary: "remove user_m",
        expiresAtMs: 4_000_000_000_000,
        votes: 1,
        voterUserIds: ["user_owner"],
      },
    ]);
    // 適用前: 対象はまだメンバー
    expect(view.members.map((m) => m.userId)).toContain("user_m");
  });

  it("uses headHashHex for a proposal that is the last entry", () => {
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const view = deriveReportedView(
      [
        genesis,
        addMember("user_a", "owner"),
        addMember("user_m", "member"),
        policyEntry(2, ["remove_member"]),
        proposal,
      ],
      HASH_P,
    );
    expect(view.proposals.map((p) => p.proposalHashHex)).toEqual([HASH_P]);
  });

  it("applies the inner op at the approve that reaches the quorum and drops it from pending", () => {
    const ownerA = addMember("user_a", "owner");
    const member = addMember("user_m", "member");
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const approval = approve("user_a", FP_A, HASH_P);
    const entries = linked(
      [genesis, ownerA, member, policyEntry(2, ["remove_member"]), proposal, approval],
      4,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    expect(view.proposals).toEqual([]);
    expect(view.members.map((m) => m.userId)).toEqual(["user_owner", "user_a"]);
  });

  it("does not count a voter who was demoted after voting, nor an approver re-added with a new key (fail-closed)", () => {
    const ownerA = addMember("user_a", "owner");
    const ownerB = addMember("user_b", "owner");
    const member = addMember("user_m", "member");
    // admin として提案 → 提案署名は票ではない(§6.2)
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const voteA = approve("user_a", FP_A, HASH_P);
    const demoteA: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "change_role",
      payload: {
        targetUserId: "user_a",
        newRole: "admin",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const entries = linked(
      [
        genesis,
        ownerA,
        ownerB,
        member,
        policyEntry(3, ["remove_member"]),
        proposal,
        voteA,
        demoteA,
      ],
      5,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    // 提案者 1 票のみ(A の票は降格で失効)
    expect(view.proposals[0]?.votes).toBe(1);
    expect(view.proposals[0]?.voterUserIds).toEqual(["user_owner"]);

    // B が投票 → 削除 → 別鍵で再追加(署名なし): B の旧票は数えない
    const voteB = approve("user_b", FP_B, HASH_P);
    const removeB: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "remove_member",
      payload: { targetUserId: "user_b" },
    };
    const readdB: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "add_member",
      payload: {
        targetUserId: "user_b",
        encPubHex: "cd".repeat(32),
        sigPubHex: "ef".repeat(32),
        role: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const again = deriveReportedView(
      linked(
        [
          genesis,
          ownerA,
          ownerB,
          member,
          policyEntry(3, ["remove_member"]),
          proposal,
          voteB,
          removeB,
          readdB,
        ],
        5,
        HASH_P,
      ),
      "99".repeat(32),
    );
    expect(again.proposals[0]?.voterUserIds).toEqual(["user_owner"]);
    // 新鍵で署名した後は、その鍵の票が数えられる
    const voteB2 = approve("user_b", FP_B2, HASH_P);
    const signed = deriveReportedView(
      linked(
        [
          genesis,
          ownerA,
          ownerB,
          member,
          policyEntry(3, ["remove_member"]),
          proposal,
          voteB,
          removeB,
          readdB,
          voteB2,
        ],
        5,
        HASH_P,
      ),
      "99".repeat(32),
    );
    expect(signed.proposals[0]?.voterUserIds.toSorted()).toEqual(["user_b", "user_owner"]);
  });

  it("keeps the vote of an owner re-added with the same key (same key ⇒ same fingerprint)", () => {
    const ownerA = addMember("user_a", "owner");
    const member = addMember("user_m", "member");
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const voteA = approve("user_a", FP_A, HASH_P);
    const removeA: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "remove_member",
      payload: { targetUserId: "user_a" },
    };
    const readdA = addMember("user_a", "owner");
    const view = deriveReportedView(
      linked(
        [
          genesis,
          ownerA,
          member,
          policyEntry(3, ["remove_member"]),
          proposal,
          voteA,
          removeA,
          readdA,
        ],
        4,
        HASH_P,
      ),
      "99".repeat(32),
    );
    expect(view.proposals[0]?.voterUserIds.toSorted()).toEqual(["user_a", "user_owner"]);
  });

  it("drops a withdrawn proposal", () => {
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const withdraw: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "withdraw",
      payload: { proposalHashHex: HASH_P },
    };
    const view = deriveReportedView(
      linked(
        [
          genesis,
          addMember("user_a", "owner"),
          addMember("user_m", "member"),
          policyEntry(2, ["remove_member"]),
          proposal,
          withdraw,
        ],
        4,
        HASH_P,
      ),
      "99".repeat(32),
    );
    expect(view.proposals).toEqual([]);
    expect(view.members.map((m) => m.userId)).toContain("user_m");
  });
});
