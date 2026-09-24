// chain-view(S5 の表示用畳み込み — 検証ではない)のユニットテスト。
// 入力は api-schema のワイヤ型に適合するフィクスチャ(型は tsc が拘束する)。
import { describe, expect, it } from "vitest";

import { deriveReportedView, reportedDeviceCount } from "../../src/dashboard/chain-view.ts";
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
      unreadableEntries: 0,
    });
  });

  it("folds genesis into an owner member whose first device is the genesis key (cap owner/all, FP = actor)", () => {
    const view = deriveReportedView([genesis]);
    expect(view.members).toEqual([
      {
        userId: "user_owner",
        role: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
        sinceSeq: genesis.seq,
        devices: [
          {
            keyFingerprintHex: FP,
            encPubHex: HEX64,
            sigPubHex: HEX64,
            roleCap: "owner",
            scopeKind: "all",
            scopeEnvironmentIds: [],
            addedSeq: genesis.seq,
          },
        ],
        unresolvedRevocations: 0,
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

  it("summarizes a proposed op whose inner payload is not a record as its op name instead of throwing", () => {
    const proposal = {
      ...signedBy("user_owner", FP),
      op: "propose",
      payload: {
        inner: { op: "remove_member", payload: null },
        expiresAtMs: 4_000_000_000_000,
      },
    } as unknown as ChainEntry;
    const view = deriveReportedView(
      [genesis, addMember("user_a", "owner"), policyEntry(2, ["remove_member"]), proposal],
      HASH_P,
    );
    expect(view.proposals.map((p) => p.innerSummary)).toEqual(["remove_member"]);
    expect(view.unreadableEntries).toBe(0);
  });

  it("counts an approved op whose inner payload is not a record as unreadable instead of throwing", () => {
    const proposal = {
      ...signedBy("user_owner", FP),
      op: "propose",
      payload: {
        inner: { op: "remove_member", payload: null },
        expiresAtMs: 4_000_000_000_000,
      },
    } as unknown as ChainEntry;
    const approval = approve("user_a", FP_A, HASH_P);
    const entries = linked(
      [
        genesis,
        addMember("user_a", "owner"),
        addMember("user_m", "member"),
        policyEntry(2, ["remove_member"]),
        proposal,
        approval,
      ],
      4,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    expect(view.proposals).toEqual([]);
    expect(view.members.map((m) => m.userId)).toEqual(["user_owner", "user_a", "user_m"]);
    expect(view.unreadableEntries).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 端末鍵(DK K5 — 設計録 dk-design.md §10 K5-1 / K5-2 / K5-4): 端末は公開鍵対で同定し、
// FP は申告のバイト列から機械的に束縛できる範囲だけ結ぶ(hash は計算しない)。失効は
// 束縛済みなら一致で、未束縛なら算術で外し、端末数は常に正確に保つ
// ---------------------------------------------------------------------------

const FP_D2 = "d2".repeat(16);
const FP_D3 = "d3".repeat(16);
const FP_R = "0e".repeat(16);
const KEYS_D2 = { encPubHex: "a2".repeat(32), sigPubHex: "b2".repeat(32) };
const KEYS_D3 = { encPubHex: "a3".repeat(32), sigPubHex: "b3".repeat(32) };
const KEYS_R = { encPubHex: "ae".repeat(32), sigPubHex: "be".repeat(32) };

function addDevice(
  userId: string,
  signerFp: string,
  keys: { encPubHex: string; sigPubHex: string },
  cap: {
    roleCap: "owner" | "admin" | "member" | "reader";
    scopeKind: "all" | "listed";
    scopeEnvironmentIds: string[];
  } = { roleCap: "owner", scopeKind: "all", scopeEnvironmentIds: [] },
): ChainEntry {
  return { ...signedBy(userId, signerFp), op: "add_device", payload: { ...keys, ...cap } };
}

function revokeDevice(
  userId: string,
  signerFp: string,
  target: string,
  fps: ReadonlyArray<string>,
): ChainEntry {
  return {
    ...signedBy(userId, signerFp),
    op: "revoke_device",
    payload: { targetUserId: target, deviceFingerprintsHex: [...fps] },
  };
}

function devicesOf(view: ReturnType<typeof deriveReportedView>, userId: string) {
  return view.members.find((m) => m.userId === userId);
}

describe("deriveReportedView — device keys (DK K5)", () => {
  it("adds a device with its reported cap and no fingerprint (the wire carries public keys only)", () => {
    const view = deriveReportedView([
      genesis,
      addDevice("user_owner", FP, KEYS_D2, {
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: ["dev"],
      }),
    ]);
    const owner = devicesOf(view, "user_owner");
    expect(reportedDeviceCount(owner!)).toBe(2);
    expect(owner?.devices.map((d) => [d.keyFingerprintHex, d.roleCap, d.scopeKind])).toEqual([
      [FP, "owner", "all"],
      [null, "member", "listed"],
    ]);
    expect(owner?.devices[1]?.scopeEnvironmentIds).toEqual(["dev"]);
  });

  it("binds a fingerprint when the member signs and exactly one device is unbound", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    // D2 が署名(R を足す)→ 未束縛は D2 だけ → 束縛。R は未束縛のまま
    const addR = addDevice("user_owner", FP_D2, KEYS_R);
    const view = deriveReportedView([genesis, addD2, addR]);
    expect(devicesOf(view, "user_owner")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      FP,
      FP_D2,
      null,
    ]);
  });

  it("revokes a bound device by fingerprint and keeps the count exact", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const addR = addDevice("user_owner", FP_D2, KEYS_R);
    const revokeD2 = revokeDevice("user_owner", FP, "user_owner", [FP_D2]);
    const view = deriveReportedView([genesis, addD2, addR, revokeD2]);
    const owner = devicesOf(view, "user_owner");
    expect(owner?.devices.map((d) => d.keyFingerprintHex)).toEqual([FP, null]);
    expect(owner?.unresolvedRevocations).toBe(0);
    expect(reportedDeviceCount(owner!)).toBe(2);
  });

  it("revokes fingerprint-less devices by arithmetic: all of them when the counts match, otherwise counts the revocation as unresolved", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const addR = addDevice("user_owner", FP, KEYS_R);
    // 未束縛 2(D2・R)に対し 1 つの FP → どれかは不明。端末数 2 は正確
    const one = deriveReportedView([
      genesis,
      addD2,
      addR,
      revokeDevice("user_owner", FP, "user_owner", [FP_R]),
    ]);
    const partial = devicesOf(one, "user_owner");
    expect(partial?.devices).toHaveLength(3);
    expect(partial?.unresolvedRevocations).toBe(1);
    expect(reportedDeviceCount(partial!)).toBe(2);
    // 残りの 1 つも失効 → 未束縛の残り 1 = 一致しない FP 1 → 未束縛を全部外す
    const both = deriveReportedView([
      genesis,
      addD2,
      addR,
      revokeDevice("user_owner", FP, "user_owner", [FP_R]),
      revokeDevice("user_owner", FP, "user_owner", [FP_D2]),
    ]);
    const resolved = devicesOf(both, "user_owner");
    expect(resolved?.devices.map((d) => d.keyFingerprintHex)).toEqual([FP]);
    expect(resolved?.unresolvedRevocations).toBe(0);
    expect(reportedDeviceCount(resolved!)).toBe(1);
  });

  it("ignores a revoke_device the reported bytes cannot read (unknown target, too many fingerprints, duplicates, last device)", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const prefix = [genesis, addD2];
    const count = (entries: ChainEntry[]) =>
      reportedDeviceCount(devicesOf(deriveReportedView(entries), "user_owner")!);
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_ghost", [FP_D2])])).toBe(2);
    // 一致しない FP 2 に対し未束縛は 1 → 読めない
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP_D2, FP_D3])])).toBe(
      2,
    );
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP_D2, FP_D2])])).toBe(
      2,
    );
    // 失効後 0 台(last-device-protected)
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP, FP_D2])])).toBe(2);
    expect(count([genesis, revokeDevice("user_owner", FP, "user_owner", [FP])])).toBe(1);
    // 壊れた payload
    const broken = {
      ...signedBy("user_owner", FP),
      op: "revoke_device",
      payload: { targetUserId: "user_owner", deviceFingerprintsHex: "not-a-list" },
    } as unknown as ChainEntry;
    expect(count([...prefix, broken])).toBe(2);
  });

  it("ignores an add_device from a non-member or with a key already held by a current member's device", () => {
    const view = deriveReportedView([
      genesis,
      addDevice("user_ghost", FP_D2, KEYS_D2),
      // genesis の鍵(HEX64 / HEX64)と同じ公開鍵 → duplicate-member-key
      addDevice("user_owner", FP, { encPubHex: HEX64, sigPubHex: "b9".repeat(32) }),
    ]);
    expect(view.members).toHaveLength(1);
    expect(reportedDeviceCount(view.members[0]!)).toBe(1);
  });

  it("re-adds a revoked key as a new device and carries its learned fingerprint over (same key ⇒ same FP)", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const signD2 = addDevice("user_owner", FP_D2, KEYS_R);
    const revokeD2 = revokeDevice("user_owner", FP, "user_owner", [FP_D2]);
    const readdD2 = addDevice("user_owner", FP, KEYS_D2, {
      roleCap: "reader",
      scopeKind: "listed",
      scopeEnvironmentIds: [],
    });
    const view = deriveReportedView([genesis, addD2, signD2, revokeD2, readdD2]);
    const owner = devicesOf(view, "user_owner");
    expect(owner?.devices.map((d) => [d.keyFingerprintHex, d.roleCap, d.addedSeq])).toEqual([
      [FP, "owner", genesis.seq],
      [null, "owner", signD2.seq],
      [FP_D2, "reader", readdD2.seq],
    ]);
  });

  it("re-adds a key after an unresolved revocation by resolving the stale row (the accepted add_device proves that key was inactive — K5-12)", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const addR = addDevice("user_owner", FP, KEYS_R);
    // 未束縛 2 のうち 1 つ(D2)を失効 → どれかは不明(unresolved 1)
    const revokeD2 = revokeDevice("user_owner", FP, "user_owner", [FP_D2]);
    // 同じ鍵を再登録 → 受理された以上 D2 の行は失効済みと確定 → 残骸を外して足す
    const readdD2 = addDevice("user_owner", FP, KEYS_D2, {
      roleCap: "member",
      scopeKind: "all",
      scopeEnvironmentIds: [],
    });
    const view = deriveReportedView([genesis, addD2, addR, revokeD2, readdD2]);
    const owner = devicesOf(view, "user_owner");
    expect(owner?.unresolvedRevocations).toBe(0);
    expect(reportedDeviceCount(owner!)).toBe(3);
    expect(owner?.devices.map((d) => [d.encPubHex, d.roleCap, d.addedSeq])).toEqual([
      [HEX64, "owner", genesis.seq],
      [KEYS_R.encPubHex, "owner", addR.seq],
      [KEYS_D2.encPubHex, "member", readdD2.seq],
    ]);
    // 残骸が無い(unresolved 0)なら同じ鍵の再追加は重複 = 無視のまま
    const dup = deriveReportedView([genesis, addD2, addR, readdD2]);
    expect(reportedDeviceCount(devicesOf(dup, "user_owner")!)).toBe(3);
    expect(devicesOf(dup, "user_owner")?.devices[1]?.roleCap).toBe("owner");
  });

  it("never binds a revoked device's fingerprint to another device, and keeps the arithmetic sound under a duplicate-FP report (K5-13)", () => {
    // user_a の最初の鍵は他メンバーと重複しない鍵にする(実チェーンの不変条件 — 重複鍵は受理されない)
    const KEYS_A1 = { encPubHex: "a1".repeat(32), sigPubHex: "b1".repeat(32) };
    const owner: ChainEntry = {
      ...base(),
      op: "add_member",
      payload: {
        targetUserId: "user_a",
        ...KEYS_A1,
        role: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    };
    const addD2 = addDevice("user_a", FP_A, KEYS_D2); // D1 (FP_A bound) + D2 (unbound)
    const revokeD1 = revokeDevice("user_a", FP_A, "user_a", [FP_A]);
    // 失効した D1 の FP で署名した行が申告される(stale actor)→ D2 へ束縛しない
    const stale = addDevice("user_a", FP_A, KEYS_D3);
    const afterStale = deriveReportedView([genesis, owner, addD2, revokeD1, stale]);
    expect(devicesOf(afterStale, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
    ]);
    // D1 の鍵を再追加 → 学習済み FP_A を復元(1 行だけが FP_A を持つ)
    const readdD1 = addDevice("user_a", FP_A, KEYS_A1);
    const readd = deriveReportedView([genesis, owner, addD2, revokeD1, stale, readdD1]);
    expect(devicesOf(readd, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
      FP_A,
    ]);
    // FP_A の失効は 1 行だけ外す(端末数 2)— 2 行が同じ FP を持つ形は作られない
    const again = deriveReportedView([
      genesis,
      owner,
      addD2,
      revokeD1,
      stale,
      readdD1,
      revokeDevice("user_a", FP_A, "user_a", [FP_A]),
    ]);
    expect(reportedDeviceCount(devicesOf(again, "user_a")!)).toBe(2);
    // 失効した端末の FP で入れた票は数えない(§6.2 — 失効した端末の票は失効)
    const proposal = proposeRemove("user_owner", FP, "user_m");
    const vote = approve("user_a", FP_A, HASH_P);
    const entries = linked(
      [
        genesis,
        owner,
        addMember("user_m", "member"),
        policyEntry(2, ["remove_member"]),
        addD2,
        revokeD1,
        proposal,
        vote,
      ],
      6,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    expect(view.proposals[0]?.voterUserIds).toEqual(["user_owner"]);
  });

  it("never lets one member hold the same fingerprint twice across a re-tenure (K5-15)", () => {
    const KEYS_B1 = { encPubHex: "c1".repeat(32), sigPubHex: "d1".repeat(32) };
    const KEYS_B2 = { encPubHex: "c2".repeat(32), sigPubHex: "d2".repeat(32) };
    const FP_X = "ee".repeat(16);
    const memberWith = (keys: { encPubHex: string; sigPubHex: string }): ChainEntry => ({
      ...base(),
      op: "add_member",
      payload: {
        targetUserId: "user_b",
        ...keys,
        role: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      },
    });
    // 在籍 1: K1 に FP_X が束縛される(署名)→ 除名 → 在籍 2: 別の鍵 K2、同じ FP_X で署名 → FP_X は
    // K1 のものなので K2 には結ばれない(表の set-once — K5-16)→ K1 を add_device: FP_X を復元
    const entries = [
      genesis,
      memberWith(KEYS_B1),
      addDevice("user_b", FP_X, KEYS_D3),
      {
        ...signedBy("user_owner", FP),
        op: "remove_member",
        payload: { targetUserId: "user_b" },
      } as ChainEntry,
      memberWith(KEYS_B2),
      addDevice("user_b", FP_X, KEYS_R),
      addDevice("user_b", FP_X, KEYS_B1),
    ];
    const view = deriveReportedView(entries);
    const b = devicesOf(view, "user_b");
    expect(b?.devices.map((d) => d.keyFingerprintHex)).toEqual([null, null, FP_X]);
    // FP_X の失効はちょうど 1 行を外す
    const revoked = deriveReportedView([
      ...entries,
      revokeDevice("user_b", FP_X, "user_b", [FP_X]),
    ]);
    expect(reportedDeviceCount(devicesOf(revoked, "user_b")!)).toBe(2);
    expect(devicesOf(revoked, "user_b")?.devices.every((d) => d.keyFingerprintHex === null)).toBe(
      true,
    );
  });

  it("never binds another member's fingerprint, and ignores a revoke that names a fingerprint owned elsewhere (K5-16)", () => {
    // owner の FP で user_a が署名した行(他人の FP の流用)→ user_a の未束縛端末には結ばれない
    const add = addMember("user_a", "member");
    const stolen = addDevice("user_a", FP, KEYS_D2);
    const view = deriveReportedView([genesis, add, stolen]);
    expect(devicesOf(view, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
    ]);
    expect(devicesOf(view, "user_owner")?.devices.map((d) => d.keyFingerprintHex)).toEqual([FP]);
    // user_a の失効に owner の FP を並べた行 → 未束縛端末を算術で削らず、行ごと無視
    const bogus = revokeDevice("user_owner", FP, "user_a", [FP]);
    expect(
      reportedDeviceCount(devicesOf(deriveReportedView([genesis, add, stolen, bogus]), "user_a")!),
    ).toBe(2);
    // 既に失効した端末の FP をもう一度失効させる行 → 同じく無視(未束縛端末を巻き込まない)
    const owner2 = addDevice("user_owner", FP, KEYS_D3);
    const revokeFirst = revokeDevice("user_owner", FP, "user_owner", [FP]);
    const twice = revokeDevice("user_owner", FP, "user_owner", [FP]);
    const again = deriveReportedView([
      genesis,
      addDevice("user_owner", FP, KEYS_R),
      owner2,
      revokeFirst,
      twice,
    ]);
    expect(reportedDeviceCount(devicesOf(again, "user_owner")!)).toBe(2);
  });

  it("counts the device entries it could not read instead of absorbing them silently (K5-17)", () => {
    const addD2 = addDevice("user_owner", FP, KEYS_D2);
    const readable = deriveReportedView([
      genesis,
      addD2,
      revokeDevice("user_owner", FP, "user_owner", [FP]),
    ]);
    expect(readable.unreadableEntries).toBe(0);
    const view = deriveReportedView([
      genesis,
      addD2,
      addDevice("user_ghost", FP_D2, KEYS_D3), // 非メンバー
      addDevice("user_owner", FP, KEYS_D2), // 重複鍵
      revokeDevice("user_owner", FP, "user_ghost", [FP]), // 対象不明
      revokeDevice("user_owner", FP, "user_owner", [FP, FP_D2]), // 失効後 0 台
    ]);
    expect(view.unreadableEntries).toBe(4);
    expect(reportedDeviceCount(devicesOf(view, "user_owner")!)).toBe(2);
  });

  it("drops malformed envelopes and payloads instead of throwing (敵対サーバー対策)", () => {
    const malformed = [
      null,
      "entry",
      { ...base(), op: "add_member", actor: null }, // actor 欠落
      { ...base(), op: "add_member", payload: null }, // payload 欠落
      {
        ...base(),
        op: "add_member",
        payload: { targetUserId: 42, role: "member", encPubHex: HEX64, sigPubHex: HEX64 },
      }, // id が文字列でない
    ];
    const view = deriveReportedView([genesis, ...(malformed as unknown[] as ChainEntry[])]);
    expect(view.unreadableEntries).toBe(5);
    expect(view.members.map((m) => m.userId)).toEqual(["user_owner"]);
  });

  it("folds an unreadable member/server scope as not-reported instead of crashing the render", () => {
    const badScope = {
      ...base(),
      op: "add_member",
      payload: {
        targetUserId: "user_b",
        role: "member",
        encPubHex: "ab".repeat(32),
        sigPubHex: "cd".repeat(64),
        scopeKind: "listed",
        scopeEnvironmentIds: "env-1", // 配列でない
      },
    } as unknown as ChainEntry;
    const badServerScope = {
      ...base(),
      op: "grant_server",
      payload: { serverKeyFingerprintHex: FP, scopeEnvironmentIds: { length: 3 } },
    } as unknown as ChainEntry;
    const view = deriveReportedView([genesis, badScope, badServerScope]);
    expect(view.unreadableEntries).toBe(0);
    expect(devicesOf(view, "user_b")!.scopeEnvironmentIds).toEqual([]);
    expect(view.servers[0]!.scopeEnvironmentIds).toEqual([]);
  });

  it("treats the first key of an add_member'd member as one device, bound once that member signs", () => {
    const add = addMember("user_a", "member");
    const before = deriveReportedView([genesis, add]);
    expect(devicesOf(before, "user_a")?.devices).toEqual([
      {
        keyFingerprintHex: null,
        encPubHex: HEX64,
        sigPubHex: HEX64,
        roleCap: "owner",
        scopeKind: "all",
        scopeEnvironmentIds: [],
        addedSeq: add.seq,
      },
    ]);
    const after = deriveReportedView([genesis, add, addDevice("user_a", FP_A, KEYS_D3)]);
    expect(devicesOf(after, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      FP_A,
      null,
    ]);
    expect(reportedDeviceCount(devicesOf(after, "user_a")!)).toBe(2);
  });

  it("removes every device with remove_member and starts the re-added member from one device", () => {
    const add = addMember("user_a", "member");
    const view = deriveReportedView([
      genesis,
      add,
      addDevice("user_a", FP_A, KEYS_D3),
      { ...signedBy("user_owner", FP), op: "remove_member", payload: { targetUserId: "user_a" } },
      addMember("user_a", "reader"),
    ]);
    expect(reportedDeviceCount(devicesOf(view, "user_a")!)).toBe(1);
    expect(devicesOf(view, "user_a")?.role).toBe("reader");
  });

  it("does not apply add_device / revoke_device carried inside a proposal (not proposable — §6.2)", () => {
    const proposal: ChainEntry = {
      ...signedBy("user_owner", FP),
      op: "propose",
      payload: {
        inner: {
          op: "add_device",
          payload: { ...KEYS_D2, roleCap: "owner", scopeKind: "all", scopeEnvironmentIds: [] },
        },
        expiresAtMs: 4_000_000_000_000,
      },
    };
    const entries = linked(
      [
        genesis,
        addMember("user_a", "owner"),
        policyEntry(1, ["remove_member"]),
        proposal,
        approve("user_a", FP_A, HASH_P),
      ],
      3,
      HASH_P,
    );
    const view = deriveReportedView(entries, "99".repeat(32));
    expect(view.proposals).toEqual([]);
    expect(reportedDeviceCount(devicesOf(view, "user_owner")!)).toBe(1);
  });

  describe("four-eyes votes are counted per device (K5-2)", () => {
    const setup = () => [
      genesis,
      addMember("user_a", "owner"),
      addMember("user_m", "member"),
      policyEntry(2, ["remove_member"]),
    ];

    it("keeps a vote cast from one device when the owner later signs from another", () => {
      const proposal = proposeRemove("user_owner", FP, "user_m");
      const addD2 = addDevice("user_a", FP_A, KEYS_D2);
      const voteFromD2 = approve("user_a", FP_D2, HASH_P);
      const signFromD1 = addDevice("user_a", FP_A, KEYS_R);
      const entries = linked([...setup(), addD2, proposal, voteFromD2, signFromD1], 5, HASH_P);
      const view = deriveReportedView(entries, "99".repeat(32));
      // D2 は署名時に唯一の未束縛端末 → 束縛。D1 が後で署名しても D2 の票は残る
      expect(view.proposals).toEqual([]);
      expect(view.members.map((m) => m.userId)).toEqual(["user_owner", "user_a"]);
    });

    it("does not count a vote from a device whose cap is below owner", () => {
      const proposal = proposeRemove("user_owner", FP, "user_m");
      const phone = addDevice("user_a", FP_A, KEYS_D2, {
        roleCap: "member",
        scopeKind: "listed",
        scopeEnvironmentIds: [],
      });
      const vote = approve("user_a", FP_D2, HASH_P);
      const entries = linked([...setup(), phone, proposal, vote], 5, HASH_P);
      const view = deriveReportedView(entries, "99".repeat(32));
      expect(view.proposals[0]?.voterUserIds).toEqual(["user_owner"]);
    });

    it("counts an unbindable vote only when every unbound device of that owner is owner-capped, and drops it after an unresolved revocation", () => {
      const proposal = proposeRemove("user_owner", FP, "user_m");
      const addD2 = addDevice("user_a", FP_A, KEYS_D2);
      const addR = addDevice("user_a", FP_A, KEYS_R);
      // 未束縛 2(どちらも owner/all)から署名 → どの端末でも owner → 数える
      const vote = approve("user_a", FP_D2, HASH_P);
      const counted = deriveReportedView(
        linked([...setup(), addD2, addR, proposal, vote], 6, HASH_P),
        "99".repeat(32),
      );
      expect(counted.proposals).toEqual([]);
      // 片方が member cap なら結論が端末で変わる → 数えない
      const capped = addDevice("user_a", FP_A, KEYS_R, {
        roleCap: "member",
        scopeKind: "all",
        scopeEnvironmentIds: [],
      });
      const notCounted = deriveReportedView(
        linked([...setup(), addD2, capped, proposal, vote], 6, HASH_P),
        "99".repeat(32),
      );
      expect(notCounted.proposals[0]?.voterUserIds).toEqual(["user_owner"]);
      // 数えた後に未束縛の 1 つが失効(どれかは不明)→ 票は失効したかもしれない → 数えない
      const policy3 = policyEntry(3, ["remove_member"]);
      const revoked = deriveReportedView(
        linked(
          [
            genesis,
            addMember("user_a", "owner"),
            addMember("user_m", "member"),
            policy3,
            addD2,
            addR,
            proposal,
            vote,
            revokeDevice("user_a", FP_A, "user_a", [FP_R]),
          ],
          6,
          HASH_P,
        ),
        "99".repeat(32),
      );
      expect(revoked.proposals[0]?.voterUserIds).toEqual(["user_owner"]);
    });
  });
});
