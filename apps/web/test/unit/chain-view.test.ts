// Unit test of chain-view (S5's display fold — not verification).
// Inputs are fixtures conforming to api-schema's wire types (the types
// are bound by tsc).
import { describe, expect, it } from "vitest";

import { reportedDeviceCount } from "../../src/dashboard/chain-view-reported.ts";
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
    // The seq of the entry that updated the role is reflected in
    // sinceSeq
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
    // Even when a hostile server claims op: "__proto__" etc., no
    // prototype-chain value is invoked and nothing throws
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
// Four-eyes (PF1 K6 — design record es-design.md §12 K6-J): the fold
// of the policy and pending proposals.
// A proposal's hash is drawn from the next entry's prevHashHex (the
// last one takes headHashHex), and votes are recounted
// ---------------------------------------------------------------------------

const FP_A = "aa".repeat(16);
const FP_B = "bb".repeat(16);
const FP_B2 = "b2".repeat(16);
const HASH_P = "77".repeat(32);

/** An entry in the shape of being signed by the given actor (as reported — the signature is not verified). */
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

/** Places a proposal's hash into the next entry's prevHashHex (the response carries no per-entry hash). */
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
    // Before application: the target is still a member
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
    // Proposed as admin → the proposal signature is not a vote (§6.2)
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
    // Only the proposer's 1 vote (A's vote was revoked by the
    // demotion)
    expect(view.proposals[0]?.votes).toBe(1);
    expect(view.proposals[0]?.voterUserIds).toEqual(["user_owner"]);

    // B votes → removed → re-added with a different key (unsigned):
    // B's old vote is not counted
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
    // After signing with the new key, that key's vote is counted
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
// Device keys (DK K5 — design record dk-design.md §10 K5-1 / K5-2 /
// K5-4): a device is identified by its public-key pair, and an FP is
// bound only as far as the reported bytes let it be bound
// mechanically (no hash is computed). A revocation removes by match
// when bound and by arithmetic when unbound; the device count is kept
// exact at all times
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
    // D2 signs (adds R) → only D2 is unbound → bind. R stays unbound
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
    // One FP against 2 unbound (D2, R) → which one is unknown. The
    // count of 2 is exact
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
    // The other one is revoked too → 1 unbound left = 1 FP that did
    // not match → drop every unbound one
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
    // 2 non-matching FPs against 1 unbound → unreadable
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP_D2, FP_D3])])).toBe(
      2,
    );
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP_D2, FP_D2])])).toBe(
      2,
    );
    // 0 devices after revocation (last-device-protected)
    expect(count([...prefix, revokeDevice("user_owner", FP, "user_owner", [FP, FP_D2])])).toBe(2);
    expect(count([genesis, revokeDevice("user_owner", FP, "user_owner", [FP])])).toBe(1);
    // A broken payload
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
      // The same public keys as genesis's (HEX64 / HEX64) →
      // duplicate-member-key
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
    // Revoke one of the 2 unbound (D2) → which one is unknown
    // (unresolved 1)
    const revokeD2 = revokeDevice("user_owner", FP, "user_owner", [FP_D2]);
    // Re-adding the same key was accepted, so D2's row is confirmed
    // revoked → drop the residue and add
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
    // With no residue (unresolved 0), a same-key re-add is a duplicate
    // = left ignored
    const dup = deriveReportedView([genesis, addD2, addR, readdD2]);
    expect(reportedDeviceCount(devicesOf(dup, "user_owner")!)).toBe(3);
    expect(devicesOf(dup, "user_owner")?.devices[1]?.roleCap).toBe("owner");
  });

  it("never binds a revoked device's fingerprint to another device, and keeps the arithmetic sound under a duplicate-FP report (K5-13)", () => {
    // user_a's first key is chosen not to collide with another
    // member's (a real-chain invariant — a duplicate key is never
    // accepted)
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
    // A row signed under the revoked D1's FP is reported (stale
    // actor) → never bound to D2
    const stale = addDevice("user_a", FP_A, KEYS_D3);
    const afterStale = deriveReportedView([genesis, owner, addD2, revokeD1, stale]);
    expect(devicesOf(afterStale, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
    ]);
    // Re-add D1's key → the learned FP_A is restored (only that one
    // row carries FP_A)
    const readdD1 = addDevice("user_a", FP_A, KEYS_A1);
    const readd = deriveReportedView([genesis, owner, addD2, revokeD1, stale, readdD1]);
    expect(devicesOf(readd, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
      FP_A,
    ]);
    // FP_A's revocation removes exactly 1 row (device count 2) — the
    // shape of 2 rows sharing one FP is never produced
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
    // A vote cast under a revoked device's FP is not counted (§6.2 —
    // a revoked device's vote is revoked)
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
    // Tenure 1: FP_X is bound to K1 (signed) → removed → tenure 2:
    // a different key K2, signed with the same FP_X → FP_X belongs to
    // K1 so it is never tied to K2 (the table is set-once — K5-16)
    // → add_device K1 back: FP_X is restored
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
    // FP_X's revocation removes exactly 1 row
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
    // A row where user_a signed under the owner's FP (borrowing
    // someone else's FP) → never tied to user_a's unbound device
    const add = addMember("user_a", "member");
    const stolen = addDevice("user_a", FP, KEYS_D2);
    const view = deriveReportedView([genesis, add, stolen]);
    expect(devicesOf(view, "user_a")?.devices.map((d) => d.keyFingerprintHex)).toEqual([
      null,
      null,
    ]);
    expect(devicesOf(view, "user_owner")?.devices.map((d) => d.keyFingerprintHex)).toEqual([FP]);
    // A row listing the owner's FP in user_a's revocation → does not
    // shrink the unbound devices by arithmetic; the whole row is
    // ignored
    const bogus = revokeDevice("user_owner", FP, "user_a", [FP]);
    expect(
      reportedDeviceCount(devicesOf(deriveReportedView([genesis, add, stolen, bogus]), "user_a")!),
    ).toBe(2);
    // A row revoking an already-revoked device's FP again → likewise
    // ignored (does not drag an unbound device in)
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
      addDevice("user_ghost", FP_D2, KEYS_D3), // non-member
      addDevice("user_owner", FP, KEYS_D2), // duplicate key
      revokeDevice("user_owner", FP, "user_ghost", [FP]), // unknown target
      revokeDevice("user_owner", FP, "user_owner", [FP, FP_D2]), // 0 devices after revocation
    ]);
    expect(view.unreadableEntries).toBe(4);
    expect(reportedDeviceCount(devicesOf(view, "user_owner")!)).toBe(2);
  });

  it("drops malformed envelopes and payloads instead of throwing (hostile-server defense)", () => {
    const malformed = [
      null,
      "entry",
      { ...base(), op: "add_member", actor: null }, // missing actor
      { ...base(), op: "add_member", payload: null }, // missing payload
      {
        ...base(),
        op: "add_member",
        payload: { targetUserId: 42, role: "member", encPubHex: HEX64, sigPubHex: HEX64 },
      }, // id is not a string
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
        scopeEnvironmentIds: "env-1", // not an array
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
      // D2 was the only unbound device when it signed → bound. D1
      // signing later does not remove D2's vote
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
      // Signed from one of 2 unbound (both owner/all) → whichever
      // device it was, it was owner → count it
      const vote = approve("user_a", FP_D2, HASH_P);
      const counted = deriveReportedView(
        linked([...setup(), addD2, addR, proposal, vote], 6, HASH_P),
        "99".repeat(32),
      );
      expect(counted.proposals).toEqual([]);
      // If one of them is member-capped, the conclusion depends on
      // the device → do not count
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
      // One of the unbound is revoked after the vote was counted
      // (which one is unknown) → the vote may have been revoked →
      // not counted
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
